#![allow(dead_code)]

use anyhow::Result;
use clap::Parser;
use config::ServerConfig;
use keys::AuthorizedKeysFile;
use std::{
    collections::HashMap,
    fs::OpenOptions,
    path::Path,
    sync::{Arc, RwLock},
};
use tokio::sync::mpsc;
use tracing_subscriber::filter::LevelFilter;

mod config;
mod decoy;
mod ebpf;
mod keys;
mod noise;
mod privilege;
mod relay;
mod spa;

#[derive(Debug, Parser)]
#[command(name = "ghostbro-server")]
#[command(about = "Ghostbro server daemon")]
struct Cli {
    /// Server configuration path.
    #[arg(long, default_value = "/etc/ghost-proxy/ghost-proxy.toml")]
    config: String,

    /// Network interface for XDP attachment. Defaults to loopback for local testing.
    #[arg(long, default_value = "lo")]
    iface: String,

    /// Compiled eBPF object path. If omitted, the server starts without XDP.
    #[arg(long)]
    ebpf_object: Option<String>,

    /// Built-in decoy bind address. Overrides [decoy].bind when provided.
    #[arg(long)]
    decoy_bind: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if let Some(ebpf_object) = cli.ebpf_object.as_deref() {
        let config = ServerConfig::load(&cli.config)?;
        init_logging(Some(&config))?;
        privilege::log_startup_privileges();
        let decoy_bind = decoy_bind_address(&cli, Some(&config));
        tracing::info!(config = %cli.config, decoy_bind = %decoy_bind, spa_path = %config.spa.https_path(), "starting built-in decoy server");

        let (https_spa_tx, https_spa_rx) = mpsc::channel(1024);
        let https_spa_tx = if config.spa.bpf_mode() & ghostbro_bpf_common::SPA_MODE_HTTPS != 0 {
            Some(https_spa_tx)
        } else {
            None
        };
        let decoy_router = decoy::router(
            https_spa_tx,
            config.spa.https_path(),
            config.spa.https_response_status(),
            config.spa.trust_forwarded_for(),
            config.spa.trusted_proxy_cidrs(),
            config
                .decoy
                .as_ref()
                .and_then(|decoy| decoy.webroot.as_deref()),
        )?;
        let decoy_tls = config.decoy.as_ref().and_then(|decoy| decoy.tls_pair());
        let decoy = serve_decoy(decoy_bind.clone(), decoy_router, decoy_tls);

        let authorized_keys = AuthorizedKeysFile::load(&config.clients.authorized_keys)?;
        let clients = authorized_keys.into_clients()?;
        // Bind this node's Noise static identity into SPA verification so a SPA
        // accepted here cannot be replayed against another node (F-003).
        let server_static_pubkey = noise::load_static_public_key(&config.server.identity)?;
        // Fail closed on a missing counter-state file unless explicitly
        // initialising a fresh deployment (F-007).
        let allow_missing_counter_state =
            std::env::var_os("GHOST_PROXY_SPA_COUNTER_INIT").is_some();
        let verifier = spa::SpaVerifier::load(
            clients,
            config.spa.time_window_seconds(),
            config.spa.counter_state_path(),
            server_static_pubkey,
            allow_missing_counter_state,
        )?;
        let allowed_sources = Arc::new(RwLock::new(HashMap::new()));
        let bpf_config = ghostbro_bpf_common::BpfConfig {
            spa_port: config.spa.udp_port(),
            proxy_port: config.proxy.port,
            rate_limit_per_minute: config.spa.udp_rate_limit(),
            spa_mode: config.spa.bpf_mode(),
        };
        let ebpf = ebpf::EbpfRuntime::load_and_attach(
            ebpf_object,
            &cli.iface,
            bpf_config,
            allowed_sources.clone(),
        )?;
        tracing::info!(iface = %cli.iface, ebpf_object, "attached Ghostbro XDP program");
        let proxy_bind = proxy_bind_address(&config);
        let relay_engine = relay::RelayEngine::start(relay_config(&config));

        tokio::select! {
            result = decoy => result?,
            result = ebpf.run_spa(verifier, config.spa.allow_ttl_seconds(), https_spa_rx, config.clients.authorized_keys) => result?,
            result = noise::run_proxy_listener(proxy_bind, config.server.identity, allowed_sources, relay_engine) => result?,
        }
    } else {
        let logging_config = ServerConfig::load(&cli.config).ok();
        init_logging(logging_config.as_ref())?;
        privilege::log_startup_privileges();
        let decoy_bind = decoy_bind_address(&cli, logging_config.as_ref());
        tracing::info!(config = %cli.config, decoy_bind = %decoy_bind, "starting built-in decoy server");

        let decoy_router = decoy::router(
            None,
            "/api/v1/telemetry",
            204,
            false,
            &[],
            logging_config
                .as_ref()
                .and_then(|config| config.decoy.as_ref())
                .and_then(|decoy| decoy.webroot.as_deref()),
        )?;
        let decoy_tls = logging_config
            .as_ref()
            .and_then(|config| config.decoy.as_ref())
            .and_then(|decoy| decoy.tls_pair());
        serve_decoy(decoy_bind, decoy_router, decoy_tls).await?;
    }

    Ok(())
}

/// Serve the decoy router over HTTPS when a TLS cert/key pair is configured,
/// otherwise plain HTTP. Both paths route through `axum::serve`, so graceful
/// shutdown and `ConnectInfo` behave identically.
async fn serve_decoy(
    bind: String,
    router: axum::Router,
    tls: Option<(String, String)>,
) -> Result<()> {
    use axum::serve::ListenerExt;

    let app = router.into_make_service_with_connect_info::<std::net::SocketAddr>();
    match tls {
        Some((cert, key)) => {
            // `tap_io` wraps the custom listener in `TapIo`, which is what axum's
            // generic `Connected` impl keys on so `ConnectInfo<SocketAddr>` still
            // resolves the peer address for HTTPS SPA source-IP extraction.
            let listener = decoy::RustlsListener::bind(&bind, &cert, &key)
                .await?
                .tap_io(|_io| {});
            tracing::info!(bind = %bind, "decoy serving HTTPS (rustls)");
            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown_signal())
                .await?;
        }
        None => {
            let listener = tokio::net::TcpListener::bind(&bind).await?;
            tracing::info!(bind = %bind, "decoy serving plain HTTP");
            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown_signal())
                .await?;
        }
    }
    Ok(())
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::warn!(?error, "failed to install Ctrl-C handler");
    }
}

/// Build the relay engine configuration from the optional `[relay]` config
/// section, applying defaults for absent fields and environment overrides last.
fn relay_config(config: &ServerConfig) -> relay::RelayConfig {
    let mut relay = relay::RelayConfig::default();
    if let Some(section) = config.relay.as_ref() {
        if let Some(dir) = section.spool_dir.as_ref() {
            relay.spool_dir = std::path::PathBuf::from(dir);
        }
        if let Some(ttl) = section.job_ttl {
            relay.job_ttl = std::time::Duration::from_secs(ttl);
        }
        if let Some(max_jobs) = section.max_jobs_per_client {
            relay.max_jobs_per_client = max_jobs;
        }
        if let Some(max_bytes) = section.max_bytes_per_client {
            relay.max_bytes_per_client = max_bytes;
        }
        if let Some(max_object) = section.max_object_len {
            relay.max_object_len = max_object;
        }
        if let Some(workers) = section.workers {
            relay.worker_count = workers;
        }
        if let Some(timeout) = section.fetch_timeout {
            relay.fetch_timeout = std::time::Duration::from_secs(timeout);
        }
        if let Some(timeout) = section.git_timeout {
            relay.git_timeout = std::time::Duration::from_secs(timeout);
        }
        relay.allow_loopback = section.allow_loopback;
    }
    relay.with_env_overrides()
}

fn proxy_bind_address(config: &ServerConfig) -> String {
    if config.proxy.bind.contains(':') {
        config.proxy.bind.clone()
    } else {
        format!("{}:{}", config.proxy.bind, config.proxy.port)
    }
}

fn decoy_bind_address(cli: &Cli, config: Option<&ServerConfig>) -> String {
    cli.decoy_bind
        .clone()
        .or_else(|| {
            config
                .and_then(|config| config.decoy.as_ref())
                .and_then(|decoy| decoy.bind.clone())
        })
        .unwrap_or_else(|| "127.0.0.1:8080".to_owned())
}

fn init_logging(config: Option<&ServerConfig>) -> Result<()> {
    if std::env::var_os("RUST_LOG").is_some() {
        tracing_subscriber::fmt::init();
        return Ok(());
    }

    let Some(logging) = config.and_then(|config| config.logging.as_ref()) else {
        tracing_subscriber::fmt::init();
        return Ok(());
    };

    let level = logging
        .level
        .parse::<LevelFilter>()
        .map_err(|error| anyhow::anyhow!("invalid logging.level {:?}: {error}", logging.level))?;

    if !logging.path.is_empty() {
        if let Some(parent) = Path::new(&logging.path).parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&logging.path)?;
        tracing_subscriber::fmt()
            .with_max_level(level)
            .with_writer(std::sync::Mutex::new(file))
            .init();
    } else {
        tracing_subscriber::fmt().with_max_level(level).init();
    }

    Ok(())
}
