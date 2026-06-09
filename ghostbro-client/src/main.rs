#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    fs,
    io::{ErrorKind, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use clap::{Parser, Subcommand};
use fast_socks5::{server::Socks5ServerProtocol, ReplyError, Socks5Command};
use ghostbro_common::{
    keys::{
        decode_signing_key, derive_noise_static_private_key, derive_noise_static_public_key,
        encode_noise_public_key, encode_public_key, encode_signing_key, generate_ed25519_keypair,
        key_id_for_public_key, key_id_hex,
    },
    protocol::{
        GHOST_RELAY_ARTIFACT_NORMALIZED, GHOST_RELAY_ARTIFACT_PRIMARY, GHOST_RELAY_OP_DELETE,
        GHOST_RELAY_OP_DOWNLOAD, GHOST_RELAY_OP_LIST, GHOST_RELAY_OP_SUBMIT_GIT,
        GHOST_RELAY_OP_SUBMIT_PACKAGE, GHOST_RELAY_OP_SUBMIT_WEB, GHOST_RELAY_STATUS_OK,
        GHOST_RELAY_STATUS_PENDING, GHOST_RELAY_VERSION,
    },
    protocol::{
        DEFAULT_TIME_WINDOW_SECONDS, GHOST_RELAY_STATUS_UNSUPPORTED, PROTOCOL_GHOST_RELAY,
    },
    spa::{SpaMode, SpaPacket},
};
use rand::{rngs::OsRng, seq::SliceRandom, RngCore};
use serde::{Deserialize, Serialize};

const IDENTITY_KEY_VERSION: u8 = 1;
const IDENTITY_KEY_KDF: &str = "argon2id";
const IDENTITY_KEY_AEAD: &str = "chacha20poly1305";
const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;
const ARGON2_KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

#[derive(Debug, Parser)]
#[command(name = "ghostbro")]
#[command(about = "Ghostbro client CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate a client identity.
    Keygen {
        /// Output path prefix for identity files.
        #[arg(long)]
        output: String,
        /// Write a legacy plaintext private key for smoke tests and local dev only.
        #[arg(long)]
        plaintext_debug: bool,
    },
    /// Generate a server Noise static identity.
    ServerKeygen {
        /// Output path prefix for server key files.
        #[arg(long)]
        output: String,
    },
    /// Enroll a server configuration.
    Enroll {
        #[arg(long)]
        server_key: String,
        #[arg(long)]
        endpoint: String,
        #[arg(long)]
        spa_mode: SpaTransport,
        #[arg(long)]
        spa_port: u16,
        /// Output TOML path for the enrolled server config.
        #[arg(long, default_value = "servers.toml")]
        output: String,
    },
    /// Connect to a configured server.
    Connect {
        /// PRD-style server config path from `enroll`.
        #[arg(long)]
        config: Option<String>,
        /// Path to encrypted or legacy plaintext Ed25519 identity key from `keygen`.
        #[arg(long)]
        identity_key: String,
        /// Path to base64 debug X25519 server public key.
        #[arg(long)]
        server_key: Option<String>,
        /// UDP SPA endpoint, e.g. 127.0.0.1:5353.
        #[arg(long)]
        spa_endpoint: Option<SocketAddr>,
        /// TCP proxy endpoint, e.g. 127.0.0.1:8443.
        #[arg(long)]
        proxy_endpoint: Option<SocketAddr>,
        /// Local SOCKS5 listen address, e.g. 127.0.0.1:1080.
        #[arg(long)]
        listen: SocketAddr,
        /// SPA transport mode for the authorization packet.
        #[arg(long)]
        spa_mode: Option<SpaTransport>,
        /// HTTPS SPA endpoint URL, e.g. https://example.com/api/v1/telemetry.
        #[arg(long)]
        https_spa_url: Option<String>,
        /// Server allow-map TTL in seconds. Refresh runs every TTL/2.
        #[arg(long, default_value_t = 14_400)]
        allow_ttl_seconds: u64,
        /// Optional counter file path. Defaults to <identity_key>.counter.
        #[arg(long)]
        counter_file: Option<String>,
    },
    /// Best-effort notification that this client key should be revoked.
    Revoke {
        #[arg(long)]
        config: String,
        /// Optional identity key used to include this client's key_id in the notification.
        #[arg(long)]
        identity_key: Option<String>,
    },
    /// Debug helper: send one UDP SPA packet using a plaintext key file.
    SendUdpSpa {
        /// Path to encrypted or legacy plaintext Ed25519 identity key from `keygen`.
        #[arg(long)]
        identity_key: String,
        /// Path to the destination server's Noise public key file. Bound into the
        /// SPA signature (not transmitted) so the packet only opens this server.
        #[arg(long)]
        server_key: String,
        /// UDP SPA endpoint, e.g. 127.0.0.1:53.
        #[arg(long)]
        endpoint: SocketAddr,
        /// Optional counter file path. Defaults to <identity_key>.counter.
        #[arg(long)]
        counter_file: Option<String>,
    },
    /// Debug helper: send one HTTPS SPA POST using a plaintext key file.
    SendHttpsSpa {
        /// Path to encrypted or legacy plaintext Ed25519 identity key from `keygen`.
        #[arg(long)]
        identity_key: String,
        /// Path to the destination server's Noise public key file. Bound into the
        /// SPA signature (not transmitted) so the packet only opens this server.
        #[arg(long)]
        server_key: String,
        /// HTTPS SPA endpoint URL, e.g. https://example.com/api/v1/telemetry.
        #[arg(long)]
        url: String,
        /// Optional counter file path. Defaults to <identity_key>.counter.
        #[arg(long)]
        counter_file: Option<String>,
    },
    /// Debug helper: send UDP SPA, then complete one Noise IK TCP exchange.
    ConnectOnce {
        /// Path to encrypted or legacy plaintext Ed25519 identity key from `keygen`.
        #[arg(long)]
        identity_key: String,
        /// Path to base64 debug X25519 server public key.
        #[arg(long)]
        server_key: String,
        /// UDP SPA endpoint, e.g. 127.0.0.1:5353.
        #[arg(long)]
        spa_endpoint: SocketAddr,
        /// TCP proxy endpoint, e.g. 127.0.0.1:8443.
        #[arg(long)]
        proxy_endpoint: SocketAddr,
        /// One plaintext message to send inside the encrypted tunnel.
        #[arg(long)]
        message: String,
        /// SPA transport mode for the authorization packet.
        #[arg(long, default_value = "udp")]
        spa_mode: SpaTransport,
        /// HTTPS SPA endpoint URL, e.g. https://example.com/api/v1/telemetry.
        #[arg(long)]
        https_spa_url: Option<String>,
        /// Optional counter file path. Defaults to <identity_key>.counter.
        #[arg(long)]
        counter_file: Option<String>,
    },
    /// Debug helper: send UDP SPA, then proxy one SOCKS5 CONNECT exchange over Noise.
    ConnectSocks5Once {
        /// Path to encrypted or legacy plaintext Ed25519 identity key from `keygen`.
        #[arg(long)]
        identity_key: String,
        /// Path to base64 debug X25519 server public key.
        #[arg(long)]
        server_key: String,
        /// UDP SPA endpoint, e.g. 127.0.0.1:5353.
        #[arg(long)]
        spa_endpoint: SocketAddr,
        /// TCP proxy endpoint, e.g. 127.0.0.1:8443.
        #[arg(long)]
        proxy_endpoint: SocketAddr,
        /// SOCKS5 CONNECT target, e.g. 127.0.0.1:9000 or example.com:80.
        #[arg(long)]
        target: String,
        /// One plaintext message to send through the encrypted SOCKS5 tunnel.
        #[arg(long)]
        message: String,
        /// SPA transport mode for the authorization packet.
        #[arg(long, default_value = "udp")]
        spa_mode: SpaTransport,
        /// HTTPS SPA endpoint URL, e.g. https://example.com/api/v1/telemetry.
        #[arg(long)]
        https_spa_url: Option<String>,
        /// Optional counter file path. Defaults to <identity_key>.counter.
        #[arg(long)]
        counter_file: Option<String>,
    },
    /// Debug helper: send UDP SPA, then probe Ghost Relay dispatch over Noise.
    ConnectGhostRelayOnce {
        /// Path to encrypted or legacy plaintext Ed25519 identity key from `keygen`.
        #[arg(long)]
        identity_key: String,
        /// Path to base64 debug X25519 server public key.
        #[arg(long)]
        server_key: String,
        /// UDP SPA endpoint, e.g. 127.0.0.1:5353.
        #[arg(long)]
        spa_endpoint: SocketAddr,
        /// TCP proxy endpoint, e.g. 127.0.0.1:8443.
        #[arg(long)]
        proxy_endpoint: SocketAddr,
        /// SPA transport mode for the authorization packet.
        #[arg(long, default_value = "udp")]
        spa_mode: SpaTransport,
        /// HTTPS SPA endpoint URL, e.g. https://example.com/api/v1/telemetry.
        #[arg(long)]
        https_spa_url: Option<String>,
        /// Optional counter file path. Defaults to <identity_key>.counter.
        #[arg(long)]
        counter_file: Option<String>,
    },
    /// Submit a Ghost Relay web fetch job and persist the result server-side.
    RelaySubmitUrl {
        #[arg(long)]
        identity_key: String,
        #[arg(long)]
        server_key: String,
        #[arg(long)]
        spa_endpoint: SocketAddr,
        #[arg(long)]
        proxy_endpoint: SocketAddr,
        #[arg(long)]
        url: String,
        /// Also store an HTML-to-markdown normalized copy of the fetched body.
        #[arg(long)]
        normalize: bool,
        #[arg(long, default_value = "udp")]
        spa_mode: SpaTransport,
        #[arg(long)]
        https_spa_url: Option<String>,
        #[arg(long)]
        counter_file: Option<String>,
    },
    /// Submit a Ghost Relay git mirror job (clone --mirror, stored as a bundle).
    RelaySubmitGit {
        #[arg(long)]
        identity_key: String,
        #[arg(long)]
        server_key: String,
        #[arg(long)]
        spa_endpoint: SocketAddr,
        #[arg(long)]
        proxy_endpoint: SocketAddr,
        #[arg(long)]
        git_url: String,
        #[arg(long, default_value = "udp")]
        spa_mode: SpaTransport,
        #[arg(long)]
        https_spa_url: Option<String>,
        #[arg(long)]
        counter_file: Option<String>,
    },
    /// Submit a Ghost Relay package retrieval job (pypi / npm / crates).
    RelaySubmitPackage {
        #[arg(long)]
        identity_key: String,
        #[arg(long)]
        server_key: String,
        #[arg(long)]
        spa_endpoint: SocketAddr,
        #[arg(long)]
        proxy_endpoint: SocketAddr,
        /// Package ecosystem: pypi, npm, or crates.
        #[arg(long)]
        ecosystem: String,
        /// Package name (npm scopes like @scope/name are supported).
        #[arg(long)]
        name: String,
        /// Package version. Optional for pypi/npm (latest), required for crates.
        #[arg(long, default_value = "")]
        version: String,
        #[arg(long, default_value = "udp")]
        spa_mode: SpaTransport,
        #[arg(long)]
        https_spa_url: Option<String>,
        #[arg(long)]
        counter_file: Option<String>,
    },
    /// List Ghost Relay jobs stored for this client identity.
    RelayList {
        #[arg(long)]
        identity_key: String,
        #[arg(long)]
        server_key: String,
        #[arg(long)]
        spa_endpoint: SocketAddr,
        #[arg(long)]
        proxy_endpoint: SocketAddr,
        #[arg(long, default_value = "udp")]
        spa_mode: SpaTransport,
        #[arg(long)]
        https_spa_url: Option<String>,
        #[arg(long)]
        counter_file: Option<String>,
    },
    /// Download a Ghost Relay job result in chunks.
    RelayDownload {
        #[arg(long)]
        identity_key: String,
        #[arg(long)]
        server_key: String,
        #[arg(long)]
        spa_endpoint: SocketAddr,
        #[arg(long)]
        proxy_endpoint: SocketAddr,
        #[arg(long)]
        job_id: String,
        #[arg(long)]
        output: PathBuf,
        /// Artifact to download: "primary" (raw body) or "markdown" (normalized).
        #[arg(long, default_value = "primary")]
        artifact: RelayArtifact,
        #[arg(long, default_value = "udp")]
        spa_mode: SpaTransport,
        #[arg(long)]
        https_spa_url: Option<String>,
        #[arg(long)]
        counter_file: Option<String>,
    },
    /// Delete a Ghost Relay job/result after successful retrieval.
    RelayDelete {
        #[arg(long)]
        identity_key: String,
        #[arg(long)]
        server_key: String,
        #[arg(long)]
        spa_endpoint: SocketAddr,
        #[arg(long)]
        proxy_endpoint: SocketAddr,
        #[arg(long)]
        job_id: String,
        #[arg(long, default_value = "udp")]
        spa_mode: SpaTransport,
        #[arg(long)]
        https_spa_url: Option<String>,
        #[arg(long)]
        counter_file: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
enum SpaTransport {
    Udp,
    Https,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum RelayArtifact {
    Primary,
    Markdown,
}

impl RelayArtifact {
    fn selector(self) -> u8 {
        match self {
            RelayArtifact::Primary => GHOST_RELAY_ARTIFACT_PRIMARY,
            RelayArtifact::Markdown => GHOST_RELAY_ARTIFACT_NORMALIZED,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ClientConfig {
    servers: Vec<ServerConfigEntry>,
    failover: Option<FailoverConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServerConfigEntry {
    endpoint: String,
    spa_endpoint: String,
    spa_mode: SpaTransport,
    spa_port: u16,
    server_public_key: String,
    priority: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
struct FailoverConfig {
    strategy: String,
    retry_interval_ms: u64,
    max_retries: u32,
}

/// How the client orders candidate servers across a connection attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailoverStrategy {
    /// Try servers in ascending `priority` order (configured order).
    Priority,
    /// Shuffle the candidate order on every attempt (load spreading).
    Random,
    /// Probe each candidate and try the lowest-latency reachable one first.
    Latency,
}

impl FailoverStrategy {
    fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "priority" => Ok(Self::Priority),
            "random" => Ok(Self::Random),
            "latency" => Ok(Self::Latency),
            other => anyhow::bail!(
                "unknown failover strategy {other:?} (expected \"priority\", \"random\", or \"latency\")"
            ),
        }
    }
}

/// Resolved failover behaviour: ordering strategy plus retry budget.
#[derive(Debug, Clone, Copy)]
struct FailoverPolicy {
    strategy: FailoverStrategy,
    retry_interval: Duration,
    max_retries: u32,
}

impl Default for FailoverPolicy {
    fn default() -> Self {
        // No `[failover]` block: single pass over priority order, no retries.
        Self {
            strategy: FailoverStrategy::Priority,
            retry_interval: Duration::from_secs(0),
            max_retries: 0,
        }
    }
}

impl FailoverPolicy {
    fn from_config(config: &ClientConfig) -> Result<Self> {
        match &config.failover {
            None => Ok(Self::default()),
            Some(failover) => Ok(Self {
                strategy: FailoverStrategy::parse(&failover.strategy)?,
                retry_interval: Duration::from_millis(failover.retry_interval_ms),
                max_retries: failover.max_retries,
            }),
        }
    }
}

/// TCP connect timeout used when probing candidate latency.
const LATENCY_PROBE_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Clone)]
struct ResolvedConnectConfig {
    server_public_key: Vec<u8>,
    spa_endpoint: SocketAddr,
    proxy_endpoint: SocketAddr,
    spa_mode: SpaTransport,
    https_spa_url: Option<String>,
}

#[derive(Debug, Serialize)]
struct RevokeRequest<'a> {
    action: &'a str,
    key_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedIdentityKey {
    version: u8,
    kdf: String,
    aead: String,
    params: EncryptedIdentityParams,
    salt: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedIdentityParams {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Command::Keygen {
            output,
            plaintext_debug,
        } => keygen(&output, plaintext_debug),
        Command::ServerKeygen { output } => server_keygen(&output),
        Command::Enroll {
            server_key,
            endpoint,
            spa_mode,
            spa_port,
            output,
        } => enroll(&server_key, &endpoint, spa_mode, spa_port, &output),
        Command::Connect {
            config,
            identity_key,
            server_key,
            spa_endpoint,
            proxy_endpoint,
            listen,
            spa_mode,
            https_spa_url,
            allow_ttl_seconds,
            counter_file,
        } => {
            let (resolved, policy) = resolve_connect_configs(
                config.as_deref(),
                server_key.as_deref(),
                spa_endpoint,
                proxy_endpoint,
                spa_mode,
                https_spa_url.as_deref(),
            )?;
            connect_listener(
                identity_key,
                resolved,
                policy,
                listen,
                allow_ttl_seconds,
                counter_file,
            )
        }
        Command::Revoke {
            config,
            identity_key,
        } => revoke(&config, identity_key.as_deref()),
        Command::SendUdpSpa {
            identity_key,
            server_key,
            endpoint,
            counter_file,
        } => {
            let server_static_pubkey = read_noise_public_key_array(&server_key)?;
            send_udp_spa(
                &identity_key,
                &server_static_pubkey,
                endpoint,
                counter_file.as_deref(),
            )
        }
        Command::SendHttpsSpa {
            identity_key,
            server_key,
            url,
            counter_file,
        } => {
            let server_static_pubkey = read_noise_public_key_array(&server_key)?;
            send_https_spa(
                &identity_key,
                &server_static_pubkey,
                &url,
                counter_file.as_deref(),
            )
        }
        Command::ConnectOnce {
            identity_key,
            server_key,
            spa_endpoint,
            proxy_endpoint,
            message,
            spa_mode,
            https_spa_url,
            counter_file,
        } => connect_once(
            &identity_key,
            &server_key,
            spa_endpoint,
            proxy_endpoint,
            &message,
            spa_mode,
            https_spa_url.as_deref(),
            counter_file.as_deref(),
        ),
        Command::ConnectSocks5Once {
            identity_key,
            server_key,
            spa_endpoint,
            proxy_endpoint,
            target,
            message,
            spa_mode,
            https_spa_url,
            counter_file,
        } => connect_socks5_once(
            &identity_key,
            &server_key,
            spa_endpoint,
            proxy_endpoint,
            &target,
            &message,
            spa_mode,
            https_spa_url.as_deref(),
            counter_file.as_deref(),
        ),
        Command::ConnectGhostRelayOnce {
            identity_key,
            server_key,
            spa_endpoint,
            proxy_endpoint,
            spa_mode,
            https_spa_url,
            counter_file,
        } => connect_ghost_relay_once(
            &identity_key,
            &server_key,
            spa_endpoint,
            proxy_endpoint,
            spa_mode,
            https_spa_url.as_deref(),
            counter_file.as_deref(),
        ),
        Command::RelaySubmitUrl {
            identity_key,
            server_key,
            spa_endpoint,
            proxy_endpoint,
            url,
            normalize,
            spa_mode,
            https_spa_url,
            counter_file,
        } => relay_submit_url(
            &identity_key,
            &server_key,
            spa_endpoint,
            proxy_endpoint,
            &url,
            normalize,
            spa_mode,
            https_spa_url.as_deref(),
            counter_file.as_deref(),
        ),
        Command::RelaySubmitGit {
            identity_key,
            server_key,
            spa_endpoint,
            proxy_endpoint,
            git_url,
            spa_mode,
            https_spa_url,
            counter_file,
        } => relay_submit_git(
            &identity_key,
            &server_key,
            spa_endpoint,
            proxy_endpoint,
            &git_url,
            spa_mode,
            https_spa_url.as_deref(),
            counter_file.as_deref(),
        ),
        Command::RelaySubmitPackage {
            identity_key,
            server_key,
            spa_endpoint,
            proxy_endpoint,
            ecosystem,
            name,
            version,
            spa_mode,
            https_spa_url,
            counter_file,
        } => relay_submit_package(
            &identity_key,
            &server_key,
            spa_endpoint,
            proxy_endpoint,
            &ecosystem,
            &name,
            &version,
            spa_mode,
            https_spa_url.as_deref(),
            counter_file.as_deref(),
        ),
        Command::RelayList {
            identity_key,
            server_key,
            spa_endpoint,
            proxy_endpoint,
            spa_mode,
            https_spa_url,
            counter_file,
        } => relay_list(
            &identity_key,
            &server_key,
            spa_endpoint,
            proxy_endpoint,
            spa_mode,
            https_spa_url.as_deref(),
            counter_file.as_deref(),
        ),
        Command::RelayDownload {
            identity_key,
            server_key,
            spa_endpoint,
            proxy_endpoint,
            job_id,
            output,
            artifact,
            spa_mode,
            https_spa_url,
            counter_file,
        } => relay_download(
            &identity_key,
            &server_key,
            spa_endpoint,
            proxy_endpoint,
            &job_id,
            &output,
            artifact,
            spa_mode,
            https_spa_url.as_deref(),
            counter_file.as_deref(),
        ),
        Command::RelayDelete {
            identity_key,
            server_key,
            spa_endpoint,
            proxy_endpoint,
            job_id,
            spa_mode,
            https_spa_url,
            counter_file,
        } => relay_delete(
            &identity_key,
            &server_key,
            spa_endpoint,
            proxy_endpoint,
            &job_id,
            spa_mode,
            https_spa_url.as_deref(),
            counter_file.as_deref(),
        ),
    }
}

fn keygen(output: &str, plaintext_debug: bool) -> Result<()> {
    let signing_key = generate_ed25519_keypair();
    let public_key = signing_key.verifying_key();
    let key_id = key_id_for_public_key(&public_key);
    let noise_public_key = derive_noise_static_public_key(&signing_key);

    let key_path = format!("{output}.key");
    let pub_path = format!("{output}.pub");
    let key_id_path = format!("{output}.keyid");
    let noise_path = format!("{output}.noise");
    let counter_path = format!("{output}.counter");

    if plaintext_debug {
        write_private_key_file(&key_path, format!("{}\n", encode_signing_key(&signing_key)))
            .with_context(|| format!("failed to write {key_path}"))?;
    } else {
        let passphrase = prompt_new_passphrase()?;
        let encrypted = encrypt_signing_key(&signing_key, &passphrase)?;
        write_private_key_file(&key_path, encrypted)
            .with_context(|| format!("failed to write {key_path}"))?;
    }
    fs::write(&pub_path, format!("{}\n", encode_public_key(&public_key)))
        .with_context(|| format!("failed to write {pub_path}"))?;
    fs::write(&key_id_path, format!("{}\n", key_id_hex(&key_id)))
        .with_context(|| format!("failed to write {key_id_path}"))?;
    fs::write(
        &noise_path,
        format!("{}\n", encode_noise_public_key(&noise_public_key)),
    )
    .with_context(|| format!("failed to write {noise_path}"))?;
    fs::write(&counter_path, "0\n").with_context(|| format!("failed to write {counter_path}"))?;

    if plaintext_debug {
        println!("wrote plaintext debug identity:");
    } else {
        println!("wrote encrypted identity:");
    }
    println!("  private key: {key_path}");
    println!("  public key:  {pub_path}");
    println!("  key id:      {key_id_path}");
    println!("  noise key:   {noise_path}");
    println!("  counter:     {counter_path}");
    println!("authorized_keys.toml entry:");
    println!("[[clients]]");
    println!("name = \"debug-client\"");
    println!("public_key = \"{}\"", encode_public_key(&public_key));
    println!(
        "noise_public_key = \"{}\"",
        encode_noise_public_key(&noise_public_key)
    );
    println!("tier = \"full\"");

    Ok(())
}

fn server_keygen(output: &str) -> Result<()> {
    let key_path = format!("{output}.key");
    let pub_path = format!("{output}.pub");
    let params = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
        .parse()
        .context("invalid Noise pattern")?;
    let keypair = snow::Builder::new(params)
        .generate_keypair()
        .context("failed to generate server Noise static keypair")?;

    write_private_key_file(
        &key_path,
        format!("{}\n", STANDARD.encode(&keypair.private)),
    )
    .with_context(|| format!("failed to write {key_path}"))?;
    fs::write(&pub_path, format!("{}\n", STANDARD.encode(&keypair.public)))
        .with_context(|| format!("failed to write {pub_path}"))?;

    println!("wrote server Noise identity:");
    println!("  private key: {key_path}");
    println!("  public key:  {pub_path}");
    println!("server config:");
    println!("[server]");
    println!("identity = \"{key_path}\"");

    Ok(())
}

fn enroll(
    server_key: &str,
    endpoint: &str,
    spa_mode: SpaTransport,
    spa_port: u16,
    output: &str,
) -> Result<()> {
    decode_noise_public_key(server_key)
        .context("--server-key must be a base64 Noise public key")?;
    let proxy_endpoint: SocketAddr = endpoint
        .parse()
        .with_context(|| format!("--endpoint must be host:port, got {endpoint}"))?;
    let config = ClientConfig {
        servers: vec![ServerConfigEntry {
            endpoint: endpoint.to_owned(),
            spa_endpoint: proxy_endpoint.ip().to_string(),
            spa_mode,
            spa_port,
            server_public_key: server_key.to_owned(),
            priority: Some(1),
        }],
        failover: Some(FailoverConfig {
            strategy: "priority".to_owned(),
            retry_interval_ms: 5_000,
            max_retries: 3,
        }),
    };

    let contents = toml::to_string_pretty(&config).context("failed to serialize server config")?;
    if let Some(parent) = Path::new(output).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
    }
    fs::write(output, contents).with_context(|| format!("failed to write {output}"))?;
    println!("wrote server config: {output}");

    Ok(())
}

fn revoke(config_path: &str, identity_key: Option<&str>) -> Result<()> {
    let config = load_client_config(config_path)?;
    let key_id = identity_key
        .map(|path| -> Result<String> {
            let signing_key = read_signing_key(path)?;
            Ok(key_id_hex(&key_id_for_public_key(
                &signing_key.verifying_key(),
            )))
        })
        .transpose()?;
    let request = RevokeRequest {
        action: "revoke",
        key_id,
    };

    let mut attempted = 0usize;
    let mut succeeded = 0usize;
    for server in &config.servers {
        let Some(url) = revoke_url_for(server) else {
            continue;
        };
        attempted += 1;
        match reqwest::blocking::Client::new()
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(revoke_request_body(&request))
            .send()
        {
            Ok(response) if response.status().is_success() || response.status().as_u16() == 204 => {
                succeeded += 1;
                println!("REVOKE_NOTIFY_SENT url={url} status={}", response.status());
            }
            Ok(response) => {
                eprintln!(
                    "REVOKE_NOTIFY_FAILED url={url} status={}",
                    response.status()
                );
            }
            Err(error) => eprintln!("REVOKE_NOTIFY_FAILED url={url} error={error:#}"),
        }
    }

    if attempted == 0 {
        println!("REVOKE_NOTIFY_SKIPPED no_https_servers=true");
    } else {
        println!("REVOKE_NOTIFY_COMPLETE attempted={attempted} succeeded={succeeded}");
    }
    println!("revoke remains best-effort; remove the key from authorized_keys.toml on the server");

    Ok(())
}

fn resolve_connect_configs(
    config_path: Option<&str>,
    server_key: Option<&str>,
    spa_endpoint: Option<SocketAddr>,
    proxy_endpoint: Option<SocketAddr>,
    spa_mode_override: Option<SpaTransport>,
    https_spa_url_override: Option<&str>,
) -> Result<(Vec<ResolvedConnectConfig>, FailoverPolicy)> {
    if let Some(config_path) = config_path {
        let config = load_client_config(config_path)?;
        let policy = FailoverPolicy::from_config(&config)?;
        let servers = ordered_servers(&config)?;
        let resolved = servers
            .into_iter()
            .map(|server| {
                let proxy_endpoint: SocketAddr = server.endpoint.parse().with_context(|| {
                    format!("invalid endpoint in {config_path}: {}", server.endpoint)
                })?;
                let spa_endpoint = parse_spa_endpoint(&server.spa_endpoint, server.spa_port)?;
                let spa_mode = spa_mode_override.unwrap_or(server.spa_mode);
                let https_spa_url = https_spa_url_override
                    .map(str::to_owned)
                    .or_else(|| https_spa_url_for(&server, spa_mode));

                Ok(ResolvedConnectConfig {
                    server_public_key: decode_noise_public_key(&server.server_public_key)?,
                    spa_endpoint,
                    proxy_endpoint,
                    spa_mode,
                    https_spa_url,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        return Ok((resolved, policy));
    }

    let server_key =
        server_key.context("--server-key is required when --config is not provided")?;
    let spa_endpoint =
        spa_endpoint.context("--spa-endpoint is required when --config is not provided")?;
    let proxy_endpoint =
        proxy_endpoint.context("--proxy-endpoint is required when --config is not provided")?;
    let spa_mode = spa_mode_override.unwrap_or(SpaTransport::Udp);

    let resolved = vec![ResolvedConnectConfig {
        server_public_key: read_noise_public_key(server_key)?,
        spa_endpoint,
        proxy_endpoint,
        spa_mode,
        https_spa_url: https_spa_url_override.map(str::to_owned),
    }];
    Ok((resolved, FailoverPolicy::default()))
}

fn load_client_config(path: &str) -> Result<ClientConfig> {
    let contents = fs::read_to_string(path).with_context(|| format!("failed to read {path}"))?;
    toml::from_str(&contents).with_context(|| format!("failed to parse {path}"))
}

fn ordered_servers(config: &ClientConfig) -> Result<Vec<ServerConfigEntry>> {
    if config.servers.is_empty() {
        anyhow::bail!("client config has no servers");
    }

    let mut servers = config.servers.clone();
    servers.sort_by_key(|server| server.priority.unwrap_or(u32::MAX));
    Ok(servers)
}

fn parse_spa_endpoint(host: &str, port: u16) -> Result<SocketAddr> {
    if let Ok(addr) = host.parse::<SocketAddr>() {
        return Ok(addr);
    }
    format!("{host}:{port}")
        .parse()
        .with_context(|| format!("invalid SPA endpoint {host}:{port}"))
}

fn https_spa_url_for(server: &ServerConfigEntry, spa_mode: SpaTransport) -> Option<String> {
    match spa_mode {
        SpaTransport::Udp => None,
        SpaTransport::Https => Some(format!(
            "https://{}:{}/api/v1/telemetry",
            server.spa_endpoint, server.spa_port
        )),
    }
}

fn revoke_url_for(server: &ServerConfigEntry) -> Option<String> {
    (server.spa_mode == SpaTransport::Https).then(|| {
        format!(
            "https://{}:{}/api/v1/revoke",
            server.spa_endpoint, server.spa_port
        )
    })
}

fn revoke_request_body(request: &RevokeRequest<'_>) -> String {
    match &request.key_id {
        Some(key_id) => format!(r#"{{"action":"{}","key_id":"{}"}}"#, request.action, key_id),
        None => format!(r#"{{"action":"{}","key_id":null}}"#, request.action),
    }
}

fn send_udp_spa(
    identity_key: &str,
    server_static_pubkey: &[u8; 32],
    endpoint: SocketAddr,
    counter_file: Option<&str>,
) -> Result<()> {
    let signing_key = read_signing_key(identity_key)?;
    let counter_path = counter_file
        .map(PathBuf::from)
        .unwrap_or_else(|| default_counter_path(identity_key));
    let counter = increment_counter(&counter_path)?;
    let timestamp_ms = unix_timestamp_ms()?;
    let payload = SpaPacket::build(
        &signing_key,
        SpaMode::Udp,
        timestamp_ms,
        counter,
        server_static_pubkey,
    );

    let socket = UdpSocket::bind(if endpoint.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .context("failed to bind UDP socket")?;
    socket
        .send_to(&payload, endpoint)
        .with_context(|| format!("failed to send UDP SPA to {endpoint}"))?;

    let key_id = key_id_for_public_key(&signing_key.verifying_key());
    println!(
        "sent UDP SPA: endpoint={endpoint} key_id={} counter={counter} bytes={}",
        key_id_hex(&key_id),
        payload.len()
    );

    Ok(())
}

fn send_https_spa(
    identity_key: &str,
    server_static_pubkey: &[u8; 32],
    url: &str,
    counter_file: Option<&str>,
) -> Result<()> {
    let signing_key = read_signing_key(identity_key)?;
    let counter_path = counter_file
        .map(PathBuf::from)
        .unwrap_or_else(|| default_counter_path(identity_key));
    let counter = increment_counter(&counter_path)?;
    let timestamp_ms = unix_timestamp_ms()?;
    let payload = SpaPacket::build(
        &signing_key,
        SpaMode::Https,
        timestamp_ms,
        counter,
        server_static_pubkey,
    );

    let response = reqwest::blocking::Client::new()
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
        .body(payload.clone())
        .send()
        .with_context(|| format!("failed to send HTTPS SPA to {url}"))?;

    let status = response.status();
    let date_header = response
        .headers()
        .get(reqwest::header::DATE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);

    if status != reqwest::StatusCode::NO_CONTENT {
        anyhow::bail!("HTTPS SPA endpoint returned unexpected status {status}");
    }

    // The HTTPS response carries the server's clock in its Date header — use it
    // to surface a clear error before the (doomed) tunnel attempt if the local
    // clock has drifted beyond the SPA acceptance window.
    if let Some(date) = date_header.as_deref() {
        check_clock_drift_from_http_date(date)?;
    }

    let key_id = key_id_for_public_key(&signing_key.verifying_key());
    println!(
        "sent HTTPS SPA: url={url} key_id={} counter={counter} bytes={}",
        key_id_hex(&key_id),
        payload.len()
    );

    Ok(())
}

/// Assumed server-side SPA timestamp window. Clients are not told the server's
/// configured `time_window`, so we compare against the protocol default.
const ASSUMED_SPA_WINDOW_SECONDS: u64 = DEFAULT_TIME_WINDOW_SECONDS;

#[derive(Debug, PartialEq, Eq)]
enum DriftVerdict {
    /// Within a comfortable fraction of the window.
    Ok,
    /// Within the window but large enough to warn about (seconds of drift).
    Warn(i64),
    /// Beyond the window — the SPA will be rejected (seconds of drift).
    Exceeded(i64),
}

/// Clock drift in seconds, `local - server`. Positive means the client clock is
/// ahead of the server.
fn clock_drift_seconds(server: SystemTime, local: SystemTime) -> i64 {
    match local.duration_since(server) {
        Ok(ahead) => ahead.as_secs() as i64,
        Err(behind) => -(behind.duration().as_secs() as i64),
    }
}

fn classify_drift(drift_secs: i64, window_secs: u64) -> DriftVerdict {
    let window = window_secs as i64;
    let magnitude = drift_secs.abs();
    if magnitude > window {
        DriftVerdict::Exceeded(drift_secs)
    } else if magnitude * 2 > window {
        DriftVerdict::Warn(drift_secs)
    } else {
        DriftVerdict::Ok
    }
}

/// Parse an HTTP `Date` header (the server's clock) and compare it to the local
/// clock. Warns on large-but-tolerable drift; errors when drift exceeds the
/// assumed SPA window, since the SPA was almost certainly rejected.
fn check_clock_drift_from_http_date(date: &str) -> Result<()> {
    let server_time = match httpdate::parse_http_date(date) {
        Ok(time) => time,
        Err(_) => {
            // A malformed Date header is not fatal; we just can't measure drift.
            tracing::debug!(date, "could not parse server Date header for drift check");
            return Ok(());
        }
    };
    let drift = clock_drift_seconds(server_time, SystemTime::now());
    match classify_drift(drift, ASSUMED_SPA_WINDOW_SECONDS) {
        DriftVerdict::Ok => Ok(()),
        DriftVerdict::Warn(secs) => {
            eprintln!(
                "WARNING: client clock differs from the server by {secs}s; the SPA window is \
                 ±{ASSUMED_SPA_WINDOW_SECONDS}s. Sync your clock (NTP) to avoid intermittent \
                 SPA rejection."
            );
            Ok(())
        }
        DriftVerdict::Exceeded(secs) => anyhow::bail!(
            "client clock is off by {secs}s, exceeding the ±{ASSUMED_SPA_WINDOW_SECONDS}s SPA \
             window; the SPA was almost certainly rejected by the server. Synchronize the clock \
             (e.g. `sudo timedatectl set-ntp true` or `sudo ntpdate <host>`) and retry."
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn connect_once(
    identity_key: &str,
    server_key: &str,
    spa_endpoint: SocketAddr,
    proxy_endpoint: SocketAddr,
    message: &str,
    spa_mode: SpaTransport,
    https_spa_url: Option<&str>,
    counter_file: Option<&str>,
) -> Result<()> {
    let server_static_pubkey = read_noise_public_key_array(server_key)?;
    send_spa(
        identity_key,
        &server_static_pubkey,
        spa_endpoint,
        spa_mode,
        https_spa_url,
        counter_file,
    )?;
    thread::sleep(Duration::from_millis(150));

    let signing_key = read_signing_key(identity_key)?;
    let key_id = key_id_for_public_key(&signing_key.verifying_key());
    let server_public_key = read_noise_public_key(server_key)?;
    let noise_private_key = derive_noise_static_private_key(&signing_key);
    let params = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
        .parse()
        .context("invalid Noise pattern")?;
    let mut noise = snow::Builder::new(params)
        .local_private_key(&noise_private_key)
        .remote_public_key(&server_public_key)
        .prologue(&key_id)
        .build_initiator()
        .context("failed to build Noise IK initiator")?;

    let mut stream = TcpStream::connect(proxy_endpoint).with_context(|| {
        format!(
            "failed to connect to proxy endpoint {proxy_endpoint}; {}",
            spa_authorization_hint()
        )
    })?;
    let mut buf = vec![0u8; 16 * 1024];
    let len = noise
        .write_message(&[], &mut buf)
        .context("failed to write Noise IK message 1")?;
    write_frame(&mut stream, &buf[..len])?;

    let msg2 = read_frame(&mut stream)?;
    noise
        .read_message(&msg2, &mut buf)
        .context("failed to read Noise IK message 2")?;
    let mut transport = noise
        .into_transport_mode()
        .context("failed to enter Noise transport mode")?;
    println!(
        "NOISE_HANDSHAKE_COMPLETE endpoint={proxy_endpoint} key_id={}",
        key_id_hex(&key_id)
    );

    let len = transport
        .write_message(message.as_bytes(), &mut buf)
        .context("failed to encrypt application frame")?;
    write_frame(&mut stream, &buf[..len])?;

    let encrypted = read_frame(&mut stream)?;
    let len = transport
        .read_message(&encrypted, &mut buf)
        .context("failed to decrypt echo frame")?;
    let echoed = String::from_utf8_lossy(&buf[..len]);
    println!("NOISE_FRAME_ROUND_TRIP bytes={} message={:?}", len, echoed);

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn connect_socks5_once(
    identity_key: &str,
    server_key: &str,
    spa_endpoint: SocketAddr,
    proxy_endpoint: SocketAddr,
    target: &str,
    message: &str,
    spa_mode: SpaTransport,
    https_spa_url: Option<&str>,
    counter_file: Option<&str>,
) -> Result<()> {
    let server_public_key = read_noise_public_key(server_key)?;
    let (mut stream, mut transport, mut buf, key_id) = connect_noise(
        identity_key,
        &server_public_key,
        spa_endpoint,
        proxy_endpoint,
        spa_mode,
        https_spa_url,
        counter_file,
    )?;

    write_encrypted_frame(&mut stream, &mut transport, &[0x05, 0x01, 0x00], &mut buf)?;
    let method = read_encrypted_frame(&mut stream, &mut transport, &mut buf)?;
    if method != [0x05, 0x00] {
        anyhow::bail!("unexpected SOCKS5 method response: {method:?}");
    }

    let request = socks5_connect_request(target)?;
    write_encrypted_frame(&mut stream, &mut transport, &request, &mut buf)?;
    let response = read_encrypted_frame(&mut stream, &mut transport, &mut buf)?;
    if response.len() < 2 || response[0] != 0x05 || response[1] != 0x00 {
        anyhow::bail!("SOCKS5 CONNECT failed: {response:?}");
    }

    println!(
        "SOCKS5_HANDSHAKE_COMPLETE endpoint={proxy_endpoint} target={target} key_id={}",
        key_id_hex(&key_id)
    );

    write_encrypted_frame(&mut stream, &mut transport, message.as_bytes(), &mut buf)?;
    let echoed = read_encrypted_frame(&mut stream, &mut transport, &mut buf)?;
    let echoed = String::from_utf8_lossy(&echoed);
    println!(
        "SOCKS5_FRAME_ROUND_TRIP bytes={} message={:?}",
        echoed.len(),
        echoed
    );

    Ok(())
}

fn connect_ghost_relay_once(
    identity_key: &str,
    server_key: &str,
    spa_endpoint: SocketAddr,
    proxy_endpoint: SocketAddr,
    spa_mode: SpaTransport,
    https_spa_url: Option<&str>,
    counter_file: Option<&str>,
) -> Result<()> {
    let server_public_key = read_noise_public_key(server_key)?;
    let (mut stream, mut transport, mut buf, key_id) = connect_noise(
        identity_key,
        &server_public_key,
        spa_endpoint,
        proxy_endpoint,
        spa_mode,
        https_spa_url,
        counter_file,
    )?;

    write_encrypted_frame(
        &mut stream,
        &mut transport,
        &[PROTOCOL_GHOST_RELAY, GHOST_RELAY_VERSION, 0xff],
        &mut buf,
    )?;
    let response = read_encrypted_frame(&mut stream, &mut transport, &mut buf)?;
    if response.len() < 3
        || response[0] != PROTOCOL_GHOST_RELAY
        || response[2] != GHOST_RELAY_STATUS_UNSUPPORTED
    {
        anyhow::bail!("unexpected Ghost Relay response: {response:?}");
    }

    println!(
        "GHOST_RELAY_UNSUPPORTED endpoint={proxy_endpoint} key_id={}",
        key_id_hex(&key_id)
    );

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn relay_submit_url(
    identity_key: &str,
    server_key: &str,
    spa_endpoint: SocketAddr,
    proxy_endpoint: SocketAddr,
    url: &str,
    normalize: bool,
    spa_mode: SpaTransport,
    https_spa_url: Option<&str>,
    counter_file: Option<&str>,
) -> Result<()> {
    let mut request = relay_request(GHOST_RELAY_OP_SUBMIT_WEB);
    relay_push_string(&mut request, url)?;
    request.push(u8::from(normalize));
    let response = run_relay_request(
        identity_key,
        server_key,
        spa_endpoint,
        proxy_endpoint,
        spa_mode,
        https_spa_url,
        counter_file,
        &request,
    )?;
    let job_id = parse_relay_bytes_response(&response)?;
    println!(
        "GHOST_RELAY_JOB_SUBMITTED job_id={}",
        String::from_utf8_lossy(job_id)
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn relay_submit_git(
    identity_key: &str,
    server_key: &str,
    spa_endpoint: SocketAddr,
    proxy_endpoint: SocketAddr,
    git_url: &str,
    spa_mode: SpaTransport,
    https_spa_url: Option<&str>,
    counter_file: Option<&str>,
) -> Result<()> {
    let mut request = relay_request(GHOST_RELAY_OP_SUBMIT_GIT);
    relay_push_string(&mut request, git_url)?;
    let response = run_relay_request(
        identity_key,
        server_key,
        spa_endpoint,
        proxy_endpoint,
        spa_mode,
        https_spa_url,
        counter_file,
        &request,
    )?;
    let job_id = parse_relay_bytes_response(&response)?;
    println!(
        "GHOST_RELAY_JOB_SUBMITTED job_id={}",
        String::from_utf8_lossy(job_id)
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn relay_submit_package(
    identity_key: &str,
    server_key: &str,
    spa_endpoint: SocketAddr,
    proxy_endpoint: SocketAddr,
    ecosystem: &str,
    name: &str,
    version: &str,
    spa_mode: SpaTransport,
    https_spa_url: Option<&str>,
    counter_file: Option<&str>,
) -> Result<()> {
    let mut request = relay_request(GHOST_RELAY_OP_SUBMIT_PACKAGE);
    relay_push_string(&mut request, ecosystem)?;
    relay_push_string(&mut request, name)?;
    relay_push_string(&mut request, version)?;
    let response = run_relay_request(
        identity_key,
        server_key,
        spa_endpoint,
        proxy_endpoint,
        spa_mode,
        https_spa_url,
        counter_file,
        &request,
    )?;
    let job_id = parse_relay_bytes_response(&response)?;
    println!(
        "GHOST_RELAY_JOB_SUBMITTED job_id={}",
        String::from_utf8_lossy(job_id)
    );
    Ok(())
}

fn relay_list(
    identity_key: &str,
    server_key: &str,
    spa_endpoint: SocketAddr,
    proxy_endpoint: SocketAddr,
    spa_mode: SpaTransport,
    https_spa_url: Option<&str>,
    counter_file: Option<&str>,
) -> Result<()> {
    let request = relay_request(GHOST_RELAY_OP_LIST);
    let response = run_relay_request(
        identity_key,
        server_key,
        spa_endpoint,
        proxy_endpoint,
        spa_mode,
        https_spa_url,
        counter_file,
        &request,
    )?;
    let rows = parse_relay_bytes_response(&response)?;
    println!("GHOST_RELAY_JOBS\n{}", String::from_utf8_lossy(rows));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn relay_download(
    identity_key: &str,
    server_key: &str,
    spa_endpoint: SocketAddr,
    proxy_endpoint: SocketAddr,
    job_id: &str,
    output: &Path,
    artifact: RelayArtifact,
    spa_mode: SpaTransport,
    https_spa_url: Option<&str>,
    counter_file: Option<&str>,
) -> Result<()> {
    let mut offset = 0u32;
    let mut body = Vec::new();
    loop {
        let mut request = relay_request(GHOST_RELAY_OP_DOWNLOAD);
        relay_push_string(&mut request, job_id)?;
        request.extend_from_slice(&offset.to_be_bytes());
        request.extend_from_slice(&(8192u16).to_be_bytes());
        request.push(artifact.selector());
        let response = run_relay_request(
            identity_key,
            server_key,
            spa_endpoint,
            proxy_endpoint,
            spa_mode,
            https_spa_url,
            counter_file,
            &request,
        )?;
        let (terminal, total, chunk) = parse_relay_download_response(&response)?;
        body.extend_from_slice(chunk);
        offset += u32::try_from(chunk.len()).context("relay chunk too large")?;
        if terminal {
            if body.len() != total as usize {
                anyhow::bail!("downloaded {} bytes, expected {total}", body.len());
            }
            break;
        }
    }
    fs::write(output, &body).with_context(|| format!("failed to write {}", output.display()))?;
    println!(
        "GHOST_RELAY_DOWNLOADED job_id={job_id} bytes={} output={}",
        body.len(),
        output.display()
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn relay_delete(
    identity_key: &str,
    server_key: &str,
    spa_endpoint: SocketAddr,
    proxy_endpoint: SocketAddr,
    job_id: &str,
    spa_mode: SpaTransport,
    https_spa_url: Option<&str>,
    counter_file: Option<&str>,
) -> Result<()> {
    let mut request = relay_request(GHOST_RELAY_OP_DELETE);
    relay_push_string(&mut request, job_id)?;
    let response = run_relay_request(
        identity_key,
        server_key,
        spa_endpoint,
        proxy_endpoint,
        spa_mode,
        https_spa_url,
        counter_file,
        &request,
    )?;
    parse_relay_bytes_response(&response)?;
    println!("GHOST_RELAY_DELETED job_id={job_id}");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_relay_request(
    identity_key: &str,
    server_key: &str,
    spa_endpoint: SocketAddr,
    proxy_endpoint: SocketAddr,
    spa_mode: SpaTransport,
    https_spa_url: Option<&str>,
    counter_file: Option<&str>,
    request: &[u8],
) -> Result<Vec<u8>> {
    let server_public_key = read_noise_public_key(server_key)?;
    let (mut stream, mut transport, mut buf, _) = connect_noise(
        identity_key,
        &server_public_key,
        spa_endpoint,
        proxy_endpoint,
        spa_mode,
        https_spa_url,
        counter_file,
    )?;
    write_encrypted_frame(&mut stream, &mut transport, request, &mut buf)?;
    read_encrypted_frame(&mut stream, &mut transport, &mut buf)
}

fn relay_request(op: u8) -> Vec<u8> {
    vec![PROTOCOL_GHOST_RELAY, GHOST_RELAY_VERSION, op]
}

fn relay_push_string(request: &mut Vec<u8>, value: &str) -> Result<()> {
    let len: u16 = value.len().try_into().context("relay string is too long")?;
    request.extend_from_slice(&len.to_be_bytes());
    request.extend_from_slice(value.as_bytes());
    Ok(())
}

fn parse_relay_bytes_response(response: &[u8]) -> Result<&[u8]> {
    if response.len() < 7
        || response[0] != PROTOCOL_GHOST_RELAY
        || response[1] != GHOST_RELAY_VERSION
    {
        anyhow::bail!("invalid Ghost Relay response: {response:?}");
    }
    if response[2] != GHOST_RELAY_STATUS_OK {
        let message = if response.len() >= 7 {
            String::from_utf8_lossy(&response[7..]).into_owned()
        } else {
            format!("status {}", response[2])
        };
        anyhow::bail!("Ghost Relay request failed: {message}");
    }
    let len = u32::from_be_bytes([response[3], response[4], response[5], response[6]]) as usize;
    if response.len() != 7 + len {
        anyhow::bail!("invalid Ghost Relay response length");
    }
    Ok(&response[7..])
}

fn parse_relay_download_response(response: &[u8]) -> Result<(bool, u32, &[u8])> {
    if response.len() < 3
        || response[0] != PROTOCOL_GHOST_RELAY
        || response[1] != GHOST_RELAY_VERSION
    {
        anyhow::bail!("invalid Ghost Relay download response: {response:?}");
    }
    if response[2] == GHOST_RELAY_STATUS_PENDING {
        anyhow::bail!("Ghost Relay job is not ready yet (still queued or running)");
    }
    if response[2] != GHOST_RELAY_STATUS_OK {
        let message = if response.len() > 7 {
            String::from_utf8_lossy(&response[7..]).into_owned()
        } else {
            format!("status {}", response[2])
        };
        anyhow::bail!("Ghost Relay download failed: {message}");
    }
    if response.len() < 12 {
        anyhow::bail!("truncated Ghost Relay download response");
    }
    let terminal = response[3] != 0;
    let total = u32::from_be_bytes([response[4], response[5], response[6], response[7]]);
    let len = u32::from_be_bytes([response[8], response[9], response[10], response[11]]) as usize;
    if response.len() != 12 + len {
        anyhow::bail!("invalid Ghost Relay download length");
    }
    Ok((terminal, total, &response[12..]))
}

fn connect_listener(
    identity_key: String,
    candidates: Vec<ResolvedConnectConfig>,
    policy: FailoverPolicy,
    listen: SocketAddr,
    allow_ttl_seconds: u64,
    counter_file: Option<String>,
) -> Result<()> {
    if candidates.is_empty() {
        anyhow::bail!("no server candidates configured");
    }
    let listener = TcpListener::bind(listen)
        .with_context(|| format!("failed to bind local SOCKS5 listener on {listen}"))?;
    let counter_lock = Arc::new(Mutex::new(()));
    let candidates = Arc::new(candidates);
    let active_candidate = Arc::new(Mutex::new(None));
    println!(
        "SOCKS5_LISTEN listen={listen} servers={} failover={:?} max_retries={}",
        candidates.len(),
        policy.strategy,
        policy.max_retries
    );
    start_spa_refresh(
        identity_key.clone(),
        candidates.clone(),
        active_candidate.clone(),
        counter_file.clone(),
        counter_lock.clone(),
        allow_ttl_seconds,
    )?;

    loop {
        let (local_stream, peer_addr) =
            listener.accept().context("failed to accept local SOCKS5")?;
        println!("SOCKS5_LOCAL_ACCEPT peer={peer_addr}");
        let identity_key = identity_key.clone();
        let counter_file = counter_file.clone();
        let counter_lock = counter_lock.clone();
        let candidates = candidates.clone();
        let active_candidate = active_candidate.clone();
        thread::spawn(move || {
            if let Err(error) = handle_local_socks5(
                local_stream,
                &identity_key,
                &candidates,
                policy,
                counter_file.as_deref(),
                &counter_lock,
                &active_candidate,
            ) {
                eprintln!("SOCKS5_LOCAL_REJECT peer={peer_addr} error={error:#}");
            }
        });
    }
}

fn start_spa_refresh(
    identity_key: String,
    candidates: Arc<Vec<ResolvedConnectConfig>>,
    active_candidate: Arc<Mutex<Option<usize>>>,
    counter_file: Option<String>,
    counter_lock: Arc<Mutex<()>>,
    allow_ttl_seconds: u64,
) -> Result<()> {
    let interval = refresh_interval(allow_ttl_seconds)?;

    thread::spawn(move || loop {
        let candidate_index = *active_candidate
            .lock()
            .expect("active candidate lock poisoned");
        if let Some(candidate_index) = candidate_index {
            if let Some(candidate) = candidates.get(candidate_index) {
                let result = {
                    let _counter_guard = counter_lock.lock().expect("counter lock poisoned");
                    match <[u8; 32]>::try_from(candidate.server_public_key.as_slice()) {
                        Ok(server_static_pubkey) => send_spa(
                            &identity_key,
                            &server_static_pubkey,
                            candidate.spa_endpoint,
                            candidate.spa_mode,
                            candidate.https_spa_url.as_deref(),
                            counter_file.as_deref(),
                        ),
                        Err(_) => Err(anyhow::anyhow!(
                            "server Noise public key must be 32 bytes"
                        )),
                    }
                };

                match result {
                    Ok(()) => println!(
                        "SPA_REFRESH_SENT endpoint={} mode={:?} next_refresh_seconds={}",
                        candidate.proxy_endpoint,
                        candidate.spa_mode,
                        interval.as_secs()
                    ),
                    Err(error) => eprintln!(
                        "SPA_REFRESH_FAILED endpoint={} mode={:?} error={error:#}",
                        candidate.proxy_endpoint, candidate.spa_mode
                    ),
                }
            }
        }

        thread::sleep(interval);
    });

    Ok(())
}

fn refresh_interval(allow_ttl_seconds: u64) -> Result<Duration> {
    if allow_ttl_seconds < 2 {
        anyhow::bail!("--allow-ttl-seconds must be at least 2");
    }

    Ok(Duration::from_secs(allow_ttl_seconds / 2))
}

#[allow(clippy::too_many_arguments)]
fn handle_local_socks5(
    local_stream: TcpStream,
    identity_key: &str,
    candidates: &[ResolvedConnectConfig],
    policy: FailoverPolicy,
    counter_file: Option<&str>,
    counter_lock: &Arc<Mutex<()>>,
    active_candidate: &Arc<Mutex<Option<usize>>>,
) -> Result<()> {
    let (local_stream, proxy_stream, transport, target, key_id, proxy_endpoint) =
        negotiate_local_socks5_tunnel(
            local_stream,
            identity_key,
            candidates,
            policy,
            counter_file,
            counter_lock,
            active_candidate,
        )?;

    println!(
        "SOCKS5_TUNNEL_OPEN endpoint={proxy_endpoint} target={target} key_id={}",
        key_id_hex(&key_id)
    );
    relay_local_socks5(local_stream, proxy_stream, transport)?;
    println!("SOCKS5_TUNNEL_CLOSED target={target}");

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn negotiate_local_socks5_tunnel(
    local_stream: TcpStream,
    identity_key: &str,
    candidates: &[ResolvedConnectConfig],
    policy: FailoverPolicy,
    counter_file: Option<&str>,
    counter_lock: &Arc<Mutex<()>>,
    active_candidate: &Arc<Mutex<Option<usize>>>,
) -> Result<(
    TcpStream,
    TcpStream,
    snow::TransportState,
    String,
    ghostbro_common::keys::KeyId,
    SocketAddr,
)> {
    local_stream
        .set_nonblocking(true)
        .context("failed to set local SOCKS5 stream nonblocking")?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .context("failed to build local SOCKS5 runtime")?;

    runtime.block_on(async move {
        let local_stream = tokio::net::TcpStream::from_std(local_stream)
            .context("failed to wrap local SOCKS5 stream for fast-socks5")?;
        let proto = Socks5ServerProtocol::accept_no_auth(local_stream)
            .await
            .context("failed local SOCKS5 no-auth negotiation")?;

        let (proto, command, target) = proto
            .read_command()
            .await
            .context("failed to read local SOCKS5 command")?;
        if command != Socks5Command::TCPConnect {
            proto
                .reply_error(&ReplyError::CommandNotSupported)
                .await
                .context("failed to reject unsupported local SOCKS5 command")?;
            anyhow::bail!("only SOCKS5 CONNECT is supported");
        }

        let target_label = target.to_string();
        let mut request = vec![0x05, 0x01, 0x00];
        request.extend_from_slice(
            &target
                .to_be_bytes()
                .context("failed to encode local SOCKS5 target")?,
        );

        let (mut proxy_stream, mut transport, mut buf, key_id, candidate_index, proxy_endpoint) = {
            let _counter_guard = counter_lock.lock().expect("counter lock poisoned");
            connect_noise_with_failover(identity_key, candidates, policy, counter_file)?
        };
        *active_candidate
            .lock()
            .expect("active candidate lock poisoned") = Some(candidate_index);

        write_encrypted_frame(
            &mut proxy_stream,
            &mut transport,
            &[0x05, 0x01, 0x00],
            &mut buf,
        )?;
        let method = read_encrypted_frame(&mut proxy_stream, &mut transport, &mut buf)?;
        if method != [0x05, 0x00] {
            proto
                .reply_error(&ReplyError::GeneralFailure)
                .await
                .context("failed to reject local SOCKS5 after remote method failure")?;
            anyhow::bail!("unexpected remote SOCKS5 method response: {method:?}");
        }

        write_encrypted_frame(&mut proxy_stream, &mut transport, &request, &mut buf)?;
        let response = read_encrypted_frame(&mut proxy_stream, &mut transport, &mut buf)?;
        if response.len() < 2 || response[0] != 0x05 || response[1] != 0x00 {
            proto
                .reply_error(&socks5_reply_error(&response))
                .await
                .context("failed to write local SOCKS5 CONNECT error")?;
            anyhow::bail!("remote SOCKS5 CONNECT failed: {response:?}");
        }

        let local_stream = proto
            .reply_success("127.0.0.1:0".parse().expect("valid SOCKS5 reply address"))
            .await
            .context("failed to write local SOCKS5 CONNECT response")?
            .into_std()
            .context("failed to convert local SOCKS5 stream back to std")?;
        local_stream
            .set_nonblocking(false)
            .context("failed to restore local SOCKS5 blocking mode")?;

        Ok((
            local_stream,
            proxy_stream,
            transport,
            target_label,
            key_id,
            proxy_endpoint,
        ))
    })
}

fn socks5_reply_error(response: &[u8]) -> ReplyError {
    match response.get(1).copied() {
        Some(0x02) => ReplyError::ConnectionNotAllowed,
        Some(0x03) => ReplyError::NetworkUnreachable,
        Some(0x04) => ReplyError::HostUnreachable,
        Some(0x05) => ReplyError::ConnectionRefused,
        Some(0x06) => ReplyError::TtlExpired,
        Some(0x07) => ReplyError::CommandNotSupported,
        Some(0x08) => ReplyError::AddressTypeNotSupported,
        _ => ReplyError::GeneralFailure,
    }
}

fn relay_local_socks5(
    local_stream: TcpStream,
    proxy_stream: TcpStream,
    transport: snow::TransportState,
) -> Result<()> {
    let mut local_reader = local_stream
        .try_clone()
        .context("failed to clone local SOCKS5 stream")?;
    let mut local_writer = local_stream;
    let mut proxy_reader = proxy_stream
        .try_clone()
        .context("failed to clone proxy stream")?;
    let mut proxy_writer = proxy_stream;
    let transport = Arc::new(Mutex::new(transport));

    let client_transport = transport.clone();
    let client_to_proxy = thread::spawn(move || -> Result<usize> {
        let mut total = 0usize;
        let mut read_buf = vec![0u8; 16 * 1024 - 16];
        let mut noise_buf = vec![0u8; 16 * 1024];
        loop {
            let len = local_reader
                .read(&mut read_buf)
                .context("failed to read local SOCKS5 payload")?;
            if len == 0 {
                break;
            }
            write_encrypted_frame_locked(
                &mut proxy_writer,
                &client_transport,
                &read_buf[..len],
                &mut noise_buf,
            )?;
            total = total.saturating_add(len);
        }
        let _ = proxy_writer.shutdown(std::net::Shutdown::Write);
        Ok(total)
    });

    let proxy_to_client = thread::spawn(move || -> Result<usize> {
        let mut total = 0usize;
        let mut noise_buf = vec![0u8; 16 * 1024];
        while let Some(plaintext) =
            read_encrypted_frame_optional_locked(&mut proxy_reader, &transport, &mut noise_buf)?
        {
            if plaintext.is_empty() {
                break;
            }
            local_writer
                .write_all(&plaintext)
                .context("failed to write local SOCKS5 response payload")?;
            total = total.saturating_add(plaintext.len());
        }
        let _ = local_writer.shutdown(std::net::Shutdown::Write);
        Ok(total)
    });

    let client_bytes = client_to_proxy
        .join()
        .map_err(|_| anyhow::anyhow!("client-to-proxy relay thread panicked"))??;
    let proxy_bytes = proxy_to_client
        .join()
        .map_err(|_| anyhow::anyhow!("proxy-to-client relay thread panicked"))??;
    println!("SOCKS5_RELAY_CLOSED client_to_proxy_bytes={client_bytes} proxy_to_client_bytes={proxy_bytes}");

    Ok(())
}

fn connect_noise(
    identity_key: &str,
    server_public_key: &[u8],
    spa_endpoint: SocketAddr,
    proxy_endpoint: SocketAddr,
    spa_mode: SpaTransport,
    https_spa_url: Option<&str>,
    counter_file: Option<&str>,
) -> Result<(
    TcpStream,
    snow::TransportState,
    Vec<u8>,
    ghostbro_common::keys::KeyId,
)> {
    let server_static_pubkey: [u8; 32] = server_public_key
        .try_into()
        .context("server Noise public key must be 32 bytes")?;
    send_spa(
        identity_key,
        &server_static_pubkey,
        spa_endpoint,
        spa_mode,
        https_spa_url,
        counter_file,
    )?;
    thread::sleep(Duration::from_millis(150));

    let signing_key = read_signing_key(identity_key)?;
    let key_id = key_id_for_public_key(&signing_key.verifying_key());
    let noise_private_key = derive_noise_static_private_key(&signing_key);
    let params = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
        .parse()
        .context("invalid Noise pattern")?;
    let mut noise = snow::Builder::new(params)
        .local_private_key(&noise_private_key)
        .remote_public_key(server_public_key)
        .prologue(&key_id)
        .build_initiator()
        .context("failed to build Noise IK initiator")?;

    let mut stream = TcpStream::connect(proxy_endpoint).with_context(|| {
        format!(
            "failed to connect to proxy endpoint {proxy_endpoint}; {}",
            spa_authorization_hint()
        )
    })?;
    let mut buf = vec![0u8; 16 * 1024];
    let len = noise
        .write_message(&[], &mut buf)
        .context("failed to write Noise IK message 1")?;
    write_frame(&mut stream, &buf[..len])?;

    let msg2 = read_frame(&mut stream)?;
    noise
        .read_message(&msg2, &mut buf)
        .context("failed to read Noise IK message 2")?;
    let transport = noise
        .into_transport_mode()
        .context("failed to enter Noise transport mode")?;
    println!(
        "NOISE_HANDSHAKE_COMPLETE endpoint={proxy_endpoint} key_id={}",
        key_id_hex(&key_id)
    );

    Ok((stream, transport, buf, key_id))
}

fn connect_noise_with_failover(
    identity_key: &str,
    candidates: &[ResolvedConnectConfig],
    policy: FailoverPolicy,
    counter_file: Option<&str>,
) -> Result<(
    TcpStream,
    snow::TransportState,
    Vec<u8>,
    ghostbro_common::keys::KeyId,
    usize,
    SocketAddr,
)> {
    if candidates.is_empty() {
        anyhow::bail!("no server candidates configured");
    }

    let rounds = policy.max_retries.saturating_add(1);
    let mut last_error = None;
    for round in 0..rounds {
        // Re-derive the order each round so `random` reshuffles and `latency`
        // re-probes with fresh measurements.
        let order = order_candidates(policy.strategy, candidates);
        for (position, &index) in order.iter().enumerate() {
            let candidate = &candidates[index];
            match connect_noise(
                identity_key,
                &candidate.server_public_key,
                candidate.spa_endpoint,
                candidate.proxy_endpoint,
                candidate.spa_mode,
                candidate.https_spa_url.as_deref(),
                counter_file,
            ) {
                Ok((stream, transport, buf, key_id)) => {
                    if !(round == 0 && position == 0) {
                        println!(
                            "CONNECT_FAILOVER_SELECTED endpoint={} index={index} round={round} strategy={:?}",
                            candidate.proxy_endpoint, policy.strategy
                        );
                    }
                    return Ok((stream, transport, buf, key_id, index, candidate.proxy_endpoint));
                }
                Err(error) => {
                    eprintln!(
                        "CONNECT_CANDIDATE_FAILED endpoint={} index={index} round={round} error={error:#}",
                        candidate.proxy_endpoint
                    );
                    last_error = Some(error);
                }
            }
        }

        if round + 1 < rounds {
            eprintln!(
                "CONNECT_RETRY round={} of {} retry_in_ms={}",
                round + 1,
                rounds - 1,
                policy.retry_interval.as_millis()
            );
            thread::sleep(policy.retry_interval);
        }
    }

    match last_error {
        Some(error) => Err(error).context(format!(
            "all configured servers failed after {rounds} round(s); {}",
            spa_authorization_hint()
        )),
        None => anyhow::bail!("no server candidates configured"),
    }
}

/// Order candidate indices for one connection round per the failover strategy.
/// Candidates arrive in priority order, so `priority` is the identity order.
fn order_candidates(strategy: FailoverStrategy, candidates: &[ResolvedConnectConfig]) -> Vec<usize> {
    match strategy {
        FailoverStrategy::Priority => (0..candidates.len()).collect(),
        FailoverStrategy::Random => {
            let mut order: Vec<usize> = (0..candidates.len()).collect();
            order.shuffle(&mut rand::thread_rng());
            order
        }
        FailoverStrategy::Latency => {
            let latencies: Vec<Option<Duration>> = candidates
                .iter()
                .map(|candidate| probe_latency(candidate.proxy_endpoint))
                .collect();
            order_by_latency(&latencies)
        }
    }
}

/// Stable-sort candidate indices by ascending probed latency. Unreachable
/// candidates (`None`) sort last; ties preserve the input (priority) order.
fn order_by_latency(latencies: &[Option<Duration>]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..latencies.len()).collect();
    order.sort_by_key(|&index| latencies[index].unwrap_or(Duration::MAX));
    order
}

/// Time a TCP connect to `endpoint`, returning the round-trip duration or
/// `None` if it failed/timed out within [`LATENCY_PROBE_TIMEOUT`].
fn probe_latency(endpoint: SocketAddr) -> Option<Duration> {
    let start = Instant::now();
    match std::net::TcpStream::connect_timeout(&endpoint, LATENCY_PROBE_TIMEOUT) {
        Ok(_) => Some(start.elapsed()),
        Err(_) => None,
    }
}

fn spa_authorization_hint() -> String {
    // In UDP SPA mode there is no server response to measure drift against, so
    // surface the client's current UTC time for the operator to eyeball against
    // a trusted clock.
    let now_utc = httpdate::fmt_http_date(SystemTime::now());
    format!(
        "if SPA was sent but the proxy stayed closed, verify the client and server clocks are \
         synchronized within the SPA time_window (default ±{DEFAULT_TIME_WINDOW_SECONDS}s); \
         client UTC now is {now_utc}"
    )
}

fn send_spa(
    identity_key: &str,
    server_static_pubkey: &[u8; 32],
    spa_endpoint: SocketAddr,
    spa_mode: SpaTransport,
    https_spa_url: Option<&str>,
    counter_file: Option<&str>,
) -> Result<()> {
    match spa_mode {
        SpaTransport::Udp => {
            send_udp_spa(identity_key, server_static_pubkey, spa_endpoint, counter_file)
        }
        SpaTransport::Https => {
            let url = https_spa_url.context("--https-spa-url is required when --spa-mode https")?;
            send_https_spa(identity_key, server_static_pubkey, url, counter_file)
        }
    }
}

fn socks5_connect_request(target: &str) -> Result<Vec<u8>> {
    if let Ok(addr) = target.parse::<SocketAddr>() {
        let mut request = vec![0x05, 0x01, 0x00];
        match addr {
            SocketAddr::V4(addr) => {
                request.push(0x01);
                request.extend_from_slice(&addr.ip().octets());
            }
            SocketAddr::V6(addr) => {
                request.push(0x04);
                request.extend_from_slice(&addr.ip().octets());
            }
        }
        request.extend_from_slice(&addr.port().to_be_bytes());
        return Ok(request);
    }

    let (domain, port) = target
        .rsplit_once(':')
        .context("domain SOCKS5 target must be host:port")?;
    if domain.is_empty() {
        anyhow::bail!("SOCKS5 target domain is empty");
    }
    let domain_len: u8 = domain
        .len()
        .try_into()
        .context("SOCKS5 target domain is too long")?;
    let port = port
        .parse::<u16>()
        .with_context(|| format!("invalid SOCKS5 target port in {target}"))?;

    let mut request = vec![0x05, 0x01, 0x00, 0x03, domain_len];
    request.extend_from_slice(domain.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    Ok(request)
}

fn read_encrypted_frame(
    stream: &mut TcpStream,
    transport: &mut snow::TransportState,
    buf: &mut [u8],
) -> Result<Vec<u8>> {
    let encrypted = read_frame(stream)?;
    let len = transport
        .read_message(&encrypted, buf)
        .context("failed to decrypt Noise application frame")?;
    Ok(buf[..len].to_vec())
}

fn write_encrypted_frame(
    stream: &mut TcpStream,
    transport: &mut snow::TransportState,
    plaintext: &[u8],
    buf: &mut [u8],
) -> Result<()> {
    let len = transport
        .write_message(plaintext, buf)
        .context("failed to encrypt Noise application frame")?;
    write_frame(stream, &buf[..len])
}

fn read_encrypted_frame_optional_locked(
    stream: &mut TcpStream,
    transport: &Arc<Mutex<snow::TransportState>>,
    buf: &mut [u8],
) -> Result<Option<Vec<u8>>> {
    let Some(encrypted) = read_frame_optional(stream)? else {
        return Ok(None);
    };
    let len = {
        let mut transport = transport.lock().expect("Noise transport lock poisoned");
        transport
            .read_message(&encrypted, buf)
            .context("failed to decrypt Noise application frame")?
    };
    Ok(Some(buf[..len].to_vec()))
}

fn write_encrypted_frame_locked(
    stream: &mut TcpStream,
    transport: &Arc<Mutex<snow::TransportState>>,
    plaintext: &[u8],
    buf: &mut [u8],
) -> Result<()> {
    let len = {
        let mut transport = transport.lock().expect("Noise transport lock poisoned");
        transport
            .write_message(plaintext, buf)
            .context("failed to encrypt Noise application frame")?
    };
    write_frame(stream, &buf[..len])
}

fn read_noise_public_key(path: impl AsRef<Path>) -> Result<Vec<u8>> {
    let path = path.as_ref();
    let encoded = fs::read_to_string(path)
        .with_context(|| format!("failed to read server Noise public key {}", path.display()))?;
    decode_noise_public_key(encoded.trim()).with_context(|| {
        format!(
            "failed to decode server Noise public key {}",
            path.display()
        )
    })
}

/// Read the server's Noise public key as a fixed 32-byte array, for binding into
/// SPA signatures (authenticated associated data, not transmitted on the wire).
fn read_noise_public_key_array(path: impl AsRef<Path>) -> Result<[u8; 32]> {
    let key = read_noise_public_key(path)?;
    key.as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("server Noise public key must be 32 bytes, got {}", key.len()))
}

fn decode_noise_public_key(encoded: &str) -> Result<Vec<u8>> {
    let key = STANDARD
        .decode(encoded.trim())
        .context("failed to decode Noise public key as base64")?;
    if key.len() != 32 {
        anyhow::bail!("Noise public key must be 32 bytes, got {}", key.len());
    }
    Ok(key)
}

fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    read_frame_optional(stream)?.context("connection closed while reading frame length")
}

fn read_frame_optional(stream: &mut TcpStream) -> Result<Option<Vec<u8>>> {
    let mut len = [0u8; 2];
    if let Err(error) = stream.read_exact(&mut len) {
        if error.kind() == ErrorKind::UnexpectedEof {
            return Ok(None);
        }
        return Err(error).context("failed to read frame length");
    }
    let len = usize::from(u16::from_be_bytes(len));
    let mut frame = vec![0u8; len];
    stream
        .read_exact(&mut frame)
        .context("failed to read frame")?;
    Ok(Some(frame))
}

fn write_frame(stream: &mut TcpStream, frame: &[u8]) -> Result<()> {
    let len: u16 = frame
        .len()
        .try_into()
        .context("frame too large for 2-byte length")?;
    stream
        .write_all(&len.to_be_bytes())
        .context("failed to write frame length")?;
    stream.write_all(frame).context("failed to write frame")?;
    Ok(())
}

fn prompt_new_passphrase() -> Result<String> {
    let passphrase = rpassword::prompt_password("identity passphrase: ")?;
    let confirm = rpassword::prompt_password("confirm identity passphrase: ")?;
    if passphrase != confirm {
        anyhow::bail!("identity passphrases do not match");
    }
    if passphrase.is_empty() {
        anyhow::bail!("identity passphrase must not be empty");
    }
    Ok(passphrase)
}

fn prompt_existing_passphrase(path: &Path) -> Result<String> {
    rpassword::prompt_password(format!("identity passphrase for {}: ", path.display()))
        .context("failed to read identity passphrase")
}

fn write_private_key_file(
    path: impl AsRef<Path>,
    contents: impl AsRef<[u8]>,
) -> std::io::Result<()> {
    let path = path.as_ref();
    #[cfg(unix)]
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(contents.as_ref())?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        fs::write(path, contents)
    }
}

fn encrypt_signing_key(
    signing_key: &ed25519_dalek::SigningKey,
    passphrase: &str,
) -> Result<String> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    encrypt_signing_key_with_salt_nonce(signing_key, passphrase, &salt, &nonce)
}

fn encrypt_signing_key_with_salt_nonce(
    signing_key: &ed25519_dalek::SigningKey,
    passphrase: &str,
    salt: &[u8],
    nonce: &[u8],
) -> Result<String> {
    if nonce.len() != NONCE_LEN {
        anyhow::bail!("identity key nonce must be {NONCE_LEN} bytes");
    }
    let key = derive_identity_key(passphrase, salt)?;
    let cipher = ChaCha20Poly1305::new((&key).into());
    let nonce = Nonce::from_slice(nonce);
    let ciphertext = cipher
        .encrypt(nonce, signing_key.to_bytes().as_slice())
        .map_err(|_| anyhow::anyhow!("failed to encrypt identity key"))?;
    let identity = EncryptedIdentityKey {
        version: IDENTITY_KEY_VERSION,
        kdf: IDENTITY_KEY_KDF.to_owned(),
        aead: IDENTITY_KEY_AEAD.to_owned(),
        params: EncryptedIdentityParams {
            memory_kib: ARGON2_MEMORY_KIB,
            iterations: ARGON2_ITERATIONS,
            parallelism: ARGON2_PARALLELISM,
        },
        salt: STANDARD.encode(salt),
        nonce: STANDARD.encode(nonce),
        ciphertext: STANDARD.encode(ciphertext),
    };
    toml::to_string_pretty(&identity).context("failed to serialize encrypted identity key")
}

fn decrypt_signing_key(
    identity: &EncryptedIdentityKey,
    passphrase: &str,
) -> Result<ed25519_dalek::SigningKey> {
    if identity.version != IDENTITY_KEY_VERSION {
        anyhow::bail!(
            "unsupported encrypted identity key version {}",
            identity.version
        );
    }
    if identity.kdf != IDENTITY_KEY_KDF {
        anyhow::bail!("unsupported encrypted identity key KDF {}", identity.kdf);
    }
    if identity.aead != IDENTITY_KEY_AEAD {
        anyhow::bail!("unsupported encrypted identity key AEAD {}", identity.aead);
    }
    if identity.params.memory_kib != ARGON2_MEMORY_KIB
        || identity.params.iterations != ARGON2_ITERATIONS
        || identity.params.parallelism != ARGON2_PARALLELISM
    {
        anyhow::bail!("unsupported encrypted identity key argon2id parameters");
    }

    let salt = STANDARD
        .decode(&identity.salt)
        .context("encrypted identity key has invalid base64 salt")?;
    let nonce = STANDARD
        .decode(&identity.nonce)
        .context("encrypted identity key has invalid base64 nonce")?;
    let ciphertext = STANDARD
        .decode(&identity.ciphertext)
        .context("encrypted identity key has invalid base64 ciphertext")?;
    if nonce.len() != NONCE_LEN {
        anyhow::bail!("encrypted identity key nonce must be {NONCE_LEN} bytes");
    }

    let key = derive_identity_key(passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new((&key).into());
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_slice())
        .map_err(|_| {
            anyhow::anyhow!("failed to decrypt identity key: bad passphrase or corrupt key file")
        })?;
    let bytes: [u8; 32] = plaintext.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!(
            "decrypted identity key must be 32 bytes, got {}",
            bytes.len()
        )
    })?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&bytes))
}

fn derive_identity_key(passphrase: &str, salt: &[u8]) -> Result<[u8; ARGON2_KEY_LEN]> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(ARGON2_KEY_LEN),
    )
    .map_err(|error| anyhow::anyhow!("invalid argon2id parameters: {error}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; ARGON2_KEY_LEN];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|error| anyhow::anyhow!("failed to derive identity encryption key: {error}"))?;
    Ok(key)
}

fn read_signing_key(path: impl AsRef<Path>) -> Result<ed25519_dalek::SigningKey> {
    let path = path.as_ref();
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read identity key {}", path.display()))?;
    match toml::from_str::<EncryptedIdentityKey>(&contents) {
        Ok(identity) => {
            let passphrase = prompt_existing_passphrase(path)?;
            decrypt_signing_key(&identity, &passphrase)
                .with_context(|| format!("failed to decrypt identity key {}", path.display()))
        }
        Err(_) => decode_signing_key(contents.trim()).with_context(|| {
            format!(
                "failed to decode legacy plaintext identity key {}",
                path.display()
            )
        }),
    }
}

fn increment_counter(path: impl AsRef<Path>) -> Result<u64> {
    let path = path.as_ref();
    let current = match fs::read_to_string(path) {
        Ok(contents) => contents
            .trim()
            .parse::<u64>()
            .with_context(|| format!("failed to parse counter file {} as u64", path.display()))?,
        Err(error) if error.kind() == ErrorKind::NotFound => 0,
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", path.display()))
        }
    };

    let next = current.saturating_add(1);
    fs::write(path, format!("{next}\n"))
        .with_context(|| format!("failed to write counter file {}", path.display()))?;
    Ok(next)
}

fn default_counter_path(identity_key: &str) -> PathBuf {
    let path = Path::new(identity_key);
    if path.extension().is_some_and(|extension| extension == "key") {
        path.with_extension("counter")
    } else {
        PathBuf::from(format!("{identity_key}.counter"))
    }
}

fn unix_timestamp_ms() -> Result<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?;
    Ok(duration.as_millis().try_into().unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drift_is_signed_local_minus_server() {
        let server = UNIX_EPOCH + Duration::from_secs(1_000_000);
        assert_eq!(
            100,
            clock_drift_seconds(server, server + Duration::from_secs(100))
        );
        assert_eq!(
            -100,
            clock_drift_seconds(server, server - Duration::from_secs(100))
        );
    }

    #[test]
    fn classifies_drift_against_window() {
        // Comfortable.
        assert_eq!(DriftVerdict::Ok, classify_drift(10, 300));
        // Within window but past the half-window warn threshold.
        assert_eq!(DriftVerdict::Warn(200), classify_drift(200, 300));
        assert_eq!(DriftVerdict::Warn(-200), classify_drift(-200, 300));
        // Beyond the window.
        assert_eq!(DriftVerdict::Exceeded(400), classify_drift(400, 300));
        assert_eq!(DriftVerdict::Exceeded(-400), classify_drift(-400, 300));
    }

    #[test]
    fn drift_check_errors_when_clock_far_off() {
        // A Date far in the past versus the (current) local clock exceeds the window.
        let result = check_clock_drift_from_http_date("Wed, 21 Oct 2015 07:28:00 GMT");
        assert!(result.is_err());
        let message = result.unwrap_err().to_string();
        assert!(message.contains("SPA window"), "message was: {message}");
    }

    #[test]
    fn drift_check_passes_for_current_time() {
        let now = httpdate::fmt_http_date(SystemTime::now());
        assert!(check_clock_drift_from_http_date(&now).is_ok());
    }

    #[test]
    fn drift_check_ignores_malformed_date() {
        assert!(check_clock_drift_from_http_date("not a date").is_ok());
    }

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "ghostbro-{name}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ))
    }

    #[test]
    fn increments_missing_counter_from_one() {
        let path = temp_path("counter");

        assert_eq!(1, increment_counter(&path).expect("first increment"));
        assert_eq!(2, increment_counter(&path).expect("second increment"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn encrypted_identity_key_round_trips() {
        let signing_key = generate_ed25519_keypair();
        let encoded = encrypt_signing_key_with_salt_nonce(
            &signing_key,
            "correct horse battery staple",
            &[7u8; SALT_LEN],
            &[9u8; NONCE_LEN],
        )
        .expect("encrypts");
        let identity: EncryptedIdentityKey = toml::from_str(&encoded).expect("encrypted toml");

        let decoded = decrypt_signing_key(&identity, "correct horse battery staple")
            .expect("decrypts with correct passphrase");

        assert_eq!(signing_key.to_bytes(), decoded.to_bytes());
        assert_eq!(IDENTITY_KEY_VERSION, identity.version);
        assert_eq!(IDENTITY_KEY_KDF, identity.kdf);
        assert_eq!(IDENTITY_KEY_AEAD, identity.aead);
        assert_eq!(ARGON2_MEMORY_KIB, identity.params.memory_kib);
        assert_eq!(ARGON2_ITERATIONS, identity.params.iterations);
        assert_eq!(ARGON2_PARALLELISM, identity.params.parallelism);
    }

    #[test]
    fn encrypted_identity_key_rejects_wrong_passphrase() {
        let signing_key = generate_ed25519_keypair();
        let encoded = encrypt_signing_key_with_salt_nonce(
            &signing_key,
            "right passphrase",
            &[1u8; SALT_LEN],
            &[2u8; NONCE_LEN],
        )
        .expect("encrypts");
        let identity: EncryptedIdentityKey = toml::from_str(&encoded).expect("encrypted toml");

        let error = decrypt_signing_key(&identity, "wrong passphrase").expect_err("rejects");

        assert!(error.to_string().contains("bad passphrase"));
    }

    #[test]
    fn legacy_plaintext_identity_key_still_loads() {
        let signing_key = generate_ed25519_keypair();
        let path = temp_path("legacy-key");
        fs::write(&path, format!("{}\n", encode_signing_key(&signing_key))).expect("write key");

        let loaded = read_signing_key(&path).expect("loads legacy key");

        assert_eq!(signing_key.to_bytes(), loaded.to_bytes());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn keygen_plaintext_debug_writes_legacy_identity_key() {
        let prefix = temp_path("debug-identity");
        keygen(prefix.to_str().expect("utf8 path"), true).expect("keygen succeeds");
        let key_path = prefix.with_extension("key");
        let pub_path = prefix.with_extension("pub");
        let key_id_path = prefix.with_extension("keyid");
        let noise_path = prefix.with_extension("noise");
        let counter_path = prefix.with_extension("counter");

        let loaded = read_signing_key(&key_path).expect("loads plaintext debug key");

        assert_eq!(32, loaded.to_bytes().len());
        assert!(pub_path.exists());
        assert!(key_id_path.exists());
        assert!(noise_path.exists());
        assert!(counter_path.exists());
        let _ = fs::remove_file(key_path);
        let _ = fs::remove_file(pub_path);
        let _ = fs::remove_file(key_id_path);
        let _ = fs::remove_file(noise_path);
        let _ = fs::remove_file(counter_path);
    }

    #[test]
    fn server_keygen_writes_noise_identity_files() {
        let prefix = temp_path("server-identity");
        server_keygen(prefix.to_str().expect("utf8 path")).expect("server keygen succeeds");
        let key_path = prefix.with_extension("key");
        let pub_path = prefix.with_extension("pub");

        let private_key = fs::read_to_string(&key_path).expect("private key readable");
        let public_key = fs::read_to_string(&pub_path).expect("public key readable");

        assert_eq!(
            32,
            STANDARD
                .decode(private_key.trim())
                .expect("private key base64")
                .len()
        );
        assert_eq!(
            32,
            STANDARD
                .decode(public_key.trim())
                .expect("public key base64")
                .len()
        );
        let _ = fs::remove_file(key_path);
        let _ = fs::remove_file(pub_path);
    }

    #[cfg(unix)]
    #[test]
    fn private_key_files_are_user_only_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let prefix = temp_path("private-mode");
        keygen(prefix.to_str().expect("utf8 path"), true).expect("keygen succeeds");
        let key_path = prefix.with_extension("key");

        let mode = fs::metadata(&key_path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(0o600, mode);
        let _ = fs::remove_file(key_path);
        let _ = fs::remove_file(prefix.with_extension("pub"));
        let _ = fs::remove_file(prefix.with_extension("keyid"));
        let _ = fs::remove_file(prefix.with_extension("noise"));
        let _ = fs::remove_file(prefix.with_extension("counter"));
    }

    #[test]
    fn default_counter_path_matches_keygen_output() {
        assert_eq!(
            PathBuf::from("identity.counter"),
            default_counter_path("identity.key")
        );
        assert_eq!(
            PathBuf::from("identity.debug.counter"),
            default_counter_path("identity.debug")
        );
    }

    #[test]
    fn refresh_interval_is_half_allow_ttl() {
        assert_eq!(
            Duration::from_secs(7_200),
            refresh_interval(14_400).expect("valid ttl")
        );
        assert!(refresh_interval(1).is_err());
    }

    #[test]
    fn maps_socks5_reply_errors_from_remote_response() {
        assert!(matches!(
            socks5_reply_error(&[0x05, 0x07]),
            ReplyError::CommandNotSupported
        ));
        assert!(matches!(
            socks5_reply_error(&[0x05, 0x08]),
            ReplyError::AddressTypeNotSupported
        ));
        assert!(matches!(
            socks5_reply_error(&[0x05, 0x99]),
            ReplyError::GeneralFailure
        ));
    }

    #[test]
    fn orders_servers_by_priority_for_failover() {
        let config = ClientConfig {
            servers: vec![
                ServerConfigEntry {
                    endpoint: "127.0.0.1:8443".to_owned(),
                    spa_endpoint: "127.0.0.1".to_owned(),
                    spa_mode: SpaTransport::Udp,
                    spa_port: 5353,
                    server_public_key: STANDARD.encode([1u8; 32]),
                    priority: Some(2),
                },
                ServerConfigEntry {
                    endpoint: "127.0.0.1:9443".to_owned(),
                    spa_endpoint: "127.0.0.1".to_owned(),
                    spa_mode: SpaTransport::Https,
                    spa_port: 443,
                    server_public_key: STANDARD.encode([2u8; 32]),
                    priority: Some(1),
                },
            ],
            failover: None,
        };

        let ordered = ordered_servers(&config).expect("servers ordered");

        assert_eq!("127.0.0.1:9443", ordered[0].endpoint);
        assert_eq!("127.0.0.1:8443", ordered[1].endpoint);
    }

    #[test]
    fn resolves_all_configured_servers_for_failover() {
        let path = temp_path("servers-toml");
        let toml = format!(
            r#"
            [[servers]]
            endpoint = "127.0.0.1:8443"
            spa_endpoint = "127.0.0.1"
            spa_mode = "udp"
            spa_port = 5353
            server_public_key = "{}"
            priority = 2

            [[servers]]
            endpoint = "127.0.0.1:9443"
            spa_endpoint = "127.0.0.1"
            spa_mode = "https"
            spa_port = 443
            server_public_key = "{}"
            priority = 1
            "#,
            STANDARD.encode([1u8; 32]),
            STANDARD.encode([2u8; 32])
        );
        fs::write(&path, toml).expect("write config");

        let (resolved, policy) = resolve_connect_configs(
            Some(path.to_str().expect("utf8 path")),
            None,
            None,
            None,
            None,
            None,
        )
        .expect("resolve config");

        assert_eq!(2, resolved.len());
        assert_eq!(
            "127.0.0.1:9443".parse::<SocketAddr>().unwrap(),
            resolved[0].proxy_endpoint
        );
        assert_eq!(
            "127.0.0.1:8443".parse::<SocketAddr>().unwrap(),
            resolved[1].proxy_endpoint
        );
        // No [failover] block => default policy.
        assert_eq!(FailoverStrategy::Priority, policy.strategy);
        assert_eq!(0, policy.max_retries);
        let _ = fs::remove_file(path);
    }

    fn sample_candidates(count: usize) -> Vec<ResolvedConnectConfig> {
        (0..count)
            .map(|index| ResolvedConnectConfig {
                server_public_key: vec![0u8; 32],
                spa_endpoint: format!("127.0.0.1:{}", 5000 + index).parse().unwrap(),
                proxy_endpoint: format!("127.0.0.1:{}", 8000 + index).parse().unwrap(),
                spa_mode: SpaTransport::Udp,
                https_spa_url: None,
            })
            .collect()
    }

    #[test]
    fn parses_failover_strategies() {
        assert_eq!(
            FailoverStrategy::Priority,
            FailoverStrategy::parse("priority").unwrap()
        );
        assert_eq!(
            FailoverStrategy::Random,
            FailoverStrategy::parse("RANDOM").unwrap()
        );
        assert_eq!(
            FailoverStrategy::Latency,
            FailoverStrategy::parse("latency").unwrap()
        );
        assert!(FailoverStrategy::parse("round-robin").is_err());
    }

    #[test]
    fn failover_policy_reads_config_block() {
        let config: ClientConfig = toml::from_str(
            r#"
            [[servers]]
            endpoint = "127.0.0.1:8443"
            spa_endpoint = "127.0.0.1"
            spa_mode = "udp"
            spa_port = 53
            server_public_key = "AAAA"
            priority = 1

            [failover]
            strategy = "random"
            retry_interval_ms = 2500
            max_retries = 4
            "#,
        )
        .expect("parse config");
        let policy = FailoverPolicy::from_config(&config).expect("policy");
        assert_eq!(FailoverStrategy::Random, policy.strategy);
        assert_eq!(Duration::from_millis(2500), policy.retry_interval);
        assert_eq!(4, policy.max_retries);
    }

    #[test]
    fn latency_order_puts_fastest_first_unreachable_last() {
        let latencies = vec![
            Some(Duration::from_millis(50)), // 0
            None,                            // 1 unreachable -> last
            Some(Duration::from_millis(10)), // 2 fastest -> first
            Some(Duration::from_millis(50)), // 3 ties with 0, keeps input order
        ];
        assert_eq!(vec![2, 0, 3, 1], order_by_latency(&latencies));
    }

    #[test]
    fn priority_order_is_identity() {
        let candidates = sample_candidates(3);
        assert_eq!(
            vec![0, 1, 2],
            order_candidates(FailoverStrategy::Priority, &candidates)
        );
    }

    #[test]
    fn random_order_is_a_permutation() {
        let candidates = sample_candidates(6);
        let mut order = order_candidates(FailoverStrategy::Random, &candidates);
        order.sort_unstable();
        assert_eq!(vec![0, 1, 2, 3, 4, 5], order);
    }

    #[test]
    fn parses_enrolled_server_config() {
        let toml = format!(
            r#"
            [[servers]]
            endpoint = "127.0.0.1:8443"
            spa_endpoint = "127.0.0.1"
            spa_mode = "udp"
            spa_port = 5353
            server_public_key = "{}"
            priority = 1

            [failover]
            strategy = "priority"
            retry_interval_ms = 5000
            max_retries = 3
            "#,
            STANDARD.encode([3u8; 32])
        );

        let config: ClientConfig = toml::from_str(&toml).expect("config parses");

        assert_eq!(1, config.servers.len());
        assert_eq!(SpaTransport::Udp, config.servers[0].spa_mode);
        assert_eq!(5353, config.servers[0].spa_port);
    }

    #[test]
    fn revoke_url_only_uses_https_servers() {
        let mut server = ServerConfigEntry {
            endpoint: "127.0.0.1:8443".to_owned(),
            spa_endpoint: "example.com".to_owned(),
            spa_mode: SpaTransport::Udp,
            spa_port: 443,
            server_public_key: STANDARD.encode([1u8; 32]),
            priority: Some(1),
        };

        assert!(revoke_url_for(&server).is_none());

        server.spa_mode = SpaTransport::Https;
        assert_eq!(
            Some("https://example.com:443/api/v1/revoke".to_owned()),
            revoke_url_for(&server)
        );
    }

    #[test]
    fn revoke_request_body_includes_optional_key_id() {
        assert_eq!(
            r#"{"action":"revoke","key_id":"abc"}"#,
            revoke_request_body(&RevokeRequest {
                action: "revoke",
                key_id: Some("abc".to_owned())
            })
        );
        assert_eq!(
            r#"{"action":"revoke","key_id":null}"#,
            revoke_request_body(&RevokeRequest {
                action: "revoke",
                key_id: None
            })
        );
    }
}
