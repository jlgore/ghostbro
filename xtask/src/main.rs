#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use ghostbro_common::keys::{
    derive_noise_static_public_key, encode_noise_public_key, encode_public_key, encode_signing_key,
    generate_ed25519_keypair, key_id_for_public_key, key_id_hex,
};

#[derive(Debug, Parser)]
#[command(name = "xtask")]
struct Cli {
    #[command(subcommand)]
    command: XtaskCommand,
}

#[derive(Debug, Subcommand)]
enum XtaskCommand {
    /// Build the eBPF object with the nightly BPF target.
    BuildEbpf,
    /// Prepare local loopback SPA smoke-test files and print commands.
    PrepareSpaLoopback {
        /// Output prefix for generated debug identity files.
        #[arg(long, default_value = "/tmp/ghost-debug")]
        identity_prefix: PathBuf,
        /// Authorized keys TOML path.
        #[arg(long, default_value = "/tmp/ghost-authorized.toml")]
        authorized_keys: PathBuf,
        /// Server config TOML path.
        #[arg(long, default_value = "/tmp/ghost-server.toml")]
        server_config: PathBuf,
        /// Loopback SPA UDP port.
        #[arg(long, default_value_t = 5353)]
        spa_port: u16,
        /// Proxy port protected by XDP.
        #[arg(long, default_value_t = 8443)]
        proxy_port: u16,
        /// Interface to attach XDP to.
        #[arg(long, default_value = "lo")]
        iface: String,
        /// Built-in decoy bind address.
        #[arg(long, default_value = "127.0.0.1:8080")]
        decoy_bind: String,
    },
    /// Run the local UDP SPA + Noise IK TCP smoke test.
    SmokeNoiseLoopback {
        /// Output prefix for generated debug identity files.
        #[arg(long, default_value = "/tmp/ghost-smoke-debug")]
        identity_prefix: PathBuf,
        /// Authorized keys TOML path.
        #[arg(long, default_value = "/tmp/ghost-smoke-authorized.toml")]
        authorized_keys: PathBuf,
        /// Server config TOML path.
        #[arg(long, default_value = "/tmp/ghost-smoke-server.toml")]
        server_config: PathBuf,
        /// Debug Noise private key path.
        #[arg(long, default_value = "/tmp/ghost-smoke-server-noise.key")]
        server_noise_key: PathBuf,
        /// Loopback SPA UDP port.
        #[arg(long, default_value_t = 5353)]
        spa_port: u16,
        /// Proxy port protected by XDP.
        #[arg(long, default_value_t = 8443)]
        proxy_port: u16,
        /// Interface to attach XDP to.
        #[arg(long, default_value = "lo")]
        iface: String,
        /// Built-in decoy bind address.
        #[arg(long, default_value = "127.0.0.1:8080")]
        decoy_bind: String,
        /// Message sent inside one encrypted Noise frame.
        #[arg(long, default_value = "hello ghost")]
        message: String,
        /// Start the server without sudo. Use this when already running as root or with needed caps.
        #[arg(long)]
        no_sudo: bool,
    },
    /// Run the local UDP SPA + Noise IK + SOCKS5 CONNECT smoke test.
    SmokeSocks5Loopback {
        /// Output prefix for generated debug identity files.
        #[arg(long, default_value = "/tmp/ghost-socks5-debug")]
        identity_prefix: PathBuf,
        /// Authorized keys TOML path.
        #[arg(long, default_value = "/tmp/ghost-socks5-authorized.toml")]
        authorized_keys: PathBuf,
        /// Server config TOML path.
        #[arg(long, default_value = "/tmp/ghost-socks5-server.toml")]
        server_config: PathBuf,
        /// Debug Noise private key path.
        #[arg(long, default_value = "/tmp/ghost-socks5-server-noise.key")]
        server_noise_key: PathBuf,
        /// Loopback SPA UDP port.
        #[arg(long, default_value_t = 5353)]
        spa_port: u16,
        /// Proxy port protected by XDP.
        #[arg(long, default_value_t = 8443)]
        proxy_port: u16,
        /// Local echo target port reached through SOCKS5 CONNECT.
        #[arg(long, default_value_t = 9000)]
        target_port: u16,
        /// Interface to attach XDP to.
        #[arg(long, default_value = "lo")]
        iface: String,
        /// Built-in decoy bind address.
        #[arg(long, default_value = "127.0.0.1:8080")]
        decoy_bind: String,
        /// Message sent through the encrypted SOCKS5 tunnel.
        #[arg(long, default_value = "hello ghost")]
        message: String,
        /// Start the server without sudo. Use this when already running as root or with needed caps.
        #[arg(long)]
        no_sudo: bool,
    },
    /// Run the local SOCKS5 listener through the protected tunnel to a loopback echo target.
    SmokeSocks5ListenerLoopback {
        /// Output prefix for generated debug identity files.
        #[arg(long, default_value = "/tmp/ghost-listener-debug")]
        identity_prefix: PathBuf,
        /// Authorized keys TOML path.
        #[arg(long, default_value = "/tmp/ghost-listener-authorized.toml")]
        authorized_keys: PathBuf,
        /// Server config TOML path.
        #[arg(long, default_value = "/tmp/ghost-listener-server.toml")]
        server_config: PathBuf,
        /// Debug Noise private key path.
        #[arg(long, default_value = "/tmp/ghost-listener-server-noise.key")]
        server_noise_key: PathBuf,
        /// Loopback SPA UDP port.
        #[arg(long, default_value_t = 5353)]
        spa_port: u16,
        /// Proxy port protected by XDP.
        #[arg(long, default_value_t = 8443)]
        proxy_port: u16,
        /// Local SOCKS5 listen port.
        #[arg(long, default_value_t = 1080)]
        socks_port: u16,
        /// Local echo target port reached through SOCKS5 CONNECT.
        #[arg(long, default_value_t = 9000)]
        target_port: u16,
        /// Interface to attach XDP to.
        #[arg(long, default_value = "lo")]
        iface: String,
        /// Built-in decoy bind address.
        #[arg(long, default_value = "127.0.0.1:8080")]
        decoy_bind: String,
        /// Message sent through the encrypted SOCKS5 tunnel.
        #[arg(long, default_value = "hello ghost")]
        message: String,
        /// Start the server without sudo. Use this when already running as root or with needed caps.
        #[arg(long)]
        no_sudo: bool,
    },
    /// Run the local UDP SPA + Noise IK + Ghost Relay content smoke test.
    SmokeGhostRelayLoopback {
        /// Output prefix for generated debug identity files.
        #[arg(long, default_value = "/tmp/ghost-relay-debug")]
        identity_prefix: PathBuf,
        /// Authorized keys TOML path.
        #[arg(long, default_value = "/tmp/ghost-relay-authorized.toml")]
        authorized_keys: PathBuf,
        /// Server config TOML path.
        #[arg(long, default_value = "/tmp/ghost-relay-server.toml")]
        server_config: PathBuf,
        /// Debug Noise private key path.
        #[arg(long, default_value = "/tmp/ghost-relay-server-noise.key")]
        server_noise_key: PathBuf,
        /// Loopback SPA UDP port.
        #[arg(long, default_value_t = 5353)]
        spa_port: u16,
        /// Proxy port protected by XDP.
        #[arg(long, default_value_t = 8443)]
        proxy_port: u16,
        /// Local HTTP fixture port fetched through Ghost Relay.
        #[arg(long, default_value_t = 9100)]
        web_port: u16,
        /// Interface to attach XDP to.
        #[arg(long, default_value = "lo")]
        iface: String,
        /// Built-in decoy bind address.
        #[arg(long, default_value = "127.0.0.1:8080")]
        decoy_bind: String,
        /// Start the server without sudo. Use this when already running as root or with needed caps.
        #[arg(long)]
        no_sudo: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        XtaskCommand::BuildEbpf => build_ebpf(),
        XtaskCommand::PrepareSpaLoopback {
            identity_prefix,
            authorized_keys,
            server_config,
            spa_port,
            proxy_port,
            iface,
            decoy_bind,
        } => prepare_spa_loopback(
            identity_prefix,
            authorized_keys,
            server_config,
            spa_port,
            proxy_port,
            &iface,
            &decoy_bind,
        ),
        XtaskCommand::SmokeNoiseLoopback {
            identity_prefix,
            authorized_keys,
            server_config,
            server_noise_key,
            spa_port,
            proxy_port,
            iface,
            decoy_bind,
            message,
            no_sudo,
        } => smoke_noise_loopback(SmokeNoiseConfig {
            identity_prefix,
            authorized_keys,
            server_config,
            server_noise_key,
            spa_port,
            proxy_port,
            iface,
            decoy_bind,
            message,
            use_sudo: !no_sudo,
        }),
        XtaskCommand::SmokeSocks5Loopback {
            identity_prefix,
            authorized_keys,
            server_config,
            server_noise_key,
            spa_port,
            proxy_port,
            target_port,
            iface,
            decoy_bind,
            message,
            no_sudo,
        } => smoke_socks5_loopback(
            SmokeNoiseConfig {
                identity_prefix,
                authorized_keys,
                server_config,
                server_noise_key,
                spa_port,
                proxy_port,
                iface,
                decoy_bind,
                message,
                use_sudo: !no_sudo,
            },
            target_port,
        ),
        XtaskCommand::SmokeSocks5ListenerLoopback {
            identity_prefix,
            authorized_keys,
            server_config,
            server_noise_key,
            spa_port,
            proxy_port,
            socks_port,
            target_port,
            iface,
            decoy_bind,
            message,
            no_sudo,
        } => smoke_socks5_listener_loopback(
            SmokeNoiseConfig {
                identity_prefix,
                authorized_keys,
                server_config,
                server_noise_key,
                spa_port,
                proxy_port,
                iface,
                decoy_bind,
                message,
                use_sudo: !no_sudo,
            },
            socks_port,
            target_port,
        ),
        XtaskCommand::SmokeGhostRelayLoopback {
            identity_prefix,
            authorized_keys,
            server_config,
            server_noise_key,
            spa_port,
            proxy_port,
            web_port,
            iface,
            decoy_bind,
            no_sudo,
        } => smoke_ghost_relay_loopback(
            SmokeNoiseConfig {
                identity_prefix,
                authorized_keys,
                server_config,
                server_noise_key,
                spa_port,
                proxy_port,
                iface,
                decoy_bind,
                message: "hello ghost relay".to_owned(),
                use_sudo: !no_sudo,
            },
            web_port,
        ),
    }
}

fn build_ebpf() -> Result<()> {
    let status = Command::new("cargo")
        .args([
            "+nightly",
            "build",
            "-p",
            "ghostbro-ebpf",
            "--target",
            "bpfel-unknown-none",
            "--release",
            "-Z",
            "build-std=core",
        ])
        .status()
        .context("failed to invoke cargo for eBPF build")?;

    if !status.success() {
        bail!("eBPF build failed with status {status}");
    }

    Ok(())
}

fn prepare_spa_loopback(
    identity_prefix: PathBuf,
    authorized_keys: PathBuf,
    server_config: PathBuf,
    spa_port: u16,
    proxy_port: u16,
    iface: &str,
    decoy_bind: &str,
) -> Result<()> {
    let fixture = write_loopback_fixture(
        identity_prefix,
        authorized_keys,
        server_config,
        PathBuf::from("/tmp/ghost-server-noise.key"),
        spa_port,
        proxy_port,
    )?;

    print_loopback_instructions(&fixture, spa_port, proxy_port, iface, decoy_bind);

    Ok(())
}

struct LoopbackFixture {
    key_path: PathBuf,
    pub_path: PathBuf,
    key_id_path: PathBuf,
    noise_path: PathBuf,
    counter_path: PathBuf,
    authorized_keys: PathBuf,
    server_config: PathBuf,
    server_noise_key: PathBuf,
}

struct SmokeNoiseConfig {
    identity_prefix: PathBuf,
    authorized_keys: PathBuf,
    server_config: PathBuf,
    server_noise_key: PathBuf,
    spa_port: u16,
    proxy_port: u16,
    iface: String,
    decoy_bind: String,
    message: String,
    use_sudo: bool,
}

fn write_loopback_fixture(
    identity_prefix: PathBuf,
    authorized_keys: PathBuf,
    server_config: PathBuf,
    server_noise_key: PathBuf,
    spa_port: u16,
    proxy_port: u16,
) -> Result<LoopbackFixture> {
    let signing_key = generate_ed25519_keypair();
    let public_key = signing_key.verifying_key();
    let key_id = key_id_for_public_key(&public_key);
    let noise_public_key = derive_noise_static_public_key(&signing_key);
    let prefix = identity_prefix.to_string_lossy();
    let key_path = PathBuf::from(format!("{prefix}.key"));
    let pub_path = PathBuf::from(format!("{prefix}.pub"));
    let key_id_path = PathBuf::from(format!("{prefix}.keyid"));
    let noise_path = PathBuf::from(format!("{prefix}.noise"));
    let counter_path = PathBuf::from(format!("{prefix}.counter"));

    write_private_key_file(&key_path, format!("{}\n", encode_signing_key(&signing_key)))
        .with_context(|| format!("failed to write {}", key_path.display()))?;
    fs::write(&pub_path, format!("{}\n", encode_public_key(&public_key)))
        .with_context(|| format!("failed to write {}", pub_path.display()))?;
    fs::write(&key_id_path, format!("{}\n", key_id_hex(&key_id)))
        .with_context(|| format!("failed to write {}", key_id_path.display()))?;
    fs::write(
        &noise_path,
        format!("{}\n", encode_noise_public_key(&noise_public_key)),
    )
    .with_context(|| format!("failed to write {}", noise_path.display()))?;
    fs::write(&counter_path, "0\n")
        .with_context(|| format!("failed to write {}", counter_path.display()))?;

    fs::write(
        &authorized_keys,
        format!(
            "[[clients]]\nname = \"debug-client\"\npublic_key = \"{}\"\nnoise_public_key = \"{}\"\ntier = \"full\"\n",
            encode_public_key(&public_key),
            encode_noise_public_key(&noise_public_key)
        ),
    )
    .with_context(|| format!("failed to write {}", authorized_keys.display()))?;

    fs::write(
        &server_config,
        format!(
            r#"[server]
identity = "{}"

[spa]
mode = "udp"

[spa.udp]
port = {spa_port}
rate_limit = 5

[spa.common]
time_window = 300
allow_ttl = 14400

[proxy]
port = {proxy_port}
noise_pattern = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
bind = "0.0.0.0"

[clients]
authorized_keys = "{}"
"#,
            server_noise_key.display(),
            authorized_keys.display()
        ),
    )
    .with_context(|| format!("failed to write {}", server_config.display()))?;

    let _ = fs::remove_file(&server_noise_key);
    let _ = fs::remove_file(public_key_path(&server_noise_key));

    Ok(LoopbackFixture {
        key_path,
        pub_path,
        key_id_path,
        noise_path,
        counter_path,
        authorized_keys,
        server_config,
        server_noise_key,
    })
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
        return Ok(());
    }

    #[cfg(not(unix))]
    {
        fs::write(path, contents)
    }
}

fn print_loopback_instructions(
    fixture: &LoopbackFixture,
    spa_port: u16,
    proxy_port: u16,
    iface: &str,
    decoy_bind: &str,
) {
    println!("prepared loopback SPA smoke test files:");
    println!("  private key:     {}", fixture.key_path.display());
    println!("  public key:      {}", fixture.pub_path.display());
    println!("  key id:          {}", fixture.key_id_path.display());
    println!("  noise key:       {}", fixture.noise_path.display());
    println!("  counter:         {}", fixture.counter_path.display());
    println!("  authorized keys: {}", fixture.authorized_keys.display());
    println!("  server config:   {}", fixture.server_config.display());
    println!("  server noise key:{}", fixture.server_noise_key.display());
    println!();
    println!("1. Build the eBPF object:");
    println!("   cargo xtask build-ebpf");
    println!();
    println!("2. Start the server in one terminal:");
    println!(
        "   sudo RUST_LOG=debug target/debug/ghostbro-server --config {} --iface {} --ebpf-object target/bpfel-unknown-none/release/ghostbro-ebpf --decoy-bind {}",
        fixture.server_config.display(),
        iface,
        decoy_bind
    );
    println!();
    println!("3. Send one SPA packet from another terminal:");
    println!(
        "   cargo run -p ghostbro-client -- send-udp-spa --identity-key {} --server-key {} --endpoint 127.0.0.1:{}",
        fixture.key_path.display(),
        public_key_path(&fixture.server_noise_key).display(),
        spa_port
    );
    println!();
    println!("Expected server logs: SPA_ACCEPT followed by ALLOW_MAP_WRITE for 127.0.0.1");
    println!();
    println!(
        "4. After the server has generated {}, try one encrypted TCP frame:",
        public_key_path(&fixture.server_noise_key).display()
    );
    println!(
        "   cargo run -p ghostbro-client -- connect-once --identity-key {} --server-key {} --spa-endpoint 127.0.0.1:{} --proxy-endpoint 127.0.0.1:{} --message \"hello ghost\"",
        fixture.key_path.display(),
        public_key_path(&fixture.server_noise_key).display(),
        spa_port,
        proxy_port
    );
}

fn smoke_noise_loopback(config: SmokeNoiseConfig) -> Result<()> {
    println!("building userspace crates");
    run_status(Command::new("cargo").arg("build"), "cargo build")?;
    println!("building eBPF object");
    build_ebpf()?;

    let fixture = write_loopback_fixture(
        config.identity_prefix.clone(),
        config.authorized_keys.clone(),
        config.server_config.clone(),
        config.server_noise_key.clone(),
        config.spa_port,
        config.proxy_port,
    )?;

    let server = spawn_server(&config, &fixture)?;
    let smoke_result = run_client_smoke(&config, &fixture);
    let server_output = stop_server(server)?;
    let server_log = output_text(&server_output);

    smoke_result?;
    assert_contains(&server_log, "SPA_ACCEPT", "server log")?;
    assert_contains(&server_log, "ALLOW_MAP_WRITE", "server log")?;
    assert_contains(&server_log, "NOISE_ACCEPT", "server log")?;
    assert_contains(&server_log, "NOISE_FRAME_DECRYPTED", "server log")?;

    println!("smoke-noise-loopback passed");

    Ok(())
}

fn smoke_socks5_loopback(config: SmokeNoiseConfig, target_port: u16) -> Result<()> {
    println!("building userspace crates");
    run_status(Command::new("cargo").arg("build"), "cargo build")?;
    println!("building eBPF object");
    build_ebpf()?;

    let fixture = write_loopback_fixture(
        config.identity_prefix.clone(),
        config.authorized_keys.clone(),
        config.server_config.clone(),
        config.server_noise_key.clone(),
        config.spa_port,
        config.proxy_port,
    )?;

    let echo = spawn_echo_target(target_port)?;
    let server = spawn_server(&config, &fixture)?;
    let smoke_result = run_client_socks5_smoke(&config, &fixture, target_port);
    let server_output = stop_server(server)?;
    let server_log = output_text(&server_output);

    smoke_result?;
    echo.join()
        .map_err(|_| anyhow::anyhow!("echo target thread panicked"))??;

    assert_contains(&server_log, "SPA_ACCEPT", "server log")?;
    assert_contains(&server_log, "NOISE_ACCEPT", "server log")?;
    assert_contains(&server_log, "SOCKS5_CONNECT", "server log")?;
    assert_contains(&server_log, "SOCKS5_CONNECT_OK", "server log")?;
    assert_contains(&server_log, "SOCKS5_FRAME_RELAYED", "server log")?;

    println!("smoke-socks5-loopback passed");

    Ok(())
}

fn smoke_socks5_listener_loopback(
    config: SmokeNoiseConfig,
    socks_port: u16,
    target_port: u16,
) -> Result<()> {
    println!("building userspace crates");
    run_status(Command::new("cargo").arg("build"), "cargo build")?;
    println!("building eBPF object");
    build_ebpf()?;

    let fixture = write_loopback_fixture(
        config.identity_prefix.clone(),
        config.authorized_keys.clone(),
        config.server_config.clone(),
        config.server_noise_key.clone(),
        config.spa_port,
        config.proxy_port,
    )?;

    let echo = spawn_echo_target(target_port)?;
    let server = spawn_server(&config, &fixture)?;
    let client = spawn_client_listener(&config, &fixture, socks_port)?;
    let smoke_result = run_local_socks5_client(socks_port, target_port, &config.message);
    let client_output = stop_server(client)?;
    let server_output = stop_server(server)?;
    let client_log = output_text(&client_output);
    let server_log = output_text(&server_output);

    if let Err(error) = smoke_result {
        bail!(
            "local SOCKS5 smoke client failed: {error:#}\n\nclient log:\n{client_log}\n\nserver log:\n{server_log}"
        );
    }
    echo.join()
        .map_err(|_| anyhow::anyhow!("echo target thread panicked"))??;

    assert_contains(&client_log, "SOCKS5_LISTEN", "client log")?;
    assert_contains(&client_log, "SOCKS5_TUNNEL_OPEN", "client log")?;
    assert_contains(&server_log, "SPA_ACCEPT", "server log")?;
    assert_contains(&server_log, "NOISE_ACCEPT", "server log")?;
    assert_contains(&server_log, "SOCKS5_CONNECT_OK", "server log")?;
    assert_contains(&server_log, "SOCKS5_FRAME_RELAYED", "server log")?;

    println!("smoke-socks5-listener-loopback passed");

    Ok(())
}

fn smoke_ghost_relay_loopback(config: SmokeNoiseConfig, web_port: u16) -> Result<()> {
    println!("building userspace crates");
    run_status(Command::new("cargo").arg("build"), "cargo build")?;
    println!("building eBPF object");
    build_ebpf()?;

    let fixture = write_loopback_fixture(
        config.identity_prefix.clone(),
        config.authorized_keys.clone(),
        config.server_config.clone(),
        config.server_noise_key.clone(),
        config.spa_port,
        config.proxy_port,
    )?;

    let web = spawn_http_content_target(web_port, &config.message)?;
    let server = spawn_server(&config, &fixture)?;
    let smoke_result = run_client_ghost_relay_smoke(&config, &fixture, web_port);
    let server_output = stop_server(server)?;
    let server_log = output_text(&server_output);

    smoke_result?;
    web.join()
        .map_err(|_| anyhow::anyhow!("HTTP fixture thread panicked"))??;
    assert_contains(&server_log, "SPA_ACCEPT", "server log")?;
    assert_contains(&server_log, "NOISE_ACCEPT", "server log")?;
    assert_contains(&server_log, "GHOST_RELAY_REQUEST", "server log")?;
    assert_contains(&server_log, "GHOST_RELAY_JOB_QUEUED", "server log")?;
    assert_contains(&server_log, "GHOST_RELAY_JOB_COMPLETE", "server log")?;
    assert_contains(&server_log, "GHOST_RELAY_JOB_DELETED", "server log")?;

    println!("smoke-ghost-relay-loopback passed");

    Ok(())
}

fn spawn_server(config: &SmokeNoiseConfig, fixture: &LoopbackFixture) -> Result<Child> {
    let mut command = if config.use_sudo {
        let mut command = Command::new("sudo");
        command.args([
            "-n",
            "prlimit",
            "--nofile=65535:65535",
            "--",
            "env",
            "RUST_LOG=debug",
            "GHOST_PROXY_DISABLE_AUTH_WATCH=1",
            "GHOST_PROXY_RELAY_ALLOW_LOOPBACK=1",
            // The fixture deletes the server Noise key and relies on the server
            // minting one at startup; opt into auto-generation explicitly since
            // the serving path now fails closed on a missing identity (F-001).
            "GHOST_PROXY_GENERATE_IDENTITY=1",
        ]);
        command.arg(format!(
            "GHOST_PROXY_RELAY_SPOOL_DIR={}-relay-spool",
            config.identity_prefix.display()
        ));
        command.arg("./target/debug/ghostbro-server");
        command
    } else {
        let mut command = Command::new("./target/debug/ghostbro-server");
        command.env("RUST_LOG", "debug");
        command.env("GHOST_PROXY_DISABLE_AUTH_WATCH", "1");
        command
    };
    command.env("GHOST_PROXY_RELAY_ALLOW_LOOPBACK", "1");
    // Smoke fixture deletes the server Noise key; opt into regeneration so the
    // fail-closed serving path (F-001) does not abort the loopback smoke run.
    command.env("GHOST_PROXY_GENERATE_IDENTITY", "1");
    command.env(
        "GHOST_PROXY_RELAY_SPOOL_DIR",
        format!("{}-relay-spool", config.identity_prefix.display()),
    );

    command
        .arg("--config")
        .arg(&fixture.server_config)
        .arg("--iface")
        .arg(&config.iface)
        .arg("--ebpf-object")
        .arg("target/bpfel-unknown-none/release/ghostbro-ebpf")
        .arg("--decoy-bind")
        .arg(&config.decoy_bind)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let child = command.spawn().context(
        "failed to start server; try running with --no-sudo if already privileged, or configure passwordless sudo",
    )?;

    let child = wait_for_server_key(
        child,
        public_key_path(&fixture.server_noise_key),
        Duration::from_secs(5),
    )?;
    thread::sleep(Duration::from_millis(300));

    Ok(child)
}

fn run_client_smoke(config: &SmokeNoiseConfig, fixture: &LoopbackFixture) -> Result<()> {
    let output = Command::new("cargo")
        .args(["run", "-p", "ghostbro-client", "--", "connect-once"])
        .arg("--identity-key")
        .arg(&fixture.key_path)
        .arg("--server-key")
        .arg(public_key_path(&fixture.server_noise_key))
        .arg("--spa-endpoint")
        .arg(format!("127.0.0.1:{}", config.spa_port))
        .arg("--proxy-endpoint")
        .arg(format!("127.0.0.1:{}", config.proxy_port))
        .arg("--message")
        .arg(&config.message)
        .output()
        .context("failed to run connect-once client")?;
    let client_log = output_text(&output);

    if !output.status.success() {
        bail!(
            "connect-once failed with status {}\n{}",
            output.status,
            client_log
        );
    }

    assert_contains(&client_log, "NOISE_HANDSHAKE_COMPLETE", "client output")?;
    assert_contains(&client_log, "NOISE_FRAME_ROUND_TRIP", "client output")?;
    assert_contains(&client_log, &config.message, "client output")?;
    Ok(())
}

fn run_client_socks5_smoke(
    config: &SmokeNoiseConfig,
    fixture: &LoopbackFixture,
    target_port: u16,
) -> Result<()> {
    let target = format!("127.0.0.1:{target_port}");
    let output = Command::new("cargo")
        .args([
            "run",
            "-p",
            "ghostbro-client",
            "--",
            "connect-socks5-once",
        ])
        .arg("--identity-key")
        .arg(&fixture.key_path)
        .arg("--server-key")
        .arg(public_key_path(&fixture.server_noise_key))
        .arg("--spa-endpoint")
        .arg(format!("127.0.0.1:{}", config.spa_port))
        .arg("--proxy-endpoint")
        .arg(format!("127.0.0.1:{}", config.proxy_port))
        .arg("--target")
        .arg(target)
        .arg("--message")
        .arg(&config.message)
        .output()
        .context("failed to run connect-socks5-once client")?;
    let client_log = output_text(&output);

    if !output.status.success() {
        bail!(
            "connect-socks5-once failed with status {}\n{}",
            output.status,
            client_log
        );
    }

    assert_contains(&client_log, "SOCKS5_HANDSHAKE_COMPLETE", "client output")?;
    assert_contains(&client_log, "SOCKS5_FRAME_ROUND_TRIP", "client output")?;
    assert_contains(&client_log, &config.message, "client output")?;
    Ok(())
}

fn run_client_ghost_relay_smoke(
    config: &SmokeNoiseConfig,
    fixture: &LoopbackFixture,
    web_port: u16,
) -> Result<()> {
    let url = format!("http://127.0.0.1:{web_port}/fixture.html");
    let output = relay_client_command(config, fixture, "relay-submit-url")
        .arg("--url")
        .arg(url)
        .arg("--normalize")
        .output()
        .context("failed to run relay-submit-url client")?;
    let submit_log = output_text(&output);
    if !output.status.success() {
        bail!(
            "relay-submit-url failed with status {}\n{}",
            output.status,
            submit_log
        );
    }
    assert_contains(&submit_log, "GHOST_RELAY_JOB_SUBMITTED", "client output")?;
    let job_id = parse_job_id(&submit_log)?;

    // Submission is async: poll the job list until the background worker marks
    // the job complete (or failed) before attempting to download.
    wait_for_relay_job_complete(config, fixture, &job_id)?;

    // Download the normalized markdown artifact and verify the normalizer ran.
    let markdown_path = PathBuf::from(format!(
        "{}-relay-download.md",
        config.identity_prefix.display()
    ));
    let output = relay_client_command(config, fixture, "relay-download")
        .arg("--job-id")
        .arg(&job_id)
        .arg("--output")
        .arg(&markdown_path)
        .arg("--artifact")
        .arg("markdown")
        .output()
        .context("failed to run relay-download (markdown) client")?;
    let download_log = output_text(&output);
    if !output.status.success() {
        bail!(
            "relay-download markdown failed with status {}\n{}",
            output.status,
            download_log
        );
    }
    assert_contains(&download_log, "GHOST_RELAY_DOWNLOADED", "client output")?;
    let markdown = fs::read_to_string(&markdown_path)
        .with_context(|| format!("failed to read {}", markdown_path.display()))?;
    let expected_markdown = format!("# {}", config.message);
    if markdown.trim() != expected_markdown {
        bail!("unexpected normalized markdown: {markdown:?} (wanted {expected_markdown:?})");
    }

    // Download the raw HTML primary artifact and confirm it carries the message.
    let primary_path = PathBuf::from(format!(
        "{}-relay-download.html",
        config.identity_prefix.display()
    ));
    let output = relay_client_command(config, fixture, "relay-download")
        .arg("--job-id")
        .arg(&job_id)
        .arg("--output")
        .arg(&primary_path)
        .output()
        .context("failed to run relay-download (primary) client")?;
    if !output.status.success() {
        bail!(
            "relay-download primary failed with status {}\n{}",
            output.status,
            output_text(&output)
        );
    }
    let primary = fs::read_to_string(&primary_path)
        .with_context(|| format!("failed to read {}", primary_path.display()))?;
    if !primary.contains(&config.message) {
        bail!("primary artifact missing message: {primary:?}");
    }

    let output = relay_client_command(config, fixture, "relay-delete")
        .arg("--job-id")
        .arg(&job_id)
        .output()
        .context("failed to run relay-delete client")?;
    let delete_log = output_text(&output);
    if !output.status.success() {
        bail!(
            "relay-delete failed with status {}\n{}",
            output.status,
            delete_log
        );
    }
    assert_contains(&delete_log, "GHOST_RELAY_DELETED", "client output")?;
    Ok(())
}

/// Poll `relay-list` until the named job reaches a terminal status. Returns an
/// error if the job fails, disappears, or does not complete within the timeout.
fn wait_for_relay_job_complete(
    config: &SmokeNoiseConfig,
    fixture: &LoopbackFixture,
    job_id: &str,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let output = relay_client_command(config, fixture, "relay-list")
            .output()
            .context("failed to run relay-list client")?;
        let list_log = output_text(&output);
        if !output.status.success() {
            bail!(
                "relay-list failed with status {}\n{}",
                output.status,
                list_log
            );
        }
        if let Some(status) = list_log.lines().find_map(|line| {
            let mut fields = line.split('\t');
            (fields.next() == Some(job_id)).then(|| fields.nth(1).unwrap_or("").to_owned())
        }) {
            match status.as_str() {
                "complete" => return Ok(()),
                "failed" => bail!("relay job {job_id} failed:\n{list_log}"),
                _ => {}
            }
        }
        if Instant::now() >= deadline {
            bail!("relay job {job_id} did not complete within timeout:\n{list_log}");
        }
        thread::sleep(Duration::from_millis(200));
    }
}

fn relay_client_command(
    config: &SmokeNoiseConfig,
    fixture: &LoopbackFixture,
    subcommand: &str,
) -> Command {
    let mut command = Command::new("cargo");
    command
        .args(["run", "-p", "ghostbro-client", "--", subcommand])
        .arg("--identity-key")
        .arg(&fixture.key_path)
        .arg("--server-key")
        .arg(public_key_path(&fixture.server_noise_key))
        .arg("--spa-endpoint")
        .arg(format!("127.0.0.1:{}", config.spa_port))
        .arg("--proxy-endpoint")
        .arg(format!("127.0.0.1:{}", config.proxy_port));
    command
}

fn parse_job_id(output: &str) -> Result<String> {
    let marker = "job_id=";
    let start = output
        .find(marker)
        .context("relay submit output did not include job_id")?
        + marker.len();
    Ok(output[start..]
        .split_whitespace()
        .next()
        .context("relay submit job_id was empty")?
        .to_owned())
}

fn spawn_client_listener(
    config: &SmokeNoiseConfig,
    fixture: &LoopbackFixture,
    socks_port: u16,
) -> Result<Child> {
    let mut child = Command::new("./target/debug/ghostbro")
        .arg("connect")
        .arg("--identity-key")
        .arg(&fixture.key_path)
        .arg("--server-key")
        .arg(public_key_path(&fixture.server_noise_key))
        .arg("--spa-endpoint")
        .arg(format!("127.0.0.1:{}", config.spa_port))
        .arg("--proxy-endpoint")
        .arg(format!("127.0.0.1:{}", config.proxy_port))
        .arg("--listen")
        .arg(format!("127.0.0.1:{socks_port}"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to start local SOCKS5 client listener")?;

    if let Err(error) =
        wait_for_tcp_port("127.0.0.1", socks_port, Duration::from_secs(10), &mut child)
    {
        let _ = child.kill();
        let output = child
            .wait_with_output()
            .context("failed to collect local SOCKS5 client listener output")?;
        bail!("{error:#}\n{}", output_text(&output));
    }
    Ok(child)
}

fn run_local_socks5_client(socks_port: u16, target_port: u16, message: &str) -> Result<()> {
    let mut stream = TcpStream::connect(("127.0.0.1", socks_port))
        .with_context(|| format!("failed to connect to local SOCKS5 listener on {socks_port}"))?;
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .context("failed to write local SOCKS5 greeting")?;
    let mut method = [0u8; 2];
    stream
        .read_exact(&mut method)
        .context("failed to read local SOCKS5 method response")?;
    if method != [0x05, 0x00] {
        bail!("unexpected local SOCKS5 method response: {method:?}");
    }

    let mut request = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    request.extend_from_slice(&target_port.to_be_bytes());
    stream
        .write_all(&request)
        .context("failed to write local SOCKS5 CONNECT request")?;
    let mut response = [0u8; 10];
    stream
        .read_exact(&mut response)
        .context("failed to read local SOCKS5 CONNECT response")?;
    if response[0] != 0x05 || response[1] != 0x00 {
        bail!("local SOCKS5 CONNECT failed: {response:?}");
    }

    stream
        .write_all(message.as_bytes())
        .context("failed to write tunneled smoke message")?;
    let mut echoed = vec![0u8; message.len()];
    stream
        .read_exact(&mut echoed)
        .context("failed to read tunneled smoke echo")?;
    if echoed != message.as_bytes() {
        bail!(
            "unexpected tunneled echo: {:?}",
            String::from_utf8_lossy(&echoed)
        );
    }
    Ok(())
}

fn spawn_echo_target(port: u16) -> Result<thread::JoinHandle<Result<()>>> {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .with_context(|| format!("failed to bind echo target on 127.0.0.1:{port}"))?;
    listener
        .set_nonblocking(false)
        .context("failed to configure echo target listener")?;

    let handle = thread::spawn(move || -> Result<()> {
        let (mut stream, _) = listener.accept().context("echo target failed to accept")?;
        let mut buf = [0u8; 16 * 1024];
        let len = stream
            .read(&mut buf)
            .context("echo target failed to read")?;
        stream
            .write_all(&buf[..len])
            .context("echo target failed to write")?;
        Ok(())
    });

    thread::sleep(Duration::from_millis(50));
    Ok(handle)
}

/// Serve a single HTML document containing `message` inside an `<h1>`. The
/// relay normalizer should render this to `# {message}`, which the smoke
/// verifies end-to-end.
fn spawn_http_content_target(port: u16, message: &str) -> Result<thread::JoinHandle<Result<()>>> {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .with_context(|| format!("failed to bind HTTP fixture on 127.0.0.1:{port}"))?;
    let body = format!(
        "<!DOCTYPE html><html><head><title>fixture</title><style>.x{{}}</style></head>\
         <body><h1>{message}</h1></body></html>"
    );

    let handle = thread::spawn(move || -> Result<()> {
        let (mut stream, _) = listener.accept().context("HTTP fixture failed to accept")?;
        let mut buf = [0u8; 4096];
        let _ = stream
            .read(&mut buf)
            .context("HTTP fixture failed to read request")?;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .context("HTTP fixture failed to write response")?;
        Ok(())
    });

    thread::sleep(Duration::from_millis(50));
    Ok(handle)
}

fn stop_server(mut server: Child) -> Result<Output> {
    if server.try_wait()?.is_none() {
        server.kill().context("failed to stop smoke server")?;
    }
    server
        .wait_with_output()
        .context("failed to collect smoke server output")
}

fn run_status(command: &mut Command, label: &str) -> Result<()> {
    let status = command
        .status()
        .with_context(|| format!("failed to invoke {label}"))?;
    if !status.success() {
        bail!("{label} failed with status {status}");
    }
    Ok(())
}

fn wait_for_server_key(mut server: Child, path: PathBuf, timeout: Duration) -> Result<Child> {
    let start = Instant::now();
    loop {
        if path.exists() {
            return Ok(server);
        }
        if let Some(status) = server.try_wait()? {
            let output = server
                .wait_with_output()
                .context("failed to collect exited server output")?;
            bail!(
                "server exited before generating {} with status {}\n{}",
                path.display(),
                status,
                output_text(&output)
            );
        }
        if start.elapsed() >= timeout {
            server
                .kill()
                .context("failed to stop timed-out smoke server")?;
            let output = server
                .wait_with_output()
                .context("failed to collect timed-out server output")?;
            bail!(
                "timed out waiting for {}\n{}",
                path.display(),
                output_text(&output)
            );
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn wait_for_tcp_port(host: &str, port: u16, timeout: Duration, child: &mut Child) -> Result<()> {
    let start = Instant::now();
    loop {
        if TcpStream::connect((host, port)).is_ok() {
            return Ok(());
        }
        if let Some(status) = child.try_wait()? {
            bail!("client listener exited before opening port {host}:{port} with status {status}");
        }
        if start.elapsed() >= timeout {
            bail!("timed out waiting for client listener on {host}:{port}");
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn assert_contains(haystack: &str, needle: &str, label: &str) -> Result<()> {
    if !haystack.contains(needle) {
        bail!("{label} did not contain {needle:?}\n{haystack}");
    }
    Ok(())
}

fn output_text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn public_key_path(path: &Path) -> PathBuf {
    if path.extension().is_some_and(|extension| extension == "key") {
        path.with_extension("pub")
    } else {
        path.with_extension("noise.pub")
    }
}
