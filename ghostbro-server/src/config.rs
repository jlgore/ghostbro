use serde::Deserialize;
use std::{fs, path::Path};

use ghostbro_common::protocol::{DEFAULT_ALLOW_TTL_SECONDS, DEFAULT_TIME_WINDOW_SECONDS};

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub server: ServerSection,
    pub spa: SpaSection,
    pub proxy: ProxySection,
    pub clients: ClientsSection,
    pub decoy: Option<DecoySection>,
    pub logging: Option<LoggingSection>,
    pub relay: Option<RelaySection>,
}

impl ServerConfig {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let contents = fs::read_to_string(path)
            .map_err(|error| anyhow::anyhow!("failed to read {}: {error}", path.display()))?;
        toml::from_str(&contents)
            .map_err(|error| anyhow::anyhow!("failed to parse {}: {error}", path.display()))
    }
}

#[derive(Debug, Deserialize)]
pub struct ServerSection {
    pub identity: String,
}

#[derive(Debug, Deserialize)]
pub struct SpaSection {
    pub mode: SpaModeConfig,
    pub common: Option<SpaCommonSection>,
    pub udp: Option<SpaUdpSection>,
    pub https: Option<SpaHttpsSection>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SpaModeConfig {
    Udp,
    Https,
    Both,
}

#[derive(Debug, Deserialize)]
pub struct SpaCommonSection {
    #[serde(default = "default_time_window")]
    pub time_window: u64,
    #[serde(default = "default_allow_ttl")]
    pub allow_ttl: u64,
    #[serde(default = "default_counter_state")]
    pub counter_state: String,
}

#[derive(Debug, Deserialize)]
pub struct SpaUdpSection {
    pub port: u16,
    pub rate_limit: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct SpaHttpsSection {
    pub path: String,
    pub response_status: Option<u16>,
    /// Reverse-proxy addresses whose `X-Forwarded-For` is trusted. A non-empty
    /// list IS the trust grant (v0.3 dropped the redundant boolean): XFF is
    /// honored only for TCP peers inside one of these CIDRs, else the TCP peer
    /// address is authoritative. nginx mode requires this to be set.
    #[serde(default)]
    pub trusted_proxy_cidrs: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ProxySection {
    pub port: u16,
    pub noise_pattern: String,
    pub bind: String,
}

#[derive(Debug, Deserialize)]
pub struct ClientsSection {
    pub authorized_keys: String,
}

#[derive(Debug, Deserialize)]
pub struct DecoySection {
    pub mode: Option<DecoyModeConfig>,
    pub bind: Option<String>,
    pub webroot: Option<String>,
    /// PEM certificate chain for serving the builtin decoy over HTTPS.
    pub tls_cert: Option<String>,
    /// PEM private key matching `tls_cert`.
    pub tls_key: Option<String>,
}

impl DecoySection {
    /// Return the cert/key pair only when both are configured. The builtin
    /// decoy serves HTTPS when this is `Some`, plain HTTP otherwise.
    pub fn tls_pair(&self) -> Option<(String, String)> {
        match (self.tls_cert.as_ref(), self.tls_key.as_ref()) {
            (Some(cert), Some(key)) => Some((cert.clone(), key.clone())),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DecoyModeConfig {
    Builtin,
}

#[derive(Debug, Deserialize)]
pub struct LoggingSection {
    pub path: String,
    pub level: String,
}

/// Ghost Relay (`0x47`) content-relay tuning. All fields are optional and fall
/// back to the engine defaults; environment overrides still apply on top.
#[derive(Debug, Default, Deserialize)]
pub struct RelaySection {
    /// Spool directory root for per-client job storage.
    pub spool_dir: Option<String>,
    /// Job time-to-live in seconds before the reaper deletes it.
    pub job_ttl: Option<u64>,
    /// Maximum number of live jobs retained per client key.
    pub max_jobs_per_client: Option<usize>,
    /// Maximum total stored bytes per client key.
    pub max_bytes_per_client: Option<u64>,
    /// Maximum size of a single stored object (web body, bundle, package).
    pub max_object_len: Option<usize>,
    /// Number of background worker tasks.
    pub workers: Option<usize>,
    /// Per-fetch HTTP timeout in seconds.
    pub fetch_timeout: Option<u64>,
    /// Per-job git operation timeout in seconds.
    pub git_timeout: Option<u64>,
    /// Allow loopback/private fetch targets (local testing only).
    #[serde(default)]
    pub allow_loopback: bool,
}

impl SpaSection {
    pub fn bpf_mode(&self) -> u32 {
        match self.mode {
            SpaModeConfig::Udp => ghostbro_bpf_common::SPA_MODE_UDP,
            SpaModeConfig::Https => ghostbro_bpf_common::SPA_MODE_HTTPS,
            SpaModeConfig::Both => ghostbro_bpf_common::SPA_MODE_BOTH,
        }
    }

    pub fn https_path(&self) -> &str {
        self.https
            .as_ref()
            .map(|https| https.path.as_str())
            .unwrap_or("/api/v1/telemetry")
    }

    pub fn https_response_status(&self) -> u16 {
        self.https
            .as_ref()
            .and_then(|https| https.response_status)
            .unwrap_or(204)
    }

    pub fn trusted_proxy_cidrs(&self) -> &[String] {
        self.https
            .as_ref()
            .map(|https| https.trusted_proxy_cidrs.as_slice())
            .unwrap_or(&[])
    }

    pub fn time_window_seconds(&self) -> u64 {
        self.common
            .as_ref()
            .map(|common| common.time_window)
            .unwrap_or_else(default_time_window)
    }

    pub fn allow_ttl_seconds(&self) -> u64 {
        self.common
            .as_ref()
            .map(|common| common.allow_ttl)
            .unwrap_or_else(default_allow_ttl)
    }

    pub fn counter_state_path(&self) -> &str {
        self.common
            .as_ref()
            .map(|common| common.counter_state.as_str())
            .unwrap_or(DEFAULT_COUNTER_STATE)
    }

    pub fn udp_port(&self) -> u16 {
        self.udp
            .as_ref()
            .map(|udp| udp.port)
            .unwrap_or(ghostbro_bpf_common::DEFAULT_SPA_PORT)
    }

    pub fn udp_rate_limit(&self) -> u32 {
        self.udp
            .as_ref()
            .and_then(|udp| udp.rate_limit)
            .unwrap_or(ghostbro_bpf_common::DEFAULT_RATE_LIMIT_PER_MINUTE)
    }
}

fn default_time_window() -> u64 {
    DEFAULT_TIME_WINDOW_SECONDS
}

fn default_allow_ttl() -> u64 {
    DEFAULT_ALLOW_TTL_SECONDS
}

fn default_counter_state() -> String {
    DEFAULT_COUNTER_STATE.to_owned()
}

const DEFAULT_COUNTER_STATE: &str = "/var/lib/ghostbro/spa-counters.toml";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_prd_style_server_config() {
        let config: ServerConfig = toml::from_str(
            r#"
            [server]
            identity = "/etc/ghostbro/server.key"

            [spa]
            mode = "udp"

            [spa.udp]
            port = 53
            rate_limit = 5

            [spa.common]
            time_window = 300
            allow_ttl = 14400

            [proxy]
            port = 8443
            noise_pattern = "Noise_XK_25519_ChaChaPoly_BLAKE2s"
            bind = "0.0.0.0"

            [clients]
            authorized_keys = "/etc/ghostbro/authorized_keys.toml"

            [decoy]
            mode = "builtin"
            bind = "0.0.0.0:443"
            webroot = "/var/www/html"
            "#,
        )
        .expect("valid config");

        assert_eq!(53, config.spa.udp_port());
        assert_eq!(5, config.spa.udp_rate_limit());
        assert_eq!(8443, config.proxy.port);
        assert_eq!(300, config.spa.time_window_seconds());
        assert_eq!(14400, config.spa.allow_ttl_seconds());
        assert_eq!(204, config.spa.https_response_status());
        let decoy = config.decoy.expect("decoy config");
        assert_eq!(Some(DecoyModeConfig::Builtin), decoy.mode);
        assert_eq!(Some("0.0.0.0:443".to_owned()), decoy.bind);
        assert_eq!(Some("/var/www/html".to_owned()), decoy.webroot);
    }

    #[test]
    fn parses_https_response_status() {
        let config: ServerConfig = toml::from_str(
            r#"
            [server]
            identity = "/etc/ghostbro/server.key"

            [spa]
            mode = "https"

            [spa.https]
            path = "/api/v1/telemetry"
            response_status = 200
            trusted_proxy_cidrs = ["127.0.0.1/32"]

            [proxy]
            port = 8443
            noise_pattern = "Noise_XK_25519_ChaChaPoly_BLAKE2s"
            bind = "0.0.0.0"

            [clients]
            authorized_keys = "/etc/ghostbro/authorized_keys.toml"
            "#,
        )
        .expect("valid config");

        assert_eq!(200, config.spa.https_response_status());
        assert_eq!(
            &["127.0.0.1/32".to_owned()],
            config.spa.trusted_proxy_cidrs()
        );
    }
}
