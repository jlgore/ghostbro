use anyhow::Context as _;
use axum::{
    body::Bytes,
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode, Uri},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Router,
};
use ipnet::IpNet;
use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{net::TcpListener, sync::mpsc};
use tokio_rustls::{rustls, server::TlsStream, TlsAcceptor};

use crate::ebpf::HttpsSpaCandidate;

#[derive(Clone)]
pub struct DecoyState {
    spa_tx: Option<mpsc::Sender<HttpsSpaCandidate>>,
    response_status: StatusCode,
    trust_forwarded_for: bool,
    trusted_proxy_cidrs: Vec<IpNet>,
    webroot: Option<PathBuf>,
}

const NGINX_INDEX: &str = r#"<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light; }
body { width: 35em; margin: 0 auto; font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p>
<p>For online documentation and support please refer to <a href="http://nginx.org/">nginx.org</a>.</p>
<p><em>Thank you for using nginx.</em></p>
</body>
</html>
"#;

pub fn router(
    spa_tx: Option<mpsc::Sender<HttpsSpaCandidate>>,
    spa_path: &str,
    response_status: u16,
    trust_forwarded_for: bool,
    trusted_proxy_cidrs: &[String],
    webroot: Option<&str>,
) -> anyhow::Result<Router> {
    let response_status = StatusCode::from_u16(response_status)
        .map_err(|error| anyhow::anyhow!("invalid HTTPS SPA response status: {error}"))?;
    let trusted_proxy_cidrs = parse_trusted_proxy_cidrs(trusted_proxy_cidrs)?;
    Ok(Router::new()
        .route("/", get(decoy_content))
        .route(spa_path, post(telemetry))
        .fallback(decoy_content)
        .with_state(DecoyState {
            spa_tx,
            response_status,
            trust_forwarded_for,
            trusted_proxy_cidrs,
            // Canonicalize the webroot once at construction so per-request
            // containment checks compare against a symlink-resolved, absolute
            // base. A missing/unreadable webroot is a hard config error.
            webroot: match webroot {
                Some(root) => Some(
                    fs::canonicalize(root)
                        .with_context(|| format!("failed to canonicalize decoy webroot {root}"))?,
                ),
                None => None,
            },
        }))
}

async fn decoy_content(State(state): State<DecoyState>, uri: Uri) -> Response {
    if let Some(webroot) = &state.webroot {
        if let Some(response) = static_response(webroot, uri.path()).await {
            return response;
        }
    }

    index().await.into_response()
}

async fn index() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(header::SERVER, HeaderValue::from_static("nginx/1.26.0"));
    headers.insert(header::DATE, http_date());
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );

    (headers, Html(NGINX_INDEX))
}

/// Current time formatted as an HTTP `Date` header value. A real nginx always
/// sends one; emitting it keeps the decoy realistic and lets SPA clients
/// measure clock drift against the server.
fn http_date() -> HeaderValue {
    HeaderValue::from_str(&httpdate::fmt_http_date(SystemTime::now()))
        .unwrap_or_else(|_| HeaderValue::from_static("Thu, 01 Jan 1970 00:00:00 GMT"))
}

async fn static_response(webroot: &Path, uri_path: &str) -> Option<Response> {
    let path = static_path(webroot, uri_path)?;
    // `static_path` blocks `..` but does not resolve symlinks, so a symlink
    // under the webroot (e.g. webroot/data -> /etc) could otherwise escape.
    // Canonicalize the candidate and require it to stay within the (already
    // canonical) webroot before reading. canonicalize() resolves every symlink
    // in the path, so containment holds for the real target.
    let resolved = fs::canonicalize(&path).ok()?;
    if !resolved.starts_with(webroot) {
        tracing::warn!(
            requested = %uri_path,
            resolved = %resolved.display(),
            "rejecting static request that resolves outside webroot"
        );
        return None;
    }
    let bytes = fs::read(&resolved).ok()?;
    let mut headers = HeaderMap::new();
    headers.insert(header::SERVER, HeaderValue::from_static("nginx/1.26.0"));
    headers.insert(header::DATE, http_date());
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(content_type(&resolved)),
    );

    Some((headers, bytes).into_response())
}

fn static_path(webroot: &Path, uri_path: &str) -> Option<PathBuf> {
    let mut path = webroot.to_path_buf();
    let requested = uri_path.trim_start_matches('/');

    if requested.is_empty() {
        path.push("index.html");
        return Some(path);
    }

    for component in Path::new(requested).components() {
        match component {
            Component::Normal(part) => path.push(part),
            _ => return None,
        }
    }

    Some(path)
}

fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("css") => "text/css; charset=utf-8",
        Some("html") | Some("htm") => "text/html; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("png") => "image/png",
        Some("svg") => "image/svg+xml",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

async fn telemetry(
    State(state): State<DecoyState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    tracing::debug!(payload_len = body.len(), "received HTTPS SPA candidate");

    if let (Some(spa_tx), Some(ip)) = (
        &state.spa_tx,
        https_spa_source_ip(
            peer,
            &headers,
            state.trust_forwarded_for,
            &state.trusted_proxy_cidrs,
        ),
    ) {
        let candidate = HttpsSpaCandidate {
            src_ip: u32::from_be_bytes(ip.octets()),
            payload: body.to_vec(),
        };
        if let Err(error) = spa_tx.try_send(candidate) {
            tracing::warn!(?error, "failed to enqueue HTTPS SPA candidate");
        }
    }

    let mut headers = HeaderMap::new();
    headers.insert(header::SERVER, HeaderValue::from_static("nginx/1.26.0"));
    headers.insert(header::DATE, http_date());
    headers.insert(
        HeaderName::from_static("x-request-id"),
        HeaderValue::from_str(&request_id()).unwrap_or_else(|_| HeaderValue::from_static("0")),
    );

    (headers, state.response_status)
}

fn parse_trusted_proxy_cidrs(cidrs: &[String]) -> anyhow::Result<Vec<IpNet>> {
    cidrs
        .iter()
        .map(|cidr| {
            cidr.parse::<IpNet>()
                .map_err(|error| anyhow::anyhow!("invalid trusted proxy CIDR {cidr}: {error}"))
        })
        .collect()
}

fn https_spa_source_ip(
    peer: SocketAddr,
    headers: &HeaderMap,
    trust_forwarded_for: bool,
    trusted_proxy_cidrs: &[IpNet],
) -> Option<Ipv4Addr> {
    if trust_forwarded_for
        && trusted_proxy_cidrs
            .iter()
            .any(|cidr| cidr.contains(&peer.ip()))
    {
        if let Some(ip) = forwarded_for_first_ipv4(headers) {
            tracing::debug!(peer = %peer.ip(), forwarded_for = %ip, "using trusted X-Forwarded-For source IP");
            return Some(ip);
        }
    }

    match peer.ip() {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(_) => None,
    }
}

fn forwarded_for_first_ipv4(headers: &HeaderMap) -> Option<Ipv4Addr> {
    let value = headers.get("x-forwarded-for")?.to_str().ok()?;
    let first = value.split(',').next()?.trim();
    first.parse().ok()
}

fn request_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("{:x}-{:x}", std::process::id(), nanos)
}

/// A TLS-terminating listener that plugs into the existing `axum::serve`
/// machinery. It accepts a TCP connection, completes the rustls handshake, and
/// yields the decrypted stream plus the peer address — so `ConnectInfo` and
/// graceful shutdown behave exactly as they do for the plain-HTTP listener.
pub struct RustlsListener {
    tcp: TcpListener,
    acceptor: TlsAcceptor,
    local_addr: SocketAddr,
}

impl RustlsListener {
    /// Bind `addr` and prepare a rustls acceptor from the PEM cert/key files.
    pub async fn bind(addr: &str, cert_path: &str, key_path: &str) -> anyhow::Result<Self> {
        let config = build_server_config(cert_path, key_path)?;
        let tcp = TcpListener::bind(addr)
            .await
            .with_context(|| format!("failed to bind decoy TLS listener on {addr}"))?;
        let local_addr = tcp
            .local_addr()
            .context("failed to read decoy TLS local address")?;
        Ok(Self {
            tcp,
            acceptor: TlsAcceptor::from(Arc::new(config)),
            local_addr,
        })
    }
}

impl axum::serve::Listener for RustlsListener {
    type Io = TlsStream<tokio::net::TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, peer) = match self.tcp.accept().await {
                Ok(pair) => pair,
                Err(error) => {
                    // Transient accept errors: log and keep serving.
                    tracing::warn!(?error, "decoy TLS TCP accept failed");
                    continue;
                }
            };
            match self.acceptor.accept(stream).await {
                Ok(tls) => return (tls, peer),
                Err(error) => {
                    // A failed handshake (scanner, wrong SNI) is not fatal.
                    tracing::debug!(?error, peer = %peer, "decoy TLS handshake failed");
                    continue;
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.local_addr)
    }
}

/// Build a rustls server config from PEM files, pinning the `ring` crypto
/// provider explicitly so we never depend on a process-wide default provider.
fn build_server_config(cert_path: &str, key_path: &str) -> anyhow::Result<rustls::ServerConfig> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("failed to select decoy TLS protocol versions")?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("invalid decoy TLS certificate or private key")?;
    Ok(config)
}

fn load_certs(path: &str) -> anyhow::Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let data = fs::read(path).with_context(|| format!("failed to read TLS cert {path}"))?;
    let certs = rustls_pemfile::certs(&mut data.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("failed to parse TLS cert {path}"))?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in {path}");
    }
    Ok(certs)
}

fn load_key(path: &str) -> anyhow::Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let data = fs::read(path).with_context(|| format!("failed to read TLS key {path}"))?;
    rustls_pemfile::private_key(&mut data.as_slice())
        .with_context(|| format!("failed to parse TLS key {path}"))?
        .with_context(|| format!("no private key found in {path}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_configured_https_spa_response_status() {
        assert!(router(None, "/api/v1/telemetry", 200, false, &[], None).is_ok());
        assert!(router(None, "/api/v1/telemetry", 204, false, &[], None).is_ok());
    }

    #[test]
    fn rejects_invalid_https_spa_response_status() {
        assert!(router(None, "/api/v1/telemetry", 42, false, &[], None).is_err());
    }

    #[test]
    fn tls_config_errors_on_missing_files() {
        assert!(build_server_config("/nonexistent/cert.pem", "/nonexistent/key.pem").is_err());
    }

    #[tokio::test]
    async fn rejects_static_symlink_escape() {
        // F-006: a symlink under the webroot that points outside it must not be
        // served, even though `static_path` accepts the (dot-dot-free) request.
        let base = std::env::temp_dir().join(format!("ghost-decoy-{}", request_id()));
        let webroot = base.join("webroot");
        let secret_dir = base.join("secret");
        fs::create_dir_all(&webroot).expect("create webroot");
        fs::create_dir_all(&secret_dir).expect("create secret dir");
        fs::write(secret_dir.join("passwd"), b"root:x:0:0").expect("write secret");

        #[cfg(unix)]
        std::os::unix::fs::symlink(&secret_dir, webroot.join("escape")).expect("symlink");
        #[cfg(not(unix))]
        {
            let _ = (&secret_dir, &webroot);
            return;
        }

        let canonical_webroot = fs::canonicalize(&webroot).expect("canonicalize webroot");

        // static_path itself accepts the path (only `..` components are blocked).
        assert!(static_path(&canonical_webroot, "/escape/passwd").is_some());

        // static_response must reject it because it resolves outside the webroot.
        assert!(static_response(&canonical_webroot, "/escape/passwd")
            .await
            .is_none());

        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn rejects_static_path_traversal() {
        let webroot = Path::new("/var/www/html");

        assert!(static_path(webroot, "/../secret").is_none());
        assert!(static_path(webroot, "/assets/../secret").is_none());
        assert_eq!(
            webroot.join("index.html"),
            static_path(webroot, "/").unwrap()
        );
        assert_eq!(
            webroot.join("assets/site.css"),
            static_path(webroot, "/assets/site.css").unwrap()
        );
    }

    #[test]
    fn uses_forwarded_for_from_trusted_proxy() {
        let peer = "127.0.0.1:443".parse().expect("peer");
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "198.51.100.10".parse().expect("header"));
        let cidrs = parse_trusted_proxy_cidrs(&["127.0.0.1/32".to_owned()]).expect("cidrs");

        let source = https_spa_source_ip(peer, &headers, true, &cidrs).expect("source");

        assert_eq!(Ipv4Addr::new(198, 51, 100, 10), source);
    }

    #[test]
    fn ignores_forwarded_for_from_untrusted_peer() {
        let peer = "203.0.113.5:443".parse().expect("peer");
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "198.51.100.10".parse().expect("header"));
        let cidrs = parse_trusted_proxy_cidrs(&["127.0.0.1/32".to_owned()]).expect("cidrs");

        let source = https_spa_source_ip(peer, &headers, true, &cidrs).expect("source");

        assert_eq!(Ipv4Addr::new(203, 0, 113, 5), source);
    }

    #[test]
    fn ignores_invalid_forwarded_for() {
        let peer = "127.0.0.1:443".parse().expect("peer");
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "not-an-ip".parse().expect("header"));
        let cidrs = parse_trusted_proxy_cidrs(&["127.0.0.1/32".to_owned()]).expect("cidrs");

        let source = https_spa_source_ip(peer, &headers, true, &cidrs).expect("source");

        assert_eq!(Ipv4Addr::LOCALHOST, source);
    }

    #[test]
    fn uses_first_forwarded_for_ip() {
        let peer = "127.0.0.1:443".parse().expect("peer");
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "198.51.100.10, 203.0.113.5".parse().expect("header"),
        );
        let cidrs = parse_trusted_proxy_cidrs(&["127.0.0.1/32".to_owned()]).expect("cidrs");

        let source = https_spa_source_ip(peer, &headers, true, &cidrs).expect("source");

        assert_eq!(Ipv4Addr::new(198, 51, 100, 10), source);
    }
}
