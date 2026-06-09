use std::{
    fs,
    io::{ErrorKind, IoSlice},
    net::IpAddr,
    path::Path,
    pin::Pin,
    task::{Context as TaskContext, Poll},
    time::Duration,
};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use fast_socks5::{
    server::{run_tcp_proxy, DnsResolveHelper, Socks5ServerProtocol},
    ReplyError, Socks5Command,
};
use ghost_proxy_common::{
    keys::key_id_hex,
    protocol::{PROTOCOL_GHOST_RELAY, PROTOCOL_SOCKS5},
};
use subtle::ConstantTimeEq;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
};

use crate::ebpf::{format_ipv4, monotonic_now_ns, AllowedSources};
use crate::relay::RelayEngine;

const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
const MAX_FRAME_LEN: usize = 16 * 1024;
const NOISE_TAG_LEN: usize = 16;

pub async fn run_proxy_listener(
    bind: String,
    identity_path: String,
    allowed_sources: AllowedSources,
    relay: RelayEngine,
) -> Result<()> {
    let static_key = load_or_generate_static_key(&identity_path)?;
    let listener = TcpListener::bind(&bind)
        .await
        .with_context(|| format!("failed to bind Noise TCP proxy on {bind}"))?;
    tracing::info!(bind, identity_path, "started Noise TCP proxy listener");

    loop {
        let (stream, peer_addr) = listener
            .accept()
            .await
            .context("failed to accept proxy TCP")?;
        let static_key = static_key.clone();
        let allowed_sources = allowed_sources.clone();
        let relay = relay.clone();

        tokio::spawn(async move {
            if let Err(error) =
                handle_connection(stream, peer_addr.ip(), static_key, allowed_sources, relay).await
            {
                tracing::warn!(?error, src_ip = %peer_addr.ip(), "NOISE_REJECT");
            }
        });
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    peer_ip: IpAddr,
    static_key: Vec<u8>,
    allowed_sources: AllowedSources,
    relay: RelayEngine,
) -> Result<()> {
    let IpAddr::V4(peer_ipv4) = peer_ip else {
        bail!("only IPv4 peers are supported in this smoke path");
    };
    let src_ip = u32::from_be_bytes(peer_ipv4.octets());
    let source = {
        let mut sources = allowed_sources
            .write()
            .expect("allowed source mirror lock poisoned");
        let Some(source) = sources.get(&src_ip).copied() else {
            bail!("source IP has no SPA allow entry");
        };
        if source.entry.expiry_ns <= monotonic_now_ns()? {
            sources.remove(&src_ip);
            bail!("SPA allow entry expired");
        }
        source
    };

    let params = NOISE_PATTERN.parse().context("invalid Noise pattern")?;
    let mut noise = snow::Builder::new(params)
        .local_private_key(&static_key)
        .prologue(&source.entry.key_id)
        .build_responder()
        .context("failed to build Noise IK responder")?;

    let msg1 = read_frame(&mut stream).await?;
    let mut buf = vec![0u8; MAX_FRAME_LEN];
    noise
        .read_message(&msg1, &mut buf)
        .context("failed to read Noise IK message 1")?;
    verify_client_noise_static(noise.get_remote_static(), &source.noise_public_key)?;

    let len = noise
        .write_message(&[], &mut buf)
        .context("failed to write Noise IK message 2")?;
    write_frame(&mut stream, &buf[..len]).await?;

    let mut transport = noise
        .into_transport_mode()
        .context("failed to enter Noise transport mode")?;
    tracing::info!(
        src_ip = %format_ipv4(src_ip),
        key_id = %key_id_hex(&source.entry.key_id),
        "NOISE_ACCEPT"
    );

    let plaintext = read_encrypted_frame(&mut stream, &mut transport, &mut buf).await?;
    match plaintext.first().copied() {
        Some(PROTOCOL_SOCKS5) => {
            handle_socks5(src_ip, plaintext, stream, transport).await?;
            return Ok(());
        }
        Some(PROTOCOL_GHOST_RELAY) => {
            handle_ghost_relay(
                src_ip,
                &source.entry.key_id,
                plaintext,
                &mut stream,
                &mut transport,
                &mut buf,
                &relay,
            )
            .await?;
            return Ok(());
        }
        _ => {}
    }

    let message = String::from_utf8_lossy(&plaintext);

    tracing::info!(
        src_ip = %format_ipv4(src_ip),
        bytes = plaintext.len(),
        message = %message,
        "NOISE_FRAME_DECRYPTED"
    );

    write_encrypted_frame(&mut stream, &mut transport, &plaintext, &mut buf).await?;

    Ok(())
}

async fn handle_ghost_relay(
    src_ip: u32,
    key_id: &[u8; 8],
    request: Vec<u8>,
    stream: &mut TcpStream,
    transport: &mut snow::TransportState,
    buf: &mut [u8],
    relay: &RelayEngine,
) -> Result<()> {
    tracing::info!(
        src_ip = %format_ipv4(src_ip),
        bytes = request.len(),
        "GHOST_RELAY_REQUEST"
    );

    let response = relay.dispatch(key_id, &request).await;
    write_encrypted_frame(stream, transport, &response, buf).await?;

    Ok(())
}

fn verify_client_noise_static(remote_static: Option<&[u8]>, expected: &[u8; 32]) -> Result<()> {
    let remote_static =
        remote_static.context("Noise IK message 1 did not include an initiator static key")?;
    // Constant-time comparison to avoid leaking how many leading bytes of the
    // SPA-authorized identity key matched. The length guard ensures ct_eq
    // operates over two equal-length 32-byte slices.
    let matches = remote_static.len() == expected.len()
        && bool::from(remote_static.ct_eq(expected.as_slice()));
    if !matches {
        bail!("client Noise static key does not match SPA-authorized identity");
    }
    Ok(())
}

async fn handle_socks5(
    src_ip: u32,
    greeting: Vec<u8>,
    stream: TcpStream,
    transport: snow::TransportState,
) -> Result<()> {
    let noise_stream = NoiseFramedStream::new(stream, transport, greeting);
    let proto = Socks5ServerProtocol::accept_no_auth(noise_stream)
        .await
        .context("failed SOCKS5 no-auth negotiation")?;
    tracing::info!(src_ip = %format_ipv4(src_ip), "SOCKS5_GREETING");

    let (proto, command, target) = proto
        .read_command()
        .await
        .context("failed to read SOCKS5 command")?
        .resolve_dns()
        .await
        .context("failed to resolve SOCKS5 target")?;
    tracing::info!(src_ip = %format_ipv4(src_ip), target = %target, "SOCKS5_CONNECT");

    if command != Socks5Command::TCPConnect {
        proto
            .reply_error(&ReplyError::CommandNotSupported)
            .await
            .context("failed to reply to unsupported SOCKS5 command")?;
        bail!("unsupported SOCKS5 command {command:?}");
    }

    let target_label = target.to_string();
    run_tcp_proxy(proto, &target, Duration::from_secs(10), false)
        .await
        .with_context(|| format!("failed to proxy SOCKS5 target {target_label}"))?;

    tracing::info!(src_ip = %format_ipv4(src_ip), target = %target_label, "SOCKS5_CONNECT_OK");
    tracing::info!(src_ip = %format_ipv4(src_ip), target = %target_label, "SOCKS5_RELAY_CLOSED");

    Ok(())
}

struct NoiseFramedStream {
    stream: TcpStream,
    transport: snow::TransportState,
    plaintext: Vec<u8>,
    plaintext_pos: usize,
    read_len: [u8; 2],
    read_len_pos: usize,
    encrypted_read: Vec<u8>,
    encrypted_read_pos: usize,
    pending_write: Vec<u8>,
    pending_write_pos: usize,
}

impl NoiseFramedStream {
    fn new(stream: TcpStream, transport: snow::TransportState, initial_plaintext: Vec<u8>) -> Self {
        Self {
            stream,
            transport,
            plaintext: initial_plaintext,
            plaintext_pos: 0,
            read_len: [0; 2],
            read_len_pos: 0,
            encrypted_read: Vec::new(),
            encrypted_read_pos: 0,
            pending_write: Vec::new(),
            pending_write_pos: 0,
        }
    }

    fn max_plaintext_len() -> usize {
        MAX_FRAME_LEN - NOISE_TAG_LEN
    }

    fn poll_read_outer_frame(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<Option<Vec<u8>>>> {
        let this = self.get_mut();

        while this.read_len_pos < this.read_len.len() {
            let before = this.read_len_pos;
            let mut len_buf = ReadBuf::new(&mut this.read_len[before..]);
            match Pin::new(&mut this.stream).poll_read(cx, &mut len_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    let read = len_buf.filled().len();
                    if read == 0 {
                        if this.read_len_pos == 0 {
                            return Poll::Ready(Ok(None));
                        }
                        return Poll::Ready(Err(std::io::Error::new(
                            ErrorKind::UnexpectedEof,
                            "connection closed while reading frame length",
                        )));
                    }
                    this.read_len_pos += read;
                }
            }
        }

        if this.encrypted_read.is_empty() {
            let frame_len = usize::from(u16::from_be_bytes(this.read_len));
            if frame_len > MAX_FRAME_LEN {
                return Poll::Ready(Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    format!("frame length {frame_len} exceeds maximum {MAX_FRAME_LEN}"),
                )));
            }
            this.encrypted_read.resize(frame_len, 0);
            this.encrypted_read_pos = 0;
        }

        while this.encrypted_read_pos < this.encrypted_read.len() {
            let before = this.encrypted_read_pos;
            let mut frame_buf = ReadBuf::new(&mut this.encrypted_read[before..]);
            match Pin::new(&mut this.stream).poll_read(cx, &mut frame_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    let read = frame_buf.filled().len();
                    if read == 0 {
                        return Poll::Ready(Err(std::io::Error::new(
                            ErrorKind::UnexpectedEof,
                            "connection closed while reading frame",
                        )));
                    }
                    this.encrypted_read_pos += read;
                }
            }
        }

        let frame = std::mem::take(&mut this.encrypted_read);
        this.encrypted_read_pos = 0;
        this.read_len = [0; 2];
        this.read_len_pos = 0;
        Poll::Ready(Ok(Some(frame)))
    }

    fn poll_flush_pending(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        while this.pending_write_pos < this.pending_write.len() {
            match Pin::new(&mut this.stream)
                .poll_write(cx, &this.pending_write[this.pending_write_pos..])
            {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        ErrorKind::WriteZero,
                        "failed to write Noise frame",
                    )));
                }
                Poll::Ready(Ok(written)) => this.pending_write_pos += written,
            }
        }
        this.pending_write.clear();
        this.pending_write_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for NoiseFramedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.as_mut().poll_flush_pending(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }

        loop {
            if self.plaintext_pos < self.plaintext.len() {
                let available = &self.plaintext[self.plaintext_pos..];
                let len = available.len().min(buf.remaining());
                buf.put_slice(&available[..len]);
                self.plaintext_pos += len;
                if self.plaintext_pos == self.plaintext.len() {
                    self.plaintext.clear();
                    self.plaintext_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            let encrypted = match self.as_mut().poll_read_outer_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(None)) => return Poll::Ready(Ok(())),
                Poll::Ready(Ok(Some(encrypted))) => encrypted,
            };

            let mut plaintext = vec![0u8; MAX_FRAME_LEN];
            let len = self
                .transport
                .read_message(&encrypted, &mut plaintext)
                .map_err(|error| std::io::Error::new(ErrorKind::InvalidData, error))?;
            plaintext.truncate(len);
            self.plaintext = plaintext;
        }
    }
}

impl AsyncWrite for NoiseFramedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.as_mut().poll_flush_pending(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let plaintext_len = buf.len().min(Self::max_plaintext_len());
        let mut encrypted = vec![0u8; MAX_FRAME_LEN];
        let encrypted_len = self
            .transport
            .write_message(&buf[..plaintext_len], &mut encrypted)
            .map_err(|error| std::io::Error::new(ErrorKind::InvalidData, error))?;
        encrypted.truncate(encrypted_len);

        let frame_len: u16 = encrypted_len
            .try_into()
            .map_err(|_| std::io::Error::new(ErrorKind::InvalidData, "Noise frame too large"))?;
        self.pending_write = Vec::with_capacity(2 + encrypted_len);
        self.pending_write
            .extend_from_slice(&frame_len.to_be_bytes());
        self.pending_write.extend_from_slice(&encrypted);
        self.pending_write_pos = 0;
        tracing::info!(bytes = plaintext_len, "SOCKS5_FRAME_RELAYED");

        match self.as_mut().poll_flush_pending(cx) {
            Poll::Pending => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }

        Poll::Ready(Ok(plaintext_len))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match self.as_mut().poll_flush_pending(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.as_mut().poll_flush_pending(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let Some(buf) = bufs.iter().find(|buf| !buf.is_empty()) else {
            return Poll::Ready(Ok(0));
        };
        self.poll_write(cx, buf)
    }

    fn is_write_vectored(&self) -> bool {
        true
    }
}

impl Unpin for NoiseFramedStream {}

fn load_or_generate_static_key(path: impl AsRef<Path>) -> Result<Vec<u8>> {
    let path = path.as_ref();
    match fs::read_to_string(path) {
        Ok(contents) => {
            let key = STANDARD.decode(contents.trim()).with_context(|| {
                format!("failed to decode Noise private key {}", path.display())
            })?;
            if key.len() != 32 {
                bail!("Noise private key must be 32 bytes, got {}", key.len());
            }
            Ok(key)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if std::env::var_os("GHOST_PROXY_GENERATE_IDENTITY").is_none() {
                bail!(
                    "Noise static identity file {} not found; refusing to mint a new pinned \
                     identity on the serving path. Provision the identity out of band, or set \
                     GHOST_PROXY_GENERATE_IDENTITY=1 to opt into auto-generation (provisioning \
                     and smoke tests only).",
                    path.display()
                );
            }
            let params = NOISE_PATTERN.parse().context("invalid Noise pattern")?;
            let keypair = snow::Builder::new(params)
                .generate_keypair()
                .context("failed to generate Noise static keypair")?;
            write_private_key_file(path, format!("{}\n", STANDARD.encode(&keypair.private)))
                .with_context(|| format!("failed to write Noise private key {}", path.display()))?;
            fs::write(
                public_key_path(path),
                format!("{}\n", STANDARD.encode(&keypair.public)),
            )
            .with_context(|| format!("failed to write Noise public key for {}", path.display()))?;
            tracing::info!(
                identity_path = %path.display(),
                public_key_path = %public_key_path(path).display(),
                "generated debug Noise static keypair"
            );
            Ok(keypair.private)
        }
        Err(error) => Err(error).with_context(|| format!("failed to read {}", path.display())),
    }
}

/// Load this server's Noise static *public* key (32 bytes) from its identity
/// file. Used to bind the server's identity into SPA verification so a SPA
/// accepted by one node does not verify on another (F-003).
pub fn load_static_public_key(path: impl AsRef<Path>) -> Result<[u8; 32]> {
    let private = load_or_generate_static_key(path)?;
    let private: [u8; 32] = private
        .as_slice()
        .try_into()
        .context("Noise static private key must be 32 bytes")?;
    Ok(ghost_proxy_common::keys::derive_noise_public_from_private(
        &private,
    ))
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
        use std::io::Write as _;
        file.write_all(contents.as_ref())?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        fs::write(path, contents)
    }
}

fn public_key_path(path: &Path) -> std::path::PathBuf {
    if path.extension().is_some_and(|extension| extension == "key") {
        path.with_extension("pub")
    } else {
        path.with_extension("noise.pub")
    }
}

async fn read_frame<R>(stream: &mut R) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    read_frame_optional(stream)
        .await?
        .context("connection closed while reading frame length")
}

async fn read_frame_optional<R>(stream: &mut R) -> Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut len = [0u8; 2];
    if let Err(error) = stream.read_exact(&mut len).await {
        if error.kind() == ErrorKind::UnexpectedEof {
            return Ok(None);
        }
        return Err(error).context("failed to read frame length");
    }
    let len = usize::from(u16::from_be_bytes(len));
    if len > MAX_FRAME_LEN {
        bail!("frame length {len} exceeds maximum {MAX_FRAME_LEN}");
    }

    let mut frame = vec![0u8; len];
    stream
        .read_exact(&mut frame)
        .await
        .context("failed to read frame")?;
    Ok(Some(frame))
}

async fn write_frame<W>(stream: &mut W, frame: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let len: u16 = frame
        .len()
        .try_into()
        .context("frame too large for 2-byte length")?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .context("failed to write frame length")?;
    stream
        .write_all(frame)
        .await
        .context("failed to write frame")?;
    Ok(())
}

async fn read_encrypted_frame(
    stream: &mut TcpStream,
    transport: &mut snow::TransportState,
    buf: &mut [u8],
) -> Result<Vec<u8>> {
    let encrypted = read_frame(stream).await?;
    let len = transport
        .read_message(&encrypted, buf)
        .context("failed to decrypt Noise application frame")?;
    Ok(buf[..len].to_vec())
}

async fn write_encrypted_frame(
    stream: &mut TcpStream,
    transport: &mut snow::TransportState,
    plaintext: &[u8],
    buf: &mut [u8],
) -> Result<()> {
    let len = transport
        .write_message(plaintext, buf)
        .context("failed to encrypt Noise application frame")?;
    write_frame(stream, &buf[..len]).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_matching_client_noise_static_key() {
        let expected = [7u8; 32];

        verify_client_noise_static(Some(&expected), &expected).expect("matching key accepted");
    }

    #[test]
    fn rejects_mismatched_client_noise_static_key() {
        let expected = [7u8; 32];
        let remote = [8u8; 32];

        let error = verify_client_noise_static(Some(&remote), &expected).expect_err("rejected");

        assert!(error.to_string().contains("does not match"));
    }

    #[test]
    fn noise_stream_plaintext_chunk_preserves_frame_limit() {
        assert_eq!(NoiseFramedStream::max_plaintext_len(), MAX_FRAME_LEN - 16);
    }
}
