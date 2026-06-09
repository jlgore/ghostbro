# Ghost Proxy: Censorship-Resistant Encrypted Proxy with eBPF Stealth Layer

## Specification v0.2 — DRAFT

---

## 1. Problem Statement

In regions where governments impose internet shutdowns or deep packet inspection (DPI), users need a proxy that is both functional and invisible. Existing solutions (Tor, Shadowsocks, vanilla VPNs) have known protocol fingerprints that state-level adversaries actively detect and block. A proxy that can be identified is a proxy that can be blocked — and in some jurisdictions, a proxy that can get its operator arrested.

Ghost Proxy addresses this by combining three layers: kernel-level traffic gating via eBPF that makes the proxy invisible to unauthorized observers, Single Packet Authorization (SPA) with asymmetric key authentication that limits the blast radius of key compromise, and a decoy service that presents a plausible cover identity to active probing.

## 2. Design Goals

- **Invisible to active probing**: An unauthorized observer connecting to the server sees only a legitimate-looking web service. No SOCKS5 fingerprint is ever exposed to untrusted clients.
- **Resistant to DPI**: The authenticated proxy tunnel uses Noise protocol, which produces traffic indistinguishable from random bytes. No TLS ClientHello, no protocol negotiation signatures.
- **Standard SPA authorization**: Access to the proxy is gated by Single Packet Authorization — a single cryptographically authenticated packet that silently opens a time-limited access window. No listening service is visible before authorization. The server never responds to invalid SPA packets.
- **Key compromise isolation**: Compromise of a single client key burns only that client. The server's identity and other clients remain secure.
- **Identity confidentiality**: A compromised server key cannot retroactively reveal which client public keys connected in captured traffic.
- **Operational simplicity**: The trust model is "I know this person." Key enrollment works over email or any channel that survives partial shutdowns.
- **Forward secrecy**: Bulk traffic capture today cannot be decrypted if long-term keys are compromised later.
- **Optimized for low-metadata protocols**: The system is designed for applications with small request payloads (BitTorrent, satellite card-sharing, SSH, DNS, package downloads) rather than raw web browsing, which leaks extensive metadata regardless of tunnel quality.

## 3. Architecture Overview

Ghost Proxy supports two SPA modes. The operator and client select the mode based on the network environment.

### 3.1 Standard SPA Mode (UDP)

Classic Single Packet Authorization over UDP. The SPA packet is a single UDP datagram containing a signed authorization payload. The server silently consumes valid packets and drops invalid ones — no response is ever sent. This is the highest-stealth mode: a network observer sees one outbound UDP packet that produces no reply.

```
┌──────────────────────────────────────────────────────────┐
│                      Internet                            │
└────────────────────────┬─────────────────────────────────┘
                         │
                ┌────────▼─────────┐
                │   XDP Program     │  Aya eBPF (kernel space)
                │                   │
                │  ┌─────────────┐  │
                │  │ SPA port:   │  │
                │  │ structural  │  │
                │  │ check +     │  │
                │  │ rate limit  │  │
                │  │ → ring buf  │  │
                │  │ → XDP_DROP  │  │
                │  ├─────────────┤  │
                │  │ Proxy port: │  │
                │  │ allow-map   │  │
                │  │ check       │  │
                │  ├─────────────┤  │
                │  │ All other:  │  │
                │  │ XDP_PASS    │  │
                │  └─────────────┘  │
                └───┬──────────┬───┘
                    │          │
          SPA valid │          │ not in allow-map
          candidate │          │
                    │          │
           ┌────────▼────────┐ │
           │  Ring Buffer     │ │
           └────────┬────────┘ │
                    │          │
           ┌────────▼────────┐ │    ┌─────────────────┐
           │ SPA Daemon      │ │    │  Decoy Service   │
           │ - Ed25519 verify│ │    │  (HTTPS on 443)  │
           │ - Replay check  │ │    └─────────────────┘
           │ - Allow-map     │ │
           │   write         │ │
           └────────┬────────┘ │
                    │          │
              ┌─────▼──────┐   │
              │  BPF Allow  │◄─┘
              │    Map      │
              └─────┬──────┘
                    │ allowed
           ┌────────▼──────────────┐
           │  fast-socks5           │
           │  + Noise IK tunnel    │
           │  (ChaCha20-Poly1305)  │
           └───────────────────────┘
```

**When to use:** Networks where UDP is not protocol-inspected. Provides maximum stealth because the SPA port never responds to anything — it's indistinguishable from a closed port to a scanner. Follows the fwknop model.

### 3.2 HTTPS SPA Mode

SPA payload delivered as the body of an HTTPS POST to the decoy web service. The server returns an identical HTTP response (204 No Content or a fake JSON body) regardless of whether the SPA payload was valid. This mode trades the absolute silence of UDP SPA for protocol conformance — the SPA looks like a normal HTTPS request to a web server.

```
┌──────────────────────────────────────────────────────────┐
│                      Internet                            │
└────────────────────────┬─────────────────────────────────┘
                         │
                ┌────────▼──────────────┐
                │   Decoy Service        │  Port 443 (TLS)
                │   (nginx / axum)       │
                │                        │
                │  ┌──────────────────┐  │
                │  │ POST /telemetry  │──┼──► SPA Daemon
                │  │ (SPA endpoint)   │  │    (Ed25519 verify)
                │  ├──────────────────┤  │         │
                │  │ /* (decoy site)  │  │         ▼
                │  └──────────────────┘  │    BPF Allow Map
                └────────────────────────┘         │
                                                   │
                ┌──────────────────────┐            │
                │   XDP Filter          │◄───────────┘
                │   (allow/deny only    │
                │    on proxy port)     │
                └──────────┬───────────┘
                           │ allowed
                ┌──────────▼───────────┐
                │   Noise IK + SOCKS5   │  Port 8443
                │   (fast-socks5)       │
                └──────────────────────┘
```

**When to use:** Networks where DPI performs protocol conformance checking (e.g., all UDP on port 53 must be valid DNS). This is more visible than UDP SPA (a full TLS handshake and HTTP exchange), but the SPA is indistinguishable from a normal web request to the decoy site.

**Note:** In HTTPS SPA mode, the XDP program is simpler — it only checks the allow-map on the proxy port. There is no ring buffer or structural SPA parsing in the XDP layer; the SPA processing happens entirely in userspace behind the web server.

## 4. Single Packet Authorization (SPA)

### 4.1 SPA Principles

Ghost Proxy's SPA implementation follows established SPA principles (as formalized by fwknop and the SPA RFC draft) with asymmetric cryptography:

1. **Single packet**: Authorization requires exactly one packet (UDP datagram or HTTPS POST body). No multi-packet sequences, no handshakes, no challenge-response.

2. **No server response to invalid packets**: In UDP mode, invalid SPA packets are silently dropped at XDP — the server behaves identically to a host with no service on that port. In HTTPS mode, valid and invalid SPA attempts receive the same HTTP response. An attacker cannot distinguish "wrong key" from "no service."

3. **Cryptographic authentication**: Each SPA packet carries an Ed25519 signature over a timestamp, counter, and nonce. Only clients whose public keys are in the server's authorized set can produce valid signatures.

4. **Replay protection**: A monotonic counter and timestamp window ensure each SPA packet is single-use. Captured packets cannot be replayed.

5. **Minimal attack surface**: Before SPA authorization, the server exposes zero listening services on the proxy port (kernel-level drop via XDP). The proxy's TCP stack is never reached by unauthorized clients.

6. **Time-limited access**: A successful SPA opens a time-limited window (default 4 hours) during which the client's source IP can reach the proxy port. Access expires automatically.

### 4.2 SPA vs. Traditional Port Knocking

Ghost Proxy uses SPA, not port knocking. The distinction matters:

| Property | Port Knocking | SPA |
|----------|--------------|-----|
| Packets required | Multiple (sequence of SYN to ports X, Y, Z) | One |
| Fingerprintable by traffic analysis | Yes — sequential SYN packets to multiple ports from one source are distinctive | No — single UDP datagram or HTTPS POST |
| Replay protection | None inherent (same sequence works forever) | Built-in (counter + timestamp + nonce) |
| Cryptographic auth | Typically none (security by obscurity) | Ed25519 signature |
| Server response to invalid attempts | May leak timing via TCP RST on some ports | None (UDP mode) or identical response (HTTPS mode) |

### 4.3 SPA Packet Format

The SPA payload is identical regardless of transport mode (UDP or HTTPS). In UDP mode, it is the UDP datagram payload. In HTTPS mode, it is the raw POST body (Content-Type: application/octet-stream).

```
┌──────────────────────────────────────────────────────────┐
│  Offset  │  Size   │  Field                              │
├──────────┼─────────┼─────────────────────────────────────┤
│  0       │  2      │  version (0x47 0x50 — "GP")         │
│  2       │  1      │  spa_flags                          │
│          │         │    bit 0: 0=UDP mode, 1=HTTPS mode  │
│          │         │    bits 1-7: reserved (zero)        │
│  3       │  8      │  key_id (first 8 bytes of           │
│          │         │    SHA-256 of client public key)     │
│  11      │  8      │  timestamp_ms (Unix millis, BE)     │
│  19      │  8      │  counter (monotonic, BE)            │
│  27      │  16     │  nonce (random)                     │
│  43      │  64     │  signature (Ed25519 over            │
│          │         │    bytes 0..43)                      │
│  107     │  0-21   │  padding (random bytes to vary      │
│          │         │    total size: 107–128 bytes)        │
└──────────────────────────────────────────────────────────┘
Total: 107–128 bytes
```

**Changes from v0.1:**

- Added 2-byte version prefix (`0x47 0x50`) for protocol evolution. Included in signed region.
- Added 1-byte `spa_flags` field for mode identification and future extensibility. Included in signed region.
- Signature now covers bytes 0–42 (version + flags + key_id + timestamp + counter + nonce).

**Signature Input**: `Ed25519_Sign(client_private_key, version || spa_flags || key_id || timestamp_ms || counter || nonce)`

**Padding**: Random bytes appended after the signature to vary total packet size between 107 and 128 bytes. Not covered by the signature. Prevents fingerprinting based on fixed packet size.

### 4.4 UDP SPA Transport Details

**Port selection**: The SPA port should be chosen based on the network environment:

| Port | Protocol | Rationale |
|------|----------|-----------|
| 53   | DNS      | Almost always allowed. Packet size (107–128 bytes) is consistent with DNS responses. Risk: DPI may check DNS conformance. |
| 123  | NTP      | Widely allowed. NTP packets are 48+ bytes, so 107–128 is plausible as an NTP extension field response. |
| 443  | QUIC/UDP | Increasingly common. Random-looking UDP on 443 blends with QUIC traffic. |
| 1194 | OpenVPN  | Common on VPS hosts. May attract attention in some regions. |

**Server behavior**: The XDP program consumes all packets on the SPA port. It never responds, never sends ICMP unreachable, never generates any outbound traffic in response to an SPA attempt. To a port scanner, the port appears filtered or closed (indistinguishable from a host that simply drops the traffic).

**Structural pre-filter (XDP)**: Before pushing to the ring buffer, the XDP program performs lightweight validation:

1. Check UDP payload length is 107–128 bytes.
2. Check version prefix is `0x47 0x50`.
3. Check `spa_flags` byte has no undefined bits set.
4. Rate-limit: check per-source-IP token bucket (max 5 attempts per minute).
5. If all checks pass: copy payload to ring buffer, return `XDP_DROP`.
6. If any check fails: `XDP_DROP` (silent).

This filters out random noise and port scans before they reach userspace, while keeping the XDP program simple enough for the eBPF verifier.

### 4.5 HTTPS SPA Transport Details

**Endpoint**: `POST /api/v1/telemetry` (or configurable path). The path should look like a legitimate analytics or telemetry endpoint.

**Request**:
```
POST /api/v1/telemetry HTTP/1.1
Host: example.com
Content-Type: application/octet-stream
Content-Length: 118
[... 107-128 bytes of SPA payload ...]
```

**Response (always identical)**:
```
HTTP/1.1 204 No Content
Server: nginx/1.26.0
X-Request-Id: <random-uuid>
Date: <current>
```

The response is the same for valid SPA, invalid SPA, and random garbage. The `X-Request-Id` is regenerated for each request so responses aren't identical byte-for-byte (which would itself be a fingerprint).

**Processing**: The web server (nginx reverse-proxying to the SPA daemon, or an axum handler in the built-in decoy) extracts the raw POST body and passes it to the same SPA verification pipeline as the UDP path. The only difference is that the source IP comes from the TCP connection (or `X-Forwarded-For` if behind a load balancer) rather than the UDP packet header.

### 4.6 SPA Verification Pipeline (Shared)

Regardless of transport mode, the SPA daemon processes payloads identically:

1. Parse the SPA envelope (§4.3).
2. Validate version prefix (`0x47 0x50`).
3. Look up client public key by `key_id` in the `authorized_keys` config.
4. If `key_id` not found: reject (log as unknown key_id, no further detail).
5. Verify Ed25519 signature over bytes 0–42.
6. If signature invalid: reject.
7. Check `timestamp_ms` is within the acceptable window (±`time_window` seconds, default 300).
8. Check `counter` > highest seen counter for this `key_id`.
9. Update high-water counter for this `key_id` (persisted to local state file).
10. Write source IP to `ALLOW_MAP` with TTL (`allow_ttl`, default 14400 seconds / 4 hours).
11. Log: `SPA_ACCEPT key_id=<hex> src=<ip> mode=<udp|https> counter=<n>`.

**Rejection logging**: All rejections are logged with the reason (unknown key, bad signature, expired timestamp, replayed counter) but no sensitive material. Rate-limited to prevent log flooding from brute-force attempts.

### 4.7 Allow-Map Management

**Map structure:**

| Map | Type | Key | Value | Purpose |
|-----|------|-----|-------|---------|
| `ALLOW_MAP` | `HashMap` | `u32` (src IPv4) | `AllowEntry { expiry_ns: u64, client_id: u16 }` | SPA-authorized clients |
| `RATE_LIMIT` | `HashMap` | `u32` (src IPv4) | `RateState { tokens: u32, last_ns: u64 }` | Per-IP SPA rate limiting (UDP mode only) |
| `SPA_RING` | `RingBuf` | — | `SpaEvent { src_ip, src_port, payload: [u8; 128] }` | SPA candidates to userspace (UDP mode only) |

**TTL reaping (dual strategy):**

1. **Lazy reaping in XDP**: On each packet to the proxy port, the XDP program reads the allow-map entry and compares `expiry_ns` against `bpf_ktime_get_ns()`. If expired, the entry is treated as non-existent and deleted in-place. Zero userspace overhead.

2. **Periodic cleanup**: A userspace task runs every 60 seconds, iterates the allow-map, and deletes expired entries. This catches entries for clients that never send another packet after their TTL expires.

### 4.8 SPA Refresh

Clients with active sessions send periodic SPA refresh packets (every `allow_ttl / 2`) to keep their allow-map entry alive. The refresh is a normal SPA packet with an incremented counter. This handles:

- TTL expiration during long sessions.
- Source IP changes (mobile networks, NAT rebinding).
- Server restarts (allow-map is in-memory and lost on restart; client re-knocks automatically).

## 5. Proxy Tunnel (fast-socks5 + Noise IK)

### 5.1 Noise Handshake Pattern

**Pattern**: `Noise_IK_25519_ChaChaPoly_BLAKE2s`

v0.2 uses Noise IK instead of KK (v0.1). The change addresses identity confidentiality under server compromise:

| Pattern | Client identity protection | Server key compromise impact |
|---------|---------------------------|-------------------------------|
| KK (v0.1) | Encrypted under server static key | Attacker can decrypt all captured handshakes and extract client public keys → mass deanonymization |
| IK (v0.2) | Encrypted under ephemeral key agreement | Attacker cannot recover client identities from captured traffic (forward secrecy on identity) |

In Noise IK, the initiator (client) sends their static public key encrypted under the ephemeral Diffie-Hellman result. Even if the server's long-term key is later compromised, the ephemeral keys are gone — the client's identity is protected.

```rust
// v0.2 Noise IK configuration
let builder = snow::Builder::new(
    "Noise_IK_25519_ChaChaPoly_BLAKE2s".parse()?
)
    .local_private_key(&client_static_private)
    .remote_public_key(&server_static_public)
    .prologue(&key_id_bytes);  // connection binding
```

### 5.2 Connection Binding via Prologue

Instead of the fragile IP-based cross-referencing in v0.1, v0.2 binds the SPA authorization to the Noise session using the Noise prologue:

- Both client and server set the Noise prologue to the client's `key_id` (8 bytes) before the handshake.
- The client knows their own `key_id`; the server looks up the `key_id` from the allow-map entry for the connecting source IP.
- If the prologues don't match, the Noise handshake fails cryptographically — no explicit check needed.
- This prevents an attacker who shares a NAT IP with a legitimate client from hijacking the allow-map entry: they don't know the `key_id` to set as the prologue.

### 5.3 Post-Handshake Protocol Multiplexing

After the Noise IK handshake completes, the first byte of application data selects the protocol:

| Byte | Protocol | Description |
|------|----------|-------------|
| `0x05` | SOCKS5 | Standard SOCKS5 greeting (backward compatible). For raw TCP proxying — BitTorrent, oscam/cccam, SSH tunneling. |
| `0x47` | Ghost Relay | Content Relay protocol (see Content Relay Module spec). For web content fetching, code downloads, package retrieval. |

This allows the same tunnel to carry both traditional SOCKS5 (for applications that need raw TCP) and the content relay (for stripped-down web content), selected per-session by the client.

### 5.4 Transport Framing

After the Noise IK handshake, application data is framed as:

```
┌──────────────────────────────────┐
│  2 bytes  │  Length (BE u16)     │
│  N bytes  │  Encrypted payload   │
│           │  (ChaCha20-Poly1305) │
└──────────────────────────────────┘
```

Maximum payload per frame: 65535 bytes. The `snow` crate handles encryption, authentication (Poly1305 tag), and nonce management.

## 6. Components

### 6.1 XDP Pre-Filter (Kernel Space)

**Crate**: `aya`, `aya-ebpf`

The XDP program runs at the earliest point in the network stack. Its responsibilities differ by SPA mode:

**UDP SPA mode:**
- SPA port: structural pre-filter → rate limit → ring buffer push → `XDP_DROP` (always, valid or not).
- Proxy port: allow-map check → `XDP_PASS` if allowed, `XDP_DROP` if not.
- All other ports: `XDP_PASS`.

**HTTPS SPA mode:**
- Proxy port: allow-map check → `XDP_PASS` if allowed, `XDP_DROP` if not.
- All other ports: `XDP_PASS` (including 443, which serves the decoy + SPA endpoint normally).

In HTTPS mode, the XDP program is minimal — just a single HashMap lookup on the proxy port. No ring buffer, no structural parsing.

### 6.2 SPA Daemon (Userspace)

**Crates**: `aya`, `ed25519-dalek`, `tokio`

In UDP mode: consumes `SpaEvent` structs from the BPF ring buffer, runs the verification pipeline (§4.6), and writes to the allow-map.

In HTTPS mode: receives SPA payloads from the web server via an internal channel (Unix socket or in-process `tokio::sync::mpsc`), runs the same verification pipeline, writes to the allow-map.

The SPA daemon is a single Rust binary that handles both modes. The mode is selected by configuration.

**Authorized Keys Config:**

```toml
# /etc/ghost-proxy/authorized_keys.toml

[[clients]]
name = "jared-laptop"
public_key = "K3J8mP2qR7vX9bN1..."  # base64 Ed25519 public key
noise_public_key = "N8vQm4pL8wR2kF5..."  # base64 derived X25519 Noise public key
tier = "full"                         # "full" = proxy access, "decoy" = decoy only
max_concurrent_sessions = 3

[[clients]]
name = "friend-phone"
public_key = "x7Qm4pL8wR2kF5..."
noise_public_key = "Y6bH2nP9qA4sT1..."
tier = "full"
max_concurrent_sessions = 2
```

**Hot Reload**: The daemon watches `authorized_keys.toml` via `inotify`. Adding or removing a key takes effect without restart. Removing a key purges active allow-map entries for that `key_id`.

### 6.3 Decoy Service

**Implementation**: nginx (recommended) or a minimal Rust static file server (`axum`)

The decoy runs on port 443 with a valid TLS certificate for a plausible domain. It serves a realistic website and, in HTTPS SPA mode, routes SPA requests to the daemon.

**Requirements:**

- Valid TLS with a real domain and Let's Encrypt certificate.
- HTTP response headers matching a stock nginx deployment.
- Real HTML/CSS/images, not a stub. Active probing tools check for realistic content.
- Access logs enabled and rotated normally.
- In HTTPS SPA mode: reverse proxy the SPA endpoint path to the SPA daemon; return identical 204 responses for valid and invalid payloads.

### 6.4 Proxy Server (fast-socks5 + Noise IK)

**Crates**: `fast-socks5`, `snow`, `tokio`

Listens on the proxy port (default 8443). Only reachable after SPA authorization (XDP drops all non-allowed traffic). Performs the Noise IK handshake, then serves SOCKS5 or Ghost Relay based on the first application byte.

## 7. Key Management

### 7.1 Key Generation

**Client:**

```bash
ghost-proxy keygen --output ~/.ghost-proxy/identity
# Generates:
#   ~/.ghost-proxy/identity.key     (Ed25519 private key, encrypted via argon2id)
#   ~/.ghost-proxy/identity.pub     (Ed25519 public key, base64, 44 chars)
#   ~/.ghost-proxy/identity.noise   (Curve25519 static key for Noise, derived)
#   ~/.ghost-proxy/identity.keyid   (key_id: first 8 bytes of SHA-256, hex)
```

Private key encrypted at rest with a user-chosen passphrase. KDF: argon2id (m=64MB, t=3, p=1, ~500ms on a modern phone).

**Server:**

```bash
ghost-proxy server-keygen --output /etc/ghost-proxy/server
# Generates:
#   /etc/ghost-proxy/server.key      (Ed25519 + Curve25519 private keys)
#   /etc/ghost-proxy/server.pub      (public keys, base64)
#   /etc/ghost-proxy/server.fp       (fingerprint: first 16 hex chars of SHA-256)
```

### 7.2 Enrollment Flow

```
 Client                         Server Operator
   │                                  │
   │  1. Generate keypair locally     │
   │                                  │
   │  2. Send public keys (Ed25519    │
   │     .pub and Noise .noise) via   │
   │     available                    │
   │     channel (email, Signal,      │
   │     in person)                   │
   │  ───────────────────────────►    │
   │                                  │  3. Verify sender identity
   │                                  │
   │                                  │  4. Add public keys to
   │                                  │     authorized_keys.toml
   │                                  │
   │  5. Receive server pubkey +      │
   │     endpoint + SPA config        │
   │  ◄────────────────────────────   │
   │                                  │
   │  6. Confirm fingerprints via     │
   │     second channel               │
   │  ◄──────────────────────────►    │
   │                                  │
   │  7. Configure client:            │
   │     ghost-proxy enroll           │
   │       --server-key <base64>      │
   │       --endpoint <ip:port>       │
   │       --spa-mode <udp|https>     │
   │       --spa-port <port>          │
   │                                  │
```

### 7.3 Revocation

Remove the client entry from `authorized_keys.toml`. The daemon detects the change via inotify, removes the key from its in-memory set, and purges active allow-map entries. In-flight Noise sessions terminate at the next rekey or TCP keepalive timeout.

## 8. Client Implementation

### 8.1 CLI Interface

```bash
# Generate identity
ghost-proxy keygen --output ~/.ghost-proxy/identity

# Enroll with a server
ghost-proxy enroll \
  --server-key "base64..." \
  --endpoint 203.0.113.42:8443 \
  --spa-mode udp \
  --spa-port 53

# Connect (SPA + tunnel + local SOCKS5 listener)
ghost-proxy connect \
  --config ~/.ghost-proxy/servers/myserver.toml \
  --listen 127.0.0.1:1080
# 1. Prompts for passphrase
# 2. Sends SPA packet (UDP or HTTPS per config)
# 3. Establishes Noise IK tunnel
# 4. Starts local SOCKS5 proxy on 1080

# Connect with explicit SPA mode override
ghost-proxy connect \
  --config ~/.ghost-proxy/servers/myserver.toml \
  --spa-mode https \
  --listen 127.0.0.1:1080
# Overrides configured SPA mode (useful when network conditions change)

# Revoke own key (best-effort notification to server)
ghost-proxy revoke --config ~/.ghost-proxy/servers/myserver.toml
```

Implementation note: the proxy server and client-side local listener use `fast-socks5`; current SOCKS5 support remains no-auth TCP CONNECT over the Noise IK tunnel.

### 8.2 Connection Sequence

1. Load client identity (decrypt private key with passphrase).
2. Load server config (server pubkey, endpoint, SPA mode, SPA port).
3. Craft SPA packet: `version || flags || key_id || timestamp || counter++ || nonce`, sign with Ed25519, pad to 107–128 bytes.
4. Send SPA:
   - **UDP mode**: Send as UDP datagram to `spa_endpoint:spa_port`.
   - **HTTPS mode**: Send as POST body to `https://spa_endpoint/api/v1/telemetry`.
5. Wait briefly (100ms default, configurable).
6. Open TCP connection to `endpoint:proxy_port`.
7. Perform Noise IK handshake with `key_id` as prologue.
8. Send protocol selector byte (`0x05` for SOCKS5, `0x47` for Ghost Relay).
9. Start local listener on `--listen` address.
10. Forward connections through the Noise tunnel.
11. Schedule SPA refresh every `allow_ttl / 2`.

### 8.3 Multi-Server Failover

The client config supports multiple server entries for resilience:

```toml
# ~/.ghost-proxy/servers/mynetwork.toml

[[servers]]
endpoint = "203.0.113.42:8443"
spa_endpoint = "203.0.113.42"
spa_mode = "udp"
spa_port = 53
server_public_key = "..."
priority = 1

[[servers]]
endpoint = "198.51.100.7:8443"
spa_endpoint = "198.51.100.7"
spa_mode = "https"
spa_port = 443
server_public_key = "..."
priority = 2

[failover]
strategy = "priority"   # or "random", "latency"
retry_interval_ms = 5000
max_retries = 3
```

The client tries servers in priority order. If SPA or handshake fails, it falls through to the next server. Different servers can use different SPA modes — the client adapts per-server.

## 9. Server Configuration

```toml
# /etc/ghost-proxy/ghost-proxy.toml

[server]
identity = "/etc/ghost-proxy/server.key"

[spa]
# SPA mode: "udp", "https", or "both"
mode = "udp"

[spa.udp]
# Port for UDP SPA packets
port = 53
# Structural pre-filter + rate limiting in XDP
rate_limit = 5          # max SPA attempts per IP per minute

[spa.https]
# Path for HTTPS SPA endpoint (behind decoy TLS)
path = "/api/v1/telemetry"
# Response to all SPA attempts (valid or not)
response_status = 204
# Only trust X-Forwarded-For from known reverse proxies
trust_forwarded_for = false
trusted_proxy_cidrs = ["127.0.0.1/32"]

[spa.common]
# Shared SPA verification parameters
time_window = 300       # timestamp tolerance in seconds
allow_ttl = 14400       # allow-map TTL in seconds (4 hours)

[proxy]
port = 8443
noise_pattern = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
bind = "0.0.0.0"

[decoy]
mode = "nginx"          # "nginx" (external) or "builtin" (axum)
port = 443
tls_cert = "/etc/letsencrypt/live/example.com/fullchain.pem"
tls_key = "/etc/letsencrypt/live/example.com/privkey.pem"
webroot = "/var/www/decoy"

[clients]
authorized_keys = "/etc/ghost-proxy/authorized_keys.toml"

[logging]
path = "/var/log/ghost-proxy/audit.log"
level = "info"
```

The `mode = "both"` option enables both UDP and HTTPS SPA simultaneously. The XDP program handles UDP SPA, and the decoy web server handles HTTPS SPA. Clients choose their mode per-connection.

## 10. Threat Model

### 10.1 What This Defends Against

| Threat | Mitigation |
|--------|------------|
| **Port scanning / active probing** | Proxy port is XDP_DROP for non-allowed IPs. UDP SPA port is XDP_DROP always (no response). HTTPS SPA returns identical response for valid/invalid. |
| **Deep packet inspection (DPI)** | Noise IK tunnel produces random-looking bytes. No TLS ClientHello, no SOCKS5 handshake visible on proxy port. |
| **Protocol conformance checking** | HTTPS SPA mode wraps the SPA in a standard HTTPS POST — passes DPI that verifies protocols match their port. |
| **Bulk capture + server key compromise** | Noise IK: client identity encrypted under ephemeral DH. Server key compromise does not reveal historical client identities. |
| **Single client key compromise** | Only the compromised client is affected. Revoke their pubkey. |
| **SPA replay** | Monotonic counter + timestamp window. Each SPA packet is single-use. |
| **SPA brute-force** | Per-IP rate limiting in XDP (UDP mode). Ed25519 signature space is infeasible to brute-force. |
| **Server impersonation** | Client pins server's Noise static public key. MitM cannot complete Noise IK without server's private key. |
| **Allow-map hijacking** | Noise prologue binding: attacker sharing a NAT IP with a legitimate client cannot complete the handshake without knowing the key_id. |

### 10.2 What This Does NOT Defend Against

| Threat | Limitation |
|--------|------------|
| **Traffic analysis / flow correlation** | Observable at both endpoints. Padding and shaping are future work. |
| **Compromised server host** | Server seizure exposes server private key and authorized_keys list. Mitigated by: Noise IK (past client identities safe), full disk encryption, multi-server deployment. |
| **Rubber-hose cryptanalysis** | Passphrase on client key buys time to revoke, not permanent protection. |
| **Endpoint compromise** | Out of scope. Owned client = game over regardless. |
| **IPv6** | v0.2 is IPv4 only. |
| **Web browsing metadata leakage** | Browser fingerprinting (User-Agent, cookies, etc.) is visible to destination servers through the proxy. Use the Content Relay module for stripped-down web content instead. |
| **UDP SPA on protocol-inspected networks** | A 107-byte UDP packet on port 53 that isn't valid DNS may be flagged. Use HTTPS SPA mode on such networks. |

## 11. Crate / Dependency Map

| Component | Crate | Purpose |
|-----------|-------|---------|
| eBPF XDP program | `aya-ebpf`, `aya-log-ebpf` | Kernel-space packet filter + SPA pre-filter |
| Userspace eBPF | `aya`, `aya-log` | XDP loader, map management, ring buffer consumer |
| Ed25519 | `ed25519-dalek` | SPA signature creation/verification |
| Noise protocol | `snow` | IK handshake, ChaCha20-Poly1305 transport |
| SOCKS5 | `fast-socks5` | Async SOCKS5 server |
| Async runtime | `tokio` | Async I/O |
| Config | `serde`, `toml` | Configuration parsing |
| Argon2id | `argon2` | Client key passphrase encryption |
| CLI | `clap` | Client and server CLI |
| File watching | `notify` | Hot-reload authorized_keys |
| Logging | `tracing`, `tracing-subscriber` | Structured audit logging |
| HTTP (HTTPS SPA) | `reqwest` (client), `axum` (server builtin) | HTTPS SPA transport |

## 12. Project Structure

```
ghost-proxy/
├── Cargo.toml                    # Workspace
├── ghost-proxy-ebpf/             # eBPF XDP program (aya-ebpf)
│   ├── Cargo.toml
│   └── src/
│       └── main.rs               # XDP filter, SPA pre-filter, allow-map check
├── ghost-proxy-common/           # Shared types
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── spa.rs                # SPA packet format, construction, parsing
│       ├── keys.rs               # Key types, key_id derivation
│       └── protocol.rs           # Wire format constants, version
├── ghost-proxy-server/           # Server daemon
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs               # Entrypoint, config, orchestration
│       ├── spa.rs                # SPA verification pipeline (shared logic)
│       ├── spa_udp.rs            # Ring buffer consumer for UDP SPA
│       ├── spa_https.rs          # HTTPS endpoint handler for HTTPS SPA
│       ├── allow_map.rs          # BPF map management, TTL reaper
│       ├── proxy.rs              # fast-socks5 + Noise IK tunnel
│       ├── decoy.rs              # Decoy HTTPS server
│       └── keys.rs               # Authorized keys, hot reload
├── ghost-proxy-client/           # Client CLI
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs               # CLI entrypoint (clap)
│       ├── keygen.rs             # Key generation + argon2id
│       ├── spa.rs                # SPA packet construction + send (UDP + HTTPS)
│       ├── tunnel.rs             # Noise IK initiator + local SOCKS5 listener
│       └── enroll.rs             # Server enrollment config
└── README.md
```

## 13. Operational Considerations

### 13.1 Choosing SPA Mode

| Network Condition | Recommended Mode |
|-------------------|-----------------|
| UDP not inspected, minimal DPI | UDP SPA (maximum stealth) |
| DPI checks protocol conformance on UDP | HTTPS SPA |
| Both UDP and HTTPS available | UDP SPA (less visible) |
| Only HTTPS works (strict firewall, everything else blocked) | HTTPS SPA |
| Unsure | Configure `mode = "both"` on server, let client try UDP first with HTTPS fallback |

### 13.2 Clock Synchronization

The SPA timestamp window (±300s) is generous because NTP may be unavailable during shutdowns. Client should surface a clear error if clock drift exceeds the window.

### 13.3 NAT and IP Instability

Allow-map is keyed on source IP. Clients behind CGNAT may share IPs or have IP changes mid-session. Mitigations: Noise IK handshake provides session-level auth regardless of IP. SPA refresh (§4.8) re-authorizes periodically. Noise prologue binding prevents allow-map hijacking by IP co-tenants.

### 13.4 Server Hardening

- Proxy runs as unprivileged user; only eBPF loader needs `CAP_BPF` / `CAP_NET_ADMIN`.
- Full disk encryption (LUKS).
- Unattended-upgrades.
- SSH: key-only, non-standard port, ideally behind its own SPA.
- Fail2ban on decoy service.
- Minimal packages.

### 13.5 Recommended Use Cases

Ghost Proxy is optimized for protocols with small, non-identifying request payloads:

| Use Case | Request Size | Response Profile | Metadata Risk |
|----------|-------------|-----------------|---------------|
| **BitTorrent** | ~50 bytes (piece request) | Chunked piece data | Low — no browser fingerprint |
| **Satellite card-sharing (oscam/cccam)** | ~150 bytes (ECM) | ~16 bytes (CW) every ~10s | Very low — minimal traffic |
| **SSH tunneling** | Variable, small | Variable | Low — encrypted end-to-end |
| **Package downloads** (via Content Relay) | ~50 bytes (package spec) | Compressed archive | Low — stripped metadata |
| **Web content** (via Content Relay) | ~50 bytes (URL) | Clean markdown/text | Low — server fetches, not client |
| **Raw web browsing** (via SOCKS5) | 2–5 KB (HTTP headers) | 2–5 MB per page load | **High** — browser fingerprint, cookies, sub-resource fetches |

Web browsing through raw SOCKS5 is supported but not recommended. The Content Relay module provides a lower-risk alternative for accessing web content.

## 14. Future Work

- **IPv6 support**: Extend BPF maps to 128-bit keys.
- **UDP ASSOCIATE**: SOCKS5 UDP forwarding through the Noise tunnel.
- **Traffic shaping / padding**: Constant-rate traffic to resist flow analysis.
- **Multi-node deployment**: Signed authorized-keys snapshots across 2–5 nodes.
- **Multi-hop**: Chain multiple Ghost Proxy instances.
- **Mobile client**: iOS/Android with tun2socks integration.
- **Meshtastic enrollment**: QR-code key exchange over LoRa.
- **Pluggable transports**: obfs4-style wire format for high-entropy-flagging environments.
- **Canary / duress key**: Alert operator when client is under coercion.
- **QUIC SPA mode**: SPA embedded in QUIC Initial packets.
- **Content Relay module**: Server-side web fetching, search, git clone, package download with store-and-forward queuing (see separate spec).

## 15. Changelog from v0.1

| Change | Rationale |
|--------|-----------|
| Renamed "knock" to "SPA" (Single Packet Authorization) throughout | Correct terminology; distinguishes from traditional port knocking |
| Added 2-byte version prefix and 1-byte flags to SPA packet | Protocol evolution support |
| Added HTTPS SPA mode alongside UDP SPA | Censorship resistance on networks with protocol conformance checking |
| Switched Noise KK → Noise IK | Identity confidentiality under server compromise |
| Replaced IP-based connection binding with Noise prologue binding | More robust, works across NAT |
| Added multi-server client failover | Survivability — no single server is a single point of failure |
| Added protocol multiplexing (SOCKS5 / Ghost Relay) | Support for Content Relay module |
| Separated XDP responsibilities by SPA mode | Simpler eBPF in HTTPS mode |
| Added recommended use cases section | Document that low-metadata protocols are the sweet spot |
| Added dual TTL reaping strategy | Lazy XDP reaping + periodic userspace cleanup |
| Split server SPA handling into `spa.rs`, `spa_udp.rs`, `spa_https.rs` | Clean separation of shared verification logic from transport-specific code |

## 16. License

TBD — consider dual-licensing under MIT + Apache 2.0 for maximum adoption in censorship-circumvention contexts.
