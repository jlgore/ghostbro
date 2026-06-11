# Ghostbro: Censorship-Resistant Encrypted Proxy with eBPF Stealth Layer

## Specification v0.3 — DRAFT

---

## 1. Problem Statement

In regions where governments impose internet shutdowns or deep packet inspection (DPI), users need a proxy that is both functional and invisible. Existing solutions (Tor, Shadowsocks, vanilla VPNs) have known protocol fingerprints that state-level adversaries actively detect and block. A proxy that can be identified is a proxy that can be blocked — and in some jurisdictions, a proxy that can get its operator arrested.

Ghostbro addresses this by combining three layers: kernel-level traffic gating via eBPF that makes the proxy invisible to unauthorized observers, Single Packet Authorization (SPA) with asymmetric key authentication that limits the blast radius of key compromise, and a decoy service that presents a plausible cover identity to active probing.

## 2. Design Goals

- **Invisible to active probing**: An unauthorized observer connecting to the server sees only a legitimate-looking web service. No SOCKS5 fingerprint is ever exposed to untrusted clients.
- **Resistant to DPI**: The authenticated proxy tunnel uses Noise protocol, which produces traffic indistinguishable from random bytes. No TLS ClientHello, no protocol negotiation signatures. Note that high-entropy, protocol-unidentifiable traffic is *itself* a detectable class to a state adversary (see §10.2); the absence of a fingerprint is a fingerprint. Defeating entropy-based classification of fully-encrypted flows requires pluggable transports (§14), which are out of scope for v0.3.
- **Standard SPA authorization**: Access to the proxy is gated by Single Packet Authorization — a single cryptographically authenticated packet that silently opens a time-limited access window. The SPA packet itself is sealed to the server's public key (§4.3), so it carries no cleartext magic, structure, or client identifier — on the wire it is indistinguishable from random bytes. No listening service is visible before authorization. The server never responds to invalid SPA packets.
- **Key compromise isolation**: Compromise of a single client key burns only that client. The server's identity and other clients remain secure.
- **Identity confidentiality (passive observer)**: Against a network adversary that has *not* compromised the server, client identities never appear in cleartext on the wire. The SPA `key_id` is inside the sealed payload (§4.3) and the Noise XK handshake transmits the client static key forward-secretly (§5.1). A passive observer cannot link the same client across networks/time, nor identify the server as a Ghostbro node from a captured packet.
- **Identity confidentiality (server-key compromise)**: The Noise XK handshake keeps the *client static key* forward-secret even if the server's long-term key is later compromised — it is sent under ephemeral-ephemeral agreement, so historical handshakes cannot be decrypted. The SPA layer is weaker by construction: the sealed packet is encrypted *to* the server's static key, and a single-packet protocol has no server-side ephemeral, so a holder of the server's static private key can decrypt captured SPA packets and recover the `key_id`. SPA payloads are therefore confidential against passive capture but **not** forward-secret against server-static-key compromise — an inherent limit of single-packet authorization (see §10.2). This is the same property fwknop has.
- **Operational simplicity**: The trust model is "I know this person." Key enrollment works over email or any channel that survives partial shutdowns.
- **Forward secrecy**: Bulk traffic capture today cannot be decrypted if long-term keys are compromised later.
- **Optimized for low-metadata protocols**: The system is designed for applications with small request payloads (BitTorrent, satellite card-sharing, SSH, DNS, package downloads) rather than raw web browsing, which leaks extensive metadata regardless of tunnel quality.

## 3. Architecture Overview

Ghostbro supports two SPA modes. The operator and client select the mode based on the network environment.

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
                │  │ length-range│  │
                │  │ + rate limit│  │
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
           │  + Noise XK tunnel    │
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
                │   Noise XK + SOCKS5   │  Port 8443
                │   (fast-socks5)       │
                └──────────────────────┘
```

**When to use:** Networks where DPI performs protocol conformance checking (e.g., all UDP on port 53 must be valid DNS). This is more visible than UDP SPA (a full TLS handshake and HTTP exchange), but the SPA is indistinguishable from a normal web request to the decoy site.

**Note:** In HTTPS SPA mode, the XDP program is simpler — it only checks the allow-map on the proxy port. There is no ring buffer or structural SPA parsing in the XDP layer; the SPA processing happens entirely in userspace behind the web server.

## 4. Single Packet Authorization (SPA)

### 4.1 SPA Principles

Ghostbro's SPA implementation follows established SPA principles (as formalized by fwknop and the SPA RFC draft) with asymmetric cryptography:

1. **Single packet**: Authorization requires exactly one packet (UDP datagram or HTTPS POST body). No multi-packet sequences, no handshakes, no challenge-response.

2. **No server response to invalid packets**: In UDP mode, invalid SPA packets are silently dropped at XDP — the server behaves identically to a host with no service on that port. In HTTPS mode, valid and invalid SPA attempts receive the same HTTP response. An attacker cannot distinguish "wrong key" from "no service."

3. **Cryptographic authentication**: The SPA payload is sealed to the server's static public key (ephemeral X25519 + ChaCha20-Poly1305, §4.3) and carries, inside the sealed envelope, an Ed25519 signature over the authorization fields. The seal provides confidentiality and wire-format indistinguishability; the inner Ed25519 signature provides sender authentication. Only clients whose public keys are in the server's authorized set can produce valid signatures. (Sealing alone is not authentication — anyone holding the server's public key can construct a sealed packet; the inner signature is what authenticates the client.)

4. **Replay protection**: A monotonic counter and timestamp window ensure each SPA packet is single-use. Captured packets cannot be replayed.

5. **Wire-format indistinguishability**: The on-wire SPA payload is a fixed-size sealed blob plus random padding — no version magic, no cleartext structure, no client identifier. To a passive observer it is indistinguishable from random bytes, so neither the client nor the server can be fingerprinted from a captured SPA packet.

6. **Minimal attack surface**: Before SPA authorization, the server exposes zero listening services on the proxy port (kernel-level drop via XDP). The proxy's TCP stack is never reached by unauthorized clients.

6. **Time-limited access**: A successful SPA opens a time-limited window (default 4 hours) during which the client's source IP can reach the proxy port. Access expires automatically.

### 4.2 SPA vs. Traditional Port Knocking

Ghostbro uses SPA, not port knocking. The distinction matters:

| Property | Port Knocking | SPA |
|----------|--------------|-----|
| Packets required | Multiple (sequence of SYN to ports X, Y, Z) | One |
| Fingerprintable by traffic analysis | Yes — sequential SYN packets to multiple ports from one source are distinctive | No — single UDP datagram or HTTPS POST |
| Replay protection | None inherent (same sequence works forever) | Built-in (monotonic counter + timestamp window; per-packet ephemeral makes every seal unique) |
| Cryptographic auth | Typically none (security by obscurity) | Ed25519 signature |
| Server response to invalid attempts | May leak timing via TCP RST on some ports | None (UDP mode) or identical response (HTTPS mode) |

### 4.3 SPA Packet Format (Sealed)

The SPA payload is identical regardless of transport mode (UDP or HTTPS). In UDP mode, it is the UDP datagram payload. In HTTPS mode, it is the raw POST body (Content-Type: application/octet-stream).

The entire authorization payload is **sealed to the server's static public key** so that nothing on the wire is fingerprintable: there is no version magic, no cleartext mode flag, and no cleartext client identifier. The construction is a libsodium-style sealed box (anonymous ephemeral X25519 + ChaCha20-Poly1305) wrapping an inner, Ed25519-signed authorization record.

**On-wire layout:**

```
┌──────────────────────────────────────────────────────────┐
│  Offset  │  Size   │  Field                              │
├──────────┼─────────┼─────────────────────────────────────┤
│  0       │  32     │  ephemeral X25519 public key        │
│  32      │  C      │  ciphertext (sealed inner record)   │
│  32+C    │  16     │  Poly1305 tag                       │
│  48+C    │  0..P   │  random padding (length jitter)     │
└──────────────────────────────────────────────────────────┘
The 32-byte ephemeral key, ciphertext, and tag are uniform-looking
bytes; padding is random. Total size varies within a fixed range
(see §4.4) so size alone is not a fingerprint.
```

**Sealing (client side):**

1. Generate a fresh ephemeral X25519 keypair `(e_pub, e_priv)` for this packet only.
2. `shared = X25519(e_priv, server_static_x25519_pub)`.
3. `aead_key = BLAKE2s(shared || e_pub || server_static_x25519_pub)` (key derivation).
4. `aead_nonce = BLAKE2s("ghostbro-spa-seal" || e_pub || server_static_x25519_pub)[..12]` (deterministic; safe because `e_pub` — and thus the key — is unique per packet).
5. `ciphertext || tag = ChaCha20Poly1305(aead_key, aead_nonce, inner_record)` with `e_pub` as associated data.
6. Append random padding.

**Inner record (the sealed plaintext, fixed size):**

```
┌──────────────────────────────────────────────────────────┐
│  Field            │  Size │  Notes                        │
├───────────────────┼───────┼───────────────────────────────┤
│  version          │  2    │  0x47 0x50 — protocol evolution│
│  spa_flags        │  1    │  bit 0: 0=UDP, 1=HTTPS mode    │
│                   │       │  bit 1: 0=explicit allow_ip,   │
│                   │       │         1=use packet source IP │
│                   │       │  bits 2-7: reserved (zero)     │
│  key_id           │  8    │  first 8 bytes of SHA-256 of   │
│                   │       │  client Ed25519 public key     │
│  timestamp_ms     │  8    │  Unix millis, BE               │
│  counter          │  8    │  monotonic, BE                 │
│  allow_ip         │  4    │  IPv4 to authorize (BE).       │
│                   │       │  Ignored when flags bit 1 set. │
│  signature        │  64   │  Ed25519 (see below)           │
└──────────────────────────────────────────────────────────┘
```

**Signature input** (inner authentication, binds identity, freshness, and destination):

```
Ed25519_Sign(client_private_key,
    version || spa_flags || key_id || timestamp_ms ||
    counter || allow_ip || e_pub || server_static_x25519_pub)
```

- `e_pub` is included so the signature is bound to this specific seal (a captured seal cannot be re-wrapped).
- `server_static_x25519_pub` is **not transmitted**; it is authenticated associated data. This makes a SPA accepted by one server fail verification on another (cross-server / failover replay protection — carried over from v0.2).

**Why seal as well as sign?** A signature alone leaves `key_id`, timestamp, and counter in cleartext — fingerprintable and identity-linking (a passive observer could track a client across networks and, after a server seizure exposing `authorized_keys.toml`, retroactively deanonymize captured traffic). Sealing removes the cleartext entirely. The seal protects confidentiality against any party that does not hold the server's static private key; it is **not** forward-secret against compromise of that key (a single-packet protocol has no server-side ephemeral — see §10.2).

**Padding**: Random bytes appended after the tag to vary total packet size (see §4.4). Not covered by the AEAD or signature.

**Note on ephemeral-key encoding**: A raw X25519 public key is not perfectly uniform (the field element is `< 2^255-19`, leaving a small statistical bias in the high bits). For v0.3 this is an accepted residual, matching fwknop's encrypted-blob model. Encoding the ephemeral key with Elligator2 to make it bit-for-bit uniform is tracked under Pluggable Transports (§14).

### 4.4 UDP SPA Transport Details

**Port selection**: The SPA port should be chosen based on the network environment:

| Port | Protocol | Rationale |
|------|----------|-----------|
| 53   | DNS      | Almost always allowed. Packet size (143–176 bytes) is consistent with larger DNS responses. Risk: DPI may check DNS conformance. |
| 123  | NTP      | Widely allowed. NTP packets are 48+ bytes, so 143–176 is plausible as an NTP extension-field response. |
| 443  | QUIC/UDP | Increasingly common. Random-looking UDP on 443 blends with QUIC traffic. |
| 1194 | OpenVPN  | Common on VPS hosts. May attract attention in some regions. |

**Server behavior**: The XDP program consumes all packets on the SPA port. It never responds, never sends ICMP unreachable, never generates any outbound traffic in response to an SPA attempt. To a port scanner, the port appears filtered or closed (indistinguishable from a host that simply drops the traffic).

**Structural pre-filter (XDP)**: With the sealed packet format (§4.3) there is no cleartext magic or flags to match — and that is intentional, so the inbound packet is not itself a signature a DPI box can write a rule for. The XDP pre-filter therefore validates only what is observable without decryption:

1. Check UDP payload length is in the sealed-SPA range (143–176 bytes).
2. Rate-limit: per-source-IP token bucket (max 5 attempts per minute).
3. Global admission budget: a single shared token bucket caps the aggregate candidates pushed to userspace per window, so an attacker spoofing a fresh source IP per packet cannot flood the userspace decrypt/verify path (UDP source IPs are trivially spoofable; the per-IP bucket alone is insufficient — see §4.7).
4. If all checks pass: copy payload to ring buffer, return `XDP_DROP`.
5. If any check fails: `XDP_DROP` (silent).

The length range and rate limit are a sufficient pre-filter: random noise and port scans are dropped cheaply, while the expensive work (X25519 + AEAD decryption, Ed25519 verification) happens in userspace behind the global budget. This is the fwknop tradeoff — the cost of an unfingerprintable wire format is that the kernel cannot pre-validate packet contents.

### 4.5 HTTPS SPA Transport Details

**Endpoint**: `POST /api/v1/telemetry` (or configurable path). The path should look like a legitimate analytics or telemetry endpoint.

**Request**:
```
POST /api/v1/telemetry HTTP/1.1
Host: example.com
Content-Type: application/octet-stream
Content-Length: 160
[... 143-176 bytes of sealed SPA payload ...]
```

**Response (always identical)**:
```
HTTP/1.1 204 No Content
Server: nginx/1.26.0
X-Request-Id: <random-uuid>
Date: <current>
```

The response is the same for valid SPA, invalid SPA, and random garbage. The `X-Request-Id` is regenerated for each request so responses aren't identical byte-for-byte (which would itself be a fingerprint).

**Processing**: The web server (nginx reverse-proxying to the SPA daemon, or an axum handler in the built-in decoy) extracts the raw POST body and passes it to the same SPA verification pipeline as the UDP path. The only difference is that the source IP comes from the TCP connection (or `X-Forwarded-For` when behind a trusted reverse proxy — see below) rather than the UDP packet header.

**No request-path timing side channel**: The endpoint handler does *not* verify the SPA on the request path. It enqueues the raw body onto an internal channel and immediately returns the fixed `204` response; the seal-open, signature verification, and counter write happen asynchronously in the consumer task. Valid and invalid payloads are therefore indistinguishable by response *timing* as well as by response *content* — there is no signature-verify or file-write latency on the request path to measure.

**Source-IP determination behind a proxy**: When the daemon runs behind a real reverse proxy (e.g. nginx in `mode = "nginx"`), it sees every connection from `127.0.0.1`, so the TCP peer address is useless as the client IP. The source IP is taken from `X-Forwarded-For` **only** when the TCP peer is inside a configured trusted-proxy CIDR (`trusted_proxy_cidrs`, §9). If that list is empty, `X-Forwarded-For` is never trusted and the TCP peer address is authoritative. nginx mode therefore *requires* a non-empty `trusted_proxy_cidrs`; otherwise every accepted SPA would authorize `127.0.0.1`. (See §9 for why the redundant `trust_forwarded_for` boolean was removed.)

### 4.6 SPA Verification Pipeline (Shared)

Regardless of transport mode, the SPA daemon processes sealed payloads identically. The pipeline is ordered so that no authorization-relevant branch is reachable without a valid seal and a valid signature (closing key/tier enumeration oracles):

1. Open the seal (§4.3): read the 32-byte ephemeral key, derive the AEAD key/nonce with the server's static X25519 private key, and decrypt the inner record. If AEAD authentication fails (not sealed to this server, or corrupt): reject. A held server static private key is required even to *read* the inner fields — so `key_id` is never exposed to anyone but this server.
2. Parse the inner record; validate the version prefix and reserved flag bits.
3. Look up the client public key by `key_id` in the `authorized_keys` config. If not found: reject (logged as unknown `key_id`, no further detail).
4. Verify the inner Ed25519 signature (binding `e_pub` and this server's static key). If invalid: reject. **This check gates everything below** — the tier branch and its distinguishable error are unreachable without a valid signature.
5. Enforce client tier: a `decoy`-tier client is rejected here (only reachable after the signature passes).
6. Check `timestamp_ms` is within the acceptable window (±`time_window` seconds, default 300).
7. Check `counter` > highest seen counter for this `key_id`.
8. **Determine the IP to authorize (source-IP binding):**
   - If `spa_flags` bit 1 is clear: the authorized IP is the signed `allow_ip` field. The observed source IP (UDP header, or trusted `X-Forwarded-For`) **must equal** `allow_ip`, or the packet is rejected. This defeats the on-path authorization-theft race (§10.2): an attacker who captures a valid SPA and replays it from their own address cannot match the signed `allow_ip`, and cannot forge a new one without the client key.
   - If `spa_flags` bit 1 is set (CGNAT escape hatch): `allow_ip` is ignored and the observed source IP is used. This is for clients that do not know their own public IP; it reopens the race for those clients and is documented as such.
9. Persist the new high-water counter for this `key_id` **before** authorizing (write-then-accept ordering with an fsync'd atomic rename — see §4.6 note), so a crash between accept and persist cannot reopen a replay window.
10. Write the authorized IP to `ALLOW_MAP` with TTL (`allow_ttl`, default 14400 seconds / 4 hours) and record the entry's `key_id` (consumed by the Noise-static-key binding check, §5.2).
11. Log: `SPA_ACCEPT key_id=<hex> src=<ip> mode=<udp|https> counter=<n>`.

**Counter durability**: The high-water counter file is written to a temp file, fsync'd, then atomically renamed over the live file, and this completes *before* the allow-map write in step 10. Because persist precedes accept, a crash never accepts a counter it has not durably recorded.

**Rejection logging**: All rejections are logged with the reason (failed seal, unknown key, bad signature, unauthorized tier, expired timestamp, replayed counter, source-IP mismatch) but no sensitive material. Rate-limited to prevent log flooding from brute-force attempts.

### 4.7 Allow-Map Management

**Map structure:**

| Map | Type | Max entries | Key | Value | Purpose |
|-----|------|-------------|-----|-------|---------|
| `ALLOW_MAP` | `LRU_HASH` | 4096 | `u32` (src IPv4) | `AllowEntry { expiry_ns: u64, client_id: u16, key_id: [u8;8] }` | SPA-authorized clients |
| `RATE_LIMIT` | `LRU_HASH` | 16384 | `u32` (src IPv4) | `RateState { tokens: u32, last_ns: u64 }` | Per-IP SPA rate limiting (UDP mode only) |
| `GLOBAL_RATE` | `Array` | 1 | — | `RateState` | Aggregate SPA admission budget (spoof-resistant, UDP mode only) |
| `SPA_RING` | `RingBuf` | 1 MiB | — | `SpaEvent { src_ip, src_port, payload: [u8; 176] }` | SPA candidates to userspace (UDP mode only) |

**Spoofed-IP map exhaustion**: UDP source addresses are trivially spoofable, so any per-source-IP map can be filled with garbage entries up to `max_entries`. Both `ALLOW_MAP` and `RATE_LIMIT` are therefore `LRU_HASH`: when full, the kernel evicts the least-recently-used entry rather than failing the insert, so a flood of spoofed sources cannot starve legitimate clients out of the map (it can only churn the LRU tail). Note that `RATE_LIMIT` keyed on a spoofable IP cannot *by itself* bound the userspace verify load — a fresh spoofed IP yields a fresh full bucket. That bound is provided by `GLOBAL_RATE`, a single aggregate token bucket checked after the per-IP bucket; it fails closed if its map slot is unavailable, so spoofing cannot bypass the gate.

**TTL reaping (dual strategy):**

1. **Lazy reaping in XDP**: On each packet to the proxy port, the XDP program reads the allow-map entry and compares `expiry_ns` against `bpf_ktime_get_ns()`. If expired, the entry is treated as non-existent and deleted in-place. Zero userspace overhead.

2. **Periodic cleanup**: A userspace task runs every 60 seconds, iterates the allow-map, and deletes expired entries. This catches entries for clients that never send another packet after their TTL expires.

### 4.8 SPA Refresh

Clients with active sessions send periodic SPA refresh packets (every `allow_ttl / 2`) to keep their allow-map entry alive. The refresh is a normal SPA packet with an incremented counter. This handles:

- TTL expiration during long sessions.
- Source IP changes (mobile networks, NAT rebinding).
- Server restarts (allow-map is in-memory and lost on restart; client re-knocks automatically).

## 5. Proxy Tunnel (fast-socks5 + Noise XK)

### 5.1 Noise Handshake Pattern

**Pattern**: `Noise_XK_25519_ChaChaPoly_BLAKE2s`

v0.3 uses Noise XK. The earlier patterns both fail the *identity confidentiality under server-key compromise* goal (§2), in different ways:

| Pattern | Where the client static goes | Effect of server static-key compromise |
|---------|------------------------------|------------------------------------------|
| KK (v0.1) | Not transmitted — both statics are pre-shared and mixed in. | Nothing to extract from captured handshakes; the client static is never on the wire. (The v0.2 table claimed the opposite; that was wrong.) |
| IK (v0.2) | Sent in message 1, encrypted under `es = DH(e_client, s_server)`. | **Recoverable.** An attacker who records the handshake and later obtains the server static private key computes `es` from the recorded `e_client` and decrypts the client static → mass deanonymization. This is the documented WireGuard/IKpsk2 limitation; v0.2's "forward secrecy on identity" claim for IK was incorrect. |
| **XK (v0.3)** | Sent in message **3**, encrypted under keys that already include `ee = DH(e_client, e_server)`. | **Protected.** The ephemeral-ephemeral secret is gone after the handshake, so a later server-key compromise cannot decrypt the client static. Identity is genuinely forward-secret. |

XK is a 1.5-round-trip (3-message) pattern versus IK's 1-RTT (2 messages). The extra half round trip is acceptable here: SPA already adds a pre-flight packet and a brief wait, and the threat model (users who face arrest) justifies prioritizing real identity forward-secrecy over one round trip.

KK was rejected (despite never putting the client static on the wire) because it requires the server to pre-load every client's static key into the handshake and gives no clean per-connection identity binding to the SPA layer; XK lets the server learn the initiator static *during* the handshake and check it against the SPA-authorized identity (§5.2).

```rust
// v0.3 Noise XK configuration (client / initiator)
let builder = snow::Builder::new(
    "Noise_XK_25519_ChaChaPoly_BLAKE2s".parse()?
)
    .local_private_key(&client_static_private)
    .remote_public_key(&server_static_public)
    .prologue(&key_id_bytes);  // connection binding (see §5.2)
```

### 5.2 Connection Binding and Anti-Hijack

Two distinct mechanisms protect a SPA-opened allow-map entry from being hijacked by an attacker who shares the legitimate client's NAT/source IP. The v0.2 spec conflated them and leaned on the wrong one; v0.3 separates them:

**1. Noise static-key binding (load-bearing).** When the server accepts a proxy connection from an allowed source IP, it looks up the `key_id` recorded in that allow-map entry (§4.6 step 10), and after reading the initiator's static key from the XK handshake it verifies — in constant time — that the initiator static equals the `noise_public_key` enrolled for that `key_id` in `authorized_keys.toml`. If it does not match, the connection is dropped. **This is the check that actually prevents allow-map co-tenant hijack**: a NAT neighbor cannot complete the handshake as the authorized identity without that client's Noise private key. (Implemented; see `verify_client_noise_static`.)

**2. Prologue binding (connection binding only).** Both sides set the Noise prologue to the client's `key_id` (8 bytes); a mismatch makes the handshake fail cryptographically with no explicit check. This binds a given handshake to a given `key_id` and is cheap defense-in-depth — but it is **not** the primary anti-hijack control, because `key_id` is no longer secret in the relevant threat: a NAT co-tenant who could observe the client's SPA could, before v0.3's sealing, read the `key_id` in cleartext. With sealed SPA (§4.3) the `key_id` is hidden on the wire too, but the spec does not rely on its secrecy — mechanism (1) is what holds.

### 5.3 Post-Handshake Protocol Multiplexing

After the Noise XK handshake completes, the first byte of application data selects the protocol:

| Byte | Protocol | Description |
|------|----------|-------------|
| `0x05` | SOCKS5 | Standard SOCKS5 greeting (backward compatible). For raw TCP proxying — BitTorrent, oscam/cccam, SSH tunneling. |
| `0x47` | Ghost Relay | Content Relay protocol (see Content Relay Module spec). For web content fetching, code downloads, package retrieval. |

This allows the same tunnel to carry both traditional SOCKS5 (for applications that need raw TCP) and the content relay (for stripped-down web content), selected per-session by the client.

### 5.4 Transport Framing

After the Noise XK handshake, application data is framed as:

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
- SPA port: length-range pre-filter → per-IP rate limit → global admission budget → ring buffer push → `XDP_DROP` (always, valid or not). No content pre-validation — the payload is sealed (§4.3).
- Proxy port: allow-map check → `XDP_PASS` if allowed, `XDP_DROP` if not.
- All other ports: `XDP_PASS`.

**HTTPS SPA mode:**
- Proxy port: allow-map check → `XDP_PASS` if allowed, `XDP_DROP` if not.
- All other ports: `XDP_PASS` (including 443, which serves the decoy + SPA endpoint normally).

In HTTPS mode, the XDP program is minimal — just a single allow-map lookup on the proxy port. No ring buffer, no SPA parsing.

### 6.2 SPA Daemon (Userspace)

**Crates**: `aya`, `ed25519-dalek`, `tokio`

In UDP mode: consumes `SpaEvent` structs from the BPF ring buffer, runs the verification pipeline (§4.6), and writes to the allow-map.

In HTTPS mode: receives SPA payloads from the web server via an internal channel (Unix socket or in-process `tokio::sync::mpsc`), runs the same verification pipeline, writes to the allow-map.

The SPA daemon is a single Rust binary that handles both modes. The mode is selected by configuration.

**Authorized Keys Config:**

```toml
# /etc/ghostbro/authorized_keys.toml

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

**Implementation**: nginx is the **supported** decoy for any real deployment. The built-in `axum` decoy is **dev/test only** and must not be relied on as cover against active probing.

The decoy runs on port 443 with a valid TLS certificate for a plausible domain. It serves a realistic website and, in HTTPS SPA mode, routes SPA requests to the daemon.

**Why nginx, not the built-in decoy, in production**: Matching nginx's `Server` header is trivial, but matching its full observable behavior is not — header *ordering*, default error pages, redirect behavior, HTTP/2 SETTINGS, and TLS-stack fingerprint (JA3/JA4) all differ between a hand-rolled axum server and a stock nginx, and active-probing systems do check these. A real nginx in front of the daemon inherits nginx's actual fingerprint for free. The built-in decoy exists so the daemon can be exercised end-to-end without an external web server; it is not a hardening target.

**Requirements (nginx deployment):**

- Valid TLS with a real domain and Let's Encrypt certificate.
- Stock nginx configuration so HTTP response headers, error pages, and TLS fingerprint match a real nginx.
- Real HTML/CSS/images, not a stub. Active probing tools check for realistic content.
- Access logs enabled and rotated normally.
- In HTTPS SPA mode: reverse proxy the SPA endpoint path to the SPA daemon (passing `X-Forwarded-For`), and return identical 204 responses for valid and invalid payloads. The daemon must be configured with `trusted_proxy_cidrs` covering the nginx address (§9).

### 6.4 Proxy Server (fast-socks5 + Noise XK)

**Crates**: `fast-socks5`, `snow`, `tokio`

Listens on the proxy port (default 8443). Only reachable after SPA authorization (XDP drops all non-allowed traffic). Performs the Noise XK handshake, then serves SOCKS5 or Ghost Relay based on the first application byte.

## 7. Key Management

### 7.1 Key Generation

**Client:**

```bash
ghostbro keygen --output ~/.ghostbro/identity
# Generates (derived-Noise mode, default):
#   ~/.ghostbro/identity.key       (Ed25519 private key, encrypted via argon2id)
#   ~/.ghostbro/identity.pub       (Ed25519 public key, base64, 44 chars)
#   ~/.ghostbro/identity.noise     (Curve25519 static *public* key for Noise — see note)
#   ~/.ghostbro/identity.keyid     (key_id: first 8 bytes of SHA-256, hex)

ghostbro keygen --output ~/.ghostbro/identity --independent-noise-key
# Additionally generates (independent-Noise mode):
#   ~/.ghostbro/identity.noise.key (Curve25519 static *private* key, encrypted via argon2id)
```

Private key encrypted at rest with a user-chosen passphrase. KDF: argon2id (m=64MB, t=3, p=1, ~500ms on a modern phone).

**Note on the Noise static key**: `identity.noise` is the client's X25519 static *public* key used in the Noise XK handshake. Two modes are supported, chosen at `keygen` time:

- **Derived (default).** v0.3 derives the Noise static deterministically from the Ed25519 signing key via a domain-separated KDF — `X25519_static = SHA-256("ghostbro client noise static v1" || ed25519_secret)` — rather than the Ed25519→X25519 birational map. The KDF gives an independent-looking scalar (not the same secret reinterpreted), but it still **couples the two keys**: anyone who compromises the Ed25519 private key can recompute the Noise static, and the two cannot be rotated independently. No private Noise key is stored on disk; it is re-derived on each connect.
- **Independent (`--independent-noise-key`).** `keygen` mints a fresh random X25519 keypair, writes the public to `identity.noise` (unchanged path/format) and the private to `identity.noise.key` (mode 0600, encrypted at rest with the *same* argon2id + ChaCha20-Poly1305 scheme and passphrase as `identity.key`; written as plaintext base64 only under `--plaintext-debug`). This **decouples** the signing and key-agreement keys: compromising the Ed25519 key no longer yields the Noise static, and the two can be rotated independently.

The connect paths auto-select: if `identity.noise.key` exists alongside the identity they load it; otherwise they fall back to the derived key. Existing derived identities keep working unchanged (backward compatible), and the choice is purely client-side — enrollment already transmits the Noise *public* key separately (§7.2), and the server only compares the initiator's Noise static against the enrolled `noise_public_key`, so no server change is needed either way. Pick one explicitly per deployment.

**Server:**

```bash
ghostbro server-keygen --output /etc/ghostbro/server
# Generates:
#   /etc/ghostbro/server.key      (Ed25519 + Curve25519 private keys)
#   /etc/ghostbro/server.pub      (public keys, base64)
#   /etc/ghostbro/server.fp       (fingerprint: first 16 hex chars of SHA-256)
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
   │     ghostbro enroll           │
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
# Generate identity (Noise static derived from the Ed25519 key)
ghostbro keygen --output ~/.ghostbro/identity

# Generate identity with an independent (decoupled) Noise static keypair (§7.1)
ghostbro keygen --output ~/.ghostbro/identity --independent-noise-key

# Enroll with a server
ghostbro enroll \
  --server-key "base64..." \
  --endpoint 203.0.113.42:8443 \
  --spa-mode udp \
  --spa-port 53

# Connect (SPA + tunnel + local SOCKS5 listener)
ghostbro connect \
  --config ~/.ghostbro/servers/myserver.toml \
  --listen 127.0.0.1:1080
# 1. Prompts for passphrase
# 2. Sends SPA packet (UDP or HTTPS per config)
# 3. Establishes Noise XK tunnel
# 4. Starts local SOCKS5 proxy on 1080

# Connect with explicit SPA mode override
ghostbro connect \
  --config ~/.ghostbro/servers/myserver.toml \
  --spa-mode https \
  --listen 127.0.0.1:1080
# Overrides configured SPA mode (useful when network conditions change)

# Connect binding the SPA to a known public IP (enables on-path replay binding, §4.6/§13.3)
ghostbro connect \
  --config ~/.ghostbro/servers/myserver.toml \
  --allow-ip 203.0.113.7 \
  --listen 127.0.0.1:1080
# Off by default (packet-source mode); the flag overrides any per-server allow_ip

# Revoke own key (best-effort notification to server)
ghostbro revoke --config ~/.ghostbro/servers/myserver.toml
```

Implementation note: the proxy server and client-side local listener use `fast-socks5`; current SOCKS5 support remains no-auth TCP CONNECT over the Noise XK tunnel.

### 8.2 Connection Sequence

1. Load client identity (decrypt private key with passphrase).
2. Load server config (server pubkey, endpoint, SPA mode, SPA port).
3. Build the inner record (`version || flags || key_id || timestamp || counter || allow_ip`, with `counter = max(timestamp_ms, last_counter + 1)`, §13.2a), Ed25519-sign it (binding the ephemeral key and server static key, §4.3), then seal the record to the server's static X25519 key with a fresh ephemeral and append random padding (total 143–176 bytes).
4. Send SPA:
   - **UDP mode**: Send as UDP datagram to `spa_endpoint:spa_port`.
   - **HTTPS mode**: Send as POST body to `https://spa_endpoint/api/v1/telemetry`.
5. Wait briefly (100ms default, configurable).
6. Open TCP connection to `endpoint:proxy_port`.
7. Perform Noise XK handshake with `key_id` as prologue.
8. Send protocol selector byte (`0x05` for SOCKS5, `0x47` for Ghost Relay).
9. Start local listener on `--listen` address.
10. Forward connections through the Noise tunnel.
11. Schedule SPA refresh every `allow_ttl / 2`.

### 8.3 Multi-Server Failover

The client config supports multiple server entries for resilience:

```toml
# ~/.ghostbro/servers/mynetwork.toml

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
# /etc/ghostbro/ghostbro.toml

[server]
identity = "/etc/ghostbro/server.key"

[spa]
# SPA mode: "udp", "https", or "both"
mode = "udp"

[spa.udp]
# Port for UDP SPA packets
port = 53
# Length-range + rate limiting in XDP (no content pre-validation; payload is sealed)
rate_limit = 5          # max SPA attempts per IP per minute

[spa.https]
# Path for HTTPS SPA endpoint (behind decoy TLS)
path = "/api/v1/telemetry"
# Response to all SPA attempts (valid or not)
response_status = 204
# Trust X-Forwarded-For ONLY when the TCP peer is inside one of these CIDRs.
# An empty/omitted list means X-Forwarded-For is never trusted and the TCP peer
# address is authoritative. nginx mode (decoy.mode = "nginx") REQUIRES a non-empty
# list covering the nginx address, or every accepted SPA would authorize 127.0.0.1.
trusted_proxy_cidrs = ["127.0.0.1/32"]

[spa.common]
# Shared SPA verification parameters
time_window = 300       # timestamp tolerance in seconds
allow_ttl = 14400       # allow-map TTL in seconds (4 hours)

[proxy]
port = 8443
noise_pattern = "Noise_XK_25519_ChaChaPoly_BLAKE2s"
bind = "0.0.0.0"

[decoy]
mode = "nginx"          # "nginx" (external) or "builtin" (axum)
port = 443
tls_cert = "/etc/letsencrypt/live/example.com/fullchain.pem"
tls_key = "/etc/letsencrypt/live/example.com/privkey.pem"
webroot = "/var/www/decoy"

[clients]
authorized_keys = "/etc/ghostbro/authorized_keys.toml"

[logging]
path = "/var/log/ghostbro/audit.log"
level = "info"
```

The `mode = "both"` option enables both UDP and HTTPS SPA simultaneously. The XDP program handles UDP SPA, and the decoy web server handles HTTPS SPA. Clients choose their mode per-connection.

**X-Forwarded-For trust (changed in v0.3)**: v0.2 had both a `trust_forwarded_for` boolean and a `trusted_proxy_cidrs` list, which were redundant and made the nginx-mode default unsafe (the daemon would write `127.0.0.1` into the allow-map). v0.3 removes the boolean: a non-empty `trusted_proxy_cidrs` *is* the trust grant. `X-Forwarded-For` is honored only for connections whose TCP peer falls inside one of the listed CIDRs; otherwise the TCP peer address is used. This makes the only correct configuration explicit and prevents the localhost-authorization footgun.

**`max_concurrent_sessions` enforcement**: The per-client `max_concurrent_sessions` value (§6.2) is enforced by the proxy server, not the SPA layer. The proxy tracks live Noise sessions per `key_id` (identified via the Noise static-key binding, §5.2) and refuses a new tunnel once the client's configured limit is reached, replying with a tunnel-level error and logging `SESSION_LIMIT key_id=<hex>`. A value of `0` or an omitted field means unlimited. (Allow-map entries are keyed on IP, not session, so this cap lives at the tunnel layer where session identity is known.)

## 10. Threat Model

### 10.1 What This Defends Against

| Threat | Mitigation |
|--------|------------|
| **Port scanning / active probing** | Proxy port is XDP_DROP for non-allowed IPs. UDP SPA port is XDP_DROP always (no response). HTTPS SPA returns identical response for valid/invalid. |
| **Deep packet inspection (DPI), content** | Noise XK tunnel and sealed SPA both produce random-looking bytes. No TLS ClientHello, no SOCKS5 handshake, no SPA magic/structure visible. |
| **SPA wire fingerprinting / client linkage** | Sealed SPA (§4.3): no cleartext magic, structure, or `key_id`. A passive observer cannot write a signature for the packet, cannot identify the server as a Ghostbro node, and cannot link a client across networks/time. |
| **Protocol conformance checking** | HTTPS SPA mode wraps the SPA in a standard HTTPS POST — passes DPI that verifies protocols match their port. |
| **Bulk capture + server key compromise (Noise layer)** | Noise XK: the client static is sent in message 3 under ephemeral-ephemeral agreement, so a later server-key compromise cannot decrypt historical handshakes to recover client identities. (Note: the *SPA* layer is weaker — see §10.2.) |
| **Single client key compromise** | Only the compromised client is affected. Revoke their pubkey. |
| **SPA replay** | Monotonic counter + timestamp window. Each SPA packet is single-use. |
| **On-path SPA authorization theft** | The signed `allow_ip` field (§4.6) binds the authorization to the client's address; a captured SPA replayed from another source IP fails the source-IP check. (Clients using the CGNAT escape hatch opt out — see §10.2.) |
| **SPA brute-force** | Per-IP + global rate limiting in XDP (UDP mode). Sealing requires the server pubkey; the inner Ed25519 signature space is infeasible to brute-force. |
| **Server impersonation** | Client pins server's Noise static public key. MitM cannot complete Noise XK without server's private key. |
| **Allow-map hijacking (NAT co-tenant)** | Server verifies the initiator's Noise static key against the `noise_public_key` enrolled for the allow-map entry's `key_id` (§5.2, load-bearing). Prologue binding is additional defense-in-depth. |

### 10.2 What This Does NOT Defend Against

| Threat | Limitation |
|--------|------------|
| **Traffic analysis / flow correlation** | Observable at both endpoints. Padding and shaping are future work. |
| **Entropy-based detection of fully-encrypted protocols** | A high-entropy, protocol-unidentifiable flow (no TLS handshake on the proxy port; random-looking SPA) is itself a detectable *class* — state adversaries have actively blocked fully-encrypted flows since ~2021 (e.g. GFW popcount/entropy heuristics, Wu et al., USENIX Security 2023). v0.3 does **not** defend against this. Mitigation is pluggable transports (§14): use HTTPS SPA mode + a TLS-fronted decoy to look like normal web traffic, and treat the raw UDP/proxy ports as higher-risk on adversaries known to do entropy classification. |
| **SPA payload confidentiality under server-key compromise** | The sealed SPA is encrypted *to* the server's static key and a single-packet protocol has no server-side ephemeral, so a holder of the server static private key can decrypt captured SPA packets and recover `key_id`. Combined with a seized `authorized_keys.toml`, this can retroactively deanonymize captured SPA traffic. Inherent to single-packet auth (fwknop has the same property). Mitigated by: full-disk encryption / key in HSM so seizure does not yield the static key, and key rotation. The Noise layer (§10.1) is *not* subject to this. |
| **On-path SPA theft for CGNAT-escape-hatch clients** | Clients in packet-source mode (§4.6) forgo the signed `allow_ip` binding, reopening the on-path replay race for their sessions. This is the **default** for the CLI client, since it cannot reliably know its public IP; the explicit binding is opt-in via `--allow-ip` / per-server `allow_ip` (§13.3) on stable-IP deployments. Either way the Noise static-key binding (§5.2) still prevents the attacker from completing a tunnel; the residual for packet-source clients is a denial-of-service (the attacker can win the allow-map write and the legitimate client must re-SPA). |
| **Compromised server host** | Server seizure exposes the server private key and authorized_keys list. Mitigated by: Noise XK (past *handshake* client identities safe), full disk encryption, multi-server deployment. Note the SPA-layer caveat above. |
| **Rubber-hose cryptanalysis** | Passphrase on client key buys time to revoke, not permanent protection. |
| **Endpoint compromise** | Out of scope. Owned client = game over regardless. |
| **IPv6** | v0.3 is IPv4 only. |
| **Web browsing metadata leakage** | Browser fingerprinting (User-Agent, cookies, etc.) is visible to destination servers through the proxy. Use the Content Relay module for stripped-down web content instead. |
| **UDP SPA on protocol-inspected networks** | A 143–176-byte UDP packet on port 53 that isn't valid DNS may be flagged. Use HTTPS SPA mode on such networks. |

## 11. Crate / Dependency Map

| Component | Crate | Purpose |
|-----------|-------|---------|
| eBPF XDP program | `aya-ebpf`, `aya-log-ebpf` | Kernel-space packet filter + SPA pre-filter |
| Userspace eBPF | `aya`, `aya-log` | XDP loader, map management, ring buffer consumer |
| Ed25519 | `ed25519-dalek` | SPA signature creation/verification |
| Noise protocol | `snow` | XK handshake, ChaCha20-Poly1305 transport |
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
ghostbro/
├── Cargo.toml                    # Workspace
├── ghostbro-ebpf/             # eBPF XDP program (aya-ebpf)
│   ├── Cargo.toml
│   └── src/
│       └── main.rs               # XDP filter, SPA pre-filter, allow-map check
├── ghostbro-common/           # Shared types
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── spa.rs                # SPA packet format, construction, parsing
│       ├── keys.rs               # Key types, key_id derivation
│       └── protocol.rs           # Wire format constants, version
├── ghostbro-server/           # Server daemon
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs               # Entrypoint, config, orchestration
│       ├── spa.rs                # SPA verification pipeline (shared logic)
│       ├── spa_udp.rs            # Ring buffer consumer for UDP SPA
│       ├── spa_https.rs          # HTTPS endpoint handler for HTTPS SPA
│       ├── allow_map.rs          # BPF map management, TTL reaper
│       ├── proxy.rs              # fast-socks5 + Noise XK tunnel
│       ├── decoy.rs              # Decoy HTTPS server
│       └── keys.rs               # Authorized keys, hot reload
├── ghostbro-client/           # Client CLI
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs               # CLI entrypoint (clap)
│       ├── keygen.rs             # Key generation + argon2id
│       ├── spa.rs                # SPA packet construction + send (UDP + HTTPS)
│       ├── tunnel.rs             # Noise XK initiator + local SOCKS5 listener
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

### 13.2a SPA Counter Derivation and Client-State Recovery

The replay counter (§4.3) is **derived from the timestamp**, not stored independently: the client sets `counter = max(timestamp_ms, last_counter + 1)`. This keeps the counter strictly monotonic within a client while making it self-recovering — a client that loses its local state (reinstall, restore from backup, second device) naturally produces a counter at or above wall-clock-millis, which exceeds any previously accepted counter (those were also millis-valued and time only moves forward). Without this, a state-losing client would emit counters below the server's persisted high-water mark and be **silently** rejected (replay), indistinguishable from network failure by design.

The server still enforces the rule it always did — strictly greater than the per-`key_id` high-water mark — so derivation changes only how the client *chooses* the counter, not how the server validates it. The timestamp window (§13.2) independently bounds how far ahead a counter can jump.

### 13.3 NAT and IP Instability

Allow-map is keyed on source IP. Clients behind CGNAT may share IPs or have IP changes mid-session. Mitigations: the Noise XK handshake provides session-level auth regardless of IP, and the server's Noise static-key binding (§5.2) — not the prologue — is what prevents allow-map hijacking by IP co-tenants. SPA refresh (§4.8) re-authorizes periodically. Clients that cannot determine their public IP may set the "use packet source" flag (§4.6) at the cost of the source-IP replay binding (§10.2).

**Opting into the source-IP binding** is **off by default** because the CLI client cannot reliably know its own public IP, so it defaults to packet-source mode. A client that *does* know its egress address can opt in explicitly with `--allow-ip <Ipv4Addr>` on `connect` (or the per-server `allow_ip` key in the enrolled config; the CLI flag overrides the config). This binds the signed `allow_ip` to that address and re-enables the server-side on-path replay check (§4.6). The mode used is logged at SPA-send time (`allow_ip=explicit(<ip>)` vs `allow_ip=packet-source`). Use it on stable-IP deployments; leave it unset behind CGNAT or where the public IP is unknown/unstable.

### 13.4 Server Hardening

- Proxy runs as unprivileged user; only eBPF loader needs `CAP_BPF` / `CAP_NET_ADMIN`.
- Full disk encryption (LUKS).
- Unattended-upgrades.
- SSH: key-only, non-standard port, ideally behind its own SPA.
- Fail2ban on decoy service.
- Minimal packages.

### 13.5 Recommended Use Cases

Ghostbro is optimized for protocols with small, non-identifying request payloads:

| Use Case | Request Size | Response Profile | Metadata Risk |
|----------|-------------|-----------------|---------------|
| **BitTorrent** | ~50 bytes (piece request) | Chunked piece data | Low — no browser fingerprint |
| **Satellite card-sharing (oscam/cccam)** | ~150 bytes (ECM) | ~16 bytes (CW) every ~10s | Very low — minimal traffic |
| **SSH tunneling** | Variable, small | Variable | Low — encrypted end-to-end |
| **Package downloads** (via Content Relay) | ~50 bytes (package spec) | Compressed archive | Low — stripped metadata |
| **Web content** (via Content Relay) | ~50 bytes (URL) | Clean markdown/text | Low — server fetches, not client |
| **Raw web browsing** (via SOCKS5) | 2–5 KB (HTTP headers) | 2–5 MB per page load | **High** — browser fingerprint, cookies, sub-resource fetches |

Web browsing through raw SOCKS5 is supported but not recommended. The Content Relay module provides a lower-risk alternative for accessing web content.

**Operator-exposure note**: Listing satellite card-sharing (and other piracy-adjacent traffic) as a headline use case changes the operator's legal-exposure profile. Mixing piracy-adjacent traffic with high-stakes circumvention users on one server gives authorities an easier, lower-bar pretext to act against the operator — and, by extension, against the at-risk users sharing that server. Operators serving circumvention users who face arrest should consider segregating these workloads onto separate infrastructure rather than co-tenanting them.

## 14. Future Work

- **IPv6 support**: Extend BPF maps to 128-bit keys.
- **UDP ASSOCIATE**: SOCKS5 UDP forwarding through the Noise tunnel.
- **Traffic shaping / padding**: Constant-rate traffic to resist flow analysis.
- **Multi-node deployment**: Signed authorized-keys snapshots across 2–5 nodes.
- **Multi-hop**: Chain multiple Ghostbro instances.
- **Mobile client**: iOS/Android with tun2socks integration.
- **Meshtastic enrollment**: QR-code key exchange over LoRa.
- **Pluggable transports**: obfs4-style wire format for environments that flag high-entropy / fully-encrypted flows (§10.2). Includes Elligator2 encoding of the SPA ephemeral key (§4.3) so the sealed packet is bit-for-bit uniform, and a TLS/HTTP-mimic transport for the proxy tunnel.
- **Canary / duress key**: Alert operator when client is under coercion.
- **QUIC SPA mode**: SPA embedded in QUIC Initial packets.
- **Content Relay module**: Server-side web fetching, search, git clone, package download with store-and-forward queuing (see separate spec).

## 15. Changelog

### From v0.2 (this revision)

| Change | Rationale |
|--------|-----------|
| **Sealed SPA packet** (ephemeral X25519 + ChaCha20-Poly1305 to server static key); removed cleartext version magic, mode flag, and `key_id` from the wire | The v0.2 packet was fingerprintable (constant magic, fixed structure, narrow size band) and leaked `key_id` in cleartext, enabling DPI signatures, server identification, and cross-network client linkage. Sealing makes the wire payload indistinguishable from random. |
| **Source-IP binding**: added signed `allow_ip` field with a "use packet source" CGNAT escape hatch | Closes the on-path authorization-theft race — a captured SPA replayed from another address no longer authorizes the attacker's IP. |
| **Noise IK → Noise XK** | IK's identity-confidentiality claim was false (client static recoverable under server-key compromise via `es`). XK sends the client static in message 3 under `ee`, making client identity genuinely forward-secret. |
| **Corrected crypto claims** in §2/§5.1/§10.1 (IK identity hiding, KK comparison) and documented the SPA-layer's non-forward-secrecy under server-key compromise | The v0.2 spec overstated identity protection; v0.3 states the actual properties, including the inherent single-packet-auth limitation. |
| **Made the Noise static-key binding the explicit anti-hijack control** (§5.2); demoted the prologue to connection binding | The prologue's secrecy argument did not hold; the load-bearing check (initiator static == enrolled `noise_public_key`) was already implemented but unspecified. |
| **XDP pre-filter: length-range + rate-limit only** (removed magic/flags content checks) | Sealed packets have no cleartext content to pre-validate; documented as the fwknop tradeoff. |
| **`ALLOW_MAP` / `RATE_LIMIT` → `LRU_HASH`**; documented `GLOBAL_RATE` aggregate budget | Prevents spoofed-source map exhaustion; bounds userspace verify load against IP spoofing. |
| **X-Forwarded-For: removed `trust_forwarded_for` boolean**; non-empty `trusted_proxy_cidrs` is the trust grant | The redundant pair made the nginx-mode default unsafe (authorizing `127.0.0.1`). |
| **Counter derived from timestamp**; documented HTTPS async (no request-path timing channel) and fsync'd write-then-accept counter durability | State-losing clients no longer get silently locked out; timing side channel and replay-on-crash windows closed/documented. |
| **nginx is the supported decoy; built-in axum is dev/test only** | A hand-rolled decoy cannot match nginx's header ordering, error pages, and TLS fingerprint against active probing. |
| **Entropy-based fully-encrypted-flow detection** added to §10.2; Elligator2 + mimic transports noted in §14 | Honest about the "absence of a fingerprint is a fingerprint" limitation for the stated adversary. |
| **Naming unified to `ghostbro`** (paths, config filename, env vars) | Post-rename consistency. |
| Documented `identity.noise` derivation tradeoff (§7.1) and `max_concurrent_sessions` enforcement (§9); added operator legal-exposure note (§13.5) | Spec completeness. |

### From v0.1

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
