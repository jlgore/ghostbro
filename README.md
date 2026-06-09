# Ghostbro

Rust workspace for the Ghostbro PRD in `PRD.md`.

- `ghostbro-common`: shared protocol, SPA packet, key, and crypto utilities
- `ghostbro-client`: client CLI, key enrollment, SPA refresh, Noise tunnel, and local SOCKS5 listener
- `ghostbro-server`: server daemon, SPA verification, built-in HTTPS decoy, XDP control, and Noise proxy listener
- `ghostbro-ebpf`: XDP/eBPF packet gate

## Build

```bash
cargo build
cargo xtask build-ebpf
```

## Operator Quickstart

### 1. Generate a Client Identity

Normal client key generation writes an encrypted Ed25519 identity key. The passphrase is used with argon2id and ChaCha20-Poly1305.

```bash
cargo run -p ghostbro-client -- keygen --output ./client/alice
```

This writes:

- `./client/alice.key`: encrypted client private identity, mode `0600` on Unix
- `./client/alice.pub`: client Ed25519 public key for SPA signatures
- `./client/alice.noise`: persistent client Noise static public key derived from the Ed25519 identity
- `./client/alice.keyid`: server lookup key ID
- `./client/alice.counter`: local SPA replay counter

The command also prints an `authorized_keys.toml` entry. Add both public keys to the server; the server verifies SPA signatures with `public_key` and verifies the Noise IK remote static key with `noise_public_key`.

```toml
[[clients]]
name = "alice"
public_key = "<base64-ed25519-public-key>"
noise_public_key = "<base64-x25519-noise-public-key>"
tier = "full"
```

### 2. Generate the Server Noise Identity

```bash
cargo run -p ghostbro-client -- server-keygen --output ./server/server
```

This writes:

- `./server/server.key`: server Noise static private key, mode `0600` on Unix
- `./server/server.pub`: base64 server Noise static public key for client enrollment

Put the private key path in server config and distribute only `server.pub` to clients.

### 3. Configure the Server

Example `/etc/ghost-proxy/ghost-proxy.toml`:

```toml
[server]
identity = "/etc/ghost-proxy/server.key"

[spa]
mode = "both" # "udp", "https", or "both"

[spa.common]
time_window = 300
allow_ttl = 14400
counter_state = "/var/lib/ghost-proxy/spa-counters.toml"

[spa.udp]
port = 53
rate_limit = 5

[spa.https]
path = "/api/v1/telemetry"
response_status = 204
trust_forwarded_for = false
trusted_proxy_cidrs = []

[proxy]
port = 8443
noise_pattern = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
bind = "0.0.0.0"

[clients]
authorized_keys = "/etc/ghost-proxy/authorized_keys.toml"

[decoy]
mode = "builtin"
bind = "0.0.0.0:443"
webroot = "/var/www/html"
# Optional: serve the builtin decoy over HTTPS. When both are set, the decoy
# terminates TLS itself (rustls/ring); omit them to serve plain HTTP.
tls_cert = "/etc/letsencrypt/live/example.com/fullchain.pem"
tls_key = "/etc/letsencrypt/live/example.com/privkey.pem"

[logging]
path = "/var/log/ghost-proxy/server.log"
level = "info"
```

`response_status` controls the built-in HTTPS SPA decoy response status for valid and invalid SPA posts. Use `trust_forwarded_for = true` only when the built-in decoy is behind a proxy you control, and list only those proxy source ranges in `trusted_proxy_cidrs`; otherwise the server uses the TCP peer IP as the allow-map source.

If `RUST_LOG` is set, it overrides `[logging].level` and logs to the default subscriber output. Without `RUST_LOG`, `[logging].level` controls runtime verbosity and `[logging].path` appends logs to that file.

`[decoy] mode = "builtin"` uses the built-in axum decoy. `bind` controls the decoy listen address unless `--decoy-bind` is provided. If `webroot` is set, non-SPA requests serve static files from that directory with path traversal rejected; otherwise the built-in nginx-like placeholder page is returned.

Start the server with XDP attached:

```bash
sudo RUST_LOG=info target/debug/ghostbro-server \
  --config /etc/ghost-proxy/ghost-proxy.toml \
  --iface eth0 \
  --ebpf-object target/bpfel-unknown-none/release/ghostbro-ebpf \
  --decoy-bind 0.0.0.0:443
```

The built-in decoy serves HTTPS directly when `[decoy].tls_cert` and `tls_key` are set (rustls/ring), so HTTPS SPA posts arrive over real TLS without a fronting proxy. Without them it serves plain HTTP — terminate TLS with a fronting proxy instead. If forwarding source IPs, configure `trust_forwarded_for` and `trusted_proxy_cidrs` as above.

For local testing you can generate a throwaway cert and point a client at it with `curl -k`:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/decoy.key \
  -out /tmp/decoy.crt -days 1 -subj "/CN=localhost"
# add tls_cert = "/tmp/decoy.crt" / tls_key = "/tmp/decoy.key" under [decoy], then:
curl -k https://127.0.0.1:8443/            # decoy page over TLS
```

### 3a. Run the server unprivileged (production hardening)

Per PRD §13.4 the proxy should not run as root — only the eBPF loader needs
capabilities. The shipped systemd unit `deploy/ghost-proxy.service` runs the
daemon as the unprivileged `ghost-proxy` user with exactly
`AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_NET_BIND_SERVICE` (drop
`CAP_NET_BIND_SERVICE` if the decoy is >1024 or behind nginx), a restricted
`CapabilityBoundingSet`, `NoNewPrivileges=true`, `ProtectSystem=strict`, a
seccomp `SystemCallFilter` of `@system-service @bpf`, and writable state confined
to `/var/lib/ghost-proxy` + `/var/log/ghost-proxy`.

The daemon logs its own privilege level at startup (`SERVER_PRIVILEGE_LEVEL`
with uid/gid and effective caps) and warns when run as full root or when a
required capability is missing — so a misconfigured deployment is obvious.

In-process root→`setuid` dropping is intentionally **not** done: Linux
capabilities are per-thread and this is a multithreaded tokio process whose
allow-map writes happen on worker threads, so systemd ambient capabilities are
the correct mechanism (they apply to every thread from process start, and keep
working on kernels with `unprivileged_bpf_disabled=1`).

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin ghost-proxy
sudo install -Dm755 target/release/ghostbro-server /usr/local/bin/ghostbro-server
sudo install -Dm644 deploy/ghost-proxy.service /etc/systemd/system/ghost-proxy.service
sudo systemctl daemon-reload && sudo systemctl enable --now ghost-proxy
```

### 4. Enroll Servers on the Client

Enroll one server from its public key:

```bash
SERVER_PUB=$(tr -d '\n' < ./server/server.pub)
cargo run -p ghostbro-client -- enroll \
  --server-key "$SERVER_PUB" \
  --endpoint 203.0.113.10:8443 \
  --spa-mode udp \
  --spa-port 53 \
  --output ./client/servers.toml
```

For multi-server failover, add more `[[servers]]` entries to `servers.toml`. Lower `priority` values are attempted first.

```toml
[[servers]]
endpoint = "203.0.113.10:8443"
spa_endpoint = "203.0.113.10"
spa_mode = "udp"
spa_port = 53
server_public_key = "<base64-server-noise-public-key>"
priority = 1

[[servers]]
endpoint = "198.51.100.20:8443"
spa_endpoint = "example.net"
spa_mode = "https"
spa_port = 443
server_public_key = "<base64-backup-server-noise-public-key>"
priority = 2

[failover]
strategy = "priority"     # "priority" | "random" | "latency"
retry_interval_ms = 5000  # pause between full retry rounds
max_retries = 3           # additional rounds after the first (0 = single pass)
```

Failover `strategy` controls the order candidates are tried each round:

- `priority` — ascending `priority` order (configured order).
- `random` — order reshuffled on every round, spreading load and avoiding a predictable first hop.
- `latency` — each candidate's proxy port is TCP-probed (1s timeout) and the lowest-latency reachable server is tried first; unreachable candidates sort last and ties keep priority order. Note the proxy port is XDP-gated until SPA authorization, so latency ordering is most useful for already-authorized source IPs or non-gated deployments; otherwise it degrades gracefully to priority order.

If a full pass over all candidates fails, the client waits `retry_interval_ms` and retries up to `max_retries` more rounds (re-deriving the order each round, so `random`/`latency` re-evaluate).

### 5. Connect

Start the local SOCKS5 listener and let the client send SPA, establish Noise IK, and fail over across configured servers if needed.

```bash
cargo run -p ghostbro-client -- connect \
  --config ./client/servers.toml \
  --identity-key ./client/alice.key \
  --listen 127.0.0.1:1080
```

The client prompts for the encrypted identity passphrase. Use applications through `socks5://127.0.0.1:1080`.

## Development Smoke Test

Plaintext private keys are only for smoke tests and local development. Do not use `--plaintext-debug` for real client identities.

Prepare a loopback debug identity, derived Noise public key, authorized keys file, and server config:

```bash
cargo xtask prepare-spa-loopback
```

The helper writes `/tmp/ghost-debug.*`, including `/tmp/ghost-debug.noise`, `/tmp/ghost-authorized.toml`, and `/tmp/ghost-server.toml`, then prints the exact server and client commands.

Run the server with XDP attached to loopback:

```bash
sudo RUST_LOG=debug target/debug/ghostbro-server \
  --config /tmp/ghost-server.toml \
  --iface lo \
  --ebpf-object target/bpfel-unknown-none/release/ghostbro-ebpf \
  --decoy-bind 127.0.0.1:8080
```

Send one UDP SPA packet:

```bash
cargo run -p ghostbro-client -- send-udp-spa \
  --identity-key /tmp/ghost-debug.key \
  --server-key /tmp/ghost-server-noise.pub \
  --endpoint 127.0.0.1:5353
```

`--server-key` is required: the destination server's Noise public key is bound
into the SPA signature (authenticated, not transmitted) so a packet only opens
the server it was built for. The server should log `SPA_ACCEPT` and
`ALLOW_MAP_WRITE` for `127.0.0.1`.

For end-to-end local checks, use the existing xtask smoke helpers such as `cargo xtask smoke-noise-loopback`, `cargo xtask smoke-socks5-loopback`, `cargo xtask smoke-socks5-listener-loopback`, or `cargo xtask smoke-ghost-relay-loopback`. The Ghost Relay smoke submits a local web fetch, reconnects to list jobs, reconnects to download the stored result, then reconnects to delete it.

Ghost Relay debug helpers support the durable web-fetch flow:

```bash
cargo run -p ghostbro-client -- relay-submit-url \
  --identity-key /tmp/ghost-debug.key \
  --server-key /tmp/ghost-server-noise.pub \
  --spa-endpoint 127.0.0.1:5353 \
  --proxy-endpoint 127.0.0.1:8443 \
  --url https://example.com/ \
  --normalize                     # also store an HTML-to-markdown copy

# Mirror a git repository (stored server-side as a git bundle):
cargo run -p ghostbro-client -- relay-submit-git \
  --identity-key /tmp/ghost-debug.key \
  --server-key /tmp/ghost-server-noise.pub \
  --spa-endpoint 127.0.0.1:5353 \
  --proxy-endpoint 127.0.0.1:8443 \
  --git-url https://github.com/rust-lang/log.git

# Retrieve a package from pypi / npm / crates (version optional for pypi/npm):
cargo run -p ghostbro-client -- relay-submit-package \
  --identity-key /tmp/ghost-debug.key \
  --server-key /tmp/ghost-server-noise.pub \
  --spa-endpoint 127.0.0.1:5353 \
  --proxy-endpoint 127.0.0.1:8443 \
  --ecosystem crates --name serde --version 1.0.197

cargo run -p ghostbro-client -- relay-list \
  --identity-key /tmp/ghost-debug.key \
  --server-key /tmp/ghost-server-noise.pub \
  --spa-endpoint 127.0.0.1:5353 \
  --proxy-endpoint 127.0.0.1:8443

cargo run -p ghostbro-client -- relay-download \
  --identity-key /tmp/ghost-debug.key \
  --server-key /tmp/ghost-server-noise.pub \
  --spa-endpoint 127.0.0.1:5353 \
  --proxy-endpoint 127.0.0.1:8443 \
  --job-id <job-id> \
  --output ./relay-result.body \
  --artifact primary              # or "markdown" for the normalized copy

cargo run -p ghostbro-client -- relay-delete \
  --identity-key /tmp/ghost-debug.key \
  --server-key /tmp/ghost-server-noise.pub \
  --spa-endpoint 127.0.0.1:5353 \
  --proxy-endpoint 127.0.0.1:8443 \
  --job-id <job-id>
```

Relay results are stored per client key ID under `GHOST_PROXY_RELAY_SPOOL_DIR` or `/var/lib/ghost-proxy/relay` by default. Loopback/private URL fetches are blocked unless `GHOST_PROXY_RELAY_ALLOW_LOOPBACK=1` is set for local smoke testing.

## PRD v0.2 Coverage

PRD v0.2 is fully implemented. Notable subsystems:

- **Decoy HTTPS** — builtin mode, webroot static serving, and TLS: set `tls_cert`/`tls_key` under `[decoy]` and the builtin decoy terminates TLS itself (rustls/ring) on its bind address, making HTTPS SPA mode real end-to-end. External nginx fronting remains a supported alternative. The decoy emits a realistic `Date` header on every response.
- **Ghost Relay / `0x47`** — full store-and-forward model: async background workers with crash recovery, per-client TTL + storage/job-count quota enforcement, web fetch with optional HTML-to-markdown normalization, git mirroring (`clone --mirror` → bundle), and package retrieval from PyPI / npm / crates.io with digest verification. Submit is asynchronous — it returns a `job_id` immediately and the result is fetched in the background; poll `relay-list` until the job status is `complete` before downloading.
- **Multi-server failover** — `priority`, `random`, and `latency` strategies with configurable retry rounds (`retry_interval_ms` / `max_retries`).
- **Clock-drift detection (§13.2)** — in HTTPS SPA mode the client measures drift against the server's HTTP `Date` header and surfaces a clear error (with remediation) when drift exceeds the assumed ±300s SPA window, or a warning past half-window. In UDP SPA mode the connection-failure hint reports the client's current UTC time for manual comparison.
- **Server hardening (§13.4)** — the daemon runs unprivileged via the shipped `deploy/ghost-proxy.service` unit (User= + ambient `CAP_BPF`/`CAP_NET_ADMIN`/`CAP_NET_BIND_SERVICE`) and reports its privilege level at startup. See [§3a](#3a-run-the-server-unprivileged-production-hardening).

### Future Work (explicitly deferred in PRD §14)

- **SOCKS5 UDP ASSOCIATE** — current SOCKS5 support is no-auth TCP CONNECT over Noise IK.
- **IPv6** — v0.2 is IPv4-only (BPF maps use 32-bit keys).
- **Two-process privilege separation** — the single-binary daemon already runs unprivileged with scoped capabilities; a separate cap-holding loader passing map fds to an unprivileged proxy process is a possible future refinement, not a v0.2 requirement.
- Traffic shaping/padding, multi-hop, QUIC SPA mode, and the other items listed in PRD §14.
