# Threat Model: Ghostbro

## 1. System context

Ghostbro is a censorship-resistant encrypted proxy whose primary security
property is *invisibility*: to any unauthorized observer the host looks like an
ordinary web server, and the proxy service is unreachable until a client proves
authorization. An XDP/eBPF program at the network edge drops all traffic to the
proxy port (TCP 8443) unless the source IP is present in a kernel allow-map.
Entries are added only after the server verifies a Single Packet Authorization
(SPA) — one Ed25519-signed datagram (UDP mode) or HTTPS POST body (HTTPS mode)
carrying a timestamp, monotonic counter, and nonce. Authorized clients then run
a Noise IK tunnel (`Noise_IK_25519_ChaChaPoly_BLAKE2s`) that multiplexes either
SOCKS5 TCP egress or the **Ghost Relay**, a server-side content fetcher (web
fetch, `git clone --mirror`, and PyPI/npm/crates package retrieval) with a
durable per-client spool.

The intended users are a small, manually-enrolled set of people ("I know this
person" trust model) operating from regions with internet shutdowns or DPI. The
intended deployment for this model is **multi-server failover**: several nodes
share the same enrolled client keys, and clients try them in priority order. The
adversary of record is a network-level censor/observer with packet-capture and
active-probing capability, plus the ordinary internet background of scanners and
the risk that any one client key or relay target is hostile.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| proxy concealment | the secret that a proxy exists on this host at all (the core product property) | critical |
| server Noise identity key | long-term static key clients pin; impersonation root | critical |
| authorized client roster | `authorized_keys.toml` — who is allowed; deanonymizing if leaked | high |
| client identity keys | Ed25519 + derived Noise static, encrypted at rest on clients | critical |
| SPA replay state | per-key monotonic counter file; integrity gates replay protection | high |
| allow-map integrity | kernel set of IPs permitted to reach the proxy port | high |
| relay egress capability | server's ability to make outbound network/process calls | high |
| relay spool contents | per-client stored fetch results on the server | medium |
| service availability | the proxy/decoy continuing to serve authorized clients | medium |
| host integrity | the server OS/process behind the proxy | critical |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| UDP SPA port (XDP) | structural pre-filter + per-IP rate-limit in kernel, ring buffer to userspace verifier | unauth network → kernel/userspace SPA pipeline | allow-map integrity, SPA replay state, proxy concealment, service availability |
| Decoy :443 (TLS + HTTPS-SPA) | axum decoy serving static/placeholder content and the HTTPS-SPA POST endpoint | unauth network → userspace verifier / file read | allow-map integrity, proxy concealment, relay spool contents, service availability |
| Proxy :8443 (Noise IK) | post-allow-map TCP; Noise IK handshake with client-static pin + prologue binding | allow-listed network → authenticated tunnel | server Noise identity key, host integrity |
| Ghost Relay channel (`0x47`) | post-handshake op dispatch: submit/list/download/delete | authenticated client → server egress + filesystem | relay egress capability, relay spool contents, host integrity |
| SOCKS5 channel (`0x05`) | post-handshake no-auth SOCKS5 TCP CONNECT | authenticated client → arbitrary TCP egress | relay egress capability, host integrity |
| authorized_keys.toml + counter state files | files read at startup and hot-reloaded (inotify) | local filesystem → process trust | authorized client roster, SPA replay state |
| server identity key file | Noise static private key loaded at startup | local filesystem → process trust | server Noise identity key |
| Cargo dependency graph | snow, ed25519-dalek, reqwest, aya, fast-socks5, HTML normalizer, etc. | upstream code → server process | host integrity, server Noise identity key |

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Relay weaponized as an SSRF pivot to internal/cloud-metadata services, exfiltrating credentials or reaching the host network | remote_auth | Ghost Relay channel | relay egress capability, host integrity | high | likely | partially_mitigated | `resolve_guard` blocks direct loopback/private/link-local/multicast targets | `relay.rs:128` redirect policy `limited(5)` never re-checks redirect targets; `relay.rs:992` guard resolves DNS independently of reqwest's own resolution (rebinding TOCTOU) |
| T3 | Pre-auth DoS: the per-IP rate-limit is defeated by source-IP spoofing, flooding the userspace Ed25519 verifier (IPv6 gate-bypass sub-case risk-accepted — see §5) | remote_unauth | UDP SPA port, Decoy :443 | proxy concealment, service availability | high | possible | partially_mitigated | per-IP token bucket + structural pre-filter (UDP only); XDP_DROP on SPA port; deployment is not dual-stack | `ebpf/src/main.rs:191` rate-limit keyed on (spoofable) src_ip; HTTPS-SPA path has no rate-limit; `ebpf/src/main.rs:60` non-IPv4 returns XDP_PASS (accepted while IPv4-only) |
| T7 | Remote compromise via a vulnerability in a parsing/crypto dependency or in relayed upstream content (git/package/HTML) | supply_chain | Cargo dependency graph, Ghost Relay channel | host integrity, server Noise identity key | high | rare | partially_mitigated | Cargo.lock pins; digest verification for packages; git runs with prompts disabled | dependency surface (snow, reqwest, aya, fast-socks5, HTML→markdown); `relay.rs:548` spawns `git clone --mirror` on client-supplied URLs |
| T2 | SPA gate opened for an attacker-chosen IP via cross-server replay and UDP source-IP spoofing (gate exposure, not tunnel access) | adjacent_network | UDP SPA port | allow-map integrity, proxy concealment | medium | likely | partially_mitigated | monotonic counter + ±300s window per server; Noise client-static pin + prologue still gate the tunnel | `spa.rs:184` signed region omits any server/endpoint identity; counter state is per-server-instance (`spa.rs:159`), so a packet to node A replays to node B; src IP never committed in signed payload |
| T5 | Resource exhaustion and quota evasion degrading availability for legitimate clients | remote_auth | Ghost Relay channel, Proxy :8443 | service availability, host integrity | medium | possible | partially_mitigated | per-client job-count and byte quotas; job TTL reaper; fetch/git timeouts | `max_concurrent_sessions` parsed but never enforced (keys.rs/proxy path); `relay.rs:398` reads whole object into memory per download; one subprocess per git job |
| T4 | Replay protection or pinned server identity defeated by tampering with / loss of on-disk state | local_admin | counter state file, server identity key file | SPA replay state, server Noise identity key | medium | possible | partially_mitigated | atomic temp+rename writes; `0600` on generated private keys | `spa.rs:159` missing counter file silently resets counters to 0 (replay reopens); `noise.rs:487` missing identity file auto-generates a new keypair (fail-open) |
| T6 | Decoy static file serving discloses files outside the intended webroot | remote_unauth | Decoy :443 | relay spool contents, host integrity | low | rare | partially_mitigated | rejects non-`Normal` path components (`..` blocked) | `decoy.rs:108` `static_path` never canonicalizes, so a symlink under webroot is followed by `fs::read` |

## 5. Deprioritized

| threat | reason |
|---|---|
| Traffic analysis / flow correlation across both endpoints | Acknowledged out of scope in PRD §10.2; padding/shaping is future work. |
| Full server host seizure / compromise | Risk accepted in PRD §10.2; mitigated structurally by Noise IK (past client identities safe) + FDE + multi-node. Modeled only where on-disk state enables a *remote-reachable* effect (see T4). |
| Single client key compromise | By design only burns that client; revocation via `authorized_keys.toml` purges allow-map entries (`ebpf.rs:261`). |
| Server impersonation / MitM of the tunnel | Mitigated: client pins server Noise static key; IK handshake fails without the server private key. |
| Endpoint/device compromise of a client | Out of scope per PRD §10.2 ("owned client = game over"). |
| Rubber-hose extraction of a client passphrase | Out of scope; passphrase buys revocation time only. |
| IPv6 gate bypass (concealment loss over IPv6) | Risk-accepted by owner: deployment is IPv4-only for now, IPv6 is future work. Revisit when the fleet goes dual-stack. |
| SPA source-IP binding inside the signed payload | Deprioritized by owner feedback: NAT/CGNAT users often can't know their public IP, and the residual it closes is gate/stealth (not access). Server-identity binding (T2) is preferred instead. |

## 6. Open questions

Resolved with the owner this session:

- **SPA binding (T2):** *Decided* — bind the **server identity** (Noise static
  pubkey) into the signed region to stop cross-node replay in the failover
  fleet. Source-IP-in-signature was considered and **deprioritized** (NAT/CGNAT
  users can't reliably know their public IP, and the residual it closes is
  gate/stealth, not tunnel access). See §5.
- **IPv6 (T3):** *Decided* — IPv4-only for now; IPv6 gate coverage is future
  work and the bypass is risk-accepted. See §5.
- **Relay redirects (T1):** *Decided* — keep following redirects, but re-run
  `resolve_guard` on **every hop** and pin the vetted IP into the connection to
  close the DNS-rebinding window.
- **`max_concurrent_sessions` (T5):** *Decided* — enforcement is expected;
  current code parses but does not enforce it.
- **Server identity fail-open (T4):** *Decided* — a missing identity file should
  be a hard startup error in production, not a silent keypair regeneration.

Still to verify in code / confirm operationally:

- **Counter-state durability (T4):** decide whether the server should refuse to
  start (or force re-key) on a counter regression, versus relying on operational
  monitoring to catch a reset.
- Confirm the exact wire layout for the server-pubkey-in-signature change so the
  XDP structural pre-filter and the client builder stay in sync.

## 7. Provenance

- mode: bootstrap-then-interview
- date: 2026-06-08
- target: /home/jg/git/ghost-boi-adv (local checkout, not a git repository)
- inputs: PRD.md, README.md (design docs); no external vuln feed
- owner: present in session; confirmed deployment = multi-server failover, IPv4-only; resolved §6 decisions on T1–T5

## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Enforce `resolve_guard` on every redirect hop (custom redirect policy) and pin the vetted IP into the connection, or disable relay redirects | T1 | yes | M |
| Bind the SPA signature to server identity (include server pubkey in the signed region) — chosen fix for cross-node replay | T2 | yes | M |
| Add a global SPA verification budget + rate-limit the HTTPS-SPA endpoint (IPv6 gate coverage deferred — risk-accepted) | T3 | partial | M |
| Fail closed on a missing server identity file; refuse to start on counter-state regression instead of resetting | T4 | yes | S |
| Enforce `max_concurrent_sessions` and stream relay downloads instead of reading whole objects into memory | T5 | partial | M |
| Canonicalize resolved static paths and confirm containment within webroot before reading | T6 | yes | S |
| Pin and routinely audit dependencies (cargo-audit/deny in CI); sandbox the git/package fetch workers | T7 | partial | M |
