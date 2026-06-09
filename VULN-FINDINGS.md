# Vulnerability Findings — Ghost Proxy

- **Target:** `/home/jg/git/ghost-boi-adv`
- **Scanned:** 2026-06-09 (static review, seeded by `THREAT_MODEL.md`)
- **Totals:** 20 findings — 4 HIGH, 7 MEDIUM, 9 LOW (1 low-confidence)
- **Focus areas (8):** relay SSRF/fetch/packages · relay git-subprocess/storage/quotas · HTML normalizer · SPA verify/replay · XDP/eBPF gate · Noise tunnel/identity · decoy HTTPS · key mgmt/client CLI
- **Note:** confidences are finder-reported (Step 3b independent re-scoring skipped). `/triage` performs the rigorous N-vote verification.

> These are **static candidates**, not verified exploits. For execution-verified crashes, use `vuln-pipeline run <target>`.

## Summary table

| id | sev | conf | category | file:line | title |
|----|-----|------|----------|-----------|-------|
| F-001 | HIGH | 0.95 | fail-open | ghost-proxy-server/src/noise.rs:487 | Server Noise identity key fails open: missing file silently regenerates keypair |
| F-002 | HIGH | 0.95 | ssrf | ghost-proxy-server/src/relay.rs:128 | HTTP redirect targets never re-validated against the SSRF guard |
| F-003 | HIGH | 0.90 | replay | ghost-proxy-common/src/spa.rs:99 | Signed SPA region omits server identity → cross-server replay |
| F-004 | HIGH | 0.90 | ssrf | ghost-proxy-server/src/relay.rs:992 | DNS-rebinding TOCTOU between guard and reqwest resolution |
| F-005 | MEDIUM | 0.90 | auth-bypass | ghost-proxy-ebpf/src/main.rs:191 | Pre-auth rate-limit keyed on spoofable source IP |
| F-006 | MEDIUM | 0.85 | path-traversal | ghost-proxy-server/src/decoy.rs:118 | static_path follows symlinks out of webroot (no canonicalization) |
| F-007 | MEDIUM | 0.85 | replay | ghost-proxy-server/src/spa.rs:156 | Missing counter-state file silently resets replay counters to zero |
| F-008 | LOW | 0.85 | info-disclosure | ghost-proxy-ebpf/src/main.rs:231 | SpaEvent payload tail left uninitialized in ring buffer |
| F-009 | MEDIUM | 0.80 | auth-bypass | ghost-proxy-server/src/relay.rs:772 | Package digest verification skipped when registry omits digest |
| F-010 | LOW | 0.80 | info-disclosure | ghost-proxy-ebpf/src/main.rs:238 | payload_len hardcoded to 107; fixed-window copy ignores real length |
| F-011 | MEDIUM | 0.70 | integer-overflow | ghost-proxy-server/src/relay.rs:571 | Git bundle read into memory with no size cap (OOM primitive) |
| F-012 | MEDIUM | 0.70 | ssrf | ghost-proxy-server/src/relay.rs:940 | Registry-controlled download URL (crates dl_path `@` host-confusion) |
| F-013 | LOW | 0.70 | auth-bypass | ghost-proxy-ebpf/src/main.rs:60 | Non-IPv4 (incl. IPv6) returns XDP_PASS, bypassing the gate |
| F-014 | MEDIUM | 0.60 | toctou | ghost-proxy-server/src/relay.rs:473 | Check-then-write race lets concurrent jobs exceed quotas |
| F-015 | LOW | 0.55 | auth-bypass | ghost-proxy-server/src/relay.rs:966 | SRI parser does not validate decoded SHA-512 length |
| F-016 | LOW | 0.55 | auth-bypass | ghost-proxy-server/src/spa.rs:114 | Tier check precedes signature verify → key/tier enumeration oracle |
| F-017 | LOW | 0.50 | ssrf | ghost-proxy-server/src/relay.rs:946 | Registry JSON queries bypass resolve_guard and follow redirects |
| F-018 | LOW | 0.40 | weak-crypto | ghost-proxy-server/src/noise.rs:179 | Client-static verification uses non-constant-time comparison |
| F-019 | LOW | 0.40 | argument-injection | ghost-proxy-server/src/relay.rs:553 | No `--` separator before client URL in git clone (defense-in-depth) |
| F-020 | LOW | 0.30 | out-of-bounds-read | ghost-proxy-ebpf/src/main.rs:321 | copy_payload_byte uses wrapping_add for bounds check |

---

### F-001 — Server Noise identity key fails open: missing file silently regenerates keypair
**HIGH · conf 0.95 · fail-open · ghost-proxy-server/src/noise.rs:487**

`load_or_generate_static_key` reads the identity file; on `ErrorKind::NotFound` (line 487) it does not error but generates a brand-new Noise static keypair, writes it to disk, logs it as a "debug" keypair, and returns it. This is the long-term static identity clients pin (impersonation root), and the function is called unconditionally at startup from `run_proxy_listener` (noise.rs:41) with no production guard. If the file is absent (deleted, ephemeral volume, wrong cwd, failed mount, restore-without-key) the server comes up with a different public key: (1) every enrolled client fails the IK handshake against the new static → silent total outage to the roster; (2) defeats the multi-server failover guarantee that nodes share enrolled keys — a regenerated node diverges from the fleet. No check that the loaded/generated key matches an expected public key.

- **Exploit:** Operator redeploys a node onto a fresh volume without restoring `identity.key`. Server mints a new keypair, logs success at info ("generated debug keypair"), serves. Every client pinning the original static fails the handshake with no obvious server error.
- **Fix:** Fail closed in production (error on `NotFound`); gate auto-generation behind an explicit opt-in used only for provisioning; support an expected-public-key pin and refuse to start on mismatch.
- **Maps to:** THREAT_MODEL T4 / §6 owner decision.

### F-002 — HTTP redirect targets never re-validated against the SSRF guard
**HIGH · conf 0.95 · ssrf · ghost-proxy-server/src/relay.rs:128**

The reqwest client is built with `redirect::Policy::limited(5)` (line 128) and follows redirects automatically. `validate_public_url → resolve_guard` runs only on the original URL (227, 525, 587); reqwest then GETs in `http_get_bytes` (609) and silently follows any `Location` with no per-hop guard. A public URL that 302s to `http://169.254.169.254/...` is fetched and spooled.

- **Exploit:** Authenticated client submits `web_fetch` for `http://attacker.com/redir`; attacker responds `302 Location: http://169.254.169.254/latest/meta-data/iam/security-credentials/`. reqwest follows it, the metadata credentials become the job body, client downloads them. Also reaches `http://127.0.0.1` internal services.
- **Fix:** `redirect::Policy::custom(...)` invoking `resolve_guard` on every hop; pin the vetted IP into the connection.
- **Maps to:** THREAT_MODEL T1.

### F-003 — Signed SPA region omits server identity → cross-server replay
**HIGH · conf 0.90 · replay · ghost-proxy-common/src/spa.rs:99**

Signature covers exactly `payload[..SPA_SIGNED_LEN]` = `version(2)+flags(1)+key_id(8)+timestamp(8)+counter(8)+nonce(16)` = 43 bytes (sign at 107, verify at 150). No server/endpoint identity is authenticated, and counter state is per-server-instance (server/spa.rs:16-23,125-134). In the confirmed multi-server failover deployment, a valid SPA accepted by node A — captured on the wire — verifies on node B (lower counter for that key) and opens B's gate.

- **Exploit:** On-path attacker captures a client SPA to node A (counter=5); A consumes 5. Within the ±300s window the attacker replays to node B (counter ≤4). Combined with UDP source-IP spoofing, B allow-lists an attacker-chosen IP, exposing the concealed port on B.
- **Fix:** Include the server's Noise static pubkey / node id in the signed region; update `SPA_SIGNED_LEN`, builder, verifier, and the XDP pre-filter together; reject non-matching server identity.
- **Maps to:** THREAT_MODEL T2 (owner's chosen fix).

### F-004 — DNS-rebinding TOCTOU between guard and reqwest resolution
**HIGH · conf 0.90 · ssrf · ghost-proxy-server/src/relay.rs:992**

`resolve_guard` (992) resolves DNS itself via `to_socket_addrs()` (999) and checks those IPs, but `http_get_bytes` (609) lets reqwest resolve again independently. An attacker-controlled authoritative DNS with near-zero TTL answers the guard with a public IP (passes) and reqwest with `127.0.0.1`/`169.254.169.254`/RFC1918. Applies to web fetch, package download, and registry queries.

- **Exploit:** `http://rebind.attacker.com/` resolves to a public IP for the guard, then flips to `169.254.169.254` (TTL 0); the worker fetch connects to the metadata service and spools the response.
- **Fix:** Resolve once, validate, then force reqwest to connect to that exact IP (`Client::builder().resolve(host, addr)` / custom connector); reject multi-A hosts unless all pass.
- **Maps to:** THREAT_MODEL T1 (TOCTOU sub-case).

### F-005 — Pre-auth rate-limit keyed on spoofable source IP
**MEDIUM · conf 0.90 · auth-bypass · ghost-proxy-ebpf/src/main.rs:191**

`rate_limit_allows` (191) keys the token bucket on `src_ip` (199), read from the attacker-controlled IPv4 header (75). Spoofing a different source IP per packet yields a fresh full bucket each time, so each structurally-valid SPA is pushed to the userspace Ed25519 verifier (142-153) with no aggregate limit; `RATE_LIMIT` (16384 entries) also fills with attacker keys.

- **Exploit:** Flood the SPA port with structurally-valid SPA headers (version `0x47 0x50`, reserved flags clear) and a randomized spoofed `src_ip` per packet; every packet passes and feeds the verifier.
- **Fix:** Add a global SPA verification budget (single global token bucket) in addition to the per-IP one; bound/evict `RATE_LIMIT`.
- **Maps to:** THREAT_MODEL T3.

### F-006 — static_path follows symlinks out of webroot (no canonicalization)
**MEDIUM · conf 0.85 · path-traversal · ghost-proxy-server/src/decoy.rs:118**

`static_path` (118-135) rejects non-`Normal` components (130) so `..`/absolute/Windows traversal is blocked, but it never canonicalizes or verifies containment; `static_response` then `fs::read`s the path (105-106). A symlink under webroot (e.g. `webroot/data -> /etc`) is followed, disclosing files outside webroot to unauthenticated clients. Only precondition: a symlink under the configured webroot (common — release `current` links, etc.).

- **Exploit:** `GET /latest/secret.key` where `webroot/latest` → a deploy dir outside webroot; `fs::read` returns out-of-webroot content with 200, `content_type` defaulting to `application/octet-stream`.
- **Fix:** Canonicalize candidate path + webroot, verify `starts_with` the canonical root before reading; reject on escape/failure; consider `O_NOFOLLOW`. Add a symlink fixture test.
- **Maps to:** THREAT_MODEL T6.

### F-007 — Missing counter-state file silently resets replay counters to zero
**MEDIUM · conf 0.85 · replay · ghost-proxy-server/src/spa.rs:156**

`load_counter_state` treats a `NotFound` file as a clean empty map (159); `verify` then defaults the per-key highest counter to 0 (125-129), so after the file is lost any captured SPA with counter ≥1 passes `counter <= highest_counter` (130). Nothing detects the regression. Corrupt/partial TOML is handled safely (errors → startup fails); the gap is the missing-file / truncation case.

- **Exploit:** Counter file lost (disk wipe, failed deploy, container without persistent volume, cleanup script). Attacker replays any previously captured valid SPA; accepted while inside the window. All old captured SPAs up to the client's true counter become replayable.
- **Fix:** Fail closed on a missing file in production (or require an explicit init flag); fsync; monotonic floor / signed watermark; treat any regression as a hard error.
- **Maps to:** THREAT_MODEL T4.

### F-008 — SpaEvent payload tail left uninitialized in ring buffer
**LOW · conf 0.85 · info-disclosure · ghost-proxy-ebpf/src/main.rs:231**

`SPA_RING.reserve::<SpaEvent>(0)` (231) returns 136 uninitialized bytes; the writer initializes through offset 114 (107 payload bytes) but the payload field spans offsets 8..=135, leaving 115..=135 (21 bytes) holding prior ring-buffer memory. Userspace `parse_spa_event` (server/ebpf.rs:388) `read_unaligned`s the whole struct. Contained today only because `payload_len` is pinned to 107 and userspace slices `payload[..payload_len]`. Becomes a kernel-memory disclosure if `payload_len` ever reflects the real length (F-010) or a consumer reads the full array.

- **Fix:** Zero the reservation before writing (memset the full payload range).

### F-009 — Package digest verification skipped when registry omits digest
**MEDIUM · conf 0.80 · auth-bypass · ghost-proxy-server/src/relay.rs:772**

`ExpectedDigest::None.verify()` returns `Ok(())` unconditionally (772). All resolvers fall back to `None` when the digest is missing: pypi (878), npm (913, also when integrity isn't a parseable sha512), crates (938). With registry-controlled URLs (F-012) and redirect/rebinding (F-002/F-004), an attacker influencing the registry response or fetched content delivers arbitrary bytes that pass "verification."

- **Exploit:** A malicious/MITM'd registry omits `digests.sha256` (pypi) or supplies a non-sha512 integrity (npm) → `None`; attacker then serves arbitrary tarball bytes; `verify` passes and the poisoned package is delivered as trusted.
- **Fix:** Treat a missing/unsupported digest as a hard failure for package downloads (or require TLS host-pinning to the official CDN before accepting `None`).
- **Maps to:** THREAT_MODEL T7.

### F-010 — payload_len hardcoded to 107; fixed-window copy ignores real length
**LOW · conf 0.80 · info-disclosure · ghost-proxy-ebpf/src/main.rs:238**

`emit_spa_event` always writes `payload_len = SPA_MIN_LEN` (238) and copies a fixed 107-byte window (240-256), ignoring the actual `payload_len` argument (224); SPA padding (107..=127) is dropped and the userspace `payload_len > SPA_MAX_LEN` guard (server/ebpf.rs:141) is dead code. Safe today (signature covers only the first 43 bytes), but a contract-drift hazard coupled to F-008.

- **Fix:** Clamp `payload_len` to `min(payload_len, SPA_MAX_LEN)`, write that value, copy exactly that many bytes, zero the remainder.

### F-011 — Git bundle read into memory with no size cap (OOM primitive)
**MEDIUM · conf 0.70 · integer-overflow · ghost-proxy-server/src/relay.rs:571**

`run_git_mirror` clones an attacker-controlled remote (`git clone --mirror`), bundles it, then `fs::read(&bundle)` (571) slurps the whole bundle with no size limit; the `max_object_len` guard runs only afterward in `process_job_inner` (478). Unlike the HTTP path (619-627) there is no streaming cap. Bounded only by `git_timeout` (120s default), during which a large/malicious remote delivers gigabytes; the read allocates it all.

- **Exploit:** `SUBMIT_GIT` for an attacker git server or a known-huge repo; within the timeout the relay clones/bundles a multi-GB repo and `fs::read` allocates it; with 4 default workers, concurrent jobs OOM-kill the proxy.
- **Fix:** Stat the bundle before reading and bail past `max_object_len`; cap the on-disk clone (`--depth`/`--filter`); read via a length-limited reader (`take(max_object_len)`).
- **Maps to:** THREAT_MODEL T5/T7.

### F-012 — Registry-controlled download URL (crates dl_path `@` host-confusion)
**MEDIUM · conf 0.70 · ssrf · ghost-proxy-server/src/relay.rs:940**

Download URLs come from untrusted registry JSON: pypi `chosen.url` (870) and npm `dist.tarball` (904) verbatim; crates `format!("https://crates.io{dl_path}")` (940) string-concatenates a registry-controlled `dl_path`. A `dl_path` like `@evil.com/x` yields `https://crates.io@evil.com/x` (userinfo trick → host becomes `evil.com`). `validate_public_url` re-runs on the resolved URL but is still subject to F-002/F-004, and the `@` confusion makes the guard validate the wrong host.

- **Fix:** Parse `dl_path` as a path-only relative ref and `Url::join` against a fixed base, asserting the resulting host equals the expected CDN; allowlist pypi/npm artifact hosts.
- **Maps to:** THREAT_MODEL T1/T7.

### F-013 — Non-IPv4 (incl. IPv6) returns XDP_PASS, bypassing the gate
**LOW · conf 0.70 · auth-bypass · ghost-proxy-ebpf/src/main.rs:60**

`try_ghost_proxy_xdp` PASSes any non-IPv4 ethertype (60-62) and the error path also PASSes (50). IPv6 packets to the proxy port are never gated, so concealment doesn't hold over IPv6. Explicitly risk-accepted in THREAT_MODEL §5 (IPv4-only deployment); reported for completeness, material if the fleet goes dual-stack.

- **Fix:** When dual-stack, parse IPv6 + extension headers and apply the same allow-map/drop, or default-drop non-IPv4 to the proxy port.
- **Maps to:** THREAT_MODEL T3 (risk-accepted sub-case).

### F-014 — Check-then-write race lets concurrent jobs exceed quotas
**MEDIUM · conf 0.60 · toctou · ghost-proxy-server/src/relay.rs:473**

Quota is enforced by unsynchronized read-then-write in two racing places: post-fetch (`process_job_inner` 473-489) and pre-check (`enqueue` 255-294). With 4 default workers and concurrent tunnels for one key_id, multiple jobs read the same pre-write usage snapshot, all pass, then all write. Combined with F-011 (objects up to `max_object_len`), on-disk total can exceed `max_bytes_per_client` by ~`worker_count * max_object_len`.

- **Fix:** Serialize quota accounting per `client_dir` (per-key async mutex across read+write), or an atomic reserved-bytes counter reconciled on completion/failure.
- **Maps to:** THREAT_MODEL T5.

### F-015 — SRI parser does not validate decoded SHA-512 length
**LOW · conf 0.55 · auth-bypass · ghost-proxy-server/src/relay.rs:966**

`parse_sri_sha512` (962) base64-decodes after the `sha512-` prefix without asserting 64 bytes; a short/malformed payload makes the comparison always mismatch (fails closed → targeted unavailability) and silently coerces malformed integrity rather than rejecting it. Not a bypass (fails closed) but a robustness/availability/auditing gap.

- **Fix:** Require `decoded.len() == 64` before constructing `ExpectedDigest::Sha512`; otherwise return `None`/bail explicitly.

### F-016 — Tier check precedes signature verify → key/tier enumeration oracle
**LOW · conf 0.55 · auth-bypass · ghost-proxy-server/src/spa.rs:114**

Order is parse → key_id lookup (110) → unknown-key reject (111) → tier reject (114-116) → only then Ed25519 verify (118). Since `key_id` is a discoverable 8-byte SHA-256 prefix, an unauthenticated attacker gets distinguishable outcomes (UnknownKey vs UnauthorizedTier vs BadSignature) before any crypto check, leaking roster membership and per-member tier — potentially observable as response/timing differences on the HTTPS-SPA endpoint. Does not open the gate.

- **Fix:** Verify the signature before the authorization decision; collapse all pre-acceptance failures into one indistinguishable rejection on the network path.

### F-017 — Registry JSON queries bypass resolve_guard and follow redirects
**LOW · conf 0.50 · ssrf · ghost-proxy-server/src/relay.rs:946**

`get_json` (947) issues `http.get(url).send()` with no `resolve_guard` and the redirect-following client. Base hosts are hard-coded (pypi/npm/crates) so not directly attacker-chosen, but name/version are interpolated into the path and the registries can 3xx-redirect to attacker/internal hosts with no per-hop guard. Compounds F-002/F-004.

- **Fix:** Route `get_json` through the hardened client (per-hop guard, IP pinning); assert the final host is the expected registry domain.

### F-018 — Client-static verification uses non-constant-time comparison
**LOW · conf 0.40 · weak-crypto · ghost-proxy-server/src/noise.rs:179**

`verify_client_noise_static` compares with `remote_static != expected.as_slice()` (179), short-circuiting rather than constant-time. The value is the client's *public* static key recovered from an already-AEAD-authenticated IK message 1, so leakage is limited and the attacker must already be a post-SPA peer. Verification ordering is otherwise correct (runs before message 2, transport mode, and dispatch). Defense-in-depth.

- **Fix:** Use `subtle::ConstantTimeEq` / `constant_time_eq`.

### F-019 — No `--` separator before client URL in git clone (defense-in-depth)
**LOW · conf 0.40 · argument-injection · ghost-proxy-server/src/relay.rs:553**

`git clone --mirror --quiet <url> <mirror>` passes the client URL as a positional arg with no `--` separator (553). Option-smuggling via a leading `-` is currently prevented only by `validate_git_url` requiring an `http/https/git` scheme; any future loosening removes the last line of defense. The bundle command (560-568) also omits `GIT_TERMINAL_PROMPT`/`GIT_ASKPASS`, and neither pins `protocol.allow` / `GIT_CONFIG_NOSYSTEM`. No working exploit today.

- **Fix:** Add `.arg("--")` before the URL; set the git env on the bundle command; consider `GIT_CONFIG_NOSYSTEM=1` + HOME isolation + protocol restrictions.

### F-020 — copy_payload_byte uses wrapping_add for bounds check
**LOW · conf 0.30 · out-of-bounds-read · ghost-proxy-ebpf/src/main.rs:321**

After a `checked_add` chain for `ptr`, the per-byte end check is `let end = ptr.wrapping_add(1); if end <= data_end` (321-322); if `ptr == usize::MAX`, `wrapping_add(1)` yields 0 and passes. Effectively unreachable given real kernel pointer arithmetic plus offsets bounded by `SPA_MIN_LEN`. Flagged only because sibling accessors use `checked_add` + strict `>` (282-288).

- **Fix:** Mirror `read_u8`: `ptr.checked_add(1).ok_or(())?` and strict `>`.
