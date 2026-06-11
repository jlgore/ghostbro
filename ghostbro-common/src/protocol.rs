pub const VERSION_PREFIX: [u8; 2] = [0x47, 0x50];
pub const VERSION_LEN: usize = 2;
pub const SPA_FLAGS_LEN: usize = 1;
pub const KEY_ID_LEN: usize = 8;
pub const TIMESTAMP_LEN: usize = 8;
pub const COUNTER_LEN: usize = 8;
pub const ALLOW_IP_LEN: usize = 4;
pub const SIGNATURE_LEN: usize = 64;

// --- Sealed SPA inner record (the plaintext that is sealed to the server) ---
//
// Layout: version | flags | key_id | timestamp_ms | counter | allow_ip | signature
// The signature (Ed25519) covers the signed region plus the per-packet ephemeral
// public key and the server static public key (associated data, not transmitted).
pub const SPA_INNER_SIGNED_LEN: usize =
    VERSION_LEN + SPA_FLAGS_LEN + KEY_ID_LEN + TIMESTAMP_LEN + COUNTER_LEN + ALLOW_IP_LEN;
pub const SPA_INNER_LEN: usize = SPA_INNER_SIGNED_LEN + SIGNATURE_LEN;

// --- Sealed SPA on-wire layout ---
//
// ephemeral X25519 public key | AEAD ciphertext (== SPA_INNER_LEN) | Poly1305 tag | padding
pub const SPA_EPHEMERAL_LEN: usize = 32;
pub const SPA_AEAD_TAG_LEN: usize = 16;
/// Fixed-size sealed core, before any length-jitter padding.
pub const SPA_SEALED_CORE_LEN: usize = SPA_EPHEMERAL_LEN + SPA_INNER_LEN + SPA_AEAD_TAG_LEN;

/// Minimum on-wire SPA length (sealed core, no padding).
pub const SPA_MIN_LEN: usize = SPA_SEALED_CORE_LEN;
/// Maximum on-wire SPA length (sealed core + max padding).
pub const SPA_MAX_LEN: usize = 176;
/// Maximum random padding appended after the sealed core for length jitter.
pub const SPA_MAX_PADDING: usize = SPA_MAX_LEN - SPA_MIN_LEN;

// spa_flags bits (inside the sealed inner record):
//   bit 0: transport mode (0 = UDP, 1 = HTTPS)
//   bit 1: source-IP mode (0 = honor signed allow_ip, 1 = use observed packet source)
pub const SPA_FLAG_HTTPS: u8 = 0b0000_0001;
pub const SPA_FLAG_USE_PACKET_SOURCE: u8 = 0b0000_0010;
pub const SPA_RESERVED_FLAGS: u8 = !(SPA_FLAG_HTTPS | SPA_FLAG_USE_PACKET_SOURCE);

pub const PROTOCOL_SOCKS5: u8 = 0x05;
pub const PROTOCOL_GHOST_RELAY: u8 = 0x47;
pub const GHOST_RELAY_VERSION: u8 = 1;
pub const GHOST_RELAY_OP_SUBMIT_WEB: u8 = 1;
pub const GHOST_RELAY_OP_LIST: u8 = 2;
pub const GHOST_RELAY_OP_DOWNLOAD: u8 = 3;
pub const GHOST_RELAY_OP_DELETE: u8 = 4;
pub const GHOST_RELAY_OP_SUBMIT_GIT: u8 = 5;
pub const GHOST_RELAY_OP_SUBMIT_PACKAGE: u8 = 6;
pub const GHOST_RELAY_STATUS_OK: u8 = 0;
/// Job accepted and queued, but its result is not yet available.
pub const GHOST_RELAY_STATUS_PENDING: u8 = 1;
pub const GHOST_RELAY_STATUS_NOT_FOUND: u8 = 2;
pub const GHOST_RELAY_STATUS_INVALID: u8 = 3;
pub const GHOST_RELAY_STATUS_FAILED: u8 = 4;
pub const GHOST_RELAY_STATUS_TOO_LARGE: u8 = 5;
/// Per-client storage or job-count quota would be exceeded.
pub const GHOST_RELAY_STATUS_QUOTA: u8 = 6;
pub const GHOST_RELAY_STATUS_UNSUPPORTED: u8 = 0x7f;

/// Download artifact selectors (trailing byte of a DOWNLOAD request).
pub const GHOST_RELAY_ARTIFACT_PRIMARY: u8 = 0;
pub const GHOST_RELAY_ARTIFACT_NORMALIZED: u8 = 1;
pub const DEFAULT_ALLOW_TTL_SECONDS: u64 = 14_400;
pub const DEFAULT_TIME_WINDOW_SECONDS: u64 = 300;
