pub const VERSION_PREFIX: [u8; 2] = [0x47, 0x50];
pub const VERSION_LEN: usize = 2;
pub const SPA_FLAGS_LEN: usize = 1;
pub const KEY_ID_LEN: usize = 8;
pub const TIMESTAMP_LEN: usize = 8;
pub const COUNTER_LEN: usize = 8;
pub const NONCE_LEN: usize = 16;
pub const SIGNATURE_LEN: usize = 64;

pub const SPA_SIGNED_LEN: usize =
    VERSION_LEN + SPA_FLAGS_LEN + KEY_ID_LEN + TIMESTAMP_LEN + COUNTER_LEN + NONCE_LEN;
pub const SPA_MIN_LEN: usize = SPA_SIGNED_LEN + SIGNATURE_LEN;
pub const SPA_MAX_LEN: usize = 128;

pub const SPA_FLAG_HTTPS: u8 = 0b0000_0001;
pub const SPA_RESERVED_FLAGS: u8 = !SPA_FLAG_HTTPS;

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
