#![no_std]

pub const KEY_ID_LEN: usize = 8;
pub const SPA_MAX_LEN: usize = 128;
pub const SPA_MIN_LEN: usize = 107;
pub const SPA_VERSION_PREFIX: [u8; 2] = [0x47, 0x50];
pub const SPA_FLAG_HTTPS: u8 = 0b0000_0001;
pub const SPA_RESERVED_FLAGS: u8 = !SPA_FLAG_HTTPS;

pub const DEFAULT_SPA_PORT: u16 = 53;
pub const DEFAULT_PROXY_PORT: u16 = 8443;
pub const DEFAULT_RATE_LIMIT_PER_MINUTE: u32 = 5;
pub const SPA_MODE_UDP: u32 = 1;
pub const SPA_MODE_HTTPS: u32 = 2;
pub const SPA_MODE_BOTH: u32 = SPA_MODE_UDP | SPA_MODE_HTTPS;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BpfConfig {
    pub spa_port: u16,
    pub proxy_port: u16,
    pub rate_limit_per_minute: u32,
    pub spa_mode: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AllowEntry {
    pub expiry_ns: u64,
    pub key_id: [u8; KEY_ID_LEN],
    pub client_id: u16,
    pub _pad: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RateState {
    pub tokens: u32,
    pub last_ns: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpaEvent {
    pub src_ip: u32,
    pub src_port: u16,
    pub payload_len: u16,
    pub payload: [u8; SPA_MAX_LEN],
}

impl Default for SpaEvent {
    fn default() -> Self {
        Self {
            src_ip: 0,
            src_port: 0,
            payload_len: 0,
            payload: [0; SPA_MAX_LEN],
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BpfConfig {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for AllowEntry {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RateState {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SpaEvent {}
