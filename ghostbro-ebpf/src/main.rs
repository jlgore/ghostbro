#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::{Array, HashMap, RingBuf},
    programs::XdpContext,
};
use ghostbro_bpf_common::{
    AllowEntry, BpfConfig, RateState, SpaEvent, DEFAULT_PROXY_PORT, DEFAULT_RATE_LIMIT_PER_MINUTE,
    DEFAULT_SPA_PORT, SPA_MAX_LEN, SPA_MIN_LEN, SPA_MODE_UDP, SPA_RESERVED_FLAGS,
    SPA_VERSION_PREFIX,
};

const ETH_HDR_LEN: usize = 14;
const IPV4_MIN_HDR_LEN: usize = 20;
const TCP_MIN_HDR_LEN: usize = 20;
const UDP_HDR_LEN: usize = 8;
const ETHERTYPE_IPV4: u16 = 0x0800;
const IP_PROTO_TCP: u8 = 6;
const IP_PROTO_UDP: u8 = 17;

macro_rules! copy_payload_bytes {
    ($data:expr, $data_end:expr, $payload_offset:expr, $payload_len:expr, $event:expr; $($index:expr),* $(,)?) => {
        $(copy_payload_byte::<$index>($data, $data_end, $payload_offset, $payload_len, $event);)*
    };
}

const CONFIG_INDEX: u32 = 0;
const RATE_REFILL_NS: u64 = 60_000_000_000;
// Single-slot index for the global SPA admission bucket.
const GLOBAL_RATE_INDEX: u32 = 0;
// The global bucket admits this many times the per-IP limit per refill window.
// This bounds the total candidates pushed to SPA_RING regardless of how many
// distinct (spoofable) source IPs an attacker cycles through, while leaving
// generous headroom for legitimate clients arriving from many IPs.
const GLOBAL_RATE_MULTIPLIER: u32 = 256;
// Absolute ceiling for the global budget (overflow / pathological-config guard).
const GLOBAL_RATE_MAX: u32 = 1_000_000;

#[map(name = "CONFIG")]
static CONFIG: Array<BpfConfig> = Array::with_max_entries(1, 0);

#[map(name = "ALLOW_MAP")]
static ALLOW_MAP: HashMap<u32, AllowEntry> = HashMap::with_max_entries(4096, 0);

#[map(name = "RATE_LIMIT")]
static RATE_LIMIT: HashMap<u32, RateState> = HashMap::with_max_entries(16384, 0);

#[map(name = "GLOBAL_RATE")]
static GLOBAL_RATE: Array<RateState> = Array::with_max_entries(1, 0);

#[map(name = "SPA_RING")]
static SPA_RING: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

#[xdp]
pub fn ghostbro_xdp(ctx: XdpContext) -> u32 {
    match try_ghostbro_xdp(ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_ghostbro_xdp(ctx: XdpContext) -> Result<u32, ()> {
    let data = ctx.data() as usize;
    let data_end = ctx.data_end() as usize;
    let config = load_config();

    let ethertype = read_be_u16(data, data_end, 12)?;
    if ethertype != ETHERTYPE_IPV4 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ipv4_offset = ETH_HDR_LEN;
    if !has_bytes(data, data_end, ipv4_offset, IPV4_MIN_HDR_LEN) {
        return Ok(xdp_action::XDP_PASS);
    }

    let vihl = read_u8(data, data_end, ipv4_offset)?;
    let ihl = ((vihl & 0x0f) as usize).wrapping_mul(4);
    if ihl < IPV4_MIN_HDR_LEN {
        return Ok(xdp_action::XDP_PASS);
    }
    let proto = read_u8(data, data_end, ipv4_offset.checked_add(9).ok_or(())?)?;
    let src_ip = read_be_u32(data, data_end, ipv4_offset.checked_add(12).ok_or(())?)?;

    let transport_offset = ipv4_offset.checked_add(ihl).ok_or(())?;
    match proto {
        IP_PROTO_TCP => handle_tcp(data, data_end, transport_offset, src_ip, config.proxy_port),
        IP_PROTO_UDP if config.spa_mode & SPA_MODE_UDP != 0 => handle_udp(
            data,
            data_end,
            transport_offset,
            src_ip,
            config.spa_port,
            config.rate_limit_per_minute,
        ),
        _ => Ok(xdp_action::XDP_PASS),
    }
}

fn handle_tcp(
    data: usize,
    data_end: usize,
    transport_offset: usize,
    src_ip: u32,
    proxy_port: u16,
) -> Result<u32, ()> {
    if !has_bytes(data, data_end, transport_offset, TCP_MIN_HDR_LEN) {
        return Ok(xdp_action::XDP_PASS);
    }
    let dst_port = read_be_u16(data, data_end, transport_offset.checked_add(2).ok_or(())?)?;
    if dst_port != proxy_port {
        return Ok(xdp_action::XDP_PASS);
    }

    if is_allowed(src_ip) {
        Ok(xdp_action::XDP_PASS)
    } else {
        Ok(xdp_action::XDP_DROP)
    }
}

fn handle_udp(
    data: usize,
    data_end: usize,
    transport_offset: usize,
    src_ip: u32,
    spa_port: u16,
    rate_limit_per_minute: u32,
) -> Result<u32, ()> {
    if !has_bytes(data, data_end, transport_offset, UDP_HDR_LEN) {
        return Ok(xdp_action::XDP_PASS);
    }
    let dst_port = read_be_u16(data, data_end, transport_offset.checked_add(2).ok_or(())?)?;
    if dst_port != spa_port {
        return Ok(xdp_action::XDP_PASS);
    }

    let src_port = read_be_u16(data, data_end, transport_offset)?;
    let udp_len = read_be_u16(data, data_end, transport_offset.checked_add(4).ok_or(())?)? as usize;
    if udp_len < UDP_HDR_LEN {
        return Ok(xdp_action::XDP_DROP);
    }

    let payload_offset = transport_offset.checked_add(UDP_HDR_LEN).ok_or(())?;
    let payload_len = udp_len.wrapping_sub(UDP_HDR_LEN);
    if !has_bytes(data, data_end, payload_offset, payload_len) {
        return Ok(xdp_action::XDP_DROP);
    }

    if is_structural_spa(data, data_end, payload_offset, payload_len)?
        && rate_limit_allows(src_ip, rate_limit_per_minute)
        && global_rate_limit_allows(rate_limit_per_minute)
    {
        emit_spa_event(
            data,
            data_end,
            payload_offset,
            payload_len,
            src_ip,
            src_port,
        )?;
    }

    Ok(xdp_action::XDP_DROP)
}

fn is_structural_spa(
    data: usize,
    data_end: usize,
    payload_offset: usize,
    payload_len: usize,
) -> Result<bool, ()> {
    if !(SPA_MIN_LEN..=SPA_MAX_LEN).contains(&payload_len) {
        return Ok(false);
    }

    let version_0 = read_u8(data, data_end, payload_offset)?;
    let version_1 = read_u8(data, data_end, payload_offset.checked_add(1).ok_or(())?)?;
    let flags = read_u8(data, data_end, payload_offset.checked_add(2).ok_or(())?)?;

    Ok(version_0 == SPA_VERSION_PREFIX[0]
        && version_1 == SPA_VERSION_PREFIX[1]
        && flags & SPA_RESERVED_FLAGS == 0)
}

fn is_allowed(src_ip: u32) -> bool {
    let Some(entry) = (unsafe { ALLOW_MAP.get(&src_ip) }) else {
        return false;
    };

    let now = unsafe { bpf_ktime_get_ns() };
    if entry.expiry_ns <= now {
        let _ = ALLOW_MAP.remove(&src_ip);
        return false;
    }

    true
}

fn rate_limit_allows(src_ip: u32, configured_limit: u32) -> bool {
    let limit = if configured_limit == 0 {
        DEFAULT_RATE_LIMIT_PER_MINUTE
    } else {
        configured_limit
    };
    let now = unsafe { bpf_ktime_get_ns() };

    let mut state = unsafe { RATE_LIMIT.get(&src_ip).copied() }.unwrap_or(RateState {
        tokens: limit,
        last_ns: now,
    });

    if now.saturating_sub(state.last_ns) >= RATE_REFILL_NS {
        state.tokens = limit;
        state.last_ns = now;
    }

    if state.tokens == 0 {
        let _ = RATE_LIMIT.insert(&src_ip, &state, 0);
        return false;
    }

    state.tokens -= 1;
    let _ = RATE_LIMIT.insert(&src_ip, &state, 0);
    true
}

/// Global SPA admission budget shared across all source IPs.
///
/// The per-IP bucket in `rate_limit_allows` is keyed on the attacker-controlled
/// IPv4 source address, so spoofing a fresh IP per packet yields a fresh full
/// bucket every time. This single global token bucket caps the aggregate number
/// of candidates that reach `emit_spa_event` (and thus the userspace Ed25519
/// verifier) per refill window, regardless of src_ip diversity.
fn global_rate_limit_allows(configured_limit: u32) -> bool {
    let per_ip_limit = if configured_limit == 0 {
        DEFAULT_RATE_LIMIT_PER_MINUTE
    } else {
        configured_limit
    };
    let limit = per_ip_limit
        .saturating_mul(GLOBAL_RATE_MULTIPLIER)
        .min(GLOBAL_RATE_MAX);

    let now = unsafe { bpf_ktime_get_ns() };

    let Some(state_ptr) = GLOBAL_RATE.get_ptr_mut(GLOBAL_RATE_INDEX) else {
        // Map slot unavailable: fail closed so spoofing cannot bypass the gate.
        return false;
    };
    // Single-element Array: this pointer is to the in-map value, so updates
    // through it persist without an explicit insert.
    let state = unsafe { &mut *state_ptr };

    // Array entries are zero-initialized by the kernel; treat last_ns == 0 as an
    // uninitialized bucket and seed it to a full budget for the current window.
    if state.last_ns == 0 || now.saturating_sub(state.last_ns) >= RATE_REFILL_NS {
        state.tokens = limit;
        state.last_ns = now;
    }

    if state.tokens == 0 {
        return false;
    }

    state.tokens = state.tokens.saturating_sub(1);
    true
}

fn emit_spa_event(
    data: usize,
    data_end: usize,
    payload_offset: usize,
    payload_len: usize,
    src_ip: u32,
    src_port: u16,
) -> Result<(), ()> {
    if !(SPA_MIN_LEN..=SPA_MAX_LEN).contains(&payload_len) {
        return Ok(());
    }

    // Reflect the real payload length in the event, clamped to the buffer size.
    // The range check above already bounds this to SPA_MIN_LEN..=SPA_MAX_LEN; the
    // min() is defensive so the writer can never advertise more than fits.
    let payload_len = if payload_len > SPA_MAX_LEN {
        SPA_MAX_LEN
    } else {
        payload_len
    };

    let Some(mut reservation) = SPA_RING.reserve::<SpaEvent>(0) else {
        return Ok(());
    };

    let event = reservation.as_mut_ptr() as *mut u8;
    write_u32_ne(event, 0, src_ip);
    write_u16_ne(event, 4, src_port);
    write_u16_ne(event, 6, payload_len as u16);

    // Enumerate the full SPA_MAX_LEN window: copy_payload_byte writes 0 for any
    // INDEX >= payload_len, so this copies exactly payload_len bytes and zeroes
    // the remainder of the fixed-size event buffer (no uninitialized tail).
    copy_payload_bytes!(
        data, data_end, payload_offset, payload_len, event;
        0, 1, 2, 3, 4, 5, 6, 7,
        8, 9, 10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23,
        24, 25, 26, 27, 28, 29, 30, 31,
        32, 33, 34, 35, 36, 37, 38, 39,
        40, 41, 42, 43, 44, 45, 46, 47,
        48, 49, 50, 51, 52, 53, 54, 55,
        56, 57, 58, 59, 60, 61, 62, 63,
        64, 65, 66, 67, 68, 69, 70, 71,
        72, 73, 74, 75, 76, 77, 78, 79,
        80, 81, 82, 83, 84, 85, 86, 87,
        88, 89, 90, 91, 92, 93, 94, 95,
        96, 97, 98, 99, 100, 101, 102, 103,
        104, 105, 106, 107, 108, 109, 110, 111,
        112, 113, 114, 115, 116, 117, 118, 119,
        120, 121, 122, 123, 124, 125, 126, 127,
    );

    reservation.submit(0);
    Ok(())
}

fn load_config() -> BpfConfig {
    CONFIG.get(CONFIG_INDEX).copied().unwrap_or(BpfConfig {
        spa_port: DEFAULT_SPA_PORT,
        proxy_port: DEFAULT_PROXY_PORT,
        rate_limit_per_minute: DEFAULT_RATE_LIMIT_PER_MINUTE,
        spa_mode: SPA_MODE_UDP,
    })
}

#[inline(always)]
fn has_bytes(data: usize, data_end: usize, offset: usize, len: usize) -> bool {
    let end = data
        .checked_add(offset)
        .and_then(|start| start.checked_add(len))
        .unwrap_or(usize::MAX);
    end <= data_end
}

#[inline(always)]
fn read_u8(data: usize, data_end: usize, offset: usize) -> Result<u8, ()> {
    let ptr = data.checked_add(offset).ok_or(())?;
    let end = ptr.checked_add(1).ok_or(())?;
    if end > data_end {
        return Err(());
    }

    Ok(unsafe { *(ptr as *const u8) })
}

#[inline(always)]
fn read_be_u16(data: usize, data_end: usize, offset: usize) -> Result<u16, ()> {
    let high = read_u8(data, data_end, offset)? as u16;
    let low = read_u8(data, data_end, offset.checked_add(1).ok_or(())?)? as u16;
    Ok((high << 8) | low)
}

#[inline(always)]
fn read_be_u32(data: usize, data_end: usize, offset: usize) -> Result<u32, ()> {
    let b0 = read_u8(data, data_end, offset)? as u32;
    let b1 = read_u8(data, data_end, offset.checked_add(1).ok_or(())?)? as u32;
    let b2 = read_u8(data, data_end, offset.checked_add(2).ok_or(())?)? as u32;
    let b3 = read_u8(data, data_end, offset.checked_add(3).ok_or(())?)? as u32;
    Ok((b0 << 24) | (b1 << 16) | (b2 << 8) | b3)
}

#[inline(always)]
fn copy_payload_byte<const INDEX: usize>(
    data: usize,
    data_end: usize,
    payload_offset: usize,
    payload_len: usize,
    event: *mut u8,
) {
    let mut value = 0;
    if payload_len > INDEX {
        if let Some(ptr) = payload_offset
            .checked_add(INDEX)
            .and_then(|offset| data.checked_add(offset))
        {
            if let Some(end) = ptr.checked_add(1) {
                if end <= data_end {
                    value = unsafe { *(ptr as *const u8) };
                }
            }
        }
    }
    write_u8(event, 8usize.wrapping_add(INDEX), value);
}

#[inline(always)]
fn write_u8(dst: *mut u8, offset: usize, value: u8) {
    unsafe { core::ptr::write(dst.wrapping_add(offset), value) };
}

#[inline(always)]
fn write_u16_ne(dst: *mut u8, offset: usize, value: u16) {
    let bytes = value.to_ne_bytes();
    write_u8(dst, offset, bytes[0]);
    write_u8(dst, offset.wrapping_add(1), bytes[1]);
}

#[inline(always)]
fn write_u32_ne(dst: *mut u8, offset: usize, value: u32) {
    let bytes = value.to_ne_bytes();
    write_u8(dst, offset, bytes[0]);
    write_u8(dst, offset.wrapping_add(1), bytes[1]);
    write_u8(dst, offset.wrapping_add(2), bytes[2]);
    write_u8(dst, offset.wrapping_add(3), bytes[3]);
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
