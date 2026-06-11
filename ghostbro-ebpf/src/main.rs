#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{xdp_action, xdp_md},
    cty::c_void,
    helpers::{bpf_ktime_get_ns, bpf_xdp_load_bytes},
    macros::{map, xdp},
    maps::{Array, LruHashMap, RingBuf},
    programs::XdpContext,
};
use ghostbro_bpf_common::{
    AllowEntry, BpfConfig, RateState, SpaEvent, DEFAULT_PROXY_PORT, DEFAULT_RATE_LIMIT_PER_MINUTE,
    DEFAULT_SPA_PORT, SPA_MAX_LEN, SPA_MIN_LEN, SPA_MODE_UDP,
};

const ETH_HDR_LEN: usize = 14;
const IPV4_MIN_HDR_LEN: usize = 20;
const TCP_MIN_HDR_LEN: usize = 20;
const UDP_HDR_LEN: usize = 8;
const ETHERTYPE_IPV4: u16 = 0x0800;
const IP_PROTO_TCP: u8 = 6;
const IP_PROTO_UDP: u8 = 17;

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

// LRU maps: source IPv4 is attacker-spoofable, so a flood of spoofed sources
// must evict the LRU tail rather than fail inserts or starve real clients.
#[map(name = "ALLOW_MAP")]
static ALLOW_MAP: LruHashMap<u32, AllowEntry> = LruHashMap::with_max_entries(4096, 0);

#[map(name = "RATE_LIMIT")]
static RATE_LIMIT: LruHashMap<u32, RateState> = LruHashMap::with_max_entries(16384, 0);

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
    let ctx_ptr = ctx.ctx;
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
            ctx_ptr,
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
    ctx: *mut xdp_md,
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

    // The SPA payload is sealed (§4.3): there is no cleartext magic or flags to
    // pre-validate. The only kernel-observable pre-filter is the length range,
    // plus the per-IP and global rate limits, before handing candidates to the
    // userspace seal-open / verify path.
    if is_spa_length(payload_len)
        && rate_limit_allows(src_ip, rate_limit_per_minute)
        && global_rate_limit_allows(rate_limit_per_minute)
    {
        emit_spa_event(ctx, payload_offset, payload_len, src_ip, src_port);
    }

    Ok(xdp_action::XDP_DROP)
}

fn is_spa_length(payload_len: usize) -> bool {
    (SPA_MIN_LEN..=SPA_MAX_LEN).contains(&payload_len)
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
    ctx: *mut xdp_md,
    payload_offset: usize,
    payload_len: usize,
    src_ip: u32,
    src_port: u16,
) {
    // Clamp the length into the sealed-SPA window with a verifier-visible bound.
    //
    // The upstream length parse is `udp_len.wrapping_sub(UDP_HDR_LEN)` over a
    // 16-bit field, so the verifier has no usable range for `payload_len`; and
    // because this call is gated on `is_spa_length()`, LLVM "knows" the bound and
    // would delete a plain clamp here. A volatile read is an optimization barrier
    // that forces LLVM to keep the clamp, so `bpf_xdp_load_bytes` gets a length
    // the verifier can prove is non-zero and fits the destination buffer.
    let observed = unsafe { core::ptr::read_volatile(&payload_len) };
    let copy_len = if observed > SPA_MAX_LEN {
        SPA_MAX_LEN
    } else {
        observed
    };
    if copy_len < SPA_MIN_LEN {
        return;
    }
    // copy_len is now provably in SPA_MIN_LEN..=SPA_MAX_LEN.

    let Some(mut reservation) = SPA_RING.reserve::<SpaEvent>(0) else {
        return;
    };

    let event = reservation.as_mut_ptr() as *mut u8;
    write_u32_ne(event, 0, src_ip);
    write_u16_ne(event, 4, src_port);
    write_u16_ne(event, 6, copy_len as u16);

    // Copy the payload with the kernel helper rather than hand-rolled per-byte
    // direct packet access: the payload sits at a *variable* offset (the IPv4
    // IHL is runtime-dependent), and the verifier cannot range-check a direct
    // packet read at a variable offset. The destination is the event's 176-byte
    // payload field at offset 8; copy_len <= SPA_MAX_LEN (176) guarantees it fits.
    let loaded = unsafe {
        bpf_xdp_load_bytes(
            ctx,
            payload_offset as u32,
            event.add(8) as *mut c_void,
            copy_len as u32,
        )
    };
    if loaded != 0 {
        reservation.discard(0);
        return;
    }

    reservation.submit(0);
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
