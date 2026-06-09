//! Startup privilege reporting (PRD §13.4 server hardening).
//!
//! Ghost Proxy's eBPF loader needs `CAP_BPF` + `CAP_NET_ADMIN` (and
//! `CAP_NET_BIND_SERVICE` to bind the builtin decoy on :443). The recommended
//! deployment runs the daemon as an **unprivileged user** with exactly those
//! ambient capabilities via the systemd unit in `deploy/ghost-proxy.service`,
//! rather than as root.
//!
//! This module deliberately does **not** perform an in-process root→user drop.
//! Linux capabilities are per-thread, and this is a multithreaded tokio process
//! whose allow-map writes happen on worker threads; a correct `setuid` drop
//! would have to re-apply `CAP_BPF` to every tokio worker (and would silently
//! break map writes on kernels with `unprivileged_bpf_disabled=1`). Privilege
//! scoping is therefore delegated to systemd (`User=` + `AmbientCapabilities=`),
//! which grants the caps to all threads from process start. Here we only surface
//! the actual runtime privilege level so a misconfigured (e.g. full-root)
//! deployment is obvious in the logs.

use std::fs;

/// Capabilities relevant to Ghost Proxy, with their Linux capability numbers.
const KNOWN_CAPS: &[(u8, &str)] = &[
    (10, "CAP_NET_BIND_SERVICE"),
    (12, "CAP_NET_ADMIN"),
    (13, "CAP_NET_RAW"),
    (21, "CAP_SYS_ADMIN"),
    (38, "CAP_PERFMON"),
    (39, "CAP_BPF"),
];

/// The capabilities Ghost Proxy actually needs at runtime.
const REQUIRED_CAPS: &[&str] = &["CAP_BPF", "CAP_NET_ADMIN"];

#[derive(Debug, PartialEq, Eq)]
pub struct PrivilegeStatus {
    pub uid: u32,
    pub gid: u32,
    pub effective_caps: Vec<&'static str>,
    pub is_root: bool,
}

/// Read the current process uid/gid and effective capability set.
pub fn report() -> PrivilegeStatus {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    let effective_caps = read_effective_caps().map(decode_caps).unwrap_or_default();
    PrivilegeStatus {
        uid,
        gid,
        effective_caps,
        is_root: uid == 0,
    }
}

/// Log the process privilege level at startup and warn on insecure deployments.
pub fn log_startup_privileges() {
    let status = report();
    tracing::info!(
        uid = status.uid,
        gid = status.gid,
        effective_caps = ?status.effective_caps,
        "SERVER_PRIVILEGE_LEVEL"
    );

    if status.is_root {
        tracing::warn!(
            "running as root (uid 0); for production run unprivileged via \
             deploy/ghost-proxy.service (User= + AmbientCapabilities=CAP_BPF \
             CAP_NET_ADMIN CAP_NET_BIND_SERVICE) so only the eBPF loader holds capabilities"
        );
    } else {
        let missing: Vec<&str> = REQUIRED_CAPS
            .iter()
            .copied()
            .filter(|cap| !status.effective_caps.contains(cap))
            .collect();
        if !missing.is_empty() {
            tracing::warn!(
                ?missing,
                "running unprivileged without all required capabilities; eBPF load and \
                 allow-map writes may fail. Grant them via AmbientCapabilities in the systemd unit"
            );
        }
    }
}

fn read_effective_caps() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    parse_cap_eff(&status)
}

/// Parse the `CapEff:` hex bitmask line out of `/proc/<pid>/status`.
fn parse_cap_eff(status: &str) -> Option<u64> {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("CapEff:") {
            return u64::from_str_radix(rest.trim(), 16).ok();
        }
    }
    None
}

/// Decode a capability bitmask into the names of the capabilities we track.
fn decode_caps(mask: u64) -> Vec<&'static str> {
    KNOWN_CAPS
        .iter()
        .filter(|(bit, _)| mask & (1u64 << bit) != 0)
        .map(|(_, name)| *name)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cap_eff_line() {
        let status = "Name:\tghost\nUid:\t0\t0\t0\t0\nCapEff:\t000001ffffffffff\nGid:\t0\n";
        assert_eq!(Some(0x0000_01ff_ffff_ffff), parse_cap_eff(status));
    }

    #[test]
    fn missing_cap_eff_returns_none() {
        assert_eq!(None, parse_cap_eff("Name:\tghost\nUid:\t0\n"));
    }

    #[test]
    fn decodes_only_known_capabilities() {
        // CAP_NET_ADMIN (12) + CAP_BPF (39) set.
        let mask = (1u64 << 12) | (1u64 << 39);
        assert_eq!(vec!["CAP_NET_ADMIN", "CAP_BPF"], decode_caps(mask));
    }

    #[test]
    fn decodes_empty_mask() {
        assert!(decode_caps(0).is_empty());
    }
}
