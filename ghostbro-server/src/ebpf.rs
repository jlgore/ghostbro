use std::{
    collections::HashMap,
    env, mem,
    net::Ipv4Addr,
    path::Path,
    sync::mpsc,
    sync::{Arc, RwLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use aya::{
    maps::{Array, HashMap as AyaHashMap, MapData, RingBuf},
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use ghostbro_bpf_common::{AllowEntry, BpfConfig, SpaEvent, SPA_MAX_LEN};
use ghostbro_common::keys::{key_id_hex, KeyId};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};

use crate::keys::AuthorizedKeysFile;
use crate::spa::{SpaAccept, SpaVerifier};

const ALLOW_MAP_REAP_INTERVAL: Duration = Duration::from_secs(60);

pub struct EbpfRuntime {
    _ebpf: Ebpf,
    allow_map: AyaHashMap<MapData, u32, AllowEntry>,
    spa_ring: RingBuf<MapData>,
    allowed_sources: AllowedSources,
}

pub type AllowedSources = Arc<RwLock<HashMap<u32, AllowedSource>>>;

#[derive(Debug, Clone, Copy)]
pub struct AllowedSource {
    pub entry: AllowEntry,
    pub noise_public_key: [u8; 32],
    pub max_concurrent_sessions: Option<u16>,
}

#[derive(Debug)]
pub struct HttpsSpaCandidate {
    pub src_ip: u32,
    pub payload: Vec<u8>,
}

impl EbpfRuntime {
    pub fn load_and_attach(
        object_path: &str,
        iface: &str,
        config: BpfConfig,
        allowed_sources: AllowedSources,
    ) -> Result<Self> {
        let mut ebpf = Ebpf::load_file(object_path)
            .with_context(|| format!("failed to load eBPF object from {object_path}"))?;

        if let Err(error) = aya_log::EbpfLogger::init(&mut ebpf) {
            tracing::debug!(?error, "eBPF logger not initialized");
        }

        let mut config_map = Array::try_from(
            ebpf.map_mut("CONFIG")
                .context("CONFIG map not found in eBPF object")?,
        )
        .context("CONFIG map has unexpected type")?;
        config_map
            .set(0, config, 0)
            .context("failed to write eBPF CONFIG map")?;

        let program: &mut Xdp = ebpf
            .program_mut("ghostbro_xdp")
            .context("ghostbro_xdp program not found in eBPF object")?
            .try_into()
            .context("ghostbro_xdp has unexpected program type")?;
        program.load().context("failed to load XDP program")?;
        program
            .attach(iface, XdpFlags::default())
            .with_context(|| format!("failed to attach XDP program to interface {iface}"))?;

        let allow_map = AyaHashMap::try_from(
            ebpf.take_map("ALLOW_MAP")
                .context("ALLOW_MAP map not found in eBPF object")?,
        )
        .context("ALLOW_MAP has unexpected type")?;

        let spa_ring = RingBuf::try_from(
            ebpf.take_map("SPA_RING")
                .context("SPA_RING map not found in eBPF object")?,
        )
        .context("SPA_RING has unexpected type")?;

        Ok(Self {
            _ebpf: ebpf,
            allow_map,
            spa_ring,
            allowed_sources,
        })
    }

    pub async fn run_spa(
        mut self,
        mut verifier: SpaVerifier,
        allow_ttl_seconds: u64,
        mut https_spa_rx: tokio::sync::mpsc::Receiver<HttpsSpaCandidate>,
        authorized_keys_path: String,
    ) -> Result<()> {
        let (reload_tx, reload_rx) = mpsc::channel();
        let _watcher = if env::var_os("GHOSTBRO_DISABLE_AUTH_WATCH").is_some() {
            tracing::warn!(authorized_keys_path, "AUTHORIZED_KEYS_WATCH_DISABLED");
            None
        } else {
            Some(watch_authorized_keys(&authorized_keys_path, reload_tx)?)
        };
        let mut next_reap = Instant::now() + ALLOW_MAP_REAP_INTERVAL;

        loop {
            let mut processed = 0usize;

            loop {
                let event = {
                    let Some(item) = self.spa_ring.next() else {
                        break;
                    };

                    match parse_spa_event(&item) {
                        Ok(event) => event,
                        Err(error) => {
                            tracing::warn!(
                                ?error,
                                event_len = item.len(),
                                "invalid SPA ring event"
                            );
                            processed += 1;
                            continue;
                        }
                    }
                };

                processed += 1;

                let payload_len = usize::from(event.payload_len);
                if payload_len > SPA_MAX_LEN {
                    tracing::warn!(payload_len, "invalid SPA payload length from ring event");
                    continue;
                }

                let payload = &event.payload[..payload_len];
                match verifier.verify(payload, Ipv4Addr::from(event.src_ip), wall_clock_now_ms()?) {
                    Ok(accept) => {
                        self.allow_source(event.src_ip, &accept, allow_ttl_seconds)?;
                        tracing::info!(
                            key_id = %ghostbro_common::keys::key_id_hex(&accept.key_id),
                            client = %accept.client_name,
                            client_id = accept.client_id,
                            src_ip = %format_ipv4(event.src_ip),
                            src_port = event.src_port,
                            mode = ?accept.mode,
                            counter = accept.counter,
                            "SPA_ACCEPT"
                        );
                    }
                    Err(error) => {
                        tracing::warn!(
                            ?error,
                            src_ip = %format_ipv4(event.src_ip),
                            src_port = event.src_port,
                            "SPA_REJECT"
                        );
                    }
                }
            }

            while let Ok(candidate) = https_spa_rx.try_recv() {
                processed += 1;
                match verifier.verify(
                    &candidate.payload,
                    Ipv4Addr::from(candidate.src_ip),
                    wall_clock_now_ms()?,
                ) {
                    Ok(accept) => {
                        self.allow_source(candidate.src_ip, &accept, allow_ttl_seconds)?;
                        tracing::info!(
                            key_id = %ghostbro_common::keys::key_id_hex(&accept.key_id),
                            client = %accept.client_name,
                            client_id = accept.client_id,
                            src_ip = %format_ipv4(candidate.src_ip),
                            mode = ?accept.mode,
                            counter = accept.counter,
                            "HTTPS_SPA_ACCEPT"
                        );
                    }
                    Err(error) => {
                        tracing::warn!(
                            ?error,
                            src_ip = %format_ipv4(candidate.src_ip),
                            "HTTPS_SPA_REJECT"
                        );
                    }
                }
            }

            while reload_rx.try_recv().is_ok() {
                processed += 1;
                match reload_authorized_keys(&authorized_keys_path, &mut verifier) {
                    Ok(removed_key_ids) => {
                        for key_id in removed_key_ids {
                            self.purge_key_id(&key_id)?;
                        }
                    }
                    Err(error) => tracing::warn!(?error, "failed to hot-reload authorized keys"),
                }
            }

            if Instant::now() >= next_reap {
                processed += 1;
                self.reap_expired_sources()?;
                next_reap = Instant::now() + ALLOW_MAP_REAP_INTERVAL;
            }

            if processed == 0 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }

    fn allow_source(
        &mut self,
        src_ip: u32,
        accept: &SpaAccept,
        allow_ttl_seconds: u64,
    ) -> Result<()> {
        let expiry_ns =
            monotonic_now_ns()?.saturating_add(allow_ttl_seconds.saturating_mul(1_000_000_000));
        let entry = AllowEntry {
            expiry_ns,
            key_id: accept.key_id,
            client_id: accept.client_id,
            _pad: 0,
        };

        self.allow_map
            .insert(src_ip, entry, 0)
            .with_context(|| format!("failed to write ALLOW_MAP for {}", format_ipv4(src_ip)))?;

        self.allowed_sources
            .write()
            .expect("allowed source mirror lock poisoned")
            .insert(
                src_ip,
                AllowedSource {
                    entry,
                    noise_public_key: accept.noise_public_key,
                    max_concurrent_sessions: accept.max_concurrent_sessions,
                },
            );

        tracing::debug!(
            src_ip = %format_ipv4(src_ip),
            client_id = accept.client_id,
            expiry_ns,
            "ALLOW_MAP_WRITE"
        );

        Ok(())
    }

    fn purge_key_id(&mut self, key_id: &KeyId) -> Result<()> {
        let sources_to_purge: Vec<u32> = self
            .allowed_sources
            .read()
            .expect("allowed source mirror lock poisoned")
            .iter()
            .filter_map(|(src_ip, source)| (source.entry.key_id == *key_id).then_some(*src_ip))
            .collect();

        if sources_to_purge.is_empty() {
            return Ok(());
        }

        let mut mirror = self
            .allowed_sources
            .write()
            .expect("allowed source mirror lock poisoned");
        for src_ip in sources_to_purge {
            self.allow_map.remove(&src_ip).with_context(|| {
                format!(
                    "failed to remove ALLOW_MAP entry for {}",
                    format_ipv4(src_ip)
                )
            })?;
            mirror.remove(&src_ip);
            tracing::info!(
                key_id = %key_id_hex(key_id),
                src_ip = %format_ipv4(src_ip),
                "ALLOW_MAP_PURGE_REVOKED_KEY"
            );
        }

        Ok(())
    }

    fn reap_expired_sources(&mut self) -> Result<()> {
        let now_ns = monotonic_now_ns()?;
        let expired_sources = expired_sources(
            &self
                .allowed_sources
                .read()
                .expect("allowed source mirror lock poisoned"),
            now_ns,
        );

        if expired_sources.is_empty() {
            return Ok(());
        }

        let mut mirror = self
            .allowed_sources
            .write()
            .expect("allowed source mirror lock poisoned");
        for src_ip in expired_sources {
            self.allow_map.remove(&src_ip).with_context(|| {
                format!(
                    "failed to remove expired ALLOW_MAP entry for {}",
                    format_ipv4(src_ip)
                )
            })?;
            mirror.remove(&src_ip);
            tracing::info!(src_ip = %format_ipv4(src_ip), "ALLOW_MAP_PURGE_EXPIRED");
        }

        Ok(())
    }
}

fn expired_sources(sources: &HashMap<u32, AllowedSource>, now_ns: u64) -> Vec<u32> {
    sources
        .iter()
        .filter_map(|(src_ip, source)| (source.entry.expiry_ns <= now_ns).then_some(*src_ip))
        .collect()
}

fn watch_authorized_keys(
    authorized_keys_path: &str,
    reload_tx: mpsc::Sender<()>,
) -> Result<RecommendedWatcher> {
    let path = Path::new(authorized_keys_path).to_path_buf();
    let watch_path = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| path.clone());
    let event_path = path.clone();
    let mut watcher = RecommendedWatcher::new(
        move |event: notify::Result<notify::Event>| match event {
            Ok(event) if event.paths.iter().any(|path| path == &event_path) => {
                let _ = reload_tx.send(());
            }
            Ok(_) => {}
            Err(error) => tracing::warn!(?error, "authorized keys watch error"),
        },
        notify::Config::default(),
    )
    .context("failed to create authorized keys watcher")?;
    watcher
        .watch(&watch_path, RecursiveMode::NonRecursive)
        .with_context(|| format!("failed to watch {}", watch_path.display()))?;
    Ok(watcher)
}

fn reload_authorized_keys(
    authorized_keys_path: &str,
    verifier: &mut SpaVerifier,
) -> Result<Vec<KeyId>> {
    let authorized_keys = AuthorizedKeysFile::load(authorized_keys_path)?;
    let clients = authorized_keys.into_clients()?;
    let removed = verifier.reload_clients(clients);
    tracing::info!(
        removed_keys = removed.len(),
        authorized_keys_path,
        "AUTHORIZED_KEYS_RELOADED"
    );
    Ok(removed)
}

fn parse_spa_event(bytes: &[u8]) -> Result<SpaEvent> {
    if bytes.len() != mem::size_of::<SpaEvent>() {
        bail!(
            "SPA ring event size mismatch: expected {}, got {}",
            mem::size_of::<SpaEvent>(),
            bytes.len()
        );
    }

    Ok(unsafe { (bytes.as_ptr() as *const SpaEvent).read_unaligned() })
}

fn wall_clock_now_ms() -> Result<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?;
    Ok(duration.as_millis().try_into().unwrap_or(u64::MAX))
}

pub(crate) fn monotonic_now_ns() -> Result<u64> {
    let mut timespec = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut timespec) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .context("clock_gettime(CLOCK_MONOTONIC) failed");
    }

    let sec =
        u64::try_from(timespec.tv_sec).context("monotonic clock returned negative seconds")?;
    let nsec =
        u64::try_from(timespec.tv_nsec).context("monotonic clock returned negative nanoseconds")?;
    Ok(sec.saturating_mul(1_000_000_000).saturating_add(nsec))
}

pub(crate) fn format_ipv4(ip: u32) -> String {
    let octets = ip.to_be_bytes();
    format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_spa_event_bytes() {
        let event = SpaEvent {
            src_ip: u32::from_be_bytes([127, 0, 0, 1]),
            src_port: 12345,
            payload_len: 3,
            payload: {
                let mut payload = [0u8; SPA_MAX_LEN];
                payload[..3].copy_from_slice(&[1, 2, 3]);
                payload
            },
        };
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&event as *const SpaEvent).cast::<u8>(),
                mem::size_of::<SpaEvent>(),
            )
        };

        let parsed = parse_spa_event(bytes).expect("event parses");

        assert_eq!(event, parsed);
    }

    #[test]
    fn rejects_wrong_spa_event_size() {
        assert!(parse_spa_event(&[0u8; 4]).is_err());
    }

    #[test]
    fn formats_ipv4_address() {
        assert_eq!("127.0.0.1", format_ipv4(u32::from_be_bytes([127, 0, 0, 1])));
    }

    #[test]
    fn selects_expired_sources_for_reaping() {
        let expired = u32::from_be_bytes([10, 0, 0, 1]);
        let active = u32::from_be_bytes([10, 0, 0, 2]);
        let mut sources = HashMap::new();
        sources.insert(
            expired,
            AllowedSource {
                entry: AllowEntry {
                    expiry_ns: 99,
                    key_id: [1u8; 8],
                    client_id: 1,
                    _pad: 0,
                },
                noise_public_key: [1u8; 32],
                max_concurrent_sessions: None,
            },
        );
        sources.insert(
            active,
            AllowedSource {
                entry: AllowEntry {
                    expiry_ns: 101,
                    key_id: [2u8; 8],
                    client_id: 2,
                    _pad: 0,
                },
                noise_public_key: [2u8; 32],
                max_concurrent_sessions: None,
            },
        );

        assert_eq!(vec![expired], expired_sources(&sources, 100));
    }
}
