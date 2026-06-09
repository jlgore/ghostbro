use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::Context;
use ghost_proxy_common::{
    keys::{key_id_from_hex, key_id_hex, KeyId},
    spa::{SpaError, SpaMode, SpaPacket},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::keys::{AuthorizedClient, ClientTier};

#[derive(Debug)]
pub struct SpaVerifier {
    clients: HashMap<KeyId, AuthorizedClient>,
    highest_counters: HashMap<KeyId, u64>,
    time_window_ms: u64,
    counter_state_path: Option<PathBuf>,
    server_static_pubkey: [u8; 32],
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct CounterStateFile {
    counters: HashMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaAccept {
    pub key_id: KeyId,
    pub client_id: u16,
    pub client_name: String,
    pub noise_public_key: [u8; 32],
    pub mode: SpaMode,
    pub counter: u64,
}

#[derive(Debug, Error)]
pub enum SpaVerifyError {
    #[error("SPA parse failed: {0}")]
    Parse(#[from] SpaError),
    #[error("unknown key_id: {0}")]
    UnknownKey(String),
    #[error("client is not authorized for proxy access: {0}")]
    UnauthorizedTier(String),
    #[error("timestamp outside configured window")]
    TimestampOutsideWindow,
    #[error("replayed or stale counter")]
    ReplayedCounter,
    #[error("failed to persist SPA counter state: {0}")]
    Persist(#[source] anyhow::Error),
}

impl SpaVerifier {
    pub fn new(
        clients: Vec<AuthorizedClient>,
        time_window_seconds: u64,
        server_static_pubkey: [u8; 32],
    ) -> Self {
        Self::from_counters(
            clients,
            time_window_seconds,
            HashMap::new(),
            None,
            server_static_pubkey,
        )
    }

    /// Load a verifier, restoring persisted replay counters from
    /// `counter_state_path`.
    ///
    /// A missing counter-state file is treated as a hard error (fail closed)
    /// unless `allow_missing_state` is set, because losing the file silently
    /// resets every per-key counter to zero and lets previously captured SPA
    /// packets replay. `allow_missing_state` is the operator-controlled
    /// first-run / provisioning opt-in.
    pub fn load(
        clients: Vec<AuthorizedClient>,
        time_window_seconds: u64,
        counter_state_path: impl AsRef<Path>,
        server_static_pubkey: [u8; 32],
        allow_missing_state: bool,
    ) -> anyhow::Result<Self> {
        let path = counter_state_path.as_ref().to_path_buf();
        let highest_counters = load_counter_state(&path, allow_missing_state)?;
        Ok(Self::from_counters(
            clients,
            time_window_seconds,
            highest_counters,
            Some(path),
            server_static_pubkey,
        ))
    }

    fn from_counters(
        clients: Vec<AuthorizedClient>,
        time_window_seconds: u64,
        highest_counters: HashMap<KeyId, u64>,
        counter_state_path: Option<PathBuf>,
        server_static_pubkey: [u8; 32],
    ) -> Self {
        let clients = clients
            .into_iter()
            .map(|client| (client.key_id, client))
            .collect();

        Self {
            clients,
            highest_counters,
            time_window_ms: time_window_seconds.saturating_mul(1_000),
            counter_state_path,
            server_static_pubkey,
        }
    }

    pub fn reload_clients(&mut self, clients: Vec<AuthorizedClient>) -> Vec<KeyId> {
        let old_key_ids: Vec<KeyId> = self.clients.keys().copied().collect();
        self.clients = clients
            .into_iter()
            .map(|client| (client.key_id, client))
            .collect();

        old_key_ids
            .into_iter()
            .filter(|key_id| !self.clients.contains_key(key_id))
            .collect()
    }

    pub fn verify(&mut self, payload: &[u8], now_ms: u64) -> Result<SpaAccept, SpaVerifyError> {
        let packet = SpaPacket::parse(payload)?;
        let Some(client) = self.clients.get(&packet.key_id) else {
            return Err(SpaVerifyError::UnknownKey(key_id_hex(&packet.key_id)));
        };

        // Verify the signature before any authorization decision so the tier
        // branch (and its distinguishable error) is unreachable without a valid
        // signature — closes the unauthenticated key/tier enumeration oracle.
        packet.verify(payload, &client.public_key, &self.server_static_pubkey)?;

        if client.tier != ClientTier::Full {
            return Err(SpaVerifyError::UnauthorizedTier(client.name.clone()));
        }

        let drift = now_ms.abs_diff(packet.timestamp_ms);
        if drift > self.time_window_ms {
            return Err(SpaVerifyError::TimestampOutsideWindow);
        }

        let highest_counter = self
            .highest_counters
            .get(&packet.key_id)
            .copied()
            .unwrap_or_default();
        if packet.counter <= highest_counter {
            return Err(SpaVerifyError::ReplayedCounter);
        }

        self.highest_counters.insert(packet.key_id, packet.counter);
        self.persist_counters()?;

        Ok(SpaAccept {
            key_id: packet.key_id,
            client_id: client.client_id,
            client_name: client.name.clone(),
            noise_public_key: client.noise_public_key,
            mode: packet.mode,
            counter: packet.counter,
        })
    }

    fn persist_counters(&self) -> Result<(), SpaVerifyError> {
        let Some(path) = &self.counter_state_path else {
            return Ok(());
        };

        save_counter_state(path, &self.highest_counters).map_err(SpaVerifyError::Persist)
    }
}

fn load_counter_state(
    path: &Path,
    allow_missing_state: bool,
) -> anyhow::Result<HashMap<KeyId, u64>> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if allow_missing_state {
                return Ok(HashMap::new());
            }
            return Err(anyhow::anyhow!(
                "SPA counter-state file {} is missing; refusing to start with reset replay \
                 counters. Set GHOST_PROXY_SPA_COUNTER_INIT=1 for an explicit first-run init.",
                path.display()
            ));
        }
        Err(error) => return Err(Into::into(error)),
    };

    let state: CounterStateFile = toml::from_str(&contents)
        .map_err(|error| anyhow::anyhow!("failed to parse {}: {error}", path.display()))?;
    let mut counters = HashMap::new();
    for (key_id, counter) in state.counters {
        counters.insert(
            key_id_from_hex(&key_id)
                .ok_or_else(|| anyhow::anyhow!("invalid key_id in {}: {key_id}", path.display()))?,
            counter,
        );
    }
    Ok(counters)
}

fn save_counter_state(path: &Path, counters: &HashMap<KeyId, u64>) -> anyhow::Result<()> {
    let state = CounterStateFile {
        counters: counters
            .iter()
            .map(|(key_id, counter)| (key_id_hex(key_id), *counter))
            .collect(),
    };
    let contents =
        toml::to_string_pretty(&state).context("failed to serialize SPA counter state")?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| anyhow::anyhow!("failed to create {}: {error}", parent.display()))?;
    }

    let temp_path = path.with_extension("tmp");
    fs::write(&temp_path, contents)
        .map_err(|error| anyhow::anyhow!("failed to write {}: {error}", temp_path.display()))?;
    fs::rename(&temp_path, path).map_err(|error| {
        anyhow::anyhow!(
            "failed to rename {} to {}: {error}",
            temp_path.display(),
            path.display()
        )
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use ghost_proxy_common::{
        keys::{derive_noise_static_public_key, generate_ed25519_keypair},
        spa::SpaPacket,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    const TEST_SERVER_PUBKEY: [u8; 32] = [0x5au8; 32];

    fn client_from_key(name: &str, signing_key: &SigningKey) -> AuthorizedClient {
        let public_key = signing_key.verifying_key();
        let key_id = ghost_proxy_common::keys::key_id_for_public_key(&public_key);

        AuthorizedClient {
            name: name.to_owned(),
            public_key,
            noise_public_key: derive_noise_static_public_key(signing_key),
            key_id,
            client_id: 1,
            tier: ClientTier::Full,
            max_concurrent_sessions: None,
        }
    }

    #[test]
    fn accepts_valid_spa_once() {
        let signing_key = generate_ed25519_keypair();
        let client = client_from_key("jared-laptop", &signing_key);
        let mut verifier = SpaVerifier::new(vec![client], 300, TEST_SERVER_PUBKEY);
        let payload =
            SpaPacket::build(&signing_key, SpaMode::Udp, 1_000_000, 1, &TEST_SERVER_PUBKEY);

        let accepted = verifier.verify(&payload, 1_000_001).expect("accepted");

        assert_eq!("jared-laptop", accepted.client_name);
        assert_eq!(SpaMode::Udp, accepted.mode);
        assert_eq!(1, accepted.counter);
    }

    #[test]
    fn rejects_replayed_counter() {
        let signing_key = generate_ed25519_keypair();
        let client = client_from_key("friend-phone", &signing_key);
        let mut verifier = SpaVerifier::new(vec![client], 300, TEST_SERVER_PUBKEY);
        let payload =
            SpaPacket::build(&signing_key, SpaMode::Https, 1_000_000, 1, &TEST_SERVER_PUBKEY);

        verifier.verify(&payload, 1_000_001).expect("first use");

        assert!(matches!(
            verifier.verify(&payload, 1_000_002),
            Err(SpaVerifyError::ReplayedCounter)
        ));
    }

    #[test]
    fn rejects_timestamp_outside_window() {
        let signing_key = generate_ed25519_keypair();
        let client = client_from_key("friend-phone", &signing_key);
        let mut verifier = SpaVerifier::new(vec![client], 300, TEST_SERVER_PUBKEY);
        let payload =
            SpaPacket::build(&signing_key, SpaMode::Https, 1_000_000, 1, &TEST_SERVER_PUBKEY);

        assert!(matches!(
            verifier.verify(&payload, 1_301_000),
            Err(SpaVerifyError::TimestampOutsideWindow)
        ));
    }

    #[test]
    fn load_errors_on_missing_state_without_init() {
        // F-007: a missing counter-state file must fail closed (no silent reset).
        let signing_key = generate_ed25519_keypair();
        let client = client_from_key("friend-phone", &signing_key);
        let state_path = temp_counter_state_path();

        let result =
            SpaVerifier::load(vec![client], 300, &state_path, TEST_SERVER_PUBKEY, false);

        assert!(
            result.is_err(),
            "missing counter-state file must fail closed without the init opt-in"
        );
        assert!(!state_path.exists());
    }

    #[test]
    fn persists_counter_state_across_verifier_reload() {
        let signing_key = generate_ed25519_keypair();
        let client = client_from_key("friend-phone", &signing_key);
        let state_path = temp_counter_state_path();
        let payload =
            SpaPacket::build(&signing_key, SpaMode::Udp, 1_000_000, 7, &TEST_SERVER_PUBKEY);

        let mut verifier =
            SpaVerifier::load(vec![client.clone()], 300, &state_path, TEST_SERVER_PUBKEY, true)
                .expect("verifier loads missing state on explicit init");
        verifier.verify(&payload, 1_000_001).expect("accepted");

        let mut reloaded =
            SpaVerifier::load(vec![client], 300, &state_path, TEST_SERVER_PUBKEY, false)
                .expect("verifier loads persisted state");
        assert!(matches!(
            reloaded.verify(&payload, 1_000_002),
            Err(SpaVerifyError::ReplayedCounter)
        ));

        let _ = fs::remove_file(state_path);
    }

    #[test]
    fn tier_check_is_gated_behind_valid_signature() {
        // F-016: a decoy-tier client with a *valid* signature is rejected as
        // UnauthorizedTier (tier is reachable only after the signature passes).
        let decoy_key = generate_ed25519_keypair();
        let mut decoy = client_from_key("decoy-client", &decoy_key);
        decoy.tier = ClientTier::Decoy;
        let mut verifier = SpaVerifier::new(vec![decoy], 300, TEST_SERVER_PUBKEY);
        let payload =
            SpaPacket::build(&decoy_key, SpaMode::Udp, 1_000_000, 1, &TEST_SERVER_PUBKEY);

        assert!(matches!(
            verifier.verify(&payload, 1_000_001),
            Err(SpaVerifyError::UnauthorizedTier(_))
        ));

        // A full-tier client whose packet carries a signature from a *different*
        // key must fail signature verification before the tier branch.
        let full_key = generate_ed25519_keypair();
        let wrong_key = generate_ed25519_keypair();
        let full = client_from_key("full-client", &full_key);
        let mut verifier = SpaVerifier::new(vec![full], 300, TEST_SERVER_PUBKEY);
        let mut forged =
            SpaPacket::build(&wrong_key, SpaMode::Udp, 1_000_000, 1, &TEST_SERVER_PUBKEY);
        let legit =
            SpaPacket::build(&full_key, SpaMode::Udp, 1_000_000, 1, &TEST_SERVER_PUBKEY);
        let key_id_len = full_key.verifying_key().to_bytes().len().min(8);
        // key_id sits at offset 3 in the packet (version(2) + flags(1)).
        let key_id_offset = 3;
        forged[key_id_offset..key_id_offset + key_id_len]
            .copy_from_slice(&legit[key_id_offset..key_id_offset + key_id_len]);

        assert!(matches!(
            verifier.verify(&forged, 1_000_001),
            Err(SpaVerifyError::Parse(SpaError::BadSignature))
        ));
    }

    #[test]
    fn reload_clients_reports_removed_keys() {
        let first_key = generate_ed25519_keypair();
        let second_key = generate_ed25519_keypair();
        let first = client_from_key("first", &first_key);
        let second = client_from_key("second", &second_key);
        let first_key_id = first.key_id;

        let mut verifier =
            SpaVerifier::new(vec![first, second.clone()], 300, TEST_SERVER_PUBKEY);
        let removed = verifier.reload_clients(vec![second]);

        assert_eq!(vec![first_key_id], removed);
    }

    fn temp_counter_state_path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "ghost-proxy-spa-counters-{}.toml",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ))
    }
}
