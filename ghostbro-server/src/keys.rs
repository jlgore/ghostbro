use serde::Deserialize;
use std::{fs, path::Path};

use ghostbro_common::{
    keys::{decode_noise_public_key, decode_public_key, key_id_for_public_key, KeyError, KeyId},
    protocol::KEY_ID_LEN,
};

#[derive(Debug, Deserialize)]
pub struct AuthorizedKeysFile {
    pub clients: Vec<AuthorizedClientConfig>,
}

#[derive(Debug, Deserialize)]
pub struct AuthorizedClientConfig {
    pub name: String,
    pub public_key: String,
    pub noise_public_key: String,
    pub tier: ClientTier,
    pub max_concurrent_sessions: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientTier {
    Full,
    Decoy,
}

#[derive(Debug, Clone)]
pub struct AuthorizedClient {
    pub name: String,
    pub public_key: ed25519_dalek::VerifyingKey,
    pub noise_public_key: [u8; 32],
    pub key_id: KeyId,
    pub client_id: u16,
    pub tier: ClientTier,
    pub max_concurrent_sessions: Option<u16>,
}

impl AuthorizedKeysFile {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let contents = fs::read_to_string(path)
            .map_err(|error| anyhow::anyhow!("failed to read {}: {error}", path.display()))?;
        toml::from_str(&contents)
            .map_err(|error| anyhow::anyhow!("failed to parse {}: {error}", path.display()))
    }

    pub fn into_clients(self) -> Result<Vec<AuthorizedClient>, KeyError> {
        self.clients
            .into_iter()
            .enumerate()
            .map(|(index, config)| AuthorizedClient::from_config(config, index_to_client_id(index)))
            .collect()
    }
}

impl AuthorizedClient {
    fn from_config(config: AuthorizedClientConfig, client_id: u16) -> Result<Self, KeyError> {
        let public_key = decode_public_key(&config.public_key)?;
        let noise_public_key = decode_noise_public_key(&config.noise_public_key)?;
        let key_id = key_id_for_public_key(&public_key);

        Ok(Self {
            name: config.name,
            public_key,
            noise_public_key,
            key_id,
            client_id,
            tier: config.tier,
            max_concurrent_sessions: config.max_concurrent_sessions,
        })
    }
}

fn index_to_client_id(index: usize) -> u16 {
    u16::try_from(index + 1).unwrap_or(u16::MAX)
}

#[cfg(test)]
mod tests {
    use ghostbro_common::keys::{
        derive_noise_static_public_key, encode_noise_public_key, encode_public_key,
        generate_ed25519_keypair,
    };

    use super::*;

    #[test]
    fn assigns_client_ids_from_file_order() {
        let first = generate_ed25519_keypair();
        let second = generate_ed25519_keypair();
        let toml = format!(
            r#"
            [[clients]]
            name = "first"
            public_key = "{}"
            noise_public_key = "{}"
            tier = "full"

            [[clients]]
            name = "second"
            public_key = "{}"
            noise_public_key = "{}"
            tier = "decoy"
            max_concurrent_sessions = 2
            "#,
            encode_public_key(&first.verifying_key()),
            encode_noise_public_key(&derive_noise_static_public_key(&first)),
            encode_public_key(&second.verifying_key()),
            encode_noise_public_key(&derive_noise_static_public_key(&second))
        );

        let keys: AuthorizedKeysFile = toml::from_str(&toml).expect("valid keys file");
        let clients = keys.into_clients().expect("valid clients");

        assert_eq!(1, clients[0].client_id);
        assert_eq!("first", clients[0].name);
        assert_eq!(ClientTier::Full, clients[0].tier);
        assert_eq!(2, clients[1].client_id);
        assert_eq!("second", clients[1].name);
        assert_eq!(ClientTier::Decoy, clients[1].tier);
        assert_eq!(Some(2), clients[1].max_concurrent_sessions);
    }
}

pub fn key_id_from_slice(bytes: &[u8]) -> Option<KeyId> {
    if bytes.len() != KEY_ID_LEN {
        return None;
    }

    let mut key_id = [0u8; KEY_ID_LEN];
    key_id.copy_from_slice(bytes);
    Some(key_id)
}
