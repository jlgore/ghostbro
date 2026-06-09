use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{
    SignatureError, SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH,
};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::protocol::KEY_ID_LEN;

pub type KeyId = [u8; KEY_ID_LEN];

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("invalid base64 public key")]
    InvalidBase64(#[from] base64::DecodeError),
    #[error("Ed25519 public key must be 32 bytes, got {0}")]
    InvalidPublicKeyLength(usize),
    #[error("Ed25519 private key must be 32 bytes, got {0}")]
    InvalidPrivateKeyLength(usize),
    #[error("Noise public key must be 32 bytes, got {0}")]
    InvalidNoisePublicKeyLength(usize),
    #[error("invalid Ed25519 public key")]
    InvalidPublicKey(#[from] SignatureError),
}

pub fn generate_ed25519_keypair() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

pub fn key_id_for_public_key(public_key: &VerifyingKey) -> KeyId {
    let digest = Sha256::digest(public_key.as_bytes());
    let mut key_id = [0u8; KEY_ID_LEN];
    key_id.copy_from_slice(&digest[..KEY_ID_LEN]);
    key_id
}

pub fn encode_public_key(public_key: &VerifyingKey) -> String {
    STANDARD.encode(public_key.as_bytes())
}

pub fn encode_signing_key(signing_key: &SigningKey) -> String {
    STANDARD.encode(signing_key.to_bytes())
}

pub fn derive_noise_static_private_key(signing_key: &SigningKey) -> [u8; 32] {
    let digest = Sha256::digest(
        [
            b"ghost-proxy client noise static v1".as_slice(),
            signing_key.to_bytes().as_slice(),
        ]
        .concat(),
    );
    digest.into()
}

pub fn derive_noise_static_public_key(signing_key: &SigningKey) -> [u8; 32] {
    let private = x25519_dalek::StaticSecret::from(derive_noise_static_private_key(signing_key));
    x25519_dalek::PublicKey::from(&private).to_bytes()
}

/// Derive the X25519 public key for a raw 32-byte Noise static private key.
///
/// The server holds its Noise static key as raw private bytes (not an Ed25519
/// identity), so it cannot use [`derive_noise_static_public_key`]. This computes
/// the matching public key so the server can bind its identity into SPA
/// verification.
pub fn derive_noise_public_from_private(private_key: &[u8; 32]) -> [u8; 32] {
    let private = x25519_dalek::StaticSecret::from(*private_key);
    x25519_dalek::PublicKey::from(&private).to_bytes()
}

pub fn encode_noise_public_key(public_key: &[u8; 32]) -> String {
    STANDARD.encode(public_key)
}

pub fn decode_noise_public_key(encoded: &str) -> Result<[u8; 32], KeyError> {
    let bytes = STANDARD.decode(encoded)?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| KeyError::InvalidNoisePublicKeyLength(bytes.len()))
}

pub fn decode_signing_key(encoded: &str) -> Result<SigningKey, KeyError> {
    let bytes = STANDARD.decode(encoded)?;
    let bytes: [u8; SECRET_KEY_LENGTH] = bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| KeyError::InvalidPrivateKeyLength(bytes.len()))?;
    Ok(SigningKey::from_bytes(&bytes))
}

pub fn decode_public_key(encoded: &str) -> Result<VerifyingKey, KeyError> {
    let bytes = STANDARD.decode(encoded)?;
    let bytes: [u8; PUBLIC_KEY_LENGTH] = bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| KeyError::InvalidPublicKeyLength(bytes.len()))?;
    Ok(VerifyingKey::from_bytes(&bytes)?)
}

pub fn key_id_hex(key_id: &KeyId) -> String {
    key_id.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn key_id_from_hex(hex: &str) -> Option<KeyId> {
    if hex.len() != KEY_ID_LEN * 2 {
        return None;
    }

    let mut key_id = [0u8; KEY_ID_LEN];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let chunk = std::str::from_utf8(chunk).ok()?;
        key_id[index] = u8::from_str_radix(chunk, 16).ok()?;
    }
    Some(key_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_key_round_trips_through_base64() {
        let signing_key = generate_ed25519_keypair();
        let public_key = signing_key.verifying_key();

        let encoded = encode_public_key(&public_key);
        let decoded = decode_public_key(&encoded).expect("valid public key");

        assert_eq!(public_key, decoded);
        assert_eq!(44, encoded.len());
    }

    #[test]
    fn signing_key_round_trips_through_base64() {
        let signing_key = generate_ed25519_keypair();

        let encoded = encode_signing_key(&signing_key);
        let decoded = decode_signing_key(&encoded).expect("valid signing key");

        assert_eq!(signing_key.to_bytes(), decoded.to_bytes());
        assert_eq!(44, encoded.len());
    }

    #[test]
    fn derived_noise_static_public_key_is_stable() {
        let signing_key = generate_ed25519_keypair();

        let first = derive_noise_static_public_key(&signing_key);
        let second = derive_noise_static_public_key(&signing_key);

        assert_eq!(first, second);
        assert_eq!(44, encode_noise_public_key(&first).len());
    }
}
