use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    keys::{key_id_for_public_key, KeyId},
    protocol::{
        COUNTER_LEN, KEY_ID_LEN, NONCE_LEN, SIGNATURE_LEN, SPA_FLAG_HTTPS, SPA_MAX_LEN,
        SPA_MIN_LEN, SPA_RESERVED_FLAGS, SPA_SIGNED_LEN, TIMESTAMP_LEN, VERSION_PREFIX,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpaMode {
    Udp,
    Https,
}

impl SpaMode {
    pub fn flags(self) -> u8 {
        match self {
            Self::Udp => 0,
            Self::Https => SPA_FLAG_HTTPS,
        }
    }

    pub fn from_flags(flags: u8) -> Result<Self, SpaError> {
        if flags & SPA_RESERVED_FLAGS != 0 {
            return Err(SpaError::InvalidFlags(flags));
        }

        Ok(if flags & SPA_FLAG_HTTPS == 0 {
            Self::Udp
        } else {
            Self::Https
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaPacket {
    pub mode: SpaMode,
    pub key_id: KeyId,
    pub timestamp_ms: u64,
    pub counter: u64,
    pub nonce: [u8; NONCE_LEN],
    pub signature: [u8; SIGNATURE_LEN],
    pub padding: Vec<u8>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SpaError {
    #[error("SPA payload length must be 107..=128 bytes, got {0}")]
    InvalidLength(usize),
    #[error("invalid SPA version prefix")]
    InvalidVersion,
    #[error("invalid SPA flags: 0x{0:02x}")]
    InvalidFlags(u8),
    #[error("SPA signature verification failed")]
    BadSignature,
    #[error("padding length must keep packet within 107..=128 bytes")]
    InvalidPaddingLength,
}

impl SpaPacket {
    pub fn build(
        signing_key: &SigningKey,
        mode: SpaMode,
        timestamp_ms: u64,
        counter: u64,
        server_static_pubkey: &[u8; 32],
    ) -> Vec<u8> {
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);

        let padding_len = random_padding_len();
        let mut padding = vec![0u8; padding_len];
        OsRng.fill_bytes(&mut padding);

        Self::build_with_padding(
            signing_key,
            mode,
            timestamp_ms,
            counter,
            nonce,
            &padding,
            server_static_pubkey,
        )
        .expect("random padding length is valid")
    }

    pub fn build_with_padding(
        signing_key: &SigningKey,
        mode: SpaMode,
        timestamp_ms: u64,
        counter: u64,
        nonce: [u8; NONCE_LEN],
        padding: &[u8],
        server_static_pubkey: &[u8; 32],
    ) -> Result<Vec<u8>, SpaError> {
        if SPA_MIN_LEN + padding.len() > SPA_MAX_LEN {
            return Err(SpaError::InvalidPaddingLength);
        }

        let public_key = signing_key.verifying_key();
        let key_id = key_id_for_public_key(&public_key);

        let mut packet = Vec::with_capacity(SPA_MIN_LEN + padding.len());
        packet.extend_from_slice(&VERSION_PREFIX);
        packet.push(mode.flags());
        packet.extend_from_slice(&key_id);
        packet.extend_from_slice(&timestamp_ms.to_be_bytes());
        packet.extend_from_slice(&counter.to_be_bytes());
        packet.extend_from_slice(&nonce);

        // Bind the destination server's Noise static public key into the
        // signature without transmitting it: it is authenticated associated
        // data, not part of the 107..=128-byte on-wire payload. This prevents a
        // SPA accepted by one server from verifying on another (cross-server
        // replay / failover replay).
        let signature = signing_key.sign(&signed_message(&packet, server_static_pubkey));
        packet.extend_from_slice(&signature.to_bytes());
        packet.extend_from_slice(padding);

        Ok(packet)
    }

    pub fn parse(payload: &[u8]) -> Result<Self, SpaError> {
        if !(SPA_MIN_LEN..=SPA_MAX_LEN).contains(&payload.len()) {
            return Err(SpaError::InvalidLength(payload.len()));
        }
        if payload[0..2] != VERSION_PREFIX {
            return Err(SpaError::InvalidVersion);
        }

        let mode = SpaMode::from_flags(payload[2])?;
        let mut offset = 3;

        let key_id = read_array::<KEY_ID_LEN>(payload, &mut offset);
        let timestamp_ms = u64::from_be_bytes(read_array::<TIMESTAMP_LEN>(payload, &mut offset));
        let counter = u64::from_be_bytes(read_array::<COUNTER_LEN>(payload, &mut offset));
        let nonce = read_array::<NONCE_LEN>(payload, &mut offset);
        let signature = read_array::<SIGNATURE_LEN>(payload, &mut offset);
        let padding = payload[offset..].to_vec();

        Ok(Self {
            mode,
            key_id,
            timestamp_ms,
            counter,
            nonce,
            signature,
            padding,
        })
    }

    pub fn verify(
        &self,
        payload: &[u8],
        verifying_key: &VerifyingKey,
        server_static_pubkey: &[u8; 32],
    ) -> Result<(), SpaError> {
        if payload.len() < SPA_MIN_LEN || payload.len() > SPA_MAX_LEN {
            return Err(SpaError::InvalidLength(payload.len()));
        }

        let signature = Signature::from_bytes(&self.signature);
        verifying_key
            .verify(
                &signed_message(&payload[..SPA_SIGNED_LEN], server_static_pubkey),
                &signature,
            )
            .map_err(|_| SpaError::BadSignature)
    }
}

/// The Ed25519-signed message: the on-wire signed region followed by the
/// destination server's Noise static public key (authenticated, not transmitted).
fn signed_message(signed_region: &[u8], server_static_pubkey: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(signed_region.len() + server_static_pubkey.len());
    message.extend_from_slice(signed_region);
    message.extend_from_slice(server_static_pubkey);
    message
}

fn read_array<const N: usize>(payload: &[u8], offset: &mut usize) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&payload[*offset..*offset + N]);
    *offset += N;
    out
}

fn random_padding_len() -> usize {
    (OsRng.next_u32() as usize) % (SPA_MAX_LEN - SPA_MIN_LEN + 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_ed25519_keypair;

    const SERVER_PUBKEY_A: [u8; 32] = [0xAu8; 32];
    const SERVER_PUBKEY_B: [u8; 32] = [0xBu8; 32];

    #[test]
    fn builds_parses_and_verifies_udp_packet() {
        let signing_key = generate_ed25519_keypair();
        let payload = SpaPacket::build_with_padding(
            &signing_key,
            SpaMode::Udp,
            1_725_000_000_000,
            42,
            [7u8; NONCE_LEN],
            &[1, 2, 3],
            &SERVER_PUBKEY_A,
        )
        .expect("valid packet");

        let packet = SpaPacket::parse(&payload).expect("parsed packet");

        assert_eq!(SpaMode::Udp, packet.mode);
        assert_eq!(42, packet.counter);
        assert_eq!(1_725_000_000_000, packet.timestamp_ms);
        assert_eq!([7u8; NONCE_LEN], packet.nonce);
        assert_eq!(vec![1, 2, 3], packet.padding);
        packet
            .verify(&payload, &signing_key.verifying_key(), &SERVER_PUBKEY_A)
            .expect("signature verifies");
    }

    #[test]
    fn rejects_packet_built_for_different_server() {
        // A SPA built to open server A's gate must NOT verify against server B's
        // identity — this defeats cross-server / failover replay (F-003).
        let signing_key = generate_ed25519_keypair();
        let payload = SpaPacket::build(
            &signing_key,
            SpaMode::Udp,
            1_725_000_000_000,
            42,
            &SERVER_PUBKEY_A,
        );

        let packet = SpaPacket::parse(&payload).expect("structurally valid packet");

        packet
            .verify(&payload, &signing_key.verifying_key(), &SERVER_PUBKEY_A)
            .expect("verifies for the server it was built for");

        assert_eq!(
            Err(SpaError::BadSignature),
            packet.verify(&payload, &signing_key.verifying_key(), &SERVER_PUBKEY_B)
        );
    }

    #[test]
    fn detects_signature_tampering() {
        let signing_key = generate_ed25519_keypair();
        let mut payload = SpaPacket::build(
            &signing_key,
            SpaMode::Https,
            1_725_000_000_000,
            42,
            &SERVER_PUBKEY_A,
        );
        payload[20] ^= 0xff;

        let packet = SpaPacket::parse(&payload).expect("structurally valid packet");

        assert_eq!(
            Err(SpaError::BadSignature),
            packet.verify(&payload, &signing_key.verifying_key(), &SERVER_PUBKEY_A)
        );
    }

    #[test]
    fn rejects_reserved_flags() {
        let signing_key = generate_ed25519_keypair();
        let mut payload = SpaPacket::build(
            &signing_key,
            SpaMode::Udp,
            1_725_000_000_000,
            42,
            &SERVER_PUBKEY_A,
        );
        payload[2] = 0b0000_0010;

        assert_eq!(Err(SpaError::InvalidFlags(2)), SpaPacket::parse(&payload));
    }
}
