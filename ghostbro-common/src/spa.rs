use std::net::Ipv4Addr;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    keys::{key_id_for_public_key, KeyId},
    protocol::{
        ALLOW_IP_LEN, COUNTER_LEN, KEY_ID_LEN, SIGNATURE_LEN, SPA_EPHEMERAL_LEN, SPA_FLAG_HTTPS,
        SPA_FLAG_USE_PACKET_SOURCE, SPA_INNER_LEN, SPA_INNER_SIGNED_LEN, SPA_MAX_LEN,
        SPA_MAX_PADDING, SPA_MIN_LEN, SPA_RESERVED_FLAGS, SPA_SEALED_CORE_LEN, TIMESTAMP_LEN,
        VERSION_PREFIX,
    },
    seal,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpaMode {
    Udp,
    Https,
}

impl SpaMode {
    fn flag_bit(self) -> u8 {
        match self {
            Self::Udp => 0,
            Self::Https => SPA_FLAG_HTTPS,
        }
    }

    fn from_flags(flags: u8) -> Self {
        if flags & SPA_FLAG_HTTPS == 0 {
            Self::Udp
        } else {
            Self::Https
        }
    }
}

/// Which source address a SPA authorizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpaAllowIp {
    /// Authorize this explicit IPv4 address; the server rejects the packet if the
    /// observed source IP differs. Defeats on-path authorization theft (§4.6).
    Explicit(Ipv4Addr),
    /// CGNAT escape hatch: authorize whatever source the server observes. The
    /// `allow_ip` field is ignored and the on-path replay binding is forgone.
    PacketSource,
}

impl SpaAllowIp {
    fn flag_bit(self) -> u8 {
        match self {
            Self::Explicit(_) => 0,
            Self::PacketSource => SPA_FLAG_USE_PACKET_SOURCE,
        }
    }

    fn ip_bytes(self) -> [u8; ALLOW_IP_LEN] {
        match self {
            Self::Explicit(ip) => ip.octets(),
            Self::PacketSource => [0u8; ALLOW_IP_LEN],
        }
    }
}

/// A parsed SPA inner record (post-decryption), plus the ephemeral public key
/// recovered from the sealed wire (needed to verify the inner signature).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaPacket {
    pub mode: SpaMode,
    pub use_packet_source: bool,
    pub key_id: KeyId,
    pub timestamp_ms: u64,
    pub counter: u64,
    pub allow_ip: Ipv4Addr,
    pub signature: [u8; SIGNATURE_LEN],
    pub ephemeral_pub: [u8; SPA_EPHEMERAL_LEN],
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SpaError {
    #[error("SPA payload length must be {SPA_MIN_LEN}..={SPA_MAX_LEN} bytes, got {0}")]
    InvalidLength(usize),
    #[error("SPA seal could not be opened (not sealed to this server, or tampered)")]
    SealOpenFailed,
    #[error("invalid SPA version prefix")]
    InvalidVersion,
    #[error("invalid SPA flags: 0x{0:02x}")]
    InvalidFlags(u8),
    #[error("SPA signature verification failed")]
    BadSignature,
}

impl SpaPacket {
    /// Build a sealed SPA wire payload: seal the signed inner record to the
    /// server's static X25519 public key and append random length-jitter padding.
    pub fn build(
        signing_key: &SigningKey,
        mode: SpaMode,
        timestamp_ms: u64,
        counter: u64,
        allow_ip: SpaAllowIp,
        server_static_pubkey: &[u8; 32],
    ) -> Vec<u8> {
        let mut padding = vec![0u8; random_padding_len()];
        OsRng.fill_bytes(&mut padding);
        Self::build_with_padding(
            signing_key,
            mode,
            timestamp_ms,
            counter,
            allow_ip,
            &padding,
            server_static_pubkey,
        )
    }

    /// Same as [`build`], with caller-supplied padding (deterministic length for
    /// tests). The ephemeral seal key is always random.
    pub fn build_with_padding(
        signing_key: &SigningKey,
        mode: SpaMode,
        timestamp_ms: u64,
        counter: u64,
        allow_ip: SpaAllowIp,
        padding: &[u8],
        server_static_pubkey: &[u8; 32],
    ) -> Vec<u8> {
        let public_key = signing_key.verifying_key();
        let key_id = key_id_for_public_key(&public_key);
        let flags = mode.flag_bit() | allow_ip.flag_bit();

        // Build the signed region (everything except the signature).
        let mut signed_region = Vec::with_capacity(SPA_INNER_SIGNED_LEN);
        signed_region.extend_from_slice(&VERSION_PREFIX);
        signed_region.push(flags);
        signed_region.extend_from_slice(&key_id);
        signed_region.extend_from_slice(&timestamp_ms.to_be_bytes());
        signed_region.extend_from_slice(&counter.to_be_bytes());
        signed_region.extend_from_slice(&allow_ip.ip_bytes());

        // Mint the ephemeral first so the signature can commit to it, then seal
        // the inner record under that same ephemeral.
        let ephemeral_secret = seal::generate_ephemeral();
        let ephemeral_pub = seal::ephemeral_public(&ephemeral_secret);

        let signature = signing_key.sign(&signed_message(
            &signed_region,
            &ephemeral_pub,
            server_static_pubkey,
        ));

        let mut inner = Vec::with_capacity(SPA_INNER_LEN);
        inner.extend_from_slice(&signed_region);
        inner.extend_from_slice(&signature.to_bytes());

        let mut wire =
            seal::seal_with_ephemeral(&inner, server_static_pubkey, &ephemeral_secret);
        wire.extend_from_slice(padding);
        wire
    }

    /// Open a sealed SPA wire payload with the server's static private key and
    /// parse the inner record. Does **not** verify the signature — call
    /// [`verify`] after looking up the client key by `key_id`.
    pub fn open(wire: &[u8], server_static_private: &[u8; 32]) -> Result<Self, SpaError> {
        if !(SPA_MIN_LEN..=SPA_MAX_LEN).contains(&wire.len()) {
            return Err(SpaError::InvalidLength(wire.len()));
        }
        // Strip length-jitter padding: the sealed core is a fixed size.
        let sealed_core = &wire[..SPA_SEALED_CORE_LEN];
        let opened = seal::open(sealed_core, server_static_private).ok_or(SpaError::SealOpenFailed)?;
        if opened.plaintext.len() != SPA_INNER_LEN {
            return Err(SpaError::SealOpenFailed);
        }

        let inner = &opened.plaintext;
        if inner[0..2] != VERSION_PREFIX {
            return Err(SpaError::InvalidVersion);
        }
        let flags = inner[2];
        if flags & SPA_RESERVED_FLAGS != 0 {
            return Err(SpaError::InvalidFlags(flags));
        }

        let mut offset = 3;
        let key_id = read_array::<KEY_ID_LEN>(inner, &mut offset);
        let timestamp_ms = u64::from_be_bytes(read_array::<TIMESTAMP_LEN>(inner, &mut offset));
        let counter = u64::from_be_bytes(read_array::<COUNTER_LEN>(inner, &mut offset));
        let allow_ip = Ipv4Addr::from(read_array::<ALLOW_IP_LEN>(inner, &mut offset));
        let signature = read_array::<SIGNATURE_LEN>(inner, &mut offset);

        Ok(Self {
            mode: SpaMode::from_flags(flags),
            use_packet_source: flags & SPA_FLAG_USE_PACKET_SOURCE != 0,
            key_id,
            timestamp_ms,
            counter,
            allow_ip,
            signature,
            ephemeral_pub: opened.ephemeral_pub,
        })
    }

    /// Verify the inner Ed25519 signature (binding the ephemeral key and the
    /// server static key). Call after [`open`] and a `key_id` lookup.
    pub fn verify(
        &self,
        verifying_key: &VerifyingKey,
        server_static_pubkey: &[u8; 32],
    ) -> Result<(), SpaError> {
        let mut signed_region = Vec::with_capacity(SPA_INNER_SIGNED_LEN);
        signed_region.extend_from_slice(&VERSION_PREFIX);
        signed_region.push(self.flags_byte());
        signed_region.extend_from_slice(&self.key_id);
        signed_region.extend_from_slice(&self.timestamp_ms.to_be_bytes());
        signed_region.extend_from_slice(&self.counter.to_be_bytes());
        signed_region.extend_from_slice(&self.allow_ip.octets());

        let signature = Signature::from_bytes(&self.signature);
        verifying_key
            .verify(
                &signed_message(&signed_region, &self.ephemeral_pub, server_static_pubkey),
                &signature,
            )
            .map_err(|_| SpaError::BadSignature)
    }

    fn flags_byte(&self) -> u8 {
        self.mode.flag_bit()
            | if self.use_packet_source {
                SPA_FLAG_USE_PACKET_SOURCE
            } else {
                0
            }
    }
}

/// The Ed25519-signed message: the inner signed region, the per-packet ephemeral
/// public key, and the destination server's static public key (authenticated,
/// not transmitted). Binding the ephemeral prevents re-wrapping a captured seal;
/// binding the server key prevents cross-server / failover replay.
fn signed_message(
    signed_region: &[u8],
    ephemeral_pub: &[u8; 32],
    server_static_pubkey: &[u8; 32],
) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(signed_region.len() + ephemeral_pub.len() + server_static_pubkey.len());
    message.extend_from_slice(signed_region);
    message.extend_from_slice(ephemeral_pub);
    message.extend_from_slice(server_static_pubkey);
    message
}

fn read_array<const N: usize>(buf: &[u8], offset: &mut usize) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&buf[*offset..*offset + N]);
    *offset += N;
    out
}

fn random_padding_len() -> usize {
    (OsRng.next_u32() as usize) % (SPA_MAX_PADDING + 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_ed25519_keypair;
    use crate::seal::x25519_public_from_private;

    const SERVER_PRIV_A: [u8; 32] = [0xAu8; 32];
    const SERVER_PRIV_B: [u8; 32] = [0xBu8; 32];

    fn server_pub(private: &[u8; 32]) -> [u8; 32] {
        x25519_public_from_private(private)
    }

    #[test]
    fn builds_opens_and_verifies_udp_packet() {
        let signing_key = generate_ed25519_keypair();
        let server_public = server_pub(&SERVER_PRIV_A);
        let wire = SpaPacket::build(
            &signing_key,
            SpaMode::Udp,
            1_725_000_000_000,
            42,
            SpaAllowIp::Explicit(Ipv4Addr::new(203, 0, 113, 7)),
            &server_public,
        );
        assert!((SPA_MIN_LEN..=SPA_MAX_LEN).contains(&wire.len()));

        let packet = SpaPacket::open(&wire, &SERVER_PRIV_A).expect("opens");
        assert_eq!(SpaMode::Udp, packet.mode);
        assert_eq!(42, packet.counter);
        assert_eq!(1_725_000_000_000, packet.timestamp_ms);
        assert_eq!(Ipv4Addr::new(203, 0, 113, 7), packet.allow_ip);
        assert!(!packet.use_packet_source);
        packet
            .verify(&signing_key.verifying_key(), &server_public)
            .expect("signature verifies");
    }

    #[test]
    fn packet_source_flag_roundtrips() {
        let signing_key = generate_ed25519_keypair();
        let server_public = server_pub(&SERVER_PRIV_A);
        let wire = SpaPacket::build(
            &signing_key,
            SpaMode::Https,
            1_000,
            5,
            SpaAllowIp::PacketSource,
            &server_public,
        );
        let packet = SpaPacket::open(&wire, &SERVER_PRIV_A).expect("opens");
        assert!(packet.use_packet_source);
        assert_eq!(SpaMode::Https, packet.mode);
        packet
            .verify(&signing_key.verifying_key(), &server_public)
            .expect("verifies");
    }

    #[test]
    fn packet_built_for_one_server_does_not_open_on_another() {
        // Sealed to server A: server B cannot even open it (AEAD fails).
        let signing_key = generate_ed25519_keypair();
        let wire = SpaPacket::build(
            &signing_key,
            SpaMode::Udp,
            1_725_000_000_000,
            42,
            SpaAllowIp::PacketSource,
            &server_pub(&SERVER_PRIV_A),
        );

        assert_eq!(
            Err(SpaError::SealOpenFailed),
            SpaPacket::open(&wire, &SERVER_PRIV_B)
        );
    }

    #[test]
    fn signature_rejects_wrong_server_binding() {
        // Even if a packet opens, the signature binds the server key, so verify
        // against a different server public key must fail.
        let signing_key = generate_ed25519_keypair();
        let server_public = server_pub(&SERVER_PRIV_A);
        let wire = SpaPacket::build(
            &signing_key,
            SpaMode::Udp,
            1_725_000_000_000,
            42,
            SpaAllowIp::PacketSource,
            &server_public,
        );
        let packet = SpaPacket::open(&wire, &SERVER_PRIV_A).expect("opens");

        assert_eq!(
            Err(SpaError::BadSignature),
            packet.verify(&signing_key.verifying_key(), &server_pub(&SERVER_PRIV_B))
        );
    }

    #[test]
    fn rejects_wrong_signer() {
        let signing_key = generate_ed25519_keypair();
        let attacker = generate_ed25519_keypair();
        let server_public = server_pub(&SERVER_PRIV_A);
        let wire = SpaPacket::build(
            &signing_key,
            SpaMode::Udp,
            1_000,
            1,
            SpaAllowIp::PacketSource,
            &server_public,
        );
        let packet = SpaPacket::open(&wire, &SERVER_PRIV_A).expect("opens");

        assert_eq!(
            Err(SpaError::BadSignature),
            packet.verify(&attacker.verifying_key(), &server_public)
        );
    }
}
