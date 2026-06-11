//! Anonymous sealed-box construction for SPA payloads.
//!
//! The SPA inner record (§4.3) is sealed to the server's static X25519 public
//! key so that nothing on the wire is fingerprintable: a fresh ephemeral X25519
//! key per packet, ChaCha20-Poly1305 over a key derived from
//! `X25519(ephemeral, server_static)`, with the ephemeral public key as
//! associated data. This is libsodium's `crypto_box_seal` shape — it provides
//! confidentiality and wire indistinguishability, *not* sender authentication
//! (anyone holding the server public key can seal). Sender authentication is the
//! Ed25519 signature carried *inside* the sealed record (see `spa.rs`).
//!
//! The server's Noise static key doubles as the SPA seal key: the client already
//! pins it, so no extra enrollment is needed. The two uses are domain-separated
//! by the KDF labels below and by Noise's own transcript hashing.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::protocol::{SPA_AEAD_TAG_LEN, SPA_EPHEMERAL_LEN};

const KEY_LABEL: &[u8] = b"ghostbro-spa-seal-key-v1";
const NONCE_LABEL: &[u8] = b"ghostbro-spa-seal-nonce-v1";

/// Derive the X25519 public key for a raw 32-byte static private key.
pub fn x25519_public_from_private(private_key: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*private_key)).to_bytes()
}

fn derive_key_nonce(
    shared: &[u8; 32],
    ephemeral_pub: &[u8; 32],
    server_pub: &[u8; 32],
) -> ([u8; 32], [u8; 12]) {
    let key = Sha256::digest(
        [KEY_LABEL, shared.as_slice(), ephemeral_pub, server_pub].concat(),
    );
    // The nonce is deterministic in (ephemeral_pub, server_pub). This is safe
    // because the ephemeral key — and therefore the derived AEAD key — is unique
    // per packet, so no (key, nonce) pair is ever reused.
    let nonce = Sha256::digest([NONCE_LABEL, ephemeral_pub.as_slice(), server_pub].concat());

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&key);
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&nonce[..12]);
    (key_bytes, nonce_bytes)
}

/// Generate a fresh ephemeral secret for a single seal.
pub fn generate_ephemeral() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// The X25519 public key for an ephemeral secret. The caller binds this into the
/// inner signature before sealing, so the transmitted ephemeral and the signed
/// ephemeral are the same.
pub fn ephemeral_public(ephemeral_secret: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*ephemeral_secret)).to_bytes()
}

/// Seal `plaintext` to `server_pub` under a caller-supplied ephemeral secret.
/// Returns `ephemeral_pub || ciphertext || tag` (no padding).
pub fn seal_with_ephemeral(
    plaintext: &[u8],
    server_pub: &[u8; 32],
    ephemeral_secret: &[u8; 32],
) -> Vec<u8> {
    let ephemeral = StaticSecret::from(*ephemeral_secret);
    let ephemeral_pub = PublicKey::from(&ephemeral).to_bytes();

    let shared = ephemeral
        .diffie_hellman(&PublicKey::from(*server_pub))
        .to_bytes();
    let (key, nonce) = derive_key_nonce(&shared, &ephemeral_pub, server_pub);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &ephemeral_pub,
            },
        )
        .expect("ChaCha20-Poly1305 seal never fails for valid key/nonce");

    let mut out = Vec::with_capacity(SPA_EPHEMERAL_LEN + ciphertext.len());
    out.extend_from_slice(&ephemeral_pub);
    out.extend_from_slice(&ciphertext);
    out
}

/// Seal `plaintext` to `server_pub` with a fresh random ephemeral.
pub fn seal(plaintext: &[u8], server_pub: &[u8; 32]) -> Vec<u8> {
    seal_with_ephemeral(plaintext, server_pub, &generate_ephemeral())
}

/// Opened seal: the recovered inner plaintext plus the ephemeral public key
/// (needed to verify the inner Ed25519 signature, which binds the ephemeral).
pub struct Opened {
    pub plaintext: Vec<u8>,
    pub ephemeral_pub: [u8; 32],
}

/// Open a sealed core (`ephemeral_pub || ciphertext || tag`, padding already
/// stripped) with the server's static private key. Returns `None` on any AEAD
/// authentication failure (not sealed to this server, truncated, or tampered).
pub fn open(sealed_core: &[u8], server_private: &[u8; 32]) -> Option<Opened> {
    if sealed_core.len() < SPA_EPHEMERAL_LEN + SPA_AEAD_TAG_LEN {
        return None;
    }
    let mut ephemeral_pub = [0u8; 32];
    ephemeral_pub.copy_from_slice(&sealed_core[..SPA_EPHEMERAL_LEN]);
    let ciphertext = &sealed_core[SPA_EPHEMERAL_LEN..];

    let server_secret = StaticSecret::from(*server_private);
    let server_pub = PublicKey::from(&server_secret).to_bytes();
    let shared = server_secret
        .diffie_hellman(&PublicKey::from(ephemeral_pub))
        .to_bytes();
    let (key, nonce) = derive_key_nonce(&shared, &ephemeral_pub, &server_pub);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &ephemeral_pub,
            },
        )
        .ok()?;

    Some(Opened {
        plaintext,
        ephemeral_pub,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server_keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
        let private = [seed; 32];
        (private, x25519_public_from_private(&private))
    }

    #[test]
    fn seal_open_roundtrip() {
        let (private, public) = server_keypair(0x11);
        let message = b"the inner SPA record";

        let sealed = seal(message, &public);
        let opened = open(&sealed, &private).expect("opens for the right server");

        assert_eq!(message.as_slice(), opened.plaintext.as_slice());
        assert_eq!(&sealed[..32], opened.ephemeral_pub.as_slice());
    }

    #[test]
    fn open_fails_for_wrong_server() {
        let (_, public_a) = server_keypair(0x22);
        let (private_b, _) = server_keypair(0x33);

        let sealed = seal(b"hello", &public_a);
        assert!(open(&sealed, &private_b).is_none());
    }

    #[test]
    fn open_fails_on_tamper() {
        let (private, public) = server_keypair(0x44);
        let mut sealed = seal(b"hello world", &public);
        let last = sealed.len() - 1;
        sealed[last] ^= 0xff;
        assert!(open(&sealed, &private).is_none());
    }
}
