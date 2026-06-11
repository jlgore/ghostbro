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
use curve25519_elligator2::{MapToPointVariant, MontgomeryPoint, Randomized};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::protocol::{SPA_AEAD_TAG_LEN, SPA_EPHEMERAL_LEN};

const KEY_LABEL: &[u8] = b"ghostbro-spa-seal-key-v1";
const NONCE_LABEL: &[u8] = b"ghostbro-spa-seal-nonce-v1";

/// Bounds the Elligator2 representable-keygen retry loop. Each random scalar is
/// representable with probability ~1/2, so 64 tries fails only on a broken RNG
/// (P(failure) ≈ 2^-64).
const ELLIGATOR_RETRY_LIMIT: usize = 64;

/// Wire encoding of the sealed-SPA ephemeral key (§4.3, §14). The choice only
/// changes how the leading 32 bytes are *encoded* — the AEAD key/nonce KDF, the
/// AAD, and the inner Ed25519 signature all bind the recovered *point*, so the
/// authenticated material is identical between transports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SealTransport {
    /// Raw X25519 ephemeral public point on the wire (v0.3 default). The field
    /// element is `< 2^255-19`, leaving a small high-bit bias — fingerprintable
    /// in principle (see §4.3 note).
    #[default]
    Raw,
    /// Elligator2 *representative* of the ephemeral public on the wire,
    /// indistinguishable from uniform random bytes (obfs4 convention: the
    /// `Randomized` variant, retry-until-representable keygen, randomized high
    /// bits, masked off before the forward map on decode). Mitigates the
    /// entropy-based fully-encrypted-flow tell (§10.2).
    Obfuscated,
}

/// Derive the X25519 public key for a raw 32-byte static private key.
pub fn x25519_public_from_private(private_key: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*private_key)).to_bytes()
}

fn derive_key_nonce(
    shared: &[u8; 32],
    ephemeral_pub: &[u8; 32],
    server_pub: &[u8; 32],
) -> ([u8; 32], [u8; 12]) {
    let key = Sha256::digest([KEY_LABEL, shared.as_slice(), ephemeral_pub, server_pub].concat());
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

/// Generate an ephemeral whose X25519 public point has a valid Elligator2
/// representative (obfs4 retry-until-representable keygen). Returns
/// `(ephemeral_secret, representative, ephemeral_pub)` where:
/// - `representative` is the 32-byte wire encoding (high bits randomized), and
/// - `ephemeral_pub` is the point **recovered from the representative**.
///
/// The crypto must use the recovered point, not `ephemeral_public(secret)`: the
/// `Randomized` variant uses a "dirty" base-point multiply (adds a low-order
/// component so representatives cover the whole field uniformly), so the
/// representative's point carries torsion that `ephemeral_public` would not
/// reproduce. Deriving the seal key/AAD/signature from the recovered point makes
/// the client (encode) and server (decode) agree byte-for-byte, and X25519's
/// scalar clamping annihilates the torsion in the Diffie-Hellman so the shared
/// secret is unchanged.
pub fn generate_obfuscated_ephemeral() -> ([u8; 32], [u8; 32], [u8; 32]) {
    for _ in 0..ELLIGATOR_RETRY_LIMIT {
        let mut ephemeral_secret = [0u8; 32];
        OsRng.fill_bytes(&mut ephemeral_secret);
        let tweak = (OsRng.next_u32() & 0xff) as u8;
        let representative: Option<[u8; 32]> =
            Randomized::to_representative(&ephemeral_secret, tweak).into();
        if let Some(representative) = representative {
            let ephemeral_pub = point_from_representative(&representative)
                .expect("a freshly produced representative always maps back to a point");
            return (ephemeral_secret, representative, ephemeral_pub);
        }
    }
    panic!("failed to find a representable ephemeral within the retry limit (broken RNG)");
}

/// Map a 32-byte Elligator2 representative back to its X25519 public point. The
/// `Randomized` forward map masks off the two randomized high bits before
/// mapping, so any 32 bytes map to *some* point — authentication is the AEAD
/// tag's job, not this step's.
pub fn point_from_representative(representative: &[u8; 32]) -> Option<[u8; 32]> {
    MontgomeryPoint::from_representative::<Randomized>(representative).map(|point| point.0)
}

/// Shared sealing core: ChaCha20-Poly1305 over a key derived from
/// `X25519(ephemeral_secret, server_pub)`, with `ephemeral_pub` as both KDF
/// input and AEAD associated data. `wire_prefix` is the 32-byte prefix written
/// to the wire — the raw point for [`SealTransport::Raw`], the Elligator2
/// representative for [`SealTransport::Obfuscated`]. Returns
/// `wire_prefix || ciphertext || tag` (no padding).
fn seal_core(
    plaintext: &[u8],
    server_pub: &[u8; 32],
    ephemeral_secret: &[u8; 32],
    ephemeral_pub: &[u8; 32],
    wire_prefix: &[u8; 32],
) -> Vec<u8> {
    let shared = StaticSecret::from(*ephemeral_secret)
        .diffie_hellman(&PublicKey::from(*server_pub))
        .to_bytes();
    let (key, nonce) = derive_key_nonce(&shared, ephemeral_pub, server_pub);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: ephemeral_pub,
            },
        )
        .expect("ChaCha20-Poly1305 seal never fails for valid key/nonce");

    let mut out = Vec::with_capacity(SPA_EPHEMERAL_LEN + ciphertext.len());
    out.extend_from_slice(wire_prefix);
    out.extend_from_slice(&ciphertext);
    out
}

/// Seal `plaintext` to `server_pub` under a caller-supplied ephemeral secret.
/// Returns `ephemeral_pub || ciphertext || tag` (no padding) — the raw transport.
pub fn seal_with_ephemeral(
    plaintext: &[u8],
    server_pub: &[u8; 32],
    ephemeral_secret: &[u8; 32],
) -> Vec<u8> {
    let ephemeral_pub = ephemeral_public(ephemeral_secret);
    seal_core(
        plaintext,
        server_pub,
        ephemeral_secret,
        &ephemeral_pub,
        &ephemeral_pub,
    )
}

/// Seal `plaintext` to `server_pub` under an obfuscated ephemeral. Emits
/// `representative || ciphertext || tag` (no padding): only the 32-byte prefix's
/// distribution differs from [`seal_with_ephemeral`] — same lengths, same inner
/// crypto, which operates on the point recovered from `representative`.
///
/// Pair `ephemeral_secret`/`representative` come from
/// [`generate_obfuscated_ephemeral`]; the recovered point used internally is the
/// same one that keygen returned, so a signature committed to that point still
/// verifies after opening.
pub fn seal_with_ephemeral_obfuscated(
    plaintext: &[u8],
    server_pub: &[u8; 32],
    ephemeral_secret: &[u8; 32],
    representative: &[u8; 32],
) -> Vec<u8> {
    let ephemeral_pub = point_from_representative(representative)
        .expect("caller-supplied representative must map back to a point");
    seal_core(
        plaintext,
        server_pub,
        ephemeral_secret,
        &ephemeral_pub,
        representative,
    )
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

/// Shared opening core: derive the AEAD key/nonce from
/// `X25519(server_private, ephemeral_pub)` and decrypt. `ephemeral_pub` is the
/// recovered point (raw transport: read directly; obfuscated: mapped from the
/// representative). Returns `None` on any AEAD authentication failure.
fn open_core(
    ephemeral_pub: [u8; 32],
    ciphertext: &[u8],
    server_private: &[u8; 32],
) -> Option<Opened> {
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

/// Open a raw sealed core (`ephemeral_pub || ciphertext || tag`, padding already
/// stripped) with the server's static private key. Returns `None` on any AEAD
/// authentication failure (not sealed to this server, truncated, or tampered).
pub fn open(sealed_core: &[u8], server_private: &[u8; 32]) -> Option<Opened> {
    if sealed_core.len() < SPA_EPHEMERAL_LEN + SPA_AEAD_TAG_LEN {
        return None;
    }
    let mut ephemeral_pub = [0u8; 32];
    ephemeral_pub.copy_from_slice(&sealed_core[..SPA_EPHEMERAL_LEN]);
    let ciphertext = &sealed_core[SPA_EPHEMERAL_LEN..];
    open_core(ephemeral_pub, ciphertext, server_private)
}

/// Open an obfuscated sealed core (`representative || ciphertext || tag`, padding
/// already stripped): map the representative back to the ephemeral point, then
/// decrypt exactly as [`open`]. The returned `Opened.ephemeral_pub` is the
/// recovered *point* (not the representative), so the caller verifies the inner
/// Ed25519 signature against the same point the client signed.
pub fn open_obfuscated(sealed_core: &[u8], server_private: &[u8; 32]) -> Option<Opened> {
    if sealed_core.len() < SPA_EPHEMERAL_LEN + SPA_AEAD_TAG_LEN {
        return None;
    }
    let mut representative = [0u8; 32];
    representative.copy_from_slice(&sealed_core[..SPA_EPHEMERAL_LEN]);
    let ephemeral_pub = point_from_representative(&representative)?;
    let ciphertext = &sealed_core[SPA_EPHEMERAL_LEN..];
    open_core(ephemeral_pub, ciphertext, server_private)
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

    #[test]
    fn obfuscated_seal_open_roundtrip() {
        let (private, public) = server_keypair(0x55);
        let message = b"the inner SPA record";

        let (ephemeral_secret, representative, ephemeral_pub) = generate_obfuscated_ephemeral();
        let sealed =
            seal_with_ephemeral_obfuscated(message, &public, &ephemeral_secret, &representative);
        let opened = open_obfuscated(&sealed, &private).expect("opens for the right server");

        assert_eq!(message.as_slice(), opened.plaintext.as_slice());
        // The wire prefix is the representative; the recovered ephemeral is the
        // *point*, which is what keygen handed back for the signature binding.
        assert_eq!(&sealed[..32], representative.as_slice());
        assert_eq!(ephemeral_pub, opened.ephemeral_pub);
    }

    #[test]
    fn obfuscated_recovered_point_matches_keygen_point() {
        // The point both sides derive from the representative is identical, so a
        // signature committed to keygen's point verifies against the opened one.
        let (_, representative, ephemeral_pub) = generate_obfuscated_ephemeral();
        assert_eq!(
            ephemeral_pub,
            point_from_representative(&representative).expect("maps back")
        );
    }

    #[test]
    fn obfuscated_open_fails_for_wrong_server() {
        let (_, public_a) = server_keypair(0x66);
        let (private_b, _) = server_keypair(0x77);

        let (secret, representative, _) = generate_obfuscated_ephemeral();
        let sealed = seal_with_ephemeral_obfuscated(b"hello", &public_a, &secret, &representative);
        assert!(open_obfuscated(&sealed, &private_b).is_none());
    }

    #[test]
    fn raw_and_obfuscated_cores_are_the_same_length() {
        let (_, public) = server_keypair(0x88);
        let message = [0u8; crate::protocol::SPA_INNER_LEN];

        let raw = seal(&message, &public);
        let (secret, representative, _) = generate_obfuscated_ephemeral();
        let obfuscated =
            seal_with_ephemeral_obfuscated(&message, &public, &secret, &representative);

        assert_eq!(raw.len(), obfuscated.len());
        assert_eq!(raw.len(), crate::protocol::SPA_SEALED_CORE_LEN);
    }

    #[test]
    fn obfuscated_prefix_has_uniform_high_bits() {
        // The raw X25519 path leaves bit 255 of the leading 32 bytes always clear
        // (the field element is < 2^255-19). The Elligator2 representative
        // randomizes the top two bits, so across many seals the high bit is set
        // roughly half the time. This is a coarse statistical tell-check, not a
        // cryptographic uniformity proof.
        const N: usize = 256;

        let mut raw_high_bit_set = 0usize;
        let (_, public) = server_keypair(0x99);
        for _ in 0..N {
            let sealed = seal(b"x", &public);
            if sealed[31] & 0x80 != 0 {
                raw_high_bit_set += 1;
            }
        }
        // The raw curve point never sets the top bit.
        assert_eq!(0, raw_high_bit_set, "raw ephemeral high bit must be fixed");

        let mut obf_high_bit_set = 0usize;
        for _ in 0..N {
            let (secret, representative, _) = generate_obfuscated_ephemeral();
            let sealed = seal_with_ephemeral_obfuscated(b"x", &public, &secret, &representative);
            if sealed[31] & 0x80 != 0 {
                obf_high_bit_set += 1;
            }
        }
        // Expect ~N/2; allow a wide band to keep the test non-flaky.
        assert!(
            (N / 4..=3 * N / 4).contains(&obf_high_bit_set),
            "obfuscated high bit should be ~uniform, got {obf_high_bit_set}/{N} set"
        );
    }
}
