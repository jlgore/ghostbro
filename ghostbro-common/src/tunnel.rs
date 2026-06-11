//! Outer obfuscation layer for the proxy tunnel (§5.4, §14 — Phase 2).
//!
//! Phase 1 made the *sealed SPA packet* bit-for-bit uniform (see [`crate::seal`]).
//! This module closes the other half of the §10.2 entropy gap: the proxy tunnel,
//! which on the raw transport reads as a fully-encrypted stream — a Noise XK
//! `msg1` ephemeral (a bare curve point) followed by cleartext 2-byte length
//! framing with no protocol structure.
//!
//! **Architecture B (outer obfs4-style layer).** Rather than re-encode Noise's
//! internal ephemeral in place — which would require patching `snow` and fighting
//! the handshake transcript hash — we leave the Noise XK handshake byte-for-byte
//! unchanged and wrap the *entire* proxy byte stream (every handshake message and
//! every transport frame) in an outer layer of our own:
//!
//! 1. The client runs a fresh Elligator2 Diffie-Hellman against the server's
//!    pinned Noise static key (the same key the client already pins), using
//!    Phase 1's distinguisher-free [`crate::seal::generate_obfuscated_ephemeral`]
//!    (the `Randomized` variant, retry-until-representable keygen). It transmits
//!    its ephemeral as a 32-byte representative — the first bytes a passive
//!    observer sees, indistinguishable from uniform random.
//! 2. Both sides derive a pair of directional stream keys from the shared secret.
//! 3. Every frame above this layer is sealed with ChaCha20-Poly1305 and framed to
//!    resemble a TLS 1.2 application-data record (`0x17 0x03 0x03` + BE length).
//!
//! Because the outer DH is ours, we control clamping exactly as Phase 1's seal
//! does: the shared secret is derived from the *recovered* point, and X25519
//! clamping annihilates the torsion the `Randomized` dirty base-point multiply
//! introduces. The Noise XK message semantics (`e, ee, s, se`; prologue =
//! `key_id`; static-key binding §5.2) are untouched — only the outer
//! encoding/framing changes. A single deployment-wide transport knob selects raw
//! vs. obfuscated on both ends; a mismatch fails the record parse cleanly rather
//! than hanging.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::seal::{generate_obfuscated_ephemeral, point_from_representative};

/// Length of the Elligator2 representative preamble the client sends first.
pub const REPRESENTATIVE_LEN: usize = 32;

/// TLS 1.2 application-data content type — the record-mimic prefix.
const TLS_CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;
/// TLS 1.2 legacy record version (`{3, 3}`), as carried on real TLS 1.2/1.3
/// application-data records.
const TLS_LEGACY_VERSION: [u8; 2] = [0x03, 0x03];
/// `content_type(1) || version(2) || length(2)`.
pub const RECORD_HEADER_LEN: usize = 5;

/// Poly1305 tag length on each outer record body.
pub const TUNNEL_TAG_LEN: usize = 16;

/// Largest inner frame (Noise ciphertext or handshake message) the codec will
/// seal into one record. Matches the proxy's `MAX_FRAME_LEN`; the outer record
/// body is at most this plus [`TUNNEL_TAG_LEN`], which still fits a `u16`.
pub const MAX_INNER_FRAME_LEN: usize = 16 * 1024;

const C2S_KEY_LABEL: &[u8] = b"ghostbro-tunnel-c2s-key-v1";
const S2C_KEY_LABEL: &[u8] = b"ghostbro-tunnel-s2c-key-v1";

/// Directional stream keys for the outer obfuscation layer. `c2s` protects
/// client→server records, `s2c` protects server→client records; each direction
/// is a separate key so the two never share a (key, nonce) pair.
struct TunnelKeys {
    c2s: [u8; 32],
    s2c: [u8; 32],
}

/// Derive the directional keys from the outer DH shared secret. The representative
/// and server static public are mixed in so the keys are bound to this specific
/// session preamble (mirrors the seal KDF in [`crate::seal`], same SHA-256 style,
/// no extra HKDF dependency).
fn derive_tunnel_keys(
    shared: &[u8; 32],
    representative: &[u8; 32],
    server_pub: &[u8; 32],
) -> TunnelKeys {
    let mut c2s = [0u8; 32];
    let mut s2c = [0u8; 32];
    c2s.copy_from_slice(&Sha256::digest(
        [C2S_KEY_LABEL, shared.as_slice(), representative, server_pub].concat(),
    ));
    s2c.copy_from_slice(&Sha256::digest(
        [S2C_KEY_LABEL, shared.as_slice(), representative, server_pub].concat(),
    ));
    TunnelKeys { c2s, s2c }
}

/// One direction of the outer record stream: a ChaCha20-Poly1305 cipher plus a
/// monotonic record counter that drives the nonce. A fresh per-direction key and
/// a never-repeating counter guarantee nonce uniqueness, so no (key, nonce) pair
/// is ever reused within a connection.
pub struct TunnelCipher {
    cipher: ChaCha20Poly1305,
    counter: u64,
}

impl TunnelCipher {
    fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(key)),
            counter: 0,
        }
    }

    /// 96-bit nonce: 4 zero bytes followed by the 64-bit big-endian record
    /// counter. Distinct per record within a direction.
    fn nonce(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&self.counter.to_be_bytes());
        nonce
    }

    /// Seal one inner frame into a complete TLS-app-data-mimic record
    /// (`header || ciphertext || tag`) and advance the record counter. Returns
    /// `None` if `frame` exceeds [`MAX_INNER_FRAME_LEN`].
    pub fn seal_record(&mut self, frame: &[u8]) -> Option<Vec<u8>> {
        if frame.len() > MAX_INNER_FRAME_LEN {
            return None;
        }
        let nonce = self.nonce();
        let ciphertext = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: frame,
                    aad: &[],
                },
            )
            .expect("ChaCha20-Poly1305 seal never fails for valid key/nonce");
        self.counter = self.counter.wrapping_add(1);

        // ciphertext = frame + tag <= MAX_INNER_FRAME_LEN + 16, fits a u16.
        let body_len = ciphertext.len() as u16;
        let mut record = Vec::with_capacity(RECORD_HEADER_LEN + ciphertext.len());
        record.push(TLS_CONTENT_TYPE_APPLICATION_DATA);
        record.extend_from_slice(&TLS_LEGACY_VERSION);
        record.extend_from_slice(&body_len.to_be_bytes());
        record.extend_from_slice(&ciphertext);
        Some(record)
    }

    /// Open one record body (`ciphertext || tag`) back to the inner frame and
    /// advance the record counter. Returns `None` on any authentication failure
    /// (tamper, truncation, wrong transport, or counter desync).
    pub fn open_record(&mut self, body: &[u8]) -> Option<Vec<u8>> {
        let nonce = self.nonce();
        let frame = self
            .cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: body,
                    aad: &[],
                },
            )
            .ok()?;
        self.counter = self.counter.wrapping_add(1);
        Some(frame)
    }
}

/// Validate a 5-byte record header and return the declared body length. Rejects
/// anything that is not a TLS-app-data-mimic header (clean failure on a raw peer
/// or a transport mismatch) or whose body would exceed the frame ceiling.
pub fn parse_record_header(header: &[u8; RECORD_HEADER_LEN]) -> Option<usize> {
    if header[0] != TLS_CONTENT_TYPE_APPLICATION_DATA || header[1..3] != TLS_LEGACY_VERSION {
        return None;
    }
    let body_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if body_len > MAX_INNER_FRAME_LEN + TUNNEL_TAG_LEN || body_len < TUNNEL_TAG_LEN {
        return None;
    }
    Some(body_len)
}

/// Client outer-layer handshake state: the representative to put on the wire
/// first, plus the two directional ciphers.
pub struct ClientTunnel {
    /// 32 uniform bytes to transmit before any record (the obfs preamble).
    pub representative: [u8; 32],
    /// Seals client→server records.
    pub send: TunnelCipher,
    /// Opens server→client records.
    pub recv: TunnelCipher,
}

/// Server outer-layer handshake state: the two directional ciphers, mirrored
/// relative to the client.
pub struct ServerTunnel {
    /// Seals server→client records.
    pub send: TunnelCipher,
    /// Opens client→server records.
    pub recv: TunnelCipher,
}

/// Run the client side of the outer obfuscation handshake against the server's
/// pinned Noise static public key. The shared secret is derived from the point
/// *recovered* from the representative (not `ephemeral_public(secret)`) so it
/// matches what the server derives — see [`crate::seal::generate_obfuscated_ephemeral`].
pub fn client_tunnel_handshake(server_pub: &[u8; 32]) -> ClientTunnel {
    let (ephemeral_secret, representative, ephemeral_pub) = generate_obfuscated_ephemeral();
    let shared = StaticSecret::from(ephemeral_secret)
        .diffie_hellman(&PublicKey::from(*server_pub))
        .to_bytes();
    // X25519 clamps the ephemeral scalar, absorbing the torsion the recovered
    // (dirty) point carries — identical reasoning to the Phase 1 seal.
    let _ = ephemeral_pub;
    let keys = derive_tunnel_keys(&shared, &representative, server_pub);
    ClientTunnel {
        representative,
        send: TunnelCipher::new(&keys.c2s),
        recv: TunnelCipher::new(&keys.s2c),
    }
}

/// Run the server side of the outer obfuscation handshake. `representative` is the
/// 32-byte preamble read from the wire; `server_private` is this node's Noise
/// static private key. Returns `None` only if the representative does not map to a
/// point (it always does after the `Randomized` high-bit masking, so this is a
/// belt-and-suspenders guard).
pub fn server_tunnel_handshake(
    representative: &[u8; 32],
    server_private: &[u8; 32],
) -> Option<ServerTunnel> {
    let ephemeral_pub = point_from_representative(representative)?;
    let server_secret = StaticSecret::from(*server_private);
    let server_pub = PublicKey::from(&server_secret).to_bytes();
    let shared = server_secret
        .diffie_hellman(&PublicKey::from(ephemeral_pub))
        .to_bytes();
    let keys = derive_tunnel_keys(&shared, representative, &server_pub);
    Some(ServerTunnel {
        send: TunnelCipher::new(&keys.s2c),
        recv: TunnelCipher::new(&keys.c2s),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::x25519_public_from_private;

    fn server_keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
        let private = [seed; 32];
        (private, x25519_public_from_private(&private))
    }

    #[test]
    fn directional_keys_agree_across_handshake() {
        let (server_private, server_pub) = server_keypair(0x11);
        let client = client_tunnel_handshake(&server_pub);
        let server = server_tunnel_handshake(&client.representative, &server_private)
            .expect("representative maps to a point");

        // The client's send key must equal the server's recv key, and vice versa.
        let mut client = client;
        let mut server = server;
        let record = client.send.seal_record(b"client to server").expect("seals");
        let body = &record[RECORD_HEADER_LEN..];
        let opened = server.recv.open_record(body).expect("server opens c2s");
        assert_eq!(b"client to server".as_slice(), opened.as_slice());

        let record = server.send.seal_record(b"server to client").expect("seals");
        let body = &record[RECORD_HEADER_LEN..];
        let opened = client.recv.open_record(body).expect("client opens s2c");
        assert_eq!(b"server to client".as_slice(), opened.as_slice());
    }

    #[test]
    fn record_roundtrip_preserves_counter_ordering() {
        let (server_private, server_pub) = server_keypair(0x22);
        let mut client = client_tunnel_handshake(&server_pub);
        let mut server = server_tunnel_handshake(&client.representative, &server_private).unwrap();

        for i in 0..8u8 {
            let frame = vec![i; (i as usize) * 7 + 1];
            let record = client.send.seal_record(&frame).expect("seals");
            let header: [u8; RECORD_HEADER_LEN] = record[..RECORD_HEADER_LEN].try_into().unwrap();
            let body_len = parse_record_header(&header).expect("valid header");
            assert_eq!(body_len, record.len() - RECORD_HEADER_LEN);
            let opened = server
                .recv
                .open_record(&record[RECORD_HEADER_LEN..])
                .expect("opens in order");
            assert_eq!(frame, opened);
        }
    }

    #[test]
    fn header_is_tls_application_data_mimic() {
        let (_, server_pub) = server_keypair(0x33);
        let mut client = client_tunnel_handshake(&server_pub);
        let record = client.send.seal_record(b"x").expect("seals");
        assert_eq!(record[0], TLS_CONTENT_TYPE_APPLICATION_DATA);
        assert_eq!(record[1..3], TLS_LEGACY_VERSION);
    }

    #[test]
    fn parse_rejects_non_tls_header() {
        // A raw peer's first wire bytes are a 2-byte BE length; the high byte is
        // 0x00 for any frame under 16 KiB, which is not 0x17.
        assert!(parse_record_header(&[0x00, 0x30, 0x01, 0x02, 0x03]).is_none());
        // Wrong version.
        assert!(parse_record_header(&[0x17, 0x03, 0x01, 0x00, 0x20]).is_none());
        // Body too short to hold a tag.
        assert!(parse_record_header(&[0x17, 0x03, 0x03, 0x00, 0x04]).is_none());
    }

    #[test]
    fn wrong_server_key_fails_to_open() {
        let (_, server_pub) = server_keypair(0x44);
        let (other_private, _) = server_keypair(0x45);
        let mut client = client_tunnel_handshake(&server_pub);
        let mut server = server_tunnel_handshake(&client.representative, &other_private).unwrap();

        let record = client.send.seal_record(b"secret").expect("seals");
        assert!(server.recv.open_record(&record[RECORD_HEADER_LEN..]).is_none());
    }

    #[test]
    fn representative_preamble_high_bits_are_uniform() {
        // The representative is the first thing on the wire; unlike a raw X25519
        // ephemeral (top bit always clear), its high bits are ~uniform. Coarse
        // statistical tell-check, not a cryptographic uniformity proof.
        const N: usize = 256;
        let (_, server_pub) = server_keypair(0x55);
        let mut high_bit_set = 0usize;
        for _ in 0..N {
            let client = client_tunnel_handshake(&server_pub);
            if client.representative[31] & 0x80 != 0 {
                high_bit_set += 1;
            }
        }
        assert!(
            (N / 4..=3 * N / 4).contains(&high_bit_set),
            "representative high bit should be ~uniform, got {high_bit_set}/{N}"
        );
    }

    #[test]
    fn tampered_record_body_fails_to_open() {
        let (server_private, server_pub) = server_keypair(0x66);
        let mut client = client_tunnel_handshake(&server_pub);
        let mut server = server_tunnel_handshake(&client.representative, &server_private).unwrap();
        let mut record = client.send.seal_record(b"hello world").expect("seals");
        let last = record.len() - 1;
        record[last] ^= 0xff;
        assert!(server.recv.open_record(&record[RECORD_HEADER_LEN..]).is_none());
    }
}
