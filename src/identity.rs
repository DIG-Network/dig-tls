//! Peer identity — `peer_id = SHA-256(TLS SubjectPublicKeyInfo DER)`.
//!
//! The transport identity of a DIG peer is the SHA-256 digest of the ASN.1 `SubjectPublicKeyInfo`
//! sequence (algorithm id + subjectPublicKey bit string) lifted from its leaf X.509 certificate.
//! This is the SAME derivation Chia uses for its node id and byte-identical to `dig-gossip`'s and
//! `dig-nat`'s `peer_id_from_tls_spki_der` — dig-tls is now the CANONICAL home so no consumer
//! re-implements it. Because every DIG connection is mutual TLS, each side derives the other's
//! [`PeerId`] from the certificate presented during the handshake.

use std::fmt;

use sha2::{Digest, Sha256};

/// A peer's stable network identity: the 32-byte SHA-256 of its TLS SPKI DER.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerId([u8; 32]);

impl PeerId {
    /// Construct from raw 32 bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        PeerId(bytes)
    }

    /// The raw 32 bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex encoding (the canonical string form used on the relay wire and in status APIs).
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.0 {
            s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
            s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
        }
        s
    }

    /// Parse a 64-char hex string. Returns `None` for a wrong length or a non-hex character.
    pub fn from_hex(hex: &str) -> Option<Self> {
        if hex.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let hi = (chunk[0] as char).to_digit(16)?;
            let lo = (chunk[1] as char).to_digit(16)?;
            out[i] = ((hi << 4) | lo) as u8;
        }
        Some(PeerId(out))
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerId({})", self.to_hex())
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Derive a [`PeerId`] from a TLS **SubjectPublicKeyInfo** block in PKIX DER form.
///
/// `spki_der` must be the full ASN.1 `SubjectPublicKeyInfo` sequence (algorithm id + subjectPublicKey
/// bit string) — **not** the bare public-key bit string. [`peer_id_from_leaf_cert_der`] extracts it
/// from a whole leaf certificate for you.
pub fn peer_id_from_tls_spki_der(spki_der: &[u8]) -> PeerId {
    PeerId(Sha256::digest(spki_der).into())
}

/// Extract the SubjectPublicKeyInfo DER from a leaf X.509 certificate (DER-encoded) and derive the
/// [`PeerId`]. Returns `None` if the certificate cannot be parsed as X.509.
pub fn peer_id_from_leaf_cert_der(cert_der: &[u8]) -> Option<PeerId> {
    let (_, x509) = x509_parser::parse_x509_certificate(cert_der).ok()?;
    Some(peer_id_from_tls_spki_der(
        x509.tbs_certificate.subject_pki.raw,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let id = PeerId::from_bytes([0xABu8; 32]);
        let hex = id.to_hex();
        assert_eq!(hex.len(), 64);
        assert_eq!(PeerId::from_hex(&hex), Some(id));
    }

    #[test]
    fn from_hex_rejects_bad_input() {
        assert_eq!(PeerId::from_hex("tooshort"), None);
        assert_eq!(PeerId::from_hex(&"z".repeat(64)), None);
    }

    #[test]
    fn peer_id_is_sha256_of_spki() {
        let spki = b"a fake SPKI DER blob";
        let expected: [u8; 32] = Sha256::digest(spki).into();
        assert_eq!(peer_id_from_tls_spki_der(spki).as_bytes(), &expected);
    }

    #[test]
    fn peer_id_from_unparseable_cert_is_none() {
        assert_eq!(peer_id_from_leaf_cert_der(b"not a certificate"), None);
    }

    #[test]
    fn display_equals_hex() {
        let id = PeerId::from_bytes([0x01u8; 32]);
        assert_eq!(format!("{id}"), id.to_hex());
    }
}
