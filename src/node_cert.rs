//! The per-peer node certificate — generated locally at first run, signed by the DigNetwork CA.
//!
//! Every DIG peer mints ONE leaf certificate (mirroring Chia's `create_all_ssl`): a fresh ECDSA
//! P-256 TLS key pair, a leaf signed by the shipped [`crate::ca::DigCa`], carrying the #1204 BLS-G1
//! binding ([`crate::binding`]). The leaf's `peer_id = SHA-256(SPKI DER)` is the peer's transport
//! identity. The cert serves BOTH directions of mutual TLS (it has `serverAuth` + `clientAuth` EKUs),
//! so the same `NodeCert` is presented whether the peer dials out or accepts a dial.
//!
//! The cert + key are persisted PEM under a caller-chosen directory and regenerated only if absent,
//! so a peer keeps a stable `peer_id` across restarts.

use std::fs;
use std::path::Path;

use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, Ia5String, KeyPair,
    KeyUsagePurpose, SanType, PKCS_ECDSA_P256_SHA256,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

use crate::binding::attach_binding;
use crate::bls::SecretKey;
use crate::ca::{DigCa, CLOCK_SKEW_BACKDATE};
use crate::error::{DigTlsError, Result};
use crate::identity::{peer_id_from_tls_spki_der, PeerId};

/// Leaf validity window: 10 years. A DIG peer's identity is its `peer_id` + BLS binding, not the
/// cert's lifetime, so a long-lived leaf keeps the identity stable without any renewal machinery at
/// this foundation layer. (A future consumer MAY rotate by deleting the persisted pair.)
pub const LEAF_LIFETIME: Duration = Duration::days(365 * 10);

/// The single SAN on a DIG peer leaf. Peers authenticate by `peer_id` + BLS binding, NOT by
/// hostname, so the SAN is a fixed, non-load-bearing placeholder (the rustls verifiers do not check
/// it — see [`crate::verify`]).
const LEAF_SAN: &str = "peer.dig";

/// The on-disk file names for the persisted node cert + key.
const CERT_FILE: &str = "node.crt";
const KEY_FILE: &str = "node.key";

/// A peer's mTLS identity certificate + private key, plus its derived `peer_id`.
///
/// The private key is held in [`Zeroizing`] so every clone/drop scrubs the plaintext PKCS#8 bytes
/// from freed heap. [`NodeCert`] deliberately does not derive `Clone` for the same reason — pass a
/// reference.
pub struct NodeCert {
    cert_pem: String,
    key_pem: Zeroizing<String>,
    cert_der: Vec<u8>,
    key_der: Zeroizing<Vec<u8>>,
    spki_der: Vec<u8>,
    peer_id: PeerId,
}

impl std::fmt::Debug for NodeCert {
    /// Never renders the private key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeCert")
            .field("peer_id", &self.peer_id)
            .field("key_pem", &"<redacted>")
            .finish()
    }
}

impl NodeCert {
    /// Generate a new node cert signed by the shipped, public DigNetwork CA (the common path).
    pub fn generate_signed(bls_sk: &SecretKey) -> Result<Self> {
        Self::generate_signed_by(&DigCa::embedded()?, bls_sk, OffsetDateTime::now_utc())
    }

    /// Generate a new node cert signed by an explicit CA at an explicit issuance time (used by tests
    /// with a throwaway CA, and internally by [`Self::generate_signed`]).
    pub fn generate_signed_by(ca: &DigCa, bls_sk: &SecretKey, now: OffsetDateTime) -> Result<Self> {
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| DigTlsError::CertGen(format!("generate leaf key: {e}")))?;

        let mut params = CertificateParams::new(Vec::<String>::new())
            .map_err(|e| DigTlsError::CertGen(format!("leaf params: {e}")))?;
        params.not_before = now - CLOCK_SKEW_BACKDATE;
        params.not_after = now + LEAF_LIFETIME;

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, LEAF_SAN);
        params.distinguished_name = dn;

        let san = Ia5String::try_from(LEAF_SAN.to_string())
            .map_err(|e| DigTlsError::CertGen(format!("leaf SAN: {e}")))?;
        params.subject_alt_names = vec![SanType::DnsName(san)];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        // Both EKUs so the ONE leaf authenticates in either direction of the mutual-TLS handshake.
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];

        // Bind peer_id ↔ BLS key BEFORE signing (the extension is part of the signed TBS cert).
        attach_binding(&mut params, &leaf_key, bls_sk);

        let cert = params
            .signed_by(&leaf_key, &ca.cert, &ca.key)
            .map_err(|e| DigTlsError::CertGen(format!("sign leaf: {e}")))?;

        Self::from_parts(cert.pem(), leaf_key.serialize_pem(), &leaf_key)
    }

    /// Load a persisted node cert + key from `dir`, or generate + persist a new one signed by the
    /// shipped DigNetwork CA if either file is absent. Keeps a peer's `peer_id` stable across restarts.
    pub fn load_or_generate(dir: impl AsRef<Path>, bls_sk: &SecretKey) -> Result<Self> {
        let dir = dir.as_ref();
        let cert_path = dir.join(CERT_FILE);
        let key_path = dir.join(KEY_FILE);
        if cert_path.exists() && key_path.exists() {
            let cert_pem = fs::read_to_string(&cert_path)?;
            let key_pem = fs::read_to_string(&key_path)?;
            return Self::from_pem(&cert_pem, &key_pem);
        }
        let node = Self::generate_signed(bls_sk)?;
        fs::create_dir_all(dir)?;
        fs::write(&cert_path, node.cert_pem.as_bytes())?;
        fs::write(&key_path, node.key_pem.as_bytes())?;
        Ok(node)
    }

    /// Reconstruct a [`NodeCert`] from persisted PEM (its cert + private key).
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self> {
        let key = KeyPair::from_pem(key_pem)
            .map_err(|e| DigTlsError::Parse(format!("parse leaf key: {e}")))?;
        Self::from_parts(cert_pem.to_string(), key_pem.to_string(), &key)
    }

    /// Assemble a [`NodeCert`] from its PEM parts, deriving the DER forms + `peer_id` once.
    fn from_parts(cert_pem: String, key_pem: String, key: &KeyPair) -> Result<Self> {
        let cert_der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .next()
            .and_then(|r| r.ok())
            .ok_or_else(|| DigTlsError::Parse("leaf PEM has no certificate".into()))?
            .to_vec();
        let key_der = key.serialize_der();
        let spki_der = key.public_key_der();
        let peer_id = peer_id_from_tls_spki_der(&spki_der);
        Ok(Self {
            cert_pem,
            key_pem: Zeroizing::new(key_pem),
            cert_der,
            key_der: Zeroizing::new(key_der),
            spki_der,
            peer_id,
        })
    }

    /// This peer's transport identity, `peer_id = SHA-256(SPKI DER)`.
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// The leaf's SubjectPublicKeyInfo DER (what `peer_id` is the SHA-256 of).
    pub fn spki_der(&self) -> &[u8] {
        &self.spki_der
    }

    /// The leaf certificate in DER form.
    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    /// The leaf certificate, PEM-encoded (for persistence / inspection).
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// The private key, PEM-encoded. Handle with care — this is secret-ADJACENT (the key authorizes
    /// the peer's identity, though the DigNetwork CA itself is public).
    pub fn key_pem(&self) -> &str {
        &self.key_pem
    }

    /// The rustls certificate chain to present in a handshake (just the leaf — the DigNetwork CA is a
    /// well-known trust anchor every peer already embeds, so it is not sent on the wire).
    pub fn rustls_cert_chain(&self) -> Vec<CertificateDer<'static>> {
        vec![CertificateDer::from(self.cert_der.clone())]
    }

    /// The rustls private key for the handshake.
    pub fn rustls_private_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::try_from(self.key_der.to_vec())
            .expect("a freshly serialized PKCS#8 key is always a valid PrivateKeyDer")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::{verify_binding_from_leaf_cert, BindingOutcome};
    use crate::bls::public_key_bytes;
    use crate::ca::generate_dig_ca;
    use sha2::{Digest, Sha256};

    fn test_ca() -> DigCa {
        let m = generate_dig_ca(OffsetDateTime::now_utc()).unwrap();
        DigCa::from_pem(&m.cert_pem, &m.key_pem).unwrap()
    }

    fn bls_sk(label: &str) -> SecretKey {
        let seed: [u8; 32] = Sha256::digest(label.as_bytes()).into();
        SecretKey::from_seed(&seed)
    }

    #[test]
    fn generated_cert_binds_peer_id_to_the_bls_key() {
        let ca = test_ca();
        let sk = bls_sk("node-cert/bind");
        let node = NodeCert::generate_signed_by(&ca, &sk, OffsetDateTime::now_utc()).unwrap();

        // peer_id is SHA-256 of the leaf SPKI.
        let expected: [u8; 32] = Sha256::digest(node.spki_der()).into();
        assert_eq!(node.peer_id().as_bytes(), &expected);

        // The cert carries a VALID binding to exactly this BLS key.
        match verify_binding_from_leaf_cert(node.cert_der()) {
            BindingOutcome::Bound { bls_pub } => assert_eq!(bls_pub, public_key_bytes(&sk)),
            other => panic!("expected Bound, got {other:?}"),
        }
    }

    #[test]
    fn distinct_peers_get_distinct_ids() {
        let ca = test_ca();
        let a = NodeCert::generate_signed_by(&ca, &bls_sk("a"), OffsetDateTime::now_utc()).unwrap();
        let b = NodeCert::generate_signed_by(&ca, &bls_sk("b"), OffsetDateTime::now_utc()).unwrap();
        assert_ne!(a.peer_id(), b.peer_id());
    }

    #[test]
    fn pem_round_trips_preserving_peer_id() {
        let ca = test_ca();
        let node =
            NodeCert::generate_signed_by(&ca, &bls_sk("rt"), OffsetDateTime::now_utc()).unwrap();
        let restored = NodeCert::from_pem(node.cert_pem(), node.key_pem()).unwrap();
        assert_eq!(node.peer_id(), restored.peer_id());
    }

    #[test]
    fn load_or_generate_is_stable_across_calls() {
        let dir = tempfile::tempdir().unwrap();
        let sk = bls_sk("persist");
        let first = NodeCert::load_or_generate(dir.path(), &sk).unwrap();
        let second = NodeCert::load_or_generate(dir.path(), &sk).unwrap();
        assert_eq!(
            first.peer_id(),
            second.peer_id(),
            "a persisted cert is reloaded, not regenerated"
        );
    }

    #[test]
    fn debug_never_leaks_the_key() {
        let ca = test_ca();
        let node =
            NodeCert::generate_signed_by(&ca, &bls_sk("dbg"), OffsetDateTime::now_utc()).unwrap();
        assert!(format!("{node:?}").contains("<redacted>"));
    }
}
