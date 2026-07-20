//! The shipped, PUBLIC DigNetwork Certificate Authority.
//!
//! dig-tls mirrors Chia's TLS model: it ships a single, well-known CA whose certificate AND private
//! key are BOTH public and compiled into the crate (exactly as `chia-blockchain` ships the
//! `chia_ca.crt` and `chia_ca.key` pair). **The CA private key is intentionally NOT a secret** — it
//! is a shared
//! trust-domain marker, not a secret gate. Anyone can mint a leaf that chains to the DigNetwork CA;
//! that is by design. Real authentication of a peer comes from the application layer — the
//! `peer_id = SHA-256(SPKI)` pin ([`crate::identity`]) and the #1204 BLS-G1 cert binding
//! ([`crate::binding`]) — never from CA-key secrecy. Because the CA key is public there is no user
//! step, no custody gate, and no runtime PKI service.
//!
//! Every DIG peer generates its own leaf certificate signed by this CA at first run
//! ([`crate::node_cert`]); every DIG peer trusts leaves that chain to this CA. The CA material is
//! byte-identical across the whole ecosystem (recorded in the `canonical` skill), so any two DIG
//! peers share the same trust anchor.

use std::sync::OnceLock;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256,
};
use rustls_pki_types::CertificateDer;
use time::{Duration, OffsetDateTime};

use crate::error::{DigTlsError, Result};

/// The shipped DigNetwork CA certificate, PEM-encoded (public — the trust anchor every peer uses).
pub const DIG_CA_CERT_PEM: &str = include_str!("ca/dig_ca.crt");

/// The shipped DigNetwork CA private key, PEM-encoded. **Intentionally public** (Chia precedent):
/// the CA key is a shared trust-domain marker, not a secret. A peer signs its own leaf with it.
pub const DIG_CA_KEY_PEM: &str = include_str!("ca/dig_ca.key");

/// The organization name on the DigNetwork CA, so a trust-store listing is self-identifying.
pub const CA_ORGANIZATION: &str = "DIG Network";

/// The DigNetwork CA CommonName.
pub const CA_COMMON_NAME: &str = "DIG Network CA";

/// CA validity window: ~100 years. The public CA is a fixed, long-lived trust anchor; it is rotated
/// only by an explicit, ecosystem-wide protocol event, never on a timer.
pub const CA_LIFETIME: Duration = Duration::days(365 * 100);

/// Backdate `not_before` by an hour so a peer with a slightly slow clock never rejects the anchor as
/// "not yet valid".
pub(crate) const CLOCK_SKEW_BACKDATE: Duration = Duration::hours(1);

/// A generated CA: the self-signed certificate and its private key, both PEM-encoded.
#[derive(Clone)]
pub struct CaMaterial {
    /// The self-signed CA certificate, PEM-encoded.
    pub cert_pem: String,
    /// The CA private key, PKCS#8 PEM-encoded (public by design — see the module docs).
    pub key_pem: String,
}

/// Mint a fresh DigNetwork CA (used ONCE to produce the shipped [`DIG_CA_CERT_PEM`]/[`DIG_CA_KEY_PEM`]
/// via `examples/generate_ca.rs`, and by tests). ECDSA P-256; 100-year validity; `CA:TRUE`
/// path-length 0 (it signs only end-entity leaves); `keyCertSign` + `cRLSign`. No name constraints:
/// DIG peer leaves carry no meaningful hostname (peers dial by IP and authenticate by peer_id + BLS
/// binding), so the CA's namespace is intentionally unconstrained.
pub fn generate_dig_ca(now: OffsetDateTime) -> Result<CaMaterial> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|e| DigTlsError::CertGen(format!("generate CA key: {e}")))?;

    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| DigTlsError::CertGen(format!("CA params: {e}")))?;
    params.not_before = now - CLOCK_SKEW_BACKDATE;
    params.not_after = now + CA_LIFETIME;

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, CA_COMMON_NAME);
    dn.push(DnType::OrganizationName, CA_ORGANIZATION);
    params.distinguished_name = dn;

    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.use_authority_key_identifier_extension = true;

    let cert = params
        .self_signed(&key)
        .map_err(|e| DigTlsError::CertGen(format!("self-sign CA: {e}")))?;

    Ok(CaMaterial {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    })
}

/// The DigNetwork CA loaded from PEM, ready to sign peer leaves.
///
/// Reconstructs the issuer handle (distinguished name + key) so leaf issuance needs only the PEM
/// material. [`DigCa::embedded`] loads the shipped public CA — the common path.
pub struct DigCa {
    pub(crate) cert: rcgen::Certificate,
    pub(crate) key: KeyPair,
}

impl DigCa {
    /// Load the shipped, public DigNetwork CA (the trust anchor every DIG peer shares).
    pub fn embedded() -> Result<Self> {
        Self::from_pem(DIG_CA_CERT_PEM, DIG_CA_KEY_PEM)
    }

    /// Load a CA from its PEM certificate + key (used by tests with a throwaway CA).
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self> {
        let key = KeyPair::from_pem(key_pem)
            .map_err(|e| DigTlsError::Ca(format!("parse CA key: {e}")))?;
        // Rematerialize the issuer handle from the stored cert; the persisted PEM is unchanged and
        // remains the trusted anchor.
        let params = CertificateParams::from_ca_cert_pem(cert_pem)
            .map_err(|e| DigTlsError::Ca(format!("parse CA cert: {e}")))?;
        let cert = params
            .self_signed(&key)
            .map_err(|e| DigTlsError::Ca(format!("rematerialize CA issuer: {e}")))?;
        Ok(Self { cert, key })
    }
}

/// The shipped DigNetwork CA certificate in DER form, parsed once and cached — the trust anchor the
/// rustls verifiers ([`crate::verify`]) chain peer leaves to.
pub fn embedded_ca_cert_der() -> Result<CertificateDer<'static>> {
    static DER: OnceLock<Vec<u8>> = OnceLock::new();
    let der = DER.get_or_init(|| {
        // The shipped PEM is generated by this crate's own `generate_dig_ca`, so it always parses;
        // an empty placeholder (before the CA is minted) yields an empty Vec that webpki rejects
        // cleanly at verify time rather than panicking here.
        rustls_pemfile::certs(&mut DIG_CA_CERT_PEM.as_bytes())
            .next()
            .and_then(|r| r.ok())
            .map(|c| c.to_vec())
            .unwrap_or_default()
    });
    if der.is_empty() {
        return Err(DigTlsError::Ca(
            "embedded DigNetwork CA certificate is missing or unparseable".into(),
        ));
    }
    Ok(CertificateDer::from(der.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_ca_round_trips_through_pem() {
        let ca = generate_dig_ca(OffsetDateTime::now_utc()).expect("mint CA");
        assert!(ca.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(ca.key_pem.contains("PRIVATE KEY"));
        // Loading it back succeeds — the issuer handle rematerializes.
        DigCa::from_pem(&ca.cert_pem, &ca.key_pem).expect("load generated CA");
    }

    #[test]
    fn embedded_ca_loads_and_parses_to_der() {
        DigCa::embedded().expect("the shipped CA loads");
        let der = embedded_ca_cert_der().expect("shipped CA parses to DER");
        assert!(!der.as_ref().is_empty());
    }
}
