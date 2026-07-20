//! The rustls mutual-auth verifiers — the trust decision every DIG peer connection makes.
//!
//! A DIG peer accepts the other side only when THREE checks pass, in order:
//!
//! 1. **Chain to the DigNetwork CA.** The presented leaf must be signed by the shipped
//!    [`crate::ca`] CA (a `webpki` path validation with the correct EKU). This is the trust-domain
//!    marker — like Chia, the CA is public, so this alone is not authentication.
//! 2. **peer_id pin.** `peer_id = SHA-256(SPKI DER)` is derived and, when the caller asked to reach a
//!    specific peer, must equal it. The derived id is always captured so the caller learns who it
//!    connected to. rustls itself proves the peer holds the leaf's private key (handshake signature),
//!    so a pinned `peer_id` is a real authentication.
//! 3. **BLS-G1 binding (#1204).** Under the configured [`BindingPolicy`], the leaf's BLS binding is
//!    verified and the bound BLS pubkey captured (the seal target). `Required` fails closed on an
//!    absent or invalid binding (anti-downgrade).
//!
//! The chain check deliberately does NOT verify a server name (DIG peers dial by IP and authenticate
//! by peer_id + binding, not by hostname), so the same verifiers work in both handshake directions.

use std::sync::{Arc, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error as TlsError, SignatureScheme};
use webpki::{anchor_from_trusted_cert, EndEntityCert, KeyUsage};

use crate::binding::{evaluate, verify_binding_from_leaf_cert, BindingPolicy};
use crate::ca::embedded_ca_cert_der;
use crate::error::Result;
use crate::identity::{peer_id_from_leaf_cert_der, PeerId};

/// The `peer_id` a verifier derived from the certificate the peer presented, captured for the caller.
/// Shared via `Arc<Mutex<_>>` because rustls verifiers are `Sync` and run inside the handshake.
#[derive(Debug, Default, Clone)]
pub struct CapturedPeerId(pub Arc<Mutex<Option<PeerId>>>);

impl CapturedPeerId {
    /// The `peer_id` derived from the peer's certificate, if the handshake reached cert verification.
    pub fn get(&self) -> Option<PeerId> {
        *self.0.lock().unwrap()
    }
}

/// The peer's verified BLS G1 identity pubkey, captured from the #1204 cert binding when the
/// handshake carried a valid one. `None` means no valid binding was presented (a legacy peer under
/// [`BindingPolicy::Opportunistic`], or [`BindingPolicy::Off`]). The sealing layer seals to this key.
#[derive(Debug, Default, Clone)]
pub struct CapturedBlsPub(pub Arc<Mutex<Option<[u8; 48]>>>);

impl CapturedBlsPub {
    /// The verified BLS G1 pubkey the peer's `peer_id` is bound to, if a valid binding was presented.
    pub fn get(&self) -> Option<[u8; 48]> {
        *self.0.lock().unwrap()
    }
}

/// ECDSA signature algorithms accepted for the CA→leaf chain signature. DIG certs are ECDSA P-256
/// (both CA and leaf); the P-384 entries are harmless future-proofing.
const CHAIN_SIG_ALGS: &[&dyn webpki::types::SignatureVerificationAlgorithm] = &[
    webpki::ring::ECDSA_P256_SHA256,
    webpki::ring::ECDSA_P256_SHA384,
    webpki::ring::ECDSA_P384_SHA256,
    webpki::ring::ECDSA_P384_SHA384,
];

/// Verify that `end_entity` chains to the shipped DigNetwork CA for `usage`, ignoring any server
/// name. Returns a rustls [`TlsError`] on any failure so it can be returned straight from a verifier.
fn verify_chain_to_dig_ca(
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    now: UnixTime,
    usage: KeyUsage,
) -> std::result::Result<(), TlsError> {
    let ca_der =
        embedded_ca_cert_der().map_err(|e| TlsError::General(format!("DigNetwork CA: {e}")))?;
    let anchor = anchor_from_trusted_cert(&ca_der).map_err(|e| {
        TlsError::General(format!("DigNetwork CA is not a valid trust anchor: {e}"))
    })?;
    let ee = EndEntityCert::try_from(end_entity)
        .map_err(|e| TlsError::General(format!("peer leaf is not a valid certificate: {e}")))?;
    ee.verify_for_usage(
        CHAIN_SIG_ALGS,
        &[anchor],
        intermediates,
        now,
        usage,
        None,
        None,
    )
    .map_err(|e| {
        TlsError::General(format!(
            "peer leaf does not chain to the DigNetwork CA: {e}"
        ))
    })?;
    Ok(())
}

/// Derive the peer_id, enforce the pin, and apply the BLS-binding policy — the shared tail of both
/// the client-side and server-side verifiers. Returns the derived `peer_id` on success.
fn pin_and_bind(
    end_entity: &CertificateDer<'_>,
    expected: Option<PeerId>,
    captured: &CapturedPeerId,
    binding_policy: BindingPolicy,
    captured_bls: &CapturedBlsPub,
) -> std::result::Result<PeerId, TlsError> {
    let derived = peer_id_from_leaf_cert_der(end_entity.as_ref()).ok_or_else(|| {
        TlsError::General("peer leaf certificate could not be parsed as X.509".to_string())
    })?;
    // Record who we connected to regardless of the pin outcome.
    *captured.0.lock().unwrap() = Some(derived);
    if let Some(expected) = expected {
        if derived != expected {
            return Err(TlsError::General(format!(
                "peer_id mismatch: expected {expected}, got {derived}"
            )));
        }
    }
    if binding_policy != BindingPolicy::Off {
        let outcome = verify_binding_from_leaf_cert(end_entity.as_ref());
        match evaluate(&outcome, binding_policy) {
            Ok(bls_pub) => *captured_bls.0.lock().unwrap() = bls_pub,
            Err(reason) => {
                return Err(TlsError::General(format!(
                    "peer {derived} rejected by cert BLS binding policy: {reason}"
                )))
            }
        }
    }
    Ok(derived)
}

/// The signature schemes ring's provider supports (for `supported_verify_schemes`).
fn default_signature_schemes() -> Vec<SignatureScheme> {
    rustls::crypto::ring::default_provider()
        .signature_verification_algorithms
        .supported_schemes()
}

fn verify_tls12(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> std::result::Result<HandshakeSignatureValid, TlsError> {
    rustls::crypto::verify_tls12_signature(
        message,
        cert,
        dss,
        &rustls::crypto::ring::default_provider().signature_verification_algorithms,
    )
}

fn verify_tls13(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> std::result::Result<HandshakeSignatureValid, TlsError> {
    rustls::crypto::verify_tls13_signature(
        message,
        cert,
        dss,
        &rustls::crypto::ring::default_provider().signature_verification_algorithms,
    )
}

/// Client-side verifier: verifies the SERVER's leaf chains to the DigNetwork CA (serverAuth), pins
/// its `peer_id`, and checks the BLS binding.
#[derive(Debug)]
pub struct DigServerCertVerifier {
    expected: Option<PeerId>,
    captured: CapturedPeerId,
    binding_policy: BindingPolicy,
    captured_bls: CapturedBlsPub,
    schemes: Vec<SignatureScheme>,
}

impl DigServerCertVerifier {
    /// Build a verifier that pins `expected` (or accepts any DigNetwork-CA peer when `None`), captures
    /// the derived id + BLS pubkey, and applies `binding_policy`.
    pub fn new(
        expected: Option<PeerId>,
        captured: CapturedPeerId,
        binding_policy: BindingPolicy,
        captured_bls: CapturedBlsPub,
    ) -> Self {
        Self {
            expected,
            captured,
            binding_policy,
            captured_bls,
            schemes: default_signature_schemes(),
        }
    }
}

impl ServerCertVerifier for DigServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, TlsError> {
        verify_chain_to_dig_ca(end_entity, intermediates, now, KeyUsage::server_auth())?;
        pin_and_bind(
            end_entity,
            self.expected,
            &self.captured,
            self.binding_policy,
            &self.captured_bls,
        )?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        verify_tls12(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        verify_tls13(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }
}

/// Server-side verifier: verifies the CLIENT's leaf chains to the DigNetwork CA (clientAuth), pins
/// its `peer_id`, and checks the BLS binding. Client auth is MANDATORY — this is mutual TLS.
#[derive(Debug)]
pub struct DigClientCertVerifier {
    expected: Option<PeerId>,
    captured: CapturedPeerId,
    binding_policy: BindingPolicy,
    captured_bls: CapturedBlsPub,
    schemes: Vec<SignatureScheme>,
    root_hints: Vec<DistinguishedName>,
}

impl DigClientCertVerifier {
    /// Build a verifier that requires a client leaf chaining to the DigNetwork CA, pins `expected`
    /// (or accepts any such peer when `None`), captures the derived id + BLS pubkey, and applies
    /// `binding_policy`.
    pub fn new(
        expected: Option<PeerId>,
        captured: CapturedPeerId,
        binding_policy: BindingPolicy,
        captured_bls: CapturedBlsPub,
    ) -> Self {
        Self {
            expected,
            captured,
            binding_policy,
            captured_bls,
            schemes: default_signature_schemes(),
            root_hints: Vec::new(),
        }
    }
}

impl ClientCertVerifier for DigClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.root_hints
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, TlsError> {
        verify_chain_to_dig_ca(end_entity, intermediates, now, KeyUsage::client_auth())?;
        pin_and_bind(
            end_entity,
            self.expected,
            &self.captured,
            self.binding_policy,
            &self.captured_bls,
        )?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        verify_tls12(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        verify_tls13(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }
}

/// A `webpki` trust anchor over the shipped DigNetwork CA — exposed so a consumer that builds its own
/// rustls config (rather than using [`crate::config`]) can reuse the same trust root.
pub fn dig_ca_trust_anchor_der() -> Result<CertificateDer<'static>> {
    embedded_ca_cert_der()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls::{public_key_bytes, SecretKey};
    use crate::ca::DigCa;
    use crate::node_cert::NodeCert;
    use rcgen::{
        CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, Ia5String, KeyPair,
        KeyUsagePurpose, SanType, PKCS_ECDSA_P256_SHA256,
    };
    use sha2::{Digest, Sha256};
    use time::OffsetDateTime;

    fn bls_sk(label: &str) -> SecretKey {
        let seed: [u8; 32] = Sha256::digest(label.as_bytes()).into();
        SecretKey::from_seed(&seed)
    }

    /// Mint a leaf signed by the SHIPPED DigNetwork CA but WITHOUT the #1204 binding extension.
    fn unbound_dig_ca_leaf() -> CertificateDer<'static> {
        let ca = DigCa::embedded().expect("embedded CA");
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "peer.dig");
        params.distinguished_name = dn;
        params.subject_alt_names = vec![SanType::DnsName(
            Ia5String::try_from("peer.dig".to_string()).unwrap(),
        )];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let cert = params.signed_by(&leaf_key, &ca.cert, &ca.key).unwrap();
        CertificateDer::from(cert.der().to_vec())
    }

    /// Under `Required`, a DigNetwork-CA-signed leaf that carries NO binding is rejected by the
    /// client verifier (anti-downgrade), even though its chain-to-CA is valid.
    #[test]
    fn required_rejects_ca_signed_unbound_leaf() {
        let leaf = unbound_dig_ca_leaf();
        let v = DigClientCertVerifier::new(
            None,
            CapturedPeerId::default(),
            BindingPolicy::Required,
            CapturedBlsPub::default(),
        );
        let err = v
            .verify_client_cert(&leaf, &[], UnixTime::now())
            .expect_err("Required rejects an unbound leaf");
        assert!(
            format!("{err}").contains("BLS binding"),
            "rejected on the binding, not the chain"
        );
    }

    /// A bound, DigNetwork-CA-signed leaf verifies AND captures the peer_id + BLS pubkey under
    /// `Required` (the verifier's accept path, exercised without a socket).
    #[test]
    fn required_accepts_bound_leaf_and_captures_identity() {
        let sk = bls_sk("verify/bound");
        let node = NodeCert::generate_signed(&sk).expect("node cert");
        let leaf = CertificateDer::from(node.cert_der().to_vec());

        let captured = CapturedPeerId::default();
        let captured_bls = CapturedBlsPub::default();
        let v = DigClientCertVerifier::new(
            None,
            captured.clone(),
            BindingPolicy::Required,
            captured_bls.clone(),
        );
        v.verify_client_cert(&leaf, &[], UnixTime::now())
            .expect("a bound DIG-CA leaf verifies");
        assert_eq!(captured.get(), Some(node.peer_id()));
        assert_eq!(captured_bls.get(), Some(public_key_bytes(&sk)));
    }

    /// A foreign-CA leaf fails the chain check regardless of policy.
    #[test]
    fn foreign_ca_leaf_fails_chain() {
        let foreign = crate::ca::generate_dig_ca(OffsetDateTime::now_utc()).unwrap();
        let foreign_ca = DigCa::from_pem(&foreign.cert_pem, &foreign.key_pem).unwrap();
        let node = NodeCert::generate_signed_by(
            &foreign_ca,
            &bls_sk("verify/foreign"),
            OffsetDateTime::now_utc(),
        )
        .unwrap();
        let leaf = CertificateDer::from(node.cert_der().to_vec());

        let v = DigServerCertVerifier::new(
            None,
            CapturedPeerId::default(),
            BindingPolicy::Off,
            CapturedBlsPub::default(),
        );
        let name = ServerName::try_from("peer.dig").unwrap();
        let err = v
            .verify_server_cert(&leaf, &[], &name, &[], UnixTime::now())
            .expect_err("foreign CA leaf is rejected");
        assert!(format!("{err}").contains("DigNetwork CA"));
    }
}
