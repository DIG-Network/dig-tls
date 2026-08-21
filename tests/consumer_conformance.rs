//! Consumer conformance — the canonical certificate parameters every DIG peer connection agrees on.
//!
//! `dig-tls` is the ONE place a DIG peer mTLS certificate is built (#1269). Several consumers still
//! carry their own copy of this logic and must migrate onto this crate; the assertions here are the
//! contract those adoption PRs check themselves against, so a drift in EITHER direction — a change
//! to dig-tls, or a consumer that re-derives an identity differently — turns this file red.
//!
//! Each test states the property it pins and the wrong implementation it is built to distinguish.
//! `tests/mtls_handshake.rs` proves the configs interoperate end to end; this file proves the
//! *parameters* are the ones consumers depend on.

use dig_tls::binding::BindingPolicy;
use dig_tls::bls::SecretKey;
use dig_tls::node_cert::{NodeCert, LEAF_LIFETIME};
use dig_tls::verify::{CapturedBlsPub, CapturedPeerId, DigClientCertVerifier};
use dig_tls::{peer_id_from_leaf_cert_der, peer_id_from_tls_spki_der};

use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::ClientCertVerifier;
use sha2::{Digest, Sha256};
use std::time::{Duration as StdDuration, SystemTime};

/// A deterministic BLS identity key, so a failure reproduces exactly.
fn bls_sk(label: &str) -> SecretKey {
    let mut seed = [0u8; 32];
    let bytes = label.as_bytes();
    seed[..bytes.len().min(32)].copy_from_slice(&bytes[..bytes.len().min(32)]);
    SecretKey::from_seed(&seed)
}

/// A self-signed ECDSA P-256 leaf built OUTSIDE dig-tls, keeping the key pair so the test can reach
/// the SubjectPublicKeyInfo by a path that never touches this crate's own X.509 parsing.
fn foreign_leaf() -> (KeyPair, CertificateDer<'static>) {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("generate P-256 key");
    let params = CertificateParams::new(vec!["conformance.peer.dig".to_string()])
        .expect("certificate params");
    let cert = params.self_signed(&key).expect("self-sign leaf");
    (key, CertificateDer::from(cert.der().to_vec()))
}

/// **Property:** `peer_id == SHA-256(TLS SubjectPublicKeyInfo DER)`.
///
/// The two sides are derived independently: the expected value walks *key → SPKI DER* through
/// `rcgen`, while dig-tls walks *certificate → X.509 parse → SPKI*. A change to either side breaks
/// the equality, which is the point — this is the ecosystem's peer-identity contract, and two crates
/// computing it differently means two nodes computing different ids for the same peer.
#[test]
fn peer_id_is_sha256_of_the_spki_der_derived_independently() {
    let (key, cert_der) = foreign_leaf();

    // Independent path: rcgen hands back the PKIX SubjectPublicKeyInfo DER for the key it generated.
    let spki_der = key.public_key_der();
    let expected: [u8; 32] = Sha256::digest(&spki_der).into();

    let derived = peer_id_from_leaf_cert_der(cert_der.as_ref()).expect("leaf parses");
    assert_eq!(
        derived.as_bytes(),
        &expected,
        "peer_id must be SHA-256 over the SPKI DER lifted from the leaf"
    );

    // The two nearest wrong implementations must be distinguishable ON THIS FIXTURE, otherwise the
    // assertion above would pass for a crate that hashes the wrong bytes.
    let whole_cert: [u8; 32] = Sha256::digest(cert_der.as_ref()).into();
    assert_ne!(
        derived.as_bytes(),
        &whole_cert,
        "hashing the whole certificate must not coincide with the canonical peer_id"
    );
    let bare_key: [u8; 32] = Sha256::digest(key.public_key_raw()).into();
    assert_ne!(
        derived.as_bytes(),
        &bare_key,
        "hashing the bare public-key bytes must not coincide with the canonical peer_id"
    );
}

/// **Property:** the id a `NodeCert` reports about itself is the id a peer derives from the
/// certificate it presents. A cached or separately-computed `peer_id()` that drifts from the wire
/// derivation would make a node advertise an identity nobody else computes.
#[test]
fn node_cert_self_reported_peer_id_matches_the_wire_derivation() {
    let node = NodeCert::generate_signed(&bls_sk("conformance-node")).expect("mint node cert");

    let from_wire = peer_id_from_leaf_cert_der(node.cert_der()).expect("node leaf parses");
    assert_eq!(node.peer_id(), from_wire);
    assert_eq!(node.peer_id(), peer_id_from_tls_spki_der(node.spki_der()));
}

/// **Property:** the canonical leaf is ECDSA P-256.
///
/// The key type is part of the identity contract, not a preference: it fixes the SPKI encoding every
/// peer hashes, and it is what a consumer's own generator must match to keep ids comparable. Pinned
/// by OID so a silent switch to Ed25519 or RSA fails here rather than at a peer that cannot verify.
#[test]
fn canonical_leaf_key_is_ecdsa_p256() {
    let node = NodeCert::generate_signed(&bls_sk("conformance-keytype")).expect("mint node cert");
    let (_, x509) = x509_parser::parse_x509_certificate(node.cert_der()).expect("leaf parses");

    let spki = &x509.tbs_certificate.subject_pki;
    assert_eq!(
        spki.algorithm.algorithm.to_id_string(),
        "1.2.840.10045.2.1",
        "leaf public key algorithm must be id-ecPublicKey"
    );
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .expect("EC parameters present")
        .as_oid()
        .expect("EC parameters are a named curve OID");
    assert_eq!(
        curve.to_id_string(),
        "1.2.840.10045.3.1.7",
        "leaf curve must be prime256v1 (P-256)"
    );
}

/// **Property:** the leaf validity window is exactly 3650 days plus the one-hour clock-skew
/// backdate, and it is live now.
///
/// The span is written as a LITERAL rather than derived from [`LEAF_LIFETIME`] on purpose. Deriving
/// it from the same constant the certificate is built from is circular — both sides move together,
/// so the assertion holds for any value and pins nothing. Confirmed live: with the expectation read
/// from the constant, shortening `LEAF_LIFETIME` to nine years left this test green.
///
/// Pinned from both sides — an exact span, not a lower bound — because a bound checked only from
/// below can only confirm itself. A consumer minting a shorter-lived cert would silently drop peers
/// mid-session; one minting a longer-lived cert would outlive the rotation model.
#[test]
fn canonical_leaf_validity_window_is_exactly_the_published_span() {
    const LEAF_DAYS: i64 = 3650;
    const SKEW_BACKDATE_SECS: i64 = 60 * 60;
    const SECS_PER_DAY: i64 = 24 * 60 * 60;

    // The published constant is itself part of the contract consumers read, so pin it too.
    assert_eq!(
        LEAF_LIFETIME.whole_days(),
        LEAF_DAYS,
        "the published LEAF_LIFETIME consumers read must stay 3650 days"
    );

    let node = NodeCert::generate_signed(&bls_sk("conformance-window")).expect("mint node cert");
    let (_, x509) = x509_parser::parse_x509_certificate(node.cert_der()).expect("leaf parses");

    let not_before = x509.validity().not_before.timestamp();
    let not_after = x509.validity().not_after.timestamp();

    assert_eq!(
        not_after - not_before,
        LEAF_DAYS * SECS_PER_DAY + SKEW_BACKDATE_SECS,
        "leaf span must be 3650 days + the one-hour clock-skew backdate, exactly"
    );

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs() as i64;
    assert!(
        not_before < now && now < not_after,
        "a freshly minted leaf must be valid right now"
    );
}

/// **Property:** client authentication is MANDATORY in both trust modes.
///
/// Every DIG peer connection is mutual TLS. A verifier that merely *offers* client auth accepts an
/// anonymous peer and leaves it with no derivable `peer_id` at all, so this is checked on the
/// SPKI-pinned mode as well as the CA-requiring one — the SPKI-pinned mode is the one consumers on
/// the no-CA model will adopt, and it is the one where the mistake would go unnoticed.
#[test]
fn both_trust_modes_require_a_client_certificate() {
    for (label, verifier) in [
        (
            "ca-requiring",
            DigClientCertVerifier::new(
                None,
                CapturedPeerId::default(),
                BindingPolicy::Off,
                CapturedBlsPub::default(),
            ),
        ),
        (
            "spki-pinned",
            DigClientCertVerifier::new_spki_pinned(
                None,
                CapturedPeerId::default(),
                BindingPolicy::Off,
                CapturedBlsPub::default(),
            ),
        ),
    ] {
        assert!(
            verifier.offer_client_auth(),
            "{label}: must request a client certificate"
        );
        assert!(
            verifier.client_auth_mandatory(),
            "{label}: an anonymous client must fail the handshake"
        );
    }
}

/// **Property:** a client leaf that does not parse as X.509 is REJECTED, in the SPKI-pinned mode
/// too.
///
/// This is the clause a "CA-agnostic" verifier is most likely to get wrong, because dropping the
/// chain check reads as "accept anything" — and an unparseable leaf has no SubjectPublicKeyInfo, so
/// accepting it admits a connection whose `peer_id` is *underivable*. The fixture is deliberately
/// garbage rather than a foreign-CA cert: a foreign-CA cert distinguishes CA-checking from
/// CA-agnostic, whereas this distinguishes CA-agnostic from unconditional acceptance, and only the
/// second is what the pinned mode must not become.
#[test]
fn spki_pinned_mode_still_rejects_an_unparseable_client_leaf() {
    let captured = CapturedPeerId::default();
    let verifier = DigClientCertVerifier::new_spki_pinned(
        None,
        captured.clone(),
        BindingPolicy::Off,
        CapturedBlsPub::default(),
    );
    let now = UnixTime::since_unix_epoch(StdDuration::from_secs(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs(),
    ));

    let garbage = CertificateDer::from(b"not a certificate".to_vec());
    assert!(
        verifier.verify_client_cert(&garbage, &[], now).is_err(),
        "an unparseable client leaf must be rejected even without a CA-chain requirement"
    );
    assert_eq!(
        captured.get(),
        None,
        "a rejected leaf must not leave a captured peer_id behind"
    );

    // Control: the SAME verifier accepts a well-formed self-signed leaf, so the rejection above is
    // the parse failing and not the pinned mode refusing everything.
    let (_, leaf) = foreign_leaf();
    assert!(
        verifier.verify_client_cert(&leaf, &[], now).is_ok(),
        "SPKI-pinned mode must accept a well-formed self-signed peer leaf"
    );
    assert_eq!(
        captured.get(),
        peer_id_from_leaf_cert_der(leaf.as_ref()),
        "an accepted leaf's peer_id must be captured for the caller"
    );
}
