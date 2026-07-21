//! Ready-to-use rustls mutual-auth configurations for a DIG peer.
//!
//! These are the two entry points most consumers want: give them a [`NodeCert`] and a
//! [`BindingPolicy`] and they return a rustls config wired with the DigNetwork-CA verifier, peer_id
//! pinning, and BLS-binding checking, plus the capture handles to read WHO connected after the
//! handshake completes. Both configs pin the `ring` crypto provider explicitly, so a consumer never
//! has to install a process-default provider (and never risks the "multiple CryptoProviders" panic).

use std::sync::Arc;

use rustls::{ClientConfig, ServerConfig};

use crate::binding::BindingPolicy;
use crate::error::{DigTlsError, Result};
use crate::identity::PeerId;
use crate::node_cert::NodeCert;
use crate::verify::{CapturedBlsPub, CapturedPeerId, DigClientCertVerifier, DigServerCertVerifier};

/// A server-side (inbound) mTLS configuration plus the handles that capture the connecting peer's
/// identity after the handshake.
pub struct ServerTls {
    /// The rustls server configuration to hand to your TLS acceptor.
    pub config: Arc<ServerConfig>,
    /// The `peer_id` of the client that connected (populated during the handshake).
    pub captured_peer_id: CapturedPeerId,
    /// The BLS G1 pubkey the client's `peer_id` is bound to (populated when a valid binding was seen).
    pub captured_bls: CapturedBlsPub,
}

/// A client-side (outbound) mTLS configuration plus the handles that capture the server peer's
/// identity after the handshake.
pub struct ClientTls {
    /// The rustls client configuration to hand to your TLS connector.
    pub config: Arc<ClientConfig>,
    /// The `peer_id` of the server that answered (populated during the handshake).
    pub captured_peer_id: CapturedPeerId,
    /// The BLS G1 pubkey the server's `peer_id` is bound to (populated when a valid binding was seen).
    pub captured_bls: CapturedBlsPub,
}

fn ring_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Build an inbound (server) mTLS config that presents `node`'s cert, REQUIRES a client cert chaining
/// to the DigNetwork CA, and applies `binding_policy` to the client's #1204 binding. Accepts any
/// DigNetwork-CA peer as the client (servers do not pin a specific caller); read
/// [`ServerTls::captured_peer_id`] after the handshake to learn who connected.
pub fn server_config(node: &NodeCert, binding_policy: BindingPolicy) -> Result<ServerTls> {
    let captured_peer_id = CapturedPeerId::default();
    let captured_bls = CapturedBlsPub::default();
    let verifier = Arc::new(DigClientCertVerifier::new(
        None,
        captured_peer_id.clone(),
        binding_policy,
        captured_bls.clone(),
    ));
    let config = ServerConfig::builder_with_provider(ring_provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| DigTlsError::RustlsConfig(format!("protocol versions: {e}")))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(node.rustls_cert_chain(), node.rustls_private_key())
        .map_err(|e| DigTlsError::RustlsConfig(format!("server single cert: {e}")))?;
    Ok(ServerTls {
        config: Arc::new(config),
        captured_peer_id,
        captured_bls,
    })
}

/// Build an outbound (client) mTLS config that presents `node`'s cert and verifies the server's leaf
/// chains to the DigNetwork CA, pinning `expected` (or accepting any DigNetwork-CA peer when `None`)
/// and applying `binding_policy` to the server's #1204 binding. Read [`ClientTls::captured_peer_id`]
/// after the handshake to learn who answered.
pub fn client_config(
    node: &NodeCert,
    expected: Option<PeerId>,
    binding_policy: BindingPolicy,
) -> Result<ClientTls> {
    let captured_peer_id = CapturedPeerId::default();
    let captured_bls = CapturedBlsPub::default();
    let verifier = Arc::new(DigServerCertVerifier::new(
        expected,
        captured_peer_id.clone(),
        binding_policy,
        captured_bls.clone(),
    ));
    let config = ClientConfig::builder_with_provider(ring_provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| DigTlsError::RustlsConfig(format!("protocol versions: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(node.rustls_cert_chain(), node.rustls_private_key())
        .map_err(|e| DigTlsError::RustlsConfig(format!("client auth cert: {e}")))?;
    Ok(ClientTls {
        config: Arc::new(config),
        captured_peer_id,
        captured_bls,
    })
}

/// Build an inbound (server) mTLS config exactly like [`server_config`], EXCEPT it does not require
/// the connecting client's leaf to chain to the DigNetwork CA — it accepts a SELF-SIGNED leaf and
/// authenticates it by `peer_id = SHA-256(SPKI DER)` + rustls proof-of-possession + the #1204 BLS
/// binding (under `binding_policy`).
///
/// Use this on the live network, where DIG peers still present self-signed / chia-ssl certs (the
/// DIG-CA-everywhere migration #1378 is deferred), so the CA-requiring [`server_config`] would reject
/// every legit peer with `UnknownIssuer` (#1422; mirrors dig-gossip #1371). Read
/// [`ServerTls::captured_peer_id`] after the handshake to learn who connected.
pub fn server_config_spki_pinned(
    node: &NodeCert,
    binding_policy: BindingPolicy,
) -> Result<ServerTls> {
    let captured_peer_id = CapturedPeerId::default();
    let captured_bls = CapturedBlsPub::default();
    let verifier = Arc::new(DigClientCertVerifier::new_spki_pinned(
        None,
        captured_peer_id.clone(),
        binding_policy,
        captured_bls.clone(),
    ));
    let config = ServerConfig::builder_with_provider(ring_provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| DigTlsError::RustlsConfig(format!("protocol versions: {e}")))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(node.rustls_cert_chain(), node.rustls_private_key())
        .map_err(|e| DigTlsError::RustlsConfig(format!("server single cert: {e}")))?;
    Ok(ServerTls {
        config: Arc::new(config),
        captured_peer_id,
        captured_bls,
    })
}

/// Build an outbound (client) mTLS config exactly like [`client_config`], EXCEPT it does not require
/// the server's leaf to chain to the DigNetwork CA — it accepts a SELF-SIGNED leaf and authenticates
/// it by `peer_id = SHA-256(SPKI DER)` pinning of `expected` (or accept-any when `None`) + rustls
/// proof-of-possession + the #1204 BLS binding (under `binding_policy`).
///
/// This is dig-nat's auto-dialer entry point for the live network's self-signed peers (#1422; #1378
/// CA-everywhere deferred; mirrors dig-gossip #1371). Read [`ClientTls::captured_peer_id`] after the
/// handshake to learn who answered.
///
/// **SAFETY / USAGE CONTRACT:** Unlike CA mode (where accept-any at least enforces the DIG trust
/// domain), SPKI-pinned mode drops the CA check, so passing `expected: None` together with a
/// non-`Required` `BindingPolicy` authenticates NOTHING about which peer answered — any peer
/// presenting any self-signed leaf is accepted, and an active MITM is undetectable. A dialer MUST
/// pass `expected: Some(peer_id)` (or use `BindingPolicy::Required`) to authenticate the specific
/// peer. See #1422 / #1371.
pub fn client_config_spki_pinned(
    node: &NodeCert,
    expected: Option<PeerId>,
    binding_policy: BindingPolicy,
) -> Result<ClientTls> {
    let captured_peer_id = CapturedPeerId::default();
    let captured_bls = CapturedBlsPub::default();
    let verifier = Arc::new(DigServerCertVerifier::new_spki_pinned(
        expected,
        captured_peer_id.clone(),
        binding_policy,
        captured_bls.clone(),
    ));
    let config = ClientConfig::builder_with_provider(ring_provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| DigTlsError::RustlsConfig(format!("protocol versions: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(node.rustls_cert_chain(), node.rustls_private_key())
        .map_err(|e| DigTlsError::RustlsConfig(format!("client auth cert: {e}")))?;
    Ok(ClientTls {
        config: Arc::new(config),
        captured_peer_id,
        captured_bls,
    })
}
