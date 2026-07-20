//! End-to-end mutual-TLS handshake tests over a real loopback TCP socket.
//!
//! These prove the rustls configs [`dig_tls`] builds actually interoperate and enforce the trust
//! model: a peer whose cert chains to the shipped DigNetwork CA is accepted (with its peer_id + BLS
//! binding captured), a peer signed by a FOREIGN CA is rejected, and a peer_id pin mismatch is
//! rejected — in a real handshake, not just a unit check of the verifier logic.

use rustls::pki_types::ServerName;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use dig_tls::binding::BindingPolicy;
use dig_tls::bls::{public_key_bytes, SecretKey};
use dig_tls::ca::{generate_dig_ca, DigCa};
use dig_tls::node_cert::NodeCert;
use dig_tls::{client_config, server_config, PeerId};

fn bls_sk(label: &str) -> SecretKey {
    let seed: [u8; 32] = Sha256::digest(label.as_bytes()).into();
    SecretKey::from_seed(&seed)
}

/// The outcome of an attempted mutual-TLS handshake: whether it succeeded, and (on success) the
/// peer_id + BLS pubkey each side captured for the other.
struct HandshakeResult {
    client_ok: bool,
    server_ok: bool,
    server_saw_client: Option<PeerId>,
    client_saw_server: Option<PeerId>,
    server_saw_client_bls: Option<[u8; 48]>,
    client_saw_server_bls: Option<[u8; 48]>,
}

/// Run one mutual-TLS handshake between `server_node` (inbound) and `client_node` (outbound) over a
/// fresh loopback socket, `expected` pinning the server's peer_id on the client side.
async fn run_handshake(
    server_node: &NodeCert,
    client_node: &NodeCert,
    expected: Option<PeerId>,
    policy: BindingPolicy,
) -> HandshakeResult {
    let server = server_config(server_node, policy).expect("server config");
    let client = client_config(client_node, expected, policy).expect("client config");

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();

    let acceptor = TlsAcceptor::from(server.config.clone());
    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept tcp");
        match acceptor.accept(tcp).await {
            Ok(mut tls) => {
                // Read the client's one byte so the handshake fully completes before we inspect.
                let mut buf = [0u8; 1];
                let _ = tls.read(&mut buf).await;
                let _ = tls.write_all(b"y").await;
                true
            }
            Err(_) => false,
        }
    });

    let connector = TlsConnector::from(client.config.clone());
    let tcp = TcpStream::connect(addr).await.expect("connect tcp");
    let name = ServerName::try_from("peer.dig").unwrap();
    let client_ok = match connector.connect(name, tcp).await {
        Ok(mut tls) => {
            let _ = tls.write_all(b"x").await;
            let mut buf = [0u8; 1];
            let _ = tls.read(&mut buf).await;
            true
        }
        Err(_) => false,
    };
    let server_ok = server_task.await.unwrap_or(false);

    HandshakeResult {
        client_ok,
        server_ok,
        server_saw_client: server.captured_peer_id.get(),
        client_saw_server: client.captured_peer_id.get(),
        server_saw_client_bls: server.captured_bls.get(),
        client_saw_server_bls: client.captured_bls.get(),
    }
}

/// The happy path: two peers whose certs chain to the shipped DigNetwork CA complete mutual TLS, each
/// captures the other's peer_id, the client's peer_id pin holds, and the BLS bindings round-trip.
#[tokio::test]
async fn dig_ca_peers_handshake_and_capture_identity() {
    let server_sk = bls_sk("hs/server");
    let client_sk = bls_sk("hs/client");
    let server_node = NodeCert::generate_signed(&server_sk).expect("server cert");
    let client_node = NodeCert::generate_signed(&client_sk).expect("client cert");

    let r = run_handshake(
        &server_node,
        &client_node,
        Some(server_node.peer_id()),
        BindingPolicy::Required,
    )
    .await;

    assert!(r.client_ok, "client side of the handshake succeeded");
    assert!(r.server_ok, "server side of the handshake succeeded");
    assert_eq!(r.server_saw_client, Some(client_node.peer_id()));
    assert_eq!(r.client_saw_server, Some(server_node.peer_id()));
    assert_eq!(r.server_saw_client_bls, Some(public_key_bytes(&client_sk)));
    assert_eq!(r.client_saw_server_bls, Some(public_key_bytes(&server_sk)));
}

/// A client cert signed by a FOREIGN CA (not the DigNetwork CA) is rejected by the server's
/// chain-to-CA check — the handshake fails.
#[tokio::test]
async fn foreign_ca_client_cert_is_rejected() {
    let server_node = NodeCert::generate_signed(&bls_sk("hs/server2")).expect("server cert");

    // A leaf signed by a throwaway CA, NOT the shipped DigNetwork CA.
    let foreign_ca_material = generate_dig_ca(OffsetDateTime::now_utc()).unwrap();
    let foreign_ca = DigCa::from_pem(&foreign_ca_material.cert_pem, &foreign_ca_material.key_pem)
        .expect("foreign CA");
    let foreign_client = NodeCert::generate_signed_by(
        &foreign_ca,
        &bls_sk("hs/foreign"),
        OffsetDateTime::now_utc(),
    )
    .expect("foreign client cert");

    let r = run_handshake(
        &server_node,
        &foreign_client,
        None,
        BindingPolicy::Opportunistic,
    )
    .await;

    // The server enforces client auth: it rejects the foreign-CA client cert. (The client's own
    // `connect()` may return before the server's TLS 1.3 alert arrives — a well-known artifact — so
    // the load-bearing assertion is the server-side rejection.)
    assert!(!r.server_ok, "server rejects a foreign-CA client cert");
    assert_eq!(
        r.server_saw_client, None,
        "the foreign client's identity is never captured (rejected at the chain check)"
    );
}

/// A server cert signed by a FOREIGN CA is rejected by the client's chain-to-CA check.
#[tokio::test]
async fn foreign_ca_server_cert_is_rejected() {
    let foreign_ca_material = generate_dig_ca(OffsetDateTime::now_utc()).unwrap();
    let foreign_ca = DigCa::from_pem(&foreign_ca_material.cert_pem, &foreign_ca_material.key_pem)
        .expect("foreign CA");
    let foreign_server =
        NodeCert::generate_signed_by(&foreign_ca, &bls_sk("hs/fsrv"), OffsetDateTime::now_utc())
            .expect("foreign server cert");
    let client_node = NodeCert::generate_signed(&bls_sk("hs/client3")).expect("client cert");

    let r = run_handshake(
        &foreign_server,
        &client_node,
        None,
        BindingPolicy::Opportunistic,
    )
    .await;

    assert!(!r.client_ok, "client rejects a foreign-CA server cert");
}

/// Pinning the WRONG peer_id on the client rejects the connection even though the server cert is
/// valid and DigNetwork-CA-signed — the peer_id pin is a real authentication.
#[tokio::test]
async fn peer_id_pin_mismatch_is_rejected() {
    let server_node = NodeCert::generate_signed(&bls_sk("hs/server4")).expect("server cert");
    let client_node = NodeCert::generate_signed(&bls_sk("hs/client4")).expect("client cert");

    // Pin an id that is NOT the server's.
    let wrong = PeerId::from_bytes([0x11u8; 32]);
    let r = run_handshake(
        &server_node,
        &client_node,
        Some(wrong),
        BindingPolicy::Opportunistic,
    )
    .await;

    assert!(!r.client_ok, "a peer_id pin mismatch rejects the server");
}
