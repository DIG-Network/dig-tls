//! # dig-tls — the canonical mTLS certificate every DIG peer connection uses
//!
//! dig-tls is the single source of truth for DIG peer transport identity. It mirrors the
//! `chia-blockchain` / `chia-tls` TLS model 1:1, swapping in a **DigNetwork** trust domain and
//! layering the #1204 BLS-G1 cert binding. Every DIG peer (dig-node, dig-relay, dig-gossip, dig-nat,
//! dig-peer) presents the SAME canonical cert shape, so any two DIG peers speak mutual TLS with a
//! byte-identical `peer_id` derivation and binding.
//!
//! ## The model (Chia precedent — the CA is PUBLIC)
//!
//! - **A shipped, PUBLIC DigNetwork CA** ([`ca`]) — the CA certificate AND private key are both
//!   compiled into this crate, exactly as `chia-blockchain` ships `chia_ca.crt` + `chia_ca.key`. The
//!   CA key is intentionally NOT a secret: it is a shared trust-domain marker, so there is no user
//!   step and no custody gate. Real authentication comes from the app layer (peer_id pin + BLS
//!   binding), never from CA-key secrecy.
//! - **A per-peer node cert** ([`node_cert::NodeCert`]) generated locally at first run, signed by the
//!   DigNetwork CA, carrying the BLS binding. Persisted so a peer keeps a stable identity.
//! - **`peer_id = SHA-256(TLS SPKI DER)`** ([`identity`]) — the transport identity (same as Chia's
//!   node id).
//! - **The #1204 BLS-G1 binding** ([`binding`]) — the cert self-attests the peer's BLS G1 identity
//!   key over its SPKI, cryptographically binding `peer_id ↔ bls_pub` (the anti-substitution root of
//!   the recipient-seal family).
//! - **Ready rustls mutual-auth configs** ([`config`]) — [`config::server_config`] /
//!   [`config::client_config`] wire the DigNetwork-CA chain check, peer_id pinning, and BLS-binding
//!   verification, and hand back the handles that capture WHO connected.
//!
//! ## Quick start
//!
//! ```no_run
//! use dig_tls::{binding::BindingPolicy, config, node_cert::NodeCert};
//! # fn demo(bls_sk: &dig_tls::bls::SecretKey) -> dig_tls::Result<()> {
//! // At first run: mint (or load) this peer's cert, signed by the shipped DigNetwork CA.
//! let node = NodeCert::load_or_generate("/var/lib/dig/tls", bls_sk)?;
//!
//! // Accept inbound peers (mutual TLS, verify-if-present binding):
//! let server = config::server_config(&node, BindingPolicy::Opportunistic)?;
//!
//! // Dial a specific peer, pinning its peer_id:
//! let expected = node.peer_id(); // in practice: the peer you resolved
//! let client = config::client_config(&node, Some(expected), BindingPolicy::Opportunistic)?;
//! # let _ = (server.config, client.config); Ok(())
//! # }
//! ```
//!
//! Hierarchy: **L00 (00-foundation)** — zero DIG-crate dependencies (BLS via `chia-bls`/`blst` on raw
//! bytes). See `SPEC.md` for the normative contract.

pub mod binding;
pub mod bls;
pub mod ca;
pub mod config;
pub mod error;
pub mod identity;
pub mod node_cert;
pub mod verify;

// --- The curated public facade: the handful of names most consumers reach for, re-exported at the
// crate root so a caller need not know the internal module split (§6.2 LLM-lookup surface). ---

pub use binding::BindingPolicy;
pub use config::{client_config, server_config, ClientTls, ServerTls};
pub use error::{DigTlsError, Result};
pub use identity::{peer_id_from_leaf_cert_der, peer_id_from_tls_spki_der, PeerId};
pub use node_cert::NodeCert;
