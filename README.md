# dig-tls

The canonical mTLS certificate every DIG peer connection uses. dig-tls mirrors the
`chia-blockchain` / `chia-tls` TLS model 1:1, swapping in a **DigNetwork** trust domain and layering
the #1204 BLS-G1 cert binding, so every DIG peer (dig-node, dig-relay, dig-gossip, dig-nat, dig-peer)
presents the same canonical cert shape.

## The model (Chia precedent — the CA is PUBLIC)

- **A shipped, PUBLIC DigNetwork CA.** The CA certificate *and* private key are both compiled into the
  crate — exactly as `chia-blockchain` ships `chia_ca.crt` + `chia_ca.key`. The CA key is **not a
  secret**; it is a shared trust-domain marker. No user step, no custody gate. Real authentication is
  the app-layer `peer_id` pin + BLS binding, never CA-key secrecy.
- **A per-peer node cert** generated locally at first run, signed by the DigNetwork CA, carrying the
  BLS binding, persisted so the peer keeps a stable identity.
- **`peer_id = SHA-256(TLS SPKI DER)`** — the transport identity (same as Chia's node id).
- **The #1204 BLS-G1 binding** — the cert self-attests the peer's BLS G1 key over its SPKI, binding
  `peer_id ↔ bls_pub` (the anti-substitution root of the recipient-seal family).

## Public API (the whole surface)

| Item | Purpose |
|------|---------|
| `NodeCert::generate_signed(bls_sk)` | Mint this peer's cert, signed by the shipped DigNetwork CA. |
| `NodeCert::load_or_generate(dir, bls_sk)` | Load a persisted cert or generate + persist a new one. |
| `NodeCert::peer_id()` / `spki_der()` / `cert_der()` / `cert_pem()` | Identity + material accessors. |
| `NodeCert::rotate(dir, new_bls_sk) -> RotatedNodeCert` | Mint a fresh identity (new `peer_id`) bound to a new BLS key; keeps the old in a `.prev` slot so the caller can dual-present. |
| `load_previous(dir)` / `retire_previous(dir)` | Reload the retiring identity after a restart; zeroize + delete it once re-announce converges. |
| `config::server_config(node, policy) -> ServerTls` | Inbound rustls mTLS config + capture handles. |
| `config::client_config(node, expected, policy) -> ClientTls` | Outbound config (pins `expected`). |
| `BindingPolicy` | `Off` / `Opportunistic` (default) / `Required` (fail-closed) for the BLS binding. |
| `PeerId`, `peer_id_from_tls_spki_der`, `peer_id_from_leaf_cert_der` | The canonical id derivation. |
| `binding::*` | The #1204 binding primitives (OID, encode/parse, `verify_binding_from_leaf_cert`). |
| `ca::{DigCa, embedded_ca_cert_der, generate_dig_ca}` | The DigNetwork CA loader + trust anchor. |
| `bls::*` | Raw-byte BLS G2 sign/verify + G1 subgroup check (zero DIG-crate deps). |

`ServerTls` / `ClientTls` each carry the `Arc<…Config>` plus `captured_peer_id` and `captured_bls`
handles you read AFTER the handshake to learn who connected.

```rust
use dig_tls::{BindingPolicy, config, NodeCert};

# fn demo(bls_sk: &dig_tls::bls::SecretKey) -> dig_tls::Result<()> {
let node = NodeCert::load_or_generate("/var/lib/dig/tls", bls_sk)?;

// Accept inbound peers (mutual TLS; verify a binding when present):
let server = config::server_config(&node, BindingPolicy::Opportunistic)?;

// Dial a specific peer, pinning its peer_id:
let peer = node.peer_id(); // in practice: the peer you resolved
let client = config::client_config(&node, Some(peer), BindingPolicy::Opportunistic)?;
# let _ = (server.config, client.config); Ok(()) }
```

## Hierarchy

**L00 (00-foundation)** — zero DIG-crate dependencies. BLS via `chia-bls` / `blst` on raw bytes; the
caller passes its BLS identity secret key in. Consumers reference it downward.

See [`SPEC.md`](./SPEC.md) for the normative contract (CA model, cert format, `peer_id` derivation,
BLS binding, mTLS config, security properties).

## The shipped DigNetwork CA

`src/ca/dig_ca.crt` + `src/ca/dig_ca.key` are the public DigNetwork CA, minted once via
`cargo run --example generate_ca`. **Do not re-run that generator** except for a deliberate,
coordinated trust-anchor rotation — it mints a NEW CA and would break every existing peer.

## License

Apache-2.0 OR MIT.
