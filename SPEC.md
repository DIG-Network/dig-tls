# dig-tls — normative specification

`dig-tls` is the canonical definition of the mutual-TLS certificate every DIG peer connection uses.
An independent reimplementation built against this document interoperates byte-for-byte with the
reference crate. dig-tls mirrors the `chia-blockchain` / `chia-tls` TLS model, swapping in a
DigNetwork trust domain and layering the #1204 BLS-G1 cert binding.

This is a **contract**. The values marked *canonical* (the DigNetwork CA material, the binding OID,
the signing context, the `peer_id` derivation) MUST NOT drift; they are recorded in the superproject
`canonical` skill and `SYSTEM.md`.

## 1. Trust model — a shipped, PUBLIC DigNetwork CA

- dig-tls ships ONE Certificate Authority whose certificate **and private key are BOTH public**,
  compiled into the crate (`src/ca/dig_ca.crt`, `src/ca/dig_ca.key`). This mirrors Chia, which ships
  `chia_ca.crt` + `chia_ca.key` publicly.
- The CA private key is **intentionally not a secret**. It is a shared trust-domain marker, not a
  gate. There is no user step, no custody ceremony, and no runtime PKI service. Any party can mint a
  leaf that chains to the DigNetwork CA — this is by design.
- **Real authentication is at the application layer**, NEVER from CA-key secrecy:
  - the `peer_id = SHA-256(SPKI DER)` pin (§3), authenticated because rustls proves the peer holds
    the leaf's private key during the handshake; and
  - the #1204 BLS-G1 cert binding (§4), which binds `peer_id ↔ bls_pub`.
- The CA is ECDSA P-256, `CA:TRUE` with path length 0 (it signs only end-entity leaves), key usages
  `keyCertSign` + `cRLSign`, ~100-year validity, and NO name constraints (DIG peers carry no
  meaningful hostname). The CA is a fixed, long-lived anchor; rotation is a deliberate, coordinated,
  ecosystem-wide protocol event, never automatic.

## 2. Per-peer node certificate

- Each peer generates ONE leaf at first run (mirroring Chia's `create_all_ssl`) and persists it, so
  its `peer_id` is stable across restarts. Files: `node.crt`, `node.key` under a caller-chosen dir.
- The leaf is ECDSA P-256, signed by the DigNetwork CA, valid `now − 1h .. now + 10y`, with:
  - key usage `digitalSignature`;
  - extended key usages **`serverAuth` AND `clientAuth`** — the same leaf authenticates in BOTH
    directions of the mutual-TLS handshake;
  - a single non-load-bearing SAN `DnsName("peer.dig")` (verifiers do NOT check the server name);
  - the #1204 BLS-binding extension (§4), part of the signed TBS certificate.
- Only the leaf is sent on the wire; the DigNetwork CA is a well-known embedded anchor, never
  transmitted.

### 2.1 Machine-key rotation

Because `peer_id = SHA-256(SPKI DER)` and the SPKI commits the BLS binding (§4), replacing the key
pair MUST change the `peer_id` — rotation is an IDENTITY change, not a cert renewal. dig-tls is a
library and MUST NOT perform networking; it provides only the rotation PRIMITIVE and the caller
orchestrates the network overlap and re-announce.

- `rotate(dir, new_bls_sk)` mints a fresh `(TLS leaf, cert)` bound to the caller-supplied new BLS
  identity secret, and returns BOTH the retiring (`previous`) and the freshly minted (`current`)
  identity so the caller can dual-present — accept inbound on the old `peer_id` while it re-announces
  the new `peer_id` — during the overlap window. dig-tls never derives or stores a BLS key; the new
  identity secret is minted by the caller (dig-identity) and passed in, mirroring `generate_signed`.
- Persistence is ADDITIVE (§5.1 back-compat): the current identity always stays in `node.crt` /
  `node.key`; the retiring identity is written to NEW `node.crt.prev` / `node.key.prev` files. A
  reader that predates rotation still loads a single-cert directory unchanged, and `load_previous`
  reports no previous identity for such a directory. Key files stay owner-only (`0600`).
- All persisted slot writes (current AND `.prev`, both `rotate` and `load_or_generate`) are ATOMIC and
  durable: the bytes are staged to a sibling `<name>.tmp`, fsynced, atomically renamed over the target,
  and the parent directory is fsynced. A crash at any point therefore leaves EITHER the intact prior
  contents or the intact new contents of a slot — never a torn or truncated half-write. A secret key's
  `.tmp` is created owner-only (`0600`) so key material is never briefly world-readable even while staged.
- `rotate` refuses (returns an error, leaving disk untouched) when a `.prev` slot is already present:
  an un-retired previous identity means a prior rotation is still mid-overlap, so the caller MUST
  `retire_previous` before rotating again — one `.prev` generation exists at a time and an in-overlap
  identity is never silently overwritten.
- `from_pem` / `from_parts` enforce cert⇔key consistency: a loaded certificate MUST certify the SAME
  public key the private key holds (SubjectPublicKeyInfo DER equal). A mismatched cert+key pair is
  REJECTED (a `Parse` error), never loaded — so a peer never pins a `peer_id` for a key its presented
  certificate does not carry.
- `load_previous(dir)` reloads the `.prev` identity after a restart that happened mid-overlap;
  `retire_previous(dir)` zeroizes the in-memory copy of the old key and deletes both `.prev` files
  once the caller's re-announce has converged (a no-op when no `.prev` slot exists).
- Cert-EXPIRY renewal under the SAME key (same `peer_id`, new validity window) is a SEPARATE, cheaper
  path and is not the concern of `rotate`.

## 3. peer_id — canonical transport identity

`peer_id = SHA-256(TLS SubjectPublicKeyInfo DER)`, where the SPKI is the full ASN.1
`SubjectPublicKeyInfo` sequence (algorithm id + subjectPublicKey bit string) of the leaf. This is
byte-identical to Chia's node id and to `dig-gossip`/`dig-nat`'s prior `peer_id_from_tls_spki_der`.
The 32 bytes are rendered as lowercase hex in wire/status contexts.

## 4. #1204 BLS-G1 cert binding (canonical)

The leaf embeds the peer's 48-byte compressed **BLS12-381 G1 identity public key** in a custom,
non-critical X.509 extension, self-attested by a 96-byte **BLS G2 signature (Chia AugScheme)** over
the leaf's SPKI DER. Because `peer_id = SHA-256(SPKI)`, signing the SPKI commits the BLS key to
exactly that `peer_id`.

- **Extension OID (canonical):** `1.3.6.1.4.1.58968.1.1` (a DIG private-use arc under IANA PEN).
- **Extension value (v1):** `version(1 byte = 0x01) || bls_pub(48 bytes) || bls_sig(96 bytes)`
  (145 bytes total). Unknown versions and wrong lengths parse as "no binding this verifier
  understands" (additive forward-compat, §5.1 spirit), NOT as tampering.
- **Signing context (canonical, must-not-drift):** the BLS G2 signature covers the exact bytes
  `b"dig-nat/cert-bls-binding/v1"` followed by the SPKI DER. This literal is preserved from the
  original dig-nat implementation so certs minted before dig-tls existed verify unchanged.
- **Verification** parses the extension, subgroup-checks the embedded G1 point (rejecting
  small-subgroup / identity / non-canonical points BEFORE trusting it), and verifies the G2
  self-attestation against the embedded pubkey over the recomputed message.

### 4.1 Binding policy (local, never wire-negotiated)

| Policy          | Absent binding | Present + valid          | Present + invalid |
|-----------------|----------------|--------------------------|-------------------|
| `Off`           | accept         | accept (not verified)    | accept            |
| `Opportunistic` | accept         | accept, capture bls_pub  | **reject**        |
| `Required`      | **reject**     | accept, capture bls_pub  | **reject**        |

`Opportunistic` is the rollout default. `Required` is fail-closed and anti-downgrade: a stripped
extension is rejected, so a peer cannot silently disable a required-mode session. The policy is a
LOCAL decision and is never taken from the wire.

## 5. mTLS configuration

Both directions are mutually authenticated. The rustls configs pin the `ring` crypto provider
explicitly (so a consumer never installs a process-default provider).

- **Server (inbound):** `with_client_cert_verifier`, client auth MANDATORY. Verifies the client leaf
  chains to the DigNetwork CA with `clientAuth` usage, derives + captures its `peer_id`, and applies
  the binding policy. Servers accept any DigNetwork-CA peer (no caller pin).
- **Client (outbound):** a custom server-cert verifier. Verifies the server leaf chains to the
  DigNetwork CA with `serverAuth` usage, pins the expected `peer_id` when supplied (mismatch →
  reject), captures the derived id, and applies the binding policy.
- **Server name is NOT checked.** DIG peers dial by IP and authenticate by `peer_id` + binding, not
  by hostname, so the same verifier logic serves both directions.
- Chain validation accepts ECDSA P-256/P-384 signature algorithms.

## 6. Security properties (testable)

1. A leaf signed by the DigNetwork CA is accepted; a leaf signed by any other CA is rejected (chain).
2. A pinned `peer_id` that does not match the presented leaf is rejected (authentication).
3. The BLS binding round-trips: a valid binding is captured; a substituted pubkey, a binding replayed
   onto a different SPKI, and a small-subgroup point are all rejected (§4 anti-substitution).
4. Under `Required`, a CA-signed but UNBOUND leaf is rejected (anti-downgrade).

## 7. Hierarchy & dependencies

`dig-tls` is an **L00 foundation** crate with ZERO DIG-crate dependencies. The BLS-G2 sign/verify and
G1 subgroup check are done via `chia-bls` + `blst` on raw bytes, so dig-tls does not depend on
`dig-identity` (a same-level L00 crate); the caller passes its BLS identity secret key in. External
deps only: `rustls`, `rustls-webpki`, `rcgen`, `chia-bls`, `blst`, `x509-parser`, `sha2`.
Consumers (dig-nat, dig-gossip, dig-peer, dig-node, dig-relay) reference it downward.
