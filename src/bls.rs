//! BLS12-381 identity primitives — on RAW bytes, so dig-tls needs no DIG-crate dependency.
//!
//! The #1204 cert binding ([`crate::binding`]) attests a peer's BLS **G1 identity key** over its TLS
//! SPKI with a **BLS G2 (Chia AugScheme)** signature. dig-identity owns the canonical identity key,
//! but dig-identity is a same-level L00 crate — dig-tls cannot depend on it (reference-DOWN-only,
//! Appendix B). So dig-tls re-implements the two operations it needs directly against the SAME vetted
//! backend dig-identity uses (`chia-bls` for AugScheme sign/verify, `blst` for the G1 subgroup check).
//! Byte-agreement with dig-identity rests on both crates sharing the same `chia-bls`/`blst` backend;
//! dig-tls (L00) cannot itself depend on dig-identity to pin this directly, so the cross-crate
//! conformance check lives at the higher adoption/integration level where both are in scope.
//!
//! Every function here is fail-closed on malformed input and takes/returns fixed-size byte arrays:
//! a 48-byte compressed G1 public key and a 96-byte compressed G2 signature.

use blst::{
    blst_p1_affine, blst_p1_affine_in_g1, blst_p1_affine_is_inf, blst_p1_uncompress, BLST_ERROR,
};
use chia_bls::{sign as aug_sign, verify as aug_verify, PublicKey, Signature};

/// Re-export of the BLS identity secret key type. The caller mints its identity key elsewhere
/// (dig-identity slot `0x0010`) and passes it in — dig-tls never derives or stores it.
pub use chia_bls::SecretKey;

/// The all-zero "compressed identity/infinity" G1 encoding, rejected up front by
/// [`g1_subgroup_check`]. (A compressed BLS identity point is actually `0xc0 00..`, but any input
/// that decompresses to infinity is caught by the explicit `is_inf` check below; this constant is a
/// cheap early-out for the common zeroed buffer.)
const G1_ZERO: [u8; 48] = [0u8; 48];

/// The 48-byte compressed BLS12-381 G1 public key for a secret key.
pub fn public_key_bytes(sk: &SecretKey) -> [u8; 48] {
    sk.public_key().to_bytes()
}

/// Validate that `pk` is a canonical, non-identity G1 point in the prime-order `r`-subgroup.
///
/// Returns `true` only when `pk` deserializes as a compressed point ON the curve, lies in the
/// `r`-subgroup (`blst` `in_g1`), and is NOT the identity/infinity point. Any failure (malformed,
/// off-curve, small-order, or identity) returns `false`. This is the mandatory gate before a peer's
/// advertised BLS key is trusted as a seal target — it blocks small-subgroup / invalid-curve
/// key-recovery attacks. Byte-identical to `dig_identity::g1_subgroup_check`.
pub fn g1_subgroup_check(pk: &[u8; 48]) -> bool {
    if pk == &G1_ZERO {
        return false;
    }
    // SAFETY: `blst` FFI over a fixed-size, initialized stack buffer; no aliasing, no escaping refs.
    unsafe {
        let mut affine = blst_p1_affine::default();
        if blst_p1_uncompress(&mut affine, pk.as_ptr()) != BLST_ERROR::BLST_SUCCESS {
            return false;
        }
        if blst_p1_affine_is_inf(&affine) {
            return false;
        }
        blst_p1_affine_in_g1(&affine)
    }
}

/// Sign `msg` with the identity key under the Chia AugScheme (BLS G2), returning the 96-byte
/// compressed signature. AugScheme prepends the signer's public key before hashing to G2, so the
/// signature is bound to the signing key — exactly the property the cert binding relies on.
/// Byte-identical to `dig_identity::sign_message`.
pub fn sign_message(sk: &SecretKey, msg: &[u8]) -> [u8; 96] {
    aug_sign(sk, msg).to_bytes()
}

/// Verify a 96-byte AugScheme signature against a 48-byte G1 identity key and `msg`.
///
/// Returns `false` on any malformed key/signature bytes or a non-verifying signature (fail-closed).
/// Byte-identical to `dig_identity::verify_signature`.
pub fn verify_signature(pk: &[u8; 48], msg: &[u8], sig: &[u8; 96]) -> bool {
    let (Ok(pk), Ok(sig)) = (PublicKey::from_bytes(pk), Signature::from_bytes(sig)) else {
        return false;
    };
    aug_verify(&sig, &pk, msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// A deterministic test identity key derived from a label — never a hard-coded literal, so a
    /// second implementation reproduces the same vector and CodeQL does not flag a hard-coded value.
    fn identity_sk(label: &str) -> SecretKey {
        let seed: [u8; 32] = Sha256::digest(label.as_bytes()).into();
        SecretKey::from_seed(&seed)
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let sk = identity_sk("bls/round-trip");
        let pk = public_key_bytes(&sk);
        let msg = b"dig-tls binding message";
        let sig = sign_message(&sk, msg);
        assert!(verify_signature(&pk, msg, &sig));
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let sk = identity_sk("bls/wrong-msg");
        let pk = public_key_bytes(&sk);
        let sig = sign_message(&sk, b"the real message");
        assert!(!verify_signature(&pk, b"a different message", &sig));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let signer = identity_sk("bls/signer");
        let other = public_key_bytes(&identity_sk("bls/other"));
        let msg = b"payload";
        let sig = sign_message(&signer, msg);
        assert!(!verify_signature(&other, msg, &sig));
    }

    #[test]
    fn verify_rejects_malformed_bytes() {
        let sk = identity_sk("bls/malformed");
        let pk = public_key_bytes(&sk);
        // A well-formed key but a garbage (non-canonical) signature must fail, not panic.
        assert!(!verify_signature(&pk, b"m", &[0xFFu8; 96]));
        // A garbage public key must fail too.
        assert!(!verify_signature(
            &[0xFFu8; 48],
            b"m",
            &sign_message(&sk, b"m")
        ));
    }

    #[test]
    fn subgroup_check_accepts_real_key_rejects_junk() {
        let pk = public_key_bytes(&identity_sk("bls/subgroup"));
        assert!(
            g1_subgroup_check(&pk),
            "a real G1 identity key is in-subgroup"
        );
        assert!(
            !g1_subgroup_check(&[0u8; 48]),
            "the zero buffer is rejected"
        );
        assert!(
            !g1_subgroup_check(&[0xFFu8; 48]),
            "off-curve junk is rejected"
        );
    }

    // ---------------------------------------------------------------------------------------
    // Golden byte vectors — the wire-compatibility contract.
    //
    // Every test above is a ROUND-TRIP: it signs and verifies with the same backend, so it passes
    // for any self-consistent implementation and cannot see a change in seed->key derivation, point
    // compression, or the AugScheme domain separator. These vectors pin the actual BYTES, so a
    // `chia-bls` uplift that alters any of them fails HERE rather than silently breaking every
    // already-deployed peer that verifies a binding produced by an older node.
    //
    // Captured on chia-bls 0.26 BEFORE the 0.36 uplift. A changed value is a compatibility break,
    // not a migration detail — re-blessing these to make a bump pass defeats their entire purpose.
    // ---------------------------------------------------------------------------------------

    /// The message the pinned signatures below are taken over.
    const GOLDEN_MSG: &[u8] = b"dig-tls golden vector message";

    /// `(label, secret key, compressed G1 public key, compressed AugScheme G2 signature)`.
    /// The keys are derived from the label, never pasted, so a second implementation reproduces
    /// them from the label alone rather than trusting a literal.
    const GOLDEN_VECTORS: &[(&str, &str, &str, &str)] = &[
        ("golden/peer-a", "2b9b10c104d2c4750cd6d4e649d69869cb9738b153eef7e93613b9ecb453d618", "9072f1915e0f024466afdc24876d4ea13dd1064df5a67495589863bcda39ec621c809d92ba67bf5bd667c6d5b3178529", "96e87a385dc5cfbeb285000c3c22e5ae76356c249f9842bf8cd8d93c6c5e0a858ad2b2b4035760b21abe71d2d6ba169605b8c6867eb25ef70472b2f0b56684fbb91c07031fe916e3a892f8c0c471ade2e4a7338e14ebf328114c676e1153e867"),
        ("golden/peer-b", "591fdea7194dd3f68d7a62bc76c18edb37aca6a9ab10222971ef8f450e26ecc1", "896df5e5c5cbf071d98233a9189423b589d63edadd92752a49e8df8d65617b2bb492162ab6ff74bf25b7b5ffa8f7fc65", "aea3cbb6ac127c107b9cfa42e940c46697a9d1d6df1ef405f6d3321959780758d9b8e0479c027dea74109bd084703e2211f9f479a82144d9f9c197ccce2d07657242364dd3cad464b30116a8bd6b25e6d58335bb016ee95fc10145fe170102c9"),
    ];

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn from_hex(s: &str, out: &mut [u8]) {
        assert_eq!(s.len(), out.len() * 2, "hex literal length mismatch");
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("valid hex literal");
        }
    }

    /// What we PRODUCE must not change: derivation, G1 compression, and the G2 signature bytes.
    #[test]
    fn golden_vectors_are_byte_identical() {
        for (label, sk_hex, pk_hex, sig_hex) in GOLDEN_VECTORS {
            let sk = identity_sk(label);
            assert_eq!(
                &to_hex(&sk.to_bytes()),
                sk_hex,
                "seed -> secret key derivation drifted for {label}"
            );
            assert_eq!(
                &to_hex(&public_key_bytes(&sk)),
                pk_hex,
                "G1 public key encoding drifted for {label}"
            );
            assert_eq!(
                &to_hex(&sign_message(&sk, GOLDEN_MSG)),
                sig_hex,
                "AugScheme G2 signature bytes drifted for {label}"
            );
        }
    }

    /// What we ACCEPT must not change either: a signature produced by the older backend still
    /// verifies. Byte-equality above cannot see a verification-side regression on its own.
    #[test]
    fn pinned_signatures_still_verify() {
        for (label, _, pk_hex, sig_hex) in GOLDEN_VECTORS {
            let mut pk = [0u8; 48];
            let mut sig = [0u8; 96];
            from_hex(pk_hex, &mut pk);
            from_hex(sig_hex, &mut sig);
            assert!(
                verify_signature(&pk, GOLDEN_MSG, &sig),
                "a signature pinned from the previous backend no longer verifies for {label}"
            );
        }
    }

    /// Regenerate the literals above: `cargo test emit_golden_vectors -- --ignored --nocapture`.
    /// Only legitimate when INTRODUCING a vector, never to silence a failing one.
    #[test]
    #[ignore]
    fn emit_golden_vectors() {
        for (label, ..) in GOLDEN_VECTORS {
            let sk = identity_sk(label);
            println!(
                "(\"{label}\", \"{}\", \"{}\", \"{}\"),",
                to_hex(&sk.to_bytes()),
                to_hex(&public_key_bytes(&sk)),
                to_hex(&sign_message(&sk, GOLDEN_MSG))
            );
        }
    }
}
