//! Ed25519 for the X-21 artifacts: contact card v2, bundle v2, binding v3 and the revocation
//! certificate v2 (design §2.4, §3.3, §3.4, §5.3).
//!
//! Each artifact type has exactly one production signer and exactly one verifier, and for these
//! four it is this module: `ed25519-dalek` 2.2.0 with `verify_strict`. Kotlin never verifies them.
//! Signatures are identical between implementations (Ed25519 is deterministic: 64 of 64 vectors
//! byte-identical in S0′ V-14), verification is not — BouncyCastle 1.85.2 verifies the cofactored
//! equation and differs from `verify_strict` on 33 of 53 edge vectors (mixed-order public keys,
//! mixed-order and small-order nonces) — so "strict verification in both" is not achievable and
//! the split above is the mitigation of R-37.

use crate::result::{DmCode, DmResult};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// Length of an Ed25519 public key.
pub const PUBLIC_KEY_BYTES: usize = 32;
/// Length of an Ed25519 signature.
pub const SIGNATURE_BYTES: usize = 64;

/// The public key of a 32-byte Ed25519 seed.
pub fn public_key(seed: &[u8; 32]) -> [u8; PUBLIC_KEY_BYTES] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// Signs `message` with a 32-byte Ed25519 seed.
pub fn sign(seed: &[u8; 32], message: &[u8]) -> [u8; SIGNATURE_BYTES] {
    SigningKey::from_bytes(seed).sign(message).to_bytes()
}

/// Strict verification (cofactorless, small-order and mixed-order keys and nonces refused).
/// A key that is not a valid point, or a signature that does not verify, is
/// [`DmCode::BadSignature`].
pub fn verify_strict(
    public: &[u8; PUBLIC_KEY_BYTES],
    message: &[u8],
    signature: &[u8; SIGNATURE_BYTES],
) -> DmResult<()> {
    let key = VerifyingKey::from_bytes(public).map_err(|_| DmCode::BadSignature)?;
    key.verify_strict(message, &Signature::from_bytes(signature))
        .map_err(|_| DmCode::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signature_verifies_only_over_its_own_message_and_key() {
        let seed = [42u8; 32];
        let public = public_key(&seed);
        let signature = sign(&seed, b"ghost");
        assert_eq!(verify_strict(&public, b"ghost", &signature), Ok(()));
        assert_eq!(
            verify_strict(&public, b"ghos", &signature),
            Err(DmCode::BadSignature)
        );
        let other = public_key(&[43u8; 32]);
        assert_eq!(
            verify_strict(&other, b"ghost", &signature),
            Err(DmCode::BadSignature)
        );
    }

    #[test]
    fn small_order_public_keys_are_refused() {
        // The order-2 point of the 8-torsion subgroup, encoded as a compressed Edwards point.
        let mut small = [0u8; 32];
        small[0] = 0x01;
        let signature = [0u8; 64];
        assert_eq!(
            verify_strict(&small, b"ghost", &signature),
            Err(DmCode::BadSignature)
        );
    }

    #[test]
    fn signing_is_deterministic() {
        let seed = [7u8; 32];
        assert_eq!(sign(&seed, b"a"), sign(&seed, b"a"));
    }
}
