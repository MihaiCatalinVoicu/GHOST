//! Revocation certificate **v2** (design §8.5, X-7, C-25).
//!
//! ```text
//! cert = version(1) = 0x02 || identity_pk(32, Ed25519) || issued_minute(u32, BE)
//!        || reason(1) || signature(64, Ed25519 over "ghost/v1/revocation" || all previous bytes)
//!      = 102 bytes
//! ```
//!
//! Three things separate it from the Phase 3 certificate v1
//! (`android/identity/.../RevocationCertificate.kt`), and each is a rule of this phase rather than
//! a preference:
//!
//!  - **Minutes, not seconds** (T13). Every time a DM byte carries is minute-granular or coarser
//!    (§7.1's timestamp summary), and v1's `issuedAtUnixSeconds` is a `u64` of seconds. v1 stays a
//!    local Phase 3 artifact and never leaves the device; v2 is the only form that travels.
//!  - **Signed and verified in Rust** (X-21, §2.4 as corrected by S0′ V-14). `ed25519-dalek`'s
//!    `verify_strict` refuses mixed-order keys and nonces that BouncyCastle's cofactored equation
//!    accepts, and "strict in both" is not reachable through BouncyCastle's public API — so each
//!    artifact type has exactly one verifier, and for this one it is here.
//!  - **It travels inside E2E**, as a TLV of an L0 (`TLV_REVOCATION`, §7.1), never as a blob in an
//!    identity namespace contacts poll (X-7, T31): polling such a namespace would be a read
//!    outside the owner's own namespaces and a per-identity relay-visible event.
//!
//! A revocation can only **block**: it moves a contact to the terminal `revoked` state (§8.5). A
//! thief holding the seed therefore gains nothing by forging one — it can already sign anything
//! that key signs — which is why verification needs no freshness rule beyond the signature.

use crate::result::{DmCode, DmResult};
use crate::sign;

/// Length of a revocation certificate v2.
pub const REVOCATION_BYTES: usize = 102;
/// The only certificate version Phase 9 issues or accepts.
pub const REVOCATION_VERSION: u8 = 0x02;
/// Label of the signature (§8.5).
pub const REVOCATION_SIGN_LABEL: &[u8] = b"ghost/v1/revocation";

/// The bytes the signature covers: everything before it.
const SIGNED_BYTES: usize = 1 + 32 + 4 + 1;

const OFFSET_IDENTITY: usize = 1;
const OFFSET_MINUTE: usize = 33;
const OFFSET_REASON: usize = 37;
const OFFSET_SIGNATURE: usize = 38;

/// Why an identity was revoked (the Phase 3 code set, kept: `DEVICE_LOST`, `DEVICE_COMPROMISED`,
/// `KEY_ROTATION`). An unknown code is [`DmCode::NonCanonical`], so a future reason cannot be
/// smuggled past a client that does not know it.
pub const REASON_MIN: u8 = 1;
/// The largest reason code Phase 9 defines.
pub const REASON_MAX: u8 = 3;

/// A parsed, signature-verified certificate.
#[derive(Clone, PartialEq, Eq)]
pub struct Revocation {
    /// The Ed25519 identity the certificate revokes.
    pub identity_pk: [u8; 32],
    /// Minutes since the Unix epoch at issue (T13: the certificate carries no seconds).
    pub issued_minute: u32,
    /// The reason code.
    pub reason: u8,
}

impl core::fmt::Debug for Revocation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The identity is the one thing a log must not carry (T3).
        f.debug_struct("Revocation")
            .field("issued_minute", &self.issued_minute)
            .field("reason", &self.reason)
            .finish()
    }
}

/// The transcript the signature covers: the label and the certificate's first 38 bytes.
fn transcript(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(REVOCATION_SIGN_LABEL.len() + SIGNED_BYTES);
    out.extend_from_slice(REVOCATION_SIGN_LABEL);
    out.extend_from_slice(body);
    out
}

/// Issues a certificate for the identity `seed` belongs to.
///
/// The caller supplies `issued_minute` — nothing in this crate reads a clock (G-R8) — and the
/// identity key is **derived from the seed** rather than taken as an argument, so a certificate
/// can only ever name the identity that signed it.
pub fn issue(seed: &[u8; 32], issued_minute: u32, reason: u8) -> DmResult<[u8; REVOCATION_BYTES]> {
    if !(REASON_MIN..=REASON_MAX).contains(&reason) {
        return Err(DmCode::NonCanonical);
    }
    let mut out = [0u8; REVOCATION_BYTES];
    out[0] = REVOCATION_VERSION;
    out[OFFSET_IDENTITY..OFFSET_MINUTE].copy_from_slice(&sign::public_key(seed));
    out[OFFSET_MINUTE..OFFSET_REASON].copy_from_slice(&issued_minute.to_be_bytes());
    out[OFFSET_REASON] = reason;
    let signature = sign::sign(seed, &transcript(&out[..SIGNED_BYTES]));
    out[OFFSET_SIGNATURE..].copy_from_slice(&signature);
    Ok(out)
}

/// Parses and verifies a certificate, fail-closed and in the order §3.3 fixes for a card: the
/// length, the version, the reason, then the signature **under the key the certificate names**.
///
/// `expected_identity_pk`, when given, is the contact's pinned Ed25519 key: a certificate for
/// another identity is [`DmCode::InvalidCard`], never applied to the wrong contact. GHOST never
/// links two Ed25519 identities (§8.3), so this check is what keeps a certificate that verifies
/// under its own key from revoking somebody else's contact row.
pub fn verify(bytes: &[u8], expected_identity_pk: Option<&[u8; 32]>) -> DmResult<Revocation> {
    if bytes.len() != REVOCATION_BYTES {
        return Err(DmCode::NonCanonical);
    }
    if bytes[0] != REVOCATION_VERSION {
        return Err(DmCode::NonCanonical);
    }
    let reason = bytes[OFFSET_REASON];
    if !(REASON_MIN..=REASON_MAX).contains(&reason) {
        return Err(DmCode::NonCanonical);
    }
    let mut identity_pk = [0u8; 32];
    identity_pk.copy_from_slice(&bytes[OFFSET_IDENTITY..OFFSET_MINUTE]);
    if let Some(expected) = expected_identity_pk {
        if &identity_pk != expected {
            return Err(DmCode::InvalidCard);
        }
    }
    let mut minute = [0u8; 4];
    minute.copy_from_slice(&bytes[OFFSET_MINUTE..OFFSET_REASON]);
    let mut signature = [0u8; sign::SIGNATURE_BYTES];
    signature.copy_from_slice(&bytes[OFFSET_SIGNATURE..]);
    sign::verify_strict(
        &identity_pk,
        &transcript(&bytes[..SIGNED_BYTES]),
        &signature,
    )?;
    Ok(Revocation {
        identity_pk,
        issued_minute: u32::from_be_bytes(minute),
        reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [0x21; 32];

    #[test]
    fn a_certificate_round_trips_and_names_its_own_identity() {
        let cert = issue(&SEED, 29_000_000, 2).expect("issue");
        assert_eq!(cert.len(), REVOCATION_BYTES);
        let parsed = verify(&cert, None).expect("verify");
        assert_eq!(parsed.identity_pk, sign::public_key(&SEED));
        assert_eq!(parsed.issued_minute, 29_000_000);
        assert_eq!(parsed.reason, 2);
        assert_eq!(
            verify(&cert, Some(&sign::public_key(&SEED))).expect("pinned"),
            parsed
        );
    }

    #[test]
    fn a_certificate_of_another_identity_is_refused_for_this_contact() {
        let cert = issue(&SEED, 1, 1).expect("issue");
        let other = sign::public_key(&[0x22; 32]);
        assert_eq!(verify(&cert, Some(&other)), Err(DmCode::InvalidCard));
    }

    #[test]
    fn every_byte_is_covered_by_the_signature() {
        let cert = issue(&SEED, 1_234_567, 3).expect("issue");
        // Flipping any byte of the signed portion, or of the signature, must fail; the identity
        // bytes fail as a bad signature because the key they name is the verifying key.
        for i in 0..REVOCATION_BYTES {
            let mut broken = cert;
            broken[i] ^= 0x01;
            assert!(
                verify(&broken, None).is_err(),
                "byte {i} is outside the transcript"
            );
        }
    }

    #[test]
    fn the_version_the_reason_and_the_length_are_fail_closed() {
        let cert = issue(&SEED, 9, 1).expect("issue");
        assert_eq!(verify(&cert[..101], None), Err(DmCode::NonCanonical));
        assert_eq!(verify(&[], None), Err(DmCode::NonCanonical));
        // A v1 certificate is not a v2 one, whatever its length.
        let mut v1 = cert;
        v1[0] = 0x01;
        assert_eq!(verify(&v1, None), Err(DmCode::NonCanonical));
        assert_eq!(issue(&SEED, 9, 0), Err(DmCode::NonCanonical));
        assert_eq!(issue(&SEED, 9, 4), Err(DmCode::NonCanonical));
        // A reason outside the set is refused **before** the signature, so a signed certificate
        // with reason 4 is still not accepted.
        let mut bad_reason = [0u8; REVOCATION_BYTES];
        bad_reason[0] = REVOCATION_VERSION;
        bad_reason[OFFSET_IDENTITY..OFFSET_MINUTE].copy_from_slice(&sign::public_key(&SEED));
        bad_reason[OFFSET_REASON] = 4;
        let signature = sign::sign(&SEED, &transcript(&bad_reason[..SIGNED_BYTES]));
        bad_reason[OFFSET_SIGNATURE..].copy_from_slice(&signature);
        assert_eq!(verify(&bad_reason, None), Err(DmCode::NonCanonical));
    }
}
