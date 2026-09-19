//! Seed derivations the spikes need (design §3.1): HKDF-SHA256 with an empty salt and a label as
//! `info`, the convention of `RootEntropy.deriveBranch` in `:identity`.

use hkdf::Hkdf;
use sha2::Sha256;

/// `ghost/v1/messaging`, the MESSAGING branch of `DerivationLabels`.
pub const MESSAGING: &str = "ghost/v1/messaging";
/// The Olm identity (X25519) secret under the MESSAGING branch (§3.1).
pub const OLM_IDENTITY: &str = "ghost/v1/dm/olm-identity";
/// The unused Ed25519 seed an Olm `Account` must carry (§3.1).
pub const OLM_ACCOUNT_SIGNING: &str = "ghost/v1/dm/olm-account-signing";

/// `HKDF-SHA256(ikm, salt = ∅, info, L = 32)`.
pub fn hkdf32(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let hkdf: Hkdf<Sha256> = Hkdf::new(None, ikm);
    let mut out = [0u8; 32];
    // A 32-byte output is always within HKDF-SHA256's 255 × 32 byte limit.
    if hkdf.expand(info, &mut out).is_err() {
        out = [0u8; 32];
    }
    out
}

/// The secrets of the Olm identity derived from the MESSAGING branch `m`.
pub struct OlmIdentitySecrets {
    pub identity: [u8; 32],
    pub account_signing_seed: [u8; 32],
}

pub fn olm_identity(messaging_branch: &[u8; 32]) -> OlmIdentitySecrets {
    OlmIdentitySecrets {
        identity: hkdf32(messaging_branch, OLM_IDENTITY.as_bytes()),
        account_signing_seed: hkdf32(messaging_branch, OLM_ACCOUNT_SIGNING.as_bytes()),
    }
}
