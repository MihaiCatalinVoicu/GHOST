//! Safety number v1 (design §8.4, FR-4.6, D12).
//!
//! ```text
//! own_id(party) = identity_pk(32, Ed25519) || OI(32, Olm identity)
//! h_0           = SHA-512("ghost/v1/safety-number" || u8(1) || own_id)
//! h_{k+1}       = SHA-512(h_k || own_id)                for k = 0 … 5 199   (5 201 evaluations)
//! digits(party) = for j in 0 … 5: (u40_be(h_5200[5j .. 5j + 5]) mod 100 000) as 5 decimal digits
//! display       = digits(party₁) || digits(party₂), the smaller 30-digit string first
//! scannable     = u8(1) || h_5200(own)[0..32] || h_5200(peer)[0..32]                  (65 bytes)
//! ```
//!
//! Matching one party's 30 digits costs about 10³⁰ ≈ 2⁹⁹·⁷ candidate identities × 5 201 hashes
//! ≈ 2¹¹² SHA-512 evaluations. Specified clean room, without reading any AGPL source; the digits
//! of a GHOST safety number are never compared with another messenger's. Computing, displaying,
//! scanning and comparing cause no network I/O (T31).

use crate::result::DmCode;
use sha2::{Digest, Sha512};

/// The version byte of a safety number.
pub const SAFETY_NUMBER_VERSION: u8 = 1;
/// Iterations after `h_0`.
pub const ITERATIONS: usize = 5200;
/// Label of `h_0`.
pub const SAFETY_NUMBER_LABEL: &[u8] = b"ghost/v1/safety-number";
/// Digits one party contributes.
pub const DIGITS_PER_PARTY: usize = 30;
/// Digits of the displayed number.
pub const DISPLAY_DIGITS: usize = 2 * DIGITS_PER_PARTY;
/// Length of the scannable form.
pub const SCANNABLE_BYTES: usize = 65;

/// One party of a safety number: its `ghost1` Ed25519 key and its Olm identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Party {
    /// The Ed25519 identity key.
    pub identity_pk: [u8; 32],
    /// The Olm identity key (X25519).
    pub olm_identity: [u8; 32],
}

impl Party {
    fn own_id(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.identity_pk);
        out[32..].copy_from_slice(&self.olm_identity);
        out
    }

    /// `h_5200` of this party.
    pub fn hash(&self) -> [u8; 64] {
        let own = self.own_id();
        let mut hash: [u8; 64] = Sha512::new()
            .chain_update(SAFETY_NUMBER_LABEL)
            .chain_update([SAFETY_NUMBER_VERSION])
            .chain_update(own)
            .finalize()
            .into();
        for _ in 0..ITERATIONS {
            hash = Sha512::new()
                .chain_update(hash)
                .chain_update(own)
                .finalize()
                .into();
        }
        hash
    }

    /// The 30 digits this party contributes.
    pub fn digits(&self) -> String {
        digits_of(&self.hash())
    }
}

fn digits_of(hash: &[u8; 64]) -> String {
    let mut out = String::with_capacity(DIGITS_PER_PARTY);
    for j in 0..6 {
        let mut chunk = [0u8; 8];
        chunk[3..].copy_from_slice(&hash[5 * j..5 * j + 5]);
        let value = u64::from_be_bytes(chunk) % 100_000;
        out.push_str(&format!("{value:05}"));
    }
    out
}

/// A computed safety number.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafetyNumber {
    /// The 60 displayed digits, the smaller party's 30 first.
    pub display: String,
    /// The 65-byte scannable form, the owner's half first.
    pub scannable: [u8; SCANNABLE_BYTES],
}

/// Computes the safety number of a conversation. `own` is this device's party.
pub fn safety_number(own: &Party, peer: &Party) -> SafetyNumber {
    let own_hash = own.hash();
    let peer_hash = peer.hash();
    let own_digits = digits_of(&own_hash);
    let peer_digits = digits_of(&peer_hash);
    let display = if own_digits <= peer_digits {
        format!("{own_digits}{peer_digits}")
    } else {
        format!("{peer_digits}{own_digits}")
    };
    let mut scannable = [0u8; SCANNABLE_BYTES];
    scannable[0] = SAFETY_NUMBER_VERSION;
    scannable[1..33].copy_from_slice(&own_hash[..32]);
    scannable[33..].copy_from_slice(&peer_hash[..32]);
    SafetyNumber { display, scannable }
}

/// The outcome of comparing a scanned code with the one this device computed (§8.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanOutcome {
    /// The scanned code is this conversation's, seen from the other side.
    Match,
    /// The code is of the expected version but names other keys.
    Mismatch,
    /// The code is of a version this build does not know.
    VersionMismatch,
}

/// Compares a scanned code with this device's own: the scanned `own` half must equal this
/// device's `peer` half and the other way round.
pub fn compare_scanned(own: &SafetyNumber, scanned: &[u8]) -> Result<ScanOutcome, DmCode> {
    if scanned.len() != SCANNABLE_BYTES {
        return Err(DmCode::NonCanonical);
    }
    if scanned[0] != SAFETY_NUMBER_VERSION {
        return Ok(ScanOutcome::VersionMismatch);
    }
    let mine_own = &own.scannable[1..33];
    let mine_peer = &own.scannable[33..];
    if &scanned[1..33] == mine_peer && &scanned[33..] == mine_own {
        Ok(ScanOutcome::Match)
    } else {
        Ok(ScanOutcome::Mismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alice() -> Party {
        Party {
            identity_pk: [1u8; 32],
            olm_identity: [2u8; 32],
        }
    }

    fn bob() -> Party {
        Party {
            identity_pk: [3u8; 32],
            olm_identity: [4u8; 32],
        }
    }

    #[test]
    fn both_sides_see_the_same_sixty_digits() {
        let a = safety_number(&alice(), &bob());
        let b = safety_number(&bob(), &alice());
        assert_eq!(a.display.len(), DISPLAY_DIGITS);
        assert!(a.display.chars().all(|c| c.is_ascii_digit()));
        assert_eq!(a.display, b.display);
        // The scannable form is not symmetric: each side puts its own half first.
        assert_ne!(a.scannable, b.scannable);
    }

    #[test]
    fn a_scan_of_the_peers_code_matches_and_a_third_party_does_not() {
        let a = safety_number(&alice(), &bob());
        let b = safety_number(&bob(), &alice());
        assert_eq!(compare_scanned(&a, &b.scannable), Ok(ScanOutcome::Match));
        assert_eq!(compare_scanned(&b, &a.scannable), Ok(ScanOutcome::Match));
        let mallory = Party {
            identity_pk: [5u8; 32],
            olm_identity: [6u8; 32],
        };
        let c = safety_number(&mallory, &alice());
        assert_eq!(compare_scanned(&a, &c.scannable), Ok(ScanOutcome::Mismatch));
        // A scan of one's own code is not a match either.
        assert_eq!(compare_scanned(&a, &a.scannable), Ok(ScanOutcome::Mismatch));
    }

    #[test]
    fn another_version_is_reported_and_a_wrong_length_refused() {
        let a = safety_number(&alice(), &bob());
        let mut other = a.scannable;
        other[0] = 2;
        assert_eq!(
            compare_scanned(&a, &other),
            Ok(ScanOutcome::VersionMismatch)
        );
        assert_eq!(compare_scanned(&a, &other[..64]), Err(DmCode::NonCanonical));
    }

    #[test]
    fn any_key_change_changes_the_number() {
        let base = safety_number(&alice(), &bob()).display;
        let mut other = bob();
        other.olm_identity[0] ^= 1;
        assert_ne!(safety_number(&alice(), &other).display, base);
        let mut other = bob();
        other.identity_pk[0] ^= 1;
        assert_ne!(safety_number(&alice(), &other).display, base);
    }

    #[test]
    fn the_iteration_count_is_the_one_the_design_fixes() {
        assert_eq!(ITERATIONS, 5200);
        assert_eq!(alice().digits().len(), DIGITS_PER_PARTY);
    }
}
