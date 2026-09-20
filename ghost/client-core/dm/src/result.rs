//! The DM result codes of the closed JNI surface (design §2.6, amended by §22.8.2 and §22.8.3).
//!
//! Every function of this crate returns one of these codes instead of a library error, so no
//! vodozemac, libcrux or RustCrypto error type crosses the crate boundary and none reaches Kotlin.
//! The one-byte wire values below are the `code(1)` of the `code(1) || TLV fields` reply shape;
//! the design names the codes but fixes no numbering, so this enumeration is the numbering and
//! `DmResultCodesTest` (S4b) asserts it together with the library mapping table.
//!
//! Codes that only the Olm facade of S4b can produce are listed here because the list is closed:
//! adding one later would change the surface, and Kotlin decodes the whole enumeration.

/// A DM result code. `Ok` is the absence of an error; `NewChain` is a result value of
/// `chainPosition`, not an error (§2.6 function 19).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum DmCode {
    /// The call succeeded.
    Ok = 0x00,
    /// The native library is missing, or the context handle is closed or foreign (§2.5).
    CryptoUnavailable = 0x01,
    /// A contact card that does not parse, verify or carry a supported version (§3.3).
    InvalidCard = 0x02,
    /// A seal, an inner layer or a KEM ciphertext that does not open (§22.8.2 rule 4).
    NotOpen = 0x03,
    /// An Ed25519 signature that does not verify under the expected key (§3.4).
    BadSignature = 0x04,
    /// A blob or an L0 that opens but does not parse exactly (R-S2, R-C4).
    NonCanonical = 0x05,
    /// A malformed or non-contributory public key (§22.8.2 rules 1, 3 and 4).
    InvalidKey = 0x06,
    /// Content that no bucket can carry (R-B1, R-C4).
    Oversize = 0x07,
    /// A sealed blob that does not fit its bucket: a GHOST bug, never a peer's doing (R-B1).
    NoFit = 0x08,
    /// Stored state that does not open under its binding or does not parse (§22.8.3).
    StateCorrupt = 0x09,
    /// Any library encryption error (§22.8.2 rule 2); produced by the S4b Olm facade.
    InvalidSession = 0x0a,
    /// A PreKey message naming a fallback key the generation does not hold (S4b).
    MissingKey = 0x0b,
    /// A PreKey message whose identity is not the pinned one (S4b).
    IdentityMismatch = 0x0c,
    /// A MAC, padding or format failure inside the session layer (S4b).
    Undecryptable = 0x0d,
    /// The message key is gone: used, evicted or never stored (S4b).
    DuplicateOrLost = 0x0e,
    /// A forward gap beyond Olm's 2 000 (S4b).
    GapTooBig = 0x0f,
    /// `chainPosition`: the receiver chains are readable and none matches (S4b).
    NewChain = 0x10,
    /// A caught Rust panic, and nothing else (§2.6).
    Internal = 0xff,
}

impl DmCode {
    /// The wire byte of this code.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// The code of a wire byte, or `None` for a byte this version does not define.
    pub const fn from_u8(byte: u8) -> Option<Self> {
        Some(match byte {
            0x00 => DmCode::Ok,
            0x01 => DmCode::CryptoUnavailable,
            0x02 => DmCode::InvalidCard,
            0x03 => DmCode::NotOpen,
            0x04 => DmCode::BadSignature,
            0x05 => DmCode::NonCanonical,
            0x06 => DmCode::InvalidKey,
            0x07 => DmCode::Oversize,
            0x08 => DmCode::NoFit,
            0x09 => DmCode::StateCorrupt,
            0x0a => DmCode::InvalidSession,
            0x0b => DmCode::MissingKey,
            0x0c => DmCode::IdentityMismatch,
            0x0d => DmCode::Undecryptable,
            0x0e => DmCode::DuplicateOrLost,
            0x0f => DmCode::GapTooBig,
            0x10 => DmCode::NewChain,
            0xff => DmCode::Internal,
            _ => return None,
        })
    }

    /// The code's name as §2.6 spells it: the form the vectors, the Kotlin `DmResult` decoder and
    /// the counters use.
    pub const fn name(self) -> &'static str {
        match self {
            DmCode::Ok => "OK",
            DmCode::CryptoUnavailable => "CRYPTO_UNAVAILABLE",
            DmCode::InvalidCard => "INVALID_CARD",
            DmCode::NotOpen => "NOT_OPEN",
            DmCode::BadSignature => "BAD_SIGNATURE",
            DmCode::NonCanonical => "NON_CANONICAL",
            DmCode::InvalidKey => "INVALID_KEY",
            DmCode::Oversize => "OVERSIZE",
            DmCode::NoFit => "NO_FIT",
            DmCode::StateCorrupt => "STATE_CORRUPT",
            DmCode::InvalidSession => "INVALID_SESSION",
            DmCode::MissingKey => "MISSING_KEY",
            DmCode::IdentityMismatch => "IDENTITY_MISMATCH",
            DmCode::Undecryptable => "UNDECRYPTABLE",
            DmCode::DuplicateOrLost => "DUPLICATE_OR_LOST",
            DmCode::GapTooBig => "GAP_TOO_BIG",
            DmCode::NewChain => "NEW_CHAIN",
            DmCode::Internal => "INTERNAL",
        }
    }

    /// Every code of the closed list, in wire order.
    pub const ALL: [DmCode; 18] = [
        DmCode::Ok,
        DmCode::CryptoUnavailable,
        DmCode::InvalidCard,
        DmCode::NotOpen,
        DmCode::BadSignature,
        DmCode::NonCanonical,
        DmCode::InvalidKey,
        DmCode::Oversize,
        DmCode::NoFit,
        DmCode::StateCorrupt,
        DmCode::InvalidSession,
        DmCode::MissingKey,
        DmCode::IdentityMismatch,
        DmCode::Undecryptable,
        DmCode::DuplicateOrLost,
        DmCode::GapTooBig,
        DmCode::NewChain,
        DmCode::Internal,
    ];
}

/// The result of every fallible DM operation.
pub type DmResult<T> = Result<T, DmCode>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_bytes_round_trip_and_are_distinct() {
        let mut seen = Vec::new();
        for code in DmCode::ALL {
            assert_eq!(DmCode::from_u8(code.as_u8()), Some(code));
            assert!(!seen.contains(&code.as_u8()), "duplicate wire byte");
            seen.push(code.as_u8());
        }
        assert_eq!(seen.len(), DmCode::ALL.len());
    }

    #[test]
    fn names_are_distinct_and_screaming_snake_case() {
        let mut names: Vec<&str> = DmCode::ALL.iter().map(|code| code.name()).collect();
        for name in &names {
            assert!(
                name.bytes().all(|b| b.is_ascii_uppercase() || b == b'_'),
                "{name}"
            );
        }
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count);
    }

    #[test]
    fn undefined_bytes_have_no_code() {
        for byte in 0x11u8..=0xfe {
            assert_eq!(DmCode::from_u8(byte), None);
        }
    }
}
