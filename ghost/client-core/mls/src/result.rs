//! Result codes of the channel API (design §10.2: every function returns `code(1) ‖ TLV fields`;
//! the byte values are the JNI surface's, slice S2b). `MlsResultCodesTest` of the design is
//! [`tests::the_codes_are_enumerated_once`]: the list below is closed, each value is used once, and
//! the detail kinds of `INVALID_COMMIT` are enumerated the same way.

use core::fmt;

/// The code byte. `Ok` is never an error; every other value is.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Code {
    Ok = 0,
    /// A caught panic or an invariant the crate does not expect to break (design §10.2: every
    /// entry point runs under `catch_unwind` with the silent panic hook in S2b).
    Internal = 1,
    /// The crypto provider or the one-worker `rayon` pool could not be set up (fn 1).
    CryptoUnavailable = 2,
    /// A key input of the wrong length or form (fn 2).
    InvalidKey = 3,
    InvalidPolicy = 4,
    /// No KeyPackage of this member matches the Welcome (fn 5).
    NotForMe = 5,
    /// A Welcome OpenMLS refuses, or one that fails the committers anchor or §5.3 (fn 5).
    InvalidWelcome = 6,
    InvalidBootstrap = 7,
    /// A stored row that does not open, a key outside both scopes, or OpenMLS's serde layout moved.
    StateCorrupt = 8,
    /// A commit that fails validation; the reason is [`CommitReason`].
    InvalidCommit = 9,
    Undecryptable = 10,
    WrongEpoch = 11,
    OrderMismatch = 12,
    NonCanonical = 13,
    /// A body larger than `C(65536)`, or a single-proposal commit above the class floor (§5.7).
    NoFit = 14,
    /// A KeyPackage that is not the canonical one (§6.2.4 (B)); the detail is its index.
    InvalidKeyPackage = 15,
    /// Admission evidence that does not verify (§6.2.4 (A), §19.2); the detail is its index.
    InvalidEvidence = 16,
    /// `encrypt` while the own pending commit removes a pseudonym (§6.3.1, §19.13); `commit`
    /// while a commit is already pending (CO-7).
    PendingCommit = 17,
    NotOpen = 18,
    UnsupportedSuite = 19,
    /// A password invite (`kdf_code ≥ 1`) parsed without a password (§19.28.4).
    PasswordRequired = 20,
    /// The invite's AEAD refused: a wrong password or a tampered link (§19.28.4).
    WrongPassword = 21,
    BadSignature = 22,
    WrongPurpose = 23,
}

impl Code {
    pub const ALL: [Code; 24] = [
        Code::Ok,
        Code::Internal,
        Code::CryptoUnavailable,
        Code::InvalidKey,
        Code::InvalidPolicy,
        Code::NotForMe,
        Code::InvalidWelcome,
        Code::InvalidBootstrap,
        Code::StateCorrupt,
        Code::InvalidCommit,
        Code::Undecryptable,
        Code::WrongEpoch,
        Code::OrderMismatch,
        Code::NonCanonical,
        Code::NoFit,
        Code::InvalidKeyPackage,
        Code::InvalidEvidence,
        Code::PendingCommit,
        Code::NotOpen,
        Code::UnsupportedSuite,
        Code::PasswordRequired,
        Code::WrongPassword,
        Code::BadSignature,
        Code::WrongPurpose,
    ];

    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn name(self) -> &'static str {
        match self {
            Code::Ok => "OK",
            Code::Internal => "INTERNAL",
            Code::CryptoUnavailable => "CRYPTO_UNAVAILABLE",
            Code::InvalidKey => "INVALID_KEY",
            Code::InvalidPolicy => "INVALID_POLICY",
            Code::NotForMe => "NOT_FOR_ME",
            Code::InvalidWelcome => "INVALID_WELCOME",
            Code::InvalidBootstrap => "INVALID_BOOTSTRAP",
            Code::StateCorrupt => "STATE_CORRUPT",
            Code::InvalidCommit => "INVALID_COMMIT",
            Code::Undecryptable => "UNDECRYPTABLE",
            Code::WrongEpoch => "WRONG_EPOCH",
            Code::OrderMismatch => "ORDER_MISMATCH",
            Code::NonCanonical => "NON_CANONICAL",
            Code::NoFit => "NO_FIT",
            Code::InvalidKeyPackage => "INVALID_KEYPACKAGE",
            Code::InvalidEvidence => "INVALID_EVIDENCE",
            Code::PendingCommit => "PENDING_COMMIT",
            Code::NotOpen => "NOT_OPEN",
            Code::UnsupportedSuite => "UNSUPPORTED_SUITE",
            Code::PasswordRequired => "PASSWORD_REQUIRED",
            Code::WrongPassword => "WRONG_PASSWORD",
            Code::BadSignature => "BAD_SIGNATURE",
            Code::WrongPurpose => "WRONG_PURPOSE",
        }
    }
}

/// Why a commit is `INVALID_COMMIT` (the detail byte of the code). CO-2 of design §6.4 as far as
/// it is a function of the commit, the pre-commit group state and its `GhostCommitAad`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CommitReason {
    /// OpenMLS refused an Add's KeyPackage lifetime (`LifetimeError`): with the constant lifetime
    /// of Q42 (a) only a non-canonical KeyPackage reaches it, so the commit is invalid for every
    /// member (§19.29.1).
    Lifetime = 1,
    /// Any other refusal of `process_message` (framing, signature, path, proposal set).
    Refused = 2,
    /// The sender is not a member (an external commit, CO-1).
    NotAMember = 3,
    /// The body exceeds `C(floor)` of the class (§5.7).
    Size = 4,
    /// The authenticated data is not a canonical `GhostCommitAad` (§19.2).
    Aad = 5,
    /// An Add or swap without its evidence entry, or evidence that does not verify (§6.2.4 (A)).
    Evidence = 6,
    /// The update-path leaf's `GhostLeaf.refresh_epoch` is not the commit's epoch, or it is missing
    /// (§19.5).
    RefreshEpoch = 7,
    /// A leaf the commit installs is not canonical (S0-5), an Add's KeyPackage is not the
    /// canonical KeyPackage (lifetime included, §19.29.1), or an HPKE key of the tree the commit
    /// produces (a leaf's or a parent node's) is not a valid X25519 key (review H1, §19.31).
    NonCanonicalLeaf = 8,
    /// A leaf the commit installs changes its member's signature key or credential (§19.14).
    Continuity = 9,
    /// A commit with an Add or a restore swap changes `committers` (S0-15).
    CommittersChanged = 10,
    /// The resulting `GhostChannelContext` is invalid (§5.3), or its change breaks the password
    /// policy (§19.28.3).
    Context = 11,
    /// A rank rule of CO-1/CO-2: a rank-255 commit with a proposal, a Remove of an equal or lower
    /// rank, a context change from a rank that may not make it, a rotation flag from a
    /// non-committer.
    Permission = 12,
    /// A proposal type GHOST never commits (Update, PSK, ReInit, ExternalInit, …).
    Proposal = 13,
    /// CO-14: a rank-255 commit whose sender's leaf was refreshed within the last `min(8, n)`
    /// epochs (review of S2a, §19.31).
    Rate = 14,
}

impl CommitReason {
    pub const ALL: [CommitReason; 14] = [
        CommitReason::Lifetime,
        CommitReason::Refused,
        CommitReason::NotAMember,
        CommitReason::Size,
        CommitReason::Aad,
        CommitReason::Evidence,
        CommitReason::RefreshEpoch,
        CommitReason::NonCanonicalLeaf,
        CommitReason::Continuity,
        CommitReason::CommittersChanged,
        CommitReason::Context,
        CommitReason::Permission,
        CommitReason::Proposal,
        CommitReason::Rate,
    ];
}

/// An error of the channel API: its code and, for the codes that carry one, the detail
/// (`INVALID_COMMIT(reason)`, `INVALID_KEYPACKAGE(index)`, `INVALID_EVIDENCE(index)`).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MlsError {
    pub code: Code,
    pub detail: Detail,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Detail {
    None,
    Index(u16),
    Reason(CommitReason),
}

impl MlsError {
    pub const fn new(code: Code) -> Self {
        Self {
            code,
            detail: Detail::None,
        }
    }
    pub const fn at(code: Code, index: u16) -> Self {
        Self {
            code,
            detail: Detail::Index(index),
        }
    }
    pub const fn commit(reason: CommitReason) -> Self {
        Self {
            code: Code::InvalidCommit,
            detail: Detail::Reason(reason),
        }
    }
}

impl From<Code> for MlsError {
    fn from(code: Code) -> Self {
        MlsError::new(code)
    }
}

impl fmt::Debug for MlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // No payload, no secret: a code name and a small detail only (a Debug string can reach a
        // panic message).
        match self.detail {
            Detail::None => f.write_str(self.code.name()),
            Detail::Index(i) => write!(f, "{}({i})", self.code.name()),
            Detail::Reason(r) => write!(f, "{}({r:?})", self.code.name()),
        }
    }
}

impl fmt::Display for MlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for MlsError {}

pub type MlsResult<T> = Result<T, MlsError>;

#[cfg(test)]
mod tests {
    use super::*;

    /// The design's `MlsResultCodesTest`: every code has one value and one name, the values are
    /// dense from 0, and `ALL` lists every variant (a variant added without a line here fails the
    /// exhaustive match below).
    #[test]
    fn the_codes_are_enumerated_once() {
        for (i, c) in Code::ALL.iter().enumerate() {
            assert_eq!(c.as_u8() as usize, i, "{} is not at its index", c.name());
            let exhaustive = match c {
                Code::Ok
                | Code::Internal
                | Code::CryptoUnavailable
                | Code::InvalidKey
                | Code::InvalidPolicy
                | Code::NotForMe
                | Code::InvalidWelcome
                | Code::InvalidBootstrap
                | Code::StateCorrupt
                | Code::InvalidCommit
                | Code::Undecryptable
                | Code::WrongEpoch
                | Code::OrderMismatch
                | Code::NonCanonical
                | Code::NoFit
                | Code::InvalidKeyPackage
                | Code::InvalidEvidence
                | Code::PendingCommit
                | Code::NotOpen
                | Code::UnsupportedSuite
                | Code::PasswordRequired
                | Code::WrongPassword
                | Code::BadSignature
                | Code::WrongPurpose => true,
            };
            assert!(exhaustive);
        }
        let mut names: Vec<&str> = Code::ALL.iter().map(|c| c.name()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), Code::ALL.len());
        for (i, r) in CommitReason::ALL.iter().enumerate() {
            assert_eq!(*r as usize, i + 1);
        }
        // `LIFETIME_PENDING` of S0-12 is withdrawn (§19.29.1): a lifetime refusal is
        // `INVALID_COMMIT(lifetime)`.
        assert!(!names.contains(&"LIFETIME_PENDING"));
    }

    #[test]
    fn errors_render_without_payload() {
        assert_eq!(
            format!("{:?}", MlsError::commit(CommitReason::Lifetime)),
            "INVALID_COMMIT(Lifetime)"
        );
        assert_eq!(
            format!("{:?}", MlsError::at(Code::InvalidKeyPackage, 2)),
            "INVALID_KEYPACKAGE(2)"
        );
    }
}
