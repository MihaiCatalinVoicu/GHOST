//! The typed result codes of the media crate (design §13.2's names; the S2 native surface maps them
//! onto `MediaResult` codes one to one).

use core::fmt;

/// A media result code. Every refusal of untrusted bytes is one of these, never a panic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Code {
    /// Bytes that do not parse exactly, break a rule of the canonical formats (§3.5, §4.1, §8.2,
    /// §8.3), or disagree with what the walker parsed (§3.5).
    NonCanonical,
    /// A chunk or manifest whose ChaCha20-Poly1305 tag does not verify (§3.4).
    NotOpen,
    /// A manifest whose commitment is not the one the key derives (§3.4, §3.5).
    CommitMismatch,
    /// A fragment or manifest that is not the blob its hash names (§3.4).
    HashMismatch,
    /// A chunk index outside the object (§13.2 M6).
    IndexRange,
    /// A second seal of one chunk index: a GHOST bug, never a peer's doing (§3.7 point 2).
    IndexReused,
    /// Content above `MAX_CONTENT`, the image bound or the sealer's largest class (§13.2 M2).
    Oversize,
    /// A source outside the allowlist of §6.1 (`sniff`, §13.2 M10).
    Unsupported,
    /// A call the sealer or reader state machine does not allow at this point (a sealer used after
    /// `finish` or a refusal, a validation pass out of order): a caller bug, never a peer's doing.
    /// Added by S1: §13.2 names no code for it; S2 maps it onto its own.
    Sequence,
}

impl Code {
    /// The code's name as §13.2 spells it: the form the vectors and the counters use.
    pub fn name(self) -> &'static str {
        match self {
            Code::NonCanonical => "NON_CANONICAL",
            Code::NotOpen => "NOT_OPEN",
            Code::CommitMismatch => "COMMIT_MISMATCH",
            Code::HashMismatch => "HASH_MISMATCH",
            Code::IndexRange => "INDEX_RANGE",
            Code::IndexReused => "INDEX_REUSED",
            Code::Oversize => "OVERSIZE",
            Code::Unsupported => "UNSUPPORTED",
            Code::Sequence => "SEQUENCE",
        }
    }

    /// The code of a name, or `None` for any other text (the vector replay's reader).
    pub fn from_name(name: &str) -> Option<Code> {
        [
            Code::NonCanonical,
            Code::NotOpen,
            Code::CommitMismatch,
            Code::HashMismatch,
            Code::IndexRange,
            Code::IndexReused,
            Code::Oversize,
            Code::Unsupported,
            Code::Sequence,
        ]
        .into_iter()
        .find(|c| c.name() == name)
    }
}

/// A refusal: the code, and a fixed text naming the rule that failed (never data from the input,
/// never a secret; tests read it to check that a case fails for its own reason).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MediaError {
    code: Code,
    rule: &'static str,
}

impl MediaError {
    /// A refusal with its code and rule.
    pub const fn new(code: Code, rule: &'static str) -> Self {
        MediaError { code, rule }
    }

    /// `NON_CANONICAL` for `rule`.
    pub const fn non_canonical(rule: &'static str) -> Self {
        MediaError::new(Code::NonCanonical, rule)
    }

    /// The code.
    pub fn code(&self) -> Code {
        self.code
    }

    /// The rule that failed.
    pub fn rule(&self) -> &'static str {
        self.rule
    }
}

impl fmt::Debug for MediaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.code.name(), self.rule)
    }
}

impl fmt::Display for MediaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for MediaError {}

/// The crate's result type.
pub type MediaResult<T> = Result<T, MediaError>;
