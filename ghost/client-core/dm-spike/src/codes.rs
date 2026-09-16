//! The DM result codes of the closed JNI surface (design §2.6, amended by §22.8.2 and §22.8.3)
//! that the spikes map library errors onto. `OK` is the absence of an error.

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Code {
    /// `MISSING_KEY`: the PreKey message names a fallback key the generation does not hold.
    MissingKey,
    /// `IDENTITY_MISMATCH`: the PreKey message's identity is not the expected (pinned) one.
    IdentityMismatch,
    /// `INVALID_KEY`: a non-contributory or malformed public key (§22.8.2).
    InvalidKey,
    /// `UNDECRYPTABLE`: MAC, padding or format failure.
    Undecryptable,
    /// `DUPLICATE_OR_LOST`: the message key is gone (used, evicted or never stored).
    DuplicateOrLost,
    /// `GAP_TOO_BIG`: the forward gap exceeds Olm's 2 000.
    GapTooBig,
    /// `INVALID_SESSION`: any library encryption error (§22.8.2 rule 2).
    InvalidSession,
    /// `STATE_CORRUPT`: stored state that does not open or parse (§22.8.3).
    StateCorrupt,
    /// `NOT_OPEN`: a seal or KEM ciphertext that does not open (§22.8.2 rule 4).
    NotOpen,
}
