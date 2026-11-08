//! GHOST update decision (Phase 14 design §7.4, §7.8), the pure client half of the channel.
//!
//! Everything here is a pure function of its inputs: the crate has no I/O, no clock, no logging
//! and no async runtime (`#![forbid(unsafe_code)]`). The caller (the `:update` module through
//! `UpdateNative`) supplies the stored facts (§9.6), the embedded root chain, the installed
//! `versionCode`/SDK, the trusted day and the run's randomness; the crate returns the new facts
//! to persist and the offer, if any. The APK parse and core hash (§7.4 steps 9–10) land with the
//! next slice.

#![forbid(unsafe_code)]

pub mod state;
pub mod decision;
pub mod offer;
pub mod draw;
pub mod apk;
pub mod codec;
#[cfg(feature = "mutants")]
pub mod mutants;

pub use state::{StoredState, TrustEpoch, Pair, Floor, Time, ChannelStatus, PersistedChange};
pub use decision::{accept_bundle, start_epoch, AcceptOutcome};
pub use offer::{offer, Offer, OfferResult};
pub use draw::{draw_mirrors, MirrorPick};

use ghost_client_release::FormatError;

/// Every refusal code of §7.4/§7.5, one enum; the strings are the fixed vocabulary Phase 13 shows.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UpdateError {
    #[error("CLOCK_UNTRUSTED")]
    ClockUntrusted,
    #[error("WRONG_NETWORK")]
    WrongNetwork,
    #[error("ROOT_CHAIN_BROKEN")]
    RootChainBroken,
    #[error("ROOT_UNLOGGED")]
    RootUnlogged,
    #[error("ROOT_MISMATCH")]
    RootMismatch,
    #[error("BAD_SIGNATURE")]
    BadSignature,
    #[error("MALFORMED")]
    Malformed,
    #[error("FLOOR_INVALID")]
    FloorInvalid,
    #[error("LOG_PROOF_INVALID")]
    LogProofInvalid,
    #[error("QUORUM_NOT_MET")]
    QuorumNotMet,
    #[error("NOT_YET_VALID")]
    NotYetValid,
    #[error("ROLLBACK")]
    Rollback,
    #[error("UNCHANGED")]
    Unchanged,
    #[error("CONFLICT")]
    Conflict,
    #[error("NO_MANIFEST")]
    NoManifest,
    #[error("STALE")]
    Stale,
    #[error("SDK_UNSUPPORTED")]
    SdkUnsupported,
    #[error("UNSUPPORTED")]
    Unsupported,
    #[error("UP_TO_DATE")]
    UpToDate,
    #[error("APK_LAYOUT")]
    ApkLayout,
    #[error("APK_LENGTH")]
    ApkLength,
    #[error("APK_HASH")]
    ApkHash,
    #[error("APK_CORE")]
    ApkCore,
    #[error("APK_SIGNER")]
    ApkSigner,
    #[error("ATTESTATION_QUORUM")]
    AttestationQuorum,
    #[error("OUT_OF_ORDER")]
    OutOfOrder,
}

impl From<FormatError> for UpdateError {
    fn from(e: FormatError) -> Self {
        // A structurally invalid document is a malformed one; the fine grain of FormatError stays
        // internal to the format crate.
        match e {
            FormatError::Network => UpdateError::WrongNetwork,
            _ => UpdateError::Malformed,
        }
    }
}

// debug helper
fn trace_state(s: &State) {
    println!("state: {:?}", s);
}
