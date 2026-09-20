//! The Olm facade over vodozemac 0.11.0 (design §2.1–§2.2, §7.9, §8.1; slice S4b).
//!
//! GHOST uses Olm **unchanged, through public API**, inside this crate, with exactly one recorded
//! exception: [`pickle`], the serde-layout reads the gap hold and the age bound need (§2.1). Olm
//! receives no address, no contact identifier and no device id — a session is a wrapped pickle in a
//! row keyed by the random local `contact_id` and a slot (§8.1) — and it is never given a clock:
//! every time value in this module is an argument.
//!
//! | Module | Design |
//! |---|---|
//! | [`account`] | §2.2 throwaway accounts through the MSC3814 dehydrated pickle |
//! | [`message`] | §2.6 the L1 header and the closed error mapping |
//! | [`state`] | §7.7 point 4 the stored state and its first-seen sidecar |
//! | [`pickle`] | §2.1 the recorded pickle-layout deviation (`chainPosition`, `sessionPrune`) |
//! | [`session`] | §8.1 the session calls themselves |
//!
//! The configuration is fixed: `SessionConfig::version_1()` everywhere, and the features
//! `libolm-compat`, `low-level-api`, `experimental-session-config` and `insecure-pk-encryption`
//! are forbidden in the shipped graph (D1, gate G-R2). A PreKey message of another session version
//! is `UNDECRYPTABLE`, never a silent downgrade (§2.6 function 14, S0′ V-2).

pub mod account;
pub mod message;
pub mod pickle;
pub mod session;
pub mod state;

pub use message::L1Header;
pub use pickle::{ChainPosition, SkippedKey};
pub use session::{
    Decrypted, Encrypted, Inbound, Outbound, Slot, StoredSession, SKIPPED_KEY_MAX_AGE_DAYS,
};
pub use state::{SessionState, Sidecar, SESSION_STATE_MAX, SIDECAR_MAX};

/// The pinned vodozemac version. Golden pickles, the key-schedule oracle and the encoder check
/// live under `tests/golden/vodozemac-<VODOZEMAC_VERSION>/`, and G-R7 compares this string with
/// the directory it reads, so a bump cannot land without regenerated goldens (§2.8, §15.2).
pub const VODOZEMAC_VERSION: &str = "0.11.0";
