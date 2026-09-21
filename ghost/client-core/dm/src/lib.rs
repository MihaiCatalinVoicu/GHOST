//! `ghost-client-dm`: the GHOST direct-message cryptography (Phase 9 design
//! `docs/design/faza9-dm.md`, §2–§9, as corrected by §21, §22 and the S0′ evidence of
//! `docs/design/faza9-s0-evidence.md`).
//!
//! Everything a DM needs below the session layer lives here, in Rust, because the ratchet and the
//! KEM are native and a Kotlin seal would have to receive the X-Wing shared secret and `k_in` on
//! the JVM heap, where they cannot be zeroised (§2.4). Kotlin keeps transaction control, database
//! rows, `:sync` calls, the Keystore wrappers and the recognition-hint **matching**; it never
//! holds an opening key in clear.
//!
//! **Slice S4a** was this crate without Olm: derivations, the contact card, the four seal modes,
//! the X-Wing wrapper and the intro inner layer, binding v3, the L0 codec, safety numbers and
//! state wrapping. **Slice S4b** adds [`olm`]: throwaway accounts through the MSC3814 dehydrated
//! pickle, the session calls, the stored state with its first-seen sidecar, and the two recorded
//! pickle-layout reads (`chainPosition`, `sessionPrune`).
//!
//! The crate has no network, no async runtime, no logging and **no clock**: every time value is an
//! argument (`binding_minute`, `today`, `now_minute`), which is what makes the deterministic
//! host/Android equivalence fixture of §15.9 item 7 possible and what keeps T13 and T33
//! executable. Randomness is drawn from the OS CSPRNG in exactly one place, `pq::fill_random`, and
//! every operation a vector replays takes its salt, nonce or KEM randomness as an argument
//! instead, through a `*_with` variant beside the production entry point.
//!
//! # Module map
//!
//! | Module | Design |
//! |---|---|
//! | [`derive`] | §3.1, §3.2 derivations and the typed key inputs of T26 |
//! | [`card`] | §3.3 contact card v2 and its link |
//! | [`binding`] | §3.4 binding v3 |
//! | [`bundle`] | §5.3, §5.4 bundle v2 |
//! | [`seal`] | §6 the four seal modes, buckets and recognition |
//! | [`pq`] | §9.2 the X-Wing wrapper |
//! | [`codec`] | §7.1 the L0 content codec and the TLV registry |
//! | [`olm`] | §2.2, §7.9, §8.1 the Olm facade over vodozemac |
//! | [`safety`] | §8.4 safety number v1 |
//! | [`wrap`] | §2.5, §22.8.3 state wrapping |
//! | [`provenance`] | §9.3 the PQ-B provenance tags of T35 |
//! | [`result`] | §2.6 the closed result-code list |
//! | [`sign`] | §2.4 Ed25519 for the X-21 artifacts |
//! | [`zbase32`] | the card link encoding |

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod binding;
pub mod bundle;
pub mod card;
pub mod codec;
pub mod derive;
#[cfg(feature = "jni-bridge")]
pub mod jni;
pub mod olm;
pub mod pq;
#[cfg(test)]
pub(crate) mod property;
pub mod provenance;
pub mod result;
pub mod revocation;
pub mod safety;
pub mod seal;
pub mod sign;
pub mod wrap;
pub mod zbase32;

pub use result::{DmCode, DmResult};
