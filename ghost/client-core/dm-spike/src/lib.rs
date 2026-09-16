//! Phase 9 S0′ measurement probe and spikes (design `docs/design/faza9-dm.md` §17.1 row S0′,
//! §22.8 and Appendix C, checks V-1 … V-16). The evidence and the values to freeze are in
//! `docs/design/faza9-s0-evidence.md`.
//!
//! This crate is not shipped and not a member of the ghost workspace. Its library holds the code
//! the checks share; the checks themselves are the integration tests under `tests/`, the JVM
//! programs under `jvm/` and the scripts under `scripts/`. Nothing here prints: measurements are
//! returned to the tests, which report them.

pub mod codes;
pub mod derive;
pub mod harness;
pub mod msc3814;
pub mod olm;
pub mod pickle_bound;
pub mod prune;
pub mod reorder;
pub mod safety;
pub mod schedule;
pub mod sizes;
pub mod xwing;

#[cfg(feature = "jni-host")]
pub mod jni_host;
