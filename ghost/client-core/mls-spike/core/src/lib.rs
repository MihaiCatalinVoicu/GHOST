//! Phase 10 slice S0 evidence probe (design `docs/design/faza10-forum.md` §14 row S0; evidence
//! `docs/design/faza10-s0-evidence.md`). **Evidence tooling, not product code**: nothing here is
//! linked into a shipped or host library, and `ghost-client-mls` (slice S2) re-implements what it
//! needs under review.
//!
//! - [`kv`]: `GhostKv`, the value-semantics storage adapter of §3.4 (change-set, scopes, wrapping,
//!   the `added_at` day rewrite).
//! - [`provider`]: the provider composition of §3.3 and the pseudonym signer.
//! - [`ext`]: GHOST's MLS extensions and AAD formats (§5.3, §5.4, §5.5, §19.2).
//! - [`harness`]: a channel world over the real OpenMLS 0.9.0 with GHOST's configuration.
//! - [`seal`]: the outer seal's capacities and bucket rule (§5.6, §5.7).
//! - `det` (feature `det`): the process-global seeded stream behind getrandom's custom backend.

pub mod codec;
#[cfg(feature = "det")]
pub mod det;
pub mod ext;
pub mod harness;
pub mod kv;
pub mod provider;
pub mod seal;

/// Pins `rayon`'s global pool to one worker (design §3.6), once per process. Returns the number
/// of threads the pool reports afterwards.
pub fn pin_rayon_single_worker() -> usize {
    let _ = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build_global();
    rayon::current_num_threads()
}
