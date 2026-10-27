//! The §11.3 mutation switches (Phase 14 design §11.3; slice S6c): one process-wide selector set
//! per JVM world through the host library's `UpdateMutants.select` JNI entry (test libraries
//! only, G-D5; the symbol exists only when `ghost-client-net` is built with `test-mutants`,
//! which only `ghost-dm-host` enables). Each mutation site reads [`active`]; with the selector
//! at 0 (the default) every site is the shipped code path, so a control world and a mutant world
//! differ in exactly the switch — the same-crate, same-build discipline as the DM stack's
//! `test-vectors`/`pq-spy` pattern.
//!
//! IDs are the design's MC-D numbers (§11.3's table): id n is MC-Dn, so a world's report names
//! the design row it killed. Constants appear as they are wired; the table's rows without a
//! constant yet are the slices that have not landed their mutation.

use core::sync::atomic::{AtomicU32, Ordering};

/// The selected mutant; 0 = none (the shipped behaviour at every site).
static ACTIVE: AtomicU32 = AtomicU32::new(0);

/// MC-D6: a lower `(root_version, manifest_seq)` pair is accepted — the `Rollback` refusal of
/// decision.rs's step 6 is skipped. Killed by the ROLLBACK mirror world.
pub const LOWER_PAIR_ACCEPTED: u32 = 6;
/// MC-D7: an equal pair with other bytes is accepted — no `Conflict` evidence is kept. Killed by
/// the EQUIVOCATE mirror world.
pub const EQUAL_PAIR_ACCEPTED: u32 = 7;
/// MC-D8: the not-after day is ignored — an expired manifest is treated as fresh and contributes
/// its directory and mirrors (MC-D30 is the same site, killed by the EXPIRED_REPLAY world).
/// Killed by the STALE world.
pub const EXPIRY_IGNORED: u32 = 8;
/// MC-D17: a manifest lowers the floor within its root version — `min` replaces `max`. Killed by
/// the floor trigger tests and the floor world.
pub const FLOOR_LOWERED: u32 = 17;

/// Selects the mutant the next calls run under; 0 restores the shipped behaviour at every site.
/// Called only from the host library's test JNI entry; a world selects once at construction,
/// before its first native call, and the selector never changes mid-run.
pub fn select(id: u32) {
    ACTIVE.store(id, Ordering::SeqCst);
}

/// Whether mutant `id` is the selected one.
pub fn active(id: u32) -> bool {
    ACTIVE.load(Ordering::SeqCst) == id
}
