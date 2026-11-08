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

// ---------------------------------------------------------------------------
// Slice S6c: the remaining rows of §11.3's table. Each constant names its design row; the
// site's comment carries the kill world. Rows without a constant are documented gaps (the
// table's site lives outside this crate or needs a fixture the slices have not built).
// ---------------------------------------------------------------------------

/// MC-D1: the chain walk verifies the transition root against its own (new) keyset — the old
/// threshold is not enforced. Killed by the bad-transition-root world (a v(n+1) root signed by
/// a key of neither old keyset, logged correctly, must not be adopted).
pub const OLD_THRESHOLD_SKIPPED: u32 = 1;
/// MC-D2: the chain walk does not verify the transition root's block at all. Killed by the
/// same bad-transition-root world.
pub const NEW_THRESHOLD_SKIPPED: u32 = 2;
/// MC-D3: the manifest's release signature block is not verified — a manifest under a key no
/// longer in the root is accepted. Killed by the revoked-signature world (a valid manifest with
/// one flipped block byte and a rebuilt proof).
pub const MANIFEST_BLOCK_SKIPPED: u32 = 3;
/// MC-D5: the bundle's network byte is not checked against the app's network. Killed by the
/// WRONG_NETWORK world.
pub const NETWORK_IGNORED: u32 = 5;
/// MC-D9: the proof's Merkle inclusion path is not checked. Killed by the broken-inclusion
/// proof fixture (one path node flipped; the checkpoint stays signed).
pub const INCLUSION_SKIPPED: u32 = 9;
/// MC-D10: the tree-head (log) signature is not checked. Killed by the flipped-log-signature
/// proof fixture.
pub const TREE_HEAD_SKIPPED: u32 = 10;
/// MC-D11: the witness quorum is not enforced. Killed by the no-cosignature proof fixture.
pub const QUORUM_NOT_ENFORCED: u32 = 11;
/// MC-D12: cosignatures by unknown witnesses count toward the quorum (no lookup, no
/// verification). Killed by the unknown-witness proof fixture.
pub const UNKNOWN_WITNESS_COUNTED: u32 = 12;
/// MC-D13: the mirror fetch reads past its fixed bound (the response larger than the bundle's
/// 1 MiB / the chunk's 4 MiB is accepted). Wired in `ghost-client-net`'s fetch; killed by the
/// ENDLESS world on the wire (a JVM-seam gap: the harness seam serves whole byte arrays).
pub const PAST_BOUND: u32 = 13;
/// MC-D14: the whole-file SHA-256 is not compared — swapped APK bytes pass. Killed by the
/// APK_SWAP world.
pub const FULL_HASH_SKIPPED: u32 = 14;
/// MC-D15: the core comparison and the attestation clause are skipped. Wired; kill-gap: the
/// arms sit behind the whole-file hash, unreachable without a second mutation.
pub const CORE_ATTESTATION_SKIPPED: u32 = 15;
/// MC-D16: a release at the installed versionCode is offered — `>=` replaces `>`. Killed by the
/// offer suite (an installed-2 client must not be offered version 2).
pub const OFFER_AT_OR_BELOW: u32 = 16;
/// MC-D18: the manifest's root binding (version and hash) is not checked — an older root's
/// manifest is adopted under the new trust. Killed by the cross-root manifest world (a manifest
/// naming root 1, signed and logged under root 2's keys).
pub const OLDER_ROOT_ADOPTED: u32 = 18;
/// MC-D19: the run uses one mirror — the second pick repeats the first. Killed by the mirror
/// view (the world's slot-to-mirror mapping sees the same mirror serve both slots).
pub const ONE_MIRROR_PER_RUN: u32 = 19;
/// MC-D20: the proof's message is not bound to the file — a proof of another manifest is
/// accepted. Killed by the re-messaged proof fixture (honest leaf, log and inclusion over the
/// served file, message naming another).
pub const PROOF_OF_OTHER_ACCEPTED: u32 = 20;
/// MC-D21: the signing block is located from the release's unsigned length, not from the
/// file's footer — the padding is treated as block. Killed by the benign world (the honest
/// APK's signer digest no longer verifies).
pub const BLOCK_FROM_MANIFEST: u32 = 21;
/// MC-D23: a new root is adopted without its log proof under the previous root's policy. Killed
/// by the wrong-message root-proof fixture (a valid proof of another file in the root-proof
/// section).
pub const ROOT_WITHOUT_LOG_PROOF: u32 = 23;
/// MC-D24: both mirrors are drawn from the manifest's extras — no anchor mirror in the run.
/// Killed by the stolen-release-key world (the anchor channel must stay in the draw).
pub const NO_ANCHOR_MIRROR: u32 = 24;
/// MC-D25: the floor is not bounded by the manifest's attested releases and not scoped to its
/// root version. Wired at both sites; killed via the scoping half (the floor must reset when a
/// new root is adopted — the stolen-release-key world). The bound half's kill fixture (a
/// validly signed manifest whose attestations do not meet the root's set) needs attestation
/// re-signing, a crafted-suite slice.
pub const FLOOR_UNBOUNDED: u32 = 25;
/// MC-D26: the core is "the file minus the block" — the zero padding is hashed into the core.
/// Killed by the benign world (the honest APK's core no longer matches the attested unsigned
/// build).
pub const CORE_MINUS_BLOCK: u32 = 26;
/// MC-D27: the signer is read from the v3.1 block whatever the SDK — the [minSdk, maxSdk]
/// window is ignored. Wired; kill-gap: needs a v3.1-with-lineage fixture (the crafted suite).
pub const SIGNER_FROM_V31: u32 = 27;
/// MC-D28: the trust anchor is the embedded chain's last root whatever the stored state — a
/// newer stored root is demoted at the next start. Killed by the epoch-restart world (a stored
/// root-2 state started over the root-1 embedded chain keeps root 2).
pub const ANCHOR_IS_EMBEDDED: u32 = 28;
/// MC-D29: the root leaf is accepted only from a release key of the previous root — root keys
/// are refused (revision 1's rule). Killed by the rotation world (the fixture chain's root
/// proof is submitted by a root key).
pub const ROOT_LEAF_RELEASE_ONLY: u32 = 29;
/// MC-D30: an expired manifest applies its directory and mirrors. Killed by the EXPIRED_REPLAY
/// world (the attacker relay must not enter the directory).
pub const EXPIRED_DIRECTORY: u32 = 30;
/// MC-D32: the stored manifest stays current after a newer root — offers keep coming from the
/// old root's manifest. Killed by the rotation world (the offer must come from the new root's
/// manifest).
pub const STORED_MANIFEST_STAYS: u32 = 32;

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
