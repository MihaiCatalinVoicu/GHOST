//! `issued.journal` pruning on the real issuer (Phase 8 design §6.3, §6.4, §19.15; runbook B1,
//! `ghost-issuer-ops journal-prune`): the segments `journal::prune_dir` removes after the verified
//! snapshot's `journal_applied` leave a journal on which the issuer restarts and from which a
//! restore of that snapshot replays, at every point of the removal. Segments are removed one at a
//! time, oldest first, so a crash during a prune leaves a removed prefix; each prefix is checked
//! with the prune running while the issuer runs, then after a crash and restart, then after a
//! restore from the snapshot, each followed by `World::check` (MS-1, MS-3, indexes, pool, payouts,
//! reconciliation) and the client's retries: another request for an issued invoice is refused and
//! the identical one re-signed byte for byte (MS-1).

mod common;

use common::faults::FaultPlan;
use common::scenarios::other_blinded;
use common::world::World;
use ghost_entitlement::grid::WEEK_SECS;
use ghost_issuer::journal::{self, PruneError, SEGMENT_PREFIX};
use ghost_issuer::service::OpenMode;
use ghost_issuer::store::{self, MetaKey, RedbSnapshot};
use ghost_issuer_api::proto as wire;

const OTHER: i32 = wire::InvoiceState::OtherRequestIssued as i32;

/// The weeks of the journal segments in a world's directory, ascending.
fn segments(w: &World) -> Vec<u64> {
    let mut weeks: Vec<u64> = std::fs::read_dir(w.dir.path().join("journal"))
        .unwrap()
        .filter_map(|e| {
            let name = e.unwrap().file_name().into_string().unwrap();
            name.strip_prefix(SEGMENT_PREFIX)
                .map(|s| s.parse().unwrap())
        })
        .collect();
    weeks.sort_unstable();
    weeks
}

fn remove_segment(w: &World, week: u64) {
    std::fs::remove_file(
        w.dir
            .path()
            .join("journal")
            .join(format!("{SEGMENT_PREFIX}{week}")),
    )
    .unwrap();
}

/// `journal_applied` of the world's snapshot, read as `journal-prune` reads it: through a
/// recovered private copy.
fn snapshot_applied(w: &World) -> u64 {
    let scratch = tempfile::tempdir().unwrap();
    let snapshot =
        RedbSnapshot::open_in(&w.dir.path().join("snapshot.redb"), scratch.path()).unwrap();
    let tx = snapshot.read().unwrap();
    store::meta(&*tx, MetaKey::JournalApplied)
        .unwrap()
        .unwrap_or(0)
}

/// One XMR pack in each of weeks 2960, 2961 and 2962, the hourly snapshot, then a pack in week
/// 2963, after it. The clock ends on Monday 12:00 of week 2963: segments 2960 and 2961 are past the
/// 7-day re-serve window and covered by the snapshot, 2962 is inside the window, 2963 is the
/// latest. Returns each pack's label and signatures.
fn world() -> (World, Vec<(String, Vec<u8>)>) {
    let mut w = World::new(true);
    let mut held = Vec::new();
    for i in 0..4 {
        if i == 3 {
            w.snapshot();
        }
        let label = format!("prune-{}", w.week());
        w.buy_pack(&label);
        held.push((label.clone(), w.sign(&label).unwrap().blind_signatures));
        if i < 3 {
            w.advance(WEEK_SECS);
            w.tick();
        }
    }
    assert_eq!(segments(&w), vec![2960, 2961, 2962, 2963]);
    (w, held)
}

/// The client retries every pack: another request first (an identical retry of a CONFIRMED invoice
/// would re-sign and hide a lost ISSUE), then the identical one.
fn retries(w: &mut World, held: &[(String, Vec<u8>)]) {
    for (label, signatures) in held {
        let other = other_blinded(w, label);
        assert_eq!(
            w.sign_with(label, other).unwrap().state,
            OTHER,
            "MS-1: another request signed for {label}"
        );
        assert_eq!(
            &w.sign(label).unwrap().blind_signatures,
            signatures,
            "MS-1: {label} re-signed differently"
        );
    }
}

#[test]
fn every_prefix_of_a_prune_leaves_a_journal_to_restart_and_restore_on() {
    let (w, held) = world();
    let applied = snapshot_applied(&w);
    let now = w.now;
    let template = w.template();

    let probe = World::from_template(&template, FaultPlan::new(Vec::new()));
    let pruned = journal::prune_dir(&probe.dir.path().join("journal"), now, applied).unwrap();
    assert_eq!(pruned.removed, vec![2960, 2961]);
    assert_eq!(pruned.kept, 2);
    assert!(pruned.first_seq <= applied + 1 && applied < pruned.last_seq);
    drop(probe);

    for k in 0..=pruned.removed.len() {
        let mut w = World::from_template(&template, FaultPlan::new(Vec::new()));
        // The prune runs from the host while the issuer serves; it stops after k removals.
        for week in &pruned.removed[..k] {
            remove_segment(&w, *week);
        }
        retries(&mut w, &held);
        w.check();
        w.reopen();
        retries(&mut w, &held);
        w.check();
        w.restore();
        retries(&mut w, &held);
        w.check();
        // A later run finishes the prune: the snapshot still fits, the rest goes.
        let rest = journal::prune_dir(&w.dir.path().join("journal"), now, applied).unwrap();
        assert_eq!(rest.removed, pruned.removed[k..].to_vec(), "prefix {k}");
    }
}

/// The issuer crashed in the middle of an append: the latest segment ends in a torn frame. The
/// prune leaves its bytes alone (it may be the issuer's live file), and the issuer's own restart
/// discards the tail as before.
#[test]
fn a_prune_never_touches_the_segment_the_issuer_writes() {
    let (mut w, held) = world();
    let applied = snapshot_applied(&w);
    w.crash();
    let latest = w
        .dir
        .path()
        .join("journal")
        .join(format!("{SEGMENT_PREFIX}2963"));
    let mut bytes = std::fs::read(&latest).unwrap();
    bytes.extend_from_slice(&[0, 0, 0, 60, 0, 0]);
    std::fs::write(&latest, &bytes).unwrap();
    let pruned = journal::prune_dir(&w.dir.path().join("journal"), w.now, applied).unwrap();
    assert_eq!(pruned.removed, vec![2960, 2961]);
    assert_eq!(std::fs::read(&latest).unwrap(), bytes);
    w.open(OpenMode::Normal);
    w.refill();
    w.tick();
    retries(&mut w, &held);
    w.check();
    assert!(std::fs::read(&latest).unwrap().len() < bytes.len());
}

/// A snapshot that does not fit the journal removes nothing: one newer than the journal (another
/// issuer's, or a journal that lost its end) and one the journal no longer continues.
#[test]
fn a_snapshot_that_does_not_fit_the_journal_removes_nothing() {
    let (mut w, _) = world();
    let applied = snapshot_applied(&w);
    w.crash();
    let dir = w.dir.path().join("journal");
    let last = journal::prune_dir(&dir, 0, applied).unwrap().last_seq;
    assert_eq!(
        journal::prune_dir(&dir, u64::MAX, last + 1).err(),
        Some(PruneError::SnapshotAhead)
    );
    assert_eq!(segments(&w), vec![2960, 2961, 2962, 2963]);
    remove_segment(&w, 2960);
    assert_eq!(
        journal::prune_dir(&dir, u64::MAX, 0).err(),
        Some(PruneError::SnapshotBehind)
    );
    assert_eq!(segments(&w), vec![2961, 2962, 2963]);
}
