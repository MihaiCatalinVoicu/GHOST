//! The weekly ANCHOR journal entry (Phase 8 design §19.25 points 2 and 5, Q32; runbook B1 and
//! §13) on the real issuer, redb store and journal. The first scanner tick of a week whose segment
//! holds no entry, once the process's ticks have agreed on that week for `ANCHOR_SETTLE_SECS`
//! (review finding Q32-CLOCK-1), while the journal holds an entry of an earlier week, decides a
//! data-free entry into it, so an idle issuer's journal gets a fresh segment every week and the
//! segment of its last transition (claim hashes, minors, digests, nullifiers, payout addresses) is
//! pruned within the 7–14-day retention: residue E31 closes while the scanner runs.
//!
//! Covered here: when an anchor is due (an idle week once its ticks have settled, also with the
//! wallet down) and when not (an empty journal, ticks inside the settle window or after the week
//! was anchored, a transition inside the window); the settle window, which a restart, a tick of
//! another week and a clock step back start again, so a brief forward clock step decides no
//! anchor, and what stays of the finding (a step that outlasts the window); a crash at each fault
//! site of the anchor (before its transaction, the entry lost, torn or durable before the commit,
//! the commit failed or done), with the exact state left before the restart and the restart's
//! replay; the prune of an idle issuer after a verified snapshot down to segments that hold only
//! anchors, on which the issuer restarts and from which a restore of that snapshot replays. The
//! same crashes, each also followed by a second one, are enumerated by I-N in `tests/crash.rs`
//! (release profile).

mod common;

use common::faults::{FaultPlan, Mode, Site};
use common::scenarios::other_blinded;
use common::world::{Template, World, BASE_WEEK};
use ghost_entitlement::grid::{invite_epoch, WEEK_SECS};
use ghost_entitlement::Kind;
use ghost_issuer::journal::{self, Entry};
use ghost_issuer::rail::RailError;
use ghost_issuer::reconcile;
use ghost_issuer::scanner::ANCHOR_SETTLE_SECS;
use ghost_issuer::service::OpenMode;
use ghost_issuer::store::{self, MetaKey, RedbSnapshot};
use ghost_issuer_api::proto as wire;

const OTHER: i32 = wire::InvoiceState::OtherRequestIssued as i32;

/// `journal_applied` of the world's snapshot, after verifying it as runbook B1 does before a prune:
/// read through a recovered private copy, it opens as schema 1 and the reconciliation invariants
/// of its counters hold at the world's clock.
fn verified_snapshot_applied(w: &World) -> u64 {
    let scratch = tempfile::tempdir().unwrap();
    let snapshot =
        RedbSnapshot::open_in(&w.dir.path().join("snapshot.redb"), scratch.path()).unwrap();
    let tx = snapshot.read().unwrap();
    let counters = reconcile::all(&*tx).unwrap();
    let mismatches = reconcile::check(&counters, &w.schedule, w.now);
    assert!(
        mismatches.is_empty(),
        "the snapshot verifies: {mismatches:?}"
    );
    store::meta(&*tx, MetaKey::JournalApplied)
        .unwrap()
        .unwrap_or(0)
}

fn weeks(w: &World) -> Vec<u64> {
    w.journal_segments()
        .into_iter()
        .map(|(week, _)| week)
        .collect()
}

fn only_anchors(w: &World) -> bool {
    w.journal_segments()
        .iter()
        .all(|(_, entries)| entries.iter().all(|(_, e)| *e == Entry::Anchor))
}

/// The client retries its pack: another request is refused, the identical one re-signed byte for
/// byte (MS-1).
fn retries(w: &mut World, label: &str, held: &[u8]) {
    let other = other_blinded(w, label);
    assert_eq!(w.sign_with(label, other).unwrap().state, OTHER, "MS-1");
    assert_eq!(w.sign(label).unwrap().blind_signatures, held, "MS-1");
}

#[test]
fn an_empty_journal_gets_no_anchor() {
    let mut w = World::new(true);
    w.advance(WEEK_SECS);
    assert!(!w.settle());
    assert!(w.journal_segments().is_empty());
    w.check();
}

/// A pack in week 2960, then idle weeks. The week's first tick starts the settle window; the first
/// tick `ANCHOR_SETTLE_SECS` after it anchors the week, later ticks and a restart's do not, and a
/// wallet that is down does not stop the anchor while the process runs (it comes before the tick's
/// rail calls).
#[test]
fn an_idle_week_is_anchored_by_its_first_settled_tick_only() {
    let mut w = World::new(true);
    w.buy_pack("p");
    let applied = w.journal_applied();
    w.advance(WEEK_SECS);
    assert!(!w.tick().unwrap().anchored, "the week's first tick");
    w.advance(ANCHOR_SETTLE_SECS - 1);
    assert!(
        !w.tick().unwrap().anchored,
        "one second short of the window"
    );
    assert!(w.anchors().is_empty());
    w.advance(1);
    assert!(w.tick().unwrap().anchored);
    w.assert_anchor_last(BASE_WEEK + 1);
    assert_eq!(w.anchors(), vec![(BASE_WEEK + 1, applied + 1)]);
    for _ in 0..3 {
        w.advance(30);
        assert!(!w.tick().unwrap().anchored);
    }
    w.reopen();
    assert!(!w.settle());
    w.assert_anchor_last(BASE_WEEK + 1);

    w.advance(WEEK_SECS);
    w.chain.set_failure(Some(RailError::Transport));
    assert!(w.tick().is_none(), "the tick fails at the rail");
    w.advance(ANCHOR_SETTLE_SECS);
    assert!(w.tick().is_none(), "the tick fails at the rail");
    w.assert_anchor_last(BASE_WEEK + 2);
    w.chain.set_failure(None);
    assert!(!w.tick().unwrap().anchored);
    assert_eq!(
        w.anchors(),
        vec![(BASE_WEEK + 1, applied + 1), (BASE_WEEK + 2, applied + 2)]
    );
    assert_eq!(weeks(&w), vec![BASE_WEEK, BASE_WEEK + 1, BASE_WEEK + 2]);
    w.check();
}

/// The settle window runs over this process's ticks without a break (review finding
/// Q32-CLOCK-1): a restart forgets it, and a tick of another week, or one earlier than the run's
/// first tick (the clock went back), starts it again.
#[test]
fn the_settle_window_starts_again_after_a_restart_another_week_or_a_clock_step_back() {
    let mut w = World::new(true);
    w.buy_pack("p");
    w.advance(WEEK_SECS);
    w.tick();
    w.advance(ANCHOR_SETTLE_SECS - 60);
    w.reopen();
    w.advance(60);
    assert!(!w.tick().unwrap().anchored, "a restart forgets the window");

    // One tick of week 2962 at a clock stepped a week forward, then the clock back in 2961.
    w.advance(WEEK_SECS);
    assert!(!w.tick().unwrap().anchored, "a new run in week 2962");
    w.now -= WEEK_SECS;
    assert!(!w.tick().unwrap().anchored, "a new run in week 2961");
    w.advance(ANCHOR_SETTLE_SECS - 1);
    assert!(
        !w.tick().unwrap().anchored,
        "the run started at the step back"
    );
    w.advance(1);
    assert!(w.tick().unwrap().anchored);
    w.assert_anchor_last(BASE_WEEK + 1);

    // Week 2963: the clock goes back within the week, before the run's first tick.
    w.advance(2 * WEEK_SECS);
    w.tick();
    let first = w.now;
    w.advance(ANCHOR_SETTLE_SECS - 10);
    assert!(!w.tick().unwrap().anchored);
    w.now = first - 20;
    assert!(!w.tick().unwrap().anchored, "a new run in the same week");
    w.advance(ANCHOR_SETTLE_SECS - 1);
    assert!(!w.tick().unwrap().anchored);
    w.advance(1);
    assert!(
        w.tick().unwrap().anchored,
        "the run's window, from the step back"
    );
    w.assert_anchor_last(BASE_WEEK + 3);
    assert_eq!(weeks(&w), vec![BASE_WEEK, BASE_WEEK + 1, BASE_WEEK + 3]);
    w.check();
}

/// Review finding Q32-CLOCK-1: a brief forward step of the issuer clock across week boundaries
/// decides no anchor. A pack in week 2960; the clock steps three weeks forward for one tick and is
/// corrected; a second pack follows. Every entry stays in the segment of the week it was decided
/// in, and the prune at the start of week 2963 leaves segments that hold only anchors, as it does
/// without the step. Before the guard the stepped tick anchored week 2963, so the second pack's
/// INVOICE and ISSUE (claim hash, minor, subaddress, digest) went to that segment too, kept until
/// `start(2965)`, and no week before 2964 was anchored.
#[test]
fn a_brief_forward_clock_step_decides_no_anchor() {
    let mut w = World::new(true);
    w.buy_pack("before");
    w.tick();
    w.advance(3 * WEEK_SECS);
    assert!(!w.tick().unwrap().anchored, "the stepped tick");
    w.now -= 3 * WEEK_SECS;
    w.advance(30);
    assert!(!w.tick().unwrap().anchored);
    w.buy_pack("after");
    assert_eq!(weeks(&w), vec![BASE_WEEK]);
    assert!(w.anchors().is_empty());
    let held: Vec<(&str, Vec<u8>)> = ["before", "after"]
        .into_iter()
        .map(|label| (label, w.sign(label).unwrap().blind_signatures))
        .collect();

    for _ in 0..2 {
        w.advance(WEEK_SECS);
        assert!(w.settle());
    }
    w.snapshot();
    let applied = verified_snapshot_applied(&w);
    w.advance(WEEK_SECS);
    assert!(w.settle());
    let pruned = journal::prune_dir(&w.dir.path().join("journal"), w.now, applied).unwrap();
    assert_eq!(pruned.removed, vec![BASE_WEEK, BASE_WEEK + 1]);
    assert_eq!(weeks(&w), vec![BASE_WEEK + 2, BASE_WEEK + 3]);
    assert!(only_anchors(&w), "only anchors are left");
    for (label, sigs) in &held {
        retries(&mut w, label, sigs);
    }
    w.check();
}

/// What stays of Q32-CLOCK-1 (§19.25 point 5 (d)): a forward step that outlasts the settle window
/// anchors the stepped week, and an entry decided after the correction goes to that segment (an
/// append never goes to a segment before the latest), which is kept until `start(stepped week + 2)`:
/// up to the step's length past the 7–14 days.
#[test]
fn a_forward_clock_step_that_outlasts_the_settle_window_anchors_the_stepped_week() {
    let mut w = World::new(true);
    w.buy_pack("before");
    w.tick();
    w.advance(3 * WEEK_SECS);
    assert!(w.settle());
    w.assert_anchor_last(BASE_WEEK + 3);
    w.now -= 3 * WEEK_SECS;
    w.tick();
    w.buy_pack("after");
    let segments = w.journal_segments();
    assert_eq!(weeks(&w), vec![BASE_WEEK, BASE_WEEK + 3]);
    let (_, entries) = segments.last().unwrap();
    assert!(
        matches!(
            entries.as_slice(),
            [
                (_, Entry::Anchor),
                (_, Entry::Invoice(_)),
                (_, Entry::Issue { .. })
            ]
        ),
        "{entries:?}"
    );
    w.check();
}

/// A transition decided inside a week's settle window starts the week's segment: nothing to
/// anchor.
#[test]
fn a_week_with_a_transition_inside_its_settle_window_gets_no_anchor() {
    let mut w = World::new(true);
    w.buy_pack("p");
    w.advance(WEEK_SECS);
    assert!(!w.tick().unwrap().anchored, "the week's first tick");
    let week = w.week();
    let invite = w.mint(Kind::Invite, invite_epoch(week), "busy-invite");
    let trial = w.trial_blinded("busy-trial", week);
    assert_eq!(
        w.redeem(&invite, week, trial).unwrap().result,
        wire::RedeemInviteResult::Ok as i32
    );
    assert!(!w.settle());
    assert!(w.anchors().is_empty());
    let segments = w.journal_segments();
    let (last_week, entries) = segments.last().unwrap();
    assert_eq!(*last_week, week);
    assert!(
        matches!(entries.as_slice(), [(_, Entry::Invite { .. })]),
        "{entries:?}"
    );
    w.check();
}

/// A pack in week 2960 and the hourly snapshot after it, closed: every crash run starts here and
/// moves to week 2961, whose first settled tick anchors it.
fn anchor_template() -> (Template, Vec<u8>) {
    let mut w = World::new(true);
    w.buy_pack("n");
    let held = w.sign("n").unwrap().blind_signatures;
    w.snapshot();
    (w.template(), held)
}

/// Moves a world of [`anchor_template`] to week 2961 and ticks through the settle window up to the
/// tick that anchors the week.
fn to_the_anchoring_tick(w: &mut World) {
    w.advance(WEEK_SECS);
    assert!(!w.tick().unwrap().anchored, "the week's first tick");
    w.advance(ANCHOR_SETTLE_SECS);
}

/// Crash before and after the append. For each fault site of the anchor the tick fails and the
/// world is left crashed; before the restart the journal holds the anchor exactly when it was
/// durable and the database applied it exactly when it committed. The restart's replay applies a
/// durable anchor (so the restarted process decides none), and the restarted process decides a lost
/// or torn one again under the same sequence number once its ticks have settled. Either way the
/// week ends with one applied anchor, which a further restart and a restore of the snapshot taken
/// before the week replay without adding one.
#[test]
fn a_crash_before_or_after_the_anchor_append_leaves_one_applied_anchor() {
    let (template, held) = anchor_template();
    // The fault-free run: the sites the anchoring tick reaches and the anchor's sequence number.
    let plan = FaultPlan::new(Vec::new());
    let mut w = World::from_template(&template, plan.clone());
    let before = w.journal_applied();
    to_the_anchoring_tick(&mut w);
    plan.arm();
    assert!(w.tick().unwrap().anchored);
    let seq = w.journal_applied();
    assert_eq!(seq, before + 1);
    let sites = plan.sites();
    let j = sites
        .iter()
        .position(|s| *s == Site::Journal)
        .expect("the anchor's append");
    // The anchor's transaction begins right before its append and commits right after it.
    assert_eq!(
        (sites[j - 1], sites[j + 1]),
        (Site::StoreBegin, Site::StoreCommit)
    );
    drop(w);

    for (site, mode) in [
        (j - 1, Mode::BeforeTxn),
        (j, Mode::JournalLost),
        (j, Mode::JournalTorn),
        (j, Mode::JournalDurable),
        (j + 1, Mode::PreCommit),
        (j + 1, Mode::PostCommit),
    ] {
        let plan = FaultPlan::new(vec![(site, mode)]);
        let mut w = World::from_template(&template, plan.clone());
        to_the_anchoring_tick(&mut w);
        plan.arm();
        assert!(w.issuer().scan_tick_at(w.now).is_err(), "{mode:?}");
        assert!(plan.take_crash(), "{mode:?}: the planned fault fired");
        let durable = matches!(
            mode,
            Mode::JournalDurable | Mode::PreCommit | Mode::PostCommit
        );
        let committed = mode == Mode::PostCommit;
        let expected: Vec<(u64, u64)> = if durable {
            vec![(BASE_WEEK + 1, seq)]
        } else {
            Vec::new()
        };
        assert_eq!(
            w.anchors(),
            expected,
            "{mode:?}: the journal before the restart"
        );
        assert_eq!(
            w.journal_applied(),
            if committed { seq } else { before },
            "{mode:?}: the database before the restart"
        );
        w.crash();
        w.open(OpenMode::Normal);
        assert_eq!(
            w.journal_applied(),
            if durable { seq } else { before },
            "{mode:?}: the restart's replay"
        );
        w.refill();
        assert_eq!(w.settle(), !durable, "{mode:?}");
        w.assert_anchor_last(BASE_WEEK + 1);
        assert_eq!(w.anchors(), vec![(BASE_WEEK + 1, seq)], "{mode:?}");
        assert_eq!(plan.fired(), 1);
        w.reopen();
        w.assert_anchor_last(BASE_WEEK + 1);
        w.restore();
        w.assert_anchor_last(BASE_WEEK + 1);
        assert_eq!(w.anchors(), vec![(BASE_WEEK + 1, seq)], "{mode:?}");
        retries(&mut w, "n", &held);
        w.check();
    }
}

/// Residue E31 closed: a pack in week 2960, then an idle issuer whose scanner ticks every week.
/// The hourly snapshot of week 2962 verifies; on Monday of week 2963 the prune removes the pack's
/// segment (2960, due since `start(2962)`) and the first anchor's (2961, due since `start(2963)`),
/// leaving segments that hold only anchors. The issuer restarts on them, a restore of the verified
/// snapshot replays the one anchor after it, and the client's pack is still re-served (MS-1). From
/// then on the idle journal holds the segments of the current and the previous week only.
#[test]
fn an_idle_issuer_prunes_down_to_anchor_segments_and_restores_from_them() {
    let mut w = World::new(true);
    w.buy_pack("idle");
    let held = w.sign("idle").unwrap().blind_signatures;
    for _ in 0..2 {
        w.advance(WEEK_SECS);
        assert!(w.settle());
    }
    w.snapshot();
    let applied = verified_snapshot_applied(&w);
    w.advance(WEEK_SECS);
    assert!(w.settle());
    assert_eq!(
        weeks(&w),
        vec![BASE_WEEK, BASE_WEEK + 1, BASE_WEEK + 2, BASE_WEEK + 3]
    );
    let anchored: Vec<u64> = w.anchors().into_iter().map(|(week, _)| week).collect();
    assert_eq!(anchored, vec![BASE_WEEK + 1, BASE_WEEK + 2, BASE_WEEK + 3]);

    let dir = w.dir.path().join("journal");
    let pruned = journal::prune_dir(&dir, w.now, applied).unwrap();
    assert_eq!(pruned.removed, vec![BASE_WEEK, BASE_WEEK + 1]);
    assert_eq!(weeks(&w), vec![BASE_WEEK + 2, BASE_WEEK + 3]);
    assert!(only_anchors(&w), "only anchors are left");
    assert!(pruned.first_seq <= applied && applied < pruned.last_seq);
    retries(&mut w, "idle", &held);
    w.check();
    w.reopen();
    retries(&mut w, "idle", &held);
    w.check();
    w.restore();
    assert_eq!(w.journal_applied(), pruned.last_seq);
    w.assert_anchor_last(BASE_WEEK + 3);
    retries(&mut w, "idle", &held);
    w.check();

    w.advance(WEEK_SECS);
    assert!(w.settle());
    w.snapshot();
    let applied = verified_snapshot_applied(&w);
    let pruned = journal::prune_dir(&dir, w.now, applied).unwrap();
    assert_eq!(pruned.removed, vec![BASE_WEEK + 2]);
    assert_eq!(weeks(&w), vec![BASE_WEEK + 3, BASE_WEEK + 4]);
    w.assert_anchor_last(BASE_WEEK + 4);
    w.check();
}
