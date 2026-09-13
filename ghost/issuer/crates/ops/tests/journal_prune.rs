//! `journal-prune` (design §6.3, §6.4, §19.15; runbook B1), run in process: the snapshot is
//! verified as B1 defines it (an issuer database of schema 1 whose reconciliation invariants hold)
//! before anything goes; its `journal_applied` mark, read through the private-copy reader, bounds
//! what goes; the 7-day window and the segment of the last entry stay; a snapshot that does not
//! fit the journal, or a journal that does not read, removes nothing. The crash-safety of a
//! removal on the real issuer is in `issuer/crates/service/tests/journal_prune.rs`.

mod common;

use std::path::{Path, PathBuf};

use common::*;
use ghost_issuer::journal::{Entry, FileJournal, Journal, SEGMENT_PREFIX};
use ghost_issuer::reconcile::CounterId;
use ghost_issuer::store::{self, MetaKey, RedbStore, Store};
use ghost_issuer_ops::report::{Code, Field, Line};
use ghost_issuer_ops::Status;

/// A journal of five entries: seq 1 and 2 in week 2957, 3 in 2958, 4 in 2959, 5 in 2960 (the week
/// of [`RECONCILE_NOW`]). At that time 2957 and 2958 are past the 7-day re-serve window, 2959 is
/// not, and 2960 is the latest.
fn journal(d: &Path) -> PathBuf {
    let dir = d.join("journal");
    let j = FileJournal::open(&dir).unwrap();
    for (i, week) in [2957u64, 2957, 2958, 2959, 2960].into_iter().enumerate() {
        let entry = Entry::Issue {
            invoice_id: [i as u8; 16],
            digest: [0xd0 + i as u8; 32],
        };
        j.append(week, &entry).unwrap();
    }
    dir
}

fn segments(dir: &Path) -> Vec<u64> {
    let mut weeks: Vec<u64> = std::fs::read_dir(dir)
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

/// Records `journal_applied` in a snapshot database (the issuer's commit of an entry does this).
fn set_applied(db: &Path, applied: u64) {
    let s = RedbStore::open(db).unwrap();
    let mut tx = s.write().unwrap();
    store::set_meta(&mut *tx, MetaKey::JournalApplied, applied).unwrap();
    tx.commit().unwrap();
}

fn prune_at(db: &Path, journal: &Path, now: &str) -> (Status, Vec<Line>) {
    let es = arg(&test_schedule_path());
    let key = schedule_public_hex();
    let (db, journal) = (arg(db), arg(journal));
    run(&[
        "journal-prune",
        "--database",
        &db,
        "--journal",
        &journal,
        "--schedule",
        &es,
        "--schedule-public-key",
        &key,
        "--now",
        now,
    ])
}

fn prune(db: &Path, journal: &Path) -> (Status, Vec<Line>) {
    prune_at(db, journal, RECONCILE_NOW)
}

fn rendered(lines: &[Line]) -> Vec<String> {
    lines.iter().map(Line::render).collect()
}

#[test]
fn a_verified_snapshot_prunes_the_old_segments_it_covers() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let db = snapshot(d, &[]);
    set_applied(&db, 4);
    let journal = journal(d);
    let before = std::fs::read(&db).unwrap();
    let (status, lines) = prune(&db, &journal);
    assert_eq!(status, Status::Ok, "{:?}", rendered(&lines));
    assert_eq!(
        rendered(&lines),
        vec![
            "SEGMENT_PRUNED week=2957",
            "SEGMENT_PRUNED week=2958",
            "JOURNAL_PRUNED removed=2 kept=2 first_seq=4 last_seq=5 applied=4",
        ]
    );
    assert_eq!(segments(&journal), vec![2959, 2960]);
    // The snapshot is read through a private copy and keeps its bytes (B1 mounts it read-only).
    assert_eq!(std::fs::read(&db).unwrap(), before);
    // The issuer reopens the journal where it was and continues it.
    assert_eq!(
        FileJournal::open(&journal)
            .unwrap()
            .append(
                2960,
                &Entry::Issue {
                    invoice_id: [9; 16],
                    digest: [9; 32],
                }
            )
            .unwrap(),
        6
    );
    // A second run finds nothing more to prune.
    let (status, lines) = prune(&db, &journal);
    assert_eq!(status, Status::Ok);
    assert_eq!(
        rendered(&lines),
        vec!["JOURNAL_PRUNED removed=0 kept=2 first_seq=4 last_seq=6 applied=4"]
    );
}

/// Segment 2959 is covered by a snapshot of every entry but ends less than 7 days before `--now`;
/// the latest segment stays whatever the snapshot covers. A snapshot covering fewer entries stops
/// the prune at the first segment it does not cover.
#[test]
fn the_re_serve_window_the_latest_segment_and_uncovered_entries_stay() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let db = snapshot(d, &[]);
    let journal = journal(d);
    set_applied(&db, 2);
    let (_, lines) = prune(&db, &journal);
    assert_eq!(
        rendered(&lines),
        vec![
            "SEGMENT_PRUNED week=2957",
            "JOURNAL_PRUNED removed=1 kept=3 first_seq=3 last_seq=5 applied=2",
        ]
    );
    set_applied(&db, 5);
    let (_, lines) = prune(&db, &journal);
    assert_eq!(
        rendered(&lines),
        vec![
            "SEGMENT_PRUNED week=2958",
            "JOURNAL_PRUNED removed=1 kept=2 first_seq=4 last_seq=5 applied=5",
        ]
    );
    assert_eq!(segments(&journal), vec![2959, 2960]);
    // Weeks later 2959 goes too; the latest segment, which the issuer writes, never does.
    let later = (1_790_596_800u64 + 4 * 604_800).to_string();
    let (_, lines) = prune_at(&db, &journal, &later);
    assert_eq!(
        rendered(&lines),
        vec![
            "SEGMENT_PRUNED week=2959",
            "JOURNAL_PRUNED removed=1 kept=1 first_seq=5 last_seq=5 applied=5",
        ]
    );
    assert_eq!(segments(&journal), vec![2960]);
}

/// Runbook B1: a snapshot that is not verified is never used; nothing is removed.
#[test]
fn an_unverified_snapshot_removes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let db = snapshot(d, &[(CounterId::SignedAccess, 2961, 1)]);
    set_applied(&db, 5);
    let journal = journal(d);
    let r = prune(&db, &journal);
    assert_refused(&r, Code::PruneRefused, "snapshot-unverified");
    assert_eq!(r.1[0].code, Code::ReconciliationMismatch);
    assert_eq!(word(&r.1[0], Field::Reason), Some("signed-access"));
    assert_eq!(segments(&journal), vec![2957, 2958, 2959, 2960]);

    let not_db = write(d, "not.redb", b"not a database");
    assert_refused(&prune(&not_db, &journal), Code::InputRefused, "open");
    assert_refused(
        &prune(&d.join("missing.redb"), &journal),
        Code::InputRefused,
        "open",
    );
    let mut tampered = test_schedule_bytes();
    tampered[200] ^= 1;
    let tampered = arg(&write(d, "tampered.ghes", &tampered));
    let (status, lines) = run(&[
        "journal-prune",
        "--database",
        &arg(&db),
        "--journal",
        &arg(&journal),
        "--schedule",
        &tampered,
        "--schedule-public-key",
        &schedule_public_hex(),
        "--now",
        RECONCILE_NOW,
    ]);
    assert_eq!(status, Status::Refused);
    assert_eq!(lines.last().unwrap().code, Code::EsRefused);
    assert_eq!(segments(&journal), vec![2957, 2958, 2959, 2960]);
}

/// A snapshot the journal does not fit, and a journal that does not read, remove nothing.
#[test]
fn a_snapshot_or_journal_that_does_not_fit_removes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let db = snapshot(d, &[]);
    let journal = journal(d);
    // Newer than the journal: applied entries the journal does not hold.
    set_applied(&db, 6);
    assert_refused(&prune(&db, &journal), Code::PruneRefused, "snapshot-ahead");
    assert_eq!(segments(&journal), vec![2957, 2958, 2959, 2960]);
    // The journal lost segment 2957 (seq 1 and 2): a snapshot that applied nothing cannot be
    // restored with it.
    std::fs::remove_file(journal.join(format!("{SEGMENT_PREFIX}2957"))).unwrap();
    set_applied(&db, 0);
    assert_refused(&prune(&db, &journal), Code::PruneRefused, "snapshot-behind");
    assert_eq!(segments(&journal), vec![2958, 2959, 2960]);
    // A gap in the middle, damage in an earlier segment, no journal at all.
    set_applied(&db, 2);
    let seg = |w: u64| journal.join(format!("{SEGMENT_PREFIX}{w}"));
    let saved = std::fs::read(seg(2959)).unwrap();
    std::fs::remove_file(seg(2959)).unwrap();
    assert_refused(&prune(&db, &journal), Code::PruneRefused, "journal-gap");
    let mut damaged = saved.clone();
    damaged[20] ^= 1;
    std::fs::write(seg(2959), &damaged).unwrap();
    assert_refused(&prune(&db, &journal), Code::PruneRefused, "journal-corrupt");
    std::fs::write(seg(2959), &saved).unwrap();
    assert_eq!(segments(&journal), vec![2958, 2959, 2960]);
    assert_refused(
        &prune(&db, &d.join("no-journal")),
        Code::PruneRefused,
        "journal-io",
    );
    // Whole again, the journal fits the snapshot; segment 2958 (seq 3) is not covered by it.
    let (status, lines) = prune(&db, &journal);
    assert_eq!(status, Status::Ok);
    assert_eq!(
        rendered(&lines),
        vec!["JOURNAL_PRUNED removed=0 kept=3 first_seq=3 last_seq=5 applied=2"]
    );
}

#[test]
fn every_flag_is_required_but_the_schedule_key() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let db = arg(&snapshot(d, &[]));
    let journal = arg(&journal(d));
    let es = arg(&test_schedule_path());
    let full = [
        ("--database", db.as_str()),
        ("--journal", journal.as_str()),
        ("--schedule", es.as_str()),
        ("--now", RECONCILE_NOW),
    ];
    for skip in 0..full.len() {
        let mut args = vec!["journal-prune"];
        for (i, (flag, value)) in full.iter().enumerate() {
            if i != skip {
                args.extend([*flag, *value]);
            }
        }
        let (status, lines) = run(&args);
        assert_eq!(status, Status::Usage, "{args:?}");
        assert_eq!(
            word(lines.last().unwrap(), Field::Reason),
            Some("missing-flag")
        );
    }
    assert_eq!(segments(Path::new(&journal)), vec![2957, 2958, 2959, 2960]);
}
