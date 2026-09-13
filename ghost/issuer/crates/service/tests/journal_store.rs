//! `issued.journal` and `issuer.redb` formats (Phase 8 design §6.1, §6.3, §19.5): frames, torn
//! tails, corruption, sequence gaps, weekly segments, pruning; schema refusal and row encodings.

use ghost_entitlement::grid::week_start;
use ghost_issuer::journal::{
    self, BatchEntry, ClaimEntry, Entry, FileJournal, InvoiceEntry, Journal, JournalError,
    PruneError, Pruned, SEGMENT_PREFIX,
};
use ghost_issuer::store::{
    self, ClaimRow, ClaimState, CreditUse, InvoiceRow, InvoiceState, MetaKey, PayWith,
    RedbSnapshot, RedbStore, Store, StoreError, Table,
};

fn entries() -> Vec<Entry> {
    vec![
        Entry::Invoice(InvoiceEntry {
            invoice_id: [1; 16],
            claim_hash: [2; 32],
            request_digest: [3; 32],
            pay_with: PayWith::Monero,
            minor: 7,
            subaddress: [b'8'; 95],
            amount: 200_000_000_000,
            base_week: 2960,
            created_height: 1_000,
            grace_height: 3_880,
            credits: Vec::new(),
        }),
        Entry::Invoice(InvoiceEntry {
            invoice_id: [4; 16],
            claim_hash: [5; 32],
            request_digest: [6; 32],
            pay_with: PayWith::Credits,
            minor: 0,
            subaddress: [0; 95],
            amount: 0,
            base_week: 2960,
            created_height: 0,
            grace_height: 0,
            credits: (0..20).map(|i| (227, [i; 32])).collect(),
        }),
        Entry::Issue {
            invoice_id: [1; 16],
            digest: [9; 32],
        },
        Entry::Invite {
            epoch: 740,
            nullifier: [10; 32],
            digest: [11; 32],
            base_week: 2960,
        },
        Entry::Claim(ClaimEntry {
            claim_id: [12; 16],
            digest: [13; 32],
            amount: 250_000_000_000,
            address: [b'4'; 95],
            credits: (0..64).map(|i| (229, [i; 32])).collect(),
        }),
    ]
}

fn segment(dir: &std::path::Path, week: u64) -> std::path::PathBuf {
    dir.join(format!("{SEGMENT_PREFIX}{week}"))
}

#[test]
fn frames_round_trip_and_sequence_numbers_continue() {
    let dir = tempfile::tempdir().unwrap();
    let j = FileJournal::open(dir.path()).unwrap();
    for (i, e) in entries().iter().enumerate() {
        assert_eq!(j.append(2960, e).unwrap(), i as u64 + 1);
    }
    drop(j);
    let j = FileJournal::open(dir.path()).unwrap();
    let read: Vec<Entry> = j.entries().unwrap().into_iter().map(|(_, e)| e).collect();
    assert_eq!(read, entries());
    assert_eq!(j.append(2960, &entries()[2]).unwrap(), 6);
}

#[test]
fn a_torn_tail_is_discarded_and_truncated() {
    let dir = tempfile::tempdir().unwrap();
    let j = FileJournal::open(dir.path()).unwrap();
    j.append(2960, &entries()[0]).unwrap();
    j.append(2960, &entries()[2]).unwrap();
    drop(j);
    let path = segment(dir.path(), 2960);
    let valid = std::fs::metadata(&path).unwrap().len();
    let frame = entries()[3].encode(3).unwrap();
    for cut in [1, 3, 4, 20, frame.len() - 1] {
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.truncate(valid as usize);
        bytes.extend_from_slice(&frame[..cut]);
        std::fs::write(&path, &bytes).unwrap();
        let j = FileJournal::open(dir.path()).unwrap();
        assert_eq!(j.entries().unwrap().len(), 2, "cut {cut}");
        assert_eq!(std::fs::metadata(&path).unwrap().len(), valid);
    }
    // A complete final frame with a bad checksum is a torn write too.
    let mut bytes = std::fs::read(&path).unwrap();
    let mut bad = frame.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    bytes.extend_from_slice(&bad);
    std::fs::write(&path, &bytes).unwrap();
    let j = FileJournal::open(dir.path()).unwrap();
    assert_eq!(j.append(2960, &entries()[3]).unwrap(), 3);
    assert_eq!(j.entries().unwrap().len(), 3);
}

/// A crash after the file was extended but before the data reached the disk leaves a zero-filled
/// (or garbage) region at the end of the last segment: its length field is 0 or out of range, or
/// a torn frame is followed by zeros. Nothing valid follows, so it is a torn tail (§6.3, §19.5).
#[test]
fn a_zero_filled_or_garbage_tail_is_torn() {
    let frame = entries()[3].encode(3).unwrap();
    let mut tails: Vec<(String, Vec<u8>)> = Vec::new();
    for fill in [0x00u8, 0xFF] {
        for n in [4usize, 16, 93] {
            tails.push((format!("{n} bytes of {fill:#04x}"), vec![fill; n]));
        }
    }
    tails.push((
        "a torn frame followed by zeros".into(),
        [&frame[..20], &[0u8; 64][..]].concat(),
    ));
    tails.push((
        "a whole frame with a bad checksum followed by zeros".into(),
        [&frame[..frame.len() - 1], &[0u8; 40][..]].concat(),
    ));
    for (what, tail) in tails {
        let dir = tempfile::tempdir().unwrap();
        let j = FileJournal::open(dir.path()).unwrap();
        j.append(2960, &entries()[0]).unwrap();
        j.append(2960, &entries()[2]).unwrap();
        drop(j);
        let path = segment(dir.path(), 2960);
        let valid = std::fs::metadata(&path).unwrap().len();
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.extend_from_slice(&tail);
        std::fs::write(&path, &bytes).unwrap();
        let j = FileJournal::open(dir.path()).unwrap_or_else(|e| panic!("{what}: {e}"));
        assert_eq!(j.entries().unwrap().len(), 2, "{what}");
        assert_eq!(std::fs::metadata(&path).unwrap().len(), valid, "{what}");
        assert_eq!(j.append(2960, &entries()[3]).unwrap(), 3, "{what}");
    }
}

/// Damage followed by a valid frame is never a torn tail, whatever the damage looks like.
#[test]
fn damage_followed_by_a_valid_frame_refuses() {
    for (what, gap) in [
        ("zeros", vec![0u8; 16]),
        ("0xFF bytes", vec![0xFF; 16]),
        (
            "a torn frame",
            entries()[3].encode(3).unwrap()[..20].to_vec(),
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = segment(dir.path(), 2960);
        let bytes = [
            entries()[0].encode(1).unwrap(),
            gap,
            entries()[2].encode(2).unwrap(),
        ]
        .concat();
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(
            FileJournal::open(dir.path()).err(),
            Some(JournalError::Corrupt),
            "{what}"
        );
    }
}

#[test]
fn damage_before_the_tail_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let j = FileJournal::open(dir.path()).unwrap();
    j.append(2960, &entries()[0]).unwrap();
    j.append(2960, &entries()[2]).unwrap();
    drop(j);
    let path = segment(dir.path(), 2960);
    let good = std::fs::read(&path).unwrap();
    let mut bytes = good.clone();
    bytes[30] ^= 0x01;
    std::fs::write(&path, &bytes).unwrap();
    assert_eq!(
        FileJournal::open(dir.path()).err(),
        Some(JournalError::Corrupt)
    );
    // An out-of-range length field followed by a valid frame.
    let mut bytes = good.clone();
    bytes[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    std::fs::write(&path, &bytes).unwrap();
    assert_eq!(
        FileJournal::open(dir.path()).err(),
        Some(JournalError::Corrupt)
    );
    // A torn frame in a segment that is not the last one.
    std::fs::write(&path, &good[..good.len() - 5]).unwrap();
    std::fs::write(segment(dir.path(), 2961), entries()[3].encode(3).unwrap()).unwrap();
    assert_eq!(
        FileJournal::open(dir.path()).err(),
        Some(JournalError::Corrupt)
    );
}

#[test]
fn an_unknown_tag_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let mut frame = entries()[2].encode(1).unwrap();
    frame[12] = 9;
    let body_end = frame.len() - 32;
    let checksum = <sha2::Sha256 as sha2::Digest>::digest(&frame[..body_end]);
    frame[body_end..].copy_from_slice(&checksum);
    std::fs::write(segment(dir.path(), 2960), &frame).unwrap();
    assert_eq!(
        FileJournal::open(dir.path()).err(),
        Some(JournalError::Format)
    );
}

#[test]
fn segments_roll_weekly_and_a_gap_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let j = FileJournal::open(dir.path()).unwrap();
    j.append(2960, &entries()[0]).unwrap();
    j.append(2961, &entries()[2]).unwrap();
    // A clock step back keeps writing to the latest segment.
    j.append(2960, &entries()[3]).unwrap();
    drop(j);
    assert_eq!(std::fs::read(segment(dir.path(), 2961)).unwrap().len(), {
        entries()[2].encode(2).unwrap().len() + entries()[3].encode(3).unwrap().len()
    });
    let j = FileJournal::open(dir.path()).unwrap();
    let seqs: Vec<u64> = j.entries().unwrap().into_iter().map(|(s, _)| s).collect();
    assert_eq!(seqs, vec![1, 2, 3]);
    drop(j);
    std::fs::write(segment(dir.path(), 2963), entries()[3].encode(5).unwrap()).unwrap();
    assert_eq!(FileJournal::open(dir.path()).err(), Some(JournalError::Gap));
}

#[test]
fn pruning_needs_age_and_a_newer_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let j = FileJournal::open(dir.path()).unwrap();
    j.append(2960, &entries()[0]).unwrap();
    j.append(2960, &entries()[2]).unwrap();
    j.append(2961, &entries()[3]).unwrap();
    j.append(2962, &entries()[4]).unwrap();
    let week = 604_800;
    // Segment 2960 ends at start(2961); it is prunable 7 days later.
    assert_eq!(
        j.prune(week_start(2961) + week - 1, 4).unwrap(),
        Vec::<u64>::new()
    );
    assert_eq!(
        j.prune(week_start(2961) + week, 1).unwrap(),
        Vec::<u64>::new()
    );
    assert_eq!(j.prune(week_start(2961) + week, 2).unwrap(), vec![2960]);
    assert_eq!(
        j.prune(week_start(2963) + week, 2).unwrap(),
        Vec::<u64>::new()
    );
    // The latest segment is never pruned.
    assert_eq!(j.prune(u64::MAX, 4).unwrap(), vec![2961]);
    let seqs: Vec<u64> = j.entries().unwrap().into_iter().map(|(s, _)| s).collect();
    assert_eq!(seqs, vec![4]);
    assert_eq!(j.append(2962, &entries()[2]).unwrap(), 5);
}

/// Runbook B1 (`ghost-issuer-ops journal-prune`): `prune_dir` removes nothing for a snapshot the
/// journal does not fit, never writes a segment (the issuer may be writing a torn tail into the
/// latest one) and reports what it left.
#[test]
fn prune_dir_needs_a_fitting_snapshot_and_never_writes_a_segment() {
    let dir = tempfile::tempdir().unwrap();
    let j = FileJournal::open(dir.path()).unwrap();
    j.append(2960, &entries()[0]).unwrap();
    j.append(2960, &entries()[2]).unwrap();
    j.append(2961, &entries()[3]).unwrap();
    j.append(2962, &entries()[4]).unwrap();
    drop(j);
    // Every segment but the latest is past the 7-day window.
    let late = week_start(2964) + 604_800;
    assert_eq!(
        journal::prune_dir(dir.path(), late, 5).err(),
        Some(PruneError::SnapshotAhead)
    );
    // The issuer is appending: the latest segment ends in part of a frame.
    let mut torn = std::fs::read(segment(dir.path(), 2962)).unwrap();
    torn.extend_from_slice(&entries()[2].encode(5).unwrap()[..20]);
    std::fs::write(segment(dir.path(), 2962), &torn).unwrap();
    assert_eq!(
        journal::prune_dir(dir.path(), late, 4).unwrap(),
        Pruned {
            removed: vec![2960, 2961],
            kept: 1,
            first_seq: 4,
            last_seq: 4,
        }
    );
    assert_eq!(std::fs::read(segment(dir.path(), 2962)).unwrap(), torn);
    // The journal now starts at 4: a snapshot that applied 2 could no longer be restored with it,
    // one that applied 3 still can.
    assert_eq!(
        journal::prune_dir(dir.path(), late, 2).err(),
        Some(PruneError::SnapshotBehind)
    );
    assert!(journal::prune_dir(dir.path(), late, 3)
        .unwrap()
        .removed
        .is_empty());
    // The issuer's own open discards the torn tail and continues the sequence.
    let j = FileJournal::open(dir.path()).unwrap();
    assert_eq!(j.append(2962, &entries()[2]).unwrap(), 5);
}

/// Review finding OPS-PRUNE-1: a newest segment that holds no entry (created by an append that
/// died before its first frame was durable: empty, or a torn frame) leaves the segment of the last
/// entry in place, so the journal still opens where it was and continues the sequence.
#[test]
fn prune_dir_keeps_the_segment_of_the_last_entry() {
    for torn in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let j = FileJournal::open(dir.path()).unwrap();
        j.append(2960, &entries()[0]).unwrap();
        j.append(2961, &entries()[2]).unwrap();
        j.append(2961, &entries()[3]).unwrap();
        drop(j);
        let bytes = if torn {
            entries()[4].encode(4).unwrap()[..20].to_vec()
        } else {
            Vec::new()
        };
        std::fs::write(segment(dir.path(), 2963), &bytes).unwrap();
        assert_eq!(
            journal::prune_dir(dir.path(), u64::MAX, 3).unwrap(),
            Pruned {
                removed: vec![2960],
                kept: 2,
                first_seq: 2,
                last_seq: 3,
            },
            "torn {torn}"
        );
        let j = FileJournal::open(dir.path()).unwrap();
        let seqs: Vec<u64> = j.entries().unwrap().into_iter().map(|(s, _)| s).collect();
        assert_eq!(seqs, vec![2, 3]);
        assert_eq!(j.append(2963, &entries()[4]).unwrap(), 4);
        drop(j);
        // Once a later segment holds an entry, 2961 goes too.
        assert_eq!(
            journal::prune_dir(dir.path(), u64::MAX, 4).unwrap().removed,
            vec![2961]
        );
    }
}

#[test]
fn prune_dir_on_an_empty_missing_or_damaged_journal_removes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(
        journal::prune_dir(dir.path(), u64::MAX, 0).unwrap(),
        Pruned {
            removed: Vec::new(),
            kept: 0,
            first_seq: 0,
            last_seq: 0,
        }
    );
    assert_eq!(
        journal::prune_dir(dir.path(), u64::MAX, 1).err(),
        Some(PruneError::SnapshotAhead)
    );
    assert_eq!(
        journal::prune_dir(&dir.path().join("missing"), u64::MAX, 0).err(),
        Some(PruneError::Journal(JournalError::Io))
    );
    let j = FileJournal::open(dir.path()).unwrap();
    j.append(2960, &entries()[0]).unwrap();
    j.append(2961, &entries()[2]).unwrap();
    j.append(2962, &entries()[3]).unwrap();
    drop(j);
    // Damage in a segment that is not the latest.
    let mut bytes = std::fs::read(segment(dir.path(), 2961)).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(segment(dir.path(), 2961), &bytes).unwrap();
    assert_eq!(
        journal::prune_dir(dir.path(), u64::MAX, 3).err(),
        Some(PruneError::Journal(JournalError::Corrupt))
    );
    assert!(segment(dir.path(), 2960).exists());
}

/// A segment listed but gone before it is read (removed by a prune that runs while an issuer
/// starts) ends a removed prefix: the journal opens after it, without the segments read before it
/// (the prune removes in ascending order), and a segment missing from the listing is still a
/// sequence gap.
#[cfg(unix)]
#[test]
fn a_segment_removed_while_the_journal_is_read_is_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let j = FileJournal::open(dir.path()).unwrap();
    j.append(2960, &entries()[0]).unwrap();
    j.append(2961, &entries()[2]).unwrap();
    j.append(2962, &entries()[3]).unwrap();
    drop(j);
    // A dangling link is listed by the directory read and gone at the file read.
    let gone = |week: u64| {
        std::fs::remove_file(segment(dir.path(), week)).unwrap();
        std::os::unix::fs::symlink(dir.path().join("vanished"), segment(dir.path(), week)).unwrap();
    };
    gone(2960);
    let seqs: Vec<u64> = FileJournal::open(dir.path())
        .unwrap()
        .entries()
        .unwrap()
        .into_iter()
        .map(|(s, _)| s)
        .collect();
    assert_eq!(seqs, vec![2, 3]);
    std::fs::remove_file(segment(dir.path(), 2960)).unwrap();
    let j = FileJournal::open(dir.path()).unwrap();
    j.append(2963, &entries()[4]).unwrap();
    drop(j);
    gone(2962);
    let seqs: Vec<u64> = FileJournal::open(dir.path())
        .unwrap()
        .entries()
        .unwrap()
        .into_iter()
        .map(|(s, _)| s)
        .collect();
    assert_eq!(seqs, vec![4]);
    std::fs::remove_file(segment(dir.path(), 2962)).unwrap();
    assert_eq!(FileJournal::open(dir.path()).err(), Some(JournalError::Gap));
}

#[test]
fn store_refuses_another_schema_version() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("issuer.redb");
    let s = RedbStore::open(&path).unwrap();
    let mut tx = s.write().unwrap();
    store::set_meta(&mut *tx, MetaKey::SchemaVersion, 2).unwrap();
    tx.commit().unwrap();
    drop(s);
    assert_eq!(RedbStore::open(&path).err(), Some(StoreError::Schema));
    let scratch = tempfile::tempdir().unwrap();
    assert_eq!(
        RedbSnapshot::open_in(&path, scratch.path()).err(),
        Some(StoreError::Schema)
    );
    assert_eq!(std::fs::read_dir(scratch.path()).unwrap().count(), 0);
}

/// Runbooks B1 and R2 (review finding INFRA-1): a snapshot is read through a private copy in the
/// scratch directory, removed with the view; the snapshot keeps its bytes, and a file that is not
/// a database leaves no copy behind.
#[test]
fn a_snapshot_is_read_through_a_private_copy() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("issuer-2026092812.redb");
    {
        let s = RedbStore::open(&path).unwrap();
        let mut tx = s.write().unwrap();
        store::set_meta(&mut *tx, MetaKey::HighestMinor, 41).unwrap();
        tx.commit().unwrap();
    }
    let before = std::fs::read(&path).unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let snapshot = RedbSnapshot::open_in(&path, scratch.path()).unwrap();
    let copies: Vec<std::path::PathBuf> = std::fs::read_dir(scratch.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(copies.len(), 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&copies[0]).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let tx = snapshot.read().unwrap();
    assert_eq!(store::meta(&*tx, MetaKey::HighestMinor).unwrap(), Some(41));
    drop(tx);
    drop(snapshot);
    assert_eq!(std::fs::read_dir(scratch.path()).unwrap().count(), 0);
    assert_eq!(std::fs::read(&path).unwrap(), before);

    let not_db = dir.path().join("not.redb");
    std::fs::write(&not_db, b"not a database").unwrap();
    assert!(RedbSnapshot::open_in(&not_db, scratch.path()).is_err());
    assert!(RedbSnapshot::open_in(&dir.path().join("missing.redb"), scratch.path()).is_err());
    assert_eq!(std::fs::read_dir(scratch.path()).unwrap().count(), 0);
}

#[test]
fn an_uncommitted_transaction_leaves_no_trace() {
    let dir = tempfile::tempdir().unwrap();
    let s = RedbStore::open(&dir.path().join("issuer.redb")).unwrap();
    let mut tx = s.write().unwrap();
    tx.put(Table::ClaimIndex, &[1; 32], &[2; 16]).unwrap();
    drop(tx);
    let tx = s.read().unwrap();
    assert_eq!(tx.get(Table::ClaimIndex, &[1; 32]).unwrap(), None);
    for t in Table::ALL {
        assert!(!t.name().is_empty());
    }
}

#[test]
fn rows_round_trip() {
    let row = InvoiceRow {
        state: InvoiceState::Issued,
        pay_with: PayWith::Monero,
        minor: 9,
        amount: 1,
        claim_hash: [1; 32],
        request_digest: [2; 32],
        base_week: 3,
        es_seq: 4,
        created_height: 5,
        seen_deadline: 6,
        grace_height: 7,
        confirmed_height: 8,
        credited: 9,
        seen: 10,
        issued_digest: Some([3; 32]),
        issued_height: 11,
        purge_height: 12,
        subaddress: [b'8'; 95],
    };
    assert_eq!(InvoiceRow::decode(&row.encode()).unwrap(), row);
    assert_eq!(row.encode().len(), 285);
    let none = InvoiceRow {
        issued_digest: None,
        ..row.clone()
    };
    assert_eq!(InvoiceRow::decode(&none.encode()).unwrap(), none);
    assert_eq!(
        InvoiceRow::decode(&row.encode()[1..]),
        Err(StoreError::Corrupt)
    );
    let claim = ClaimRow {
        state: ClaimState::Queued,
        amount: 5,
        credits: 10,
        digest: [4; 32],
        address: [b'4'; 95],
        batch_id: [0; 16],
    };
    assert_eq!(ClaimRow::decode(&claim.encode()).unwrap(), claim);
    for u in [
        CreditUse::Discount,
        CreditUse::Payout,
        CreditUse::Refresh([3; 32]),
    ] {
        assert_eq!(CreditUse::decode(&u.encode()).unwrap(), u);
    }
    // Only a refresh keeps a reference (§6.1), its whole digest: a discount or payout row carrying
    // one is refused, and so is a row of the former 17 bytes (a 16-byte prefix).
    assert_eq!(
        CreditUse::Discount.encode(),
        [[1u8].as_slice(), &[0; 32]].concat()[..]
    );
    assert_eq!(CreditUse::Payout.encode()[1..], [0; 32]);
    for code in [1u8, 2] {
        let mut row = [0u8; 33];
        row[0] = code;
        row[32] = 1;
        assert_eq!(CreditUse::decode(&row), Err(StoreError::Corrupt));
    }
    assert_eq!(CreditUse::decode(&[4; 33]), Err(StoreError::Corrupt));
    assert_eq!(CreditUse::decode(&[3; 17]), Err(StoreError::Corrupt));
    for state in [
        ClaimState::Queued,
        ClaimState::Batched,
        ClaimState::Paid,
        ClaimState::Refused,
    ] {
        let row = ClaimRow {
            state,
            ..claim.clone()
        };
        assert_eq!(ClaimRow::decode(&row.encode()).unwrap(), row);
    }
}

#[test]
fn batch_entries_round_trip_and_refused_lists_are_canonical() {
    let dir = tempfile::tempdir().unwrap();
    let j = FileJournal::open(dir.path()).unwrap();
    let written = vec![
        Entry::Batch(BatchEntry {
            batch_id: [1; 16],
            week: 2960,
            cumulative_credited: 5,
            claims: vec![[2; 16], [3; 16]],
        }),
        Entry::BatchPaid {
            batch_id: [1; 16],
            week: 2961,
            refused: vec![[2; 16]],
        },
        Entry::BatchPaid {
            batch_id: [4; 16],
            week: 2961,
            refused: Vec::new(),
        },
    ];
    for e in &written {
        j.append(2960, e).unwrap();
    }
    drop(j);
    let read: Vec<Entry> = FileJournal::open(dir.path())
        .unwrap()
        .entries()
        .unwrap()
        .into_iter()
        .map(|(_, e)| e)
        .collect();
    assert_eq!(read, written);
    let id = |i: u16| {
        let mut id = [0u8; 16];
        id[14..].copy_from_slice(&i.to_be_bytes());
        id
    };
    for refused in [
        vec![id(3), id(2)],
        vec![id(2), id(2)],
        (0..=200).map(id).collect(),
    ] {
        let entry = Entry::BatchPaid {
            batch_id: [1; 16],
            week: 2961,
            refused,
        };
        assert!(entry.encode(1).is_err());
    }
    let most = Entry::BatchPaid {
        batch_id: [1; 16],
        week: 2961,
        refused: (0..200).map(id).collect(),
    };
    assert!(most.encode(1).is_ok());
}
