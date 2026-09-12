//! The payout pipeline, issuer side (Phase 8 design §9.5, §19.5, §19.7, §6.9): batches of queued
//! claims (journaled `BATCH`), the batch file signed by the ops key and rewritten byte for byte,
//! the workstation's acknowledgement (`BATCH_PAID`), the weekly job, retention, restores, and the
//! reconciliation checks with the relay aggregates and the workstation's view.

mod common;

use std::collections::BTreeMap;

use common::fixture;
use common::scenarios::{claim_address, CLAIM_SPENT, NOON, QUEUED};
use common::world::{claim_id, ops_key, World, BASE_WEEK, PRICE};
use ghost_entitlement::grid::{week_start, DAY_SECS};
use ghost_entitlement::monero::MoneroNetwork;
use ghost_entitlement::{Kind, Schedule, Token};
use ghost_issuer::journal::{BatchEntry, Entry, MAX_BATCH_CLAIMS};
use ghost_issuer::payout::{self, AckFile, BatchFile, EntryOutcome, PayoutFileError};
use ghost_issuer::reconcile::{self, CounterId, Mismatch};
use ghost_issuer::store::{self, BatchState, ClaimState, ADDRESS_LEN};
use ghost_issuer_api::proto as wire;

fn mint_many(w: &World, n: usize, tag: &str) -> Vec<Token> {
    (0..n)
        .map(|i| w.mint(Kind::Credit, 227, &format!("{tag}-{i}")))
        .collect()
}

/// A world with `claims` queued claims of ten minted credits each (payout addresses of minors
/// 9 001, 9 002, …).
fn with_claims(claims: usize) -> World {
    let mut w = World::new(true);
    w.external_credits = true;
    for i in 0..claims {
        let credits = mint_many(&w, 10, &format!("q{i}"));
        let address = common::chain_port::address(9_001 + i as u32);
        assert_eq!(
            w.claim(&format!("q{i}"), &credits, &address)
                .unwrap()
                .result,
            QUEUED
        );
    }
    w
}

fn counter_total(w: &World, id: CounterId) -> u64 {
    let tx = w.issuer().store().read().unwrap();
    reconcile::all(&*tx)
        .unwrap()
        .iter()
        .filter(|((c, _), _)| *c == id)
        .map(|(_, v)| *v)
        .sum()
}

#[test]
fn queued_claims_are_exported_in_one_signed_batch_rewritten_byte_for_byte() {
    let mut w = with_claims(3);
    let now = w.now;
    assert!(w.issuer().status_at(now).unwrap().payout_batch_ready);
    let report = w.export();
    assert_eq!((report.created.len(), report.written), (1, 1));
    let files = w.batch_files();
    assert_eq!(files.len(), 1);
    let file = &files[0];
    assert_eq!(file.network, MoneroNetwork::Regtest);
    assert_eq!(file.week, BASE_WEEK);
    assert_eq!((file.entries.len(), file.total), (3, 3 * PRICE));
    let mut ids: Vec<[u8; 16]> = file.entries.iter().map(|e| e.claim_id).collect();
    ids.sort();
    let mut expected: Vec<[u8; 16]> = (0..3).map(|i| claim_id(&format!("q{i}"))).collect();
    expected.sort();
    assert_eq!(ids, expected);
    for e in &file.entries {
        let i = (0..3)
            .find(|i| claim_id(&format!("q{i}")) == e.claim_id)
            .unwrap();
        assert_eq!(e.address_text(), common::chain_port::address(9_001 + i));
        assert_eq!(e.amount, PRICE);
    }
    assert!(!w.issuer().status_at(now).unwrap().payout_batch_ready);
    // Re-exports, after a restart too, write nothing new; a deleted file comes back identical.
    assert_eq!(w.export().written, 0);
    w.reopen();
    assert_eq!(w.export().written, 0);
    let path = w.export_dir().join(payout::batch_file_name(&file.batch_id));
    std::fs::remove_file(&path).unwrap();
    assert_eq!(w.export().written, 1);
    // Another ops key does not verify the file.
    let bytes = std::fs::read(&path).unwrap();
    let other = payout::OpsKey::from_seed(&[1; 32]);
    assert_eq!(
        BatchFile::verify(&bytes, &other.public()),
        Err(PayoutFileError::Signature)
    );
    w.check();
}

#[test]
fn the_batch_file_carries_the_cumulative_credited_revenue() {
    let mut w = World::new(true);
    w.external_credits = true;
    w.buy_pack("a");
    w.buy_pack("b");
    {
        let tx = w.issuer().store().read().unwrap();
        assert_eq!(
            reconcile::get(&*tx, CounterId::XmrCreditedTotal, reconcile::TOTAL_INDEX).unwrap(),
            2 * PRICE
        );
    }
    let credits = mint_many(&w, 10, "c");
    assert_eq!(
        w.claim("q", &credits, &claim_address()).unwrap().result,
        QUEUED
    );
    w.export();
    assert_eq!(w.batch_files()[0].cumulative_credited, 2 * PRICE);
    w.check();
}

#[test]
fn an_acknowledgement_must_name_exactly_the_batch() {
    let mut w = with_claims(2);
    w.export();
    let file = w.batch_files()[0].clone();
    let dir = w.export_dir();
    let good = AckFile {
        batch_id: file.batch_id,
        entries: file
            .entries
            .iter()
            .map(|e| (e.claim_id, EntryOutcome::Paid))
            .collect(),
    };
    let write = |ack: &AckFile, id: &[u8; 16]| {
        std::fs::write(dir.join(payout::ack_file_name(id)), ack.encode().unwrap()).unwrap();
    };
    let mut bad: Vec<(AckFile, [u8; 16])> = Vec::new();
    let mut missing = good.clone();
    missing.entries.pop();
    bad.push((missing, file.batch_id));
    let mut duplicate = good.clone();
    duplicate.entries[1].0 = duplicate.entries[0].0;
    bad.push((duplicate, file.batch_id));
    let mut other_claim = good.clone();
    other_claim.entries[1].0 = claim_id("nobody");
    bad.push((other_claim, file.batch_id));
    let mut extra = good.clone();
    extra
        .entries
        .push((claim_id("nobody"), EntryOutcome::Refused));
    bad.push((extra, file.batch_id));
    let mut unknown = good.clone();
    unknown.batch_id = [0x55; 16];
    bad.push((unknown, [0x55; 16]));
    // An ack whose batch id differs from its file name.
    bad.push((good.clone(), [0x66; 16]));
    for (ack, id) in &bad {
        write(ack, id);
        let report = w.export();
        assert_eq!(
            (report.acks_refused, report.acknowledged.len()),
            (1, 0),
            "{ack:?}"
        );
        // Kept for the operator to replace only while it names an exported batch (§6.4).
        let path = dir.join(payout::ack_file_name(id));
        assert_eq!(path.exists(), *id == file.batch_id, "{ack:?}");
        let _ = std::fs::remove_file(path);
    }
    std::fs::write(dir.join(payout::ack_file_name(&file.batch_id)), b"garbage").unwrap();
    assert_eq!(w.export().acks_refused, 1);
    {
        let tx = w.issuer().store().read().unwrap();
        assert_eq!(
            store::batch(&*tx, &file.batch_id).unwrap().unwrap().state,
            BatchState::Exported
        );
    }
    assert_eq!(
        w.batch_files().len(),
        1,
        "an unacknowledged batch stays exported"
    );

    write(&good, &file.batch_id);
    let report = w.export();
    assert_eq!(report.acknowledged, vec![file.batch_id]);
    assert!(w.batch_files().is_empty());
    assert!(!dir.join(payout::ack_file_name(&file.batch_id)).exists());
    assert_eq!(counter_total(&w, CounterId::PayoutPaidAtomic), 2 * PRICE);
    {
        let tx = w.issuer().store().read().unwrap();
        for (_, c) in store::claims(&*tx).unwrap() {
            assert_eq!(c.state, ClaimState::Paid);
        }
    }
    // The same acknowledgement again: already paid, consumed, counted once.
    write(&good, &file.batch_id);
    let report = w.export();
    assert_eq!((report.acks_refused, report.acknowledged.len()), (0, 0));
    assert!(!dir.join(payout::ack_file_name(&file.batch_id)).exists());
    assert_eq!(counter_total(&w, CounterId::PayoutPaidAtomic), 2 * PRICE);
    w.check();
}

#[test]
fn a_restore_never_requeues_a_batched_claim() {
    let mut w = with_claims(2);
    w.snapshot();
    w.export();
    let file = w.batch_files()[0].clone();
    let bytes =
        std::fs::read(w.export_dir().join(payout::batch_file_name(&file.batch_id))).unwrap();
    w.restore();
    let report = w.export();
    assert!(report.created.is_empty(), "§19.5: no claim re-queued");
    assert_eq!(report.written, 0, "the same file");
    assert_eq!(
        std::fs::read(w.export_dir().join(payout::batch_file_name(&file.batch_id))).unwrap(),
        bytes
    );
    w.write_ack(&file);
    w.export();
    assert_eq!(counter_total(&w, CounterId::PayoutPaidAtomic), 2 * PRICE);
    // Restored again from the snapshot: BATCH and BATCH_PAID replay; paid once.
    w.restore();
    assert!(w.export().created.is_empty());
    assert_eq!(counter_total(&w, CounterId::PayoutPaidAtomic), 2 * PRICE);
    w.check();
}

#[test]
fn a_batch_holds_at_most_200_claims() {
    let mut w = World::new(true);
    w.external_credits = true;
    let mut content = w.schedule.content().clone();
    content.constants.min_claim_credits = 1;
    w.schedule = Schedule::verify_with_key(
        &fixture::sign_content(&content),
        &fixture::schedule_public_key(),
    )
    .unwrap();
    w.reopen();
    for i in 0..=MAX_BATCH_CLAIMS {
        let credit = w.mint(Kind::Credit, 227, &format!("one-{i}"));
        assert_eq!(
            w.claim(
                &format!("one-{i}"),
                &[credit],
                &common::chain_port::address(10_000 + i as u32)
            )
            .unwrap()
            .result,
            QUEUED
        );
    }
    let report = w.export();
    assert_eq!(report.created.len(), 2);
    let mut sizes: Vec<usize> = w.batch_files().iter().map(|f| f.entries.len()).collect();
    sizes.sort();
    assert_eq!(sizes, vec![1, MAX_BATCH_CLAIMS]);
    w.check();
}

const ADDRESS_REJECTED: i32 = wire::ClaimPayoutResult::AddressRejected as i32;

/// S6 review (MONEY-1, PRIV-1): a payout address is in at most one queued or batched claim, so no
/// batch ever carries it twice; a duplicate is refused in-band and consumes nothing. Once its batch
/// is paid the issuer has deleted the address and cannot know it any more: the workstation refuses
/// such a repeat per entry.
#[test]
fn a_payout_address_of_a_queued_or_batched_claim_is_rejected() {
    let mut w = World::new(true);
    w.external_credits = true;
    let address = claim_address();
    let first = mint_many(&w, 10, "a");
    assert_eq!(w.claim("a", &first, &address).unwrap().result, QUEUED);
    let second = mint_many(&w, 10, "b");
    let r = w.claim("b", &second, &address).unwrap();
    assert_eq!(
        (r.result, r.queued_atomic, r.spent_mask),
        (ADDRESS_REJECTED, 0, 0),
        "queued"
    );
    // Nothing was consumed: the same credits queue a claim to another address.
    let other = common::chain_port::address(9_002);
    assert_eq!(w.claim("b2", &second, &other).unwrap().result, QUEUED);
    w.export();
    let third = mint_many(&w, 10, "c");
    assert_eq!(
        w.claim("c", &third, &address).unwrap().result,
        ADDRESS_REJECTED,
        "batched"
    );
    let file = w.batch_files()[0].clone();
    assert_eq!(file.entries.len(), 2);
    w.write_ack(&file);
    w.export();
    assert_eq!(w.claim("c", &third, &address).unwrap().result, QUEUED);
    w.check();
}

/// S6 review (MONEY-3): an entry named like an acknowledgement that cannot be read (here a
/// directory) is counted as refused; the run still creates and writes the week's batches.
#[test]
fn an_unreadable_acknowledgement_does_not_stop_the_payout_run() {
    let w = with_claims(1);
    let dir = w.export_dir();
    std::fs::create_dir_all(dir.join(payout::ack_file_name(&[0x42; 16]))).unwrap();
    let report = w
        .issuer()
        .payout_export_at(w.now, &ops_key(), &dir)
        .expect("an unreadable acknowledgement does not fail the run");
    assert_eq!(
        (report.created.len(), report.written, report.acks_refused),
        (1, 1, 1)
    );
}

/// S6 review (PRIV-4): payout residues that no retention rule covers are removed at every run: a
/// temporary batch file a crash left behind, and an acknowledgement that can never apply (its
/// batch is unknown, or already paid and swept). An acknowledgement of an exported batch that does
/// not match stays, for the operator to replace.
#[test]
fn payout_residues_are_removed_at_every_run() {
    let mut w = with_claims(1);
    let dir = w.export_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let tmp = dir.join(format!("batch-{}.tmp", "ab".repeat(16)));
    std::fs::write(&tmp, b"claim ids and payout addresses").unwrap();
    let unknown = dir.join(payout::ack_file_name(&[0x55; 16]));
    std::fs::write(&unknown, b"garbage").unwrap();
    let report = w.export();
    assert_eq!((report.created.len(), report.acks_refused), (1, 1));
    assert!(!tmp.exists(), "a stale temporary batch file");
    assert!(!unknown.exists(), "an acknowledgement of no exported batch");
    let file = w.batch_files()[0].clone();
    let own = dir.join(payout::ack_file_name(&file.batch_id));
    std::fs::write(&own, b"garbage").unwrap();
    assert_eq!(w.export().acks_refused, 1);
    assert!(own.exists(), "the operator replaces it");
    w.write_ack(&file);
    assert_eq!(w.export().acknowledged, vec![file.batch_id]);
    assert!(std::fs::read_dir(&dir).unwrap().next().is_none());
    w.check();
}

/// S6 review (PRIV-3): the week's export hour is drawn once, at the first run of the week, and kept
/// across restarts. At that hour whatever is queued is batched; a claim queued after it waits for
/// the next week's hour, so the time a batch is created never follows the time a claim arrived.
#[test]
fn the_export_hour_is_drawn_once_a_week_whatever_the_queue_holds() {
    let mut w = World::new(true);
    w.external_credits = true;
    let key = ops_key();
    let dir = w.export_dir();
    let job = |w: &World, now: u64, draw: u64| {
        w.issuer()
            .payout_job_at(now, &key, &dir, draw)
            .unwrap()
            .created
            .len()
    };
    let start = week_start(BASE_WEEK);
    // The first run of the week draws hour 12 (draw mod 168); the queue is empty then.
    assert_eq!(job(&w, start + 12 * 3_600, 12), 0);
    let credits = mint_many(&w, 10, "late");
    assert_eq!(
        w.claim("late", &credits, &claim_address()).unwrap().result,
        QUEUED
    );
    let end = week_start(BASE_WEEK + 1);
    for (now, draw) in [(start + 13 * 3_600, 0), (end - 3_600, 0), (end - 1, 7)] {
        assert_eq!(job(&w, now, draw), 0, "after the week's hour: {now}");
    }
    // The next week draws hour 30 at its first run; a restart keeps it.
    assert_eq!(job(&w, end, 30), 0);
    w.reopen();
    assert_eq!(job(&w, end + 29 * 3_600, 0), 0, "before the drawn hour");
    assert_eq!(job(&w, end + 30 * 3_600, 5), 1, "the drawn hour");
    assert_eq!(job(&w, end + 31 * 3_600, 0), 0, "one export a week");
    w.check();
}

/// S6 review (PRIV-5): §6.1 and §6.4 delete a paid batch's claims 7 days and its row 30 days after
/// the acknowledgement. With weeks as the only clock (§19.15) the claims go at the start of the
/// week after the acknowledgement and the row four weeks after it: never later than 7 and 30 days,
/// wherever in its week the acknowledgement came (here its first second, the worst case).
#[test]
fn paid_claims_and_batches_are_deleted_within_seven_and_thirty_days() {
    let mut w = with_claims(1);
    w.export();
    let file = w.batch_files()[0].clone();
    w.now = week_start(BASE_WEEK + 1);
    w.write_ack(&file);
    assert_eq!(w.export().acknowledged, vec![file.batch_id]);
    let acked = w.now;
    let rows = |w: &World| {
        let tx = w.issuer().store().read().unwrap();
        (
            store::claims(&*tx).unwrap().len(),
            store::batches(&*tx).unwrap().len(),
        )
    };
    w.sweep();
    assert_eq!(rows(&w), (1, 1), "kept in the week of the acknowledgement");
    w.now = acked + 7 * DAY_SECS;
    w.sweep();
    assert_eq!(
        rows(&w),
        (0, 1),
        "claims: at most 7 d after the acknowledgement"
    );
    w.now = acked + 30 * DAY_SECS;
    w.sweep();
    assert_eq!(
        rows(&w),
        (0, 0),
        "batch: at most 30 d after the acknowledgement"
    );
    // The claim id is forgotten; its credits stay spent.
    let credits = mint_many(&w, 10, "q0");
    let r = w
        .claim("q0", &credits, &common::chain_port::address(9_001))
        .unwrap();
    assert_eq!(r.result, CLAIM_SPENT);
}

/// S6 review (MONEY-1, PRIV-1): the workstation refused an entry (a payout address it had seen
/// before): the acknowledgement names it refused and the batch closes. That claim closes unpaid
/// with its address deleted and its credits spent; only the paid entries count as paid; a restore
/// replays the refusal.
#[test]
fn a_refused_entry_closes_its_claim_unpaid_and_the_batch_is_acknowledged() {
    let mut w = with_claims(3);
    w.export();
    let file = w.batch_files()[0].clone();
    w.snapshot();
    let refused = file.entries[1].claim_id;
    w.write_ack_refusing(&file, &[refused]);
    assert_eq!(w.export().acknowledged, vec![file.batch_id]);
    assert!(std::fs::read_dir(w.export_dir()).unwrap().next().is_none());
    let closed = |w: &World| {
        let tx = w.issuer().store().read().unwrap();
        for (id, c) in store::claims(&*tx).unwrap() {
            let expected = if id == refused {
                ClaimState::Refused
            } else {
                ClaimState::Paid
            };
            assert_eq!(c.state, expected);
            assert_eq!(c.address, [0u8; ADDRESS_LEN], "the address is deleted");
        }
        assert_eq!(
            store::batch(&*tx, &file.batch_id).unwrap().unwrap().state,
            BatchState::Paid
        );
    };
    closed(&w);
    assert_eq!(counter_total(&w, CounterId::PayoutPaidAtomic), 2 * PRICE);
    assert_eq!(counter_total(&w, CounterId::PayoutRefusedAtomic), PRICE);
    w.restore();
    closed(&w);
    assert_eq!(counter_total(&w, CounterId::PayoutPaidAtomic), 2 * PRICE);
    assert_eq!(counter_total(&w, CounterId::PayoutRefusedAtomic), PRICE);
    let i = (0..3)
        .find(|i| claim_id(&format!("q{i}")) == refused)
        .unwrap();
    let credits = mint_many(&w, 10, &format!("q{i}"));
    let r = w
        .claim("again", &credits, &common::chain_port::address(9_100))
        .unwrap();
    assert_eq!(
        r.result, CLAIM_SPENT,
        "a refused claim's credits stay spent"
    );
    w.check();
}

/// Two concurrent claims to one address (the I-K interleaving): both pass the checks before the
/// transaction, and the transaction's re-check queues one and answers the other ADDRESS_REJECTED.
#[test]
fn concurrent_claims_to_one_address_queue_one() {
    let mut w = World::new(true);
    w.external_credits = true;
    let request = |label: &str, credits: Vec<Token>| wire::ClaimPayoutRequest {
        version: 1,
        claim_id: claim_id(label).to_vec(),
        credits: credits.iter().map(|t| t.as_bytes().to_vec()).collect(),
        payout_address: claim_address(),
    };
    let ra = request("x", mint_many(&w, 10, "x"));
    let rb = request("y", mint_many(&w, 10, "y"));
    let (a, b) = w.race(
        move |i, now| i.claim_payout_at(ra, now),
        move |i, now| i.claim_payout_at(rb, now),
    );
    let mut results = [a.unwrap().result, b.unwrap().result];
    results.sort();
    assert_eq!(results, [QUEUED, ADDRESS_REJECTED]);
    w.reopen();
    w.check();
}

#[test]
fn batch_journal_entries_are_bounded() {
    let entry = |n: usize| {
        Entry::Batch(BatchEntry {
            batch_id: [1; 16],
            week: BASE_WEEK,
            cumulative_credited: 0,
            claims: (0..n).map(|i| [(i % 256) as u8; 16]).collect(),
        })
    };
    assert!(entry(MAX_BATCH_CLAIMS).encode(1).is_ok());
    assert!(entry(MAX_BATCH_CLAIMS + 1).encode(1).is_err());
    assert!(entry(0).encode(1).is_err());
}

#[test]
fn relay_redemptions_are_bounded_per_week_over_all_slots() {
    let mut w = World::new(true);
    w.buy_pack("p");
    let invite = w.mint(Kind::Invite, 740, "i");
    let trial = w.trial_blinded("t", BASE_WEEK);
    assert_eq!(
        w.redeem(&invite, BASE_WEEK, trial).unwrap().result,
        wire::RedeemInviteResult::Ok as i32
    );
    let tx = w.issuer().store().read().unwrap();
    let counters = reconcile::all(&*tx).unwrap();
    // Small schedule: 3 slots, 1 access and 1 trial position per slot and week.
    let expected = |week: u64| -> u64 {
        match week {
            w if w == BASE_WEEK || w == BASE_WEEK + 1 => 3 + 3,
            w if w <= BASE_WEEK + 4 => 3,
            _ => 0,
        }
    };
    assert_eq!(
        reconcile::expected_access(&counters, &w.schedule, BASE_WEEK),
        6
    );
    let within: BTreeMap<u64, u64> = (BASE_WEEK..BASE_WEEK + 6)
        .map(|w| (w, expected(w)))
        .collect();
    assert!(reconcile::check_relays(&counters, &w.schedule, w.now, &within).is_empty());
    let over: BTreeMap<u64, u64> = [(BASE_WEEK + 1, 7), (BASE_WEEK + 5, 1)].into();
    assert_eq!(
        reconcile::check_relays(&counters, &w.schedule, w.now, &over),
        vec![
            Mismatch::RelayRedemptions {
                week: BASE_WEEK + 1
            },
            Mismatch::RelayRedemptions {
                week: BASE_WEEK + 5
            }
        ]
    );
}

/// The counters of a credit epoch are kept until 400 days after its credits can no longer be
/// presented (the start of epoch c + 5), and the totals are never swept.
#[test]
fn credit_epoch_counters_outlive_their_credits_and_totals_are_kept() {
    let mut w = World::new(true);
    w.external_credits = true;
    w.now = week_start(231 * 13) + NOON; // the last credit epoch that accepts credits of 227
    let credits = mint_many(&w, 10, "late");
    assert_eq!(
        w.claim("late", &credits, &claim_address()).unwrap().result,
        QUEUED
    );
    let payout_of = |w: &World| {
        let tx = w.issuer().store().read().unwrap();
        (
            reconcile::get(&*tx, CounterId::CreditsPayout, 227).unwrap(),
            reconcile::get(&*tx, CounterId::PayoutQueuedTotal, reconcile::TOTAL_INDEX).unwrap(),
        )
    };
    let closed = (227 + 5) * 13;
    w.now = week_start(closed + reconcile::RETENTION_WEEKS) + NOON;
    w.sweep();
    assert_eq!(payout_of(&w), (10, PRICE), "58 weeks old: kept");
    w.check();
    w.now = week_start(closed + reconcile::RETENTION_WEEKS + 1) + NOON;
    w.sweep();
    assert_eq!(
        payout_of(&w),
        (0, PRICE),
        "swept once older than 58 weeks after the acceptance closed"
    );
}

#[test]
fn the_view_bounds_credited_revenue_and_cumulative_payouts() {
    assert!(reconcile::check_view(100, 100, 10).is_empty());
    assert_eq!(
        reconcile::check_view(101, 100, 0),
        vec![Mismatch::ViewBelowCredited]
    );
    assert_eq!(reconcile::check_view(0, 100, 11), vec![Mismatch::PayoutCap]);
    assert!(reconcile::within_cap(u64::MAX / 10, u64::MAX));
    assert!(!reconcile::within_cap(u64::MAX / 10 + 1, u64::MAX));
}
