//! The payout pipeline, issuer side (Phase 8 design §9.5, §19.5, §19.7, §6.9): batches of queued
//! claims (journaled `BATCH`), the batch file signed by the ops key and rewritten byte for byte,
//! the workstation's acknowledgement (`BATCH_PAID`), the weekly job, retention, restores, and the
//! reconciliation checks with the relay aggregates and the workstation's view.

mod common;

use std::collections::BTreeMap;

use common::fixture;
use common::scenarios::{claim_address, NOON, QUEUED};
use common::world::{claim_id, ops_key, payout_txid, World, BASE_WEEK, PRICE};
use ghost_entitlement::grid::week_start;
use ghost_entitlement::monero::MoneroNetwork;
use ghost_entitlement::{Kind, Schedule, Token};
use ghost_issuer::journal::{BatchEntry, Entry, MAX_BATCH_CLAIMS};
use ghost_issuer::payout::{self, AckFile, BatchFile, PayoutFileError};
use ghost_issuer::reconcile::{self, CounterId, Mismatch};
use ghost_issuer::store::{self, BatchState, ClaimState};
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
            .enumerate()
            .map(|(i, e)| (e.claim_id, payout_txid(3, i)))
            .collect(),
    };
    let write = |ack: &AckFile, id: &[u8; 16]| {
        std::fs::write(dir.join(payout::ack_file_name(id)), ack.encode().unwrap()).unwrap();
    };
    let mut bad: Vec<(AckFile, [u8; 16])> = Vec::new();
    let mut missing = good.clone();
    missing.entries.pop();
    bad.push((missing, file.batch_id));
    let mut duplicate_txid = good.clone();
    duplicate_txid.entries[1].1 = duplicate_txid.entries[0].1;
    bad.push((duplicate_txid, file.batch_id));
    let mut zero_txid = good.clone();
    zero_txid.entries[0].1 = [0; 32];
    bad.push((zero_txid, file.batch_id));
    let mut other_claim = good.clone();
    other_claim.entries[1].0 = claim_id("nobody");
    bad.push((other_claim, file.batch_id));
    let mut extra = good.clone();
    extra.entries.push((claim_id("nobody"), payout_txid(3, 9)));
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
        std::fs::remove_file(dir.join(payout::ack_file_name(id))).unwrap();
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
    w.write_ack(&file, 4);
    w.export();
    assert_eq!(counter_total(&w, CounterId::PayoutPaidAtomic), 2 * PRICE);
    // Restored again from the snapshot: BATCH and BATCH_PAID replay; paid once.
    w.restore();
    assert!(w.export().created.is_empty());
    assert_eq!(counter_total(&w, CounterId::PayoutPaidAtomic), 2 * PRICE);
    w.check();
}

#[test]
fn the_weekly_job_creates_batches_once_a_week_at_a_drawn_hour() {
    let mut w = with_claims(1);
    let key = ops_key();
    let dir = w.export_dir();
    let now = week_start(BASE_WEEK) + NOON; // 156 hours left in the week
    let job = |w: &World, now: u64, draw: u64| {
        w.issuer()
            .payout_job_at(now, &key, &dir, draw)
            .unwrap()
            .created
            .len()
    };
    assert_eq!(job(&w, now, 1), 0, "not the drawn hour");
    assert_eq!(job(&w, now, 156), 1, "the drawn hour");
    let credits = mint_many(&w, 10, "later");
    assert_eq!(
        w.claim("later", &credits, &claim_address()).unwrap().result,
        QUEUED
    );
    assert_eq!(job(&w, now + 3_600, 0), 0, "one batch a week");
    assert_eq!(job(&w, week_start(BASE_WEEK + 1), 0), 1, "the next week");
    w.check();
}

#[test]
fn paid_batches_are_deleted_after_their_retention() {
    let mut w = with_claims(1);
    w.export();
    let file = w.batch_files()[0].clone();
    w.write_ack(&file, 5);
    w.export();
    let rows = |w: &World| {
        let tx = w.issuer().store().read().unwrap();
        (
            store::claims(&*tx).unwrap().len(),
            store::batches(&*tx).unwrap().len(),
        )
    };
    let paid_week = BASE_WEEK;
    w.now = week_start(paid_week + 1) + NOON;
    w.sweep();
    assert_eq!(rows(&w), (1, 1));
    w.now = week_start(paid_week + payout::CLAIMS_KEEP_WEEKS) + NOON;
    w.sweep();
    assert_eq!(rows(&w), (0, 1), "claims: paid + 7 d");
    w.now = week_start(paid_week + payout::BATCH_KEEP_WEEKS) + NOON;
    w.sweep();
    assert_eq!(rows(&w), (0, 0), "batch: paid + 30 d");
    // The claim id is forgotten; its credits stay spent.
    let credits = mint_many(&w, 10, "q0");
    let r = w
        .claim("q0", &credits, &common::chain_port::address(9_001))
        .unwrap();
    assert_eq!(r.result, wire::ClaimPayoutResult::CreditsSpent as i32);
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
            w.claim(&format!("one-{i}"), &[credit], &claim_address())
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
