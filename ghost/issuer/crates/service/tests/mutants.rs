//! The issuer mutants of Phase 8 design §13.5, each caught by the test the design names:
//! MM1, MM2, MM10, MM11, MM12, MM15, MM16, MM17, MM18 (issuer side) and MM20. MM3 is in
//! `tests/crash.rs`; MM4–MM9 and MM19 are caught by the live Monero job (`monero_regtest.rs`);
//! MM13, MM14 and the relay side of MM18 by the relay (`relay/crates/node/tests/redeem.rs`).
//!
//! The `MutantDetectionTest` pattern: a detector runs once against the real issuer, where it must
//! pass, and once with the mutation, where it must fail. Production code has no hooks, so a mutant
//! is the behaviour the mutated issuer would show, produced from the outside: the answer it would
//! give (blind signatures computed with the test keys), the counters or journal entries it would
//! write (written into the closed database or journal and replayed by the real startup), or the
//! state it would run on (a key window, an open mode, a rail view, forgotten high-water marks).

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::panic::AssertUnwindSafe;

use common::scenarios::{
    claim_address, clock_back_credit, clock_back_credit_world, clock_back_invite,
    clock_back_invite_world, other_blinded, race_blinded, race_retry, race_world, with_credits,
    RaceKind, NOON, OK, OTHER, SIGNED,
};
use common::world::{claim_id, claim_key, World, BASE_WEEK, PRICE};
use ghost_entitlement::batch::{self, Layout};
use ghost_entitlement::grid::{credit_epoch, week_start, DAY_SECS};
use ghost_entitlement::{Kind, Token};
use ghost_issuer::custody::destroy_after;
use ghost_issuer::journal::{ClaimEntry, Entry, InvoiceEntry};
use ghost_issuer::reconcile::{self, CounterId};
use ghost_issuer::service::{claim_digest, request_invoice_digest, OpenMode};
use ghost_issuer::store::{PayWith, ADDRESS_LEN};
use ghost_issuer_api::proto as wire;
use tonic::Code;

const AWAITING_PAYMENT: i32 = wire::InvoiceState::AwaitingPayment as i32;

/// Runs `detector` against the real issuer (it must pass) and with the mutation (it must fail).
fn detected(name: &str, detector: fn(bool)) {
    detector(false);
    let caught = std::panic::catch_unwind(AssertUnwindSafe(|| detector(true))).is_err();
    assert!(caught, "{name} was not detected");
}

/// Blind signatures of `blinded` over `layout` computed with the test keys: what a mutated issuer
/// returns.
fn sign_with_keys(w: &World, layout: &Layout, blinded: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for (p, block) in layout.positions().iter().zip(blinded.as_chunks::<256>().0) {
        let sig = w
            .keys
            .get(p.kind, p.epoch)
            .unwrap()
            .blind_sign(block)
            .unwrap();
        out.extend_from_slice(&sig);
    }
    out
}

/// Counters a mutated issuer would add, written into the database.
fn add_counters(w: &World, counters: &BTreeMap<(CounterId, u64), u64>) {
    let mut tx = w.issuer().store().write().unwrap();
    for (&(id, index), &delta) in counters {
        reconcile::add(&mut *tx, id, index, delta).unwrap();
    }
    tx.commit().unwrap();
}

fn signed_counter(kind: Kind) -> CounterId {
    match kind {
        Kind::Access => CounterId::SignedAccess,
        Kind::Invite => CounterId::SignedInvite,
        Kind::Credit => CounterId::SignedCredit,
    }
}

// ------------------------------------------------------------------------------------------------
// MM1 NoDigestGuard: the issuer signs a different blinded set after ISSUED.
// Caught by the issuer negative test and the crash harness (MS-1).
// ------------------------------------------------------------------------------------------------

fn only_the_identical_request_is_served_after_issue(mutant: bool) {
    let mut w = World::new(true);
    w.buy_pack("p");
    let other = other_blinded(&w, "p");
    let answer = if mutant {
        let p = w.purchase("p");
        let sigs = sign_with_keys(&w, &w.layout(&p), &other);
        w.observed
            .signed
            .entry(p.id)
            .or_default()
            .insert((batch::request_digest(&p.id, &other), sigs.clone()));
        wire::BlindSignResponse {
            state: SIGNED,
            blind_signatures: sigs,
            credited_atomic: PRICE,
            seen_atomic: 0,
        }
    } else {
        w.sign_with("p", other).unwrap()
    };
    assert_eq!(answer.state, OTHER, "another request signed after ISSUED");
    w.check();
}

#[test]
fn mm1_no_digest_guard_is_detected() {
    detected(
        "MM1 NoDigestGuard",
        only_the_identical_request_is_served_after_issue,
    );
}

// ------------------------------------------------------------------------------------------------
// MM2 NoCasOnIssue: a commit without re-reading the state; two different concurrent requests
// both signed. Caught by the concurrency test (I-K) and MS-1.
// ------------------------------------------------------------------------------------------------

fn one_of_two_concurrent_blind_signs_signs(mutant: bool) {
    let mut w = race_world(RaceKind::BlindSign, false);
    if mutant {
        // The losing transaction committed without the compare-and-set: its request was signed.
        let p = w.purchase("k");
        let (won, _) = w.observed.signed[&p.id].iter().next().unwrap().clone();
        let lost = race_blinded(&w)
            .into_iter()
            .find(|b| batch::request_digest(&p.id, b) != won)
            .unwrap();
        let sigs = sign_with_keys(&w, &w.layout(&p), &lost);
        w.observed
            .signed
            .get_mut(&p.id)
            .unwrap()
            .insert((batch::request_digest(&p.id, &lost), sigs));
    }
    w.reopen();
    w.check();
    race_retry(RaceKind::BlindSign, &mut w);
}

#[test]
fn mm2_no_cas_on_issue_is_detected() {
    detected("MM2 NoCasOnIssue", one_of_two_concurrent_blind_signs_signs);
}

// ------------------------------------------------------------------------------------------------
// MM10 ExpireFromStaleView. Caught by crash scenario I-C: a stale view never expires an invoice.
// ------------------------------------------------------------------------------------------------

fn a_stale_view_never_expires_an_invoice(mutant: bool) {
    let mut w = World::new(true);
    assert_eq!(w.request("c", BASE_WEEK, &[]).unwrap().result, OK);
    // The view is stale. The real scanner sees it as the rail reports it; the mutant's scanner
    // decides on it as if it were synced, which is what it sees when the flag never reaches it.
    if !mutant {
        w.chain.set_synced(false);
    }
    w.mine(720 + 2_160 + 10 + 1);
    assert_eq!(
        w.sign("c").unwrap().state,
        AWAITING_PAYMENT,
        "expired from a stale view"
    );
}

#[test]
fn mm10_expire_from_stale_view_is_detected() {
    detected(
        "MM10 ExpireFromStaleView",
        a_stale_view_never_expires_an_invoice,
    );
}

// ------------------------------------------------------------------------------------------------
// MM11 CreditOnCreditsPack. Caught by the layout unit test and the reconciliation invariant.
// ------------------------------------------------------------------------------------------------

fn a_credits_pack_mints_no_credit(mutant: bool) {
    let mut w = with_credits("m11");
    assert!(
        Layout::pack(&w.schedule, BASE_WEEK, false)
            .unwrap()
            .positions()
            .iter()
            .all(|p| p.kind != Kind::Credit),
        "a credits-paid layout has no credit position"
    );
    let credits = w.wallet.credits.clone();
    assert_eq!(w.request("d", BASE_WEEK, &credits).unwrap().result, OK);
    let s = w.sign("d").unwrap();
    assert_eq!(w.finalize("d", &s.blind_signatures).len(), 17);
    if mutant {
        // The mutant's credits pack also signed, and counted, a credit position.
        add_counters(
            &w,
            &BTreeMap::from([((CounterId::SignedCredit, credit_epoch(BASE_WEEK)), 1)]),
        );
    }
    w.check();
}

#[test]
fn mm11_credit_on_credits_pack_is_detected() {
    detected("MM11 CreditOnCreditsPack", a_credits_pack_mints_no_credit);
}

// ------------------------------------------------------------------------------------------------
// MM12 CountOnReserve. Caught by the reconciliation invariants in the crash harness.
// ------------------------------------------------------------------------------------------------

fn a_reserve_counts_nothing(mutant: bool) {
    let mut w = World::new(true);
    w.buy_pack("p");
    assert_eq!(w.sign("p").unwrap().state, SIGNED, "the identical re-serve");
    if mutant {
        // The re-serve counted the issuance again, every counter the first issuance counted.
        let p = w.purchase("p");
        let mut counts: BTreeMap<(CounterId, u64), u64> = BTreeMap::new();
        for pos in w.layout(&p).positions() {
            *counts
                .entry((signed_counter(pos.kind), pos.epoch))
                .or_default() += 1;
        }
        counts.insert((CounterId::PacksXmr, BASE_WEEK), 1);
        counts.insert((CounterId::XmrCreditedAtomic, BASE_WEEK), PRICE);
        add_counters(&w, &counts);
    }
    w.check();
}

#[test]
fn mm12_count_on_reserve_is_detected() {
    detected("MM12 CountOnReserve", a_reserve_counts_nothing);
}

// ------------------------------------------------------------------------------------------------
// MM15 PoolNotResetOnRestore. Caught by crash scenario I-H: a minor handed out twice.
// ------------------------------------------------------------------------------------------------

/// The pool reset is the defence for a restore whose journal lacks the invoices created after the
/// snapshot (§19.5 rule 3): their minors are in the snapshot's pool.
fn a_restore_hands_out_no_minor_twice(mutant: bool) {
    let mut w = World::new(true);
    w.snapshot();
    let applied = w.journal_applied();
    assert_eq!(w.request("lost", BASE_WEEK, &[]).unwrap().result, OK);
    w.crash();
    let removed = w.lose_journal_entries(applied, |e| matches!(e, Entry::Invoice(_)));
    assert_eq!(removed, 1);
    w.restore_with(if mutant {
        OpenMode::Normal
    } else {
        OpenMode::Restore
    });
    // World::request refuses a minor handed out before.
    assert_eq!(w.request("new", BASE_WEEK, &[]).unwrap().result, OK);
    assert_ne!(w.purchase("new").minor, w.purchase("lost").minor);
    w.check();
}

#[test]
fn mm15_pool_not_reset_on_restore_is_detected() {
    detected(
        "MM15 PoolNotResetOnRestore",
        a_restore_hands_out_no_minor_twice,
    );
}

// ------------------------------------------------------------------------------------------------
// MM16 JournalBeforeDecision: entries appended before the in-transaction re-check. Caught by
// crash scenario I-K (a loser replayed).
// ------------------------------------------------------------------------------------------------

/// The journal entry of the losing claim of the I-K claim race, as an issuer that appended before
/// its re-check would have written it.
fn journal_the_loser(w: &World) {
    let loser = if w.observed.claims.contains_key(&claim_id("k1")) {
        "k2"
    } else {
        "k1"
    };
    let credits: Vec<Vec<u8>> = w
        .wallet
        .credits
        .iter()
        .map(|t| t.as_bytes().to_vec())
        .collect();
    let address = claim_address();
    w.append_journal_entry(&Entry::Claim(ClaimEntry {
        claim_id: claim_id(loser),
        digest: claim_digest(&address, &credits),
        amount: PRICE,
        address: address.as_bytes().try_into().unwrap(),
        credits: w
            .wallet
            .credits
            .iter()
            .map(|t| (credit_epoch(BASE_WEEK), t.nullifier()))
            .collect(),
    }));
}

fn a_race_loser_is_never_replayed_after_a_restart(mutant: bool) {
    let mut w = race_world(RaceKind::ClaimPayout, false);
    if mutant {
        journal_the_loser(&w);
    }
    w.reopen();
    race_retry(RaceKind::ClaimPayout, &mut w);
    w.check();
}

fn a_race_loser_is_never_replayed_after_a_restore(mutant: bool) {
    let mut w = race_world(RaceKind::ClaimPayout, true);
    if mutant {
        journal_the_loser(&w);
    }
    w.restore();
    race_retry(RaceKind::ClaimPayout, &mut w);
    w.check();
}

#[test]
fn mm16_journal_before_decision_is_detected() {
    detected(
        "MM16 JournalBeforeDecision (restart)",
        a_race_loser_is_never_replayed_after_a_restart,
    );
    detected(
        "MM16 JournalBeforeDecision (restore)",
        a_race_loser_is_never_replayed_after_a_restore,
    );
}

// ------------------------------------------------------------------------------------------------
// MM17 KeyDestroyedAtFixedTime. Caught by crash scenario I-I (MS-6).
// ------------------------------------------------------------------------------------------------

fn a_paid_invoice_is_signed_weeks_later(mutant: bool) {
    let mut w = World::new(true);
    assert_eq!(w.request("p", BASE_WEEK, &[]).unwrap().result, OK);
    w.pay("p", PRICE);
    w.mine(10);
    w.now = destroy_after(Kind::Access, BASE_WEEK) + DAY_SECS;
    w.tick();
    w.sweep();
    if mutant {
        // Keys leave memory at end(epoch) + 8 d whatever an open invoice still references.
        let now = w.now;
        w.keys.destroy_due(now, &BTreeSet::new());
        w.reopen();
    }
    let s = w.sign("p").expect("MS-6: a paid invoice is signed");
    assert_eq!(s.state, SIGNED);
    w.finalize("p", &s.blind_signatures);
    w.check();
}

#[test]
fn mm17_key_destroyed_at_fixed_time_is_detected() {
    detected(
        "MM17 KeyDestroyedAtFixedTime",
        a_paid_invoice_is_signed_weeks_later,
    );
}

// ------------------------------------------------------------------------------------------------
// MM18 ClosedPeriodReopened (issuer side): no persisted high-water. Caught by the clock-regression
// tests and crash scenario I-L.
// ------------------------------------------------------------------------------------------------

fn a_closed_invite_epoch_stays_closed(mutant: bool) {
    let mut w = clock_back_invite_world();
    clock_back_invite(&mut w, mutant);
    w.check();
}

fn a_closed_credit_epoch_stays_closed(mutant: bool) {
    let mut w = clock_back_credit_world();
    clock_back_credit(&mut w, mutant);
    w.check();
}

#[test]
fn mm18_closed_period_reopened_is_detected() {
    detected(
        "MM18 ClosedPeriodReopened (invites)",
        a_closed_invite_epoch_stays_closed,
    );
    detected(
        "MM18 ClosedPeriodReopened (credits)",
        a_closed_credit_epoch_stays_closed,
    );
}

// ------------------------------------------------------------------------------------------------
// MM20 CreditValueAtCurrentPrice. Caught by the reconciliation test across a price change.
// ------------------------------------------------------------------------------------------------

fn mint_credits(w: &World, n: usize, tag: &str) -> Vec<Token> {
    (0..n)
        .map(|i| w.mint(Kind::Credit, 227, &format!("{tag}-{i}")))
        .collect()
}

/// Price epoch 229 costs 250 000 000 000; credits of epoch 227 keep their value of
/// 20 000 000 000: a pack of epoch 229 needs 13 of them, and a claim of ten queues 200 000 000 000.
fn credits_keep_the_price_of_their_epoch(mutant: bool) {
    let mut w = World::new(true);
    w.external_credits = true;
    w.now = week_start(2977) + NOON;
    let credits = mint_credits(&w, 13, "m20");
    assert_eq!(
        w.request("ten", 2977, &credits[..10]).unwrap_err().code(),
        Code::PermissionDenied
    );
    assert_eq!(w.request("thirteen", 2977, &credits).unwrap().result, OK);
    assert_eq!(w.sign("thirteen").unwrap().state, SIGNED);
    let claimed = mint_credits(&w, 10, "m20-claim");
    let r = w.claim("q", &claimed, &claim_address()).unwrap();
    assert_eq!(r.queued_atomic, 10 * 20_000_000_000);
    if mutant {
        // The mutant values every credit at price(229) / 10: ten credits of 227 pay a pack of 229,
        // and a claim of ten more is queued at 250 000 000 000. Its decided entries, replayed.
        w.crash();
        let ten = mint_credits(&w, 10, "m20-mutant");
        let nullifiers: Vec<[u8; 32]> = ten.iter().map(Token::nullifier).collect();
        w.append_journal_entry(&Entry::Invoice(InvoiceEntry {
            invoice_id: [0x20; 16],
            claim_hash: batch::claim_hash(&claim_key("m20-mutant")),
            request_digest: request_invoice_digest(2977, &nullifiers),
            pay_with: PayWith::Credits,
            minor: 0,
            subaddress: [0; ADDRESS_LEN],
            amount: 0,
            base_week: 2977,
            created_height: 0,
            grace_height: 0,
            credits: nullifiers.iter().map(|n| (227, *n)).collect(),
        }));
        let more = mint_credits(&w, 10, "m20-mutant-claim");
        let bytes: Vec<Vec<u8>> = more.iter().map(|t| t.as_bytes().to_vec()).collect();
        // Another address than claim "q"'s: the mutant is caught by the value, not by a pending
        // address repeated.
        let address = common::chain_port::address(9_997);
        w.append_journal_entry(&Entry::Claim(ClaimEntry {
            claim_id: claim_id("m20-mutant"),
            digest: claim_digest(&address, &bytes),
            amount: 10 * 25_000_000_000,
            address: address.as_bytes().try_into().unwrap(),
            credits: more.iter().map(|t| (227, t.nullifier())).collect(),
        }));
        w.reopen();
    }
    w.check();
}

#[test]
fn mm20_credit_value_at_current_price_is_detected() {
    detected(
        "MM20 CreditValueAtCurrentPrice",
        credits_keep_the_price_of_their_epoch,
    );
}
