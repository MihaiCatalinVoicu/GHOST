//! Issuer crash safety (Phase 8 design §13.2, §5.8, §19.5; G-10): scenarios I-A … I-N on the real
//! issuer, redb store and journal. Every fault site of a scenario (FaultyStore: before a write
//! transaction, pre-commit, post-commit; FaultyJournal: entry lost, torn, durable before the
//! commit; FaultyRail: before the call, effect without answer) is crashed once; I-A, I-D, I-H, I-K
//! and I-N are also crashed twice (a crash during recovery or the first retry). A crash drops every
//! in-memory object and reopens the same files; the client then retries identically. After every
//! run `World::check` asserts MS-1, MS-2, MS-3, index and pool consistency, the payout invariants
//! and the reconciliation invariants; each scenario asserts MS-6 (the paid invoice ends with its
//! tokens).
//!
//! I-G covers the claim, the weekly payout export (a signed batch file, rewritten byte for byte)
//! and the workstation's acknowledgement; "I-F refresh" a received credit exchanged by
//! `RefreshCredit` (§19.8). I-K (two concurrent requests, then a restart or a restore) and I-L (a
//! clock step back across a swept epoch) are shared with the mutant detections
//! (`common/scenarios.rs`); I-M is a lost `create_address` answer without a crash (§19.6 rule 4);
//! I-N the weekly ANCHOR journal entry of an idle issuer (Q32, §19.25; single crashes at each of
//! its sites, with their exact states before the restart, also in `tests/journal_anchor.rs`).
//! The depth of the double-crash enumeration can be raised with `GHOST_ISSUER_CRASH_DEPTH`
//! (default 2 sites after the first crash).
//!
//! Mutant MM3 `NoJournal` (§13.5) is implemented here, in `tests/` only: the ISSUE or the INVITE
//! entries decided after the snapshot are removed from the journal before the restore, and I-H
//! must fail on each. The other issuer mutants are in `tests/mutants.rs`.
//!
//! The suite runs in the release profile (§19.17 point 2; CI job `rust`):
//! `cargo test -p ghost-issuer --release --test crash`. A debug build lists its tests as ignored,
//! which keeps the debug workspace run fast (the suite takes minutes there).

mod common;

use std::panic::AssertUnwindSafe;

use common::chain_port;
use common::scenarios::{
    clock_back_credit_world, clock_back_invite_world, i_l_credit, i_l_invite, other_blinded,
    race_retry, race_world, with_credits, RaceKind,
};
use common::world::{claim_id, enumerate, Template, World, BASE_WEEK, PRICE};
use ghost_entitlement::grid::{invite_epoch, WEEK_SECS};
use ghost_entitlement::{Kind, Token};
use ghost_issuer::journal::Entry;
use ghost_issuer::pool::PoolError;
use ghost_issuer::rail::RailError;
use ghost_issuer::reconcile::{self, CounterId};
use ghost_issuer::store::{self, ClaimState};
use ghost_issuer_api::proto as wire;

const SIGNED: i32 = wire::InvoiceState::Signed as i32;
const AWAITING_PAYMENT: i32 = wire::InvoiceState::AwaitingPayment as i32;
const AWAITING_CONFIRMATIONS: i32 = wire::InvoiceState::AwaitingConfirmations as i32;
const UNDERPAID: i32 = wire::InvoiceState::Underpaid as i32;
const EXPIRED: i32 = wire::InvoiceState::Expired as i32;
const OTHER: i32 = wire::InvoiceState::OtherRequestIssued as i32;
const OK: i32 = wire::RequestInvoiceResult::Ok as i32;
const CREDITS_SPENT: i32 = wire::RequestInvoiceResult::CreditsSpent as i32;
const REFRESH_OK: i32 = wire::RefreshCreditResult::Ok as i32;
const REFRESH_REPLAYED: i32 = wire::RefreshCreditResult::Replayed as i32;

/// Double-crash depth of I-A, I-D, I-H and I-K.
const DEPTH: usize = 2;

fn fresh() -> Template {
    World::new(true).template()
}

fn counter(w: &World, id: CounterId) -> u64 {
    let tx = w.issuer().store().read().unwrap();
    reconcile::get(&*tx, id, w.week()).unwrap()
}

fn report(name: &str, stats: common::world::Stats) {
    eprintln!(
        "{name}: {} fault sites, {} crash runs, {} crashes",
        stats.sites, stats.runs, stats.crashes
    );
    assert!(
        stats.sites > 0 && stats.runs > 0,
        "{name}: nothing enumerated"
    );
    assert!(
        stats.crashes >= stats.runs,
        "{name}: a crash run did not crash"
    );
}

/// I-A: request → pay → confirm → sign → re-serve.
fn i_a(w: &mut World) {
    let r = w.request("a", BASE_WEEK, &[]).unwrap();
    assert_eq!(r.result, OK);
    assert_eq!(r.amount_atomic, PRICE);
    assert_eq!(w.sign("a").unwrap().state, AWAITING_PAYMENT);
    w.pay("a", PRICE);
    w.tick();
    assert_eq!(w.sign("a").unwrap().state, AWAITING_CONFIRMATIONS);
    w.mine(9);
    assert_eq!(w.sign("a").unwrap().state, AWAITING_CONFIRMATIONS);
    w.mine(1);
    let s = w.sign("a").unwrap();
    assert_eq!(s.state, SIGNED);
    assert_eq!(w.finalize("a", &s.blind_signatures).len(), 18);
    assert_eq!(w.sign("a").unwrap().blind_signatures, s.blind_signatures);
    assert_eq!(w.status("a").unwrap().state, SIGNED);
    let other = other_blinded(w, "a");
    assert_eq!(w.sign_with("a", other).unwrap().state, OTHER);
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "crash suite: release profile only (design §19.17 point 2)"
)]
fn i_a_request_pay_confirm_sign_reserve() {
    report("I-A", enumerate(&fresh(), i_a, DEPTH));
}

/// I-B: underpay, top up to the same subaddress, confirm, sign.
fn i_b(w: &mut World) {
    assert_eq!(w.request("b", BASE_WEEK, &[]).unwrap().result, OK);
    w.pay("b", PRICE / 2);
    w.tick();
    let s = w.sign("b").unwrap();
    assert_eq!((s.state, s.seen_atomic), (UNDERPAID, PRICE / 2));
    w.mine(10);
    let s = w.sign("b").unwrap();
    assert_eq!((s.state, s.credited_atomic), (UNDERPAID, PRICE / 2));
    w.pay("b", PRICE - PRICE / 2);
    w.tick();
    assert_eq!(w.sign("b").unwrap().state, AWAITING_CONFIRMATIONS);
    w.mine(10);
    let s = w.sign("b").unwrap();
    assert_eq!(s.state, SIGNED);
    w.finalize("b", &s.blind_signatures);
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "crash suite: release profile only (design §19.17 point 2)"
)]
fn i_b_underpay_and_top_up() {
    report("I-B", enumerate(&fresh(), i_b, 0));
}

/// I-C: no payment; a stale view never expires the invoice, a synced one does; a late payment is
/// unattributed revenue; after the purge the invoice is unknown.
fn i_c(w: &mut World) {
    assert_eq!(w.request("c", BASE_WEEK, &[]).unwrap().result, OK);
    w.chain.set_synced(false);
    w.mine(720 + 2_160 + 10 + 1);
    assert_eq!(w.sign("c").unwrap().state, AWAITING_PAYMENT);
    w.chain.set_synced(true);
    w.chain.set_daemon_ahead(5);
    w.tick();
    assert_eq!(
        w.sign("c").unwrap().state,
        AWAITING_PAYMENT,
        "wallet behind the daemon"
    );
    w.chain.set_daemon_ahead(0);
    w.tick();
    assert_eq!(w.sign("c").unwrap().state, EXPIRED);
    assert_eq!(w.status("c").unwrap().state, EXPIRED);
    w.pay("c", PRICE);
    w.mine(10);
    assert_eq!(w.sign("c").unwrap().state, EXPIRED);
    assert_eq!(counter(w, CounterId::UnattributedAtomic), PRICE);
    w.mine(5_040);
    assert_eq!(
        w.sign("c").unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "crash suite: release profile only (design §19.17 point 2)"
)]
fn i_c_expiry_from_a_synced_view_only() {
    report("I-C", enumerate(&fresh(), i_c, 0));
}

/// I-C (underpaid, §19.6 rule 2): an underpaid invoice expires. Its credited transfer was
/// attributed to the invoice when it became final; at the expiry it becomes unattributed revenue,
/// so incoming = credited + overpaid + unattributed still holds after the purge
/// (`World::check`).
fn i_c_underpaid(w: &mut World) {
    assert_eq!(w.request("u", BASE_WEEK, &[]).unwrap().result, OK);
    w.pay("u", PRICE / 2);
    w.mine(10);
    assert_eq!(w.sign("u").unwrap().state, UNDERPAID);
    w.mine(720 + 2_160);
    assert_eq!(w.sign("u").unwrap().state, EXPIRED);
    assert_eq!(counter(w, CounterId::UnattributedAtomic), PRICE / 2);
    w.mine(5_040);
    assert_eq!(
        w.sign("u").unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "crash suite: release profile only (design §19.17 point 2)"
)]
fn i_c_underpaid_invoice_expires_into_unattributed_revenue() {
    report("I-C underpaid", enumerate(&fresh(), i_c_underpaid, 0));
}

/// I-D: a reorg below 10 confirmations before issuance reverts the credit; a reorg after issuance
/// is counted and the tokens are re-served.
fn i_d(w: &mut World) {
    assert_eq!(w.request("d", BASE_WEEK, &[]).unwrap().result, OK);
    w.pay("d", PRICE);
    w.mine(10);
    w.chain.pop(10, true);
    w.tick();
    assert_eq!(w.sign("d").unwrap().state, AWAITING_CONFIRMATIONS);
    w.mine(10);
    let s = w.sign("d").unwrap();
    assert_eq!(s.state, SIGNED);
    w.chain.pop(10, false);
    w.tick();
    assert_eq!(counter(w, CounterId::ReorgAfterIssue), 1);
    assert_eq!(w.sign("d").unwrap().blind_signatures, s.blind_signatures);
    w.finalize("d", &s.blind_signatures);
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "crash suite: release profile only (design §19.17 point 2)"
)]
fn i_d_reorg_before_and_after_issuance() {
    report("I-D", enumerate(&fresh(), i_d, DEPTH));
}

/// I-D (timely re-mine, §19.6 rule 3, §7.4): the transfer is credited a few blocks before
/// `grace_height`; after `grace_height + C` a reorg puts it back in the pool, and it is re-mined
/// above `grace_height` but at most 100 blocks above it. The invoice never expires in between and
/// is signed once the re-mined transfer has 10 confirmations (MS-6).
fn i_d_timely(w: &mut World) {
    let grace = w.chain.blocks() + 720 + 2_160;
    assert_eq!(w.request("t", BASE_WEEK, &[]).unwrap().result, OK);
    w.chain.mine_empty(grace - 5 - w.chain.blocks());
    w.tick();
    w.pay("t", PRICE);
    w.mine(10);
    assert_eq!(w.status("t").unwrap().state, AWAITING_CONFIRMATIONS);
    w.mine(5);
    // Wallet at grace + C; the credited transfer goes back to the pool and stays there.
    w.chain.pop(16, true);
    w.chain.mine_empty(16);
    w.tick();
    assert_eq!(
        w.sign("t").unwrap().state,
        AWAITING_CONFIRMATIONS,
        "expired while its credited txid is in the pool"
    );
    // Re-mined at grace + 10, 6 confirmations.
    w.mine(6);
    assert_eq!(w.sign("t").unwrap().state, AWAITING_CONFIRMATIONS);
    w.mine(4);
    let s = w.sign("t").unwrap();
    assert_eq!(s.state, SIGNED);
    w.finalize("t", &s.blind_signatures);
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "crash suite: release profile only (design §19.17 point 2)"
)]
fn i_d_credited_txid_re_mined_after_grace_stays_timely() {
    report("I-D timely re-mine", enumerate(&fresh(), i_d_timely, 0));
}

/// I-E: an invite is redeemed once for a trial (identical retries re-served, another request
/// REPLAYED); a revoked invite (redeemed by its inviter) fails for the invitee.
fn i_e(w: &mut World) {
    let e = invite_epoch(BASE_WEEK);
    let invite = w.mint(Kind::Invite, e, "e-invite");
    let blinded = w.trial_blinded("e-trial", BASE_WEEK);
    let r = w.redeem(&invite, BASE_WEEK, blinded.clone()).unwrap();
    assert_eq!(r.result, wire::RedeemInviteResult::Ok as i32);
    assert_eq!(r.blind_signatures.len(), 6 * 256);
    let again = w.redeem(&invite, BASE_WEEK, blinded).unwrap();
    assert_eq!(again.blind_signatures, r.blind_signatures);
    let other = w.trial_blinded("e-other", BASE_WEEK);
    assert_eq!(
        w.redeem(&invite, BASE_WEEK, other).unwrap().result,
        wire::RedeemInviteResult::Replayed as i32
    );
    let revoked = w.mint(Kind::Invite, e, "e-revoked");
    let own = w.trial_blinded("e-inviter", BASE_WEEK);
    assert_eq!(
        w.redeem(&revoked, BASE_WEEK, own).unwrap().result,
        wire::RedeemInviteResult::Ok as i32
    );
    let invitee = w.trial_blinded("e-invitee", BASE_WEEK);
    assert_eq!(
        w.redeem(&revoked, BASE_WEEK, invitee).unwrap().result,
        wire::RedeemInviteResult::Replayed as i32
    );
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "crash suite: release profile only (design §19.17 point 2)"
)]
fn i_e_invite_redeem_and_revoke() {
    report("I-E", enumerate(&fresh(), i_e, 0));
}

/// I-F: a pack paid with ten credits minted by the issuer: amount 0, signed, the credits spent.
fn i_f(w: &mut World) {
    let credits = w.wallet.credits.clone();
    let r = w.request("f", BASE_WEEK, &credits).unwrap();
    assert_eq!(
        (r.result, r.amount_atomic, r.subaddress.as_str()),
        (OK, 0, "")
    );
    let s = w.sign("f").unwrap();
    assert_eq!(s.state, SIGNED);
    assert_eq!(
        w.finalize("f", &s.blind_signatures).len(),
        17,
        "no credit on a credits pack"
    );
    assert_eq!(w.sign("f").unwrap().blind_signatures, s.blind_signatures);
    let again = w.request("f2", BASE_WEEK, &credits).unwrap();
    assert_eq!((again.result, again.spent_mask), (CREDITS_SPENT, 0x3FF));
    let claim = w
        .claim("f-claim", &credits, &chain_port::address(9_999))
        .unwrap();
    assert_eq!(
        (claim.result, claim.spent_mask),
        (wire::ClaimPayoutResult::CreditsSpent as i32, 0x3FF)
    );
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "crash suite: release profile only (design §19.17 point 2)"
)]
fn i_f_credits_pack() {
    report("I-F", enumerate(&with_credits("f").template(), i_f, 0));
}

/// I-G: a claim of ten credits is queued once; the same id with another body conflicts; the
/// credits are spent for every other use.
fn i_g(w: &mut World) {
    let credits = w.wallet.credits.clone();
    let address = chain_port::address(9_999);
    let r = w.claim("g", &credits, &address).unwrap();
    assert_eq!(
        (r.result, r.queued_atomic),
        (wire::ClaimPayoutResult::Queued as i32, PRICE)
    );
    assert_eq!(
        w.claim("g", &credits, &address).unwrap().queued_atomic,
        PRICE
    );
    let conflict = w.claim("g", &credits, &chain_port::address(9_998)).unwrap();
    assert_eq!(
        conflict.result,
        wire::ClaimPayoutResult::ClaimConflict as i32
    );
    let spent = w.claim("g2", &credits, &address).unwrap();
    assert_eq!(
        (spent.result, spent.spent_mask),
        (wire::ClaimPayoutResult::CreditsSpent as i32, 0x3FF)
    );
    let request = w.request("g-pack", BASE_WEEK, &credits).unwrap();
    assert_eq!((request.result, request.spent_mask), (CREDITS_SPENT, 0x3FF));
    let now = w.now;
    assert!(w.issuer().status_at(now).unwrap().payout_batch_ready);

    // §9.5 step 1: the weekly export assigns the claim to a batch and writes the batch file,
    // signed by the ops key; a second export rewrites the same bytes (World::check).
    w.export();
    let files = w.batch_files();
    assert_eq!(files.len(), 1);
    let file = files[0].clone();
    assert_eq!(file.entries.len(), 1);
    assert_eq!(
        (
            file.entries[0].claim_id,
            file.entries[0].amount,
            file.total,
            file.entries[0].address_text()
        ),
        (claim_id("g"), PRICE, PRICE, address.as_str())
    );
    w.export();
    assert!(!w.issuer().status_at(now).unwrap().payout_batch_ready);

    // §9.5 step 4: the workstation's acknowledgement marks the batch paid; its files go, the
    // claim keeps no payout address, and an identical claim retry still answers QUEUED.
    w.write_ack(&file);
    w.export();
    assert!(
        w.batch_files().is_empty(),
        "the paid batch's file is deleted"
    );
    assert!(
        std::fs::read_dir(w.export_dir()).unwrap().next().is_none(),
        "the acknowledgement is consumed"
    );
    {
        let tx = w.issuer().store().read().unwrap();
        let row = store::claim(&*tx, &claim_id("g")).unwrap().unwrap();
        assert_eq!(row.state, ClaimState::Paid);
    }
    assert_eq!(counter(w, CounterId::PayoutPaidAtomic), PRICE);
    assert_eq!(
        w.claim("g", &credits, &address).unwrap().queued_atomic,
        PRICE
    );
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "crash suite: release profile only (design §19.17 point 2)"
)]
fn i_g_claim() {
    report("I-G", enumerate(&with_credits("g").template(), i_g, 0));
}

/// What the I-H client holds across the restore.
struct HeldAcrossRestore {
    credits: Vec<Token>,
    signed_b: Vec<u8>,
    signed_c: Vec<u8>,
    invite: Token,
    trial: Vec<u8>,
    trial_signatures: Vec<u8>,
}

/// I-H before the restore: an XMR invoice issued, a credits-paid invoice issued, a trial and an
/// unpaid invoice, all after the snapshot.
fn i_h_before(w: &mut World) -> HeldAcrossRestore {
    let credits: Vec<_> = w.wallet.credits[..10].to_vec();
    w.buy_pack("h-b");
    let signed_b = w.sign("h-b").unwrap().blind_signatures;
    let r = w.request("h-c", BASE_WEEK, &credits).unwrap();
    assert_eq!(r.result, OK);
    let signed_c = w.sign("h-c").unwrap();
    assert_eq!(signed_c.state, SIGNED);
    let invite = w.mint(Kind::Invite, invite_epoch(BASE_WEEK), "h-invite");
    let trial = w.trial_blinded("h-trial", BASE_WEEK);
    let t = w.redeem(&invite, BASE_WEEK, trial.clone()).unwrap();
    assert_eq!(t.result, wire::RedeemInviteResult::Ok as i32);
    assert_eq!(w.request("h-e", BASE_WEEK, &[]).unwrap().result, OK);
    HeldAcrossRestore {
        credits,
        signed_b,
        signed_c: signed_c.blind_signatures,
        invite,
        trial,
        trial_signatures: t.blind_signatures,
    }
}

/// I-H after the restore: different requests are refused, identical retries served, no credit or
/// invite is spent twice and no minor is handed out twice.
///
/// The different request always comes first. An identical retry on a CONFIRMED invoice (or for an
/// unrecorded invite) re-signs the same digest, so it would recreate a decided ISSUE or INVITE
/// outcome the restore lost and hide it (MM3); only a different request shows whether the
/// outcome survived the snapshot restore and the journal replay.
fn i_h_after(w: &mut World, held: &HeldAcrossRestore) {
    let other = other_blinded(w, "h-b");
    assert_eq!(
        w.sign_with("h-b", other).unwrap().state,
        OTHER,
        "MS-1: another request signed after the restore"
    );
    assert_eq!(w.sign("h-b").unwrap().blind_signatures, held.signed_b);
    let other = other_blinded(w, "h-c");
    assert_eq!(
        w.sign_with("h-c", other).unwrap().state,
        OTHER,
        "MS-1: another request signed after the restore"
    );
    assert_eq!(w.sign("h-c").unwrap().blind_signatures, held.signed_c);
    let spent = w.request("h-c2", BASE_WEEK, &held.credits).unwrap();
    assert_eq!((spent.result, spent.spent_mask), (CREDITS_SPENT, 0x3FF));
    let other_trial = w.trial_blinded("h-trial-2", BASE_WEEK);
    assert_eq!(
        w.redeem(&held.invite, BASE_WEEK, other_trial)
            .unwrap()
            .result,
        wire::RedeemInviteResult::Replayed as i32,
        "MS-3: an invite redeemed again after the restore"
    );
    assert_eq!(
        w.redeem(&held.invite, BASE_WEEK, held.trial.clone())
            .unwrap()
            .blind_signatures,
        held.trial_signatures
    );
    assert_eq!(w.request("h-e", BASE_WEEK, &[]).unwrap().result, OK);
    assert_eq!(w.request("h-f", BASE_WEEK, &[]).unwrap().result, OK);
    assert_eq!(w.sign("h-a").unwrap().state, SIGNED);
}

/// I-H: restore from a snapshot plus journal replay, with a pool that must be reset.
fn i_h(w: &mut World) {
    let held = i_h_before(w);
    w.restore();
    i_h_after(w, &held);
}

/// The I-H world: ten credits, pack "h-a" bought, then the snapshot.
fn i_h_world() -> World {
    let mut w = with_credits("h");
    w.buy_pack("h-a");
    w.snapshot();
    w
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "crash suite: release profile only (design §19.17 point 2)"
)]
fn i_h_restore_from_snapshot_with_journal_replay() {
    report("I-H", enumerate(&i_h_world().template(), i_h, DEPTH));
}

/// Runs I-H with the entries `lost` selects missing from the journal at the restore (the decided
/// outcomes a `NoJournal` issuer would not have recorded): how many were removed, and how I-H after
/// the restore (with `World::check`) ended (the panic message).
fn i_h_with_lost_entries(lost: fn(&Entry) -> bool) -> (usize, Result<(), String>) {
    let mut w = i_h_world();
    let applied = w.journal_applied();
    let held = i_h_before(&mut w);
    w.crash();
    let removed = w.lose_journal_entries(applied, lost);
    w.restore();
    let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
        i_h_after(&mut w, &held);
        w.check();
    }))
    .map_err(|e| {
        e.downcast_ref::<String>()
            .cloned()
            .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default()
    });
    (removed, outcome)
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "crash suite: release profile only (design §19.17 point 2)"
)]
fn mm3_control_a_rewritten_journal_passes_i_h() {
    let (removed, outcome) = i_h_with_lost_entries(|_| false);
    assert_eq!(removed, 0);
    outcome.unwrap();
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "crash suite: release profile only (design §19.17 point 2)"
)]
fn mm3_lost_issue_entries_are_caught_by_i_h() {
    let (removed, outcome) = i_h_with_lost_entries(|e| matches!(e, Entry::Issue { .. }));
    assert!(removed > 0);
    let message = outcome.expect_err("MM3 (ISSUE entries not journaled) survived I-H");
    assert!(
        message.contains("MS-1"),
        "caught for another reason: {message}"
    );
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "crash suite: release profile only (design §19.17 point 2)"
)]
fn mm3_lost_invite_entries_are_caught_by_i_h() {
    let (removed, outcome) = i_h_with_lost_entries(|e| matches!(e, Entry::Invite { .. }));
    assert!(removed > 0);
    let message = outcome.expect_err("MM3 (INVITE entries not journaled) survived I-H");
    assert!(
        message.contains("MS-3"),
        "caught for another reason: {message}"
    );
}

// ------------------------------------------------------------------------------------------------
// RefreshCredit (§19.8).
// ------------------------------------------------------------------------------------------------

/// I-F refresh: a credit standing for one received through a drop is exchanged for a fresh one
/// of the same epoch; the identical retry is re-served, another blinded value is REPLAYED; the
/// received credit is spent, and the fresh one pays for a pack with nine others.
fn i_f_refresh(w: &mut World) {
    let received = w.wallet.credits[0].clone();
    let blinded = w.refresh_blinded("r", 227);
    let r = w.refresh(&received, blinded.clone()).unwrap();
    assert_eq!(r.result, REFRESH_OK);
    assert_eq!(r.blind_signature.len(), 256);
    let fresh = w.finalize_refresh("r", 227, &r.blind_signature);
    assert_ne!(fresh.nullifier(), received.nullifier());
    assert_eq!(
        w.refresh(&received, blinded).unwrap().blind_signature,
        r.blind_signature
    );
    let other = w.refresh_blinded("r-other", 227);
    assert_eq!(
        w.refresh(&received, other).unwrap().result,
        REFRESH_REPLAYED
    );
    let mut stale = w.wallet.credits[1..10].to_vec();
    stale.push(received);
    let spent = w.request("rf-stale", BASE_WEEK, &stale).unwrap();
    assert_eq!((spent.result, spent.spent_mask), (CREDITS_SPENT, 1 << 9));
    let mut set = w.wallet.credits[1..10].to_vec();
    set.push(fresh);
    assert_eq!(w.request("rf", BASE_WEEK, &set).unwrap().result, OK);
    let s = w.sign("rf").unwrap();
    assert_eq!(s.state, SIGNED);
    assert_eq!(w.finalize("rf", &s.blind_signatures).len(), 17);
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "crash suite: release profile only (design §19.17 point 2)"
)]
fn i_f_refresh_a_received_credit() {
    report(
        "I-F refresh",
        enumerate(&with_credits("r").template(), i_f_refresh, 0),
    );
}

// ------------------------------------------------------------------------------------------------
// I-K: races then restart, races then restore (§19.5).
// ------------------------------------------------------------------------------------------------

fn i_k_blind_sign(w: &mut World) {
    w.reopen();
    race_retry(RaceKind::BlindSign, w);
}

fn i_k_redeem_invite(w: &mut World) {
    w.reopen();
    race_retry(RaceKind::RedeemInvite, w);
}

fn i_k_claim(w: &mut World) {
    w.reopen();
    race_retry(RaceKind::ClaimPayout, w);
}

fn i_k_credits_pack(w: &mut World) {
    w.reopen();
    race_retry(RaceKind::CreditsPack, w);
}

fn i_k_blind_sign_restore(w: &mut World) {
    w.restore();
    race_retry(RaceKind::BlindSign, w);
}

fn i_k_redeem_invite_restore(w: &mut World) {
    w.restore();
    race_retry(RaceKind::RedeemInvite, w);
}

fn i_k_claim_restore(w: &mut World) {
    w.restore();
    race_retry(RaceKind::ClaimPayout, w);
}

fn i_k_credits_pack_restore(w: &mut World) {
    w.restore();
    race_retry(RaceKind::CreditsPack, w);
}

/// The template of a race: its world after the race (a restore variant snapshots before it).
fn race_template(kind: RaceKind, restore: bool) -> Template {
    race_world(kind, restore).template()
}

/// One I-K case: its name, the kind of race and the body enumerated after it.
type RaceCase = (&'static str, RaceKind, fn(&mut World));

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "crash suite: release profile only (design §19.17 point 2)"
)]
fn i_k_races_then_restart() {
    let cases: [RaceCase; 4] = [
        ("I-K BlindSign", RaceKind::BlindSign, i_k_blind_sign),
        (
            "I-K RedeemInvite",
            RaceKind::RedeemInvite,
            i_k_redeem_invite,
        ),
        ("I-K ClaimPayout", RaceKind::ClaimPayout, i_k_claim),
        (
            "I-K credits RequestInvoice",
            RaceKind::CreditsPack,
            i_k_credits_pack,
        ),
    ];
    for (name, kind, body) in cases {
        report(name, enumerate(&race_template(kind, false), body, DEPTH));
    }
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "crash suite: release profile only (design §19.17 point 2)"
)]
fn i_k_races_then_restore() {
    let cases: [RaceCase; 4] = [
        (
            "I-K BlindSign, restore",
            RaceKind::BlindSign,
            i_k_blind_sign_restore,
        ),
        (
            "I-K RedeemInvite, restore",
            RaceKind::RedeemInvite,
            i_k_redeem_invite_restore,
        ),
        (
            "I-K ClaimPayout, restore",
            RaceKind::ClaimPayout,
            i_k_claim_restore,
        ),
        (
            "I-K credits RequestInvoice, restore",
            RaceKind::CreditsPack,
            i_k_credits_pack_restore,
        ),
    ];
    for (name, kind, body) in cases {
        report(name, enumerate(&race_template(kind, true), body, DEPTH));
    }
}

// ------------------------------------------------------------------------------------------------
// I-L: a clock step back across a swept epoch boundary (§19.10).
// ------------------------------------------------------------------------------------------------

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "crash suite: release profile only (design §19.17 point 2)"
)]
fn i_l_clock_step_back_across_a_swept_epoch() {
    report(
        "I-L invites",
        enumerate(&clock_back_invite_world().template(), i_l_invite, 0),
    );
    report(
        "I-L credits",
        enumerate(&clock_back_credit_world().template(), i_l_credit, 0),
    );
}

// ------------------------------------------------------------------------------------------------
// I-M: a lost create_address answer without a crash (§19.6 rule 4).
// ------------------------------------------------------------------------------------------------

/// I-M: the pool is drained, then a refill's `create_address` takes effect in the wallet but its
/// answer is lost. That run stops; the next one reconciles `highest_minor` with the wallet in the
/// process (`POOL_RECONCILED`) and refills above the lost minor, which is never handed out.
fn i_m(w: &mut World) {
    for i in 0..4 {
        assert_eq!(
            w.request(&format!("m-{i}"), BASE_WEEK, &[]).unwrap().result,
            OK
        );
    }
    let lost = w.chain.subaddress_count();
    w.chain.lose_next_address_answer();
    let first = w.run(|i, now| i.pool_refill_at(now));
    if w.crashes == 0 {
        assert_eq!(first.unwrap_err(), PoolError::Rail(RailError::Transport));
    }
    w.refill();
    if w.crashes == 0 {
        assert!(
            counter(w, CounterId::PoolReconciled) >= 1,
            "POOL_RECONCILED"
        );
    }
    for i in 4..8 {
        assert_eq!(
            w.request(&format!("m-{i}"), BASE_WEEK, &[]).unwrap().result,
            OK
        );
        assert_ne!(w.purchase(&format!("m-{i}")).minor, lost, "the lost minor");
    }
    let tx = w.issuer().store().read().unwrap();
    assert!(store::pool(&*tx).unwrap().iter().all(|(m, _)| *m != lost));
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "crash suite: release profile only (design §19.17 point 2)"
)]
fn i_m_lost_create_address_answer_without_a_crash() {
    report("I-M", enumerate(&fresh(), i_m, 0));
}

// ------------------------------------------------------------------------------------------------
// I-N: the weekly ANCHOR journal entry (Q32, §19.25).
// ------------------------------------------------------------------------------------------------

/// I-N: the first tick of an idle week decides the data-free ANCHOR entry. Its fault sites are the
/// anchor's transaction (before it begins), its append (the entry lost, torn, or durable before
/// the commit), its commit (failed or done), then the tick's rail calls and transaction. The week
/// ends with one anchor, the journal's last entry, applied; a restart and a restore of the snapshot
/// taken before the week replay it and add none; the pack bought before stays re-served byte for
/// byte and refuses another request (MS-1).
fn i_n(w: &mut World) {
    w.advance(WEEK_SECS);
    w.tick();
    w.assert_anchor_last(BASE_WEEK + 1);
    w.reopen();
    w.assert_anchor_last(BASE_WEEK + 1);
    w.restore();
    w.assert_anchor_last(BASE_WEEK + 1);
    let other = other_blinded(w, "n");
    assert_eq!(w.sign_with("n", other).unwrap().state, OTHER);
    assert_eq!(w.sign("n").unwrap().state, SIGNED);
}

/// A pack in week 2960 and the hourly snapshot after it.
fn anchor_template() -> Template {
    let mut w = World::new(true);
    w.buy_pack("n");
    w.snapshot();
    w.template()
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "crash suite: release profile only (design §19.17 point 2)"
)]
fn i_n_anchor_at_a_week_change() {
    report("I-N", enumerate(&anchor_template(), i_n, DEPTH));
}
