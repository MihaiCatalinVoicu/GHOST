//! Issuer crash safety (Phase 8 design §13.2, §5.8, §19.5; G-10): scenarios I-A … I-H on the real
//! issuer, redb store and journal. Every fault site of a scenario (FaultyStore: before a write
//! transaction, pre-commit, post-commit; FaultyJournal: entry lost, torn, durable before the
//! commit; FaultyRail: before the call, effect without answer) is crashed once; I-A, I-D and I-H
//! are also crashed twice (a crash during recovery or the first retry). A crash drops every
//! in-memory object and reopens the same files; the client then retries identically. After every
//! run `World::check` asserts MS-1, MS-2, MS-3, index and pool consistency and the reconciliation
//! invariants; each scenario asserts MS-6 (the paid invoice ends with its tokens).
//!
//! Scope of S4: the payout export and acknowledgement of I-G are slice S6 (this suite covers the
//! claim itself). The depth of the double-crash enumeration can be raised with
//! `GHOST_ISSUER_CRASH_DEPTH` (default 2 sites after the first crash).
//!
//! Mutant MM3 `NoJournal` (§13.5) is implemented here, in `tests/` only: the ISSUE or the INVITE
//! entries decided after the snapshot are removed from the journal before the restore, and I-H
//! must fail on each.
//!
//! The suite runs in the release profile (§19.17 point 2; CI job `rust`):
//! `cargo test -p ghost-issuer --release --test crash`. A debug build lists its tests as ignored,
//! which keeps the debug workspace run fast (the suite takes minutes there).

mod common;

use std::panic::AssertUnwindSafe;

use common::chain_port;
use common::world::{enumerate, seed, Template, World, BASE_WEEK, PRICE};
use ghost_entitlement::batch;
use ghost_entitlement::grid::invite_epoch;
use ghost_entitlement::{Kind, Token};
use ghost_issuer::journal::{Entry, FileJournal, Journal};
use ghost_issuer::reconcile::{self, CounterId};
use ghost_issuer::store::{self, MetaKey};
use ghost_issuer_api::proto as wire;

const SIGNED: i32 = wire::InvoiceState::Signed as i32;
const AWAITING_PAYMENT: i32 = wire::InvoiceState::AwaitingPayment as i32;
const AWAITING_CONFIRMATIONS: i32 = wire::InvoiceState::AwaitingConfirmations as i32;
const UNDERPAID: i32 = wire::InvoiceState::Underpaid as i32;
const EXPIRED: i32 = wire::InvoiceState::Expired as i32;
const OTHER: i32 = wire::InvoiceState::OtherRequestIssued as i32;
const OK: i32 = wire::RequestInvoiceResult::Ok as i32;
const CREDITS_SPENT: i32 = wire::RequestInvoiceResult::CreditsSpent as i32;

/// Double-crash depth of I-A, I-D and I-H.
const DEPTH: usize = 2;

fn fresh() -> Template {
    World::new(true).template()
}

/// A world whose client holds ten credits minted by ten XMR packs through the issuer.
fn with_credits(prefix: &str) -> World {
    let mut w = World::new(true);
    for i in 0..10 {
        w.buy_pack(&format!("{prefix}-warm-{i}"));
    }
    assert_eq!(w.wallet.credits.len(), 10);
    w
}

fn other_blinded(w: &World, label: &str) -> Vec<u8> {
    let p = w.purchase(label);
    batch::blind(&w.schedule, &seed(&format!("{label}/other")), &w.layout(&p)).unwrap()
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

/// Rewrites the (closed) journal without the entries after sequence number `after` that `lost`
/// selects: the decided outcomes a `NoJournal` issuer would not have recorded. Returns how many
/// entries were removed.
fn lose_journal_entries(w: &World, after: u64, lost: fn(&Entry) -> bool) -> usize {
    let dir = w.dir.path().join("journal");
    let all = FileJournal::open(&dir).unwrap().entries().unwrap();
    let kept: Vec<Entry> = all
        .iter()
        .filter(|(seq, e)| *seq <= after || !lost(e))
        .map(|(_, e)| e.clone())
        .collect();
    std::fs::remove_dir_all(&dir).unwrap();
    let journal = FileJournal::open(&dir).unwrap();
    for e in &kept {
        journal.append(w.week(), e).unwrap();
    }
    all.len() - kept.len()
}

/// Runs I-H with the entries `lost` selects missing from the journal at the restore: how many were
/// removed, and how I-H after the restore (with `World::check`) ended (the panic message).
fn i_h_with_lost_entries(lost: fn(&Entry) -> bool) -> (usize, Result<(), String>) {
    let mut w = i_h_world();
    let applied = {
        let tx = w.issuer().store().read().unwrap();
        store::meta(&*tx, MetaKey::JournalApplied)
            .unwrap()
            .unwrap_or(0)
    };
    let held = i_h_before(&mut w);
    w.crash();
    let removed = lose_journal_entries(&w, applied, lost);
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
