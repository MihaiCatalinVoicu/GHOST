//! Scenario bodies shared by the crash suite (`tests/crash.rs`) and the mutant detections
//! (`tests/mutants.rs`), Phase 8 design §13.2 and §13.5:
//!
//! - **I-K** (§19.5): two concurrent requests of one kind (`BlindSign` of one invoice with two
//!   different blinded sets, `RedeemInvite` of one invite with two trials, `ClaimPayout` and a
//!   credits-paid `RequestInvoice` of one credit set under two claims) that both pass their checks
//!   before either commits; then a restart or a restore from a snapshot taken before the race.
//!   The winner's answer is served again byte for byte; the loser's request is never replayed.
//! - **I-L** (§19.10): a clock step back across a swept epoch boundary. The sweep deleted the
//!   nullifiers of the closed epoch and raised the persisted high-water mark; the issuer restarts
//!   with a clock at which the epoch would still be acceptable, and the spent token stays refused.

use ghost_entitlement::batch;
use ghost_entitlement::grid::{invite_epoch, week_start};
use ghost_entitlement::{Kind, Token};
use ghost_issuer::store::{MetaKey, RedbStore, Store, Table};
use ghost_issuer_api::proto as wire;
use tonic::Code;

use super::chain_port;
use super::world::{claim_id, claim_key, seed, Purchase, World, BASE_WEEK, PRICE};

pub const SIGNED: i32 = wire::InvoiceState::Signed as i32;
pub const OTHER: i32 = wire::InvoiceState::OtherRequestIssued as i32;
pub const OK: i32 = wire::RequestInvoiceResult::Ok as i32;
pub const CREDITS_SPENT: i32 = wire::RequestInvoiceResult::CreditsSpent as i32;
pub const INVITE_OK: i32 = wire::RedeemInviteResult::Ok as i32;
pub const INVITE_REPLAYED: i32 = wire::RedeemInviteResult::Replayed as i32;
pub const QUEUED: i32 = wire::ClaimPayoutResult::Queued as i32;
pub const CLAIM_SPENT: i32 = wire::ClaimPayoutResult::CreditsSpent as i32;
/// 12:00 UTC.
pub const NOON: u64 = 43_200;
/// The payout address of the scenarios' claims.
pub const CLAIM_ADDRESS_MINOR: u32 = 9_999;

/// A world whose client holds ten credits minted by ten XMR packs through the issuer.
pub fn with_credits(prefix: &str) -> World {
    let mut w = World::new(true);
    for i in 0..10 {
        w.buy_pack(&format!("{prefix}-warm-{i}"));
    }
    assert_eq!(w.wallet.credits.len(), 10);
    w
}

/// Another blinded set over the layout of purchase `label` (another seed).
pub fn other_blinded(w: &World, label: &str) -> Vec<u8> {
    let p = w.purchase(label);
    batch::blind(&w.schedule, &seed(&format!("{label}/other")), &w.layout(&p)).unwrap()
}

pub fn claim_address() -> String {
    chain_port::address(CLAIM_ADDRESS_MINOR)
}

// ------------------------------------------------------------------------------------------------
// I-K.
// ------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaceKind {
    BlindSign,
    RedeemInvite,
    ClaimPayout,
    CreditsPack,
}

fn race_invite(w: &World) -> Token {
    w.mint(Kind::Invite, invite_epoch(BASE_WEEK), "k-invite")
}

/// The one index of `won` that is true.
fn winner(won: [bool; 2], what: &str) -> usize {
    assert!(won[0] ^ won[1], "I-K: exactly one {what} must win");
    usize::from(won[1])
}

/// The world of an I-K race: its setup, a snapshot when `restore`, then the race, recorded in the
/// world's observations. The world is left crashed (a restart, a template or a restore follows).
pub fn race_world(kind: RaceKind, restore: bool) -> World {
    let mut w = match kind {
        RaceKind::ClaimPayout | RaceKind::CreditsPack => with_credits("k"),
        RaceKind::BlindSign | RaceKind::RedeemInvite => World::new(true),
    };
    if kind == RaceKind::BlindSign {
        assert_eq!(w.request("k", BASE_WEEK, &[]).unwrap().result, OK);
        w.pay("k", PRICE);
        w.mine(10);
    }
    if restore {
        w.snapshot();
    }
    match kind {
        RaceKind::BlindSign => race_blind_sign(&mut w),
        RaceKind::RedeemInvite => race_redeem_invite(&mut w),
        RaceKind::ClaimPayout => race_claim(&mut w),
        RaceKind::CreditsPack => race_credits_pack(&mut w),
    }
    w
}

/// The two blinded sets of the `BlindSign` race.
pub fn race_blinded(w: &World) -> [Vec<u8>; 2] {
    [w.blinded("k"), other_blinded(w, "k")]
}

fn race_blind_sign(w: &mut World) {
    let p = w.purchase("k");
    let request = |blinded: &[u8]| wire::BlindSignRequest {
        version: 1,
        invoice_id: p.id.to_vec(),
        claim_key: claim_key("k").to_vec(),
        blinded: blinded.to_vec(),
    };
    let sets = race_blinded(w);
    let (ra, rb) = (request(&sets[0]), request(&sets[1]));
    let (a, b) = w.race(
        move |i, now| i.blind_sign_at(ra, now),
        move |i, now| i.blind_sign_at(rb, now),
    );
    let answers = [a.unwrap(), b.unwrap()];
    let k = winner(answers.clone().map(|r| r.state == SIGNED), "BlindSign");
    assert_eq!(answers[1 - k].state, OTHER);
    assert!(answers[1 - k].blind_signatures.is_empty());
    w.observed.signed.entry(p.id).or_default().insert((
        batch::request_digest(&p.id, &sets[k]),
        answers[k].blind_signatures.clone(),
    ));
}

fn race_redeem_invite(w: &mut World) {
    let invite = race_invite(w);
    let trials = [
        w.trial_blinded("k-ta", BASE_WEEK),
        w.trial_blinded("k-tb", BASE_WEEK),
    ];
    let request = |t: &[u8]| wire::RedeemInviteRequest {
        version: 1,
        invite_token: invite.as_bytes().to_vec(),
        base_week: BASE_WEEK,
        blinded: t.to_vec(),
    };
    let (ra, rb) = (request(&trials[0]), request(&trials[1]));
    let (a, b) = w.race(
        move |i, now| i.redeem_invite_at(ra, now),
        move |i, now| i.redeem_invite_at(rb, now),
    );
    let answers = [a.unwrap(), b.unwrap()];
    let k = winner(
        answers.clone().map(|r| r.result == INVITE_OK),
        "RedeemInvite",
    );
    assert_eq!(answers[1 - k].result, INVITE_REPLAYED);
    let n = invite.nullifier();
    w.observed
        .trials
        .entry((invite_epoch(BASE_WEEK), n))
        .or_default()
        .insert((
            batch::trial_digest(&n, BASE_WEEK, &trials[k]),
            answers[k].blind_signatures.clone(),
        ));
}

fn race_claim(w: &mut World) {
    let credits: Vec<Vec<u8>> = w
        .wallet
        .credits
        .iter()
        .map(|t| t.as_bytes().to_vec())
        .collect();
    let request = |label: &str| wire::ClaimPayoutRequest {
        version: 1,
        claim_id: claim_id(label).to_vec(),
        credits: credits.clone(),
        payout_address: claim_address(),
    };
    let (ra, rb) = (request("k1"), request("k2"));
    let (a, b) = w.race(
        move |i, now| i.claim_payout_at(ra, now),
        move |i, now| i.claim_payout_at(rb, now),
    );
    let answers = [a.unwrap(), b.unwrap()];
    let k = winner(answers.map(|r| r.result == QUEUED), "ClaimPayout");
    assert_eq!(answers[k].queued_atomic, PRICE);
    assert_eq!(
        (answers[1 - k].result, answers[1 - k].spent_mask),
        (CLAIM_SPENT, 0x3FF)
    );
    w.observed
        .claims
        .insert(claim_id(["k1", "k2"][k]), answers[k].queued_atomic);
    record_spent(w);
}

fn race_credits_pack(w: &mut World) {
    let credits: Vec<Vec<u8>> = w
        .wallet
        .credits
        .iter()
        .map(|t| t.as_bytes().to_vec())
        .collect();
    let request = |label: &str| wire::RequestInvoiceRequest {
        version: 1,
        rail: wire::Rail::Monero as i32,
        product: wire::Product::Pack as i32,
        claim_hash: batch::claim_hash(&claim_key(label)).to_vec(),
        credits: credits.clone(),
        base_week: BASE_WEEK,
    };
    let (ra, rb) = (request("k1"), request("k2"));
    let (a, b) = w.race(
        move |i, now| i.request_invoice_at(ra, now),
        move |i, now| i.request_invoice_at(rb, now),
    );
    let answers = [a.unwrap(), b.unwrap()];
    let k = winner(answers.clone().map(|r| r.result == OK), "RequestInvoice");
    assert_eq!(
        (answers[1 - k].result, answers[1 - k].spent_mask),
        (CREDITS_SPENT, 0x3FF)
    );
    let label = ["k1", "k2"][k];
    w.wallet.purchases.insert(
        label.to_string(),
        Purchase {
            id: answers[k].invoice_id.as_slice().try_into().unwrap(),
            base_week: BASE_WEEK,
            xmr: false,
            minor: 0,
            amount: 0,
            seed: seed(label),
        },
    );
    record_spent(w);
}

fn record_spent(w: &mut World) {
    let spent: Vec<(u64, [u8; 32])> = w
        .wallet
        .credits
        .iter()
        .map(|t| {
            (
                w.schedule.key_by_id(t.key_id()).unwrap().epoch,
                t.nullifier(),
            )
        })
        .collect();
    w.observed.spent.extend(spent);
}

/// I-K after the race and the restart or restore: both requests are retried identically; the
/// winner's answer is served again byte for byte, the loser's request never succeeds.
pub fn race_retry(kind: RaceKind, w: &mut World) {
    match kind {
        RaceKind::BlindSign => {
            let p = w.purchase("k");
            let (digest, sigs) = w.observed.signed[&p.id].iter().next().unwrap().clone();
            for blinded in race_blinded(w) {
                let r = w.sign_with("k", blinded.clone()).unwrap();
                if batch::request_digest(&p.id, &blinded) == digest {
                    assert_eq!(
                        (r.state, r.blind_signatures),
                        (SIGNED, sigs.clone()),
                        "MS-1"
                    );
                } else {
                    assert_eq!(r.state, OTHER, "I-K: the losing BlindSign was replayed");
                }
            }
        }
        RaceKind::RedeemInvite => {
            let invite = race_invite(w);
            let n = invite.nullifier();
            let (digest, sigs) = w.observed.trials[&(invite_epoch(BASE_WEEK), n)]
                .iter()
                .next()
                .unwrap()
                .clone();
            for label in ["k-ta", "k-tb"] {
                let trial = w.trial_blinded(label, BASE_WEEK);
                let r = w.redeem(&invite, BASE_WEEK, trial.clone()).unwrap();
                if batch::trial_digest(&n, BASE_WEEK, &trial) == digest {
                    assert_eq!(
                        (r.result, r.blind_signatures),
                        (INVITE_OK, sigs.clone()),
                        "MS-3"
                    );
                } else {
                    assert_eq!(
                        r.result, INVITE_REPLAYED,
                        "I-K: the losing trial was replayed"
                    );
                }
            }
        }
        RaceKind::ClaimPayout => {
            let credits = w.wallet.credits.clone();
            for label in ["k1", "k2"] {
                let won = w.observed.claims.contains_key(&claim_id(label));
                let r = w.claim(label, &credits, &claim_address()).unwrap();
                if won {
                    assert_eq!((r.result, r.queued_atomic), (QUEUED, PRICE));
                } else {
                    assert_eq!(
                        (r.result, r.spent_mask),
                        (CLAIM_SPENT, 0x3FF),
                        "I-K: the losing claim was replayed"
                    );
                }
            }
        }
        RaceKind::CreditsPack => {
            let credits = w.wallet.credits.clone();
            for label in ["k1", "k2"] {
                let won = w.wallet.purchases.contains_key(label);
                let r = w.request(label, BASE_WEEK, &credits).unwrap();
                if won {
                    assert_eq!(r.result, OK);
                    let s = w.sign(label).unwrap();
                    assert_eq!(s.state, SIGNED);
                    assert_eq!(w.finalize(label, &s.blind_signatures).len(), 17);
                } else {
                    assert_eq!(
                        (r.result, r.spent_mask),
                        (CREDITS_SPENT, 0x3FF),
                        "I-K: the losing pack was replayed"
                    );
                }
            }
        }
    }
}

// ------------------------------------------------------------------------------------------------
// I-L.
// ------------------------------------------------------------------------------------------------

/// Mutant MM18 `ClosedPeriodReopened`: an issuer that does not persist its high-water marks. The
/// world is left crashed.
pub fn forget_closed_marks(w: &mut World) {
    w.crash();
    let store = RedbStore::open(&w.dir.path().join("issuer.redb")).unwrap();
    let mut tx = store.write().unwrap();
    for key in [
        MetaKey::ClosedThroughInviteEpoch,
        MetaKey::ClosedThroughCreditEpoch,
    ] {
        tx.delete(Table::Meta, key.name().as_bytes()).unwrap();
    }
    tx.commit().unwrap();
}

fn refused<T: std::fmt::Debug>(r: Result<T, tonic::Status>, what: &str) {
    match r {
        Err(status) => assert_eq!(status.code(), Code::PermissionDenied, "{what}"),
        Ok(answer) => panic!("§19.10: {what} accepted after the clock stepped back: {answer:?}"),
    }
}

/// I-L (invites): a trial redeemed in week 2964 with an invite of epoch 740.
pub fn clock_back_invite_world() -> World {
    let mut w = World::new(true);
    w.now = week_start(2964) + NOON;
    let invite = w.mint(Kind::Invite, 740, "l-invite");
    let trial = w.trial_blinded("l-t", 2964);
    assert_eq!(w.redeem(&invite, 2964, trial).unwrap().result, INVITE_OK);
    w
}

/// I-L (invites): the sweep of week 2972 closes the invite epochs through 741 and deletes the
/// nullifiers of 740 (their trials are past the re-serve window); the clock steps back to week
/// 2964, where 740 is `e_now − 1`, and the issuer restarts. The spent invite with another trial,
/// and a fresh invite of 740, stay refused.
pub fn clock_back_invite(w: &mut World, forget_marks: bool) {
    let invite = w.mint(Kind::Invite, 740, "l-invite");
    w.now = week_start(2972) + NOON;
    w.tick();
    w.sweep();
    if forget_marks {
        forget_closed_marks(w);
    }
    w.now = week_start(2964) + NOON;
    w.reopen();
    let other = w.trial_blinded("l-t2", 2964);
    refused(
        w.redeem(&invite, 2964, other),
        "a spent invite of a closed epoch",
    );
    let fresh = w.mint(Kind::Invite, 740, "l-fresh");
    let trial = w.trial_blinded("l-t3", 2964);
    refused(w.redeem(&fresh, 2964, trial), "an invite of a closed epoch");
}

pub fn i_l_invite(w: &mut World) {
    clock_back_invite(w, false);
}

/// The credits of the I-L credit scenario: ten of epoch 227, minted outside the issuer.
pub fn clock_back_credits(w: &World) -> Vec<Token> {
    (0..10)
        .map(|i| w.mint(Kind::Credit, 227, &format!("l-c-{i}")))
        .collect()
}

/// I-L (credits): ten credits of epoch 227 claimed in the last credit epoch that accepts them
/// (231).
pub fn clock_back_credit_world() -> World {
    let mut w = World::new(true);
    w.external_credits = true;
    w.now = week_start(231 * 13) + NOON;
    let credits = clock_back_credits(&w);
    assert_eq!(
        w.claim("l1", &credits, &claim_address()).unwrap().result,
        QUEUED
    );
    w
}

/// I-L (credits): the sweep of credit epoch 232 closes 227 and deletes its nullifiers; the clock
/// steps back into 231 and the issuer restarts. The spent credits stay refused for a claim and
/// for a refresh.
pub fn clock_back_credit(w: &mut World, forget_marks: bool) {
    let credits = clock_back_credits(w);
    w.now = week_start(232 * 13) + NOON;
    w.tick();
    w.sweep();
    if forget_marks {
        forget_closed_marks(w);
    }
    w.now = week_start(231 * 13) + NOON;
    w.reopen();
    refused(
        w.claim("l2", &credits, &claim_address()),
        "spent credits of a closed epoch",
    );
    let blinded = w.refresh_blinded("l-r", 227);
    refused(
        w.refresh(&credits[0], blinded),
        "a refresh of a spent credit of a closed epoch",
    );
}

pub fn i_l_credit(w: &mut World) {
    clock_back_credit(w, false);
}
