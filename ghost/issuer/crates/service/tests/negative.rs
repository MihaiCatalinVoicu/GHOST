//! Issuer negative suite (Phase 8 design §13.1, the issuer column; §19.1, §19.8, §19.9, §19.10):
//! reuse, expired, forged, wrong period, wrong kind, wrong key and ES, money, clock regression,
//! retries across boundaries, and the startup refusals of §6.6 that do not need the wallet.

mod common;

use common::chain_port;
use common::fixture;
use common::world::{claim_key, harness_params, seed, World, BASE, BASE_WEEK, PRICE};
use ghost_blind_rsa::BigUint;
use ghost_entitlement::batch;
use ghost_entitlement::grid::{invite_epoch, week_start};
use ghost_entitlement::schedule::SlotEntry;
use ghost_entitlement::{Kind, Schedule, ScheduleError, Token};
use ghost_issuer::custody::{KeyWindow, LoadError};
use ghost_issuer::journal::{FileJournal, JournalError};
use ghost_issuer::reconcile::{self, CounterId};
use ghost_issuer::service::{IssuerParams, OpenMode, StartupError};
use ghost_issuer::signer::{CheckedSigner, ReferenceSigner};
use ghost_issuer::store::{self, InvoiceState, MetaKey};
use ghost_issuer_api::proto as wire;
use tonic::Code;

const DAY: u64 = 86_400;
const NOON: u64 = 43_200;
const INVITE_OK: i32 = wire::RedeemInviteResult::Ok as i32;
const REPLAYED: i32 = wire::RedeemInviteResult::Replayed as i32;
const OK: i32 = wire::RequestInvoiceResult::Ok as i32;
const QUEUED: i32 = wire::ClaimPayoutResult::Queued as i32;

fn rq(label: &str, base_week: u64, credits: &[Token]) -> wire::RequestInvoiceRequest {
    wire::RequestInvoiceRequest {
        version: 1,
        rail: wire::Rail::Monero as i32,
        product: wire::Product::Pack as i32,
        claim_hash: batch::claim_hash(&claim_key(label)).to_vec(),
        credits: credits.iter().map(|t| t.as_bytes().to_vec()).collect(),
        base_week,
    }
}

fn code<T: std::fmt::Debug>(r: Result<T, tonic::Status>) -> Code {
    r.unwrap_err().code()
}

fn mint_many(w: &World, kind: Kind, epoch: u64, n: usize, tag: &str) -> Vec<Token> {
    (0..n)
        .map(|i| w.mint(kind, epoch, &format!("{tag}-{i}")))
        .collect()
}

fn address() -> String {
    chain_port::address(9_999)
}

fn at_week(w: &mut World, week: u64) {
    w.now = week_start(week) + NOON;
}

/// A world with one CONFIRMED XMR invoice "p" (paid, 10 confirmations, not signed).
fn confirmed(small: bool) -> World {
    let mut w = World::new(small);
    assert_eq!(w.request("p", BASE_WEEK, &[]).unwrap().result, OK);
    w.pay("p", PRICE);
    w.mine(10);
    w
}

fn resigned(
    w: &World,
    edit: impl FnOnce(&mut ghost_entitlement::schedule::ScheduleContent),
) -> Schedule {
    let mut content = w.schedule.content().clone();
    edit(&mut content);
    Schedule::verify_with_key(
        &fixture::sign_content(&content),
        &fixture::schedule_public_key(),
    )
    .unwrap()
}

// ------------------------------------------------------------------------------------------------
// Reuse.
// ------------------------------------------------------------------------------------------------

#[test]
fn reuse_an_invite_with_another_request_is_replayed() {
    let mut w = World::new(true);
    let invite = w.mint(Kind::Invite, invite_epoch(BASE_WEEK), "invite");
    let first = w.trial_blinded("first", BASE_WEEK);
    assert_eq!(
        w.redeem(&invite, BASE_WEEK, first).unwrap().result,
        INVITE_OK
    );
    let other = w.trial_blinded("other", BASE_WEEK);
    assert_eq!(
        w.redeem(&invite, BASE_WEEK, other).unwrap().result,
        REPLAYED
    );
    w.check();
}

#[test]
fn reuse_a_credit_discount_then_payout_names_exactly_the_spent_credits() {
    let mut w = World::new(true);
    w.external_credits = true;
    let credits = mint_many(&w, Kind::Credit, 227, 11, "c");
    assert_eq!(
        w.request("d", BASE_WEEK, &credits[..10]).unwrap().result,
        OK
    );
    let r = w.claim("q", &credits[1..11], &address()).unwrap();
    assert_eq!(
        (r.result, r.spent_mask),
        (wire::ClaimPayoutResult::CreditsSpent as i32, 0x1FF)
    );
    // Nothing was consumed: the free credit still pays.
    let mut set = vec![credits[10].clone()];
    set.extend(mint_many(&w, Kind::Credit, 227, 9, "f"));
    assert_eq!(w.claim("q2", &set, &address()).unwrap().result, QUEUED);
    w.check();
}

#[test]
fn reuse_a_credit_payout_then_discount_is_credits_spent() {
    let mut w = World::new(true);
    w.external_credits = true;
    let credits = mint_many(&w, Kind::Credit, 227, 10, "p");
    assert_eq!(w.claim("q", &credits, &address()).unwrap().result, QUEUED);
    let r = w.request("d", BASE_WEEK, &credits).unwrap();
    assert_eq!(
        (r.result, r.spent_mask),
        (wire::RequestInvoiceResult::CreditsSpent as i32, 0x3FF)
    );
    w.check();
}

#[test]
fn reuse_a_claim_id_with_another_body_conflicts() {
    let mut w = World::new(true);
    let credits = mint_many(&w, Kind::Credit, 227, 10, "c");
    assert_eq!(w.claim("q", &credits, &address()).unwrap().result, QUEUED);
    let conflict = wire::ClaimPayoutResult::ClaimConflict as i32;
    assert_eq!(
        w.claim("q", &credits, &chain_port::address(9_998))
            .unwrap()
            .result,
        conflict
    );
    assert_eq!(
        w.claim("q", &credits[..9], &address()).unwrap().result,
        conflict
    );
}

#[test]
fn reuse_blind_sign_after_issue_serves_only_the_identical_request() {
    let mut w = confirmed(true);
    let s = w.sign("p").unwrap();
    assert_eq!(s.state, wire::InvoiceState::Signed as i32);
    assert_eq!(w.sign("p").unwrap().blind_signatures, s.blind_signatures);
    let p = w.purchase("p");
    let other = batch::blind(&w.schedule, &seed("p/other"), &w.layout(&p)).unwrap();
    let r = w.sign_with("p", other).unwrap();
    assert_eq!(r.state, wire::InvoiceState::OtherRequestIssued as i32);
    assert!(r.blind_signatures.is_empty());
    w.check();
}

// ------------------------------------------------------------------------------------------------
// Expired.
// ------------------------------------------------------------------------------------------------

#[test]
fn expired_invite_epochs_are_refused_the_previous_one_accepted() {
    let mut w = World::new(true);
    at_week(&mut w, 2964); // invite epoch 741
    let current = w.mint(Kind::Invite, 741, "e");
    let previous = w.mint(Kind::Invite, 740, "e-1");
    let old = w.mint(Kind::Invite, 739, "e-2");
    for (token, label) in [(&current, "a"), (&previous, "b")] {
        let blinded = w.trial_blinded(label, 2964);
        assert_eq!(w.redeem(token, 2964, blinded).unwrap().result, INVITE_OK);
    }
    let blinded = w.trial_blinded("c", 2964);
    assert_eq!(code(w.redeem(&old, 2964, blinded)), Code::PermissionDenied);
}

#[test]
fn expired_credit_epochs_c_minus_4_accepted_c_minus_5_refused() {
    let mut w = World::new(true);
    w.now = week_start(231 * 13) + NOON;
    let credits = mint_many(&w, Kind::Credit, 227, 10, "c");
    assert_eq!(w.claim("q", &credits, &address()).unwrap().result, QUEUED);
    w.now = week_start(232 * 13) + NOON;
    let later = mint_many(&w, Kind::Credit, 227, 10, "d");
    assert_eq!(
        code(w.claim("q2", &later, &address())),
        Code::PermissionDenied
    );
}

#[test]
fn expired_invoice_signs_nothing_and_is_unknown_after_the_purge() {
    let mut w = World::new(true);
    assert_eq!(w.request("x", BASE_WEEK, &[]).unwrap().result, OK);
    w.mine(720 + 2_160 + 10);
    let s = w.sign("x").unwrap();
    assert_eq!(s.state, wire::InvoiceState::Expired as i32);
    assert!(s.blind_signatures.is_empty());
    {
        let tx = w.issuer().store().read().unwrap();
        let row = store::invoice(&*tx, &w.purchase("x").id).unwrap().unwrap();
        assert_eq!(row.state, InvoiceState::Expired);
        assert_eq!(row.issued_digest, None);
    }
    w.mine(5_040);
    assert_eq!(code(w.sign("x")), Code::PermissionDenied);
    assert_eq!(code(w.status("x")), Code::PermissionDenied);
}

// ------------------------------------------------------------------------------------------------
// Forged.
// ------------------------------------------------------------------------------------------------

#[test]
fn forged_invites_every_byte_flipped_and_bad_authenticators() {
    let mut w = World::new(true);
    let e = invite_epoch(BASE_WEEK);
    let invite = w.mint(Kind::Invite, e, "invite");
    let blinded = w.trial_blinded("t", BASE_WEEK);
    let req = |bytes: Vec<u8>| wire::RedeemInviteRequest {
        version: 1,
        invite_token: bytes,
        base_week: BASE_WEEK,
        blinded: blinded.clone(),
    };
    for i in 0..invite.as_bytes().len() {
        let mut bytes = invite.as_bytes().to_vec();
        bytes[i] ^= 0x01;
        let r = w.issuer().redeem_invite_at(req(bytes), w.now);
        assert_eq!(code(r), Code::PermissionDenied, "byte {i}");
    }
    let n = w
        .schedule
        .key(Kind::Invite, e)
        .unwrap()
        .public_key
        .n()
        .clone();
    let pad = |v: &BigUint| {
        let b = v.to_bytes_be();
        let mut out = vec![0u8; 256 - b.len()];
        out.extend_from_slice(&b);
        out
    };
    for auth in [
        vec![0u8; 256],
        pad(&BigUint::from(1u32)),
        pad(&(n.clone() - BigUint::from(1u32))),
        pad(&n),
        vec![0xFF; 256],
    ] {
        let mut bytes = invite.as_bytes()[..98].to_vec();
        bytes.extend_from_slice(&auth);
        assert_eq!(
            code(w.issuer().redeem_invite_at(req(bytes), w.now)),
            Code::PermissionDenied
        );
    }
    for token_type in [0x0001u16, 0x0003] {
        let mut bytes = invite.as_bytes().to_vec();
        bytes[..2].copy_from_slice(&token_type.to_be_bytes());
        assert_eq!(
            code(w.issuer().redeem_invite_at(req(bytes), w.now)),
            Code::PermissionDenied
        );
    }
    let mut short = invite.as_bytes().to_vec();
    short.pop();
    assert_eq!(
        code(w.issuer().redeem_invite_at(req(short), w.now)),
        Code::InvalidArgument
    );
    let mut long = invite.as_bytes().to_vec();
    long.push(0);
    assert_eq!(
        code(w.issuer().redeem_invite_at(req(long), w.now)),
        Code::InvalidArgument
    );
    // The genuine token still works: nothing above was recorded.
    assert_eq!(
        w.redeem(&invite, BASE_WEEK, blinded.clone())
            .unwrap()
            .result,
        INVITE_OK
    );
}

/// A forged credit among ten valid ones, in `RequestInvoice` and in `ClaimPayout` (§13.1, the
/// invite cases): every byte flipped (354 cases), authenticators 0, 1, n − 1, n and all ones,
/// `token_type` 0x0001 and 0x0003 → `PERMISSION_DENIED` (an invalid credit, §5.6 step 5 and
/// step 4); truncated or extended → `INVALID_ARGUMENT` (a size, step 1). Nothing is recorded.
#[test]
fn forged_credits_every_byte_flipped_and_bad_authenticators() {
    let mut w = World::with_params(
        true,
        IssuerParams {
            rate_burst: 100_000,
            ..harness_params()
        },
    );
    w.external_credits = true;
    let credits = mint_many(&w, Kind::Credit, 227, 10, "c");
    let genuine = credits[3].as_bytes().to_vec();
    let mut forged: Vec<(String, Vec<u8>)> = Vec::new();
    for i in 0..genuine.len() {
        let mut bytes = genuine.clone();
        bytes[i] ^= 0x01;
        forged.push((format!("byte {i} flipped"), bytes));
    }
    let n = w
        .schedule
        .key(Kind::Credit, 227)
        .unwrap()
        .public_key
        .n()
        .clone();
    let pad = |v: &BigUint| {
        let b = v.to_bytes_be();
        let mut out = vec![0u8; 256 - b.len()];
        out.extend_from_slice(&b);
        out
    };
    for (what, auth) in [
        ("authenticator 0", vec![0u8; 256]),
        ("authenticator 1", pad(&BigUint::from(1u32))),
        (
            "authenticator n - 1",
            pad(&(n.clone() - BigUint::from(1u32))),
        ),
        ("authenticator n", pad(&n)),
        ("authenticator all ones", vec![0xFF; 256]),
    ] {
        forged.push((what.into(), [&genuine[..98], &auth[..]].concat()));
    }
    for token_type in [0x0001u16, 0x0003] {
        let mut bytes = genuine.clone();
        bytes[..2].copy_from_slice(&token_type.to_be_bytes());
        forged.push((format!("token_type {token_type:#06x}"), bytes));
    }
    let set_with = |bytes: &[u8]| -> Vec<Vec<u8>> {
        let mut set: Vec<Vec<u8>> = credits.iter().map(|t| t.as_bytes().to_vec()).collect();
        set[3] = bytes.to_vec();
        set
    };
    let request = |set: Vec<Vec<u8>>| wire::RequestInvoiceRequest {
        credits: set,
        ..rq("r", BASE_WEEK, &[])
    };
    let claim = |set: Vec<Vec<u8>>| wire::ClaimPayoutRequest {
        version: 1,
        claim_id: vec![7; 16],
        credits: set,
        payout_address: address(),
    };
    let now = w.now;
    for (what, bytes) in &forged {
        let r = w.issuer().request_invoice_at(request(set_with(bytes)), now);
        assert_eq!(code(r), Code::PermissionDenied, "RequestInvoice: {what}");
        let r = w.issuer().claim_payout_at(claim(set_with(bytes)), now);
        assert_eq!(code(r), Code::PermissionDenied, "ClaimPayout: {what}");
    }
    for (what, bytes) in [
        ("truncated", genuine[..353].to_vec()),
        ("extended", [&genuine[..], &[0u8][..]].concat()),
    ] {
        let r = w
            .issuer()
            .request_invoice_at(request(set_with(&bytes)), now);
        assert_eq!(code(r), Code::InvalidArgument, "RequestInvoice: {what}");
        let r = w.issuer().claim_payout_at(claim(set_with(&bytes)), now);
        assert_eq!(code(r), Code::InvalidArgument, "ClaimPayout: {what}");
    }
    // Nothing above was recorded: the genuine credits still pay.
    assert_eq!(w.request("r", BASE_WEEK, &credits).unwrap().result, OK);
    w.check();
}

#[test]
fn forged_claim_key_and_unknown_invoice_get_the_same_answer() {
    let w = confirmed(true);
    let p = w.purchase("p");
    let blinded = w.blinded("p");
    let wrong_key = wire::BlindSignRequest {
        version: 1,
        invoice_id: p.id.to_vec(),
        claim_key: claim_key("someone else").to_vec(),
        blinded: blinded.clone(),
    };
    let unknown = wire::BlindSignRequest {
        invoice_id: vec![0xAB; 16],
        claim_key: claim_key("p").to_vec(),
        ..wrong_key.clone()
    };
    let a = w.issuer().blind_sign_at(wrong_key, w.now).unwrap_err();
    let b = w.issuer().blind_sign_at(unknown, w.now).unwrap_err();
    assert_eq!((a.code(), a.message()), (b.code(), b.message()));
    assert_eq!(a.code(), Code::PermissionDenied);
    let status = wire::InvoiceStatusRequest {
        version: 1,
        invoice_id: p.id.to_vec(),
        claim_key: claim_key("someone else").to_vec(),
    };
    assert_eq!(
        code(w.issuer().invoice_status_at(status, w.now)),
        Code::PermissionDenied
    );
}

#[test]
fn forged_blinded_values_zero_n_and_above_n_are_refused() {
    let mut w = confirmed(true);
    let p = w.purchase("p");
    let blinded = w.blinded("p");
    let n = w
        .schedule
        .key(Kind::Access, BASE_WEEK)
        .unwrap()
        .public_key
        .n()
        .to_bytes_be();
    assert_eq!(n.len(), 256);
    let with_block = |block: &[u8]| {
        let mut b = blinded.clone();
        b[..256].copy_from_slice(block);
        b
    };
    for bad in [
        with_block(&[0u8; 256]),
        with_block(&n),
        with_block(&[0xFF; 256]),
        blinded[256..].to_vec(),
        [blinded.as_slice(), &blinded[..256]].concat(),
        blinded[..blinded.len() - 1].to_vec(),
    ] {
        let req = wire::BlindSignRequest {
            version: 1,
            invoice_id: p.id.to_vec(),
            claim_key: claim_key("p").to_vec(),
            blinded: bad,
        };
        assert_eq!(
            code(w.issuer().blind_sign_at(req, w.now)),
            Code::InvalidArgument
        );
    }
    // Nothing was recorded: the honest request is signed.
    assert_eq!(
        w.sign("p").unwrap().state,
        wire::InvoiceState::Signed as i32
    );
    let invite = w.mint(Kind::Invite, invite_epoch(BASE_WEEK), "i");
    let mut trial = w.trial_blinded("t", BASE_WEEK);
    let good = trial.clone();
    trial[..256].copy_from_slice(&[0u8; 256]);
    assert_eq!(
        code(w.redeem(&invite, BASE_WEEK, trial)),
        Code::InvalidArgument
    );
    assert_eq!(
        w.redeem(&invite, BASE_WEEK, good).unwrap().result,
        INVITE_OK
    );
}

// ------------------------------------------------------------------------------------------------
// Wrong period.
// ------------------------------------------------------------------------------------------------

#[test]
fn wrong_period_records_nothing() {
    let mut w = World::new(true);
    let wrong = w.request("x", BASE_WEEK + 1, &[]).unwrap();
    assert_eq!(wrong.result, wire::RequestInvoiceResult::WrongPeriod as i32);
    assert!(wrong.invoice_id.is_empty());
    // The same claim hash with another base week would be CLAIM_CONFLICT if anything was recorded.
    assert_eq!(w.request("x", BASE_WEEK, &[]).unwrap().result, OK);
    let invite = w.mint(Kind::Invite, invite_epoch(BASE_WEEK), "i");
    let trial = w.trial_blinded("t", BASE_WEEK + 1);
    assert_eq!(
        w.redeem(&invite, BASE_WEEK + 1, trial).unwrap().result,
        wire::RedeemInviteResult::WrongPeriod as i32
    );
    let trial = w.trial_blinded("t", BASE_WEEK);
    assert_eq!(
        w.redeem(&invite, BASE_WEEK, trial).unwrap().result,
        INVITE_OK
    );
}

#[test]
fn wrong_period_tolerance_is_four_hours_either_side() {
    let mut w = World::new(true);
    let boundary = week_start(BASE_WEEK + 1);
    let cases = [
        (boundary + 4 * 3_600 - 1, BASE_WEEK, true),
        (boundary + 4 * 3_600, BASE_WEEK, false),
        (boundary - 4 * 3_600, BASE_WEEK + 1, true),
        (boundary - 4 * 3_600 - 1, BASE_WEEK + 1, false),
        (boundary - 1, BASE_WEEK + 1, true),
        (boundary, BASE_WEEK, true),
    ];
    for (i, (now, base, accepted)) in cases.into_iter().enumerate() {
        w.now = now;
        w.tick();
        let r = w.request(&format!("edge-{i}"), base, &[]).unwrap();
        let expected = if accepted {
            OK
        } else {
            wire::RequestInvoiceResult::WrongPeriod as i32
        };
        assert_eq!(r.result, expected, "case {i}");
    }
}

#[test]
fn wrong_period_an_idempotent_retry_succeeds_after_the_week_changed() {
    let mut w = World::new(true);
    let first = w.request("x", BASE_WEEK, &[]).unwrap();
    w.advance(8 * DAY);
    let again = w.request("x", BASE_WEEK, &[]).unwrap();
    assert_eq!(again, first);
}

// ------------------------------------------------------------------------------------------------
// Wrong kind.
// ------------------------------------------------------------------------------------------------

#[test]
fn wrong_kind_tokens_are_refused() {
    let mut w = World::new(true);
    let access = w.mint(Kind::Access, BASE_WEEK, "a");
    let trial = w.trial_blinded("t", BASE_WEEK);
    assert_eq!(
        code(w.redeem(&access, BASE_WEEK, trial.clone())),
        Code::PermissionDenied
    );
    let credit = w.mint(Kind::Credit, 227, "c");
    assert_eq!(
        code(w.redeem(&credit, BASE_WEEK, trial)),
        Code::PermissionDenied
    );
    let mut credits = mint_many(&w, Kind::Credit, 227, 9, "c");
    credits.push(access);
    assert_eq!(
        code(w.claim("q", &credits, &address())),
        Code::PermissionDenied
    );
    let invites = mint_many(&w, Kind::Invite, invite_epoch(BASE_WEEK), 10, "i");
    assert_eq!(
        code(w.request("r", BASE_WEEK, &invites)),
        Code::PermissionDenied
    );
    assert_eq!(
        code(w.claim("q2", &invites, &address())),
        Code::PermissionDenied
    );
}

// ------------------------------------------------------------------------------------------------
// Money.
// ------------------------------------------------------------------------------------------------

#[test]
fn money_unpaid_and_underpaid_never_sign() {
    let mut w = World::new(true);
    assert_eq!(w.request("u", BASE_WEEK, &[]).unwrap().result, OK);
    let s = w.sign("u").unwrap();
    assert_eq!(s.state, wire::InvoiceState::AwaitingPayment as i32);
    assert!(s.blind_signatures.is_empty());
    w.pay("u", PRICE - 1);
    w.mine(10);
    let s = w.sign("u").unwrap();
    assert_eq!(
        (s.state, s.credited_atomic),
        (wire::InvoiceState::Underpaid as i32, PRICE - 1)
    );
    // Overpaid in the pool, underpaid on the chain: still not paid.
    w.pay("u", 5);
    w.tick();
    assert_eq!(
        w.sign("u").unwrap().state,
        wire::InvoiceState::AwaitingConfirmations as i32
    );
    let tx = w.issuer().store().read().unwrap();
    let row = store::invoice(&*tx, &w.purchase("u").id).unwrap().unwrap();
    assert_eq!(row.state, InvoiceState::Seen);
    assert_eq!(
        reconcile::get(&*tx, CounterId::SignedAccess, BASE_WEEK).unwrap(),
        0
    );
}

#[test]
fn money_lock_time_and_double_spend_never_credit() {
    let mut w = World::new(true);
    assert_eq!(w.request("l", BASE_WEEK, &[]).unwrap().result, OK);
    let minor = w.purchase("l").minor;
    w.chain.pay_with(minor, PRICE, 1_234, false);
    w.chain.pay_with(minor, PRICE, 0, true);
    w.mine(10);
    let s = w.sign("l").unwrap();
    assert_eq!((s.credited_atomic, s.seen_atomic), (0, 0));
    assert_eq!(s.state, wire::InvoiceState::AwaitingPayment as i32);
}

#[test]
fn money_credit_sets_must_be_the_smallest_covering_set() {
    let mut w = World::new(true);
    let credits = mint_many(&w, Kind::Credit, 227, 21, "c");
    assert_eq!(
        code(w.request("nine", BASE_WEEK, &credits[..9])),
        Code::PermissionDenied
    );
    assert_eq!(
        code(w.request("eleven", BASE_WEEK, &credits[..11])),
        Code::PermissionDenied
    );
    let mut dup = credits[..9].to_vec();
    dup.push(credits[0].clone());
    assert_eq!(
        code(w.request("dup", BASE_WEEK, &dup)),
        Code::PermissionDenied
    );
    assert_eq!(
        code(w.request("many", BASE_WEEK, &credits)),
        Code::InvalidArgument
    );
    let r = w.request("ten", BASE_WEEK, &credits[..10]).unwrap();
    assert_eq!((r.result, r.amount_atomic), (OK, 0));
    // No credit position on a credits-paid pack.
    let s = w.sign("ten").unwrap();
    assert_eq!(w.finalize("ten", &s.blind_signatures).len(), 17);
}

#[test]
fn money_credits_keep_the_price_of_their_own_epoch() {
    // Price epoch 229 costs 250 000 000 000; credits of epoch 227 are worth 20 000 000 000 each.
    let mut w = World::new(true);
    at_week(&mut w, 2977);
    let credits = mint_many(&w, Kind::Credit, 227, 14, "c");
    assert_eq!(
        code(w.request("twelve", 2977, &credits[..12])),
        Code::PermissionDenied
    );
    assert_eq!(
        code(w.request("fourteen", 2977, &credits)),
        Code::PermissionDenied
    );
    assert_eq!(
        w.request("thirteen", 2977, &credits[..13]).unwrap().result,
        OK
    );
    let mixed = [
        mint_many(&w, Kind::Credit, 227, 5, "a"),
        mint_many(&w, Kind::Credit, 229, 5, "b"),
    ]
    .concat();
    let r = w.claim("q", &mixed, &address()).unwrap();
    assert_eq!(r.queued_atomic, 5 * 20_000_000_000 + 5 * 25_000_000_000);
}

#[test]
fn money_claim_bounds_and_address_checks() {
    let mut w = World::new(true);
    let credits = mint_many(&w, Kind::Credit, 227, 51, "c");
    assert_eq!(
        code(w.claim("nine", &credits[..9], &address())),
        Code::PermissionDenied
    );
    assert_eq!(
        code(w.claim("many", &credits, &address())),
        Code::PermissionDenied
    );
    let rejected = wire::ClaimPayoutResult::AddressRejected as i32;
    let mut flipped = address().into_bytes();
    let last = flipped.len() - 1;
    flipped[last] = if flipped[last] == b'2' { b'3' } else { b'2' };
    let stagenet = "73LhUiix4DVFMcKhsPRG51QmCsv8dYYbL6GcQoLwEEFvPvkVvc7BhebfA4pnEFF9Lq66hwvLqBvpHjTcqvpJMHmmNjPPBqa";
    for bad in [
        String::from_utf8(flipped).unwrap(),
        stagenet.to_string(),
        "4".repeat(106),
        String::new(),
    ] {
        // The address is checked before the credits: invalid credits do not change the answer.
        assert_eq!(
            w.claim("bad", &credits[..3], &bad).unwrap().result,
            rejected
        );
    }
    assert_eq!(
        w.claim("ok", &credits[..50], &address()).unwrap().result,
        QUEUED
    );
}

#[test]
fn unavailable_without_value_preconditions() {
    // The open-invoice cap.
    let mut w = World::with_params(
        true,
        IssuerParams {
            max_open_invoices: 2,
            ..harness_params()
        },
    );
    assert_eq!(w.request("a", BASE_WEEK, &[]).unwrap().result, OK);
    assert_eq!(w.request("b", BASE_WEEK, &[]).unwrap().result, OK);
    assert_eq!(code(w.request("c", BASE_WEEK, &[])), Code::Unavailable);

    // An empty pool.
    let mut w = World::with_params(
        true,
        IssuerParams {
            pool_target: 1,
            ..harness_params()
        },
    );
    assert_eq!(w.request("a", BASE_WEEK, &[]).unwrap().result, OK);
    assert_eq!(code(w.request("b", BASE_WEEK, &[])), Code::Unavailable);
    w.refill();
    assert_eq!(w.request("b", BASE_WEEK, &[]).unwrap().result, OK);

    // A stale, an unsynced and a lagging scanner tick; no tick in this process.
    let mut w = World::new(true);
    w.advance(120);
    assert_eq!(code(w.request("a", BASE_WEEK, &[])), Code::Unavailable);
    w.tick();
    assert_eq!(w.request("a", BASE_WEEK, &[]).unwrap().result, OK);
    w.chain.set_synced(false);
    w.tick();
    assert_eq!(code(w.request("b", BASE_WEEK, &[])), Code::Unavailable);
    w.chain.set_synced(true);
    w.chain.set_daemon_ahead(2);
    w.tick();
    assert_eq!(code(w.request("b", BASE_WEEK, &[])), Code::Unavailable);
    w.chain.set_daemon_ahead(0);
    w.crash();
    w.open(OpenMode::Normal);
    w.refill();
    assert_eq!(code(w.request("b", BASE_WEEK, &[])), Code::Unavailable);
    w.tick();
    assert_eq!(w.request("b", BASE_WEEK, &[]).unwrap().result, OK);
}

#[test]
fn unavailable_when_a_layout_key_is_missing() {
    let mut w = confirmed(true);
    let mut window = KeyWindow::new();
    for ((kind, epoch), signer) in fixture::signers(&w.schedule) {
        if (kind, epoch) != (Kind::Access, BASE_WEEK + 4) {
            window.insert(signer);
        }
    }
    w.keys = window;
    w.reopen();
    assert_eq!(code(w.request("new", BASE_WEEK, &[])), Code::Unavailable);
    let credits = mint_many(&w, Kind::Credit, 227, 10, "c");
    assert_eq!(
        code(w.request("credits", BASE_WEEK, &credits)),
        Code::Unavailable
    );
    // A paid invoice whose key is missing fails closed and stays CONFIRMED.
    assert_eq!(code(w.sign("p")), Code::Unavailable);
    assert_eq!(
        w.status("p").unwrap().state,
        wire::InvoiceState::AwaitingConfirmations as i32
    );
    let now = w.now;
    assert!(w.issuer().status_at(now).unwrap().keys_missing >= 3);
}

#[test]
fn rate_limit_is_a_global_token_bucket() {
    let mut w = World::new(true);
    for i in 0..40 {
        // Uncovered base weeks: UNAVAILABLE, but each call takes a token.
        let r = w
            .issuer()
            .request_invoice_at(rq(&format!("r{i}"), 3_500, &[]), w.now);
        assert_eq!(code(r), Code::Unavailable);
    }
    let r = w.issuer().request_invoice_at(rq("over", 3_500, &[]), w.now);
    assert_eq!(code(r), Code::ResourceExhausted);
    w.advance(1);
    for i in 0..2 {
        let r = w
            .issuer()
            .request_invoice_at(rq(&format!("s{i}"), 3_500, &[]), w.now);
        assert_eq!(code(r), Code::Unavailable);
    }
    let r = w
        .issuer()
        .request_invoice_at(rq("over2", 3_500, &[]), w.now);
    assert_eq!(code(r), Code::ResourceExhausted);
}

#[test]
fn malformed_requests_are_invalid_argument() {
    let mut w = World::new(true);
    let now = w.now;
    let i = w.issuer();
    let base = rq("m", BASE_WEEK, &[]);
    for bad in [
        wire::RequestInvoiceRequest {
            version: 2,
            ..base.clone()
        },
        wire::RequestInvoiceRequest {
            rail: wire::Rail::Lightning as i32,
            ..base.clone()
        },
        wire::RequestInvoiceRequest {
            rail: 7,
            ..base.clone()
        },
        wire::RequestInvoiceRequest {
            product: 0,
            ..base.clone()
        },
        wire::RequestInvoiceRequest {
            claim_hash: vec![0; 31],
            ..base.clone()
        },
        wire::RequestInvoiceRequest {
            credits: vec![vec![0; 353]],
            ..base.clone()
        },
    ] {
        assert_eq!(code(i.request_invoice_at(bad, now)), Code::InvalidArgument);
    }
    let sign = wire::BlindSignRequest {
        version: 1,
        invoice_id: vec![0; 16],
        claim_key: vec![0; 32],
        blinded: vec![1; 256],
    };
    for bad in [
        wire::BlindSignRequest {
            version: 0,
            ..sign.clone()
        },
        wire::BlindSignRequest {
            invoice_id: vec![0; 15],
            ..sign.clone()
        },
        wire::BlindSignRequest {
            claim_key: vec![0; 33],
            ..sign.clone()
        },
        wire::BlindSignRequest {
            blinded: Vec::new(),
            ..sign.clone()
        },
        wire::BlindSignRequest {
            blinded: vec![1; 255],
            ..sign.clone()
        },
    ] {
        assert_eq!(code(i.blind_sign_at(bad, now)), Code::InvalidArgument);
    }
    let claim = wire::ClaimPayoutRequest {
        version: 1,
        claim_id: vec![1; 15],
        credits: Vec::new(),
        payout_address: address(),
    };
    assert_eq!(code(i.claim_payout_at(claim, now)), Code::InvalidArgument);
    let _ = &mut w;
}

// ------------------------------------------------------------------------------------------------
// Clock regression and retries across boundaries (§19.9, §19.10).
// ------------------------------------------------------------------------------------------------

#[test]
fn clock_regression_closed_invite_epochs_stay_refused() {
    let mut control = World::new(true);
    at_week(&mut control, 2964);
    let invite = control.mint(Kind::Invite, 740, "i");
    let trial = control.trial_blinded("t", 2964);
    assert_eq!(
        control.redeem(&invite, 2964, trial.clone()).unwrap().result,
        INVITE_OK
    );

    let mut w = World::new(true);
    at_week(&mut w, 2968); // invite epoch 742: epochs <= 740 are closed by the sweep
    w.sweep();
    {
        let tx = w.issuer().store().read().unwrap();
        assert_eq!(
            store::meta(&*tx, MetaKey::ClosedThroughInviteEpoch).unwrap(),
            Some(740)
        );
    }
    at_week(&mut w, 2964); // the clock steps back into epoch 741
    assert_eq!(code(w.redeem(&invite, 2964, trial)), Code::PermissionDenied);
}

#[test]
fn clock_regression_closed_credit_epochs_stay_refused() {
    let mut control = World::new(true);
    control.now = week_start(231 * 13) + NOON;
    let credits = mint_many(&control, Kind::Credit, 227, 10, "c");
    assert_eq!(
        control.claim("q", &credits, &address()).unwrap().result,
        QUEUED
    );

    let mut w = World::new(true);
    w.now = week_start(232 * 13) + NOON;
    w.sweep();
    w.now = week_start(231 * 13) + NOON;
    assert_eq!(
        code(w.claim("q", &credits, &address())),
        Code::PermissionDenied
    );
}

#[test]
fn retries_across_boundaries_are_served() {
    let mut w = World::new(true);
    let invite = w.mint(Kind::Invite, invite_epoch(BASE_WEEK), "i");
    let trial = w.trial_blinded("t", BASE_WEEK);
    let first = w.redeem(&invite, BASE_WEEK, trial.clone()).unwrap();
    let credits = mint_many(&w, Kind::Credit, 227, 10, "c");
    let claim = w.claim("q", &credits, &address()).unwrap();
    at_week(&mut w, 2968); // the invite epoch is e − 2: a new redemption would be refused
    assert_eq!(
        w.redeem(&invite, BASE_WEEK, trial)
            .unwrap()
            .blind_signatures,
        first.blind_signatures
    );
    w.now = week_start(233 * 13) + NOON; // the credits' epoch is long closed for new claims
    assert_eq!(w.claim("q", &credits, &address()).unwrap(), claim);
}

#[test]
fn revoked_epochs_refuse_new_redemptions_and_serve_recorded_ones() {
    let mut w = World::new(true);
    let invite = w.mint(Kind::Invite, invite_epoch(BASE_WEEK), "i");
    let trial = w.trial_blinded("t", BASE_WEEK);
    let first = w.redeem(&invite, BASE_WEEK, trial.clone()).unwrap();
    w.schedule = resigned(&w, |c| {
        c.seq = 2;
        c.revoked = vec![(Kind::Invite, 740), (Kind::Credit, 227)];
    });
    w.reopen();
    assert_eq!(
        w.redeem(&invite, BASE_WEEK, trial)
            .unwrap()
            .blind_signatures,
        first.blind_signatures
    );
    let fresh = w.mint(Kind::Invite, 740, "fresh");
    let trial = w.trial_blinded("t2", BASE_WEEK);
    assert_eq!(
        code(w.redeem(&fresh, BASE_WEEK, trial)),
        Code::PermissionDenied
    );
    let credits = mint_many(&w, Kind::Credit, 227, 10, "c");
    assert_eq!(
        code(w.claim("q", &credits, &address())),
        Code::PermissionDenied
    );
}

// ------------------------------------------------------------------------------------------------
// Retention.
// ------------------------------------------------------------------------------------------------

/// RET (§6.1, §6.4, §19.1 rule 5): the credit nullifiers of a credits-paid invoice and of a claim
/// are kept 52–65 weeks, the invoice about 7 days after issuance; the nullifier rows carry no
/// reference to the invoice or the claim, so the set of credits presented together is not kept
/// beyond the invoice row and the journal segment.
#[test]
fn retention_spent_credits_keep_no_invoice_or_claim_reference() {
    let mut w = World::new(true);
    w.external_credits = true;
    let pack = mint_many(&w, Kind::Credit, 227, 10, "d");
    assert_eq!(w.request("d", BASE_WEEK, &pack).unwrap().result, OK);
    assert_eq!(
        w.sign("d").unwrap().state,
        wire::InvoiceState::Signed as i32
    );
    let claimed = mint_many(&w, Kind::Credit, 227, 10, "q");
    assert_eq!(w.claim("q", &claimed, &address()).unwrap().result, QUEUED);
    w.mine(5_040);
    let tx = w.issuer().store().read().unwrap();
    assert_eq!(
        store::invoice(&*tx, &w.purchase("d").id).unwrap(),
        None,
        "the credits-paid invoice is purged"
    );
    let rows = tx
        .range(ghost_issuer::store::Table::CreditNullifier, &[], None)
        .unwrap();
    assert_eq!(rows.len(), 20);
    for (_, value) in &rows {
        assert!(matches!(value[0], 1 | 2), "use discount or payout");
        assert_eq!(value[1..], [0u8; 32], "a spent credit keeps a reference");
    }
    drop(tx);
    w.check();
}

// ------------------------------------------------------------------------------------------------
// Wrong key or ES: the issuer refuses to start.
// ------------------------------------------------------------------------------------------------

#[test]
fn startup_refuses_a_rolled_back_or_changed_schedule() {
    let mut w = World::new(true);
    let original = w.schedule.clone();
    w.schedule = resigned(&w, |c| {
        c.seq = 2;
        c.revoked = vec![(Kind::Credit, 229)];
    });
    w.reopen();
    let v2 = w.schedule.clone();
    w.schedule = original;
    assert_eq!(
        w.try_open(OpenMode::Normal),
        Err(StartupError::Schedule(ScheduleError::Rollback))
    );
    let dropped = {
        w.schedule = v2.clone();
        resigned(&w, |c| {
            c.seq = 3;
            c.revoked.clear();
        })
    };
    w.schedule = dropped;
    assert_eq!(
        w.try_open(OpenMode::Normal),
        Err(StartupError::Schedule(ScheduleError::RevocationDropped))
    );
    w.schedule = v2.clone();
    let repriced = resigned(&w, |c| {
        c.seq = 3;
        c.prices.iter_mut().for_each(|p| {
            if p.price_epoch == 229 {
                p.pack_price_atomic = 300_000_000_000;
            }
        });
    });
    w.schedule = repriced;
    assert_eq!(
        w.try_open(OpenMode::Normal),
        Err(StartupError::Schedule(ScheduleError::PriceChanged))
    );
    w.schedule = v2.clone();
    let reslotted = resigned(&w, |c| {
        c.seq = 3;
        // Slot 3 behind slot 0's onion service at another port: the exact onion:port of another
        // slot in the same week is refused by rule 4 (Q27), not by the memory check tested here.
        let (host, port) = c.slots[0].onion.rsplit_once(':').unwrap();
        let onion = format!("{host}:{}", port.parse::<u16>().unwrap() + 1);
        c.slots.push(SlotEntry {
            slot: 3,
            onion,
            valid_from_week: 2_970,
            valid_until_week: 0,
        });
    });
    w.schedule = reslotted;
    assert_eq!(
        w.try_open(OpenMode::Normal),
        Err(StartupError::Schedule(ScheduleError::SlotSetChanged))
    );
    // An append-only successor is accepted.
    w.schedule = v2;
    w.try_open(OpenMode::Normal).unwrap();
}

#[test]
fn startup_refuses_a_key_that_is_not_its_schedule_entry() {
    let mut w = World::new(true);
    let text = std::fs::read_to_string(fixture::dir().join("test_keys.txt")).unwrap();
    let der = text
        .lines()
        .find(|l| l.starts_with("1 2958 "))
        .map(|l| hex::decode(l.split(' ').nth(2).unwrap()).unwrap())
        .unwrap();
    // The private key of week 2958 presented as the key of week 2957.
    let signer = ReferenceSigner::from_pkcs8_der(Kind::Access, 2957, &der).unwrap();
    let pk = w
        .schedule
        .key(Kind::Access, 2958)
        .unwrap()
        .public_key
        .clone();
    let mut window = w.keys.clone();
    window.insert(CheckedSigner::new(signer, pk).unwrap());
    w.keys = window;
    w.crash();
    assert_eq!(
        w.try_open(OpenMode::Normal),
        Err(StartupError::Keys(LoadError::Mismatch(Kind::Access, 2957)))
    );
}

#[test]
fn startup_refuses_a_journal_behind_the_database_or_corrupt() {
    let mut w = World::new(true);
    assert_eq!(w.request("a", BASE_WEEK, &[]).unwrap().result, OK);
    assert_eq!(w.request("b", BASE_WEEK, &[]).unwrap().result, OK);
    w.crash();
    let journal = w.dir.path().join("journal");
    let segment = std::fs::read_dir(&journal)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let bytes = std::fs::read(&segment).unwrap();
    // A flipped byte in the first of two entries is damage, not a torn tail.
    let mut corrupt = bytes.clone();
    corrupt[20] ^= 0x01;
    std::fs::write(&segment, &corrupt).unwrap();
    assert_eq!(
        FileJournal::open(&journal).err(),
        Some(JournalError::Corrupt)
    );
    // A lost journal (the database has applied entries it no longer holds).
    std::fs::remove_file(&segment).unwrap();
    assert_eq!(
        w.try_open(OpenMode::Normal).err(),
        Some(StartupError::Journal(JournalError::Gap))
    );
    std::fs::write(&segment, &bytes).unwrap();
    w.try_open(OpenMode::Normal).unwrap();
    let _ = BASE;
}
