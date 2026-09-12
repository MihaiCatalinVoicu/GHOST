//! `RefreshCredit` (Phase 8 design §5.6, §19.8, §19.9, §19.10): a received credit is exchanged for
//! one fresh blind credit of the same epoch; the order is sizes, verification under any listed
//! CREDIT key, the nullifier lookup (idempotency before validity), then the epoch window, the
//! revocation, the closed-through mark and the blinded value's range.

mod common;

use common::fixture;
use common::scenarios::{claim_address, with_credits, NOON, OK, QUEUED};
use common::world::{World, BASE_WEEK};
use ghost_blind_rsa::BigUint;
use ghost_entitlement::grid::{invite_epoch, week_start, DAY_SECS};
use ghost_entitlement::{Expect, Kind, Schedule, Token};
use ghost_issuer::credit::refresh_digest;
use ghost_issuer::custody::destroy_after;
use ghost_issuer::reconcile::{self, CounterId};
use ghost_issuer::store::{self, Table};
use ghost_issuer_api::proto as wire;
use tonic::Code;

const REFRESHED: i32 = wire::RefreshCreditResult::Ok as i32;
const REPLAYED: i32 = wire::RefreshCreditResult::Replayed as i32;

fn code<T: std::fmt::Debug>(r: Result<T, tonic::Status>) -> Code {
    r.unwrap_err().code()
}

fn mint_many(w: &World, kind: Kind, epoch: u64, n: usize, tag: &str) -> Vec<Token> {
    (0..n)
        .map(|i| w.mint(kind, epoch, &format!("{tag}-{i}")))
        .collect()
}

fn counter(w: &World, id: CounterId, index: u64) -> u64 {
    let tx = w.issuer().store().read().unwrap();
    reconcile::get(&*tx, id, index).unwrap()
}

#[test]
fn a_received_credit_becomes_a_fresh_credit_of_the_same_epoch() {
    let mut w = with_credits("r");
    let received = w.wallet.credits[0].clone();
    let blinded = w.refresh_blinded("r", 227);
    let r = w.refresh(&received, blinded.clone()).unwrap();
    assert_eq!(r.result, REFRESHED);
    let fresh = w.finalize_refresh("r", 227, &r.blind_signature);
    let v = w.schedule.verify_token(&fresh, Expect::Credit).unwrap();
    assert_eq!(v.epoch, 227, "the value is unchanged");
    assert_eq!(counter(&w, CounterId::CreditsRefreshed, 227), 1);
    assert_eq!(counter(&w, CounterId::SignedCredit, 227), 11);
    // Idempotent by the blinded value; any other request for the nullifier is REPLAYED.
    let again = w.refresh(&received, blinded).unwrap();
    assert_eq!(
        (again.result, again.blind_signature),
        (REFRESHED, r.blind_signature)
    );
    let other = w.refresh_blinded("r-other", 227);
    let replayed = w.refresh(&received, other).unwrap();
    assert_eq!(
        (replayed.result, replayed.blind_signature.len()),
        (REPLAYED, 0)
    );
    assert_eq!(
        counter(&w, CounterId::CreditsRefreshed, 227),
        1,
        "a re-serve counts nothing"
    );
    // A refreshed credit is a credit like any other: it can be refreshed again (net zero).
    let blinded = w.refresh_blinded("r2", 227);
    assert_eq!(w.refresh(&fresh, blinded).unwrap().result, REFRESHED);
    w.check();
}

#[test]
fn a_spent_credit_is_replayed_and_a_refreshed_one_is_spent() {
    let mut w = World::new(true);
    w.external_credits = true;
    let credits = mint_many(&w, Kind::Credit, 227, 11, "c");
    assert_eq!(
        w.request("d", BASE_WEEK, &credits[..10]).unwrap().result,
        OK
    );
    let blinded = w.refresh_blinded("x", 227);
    assert_eq!(
        w.refresh(&credits[0], blinded).unwrap().result,
        REPLAYED,
        "a credit spent for a discount"
    );
    let blinded = w.refresh_blinded("y", 227);
    assert_eq!(w.refresh(&credits[10], blinded).unwrap().result, REFRESHED);
    let mut set = mint_many(&w, Kind::Credit, 227, 9, "f");
    set.push(credits[10].clone());
    let r = w.claim("q", &set, &claim_address()).unwrap();
    assert_eq!(
        (r.result, r.spent_mask),
        (wire::ClaimPayoutResult::CreditsSpent as i32, 1 << 9),
        "the refreshed input is spent"
    );
    w.check();
}

#[test]
fn only_the_current_and_the_previous_credit_epoch_refresh() {
    let mut w = World::new(true);
    w.now = week_start(2964) + NOON; // credit epoch 228
    let old = w.mint(Kind::Credit, 227, "old");
    let current = w.mint(Kind::Credit, 228, "current");
    let next = w.mint(Kind::Credit, 229, "next");
    for (token, epoch, label) in [(&old, 227, "a"), (&current, 228, "b")] {
        let blinded = w.refresh_blinded(label, epoch);
        assert_eq!(w.refresh(token, blinded).unwrap().result, REFRESHED);
    }
    let blinded = w.refresh_blinded("c", 229);
    assert_eq!(
        code(w.refresh(&next, blinded)),
        Code::PermissionDenied,
        "a future epoch"
    );
    w.now = week_start(2977) + NOON; // credit epoch 229: 227 is c − 2
    let older = w.mint(Kind::Credit, 227, "older");
    let blinded = w.refresh_blinded("d", 227);
    assert_eq!(code(w.refresh(&older, blinded)), Code::PermissionDenied);
}

#[test]
fn a_refresh_is_reserved_across_the_epoch_boundary_until_its_key_is_destroyed() {
    let mut w = World::new(true);
    w.now = week_start(2976) + NOON; // the last week of credit epoch 228: 227 is c − 1
    let credit = w.mint(Kind::Credit, 227, "c");
    let blinded = w.refresh_blinded("c", 227);
    let first = w.refresh(&credit, blinded.clone()).unwrap();
    assert_eq!(first.result, REFRESHED);
    w.now = week_start(2977) + NOON; // 227 is c − 2: new refreshes of 227 are refused
    let fresh = w.mint(Kind::Credit, 227, "fresh");
    let other = w.refresh_blinded("f", 227);
    assert_eq!(code(w.refresh(&fresh, other)), Code::PermissionDenied);
    assert_eq!(
        w.refresh(&credit, blinded.clone()).unwrap().blind_signature,
        first.blind_signature,
        "§19.9: the recorded refresh is re-served"
    );
    // Once the key of 227 is destroyed (end(228) + 8 d) the re-serve is REPLAYED (§19.1).
    w.now = destroy_after(Kind::Credit, 227) + DAY_SECS;
    w.sweep();
    assert!(!w.issuer().keys_held().contains(&(Kind::Credit, 227)));
    assert_eq!(w.refresh(&credit, blinded).unwrap().result, REPLAYED);
}

#[test]
fn revoked_and_closed_epochs_refuse_new_refreshes_and_serve_recorded_ones() {
    let mut w = World::new(true);
    let credit = w.mint(Kind::Credit, 227, "c");
    let blinded = w.refresh_blinded("c", 227);
    let first = w.refresh(&credit, blinded.clone()).unwrap();
    let mut content = w.schedule.content().clone();
    content.seq = 2;
    content.revoked = vec![(Kind::Credit, 227)];
    w.schedule = Schedule::verify_with_key(
        &fixture::sign_content(&content),
        &fixture::schedule_public_key(),
    )
    .unwrap();
    w.reopen();
    assert_eq!(
        w.refresh(&credit, blinded).unwrap().blind_signature,
        first.blind_signature
    );
    let fresh = w.mint(Kind::Credit, 227, "fresh");
    let other = w.refresh_blinded("f", 227);
    assert_eq!(code(w.refresh(&fresh, other)), Code::PermissionDenied);

    // A closed epoch (§19.10): the sweep of credit epoch 232 closes 227; with the clock back in
    // 228, where 227 would be c − 1, a new refresh is refused.
    let mut w = World::new(true);
    w.now = week_start(232 * 13) + NOON;
    w.sweep();
    w.now = week_start(2964) + NOON;
    let credit = w.mint(Kind::Credit, 227, "late");
    let blinded = w.refresh_blinded("late", 227);
    assert_eq!(code(w.refresh(&credit, blinded)), Code::PermissionDenied);
}

#[test]
fn forged_and_malformed_refreshes_are_refused() {
    let w = World::new(true);
    let credit = w.mint(Kind::Credit, 227, "c");
    let blinded = w.refresh_blinded("c", 227);
    let issuer = w.issuer();
    let now = w.now;
    let refresh = |credit: Vec<u8>, blinded: Vec<u8>, version: u32| {
        issuer.refresh_credit_at(
            wire::RefreshCreditRequest {
                version,
                credit,
                blinded,
            },
            now,
        )
    };
    let bytes = credit.as_bytes().to_vec();
    // Sizes and the version.
    for (c, b, v) in [
        (bytes[..353].to_vec(), blinded.clone(), 1),
        ([bytes.clone(), vec![0]].concat(), blinded.clone(), 1),
        (bytes.clone(), blinded[..255].to_vec(), 1),
        (bytes.clone(), [blinded.clone(), vec![0]].concat(), 1),
        (bytes.clone(), blinded.clone(), 2),
    ] {
        assert_eq!(code(refresh(c, b, v)), Code::InvalidArgument);
    }
    // Forged: the type, the challenge, the key id and the authenticator.
    for i in [0, 1, 40, 70, 100, 353] {
        let mut forged = bytes.clone();
        forged[i] ^= 0x01;
        assert_eq!(
            code(refresh(forged, blinded.clone(), 1)),
            Code::PermissionDenied,
            "byte {i}"
        );
    }
    // Another kind of token.
    let invite = w.mint(Kind::Invite, invite_epoch(BASE_WEEK), "i");
    let access = w.mint(Kind::Access, BASE_WEEK, "a");
    for t in [invite, access] {
        assert_eq!(
            code(refresh(t.as_bytes().to_vec(), blinded.clone(), 1)),
            Code::PermissionDenied
        );
    }
    // The blinded value must lie in [1, n − 1] under the epoch's key.
    let n = w
        .schedule
        .key(Kind::Credit, 227)
        .unwrap()
        .public_key
        .n()
        .clone();
    let above = (n.clone() + BigUint::from(1u32)).to_bytes_be();
    for value in [vec![0u8; 256], n.to_bytes_be(), above] {
        assert_eq!(value.len(), 256);
        assert_eq!(
            code(refresh(bytes.clone(), value, 1)),
            Code::InvalidArgument
        );
    }
    assert_eq!(refresh(bytes, blinded, 1).unwrap().result, REFRESHED);
}

/// S6 review (MONEY-2): the re-serve of a refresh compares the whole 32-byte digest of the recorded
/// request. A recorded digest that agrees with a new request's digest in its first 16 bytes only (a
/// birthday search on the prefix costs about 2^64 hashes) belongs to another request: REPLAYED,
/// never a second fresh credit.
#[test]
fn a_refresh_reserve_compares_the_whole_digest() {
    let mut w = World::new(true);
    let credit = w.mint(Kind::Credit, 227, "h");
    let first = w.refresh_blinded("h1", 227);
    assert_eq!(w.refresh(&credit, first).unwrap().result, REFRESHED);
    let second = w.refresh_blinded("h2", 227);
    let n = credit.nullifier();
    let mut recorded = refresh_digest(&n, &second);
    for b in &mut recorded[16..] {
        *b ^= 0xff;
    }
    {
        let mut tx = w.issuer().store().write().unwrap();
        tx.put(
            Table::CreditNullifier,
            &store::nullifier_key(227, &n),
            &[&[3u8][..], &recorded].concat(),
        )
        .unwrap();
        tx.commit().unwrap();
    }
    let r = w.refresh(&credit, second).unwrap();
    assert_eq!((r.result, r.blind_signature.len()), (REPLAYED, 0));
}

#[test]
fn a_refresh_survives_a_snapshot_restore() {
    let mut w = with_credits("s");
    w.snapshot();
    let received = w.wallet.credits[0].clone();
    let blinded = w.refresh_blinded("s", 227);
    let first = w.refresh(&received, blinded.clone()).unwrap();
    assert_eq!(first.result, REFRESHED);
    w.restore();
    let other = w.refresh_blinded("s-other", 227);
    assert_eq!(
        w.refresh(&received, other).unwrap().result,
        REPLAYED,
        "MS-3: a refreshed credit refreshed again after the restore"
    );
    assert_eq!(
        w.refresh(&received, blinded).unwrap().blind_signature,
        first.blind_signature
    );
    let r = w
        .claim("q", &w.wallet.credits.clone(), &claim_address())
        .unwrap();
    assert_eq!(r.spent_mask, 1, "the refreshed input stays spent");
    assert_ne!(r.result, QUEUED);
    w.check();
}
