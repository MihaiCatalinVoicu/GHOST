//! Key custody (Phase 8 design §3.3, §19.1): keys load from the sealed files of slice S2 through a
//! K3 load file, are proven against the schedule, and leave memory only when no open invoice (or
//! trial re-serve window) needs them. Scenarios I-I (a CONFIRMED invoice signed in week base + 2
//! and later) and I-J (issued late in week base + 1, re-served six days later) are here.

mod common;

use std::collections::BTreeSet;

use common::fixture;
use common::world::{World, BASE_WEEK, PRICE};
use ghost_entitlement::grid::{week_start, DAY_SECS};
use ghost_entitlement::Kind;
use ghost_issuer::custody::{
    destroy_after, sealed_file_name, CustodyError, CustodySecret, KeyWindow, LoadError, SealLoad,
};
use ghost_issuer_api::proto as wire;

const SIGNED: i32 = wire::InvoiceState::Signed as i32;

fn load_of(keys: &[(Kind, u64)]) -> SealLoad {
    let secret = CustodySecret::from_bytes(fixture::custody_secret_bytes());
    let mut load = SealLoad::new();
    for &(k, e) in keys {
        load.insert(k, e, secret.seal_key(k, e)).unwrap();
    }
    // Through the load file encoding, as the issuer receives it.
    SealLoad::parse(&load.encode().unwrap()).unwrap()
}

#[test]
fn keys_load_from_sealed_files_and_a_load_file() {
    let (schedule, _) = fixture::small();
    let wanted = [
        (Kind::Access, BASE_WEEK),
        (Kind::Access, BASE_WEEK + 1),
        (Kind::Invite, 740),
        (Kind::Credit, 227),
    ];
    let window = KeyWindow::load(schedule, &load_of(&wanted), &fixture::sealed_dir()).unwrap();
    let mut expected = wanted.to_vec();
    expected.sort();
    assert_eq!(window.held(), expected);
    window.check_against(schedule).unwrap();

    // Another epoch's k_seal does not open the file.
    let secret = CustodySecret::from_bytes(fixture::custody_secret_bytes());
    let mut wrong = SealLoad::new();
    wrong
        .insert(
            Kind::Access,
            BASE_WEEK,
            secret.seal_key(Kind::Access, BASE_WEEK + 1),
        )
        .unwrap();
    assert_eq!(
        KeyWindow::load(schedule, &wrong, &fixture::sealed_dir()).unwrap_err(),
        LoadError::Custody(Kind::Access, BASE_WEEK, CustodyError::Open)
    );
    // A sealed file presented under another (kind, epoch).
    let dir = tempfile::tempdir().unwrap();
    std::fs::copy(
        fixture::sealed_dir().join(sealed_file_name(Kind::Access, BASE_WEEK + 1)),
        dir.path().join(sealed_file_name(Kind::Access, BASE_WEEK)),
    )
    .unwrap();
    assert_eq!(
        KeyWindow::load(schedule, &load_of(&[(Kind::Access, BASE_WEEK)]), dir.path()).unwrap_err(),
        LoadError::Custody(Kind::Access, BASE_WEEK, CustodyError::WrongKey)
    );
    assert_eq!(
        KeyWindow::load(
            schedule,
            &load_of(&[(Kind::Access, BASE_WEEK + 1)]),
            dir.path()
        )
        .unwrap_err(),
        LoadError::SealedFileMissing(Kind::Access, BASE_WEEK + 1)
    );
    assert_eq!(
        KeyWindow::load(
            schedule,
            &load_of(&[(Kind::Access, 3_100)]),
            &fixture::sealed_dir()
        )
        .unwrap_err(),
        LoadError::NotInSchedule(Kind::Access, 3_100)
    );
}

#[test]
fn an_issuer_runs_on_a_loaded_window() {
    let (schedule, _) = fixture::small();
    let mut keys: Vec<(Kind, u64)> = (BASE_WEEK..BASE_WEEK + 7)
        .map(|w| (Kind::Access, w))
        .collect();
    keys.extend([
        (Kind::Invite, 740),
        (Kind::Invite, 741),
        (Kind::Credit, 227),
    ]);
    let mut w = World::new(true);
    w.keys = KeyWindow::load(schedule, &load_of(&keys), &fixture::sealed_dir()).unwrap();
    w.reopen();
    w.buy_pack("p");
    let now = w.now;
    assert_eq!(
        w.issuer().status_at(now).unwrap().keys_ready_until_week,
        BASE_WEEK + 3,
        "credit epoch 228 (week 2964) is not loaded"
    );
    w.check();
}

#[test]
fn destruction_times_follow_19_1() {
    let d = 8 * DAY_SECS;
    assert_eq!(destroy_after(Kind::Access, 2960), week_start(2962) + d);
    assert_eq!(destroy_after(Kind::Invite, 740), week_start(4 * 741) + d);
    assert_eq!(destroy_after(Kind::Credit, 227), week_start(13 * 229) + d);
    let (_, full) = fixture::small();
    let mut window = full.clone();
    let referenced: BTreeSet<_> = [(Kind::Access, 2957)].into();
    let destroyed = window.destroy_due(week_start(2966), &referenced);
    assert!(destroyed.contains(&(Kind::Access, 2958)));
    assert!(
        !destroyed.contains(&(Kind::Access, 2957)),
        "referenced by an open invoice"
    );
    assert!(!destroyed.contains(&(Kind::Access, 2963)));
    assert!(window.contains(Kind::Access, 2957));
}

/// I-I: a paid invoice whose client comes back in week base + 2 and later is still signed; its
/// keys are destroyed only after it is purged.
#[test]
fn i_i_confirmed_invoice_signed_weeks_later() {
    let mut w = World::new(true);
    assert_eq!(
        w.request("p", BASE_WEEK, &[]).unwrap().result,
        wire::RequestInvoiceResult::Ok as i32
    );
    w.pay("p", PRICE);
    w.mine(10);
    // Past the fixed destruction time of week base: end(base + 1) + 8 d, and later still.
    w.now = destroy_after(Kind::Access, BASE_WEEK) + DAY_SECS;
    w.tick();
    w.sweep();
    assert!(w.issuer().keys_held().contains(&(Kind::Access, BASE_WEEK)));
    assert!(!w
        .issuer()
        .keys_held()
        .contains(&(Kind::Access, BASE_WEEK - 3)));
    let s = w.sign("p").unwrap();
    assert_eq!(s.state, SIGNED);
    w.finalize("p", &s.blind_signatures);
    // Issued, then purged 5 040 blocks later: the key goes at the next sweep.
    w.mine(5_040);
    w.sweep();
    assert!(!w.issuer().keys_held().contains(&(Kind::Access, BASE_WEEK)));
    w.check();
}

/// I-J: issued late in week base + 1 and re-served six days later.
#[test]
fn i_j_issued_late_reserved_six_days_later() {
    let mut w = World::new(true);
    assert_eq!(
        w.request("p", BASE_WEEK, &[]).unwrap().result,
        wire::RequestInvoiceResult::Ok as i32
    );
    w.pay("p", PRICE);
    w.mine(10);
    w.now = week_start(BASE_WEEK + 2) - 3_600;
    w.tick();
    let s = w.sign("p").unwrap();
    assert_eq!(s.state, SIGNED);
    w.advance(6 * DAY_SECS);
    w.tick();
    w.sweep();
    assert_eq!(w.sign("p").unwrap().blind_signatures, s.blind_signatures);
    w.check();
}

/// §19.1 rule 2: a trial is re-served for at least 8 days after week base + 1 ends; afterwards
/// the identical retry is REPLAYED.
#[test]
fn trial_reserve_window() {
    let mut w = World::new(true);
    let invite = w.mint(Kind::Invite, 740, "i");
    let trial = w.trial_blinded("t", BASE_WEEK);
    let first = w.redeem(&invite, BASE_WEEK, trial.clone()).unwrap();
    w.now = week_start(BASE_WEEK + 2) + 8 * DAY_SECS - 1;
    w.sweep();
    assert_eq!(
        w.redeem(&invite, BASE_WEEK, trial.clone())
            .unwrap()
            .blind_signatures,
        first.blind_signatures
    );
    w.now = week_start(BASE_WEEK + 2) + 8 * DAY_SECS;
    w.sweep();
    assert!(!w.issuer().keys_held().contains(&(Kind::Access, BASE_WEEK)));
    assert_eq!(
        w.redeem(&invite, BASE_WEEK, trial).unwrap().result,
        wire::RedeemInviteResult::Replayed as i32
    );
}

/// §19.1 rule 2 for a trial redeemed in the last week of the invite epoch after the token's: the
/// sweep at the next epoch boundary closes the token's epoch for new redemptions, but the trial's
/// nullifier stays until its re-serve window ends, so the identical retry is served until
/// `end(base + 1) + 8 d` (REPLAYED afterwards); the row is deleted later (RET).
#[test]
fn trial_redeemed_in_the_last_week_of_the_next_epoch_is_reserved() {
    let mut w = World::new(true);
    let base = 2967; // the last week of invite epoch 741
    w.now = week_start(base) + DAY_SECS / 2;
    let invite = w.mint(Kind::Invite, 740, "i");
    let trial = w.trial_blinded("t", base);
    let first = w.redeem(&invite, base, trial.clone()).unwrap();
    assert_eq!(first.result, wire::RedeemInviteResult::Ok as i32);
    // Invite epoch 742 begins: epoch 740 is closed for new redemptions.
    w.now = week_start(base + 1) + DAY_SECS;
    w.sweep();
    assert!(w.issuer().keys_held().contains(&(Kind::Access, base)));
    assert_eq!(
        w.redeem(&invite, base, trial.clone())
            .unwrap()
            .blind_signatures,
        first.blind_signatures
    );
    let fresh = w.mint(Kind::Invite, 740, "fresh");
    let other = w.trial_blinded("t2", base + 1);
    assert_eq!(
        w.redeem(&fresh, base + 1, other).unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
    // The last second of the guarantee.
    w.now = week_start(base + 2) + 8 * DAY_SECS - 1;
    w.sweep();
    assert_eq!(
        w.redeem(&invite, base, trial.clone())
            .unwrap()
            .blind_signatures,
        first.blind_signatures
    );
    w.now = week_start(base + 2) + 8 * DAY_SECS;
    w.sweep();
    assert_eq!(
        w.redeem(&invite, base, trial).unwrap().result,
        wire::RedeemInviteResult::Replayed as i32
    );
    // Once no trial of the epoch can be re-served any more, its nullifiers are deleted.
    w.now = week_start(base + 3) + 8 * DAY_SECS;
    w.sweep();
    let tx = w.issuer().store().read().unwrap();
    assert_eq!(
        ghost_issuer::store::invite_nullifier(&*tx, 740, &invite.nullifier()).unwrap(),
        None,
        "RET: an invite nullifier outlives its rule"
    );
}

#[test]
fn the_window_reports_readiness() {
    let (_, full) = fixture::small();
    assert_eq!(full.ready_until_week(BASE_WEEK), Some(2982));
    let empty = KeyWindow::new();
    assert_eq!(empty.ready_until_week(BASE_WEEK), None);
}
