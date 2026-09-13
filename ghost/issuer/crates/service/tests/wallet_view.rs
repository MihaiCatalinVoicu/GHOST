//! The scanner decides only from a complete, synced wallet view (Phase 8 design §5.4, §7.3, §7.5,
//! §19.6; review findings S5-MON-1 and S5-MON-5): a view-only wallet restored without runbook R5's
//! replay, which no longer holds every minor the issuer handed out, blocks every scanner decision,
//! the pool refill and new XMR invoices until the replay; a daemon behind the wallet is not the
//! wallet's own daemon and gives no synced view.

mod common;

use common::world::{World, BASE_WEEK, PRICE};
use ghost_issuer::store::{self, InvoiceRow, InvoiceState, MetaKey};
use ghost_issuer_api::proto as wire;
use tonic::Code;

const OK: i32 = wire::RequestInvoiceResult::Ok as i32;
const SIGNED: i32 = wire::InvoiceState::Signed as i32;

fn code<T: std::fmt::Debug>(r: Result<T, tonic::Status>) -> Code {
    r.unwrap_err().code()
}

fn row(w: &World, label: &str) -> InvoiceRow {
    let id = w.purchase(label).id;
    store::invoice(&*w.issuer().store().read().unwrap(), &id)
        .unwrap()
        .expect("the invoice is kept")
}

fn highest_minor(w: &World) -> u64 {
    store::meta(&*w.issuer().store().read().unwrap(), MetaKey::HighestMinor)
        .unwrap()
        .unwrap()
}

fn status(w: &World) -> String {
    w.issuer().status_at(w.now).unwrap().to_json()
}

#[test]
fn a_wallet_restored_without_the_replay_blocks_every_decision() {
    let mut w = World::new(true);
    // A paid invoice the client has not signed yet, and one paid but still in the pool.
    assert_eq!(w.request("paid", BASE_WEEK, &[]).unwrap().result, OK);
    w.pay("paid", PRICE);
    w.mine(10);
    assert_eq!(row(&w, "paid").state, InvoiceState::Confirmed);
    assert_eq!(w.request("waiting", BASE_WEEK, &[]).unwrap().result, OK);
    w.pay("waiting", PRICE);
    w.tick();
    let before = (row(&w, "paid"), row(&w, "waiting"));
    let highest = highest_minor(&w);

    // The wallet is restored from its keys without the replay: it holds its primary address only
    // and sees neither payment. Far past grace and the timely-reorg window, a view taken as
    // complete would expire both invoices (terminal, MS-6).
    w.chain.restore_without_replay(1);
    let past = before.0.grace_height + 1_000;
    w.chain.mine(past - w.chain.blocks());
    let tick = w.issuer().scan_tick_at(w.now);
    assert!(
        tick.is_err(),
        "a tick decided from an incomplete wallet: {tick:?}"
    );
    assert_eq!(
        (row(&w, "paid"), row(&w, "waiting")),
        before,
        "no state change from an incomplete wallet"
    );
    let s = status(&w);
    assert!(s.contains("\"SCANNER\":\"WALLET_INCOMPLETE\""), "{s}");
    assert_eq!(
        code(w.request("new", BASE_WEEK, &[])),
        Code::Unavailable,
        "no new XMR invoice without a synced tick of a complete wallet"
    );
    // The refill creates nothing: it never replays the wallet itself (a replay without the
    // rescan would pass the count check while the payments stay invisible).
    let count = w.chain.subaddress_count();
    assert!(w.issuer().pool_refill_at(w.now).is_err());
    assert_eq!(w.chain.subaddress_count(), count, "no subaddress burned");
    assert!(w.issuer().scan_tick_at(w.now).is_err(), "still incomplete");

    // Runbook R5: the replay through highest_minor and the rescan. The next tick sees both
    // payments; the paid invoice is signed.
    w.chain.replay_through(u32::try_from(highest).unwrap());
    w.tick();
    assert!(status(&w).contains("\"SCANNER\":\"SCANNER_OK\""));
    let paid = row(&w, "paid");
    assert_eq!(
        (paid.state, paid.credited),
        (InvoiceState::Confirmed, PRICE)
    );
    let waiting = row(&w, "waiting");
    assert_eq!(
        (waiting.state, waiting.credited),
        (InvoiceState::Confirmed, PRICE)
    );
    assert_eq!(w.sign("paid").unwrap().state, SIGNED);
    w.refill();
    assert_eq!(w.request("new", BASE_WEEK, &[]).unwrap().result, OK);
}

#[test]
fn a_daemon_behind_the_wallet_is_not_a_synced_view() {
    let mut w = World::new(true);
    assert_eq!(w.request("late", BASE_WEEK, &[]).unwrap().result, OK);
    let grace = row(&w, "late").grace_height;
    let c = u64::from(w.schedule.constants().confirmations);
    w.chain.mine_empty(grace + c + 1 - w.chain.blocks());
    // The configured daemon lags the wallet: it is not the wallet's own daemon, whose height the
    // refresh has just reached, so nothing it reports makes the view synced.
    w.chain.set_daemon_behind(2);
    w.tick();
    assert_eq!(
        row(&w, "late").state,
        InvoiceState::Created,
        "EXPIRED from a view that is not synced"
    );
    assert_eq!(code(w.request("new", BASE_WEEK, &[])), Code::Unavailable);
    // One block behind: the wallet's own daemon between the refresh and get_info.
    w.chain.set_daemon_behind(1);
    w.tick();
    assert_eq!(row(&w, "late").state, InvoiceState::Expired);
}
