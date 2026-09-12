//! Regtest step 14 in process (Phase 8 design §13.3 step 14; the live job repeats it on the pinned
//! wallet): an invoice, its payment and 10 confirmations on the `ChainPort` wallet, `BlindSign` on
//! the production issuer, finalization with the production client crypto, and the redemption of
//! one of the pack's access tokens at an in-process relay of its slot, for a write capability of a
//! namespace.

mod common;

use common::relay::{capability, redeem, relay_for_slot};
use common::world::{World, BASE_WEEK};
use ghost_entitlement::{Expect, Kind, Token};
use ghost_relay_api::proto::RedeemResult;
use ghost_relay_api::CapabilityKind;
use tonic::Code;

#[test]
fn a_paid_pack_redeems_at_a_relay_for_a_namespace_capability() {
    let mut w = World::new(true);
    let tokens = w.buy_pack("e2e");
    let p = w.purchase("e2e");
    let layout = w.layout(&p);
    let access = |slot: u8| -> Token {
        layout
            .positions()
            .iter()
            .zip(&tokens)
            .find(|(pos, _)| {
                pos.kind == Kind::Access && pos.epoch == BASE_WEEK && pos.slot == Some(slot)
            })
            .map(|(_, t)| t.clone())
            .unwrap()
    };
    let token = access(1);
    assert!(w
        .schedule
        .verify_token(&token, Expect::AccessAtSlot(1))
        .is_ok());

    let dir = tempfile::tempdir().unwrap();
    let now = w.now;
    let relay = relay_for_slot(dir.path(), &w.schedule, 1, now);
    let namespace = [0x5a; 32];
    let answer = redeem(&relay, &token, &namespace, &[1; 16], now).unwrap();
    let cap = capability(&answer).expect("a write capability");
    let header = relay.key().verify_any(&cap, now).unwrap();
    assert_eq!(
        (header.kind, header.namespace),
        (CapabilityKind::Write, namespace)
    );
    // MS-8: the identical retry gets the identical capability; another namespace is REPLAYED.
    let again = redeem(&relay, &token, &namespace, &[1; 16], now).unwrap();
    assert_eq!(capability(&again), Some(cap));
    let other = redeem(&relay, &token, &[0x5b; 32], &[2; 16], now).unwrap();
    assert_eq!(other.result, RedeemResult::Replayed as i32);
    // A token of another slot is refused here (its challenge names another relay).
    assert_eq!(
        redeem(&relay, &access(0), &namespace, &[3; 16], now)
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    w.check();
}
