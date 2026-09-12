//! The committed Entitlement Schedule (`protocol/entitlement/schedule.ghes`, slice S2b, design
//! §15.1, §19.17 point 1, Q20 as revised): the production entry point `Schedule::verify` accepts
//! it under the stagenet key pinned in `ghost-entitlement`, and no bytes derived from it verify as
//! a schedule of another network.

use std::collections::BTreeSet;

use ghost_entitlement::grid::{credit_epoch, invite_epoch, price_epoch, week_start};
use ghost_entitlement::monero::MoneroNetwork;
use ghost_entitlement::{Kind, Schedule, ScheduleError};

const COMMITTED: &[u8] = include_bytes!("../../../../protocol/entitlement/schedule.ghes");
/// The stagenet schedule public key of S2b, as `ghost-issuer-ops keygen --new-schedule-key`
/// printed it.
const STAGENET_SCHEDULE_KEY: &str =
    "8b95a751974352372733718e49358be2f28bbc5c45d1bf4a4dd7b6c1664b7dad";
/// ISO week 2026-W37 (Monday 2026-09-07 00:00 UTC), the first access week.
const FIRST_WEEK: u64 = 2957;
/// 0.05 stagenet XMR per pack.
const PACK_PRICE_ATOMIC: u64 = 50_000_000_000;
/// Offset of the network byte: magic (4) || version (1) || seq (8).
const NETWORK_OFFSET: usize = 13;

fn stagenet_key() -> [u8; 32] {
    hex::decode(STAGENET_SCHEDULE_KEY)
        .unwrap()
        .try_into()
        .unwrap()
}

#[test]
fn production_verify_accepts_the_committed_stagenet_schedule() {
    let s = Schedule::verify(COMMITTED).expect("the pinned stagenet key verifies it");
    assert_eq!(s.network(), MoneroNetwork::Stagenet);
    assert!(s.refuse_regtest().is_ok());
    assert_eq!(s.seq(), 1);
    // The pinned key is the S2b key.
    let explicit = Schedule::verify_with_key(COMMITTED, &stagenet_key()).unwrap();
    assert_eq!(explicit.digest(), s.digest());

    assert_eq!(s.first_access_week(), FIRST_WEEK);
    assert_eq!(week_start(FIRST_WEEK), 1_788_739_200);
    let weeks = s.last_access_week() - s.first_access_week() + 1;
    assert!(weeks >= 30, "{weeks} weeks");

    // Constants at the design defaults (§3.1; min_claim_credits = 10 by §19.8 point 2).
    let c = s.constants();
    assert_eq!(
        (c.confirmations, c.invoice_blocks, c.grace_blocks),
        (10, 720, 2160)
    );
    assert_eq!(
        (c.access_per_slot, c.trial_per_slot, c.invites_per_pack),
        (16, 8, 2)
    );
    assert_eq!(
        (
            c.credits_per_free_pack,
            c.min_claim_credits,
            c.max_claim_credits
        ),
        (10, 10, 50)
    );
    assert_eq!(
        (c.early_window_hours, c.capability_quota_bytes),
        (24, 268_435_456)
    );

    for w in s.first_access_week()..=s.last_access_week() {
        assert!(s.key(Kind::Access, w).is_some(), "week {w}");
        assert!(s.key(Kind::Invite, invite_epoch(w)).is_some(), "week {w}");
        assert!(s.key(Kind::Credit, credit_epoch(w)).is_some(), "week {w}");
        assert_eq!(s.pack_price(price_epoch(w)), Some(PACK_PRICE_ATOMIC));
        assert_eq!(s.slots_in_week(w), vec![0, 1, 2], "week {w}");
    }
    assert!(s.content().revoked.is_empty());
    // Three relay onions and the issuer's, all distinct.
    let mut onions: BTreeSet<&str> = s.content().slots.iter().map(|x| x.onion.as_str()).collect();
    assert_eq!(onions.len(), 3);
    assert!(onions.insert(s.content().issuer_onion.as_str()));
}

#[test]
fn nothing_derived_from_the_committed_schedule_verifies_as_another_network() {
    assert_eq!(COMMITTED[NETWORK_OFFSET], 2, "stagenet");
    for network in [1u8, 3] {
        let mut relabelled = COMMITTED.to_vec();
        relabelled[NETWORK_OFFSET] = network;
        // The network byte is signed: not even the stagenet key verifies the relabelled bytes.
        assert_eq!(
            Schedule::verify_with_key(&relabelled, &stagenet_key()).err(),
            Some(ScheduleError::Signature)
        );
        assert!(matches!(
            Schedule::verify(&relabelled),
            Err(ScheduleError::NoPinnedKey | ScheduleError::Signature)
        ));
    }
    let mut tampered = COMMITTED.to_vec();
    tampered[200] ^= 0x01;
    assert_eq!(
        Schedule::verify(&tampered).err(),
        Some(ScheduleError::Signature)
    );
}
