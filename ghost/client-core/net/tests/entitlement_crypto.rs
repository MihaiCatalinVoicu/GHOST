//! The stateless `EntitlementCrypto` functions (design §11.7) over the test schedule: the verified
//! summary, layout digests, offline token checks, address validation and the payment URI; and the
//! production load path, which never accepts a test schedule.

mod common;

use common::*;
use ed25519_dalek::Signer as _;
use ghost_client_net::entitlement::{self, load_schedule, Product, EMBEDDED_SCHEDULE};
use ghost_entitlement::batch::Layout;
use ghost_entitlement::monero::{AddressError, AddressPurpose};
use ghost_entitlement::{Kind, ScheduleError};

#[test]
fn the_production_load_path_refuses_every_test_schedule() {
    assert_eq!(
        load_schedule(TEST_SCHEDULE).err(),
        Some(ScheduleError::NoPinnedKey)
    );
    // The test content under the stagenet network byte, signed with the test key: the pinned
    // stagenet key refuses it.
    let relabelled = resigned(|c| c.network = ghost_entitlement::monero::MoneroNetwork::Stagenet);
    let content = relabelled.content();
    let sig = schedule_signing_key().sign(&content.signing_message().unwrap());
    let bytes = content.to_signed_bytes(&sig.to_bytes()).unwrap();
    assert_eq!(load_schedule(&bytes).err(), Some(ScheduleError::Signature));
    // The embedded schedule is a different file from the test schedule.
    assert_ne!(EMBEDDED_SCHEDULE, TEST_SCHEDULE);
}

/// A strict reader of the summary layout (the rules of the Kotlin decoder).
struct Summary {
    slots: Vec<(u8, u64, u64, String)>,
    prices: Vec<(u64, u64)>,
    keys: Vec<(u8, u64, [u8; 32])>,
    revoked: Vec<(u8, u64)>,
}

fn read(b: &[u8]) -> Summary {
    let u64_at = |i: usize| u64::from_be_bytes(b[i..i + 8].try_into().unwrap());
    let u16_at = |i: usize| usize::from(u16::from_be_bytes([b[i], b[i + 1]]));
    let count = usize::from(b[77]);
    let mut i = 78;
    let mut slots = Vec::new();
    for _ in 0..count {
        let len = usize::from(b[i + 17]);
        let onion = String::from_utf8(b[i + 18..i + 18 + len].to_vec()).unwrap();
        slots.push((b[i], u64_at(i + 1), u64_at(i + 9), onion));
        i += 18 + len;
    }
    let n = u16_at(i);
    i += 2;
    let prices = (0..n)
        .map(|k| (u64_at(i + 16 * k), u64_at(i + 16 * k + 8)))
        .collect();
    i += 16 * n;
    let n = u16_at(i);
    i += 2;
    let keys = (0..n)
        .map(|k| {
            let at = i + 41 * k;
            (
                b[at],
                u64_at(at + 1),
                b[at + 9..at + 41].try_into().unwrap(),
            )
        })
        .collect();
    i += 41 * n;
    let n = u16_at(i);
    i += 2;
    let revoked = (0..n)
        .map(|k| (b[i + 9 * k], u64_at(i + 9 * k + 1)))
        .collect();
    i += 9 * n;
    assert_eq!(i, b.len(), "no trailing bytes");
    Summary {
        slots,
        prices,
        keys,
        revoked,
    }
}

#[test]
fn the_summary_carries_every_fact_kotlin_remembers() {
    let s = schedule();
    let b = entitlement::schedule_summary(s).unwrap();
    assert_eq!(&b[..32], s.digest());
    assert_eq!(u64::from_be_bytes(b[32..40].try_into().unwrap()), 1);
    assert_eq!(b[40], 3, "regtest");
    assert_eq!(u64::from_be_bytes(b[41..49].try_into().unwrap()), 2957);
    assert_eq!(u64::from_be_bytes(b[49..57].try_into().unwrap()), 2982);
    assert_eq!(&b[57..62], &[10, 0x02, 0xD0, 0x08, 0x70]); // 10 confirmations, 720, 2160
    assert_eq!(&b[62..69], &[16, 8, 2, 10, 10, 50, 24]);
    assert_eq!(
        u64::from_be_bytes(b[69..77].try_into().unwrap()),
        268_435_456
    );
    let sum = read(&b);
    assert_eq!(sum.slots.len(), 4);
    for (slot, from, until, onion) in &sum.slots {
        let entry = s
            .content()
            .slots
            .iter()
            .find(|e| e.slot == *slot && e.valid_from_week == *from)
            .unwrap();
        assert_eq!(
            (entry.valid_until_week, entry.onion.as_str()),
            (*until, onion.as_str())
        );
        ghost_client_net::OnionAddress::parse(onion).unwrap();
    }
    assert_eq!(
        sum.slots[3],
        (2, 2967, 0, s.slot_onion(2, 2967).unwrap().to_owned())
    );
    assert_eq!(sum.prices.len(), 3);
    assert_eq!(sum.prices[0], (227, 200_000_000_000));
    assert_eq!(sum.keys.len(), s.keys().count());
    assert_eq!(sum.keys.len(), 26 + 7 + 3);
    for (kind, epoch, id) in &sum.keys {
        let k = s.key(Kind::from_byte(*kind).unwrap(), *epoch).unwrap();
        assert_eq!(&k.key_id, id);
    }
    assert!(sum.revoked.is_empty());

    // Revocations travel in ES order.
    let revoked = resigned(|c| c.revoked = vec![(Kind::Access, 2960), (Kind::Credit, 228)]);
    let sum = read(&entitlement::schedule_summary(&revoked).unwrap());
    assert_eq!(sum.revoked, vec![(1, 2960), (3, 228)]);
}

#[test]
fn layout_digests_are_those_of_the_batch_layouts() {
    let s = schedule();
    let n = |b: &[u8; 36]| u32::from_be_bytes(b[32..].try_into().unwrap());
    let cases = [
        (
            Product::PackXmr,
            2957,
            Layout::pack(s, 2957, true).unwrap(),
            243,
        ),
        (
            Product::PackCredits,
            2957,
            Layout::pack(s, 2957, false).unwrap(),
            242,
        ),
        // Slot 2 changes relay at 2967 inside this pack; the layout counts slots, not relays.
        (
            Product::PackXmr,
            2965,
            Layout::pack(s, 2965, true).unwrap(),
            243,
        ),
        (Product::Trial, 2957, Layout::trial(s, 2957).unwrap(), 48),
        (Product::Refresh, 227, Layout::refresh(s, 227).unwrap(), 1),
        (
            Product::PackXmr,
            2978,
            Layout::pack(s, 2978, true).unwrap(),
            243,
        ),
    ];
    for (product, index, layout, count) in cases {
        let b = entitlement::layout_digest(s, product, index).unwrap();
        assert_eq!(b[..32], layout.digest(), "{product:?} {index}");
        assert_eq!(n(&b), count, "{product:?} {index}");
    }
    // Weeks and epochs the ES does not cover have no layout.
    assert!(entitlement::layout_digest(s, Product::PackXmr, 2979).is_err());
    assert!(entitlement::layout_digest(s, Product::Trial, 2982).is_err());
    assert!(entitlement::layout_digest(s, Product::Refresh, 230).is_err());
    assert!(entitlement::layout_digest(s, Product::PackXmr, 2956).is_err());
}

#[test]
fn tokens_are_checked_offline_for_their_kind() {
    let s = schedule();
    let access = mint(Kind::Access, 2959, Some(1), seed(1, 0x7A));
    let invite = mint(Kind::Invite, INVITE_EPOCH, None, seed(2, 0x7A));
    let credit = mint(Kind::Credit, CREDIT_EPOCH, None, seed(3, 0x7A));
    for (token, kind, epoch, slot) in [
        (&access, Kind::Access, 2959, Some(1)),
        (&invite, Kind::Invite, INVITE_EPOCH, None),
        (&credit, Kind::Credit, CREDIT_EPOCH, None),
    ] {
        let v = entitlement::verify_token(s, token.as_bytes(), kind).unwrap();
        assert_eq!(
            (v.kind, v.epoch, v.slot, v.nullifier),
            (kind, epoch, slot, token.nullifier())
        );
        let p = entitlement::pack_verified(&v);
        assert_eq!(p[0], kind.byte());
        assert_eq!(&p[1..9], &epoch.to_be_bytes());
        assert_eq!(p[9], slot.unwrap_or(0xFF));
        assert_eq!(&p[10..], &token.nullifier());
        // Any other kind refuses it.
        for other in Kind::ALL.into_iter().filter(|k| *k != kind) {
            assert_eq!(entitlement::verify_token(s, token.as_bytes(), other), None);
        }
    }
    // A pinned vector token, a tampered one and one of a revoked epoch.
    let a1 = pinned("a1");
    assert_eq!(
        entitlement::verify_token(s, &a1, Kind::Access)
            .unwrap()
            .slot,
        Some(1)
    );
    let mut tampered = invite.as_bytes().to_vec();
    tampered[300] ^= 1;
    assert_eq!(entitlement::verify_token(s, &tampered, Kind::Invite), None);
    let revoked = resigned(|c| c.revoked = vec![(Kind::Invite, INVITE_EPOCH)]);
    assert_eq!(
        entitlement::verify_token(&revoked, invite.as_bytes(), Kind::Invite),
        None
    );
    assert_eq!(entitlement::verify_token(s, &a1[..300], Kind::Access), None);
}

#[test]
fn addresses_of_the_schedule_network_only() {
    let s = schedule();
    assert_eq!(
        entitlement::validate_address(s, SUBADDRESS, AddressPurpose::Invoice),
        Ok(0x0302)
    );
    assert_eq!(
        entitlement::validate_address(s, SUBADDRESS, AddressPurpose::Payout),
        Ok(0x0302)
    );
    assert_eq!(
        entitlement::validate_address(s, PAYOUT, AddressPurpose::Payout),
        Ok(0x0301)
    );
    assert_eq!(
        entitlement::validate_address(s, PAYOUT, AddressPurpose::Invoice),
        Err(AddressError::WrongType)
    );
    assert_eq!(
        entitlement::validate_address(s, STAGENET_SUBADDRESS, AddressPurpose::Payout),
        Err(AddressError::WrongNetwork)
    );
    assert_eq!(
        entitlement::payment_uri(s, SUBADDRESS, 200_000_000_000).unwrap(),
        format!("monero:{SUBADDRESS}?tx_amount=0.200000000000")
    );
    assert!(entitlement::payment_uri(s, PAYOUT, 1).is_err());
    assert!(entitlement::payment_uri(s, SUBADDRESS, 0).is_err());
}
