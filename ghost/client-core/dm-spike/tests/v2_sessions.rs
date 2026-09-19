//! V-2: sessions through throwaway accounts on a scripted two-client harness; D2b; R-SS1 … R-SS3
//! with the §22.8.4 age rules; the library errors mapped to the §2.6 codes (both pins); the
//! §22.8.2 non-contributory inner ratchet key.

use curve25519_dalek::constants::EIGHT_TORSION;
use ghost_dm_spike::codes::Code;
use ghost_dm_spike::harness::{Client, Drop, Envelope, Establish, Outcome, Role, SlotName};
use ghost_dm_spike::msc3814::DehydratedSecrets;
use ghost_dm_spike::olm::{random_bytes, x25519_public};
use ghost_dm_spike::{schedule, sizes};
use serde_json::Value;

fn pair() -> (Client, Client) {
    let mut a = Client::new(&random_bytes());
    let mut b = Client::new(&random_bytes());
    a.pin(b.identity());
    b.pin(a.identity());
    (a, b)
}

fn displayed(outcome: &Outcome) -> Option<(Vec<u8>, SlotName, bool, bool)> {
    match outcome {
        Outcome::Displayed {
            plaintext,
            slot,
            created,
            swapped,
        } => Some((plaintext.clone(), *slot, *created, *swapped)),
        Outcome::Dropped(_) => None,
    }
}

fn current_id(c: &Client) -> String {
    c.current
        .as_ref()
        .map(|s| s.session_id.clone())
        .unwrap_or_default()
}

#[test]
fn first_flight_acknowledgement_and_d2b() {
    let (mut a, mut b) = pair();
    let bundle = b.bundle();
    a.establish(&bundle, Establish::First).expect("EST-READY");
    let a1 = a.send(b"a1", 100).expect("send");
    let a2 = a.send(b"a2", 101).expect("send");
    let a3 = a.send(b"a3", 102).expect("send");
    assert!(a1.is_prekey && a2.is_prekey && a3.is_prekey);

    let r = b.receive(&a1);
    assert_eq!(
        displayed(&r).map(|d| (d.0, d.1, d.2)),
        Some((b"a1".to_vec(), SlotName::Current, true))
    );
    assert_eq!(
        displayed(&b.receive(&a2)).map(|d| (d.1, d.2)),
        Some((SlotName::Current, false))
    );
    // A duplicate of a known-session PreKey message: D2a (the message key is gone).
    assert_eq!(
        b.receive(&a1),
        Outcome::Dropped(Drop::Library(Code::DuplicateOrLost))
    );

    // Acknowledgement: B's normal reply makes A's session acknowledged; A's outputs turn normal.
    let reply = b.send(b"b1", 103).expect("send");
    assert!(!reply.is_prekey);
    assert!(displayed(&a.receive(&reply)).is_some());
    assert!(a.current.as_ref().is_some_and(|s| s.acknowledged));
    assert!(!a.send(b"a4", 104).expect("send").is_prekey);

    // B resets (R-SS0): the replayed first flight hits the reuse set, not a new session.
    b.delete_sessions();
    assert_eq!(b.receive(&a3), Outcome::Dropped(Drop::Replay));
    assert!(b.current.is_none());

    // Mutant MC-7′ (no D2b): the library accepts the replay and a second session appears.
    b.d2b = false;
    let r = b.receive(&a3);
    assert_eq!(
        displayed(&r).map(|d| d.2),
        Some(true),
        "without D2b the replay creates a session"
    );
}

/// The library fact behind D2b, on both pins: a fallback key is not consumed, so the same PreKey
/// message creates the same session twice.
#[test]
fn fallback_keys_are_not_consumed_on_either_pin() {
    macro_rules! check {
        ($olm:path) => {{
            use $olm as olm;
            let a = DehydratedSecrets {
                curve25519: random_bytes(),
                ed25519_seed: random_bytes(),
                fallback: None,
            };
            let f: [u8; 32] = random_bytes();
            let b = DehydratedSecrets {
                curve25519: random_bytes(),
                ed25519_seed: random_bytes(),
                fallback: Some(f),
            };
            let (state, _) =
                olm::session_outbound(&a, &x25519_public(&b.curve25519), &x25519_public(&f))
                    .expect("outbound");
            let first = olm::encrypt(&state, b"x").expect("encrypt");
            let one =
                olm::session_inbound(&b, &x25519_public(&a.curve25519), &first.l1).expect("first");
            let two =
                olm::session_inbound(&b, &x25519_public(&a.curve25519), &first.l1).expect("replay");
            assert_eq!(one.session_id, two.session_id);
        }};
    }
    check!(ghost_dm_spike::olm::v11);
    check!(ghost_dm_spike::olm::v10);
}

/// R-SS3: simultaneous first contact converges on the smaller session id within two round trips.
#[test]
fn simultaneous_first_contact_converges() {
    for _ in 0..8 {
        let (mut a, mut b) = pair();
        a.establish(&b.bundle(), Establish::First).expect("A");
        b.establish(&a.bundle(), Establish::First).expect("B");
        let a1 = a.send(b"a1", 200).expect("send");
        let b1 = b.send(b"b1", 200).expect("send");
        assert!(displayed(&a.receive(&b1)).is_some_and(|d| d.1 == SlotName::Current && d.2));
        assert!(displayed(&b.receive(&a1)).is_some_and(|d| d.1 == SlotName::Current && d.2));
        let mut minute = 201;
        let mut shown = 2;
        for _round in 0..2 {
            let x = a.send(b"x", minute).expect("send");
            assert!(displayed(&b.receive(&x)).is_some());
            let y = b.send(b"y", minute + 1).expect("send");
            assert!(displayed(&a.receive(&y)).is_some());
            minute += 2;
            shown += 2;
        }
        assert_eq!(current_id(&a), current_id(&b), "slots did not converge");
        let ids = [
            a.current.as_ref().unwrap().session_id.clone(),
            a.previous.as_ref().unwrap().session_id.clone(),
        ];
        let smallest = ids
            .iter()
            .min_by_key(|s| vz11::base64_decode(s.as_str()).unwrap())
            .unwrap();
        assert_eq!(&current_id(&a), smallest);
        assert_eq!(shown, 6);
        // And the converged session keeps working both ways.
        let z = a.send(b"z", minute).expect("send");
        assert_eq!(
            displayed(&b.receive(&z)).map(|d| d.1),
            Some(SlotName::Current)
        );
    }
}

/// R-SS1 after a restore of B (same Olm identity): B's reconnect intro becomes A's `current`; A's
/// reply reaches B; a pre-restore message to B's lost session is undecryptable (declared loss).
#[test]
fn restore_renewal() {
    let (mut a, mut b) = pair();
    a.establish(&b.bundle(), Establish::First).expect("A");
    let a1 = a.send(b"a1", 300).expect("send");
    assert!(displayed(&b.receive(&a1)).is_some());
    let b1 = b.send(b"b1", 301).expect("send");
    assert!(displayed(&a.receive(&b1)).is_some());
    let in_transit = a.send(b"before restore", 302).expect("send");

    let old_identity = b.identity();
    b.restore();
    assert_eq!(
        b.identity(),
        old_identity,
        "restore must reproduce the Olm identity"
    );
    b.pin(a.identity());
    b.establish(&a.bundle(), Establish::First)
        .expect("reconnect");
    let r1 = b.send(b"reconnect", 400).expect("send");
    let outcome = a.receive(&r1);
    assert_eq!(
        displayed(&outcome).map(|d| (d.1, d.2)),
        Some((SlotName::Current, true))
    );
    assert_eq!(a.current.as_ref().map(|s| s.role), Some(Role::Responder));
    assert_eq!(a.previous.as_ref().map(|s| s.role), Some(Role::Initiator));

    let reply = a.send(b"welcome back", 401).expect("send");
    assert!(!reply.is_prekey);
    assert_eq!(
        displayed(&b.receive(&reply)).map(|d| d.0),
        Some(b"welcome back".to_vec())
    );
    assert_eq!(
        b.receive(&in_transit),
        Outcome::Dropped(Drop::Library(Code::Undecryptable))
    );
}

/// §22.8.4: a contact's older first flight (sealed before its reset) processed after its newer
/// intro becomes `previous`, not `current`; its PreKey re-send never swaps; without the age rules
/// (mutant MC-32) the old session wins and the user's replies are lost.
#[test]
fn late_first_flight_age_rule() {
    for age_rules in [true, false] {
        let (mut me, mut c) = pair();
        me.age_rules = age_rules;
        c.establish(&me.bundle(), Establish::First).expect("old");
        let old1 = c.send(b"old first flight", 1000).expect("send");
        let old2 = c.send(b"old re-send", 1010).expect("send");
        c.establish(&me.bundle(), Establish::Reset).expect("new");
        let new1 = c.send(b"new first flight", 2000).expect("send");

        assert_eq!(
            displayed(&me.receive(&new1)).map(|d| (d.1, d.2)),
            Some((SlotName::Current, true))
        );
        let late = me.receive(&old1);
        let reply = me.send(b"reply", 2001).expect("send");
        let at_contact = c.receive(&reply);
        if age_rules {
            assert_eq!(
                displayed(&late).map(|d| (d.1, d.2)),
                Some((SlotName::Previous, true))
            );
            // The re-send decrypts on `previous` and does not swap (guard a).
            assert_eq!(
                displayed(&me.receive(&old2)).map(|d| (d.1, d.3)),
                Some((SlotName::Previous, false))
            );
            assert!(
                displayed(&at_contact).is_some(),
                "reply lost with the age rules"
            );
        } else {
            assert_eq!(displayed(&late).map(|d| d.1), Some(SlotName::Current));
            assert_eq!(
                at_contact,
                Outcome::Dropped(Drop::Library(Code::Undecryptable)),
                "MC-32 not detected"
            );
        }
    }
}

/// A third first flight older than both slots is dropped as `stale_session`, with no reuse tuple.
#[test]
fn stale_session_drop() {
    let (mut me, mut c) = pair();
    c.establish(&me.bundle(), Establish::First).expect("s0");
    let s0 = c.send(b"s0", 900).expect("send");
    c.establish(&me.bundle(), Establish::Reset).expect("s1");
    let s1 = c.send(b"s1", 1000).expect("send");
    c.establish(&me.bundle(), Establish::Reset).expect("s2");
    let s2 = c.send(b"s2", 2000).expect("send");
    assert!(displayed(&me.receive(&s2)).is_some());
    assert!(displayed(&me.receive(&s1)).is_some_and(|d| d.1 == SlotName::Previous));
    let before = me.reuse.len();
    assert_eq!(me.receive(&s0), Outcome::Dropped(Drop::StaleSession));
    assert_eq!(me.reuse.len(), before);
}

/// The small-order u-coordinates of Curve25519 (from the 8-torsion subgroup) and their
/// non-canonical encodings (u + p).
fn low_order_points() -> Vec<[u8; 32]> {
    let mut out: Vec<[u8; 32]> = EIGHT_TORSION
        .iter()
        .map(|p| p.to_montgomery().to_bytes())
        .collect();
    let p = {
        let mut p = [0xffu8; 32];
        p[0] = 0xed;
        p[31] = 0x7f;
        p
    };
    for base in out.clone() {
        // u + p fits in 255 bits only for u < 2^255 - p = 19.
        if base[1..].iter().all(|&b| b == 0) && base[0] < 19 {
            let mut sum = p;
            let (v, carry) = sum[0].overflowing_add(base[0]);
            sum[0] = v;
            if carry {
                for byte in sum.iter_mut().skip(1) {
                    let (v, c) = byte.overflowing_add(1);
                    *byte = v;
                    if !c {
                        break;
                    }
                }
            }
            out.push(sum);
        }
    }
    out.push(p);
    out.sort();
    out.dedup();
    out
}

fn chain_key_of(pickle: &[u8]) -> [u8; 32] {
    let v: Value = serde_json::from_slice(pickle).expect("json");
    let items = v
        .pointer("/sending_ratchet/symmetric_key_ratchet/key")
        .and_then(Value::as_array)
        .expect("chain key");
    let mut out = [0u8; 32];
    for (slot, item) in out.iter_mut().zip(items) {
        *slot = item.as_u64().expect("byte") as u8;
    }
    out
}

/// §22.8.2 rule 1: a PreKey message whose inner ratchet key is low-order (re-authenticated with
/// the chain key, as a malicious sender can) creates a session in the library, whose first
/// encryption then fails; GHOST's pre-check refuses it first.
#[test]
fn non_contributory_inner_ratchet_key() {
    macro_rules! check {
        ($olm:path) => {{
            use $olm as olm;
            let a = DehydratedSecrets { curve25519: random_bytes(), ed25519_seed: random_bytes(), fallback: None };
            let f: [u8; 32] = random_bytes();
            let b = DehydratedSecrets { curve25519: random_bytes(), ed25519_seed: random_bytes(), fallback: Some(f) };
            let a_oi = x25519_public(&a.curve25519);
            for point in low_order_points() {
                let (state, _) = olm::session_outbound(&a, &x25519_public(&b.curve25519), &x25519_public(&f)).expect("outbound");
                let chain_key = chain_key_of(&state);
                let out = olm::encrypt(&state, b"hello").expect("encrypt");
                // PreKey = version ‖ 3 × (tag, 0x20, key) ‖ 0x22 ‖ varint(len) ‖ inner message.
                let mut l1 = out.l1.clone();
                let inner_start = 1 + 3 * 34 + 2;
                assert!(l1[inner_start - 1] < 0x80, "short inner message expected");
                let inner_end = l1.len();
                l1[inner_start + 3..inner_start + 35].copy_from_slice(&point);
                let mac = schedule::truncated_mac(&schedule::message_key(&chain_key), &l1[inner_start..inner_end - 8]);
                l1[inner_end - 8..].copy_from_slice(&mac);

                let created = olm::session_inbound_library(&b, &a_oi, &l1).expect("library accepts the session");
                assert_eq!(created.plaintext, b"hello");
                assert_eq!(olm::encrypt(&created.pickle, b"reply").err(), Some(Code::InvalidSession));
                assert_eq!(olm::session_inbound(&b, &a_oi, &l1).err(), Some(Code::InvalidKey));
            }
        }};
    }
    check!(ghost_dm_spike::olm::v11);
    check!(ghost_dm_spike::olm::v10);
}

/// Library errors map to the §2.6 codes on both pins.
#[test]
fn error_codes() {
    macro_rules! check {
        ($olm:path) => {{
            use $olm as olm;
            let a = DehydratedSecrets {
                curve25519: random_bytes(),
                ed25519_seed: random_bytes(),
                fallback: None,
            };
            let f: [u8; 32] = random_bytes();
            let b = DehydratedSecrets {
                curve25519: random_bytes(),
                ed25519_seed: random_bytes(),
                fallback: Some(f),
            };
            let a_oi = x25519_public(&a.curve25519);
            let b_oi = x25519_public(&b.curve25519);
            // INVALID_KEY: outbound to a low-order fallback key or identity.
            for point in low_order_points() {
                assert_eq!(
                    olm::session_outbound(&a, &b_oi, &point).err(),
                    Some(Code::InvalidKey)
                );
                assert_eq!(
                    olm::session_outbound(&a, &point, &x25519_public(&f)).err(),
                    Some(Code::InvalidKey)
                );
            }
            let (state, _) =
                olm::session_outbound(&a, &b_oi, &x25519_public(&f)).expect("outbound");
            let first = olm::encrypt(&state, b"one").expect("encrypt");
            // IDENTITY_MISMATCH: another expected identity.
            assert_eq!(
                olm::session_inbound(&b, &x25519_public(&random_bytes()), &first.l1).err(),
                Some(Code::IdentityMismatch)
            );
            // MISSING_KEY: a generation that does not hold the named fallback key.
            let other = DehydratedSecrets {
                fallback: Some(random_bytes()),
                ..b.clone()
            };
            assert_eq!(
                olm::session_inbound(&other, &a_oi, &first.l1).err(),
                Some(Code::MissingKey)
            );
            let created = olm::session_inbound(&b, &a_oi, &first.l1).expect("inbound");
            // UNDECRYPTABLE: a flipped ciphertext byte.
            let second = olm::encrypt(&first.pickle, b"two").expect("encrypt");
            let mut tampered = second.l1.clone();
            let n = tampered.len();
            tampered[n - 12] ^= 1;
            assert_eq!(
                olm::decrypt(&created.pickle, &tampered, true).err(),
                Some(Code::Undecryptable)
            );
            // DUPLICATE_OR_LOST: the same message twice.
            let once = olm::decrypt(&created.pickle, &second.l1, true).expect("decrypts");
            assert_eq!(
                olm::decrypt(&once.pickle, &second.l1, true).err(),
                Some(Code::DuplicateOrLost)
            );
            // GAP_TOO_BIG: a forward gap above 2 000 (the sender's index moved in its pickle).
            let jumped = sizes::set_sending_index(&second.pickle, 2 + 2001).expect("edit");
            let far = olm::encrypt(&jumped, b"far").expect("encrypt");
            assert_eq!(
                olm::decrypt(&once.pickle, &far.l1, true).err(),
                Some(Code::GapTooBig)
            );
            // STATE_CORRUPT: a pickle that does not parse.
            assert_eq!(
                olm::decrypt(b"not json", &second.l1, true).err(),
                Some(Code::StateCorrupt)
            );
        }};
    }
    check!(ghost_dm_spike::olm::v11);
    check!(ghost_dm_spike::olm::v10);
}

#[allow(dead_code)]
fn unused(_: Envelope) {}
