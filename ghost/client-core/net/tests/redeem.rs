//! `NamespaceClient::redeem`'s checks against the real relay (design §10.9): a real
//! `ghost_relay_node::Relay` of the test schedule serving slot 1 as `relay-b`, called in-process
//! through the `RedeemRpc` seam, with the pinned tokens of `protocol/test-vectors/redeem.txt`.
//! Tokens bound elsewhere never leave the device (mutant M6); answers that disagree with the ES are
//! `malformed_response`.

mod common;

use common::*;
use ghost_client_net::categories::{for_relay, MALFORMED_RESPONSE, UNAUTHORIZED};
use ghost_client_net::namespace_client::{redeem_binding, redeem_with, RedeemBinding};
use ghost_client_net::{NamespaceClient, RelayError, TorTransport, TransportConfig};
use ghost_entitlement::grid;
use ghost_entitlement::Kind;
use ghost_relay_api::proto::{Capability, RedeemResult, RedeemTokenResponse};
use ghost_relay_api::{capability_header, CapabilityKind};

const NS: [u8; 32] = [0xA1; 32];
const OTHER_NS: [u8; 32] = [0xB2; 32];

/// The vector file's relay: slot 1 served by relay-b, clock at 2959 + 1 day.
fn relay_b(dir: &std::path::Path) -> InProcessRelay {
    let now = at(2959, 86_400);
    InProcessRelay::new(
        open_relay(dir, schedule().clone(), 1, "ghost/test/relay-b", now),
        now,
    )
}

#[tokio::test]
async fn ok_identical_retry_replay_and_wrong_period() {
    let dir = tempfile::tempdir().unwrap();
    let mut relay = relay_b(dir.path());
    let now = relay.now;
    let addr = relay_address("ghost/test/relay-b", 443);
    let s = schedule();
    let a1 = pinned("a1");
    assert_eq!(
        redeem_binding(s, &addr, &a1).unwrap(),
        RedeemBinding {
            week: 2959,
            slot: 1
        }
    );

    let ok = redeem_with(&mut relay, s, &addr, NS, &a1, [1; 16], now)
        .await
        .unwrap();
    assert_eq!(ok.result, RedeemResult::Ok);
    assert_eq!((ok.relay_period_id, ok.relay_minute), (2959, now / 60));
    let cap = ok.capability.clone().unwrap();
    assert_eq!(cap.len(), 98);
    let header = capability_header(&cap).unwrap();
    assert_eq!(header.kind, CapabilityKind::Write);
    assert_eq!(header.namespace, NS);
    assert_eq!(header.quota_bytes, s.constants().capability_quota_bytes);
    assert_eq!(ok.expiry_unix, grid::week_start(2960) + 3_600);
    let p = ok.pack();
    assert_eq!(p.len(), 25 + 98);
    assert_eq!(p[0], 1);
    assert_eq!(&p[1..9], &2959u64.to_be_bytes());
    assert_eq!(&p[9..17], &(now / 60).to_be_bytes());
    assert_eq!(&p[17..25], &ok.expiry_unix.to_be_bytes());
    assert_eq!(&p[25..], &cap[..]);

    // An identical retry gets the identical capability; another namespace is REPLAYED.
    let again = redeem_with(&mut relay, s, &addr, NS, &a1, [1; 16], now)
        .await
        .unwrap();
    assert_eq!(again, ok);
    let replayed = redeem_with(&mut relay, s, &addr, OTHER_NS, &a1, [2; 16], now)
        .await
        .unwrap();
    assert_eq!(replayed.result, RedeemResult::Replayed);
    assert_eq!(
        (replayed.capability.as_deref(), replayed.expiry_unix),
        (None, 0)
    );
    assert_eq!(replayed.pack().len(), 25);
    // A token of week 2958 one day into 2959: WRONG_PERIOD, nothing recorded.
    let late = redeem_with(&mut relay, s, &addr, NS, &pinned("b0"), [3; 16], now)
        .await
        .unwrap();
    assert_eq!(late.result, RedeemResult::WrongPeriod);
    assert_eq!(late.pack()[0], 3);
    assert_eq!(relay.calls, 4);

    // A relay listed under another port for the same service key is the same relay.
    let other_port = relay_address("ghost/test/relay-b", 9001);
    assert!(redeem_binding(s, &other_port, &a1).is_ok());
}

#[tokio::test]
async fn tokens_bound_elsewhere_never_leave_the_device() {
    let dir = tempfile::tempdir().unwrap();
    let mut relay = relay_b(dir.path());
    let now = relay.now;
    let s = schedule();
    let at_b = relay_address("ghost/test/relay-b", 443);
    let at_a = relay_address("ghost/test/relay-a", 443);
    let at_c = relay_address("ghost/test/relay-c", 443);
    let unlisted = relay_address("ghost/test/relay-z", 443);
    let a1 = pinned("a1");
    let mut authenticator = a1.clone();
    authenticator[200] ^= 1;
    let mut challenge = a1.clone();
    challenge[40] ^= 1;
    let mut token_type = a1.clone();
    token_type[1] = 3;
    let revoked = resigned(|c| c.revoked = vec![(Kind::Access, 2959)]);
    let cases: Vec<(
        &str,
        &ghost_entitlement::Schedule,
        &ghost_client_net::OnionAddress,
        Vec<u8>,
    )> = vec![
        ("a slot-0 token at the slot-1 relay", s, &at_b, pinned("s0")),
        ("a slot-1 token at the slot-0 relay", s, &at_a, a1.clone()),
        (
            "a slot-1 token at a relay the ES does not list",
            s,
            &unlisted,
            a1.clone(),
        ),
        (
            "a slot-2 token of relay-c at relay-b",
            s,
            &at_b,
            pinned("m1"),
        ),
        ("a slot-1 token at relay-c", s, &at_c, a1.clone()),
        ("an invite token", s, &at_b, pinned("i1")),
        ("a credit token", s, &at_b, pinned("k1")),
        ("signed by an invite key", s, &at_b, pinned("x1")),
        ("signed by another week's key", s, &at_b, pinned("y1")),
        ("a key that is no ES key", s, &at_b, pinned("n1")),
        ("a flipped authenticator", s, &at_b, authenticator),
        ("a flipped challenge", s, &at_b, challenge),
        ("token type 0x0003", s, &at_b, token_type),
        ("353 bytes", s, &at_b, a1[..353].to_vec()),
        ("355 bytes", s, &at_b, [&a1[..], &[0]].concat()),
        ("a revoked week", &revoked, &at_b, a1.clone()),
    ];
    for (why, schedule, addr, token) in cases {
        let r = redeem_with(&mut relay, schedule, addr, NS, &token, [4; 16], now).await;
        assert!(
            matches!(r, Err(RelayError::InvalidArgument)),
            "{why}: {r:?}"
        );
    }
    assert_eq!(relay.calls, 0, "no token bound elsewhere reached the relay");
}

/// `NamespaceClient::redeem`, the one redemption path that opens a Tor connection, binds tokens
/// with the ES built into the library and takes no schedule: a real token of the test schedule,
/// at the relay that schedule assigns it to, is refused before any I/O (had the client tried to
/// connect, the transport, never bootstrapped, would have answered `not_bootstrapped`).
#[tokio::test(flavor = "multi_thread")]
async fn redemption_over_tor_binds_with_the_embedded_schedule_only() {
    let dir = tempfile::tempdir().unwrap();
    let t = TorTransport::create(&TransportConfig {
        state_dir: dir.path().join("state"),
        cache_dir: dir.path().join("cache"),
        bridge_lines: vec![],
    })
    .unwrap();
    let addr = relay_address("ghost/test/relay-b", 443);
    let a1 = pinned("a1");
    assert!(
        redeem_binding(schedule(), &addr, &a1).is_ok(),
        "bound by the test ES"
    );
    let r = NamespaceClient::over_tor(&t, &addr, NS)
        .redeem(&a1, [8; 16])
        .await;
    assert!(matches!(r, Err(RelayError::InvalidArgument)), "{r:?}");
}

/// One onion service under two slots in one week: two relay processes behind one onion service on
/// different ports, which relays allow (they match their own onion by service key, §19.21 point
/// 2). A token binds to the slot the ES lists under the relay's exact address and that the token
/// was made for: a paid token is redeemable at its own relay, and the other slot's token never
/// leaves the device (it would be refused there and deleted). An unlisted port of that service key
/// names no slot: which process answers there is unknown.
#[tokio::test]
async fn one_service_key_under_two_slots_binds_by_address_and_token() {
    let at_443 = relay_address("ghost/test/relay-b", 443);
    let at_444 = relay_address("ghost/test/relay-b", 444);
    let at_9001 = relay_address("ghost/test/relay-b", 9001);
    // Slot 0 moves behind relay-b's onion service on port 444; slot 1 stays relay-b:443.
    let shared = resigned(|c| {
        for s in c.slots.iter_mut().filter(|s| s.slot == 0) {
            s.onion = at_444.to_string();
        }
    });
    let (a1, s0) = (pinned("a1"), pinned("s0"));
    assert_eq!(
        redeem_binding(&shared, &at_443, &a1).unwrap(),
        RedeemBinding {
            week: 2959,
            slot: 1
        }
    );
    assert_eq!(
        redeem_binding(&shared, &at_444, &s0).unwrap(),
        RedeemBinding {
            week: 2959,
            slot: 0
        }
    );
    for (why, addr, token) in [
        ("a slot-0 token at the slot-1 port", &at_443, &s0),
        ("a slot-1 token at the slot-0 port", &at_444, &a1),
        ("a slot-1 token at an unlisted port", &at_9001, &a1),
        ("a slot-0 token at an unlisted port", &at_9001, &s0),
    ] {
        let r = redeem_binding(&shared, addr, token);
        assert!(
            matches!(r, Err(RelayError::InvalidArgument)),
            "{why}: {r:?}"
        );
    }

    // End to end: the slot-1 relay behind :443 redeems a1; s0 never reaches it.
    let dir = tempfile::tempdir().unwrap();
    let now = at(2959, 86_400);
    let mut relay = InProcessRelay::new(
        open_relay(dir.path(), shared.clone(), 1, "ghost/test/relay-b", now),
        now,
    );
    let ok = redeem_with(&mut relay, &shared, &at_443, NS, &a1, [9; 16], now)
        .await
        .unwrap();
    assert_eq!(ok.result, RedeemResult::Ok);
    let r = redeem_with(&mut relay, &shared, &at_443, NS, &s0, [9; 16], now).await;
    assert!(matches!(r, Err(RelayError::InvalidArgument)), "{r:?}");
    assert_eq!(relay.calls, 1);
}

#[tokio::test]
async fn hostile_relay_answers_are_malformed() {
    let dir = tempfile::tempdir().unwrap();
    let mut relay = relay_b(dir.path());
    let now = relay.now;
    let s = schedule();
    let addr = relay_address("ghost/test/relay-b", 443);
    let a1 = pinned("a1");
    type Hook = Box<dyn Fn(&mut RedeemTokenResponse) + Send>;
    let edit_cap = |f: fn(&mut Vec<u8>)| -> Hook {
        Box::new(move |a: &mut RedeemTokenResponse| {
            if let Some(c) = a.capability.as_mut() {
                f(&mut c.token)
            }
        })
    };
    let cases: Vec<(&str, Hook)> = vec![
        (
            "a v1 capability",
            edit_cap(|c| {
                let v1 = [&[1u8][..], &c[1..50], &c[66..98]].concat();
                *c = v1;
            }),
        ),
        ("another namespace", edit_cap(|c| c[2] ^= 1)),
        ("another quota", edit_cap(|c| c[41] ^= 1)),
        ("an expiry one second off", edit_cap(|c| c[49] ^= 1)),
        ("a read capability", edit_cap(|c| c[1] = 1)),
        (
            "97 bytes",
            edit_cap(|c| {
                c.pop();
            }),
        ),
        ("OK without a capability", Box::new(|a| a.capability = None)),
        (
            "REPLAYED with a capability",
            Box::new(|a| a.result = RedeemResult::Replayed as i32),
        ),
        (
            "WRONG_PERIOD with a capability",
            Box::new(|a| a.result = RedeemResult::WrongPeriod as i32),
        ),
        ("unspecified result", Box::new(|a| a.result = 0)),
        ("unknown result", Box::new(|a| a.result = 7)),
        (
            "a period two weeks ahead",
            Box::new(|a| {
                a.relay_period_id += 2;
                a.relay_minute += 2 * 10_080;
            }),
        ),
        (
            "a minute outside the period",
            Box::new(|a| a.relay_minute += 10_080),
        ),
        (
            "a minute that overflows",
            Box::new(|a| a.relay_minute = u64::MAX),
        ),
    ];
    for (why, hook) in cases {
        relay.tamper = Some(hook);
        let r = redeem_with(&mut relay, s, &addr, NS, &a1, [5; 16], now).await;
        match r {
            Err(e @ RelayError::Malformed) => assert_eq!(for_relay(&e), MALFORMED_RESPONSE),
            other => panic!("{why}: expected malformed_response, got {other:?}"),
        }
    }
    // A REPLAYED answer whose capability field is present but for another namespace is refused
    // too; an honest REPLAYED answer (no capability) is accepted.
    relay.tamper = Some(Box::new(|a| {
        a.result = RedeemResult::Replayed as i32;
        a.capability = Some(Capability { token: vec![0; 98] });
    }));
    assert!(matches!(
        redeem_with(&mut relay, s, &addr, NS, &a1, [5; 16], now).await,
        Err(RelayError::Malformed)
    ));
}

#[tokio::test]
async fn the_relay_week_must_be_within_one_week_of_the_client_week() {
    let dir = tempfile::tempdir().unwrap();
    let mut relay = relay_b(dir.path());
    let s = schedule();
    let addr = relay_address("ghost/test/relay-b", 443);
    let a1 = pinned("a1");
    // The relay answers in week 2959. A client clock one week behind or ahead accepts the
    // answer; two weeks off, the answer is refused.
    for client in [at(2958, 100), at(2960, 100)] {
        let r = redeem_with(&mut relay, s, &addr, NS, &a1, [6; 16], client).await;
        assert_eq!(r.unwrap().result, RedeemResult::Ok);
    }
    for client in [at(2957, 100), at(2961, 100)] {
        let r = redeem_with(&mut relay, s, &addr, NS, &a1, [6; 16], client).await;
        assert!(matches!(r, Err(RelayError::Malformed)), "{r:?}");
    }
}

#[tokio::test]
async fn a_relay_refusing_the_token_maps_to_unauthorized() {
    // The ES lists relay-b for slot 1, but the relay behind that address serves slot 0 as relay-a:
    // it refuses the token (PERMISSION_DENIED, rejected_token).
    let dir = tempfile::tempdir().unwrap();
    let now = at(2959, 86_400);
    let mut relay = InProcessRelay::new(
        open_relay(dir.path(), schedule().clone(), 0, "ghost/test/relay-a", now),
        now,
    );
    let addr = relay_address("ghost/test/relay-b", 443);
    let e = redeem_with(
        &mut relay,
        schedule(),
        &addr,
        NS,
        &pinned("a1"),
        [7; 16],
        now,
    )
    .await
    .unwrap_err();
    assert!(matches!(&e, RelayError::Rpc(s) if s.code() == tonic::Code::PermissionDenied));
    assert_eq!(for_relay(&e), UNAUTHORIZED);
    assert_eq!(relay.calls, 1);
}
