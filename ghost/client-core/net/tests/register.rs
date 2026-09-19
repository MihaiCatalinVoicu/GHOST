//! `NamespaceClient::register_key`'s checks against the real relay (Phase 9 design §4.4, §4.8): a
//! real `ghost_relay_node::Relay` of the test schedule serving slot 1 as `relay-b`, called
//! in-process through the `RegisterRpc` seam, with a write capability the client redeemed itself
//! from a pinned token of `protocol/test-vectors/redeem.txt`.
//!
//! The relay's own rules are pinned by `protocol/test-vectors/register.txt` (the Rust and Kotlin
//! replayers). What is checked here is the client's side: the request it builds, the answers it
//! accepts, and the answers it refuses as `malformed_response` — an `OK` whose validity is not the
//! period's, a `WRONG_PERIOD` carrying one, a result this build does not know, and a relay week or
//! minute that disagrees with the device clock.

mod common;

use common::*;
use ghost_client_net::categories::{for_relay, MALFORMED_RESPONSE, UNAUTHORIZED};
use ghost_client_net::namespace_client::{
    redeem_with, register_with, registration_valid_until, RegisterOutcome,
};
use ghost_client_net::RelayError;
use ghost_entitlement::grid;
use ghost_relay_api::proto::{Capability, RegisterKeyResponse, RegisterResult, StoreBlobRequest};
use ghost_relay_api::{BearerCredential, BearerKind, PROTOCOL_VERSION, REQUEST_ID_BYTES};
use sha2::{Digest, Sha256};

const NS: [u8; 32] = [0xA1; 32];
const OTHER_NS: [u8; 32] = [0xB2; 32];
/// The ES slot `relay-b` holds in the test schedule.
const SLOT: u8 = 1;
const WEEK: u64 = 2959;

/// The vector file's relay: slot 1 served by relay-b, clock at 2959 + 1 day.
fn relay_b(dir: &std::path::Path) -> InProcessRelay {
    let now = at(WEEK, 86_400);
    InProcessRelay::new(
        open_relay(dir, schedule().clone(), SLOT, "ghost/test/relay-b", now),
        now,
    )
}

/// A bearer secret of the test, and the credential and verifier built from it exactly as design
/// §4.3 states (an independent implementation of `ghost_relay_capability::bearer_verifier`).
fn secret(label: &str) -> [u8; 32] {
    Sha256::digest(format!("ghost/test/secret/{label}")).into()
}

fn credential(kind: BearerKind, namespace: [u8; 32], secret: [u8; 32]) -> BearerCredential {
    BearerCredential {
        kind,
        slot: SLOT,
        namespace,
        secret,
    }
}

fn verifier(c: &BearerCredential) -> [u8; 32] {
    let label: &[u8] = match c.kind {
        BearerKind::Read => b"ghost/v1/read-verifier",
        BearerKind::Deposit => b"ghost/v1/deposit-verifier",
        BearerKind::Fetch => b"ghost/v1/fetch-verifier",
    };
    let mut h = Sha256::new();
    h.update(label);
    h.update([c.slot]);
    h.update(c.namespace);
    h.update(c.secret);
    h.finalize().into()
}

/// The write capability of `NS` at this relay for week 2959, redeemed from the pinned token.
async fn write_capability(relay: &mut InProcessRelay) -> Vec<u8> {
    let addr = relay_address("ghost/test/relay-b", 443);
    let now = relay.now;
    let ok = redeem_with(relay, schedule(), &addr, NS, &pinned("a1"), [1; 16], now)
        .await
        .unwrap();
    ok.capability.expect("the relay minted a capability")
}

#[tokio::test]
async fn ok_retry_next_period_and_wrong_period() {
    let dir = tempfile::tempdir().unwrap();
    let mut relay = relay_b(dir.path());
    let now = relay.now;
    let capability = write_capability(&mut relay).await;
    let deposit = credential(BearerKind::Deposit, NS, secret("deposit"));

    let ok = register_with(
        &mut relay,
        NS,
        capability.clone(),
        WEEK,
        BearerKind::Deposit,
        verifier(&deposit),
        [7; REQUEST_ID_BYTES],
        now,
    )
    .await
    .unwrap();
    assert_eq!(ok.result, RegisterResult::Ok);
    assert_eq!((ok.relay_period_id, ok.relay_minute), (WEEK, now / 60));
    assert_eq!(ok.valid_until_unix, grid::week_start(WEEK + 2) + 3_600);
    assert_eq!(ok.valid_until_unix, registration_valid_until(WEEK));
    let p = ok.pack();
    assert_eq!(p.len(), 25);
    assert_eq!(p[0], 1);
    assert_eq!(&p[1..9], &WEEK.to_be_bytes());
    assert_eq!(&p[9..17], &(now / 60).to_be_bytes());
    assert_eq!(&p[17..25], &ok.valid_until_unix.to_be_bytes());

    // The relay recorded exactly what the client asked for: the verifier, the capability's quota,
    // one serial. The secret never left the device.
    let record = relay
        .relay
        .key_store()
        .record(&NS, WEEK, BearerKind::Deposit.byte(), &verifier(&deposit))
        .unwrap()
        .expect("a record");
    assert_eq!(
        record.quota_bytes,
        schedule().constants().capability_quota_bytes
    );
    assert_eq!(record.serials.len(), 1);
    assert_eq!(record.valid_until, ok.valid_until_unix);

    // An identical retry is the identical answer; the next period is accepted and lives a week
    // longer; the period after it is WRONG_PERIOD with no validity (§4.4 point 3).
    let again = register_with(
        &mut relay,
        NS,
        capability.clone(),
        WEEK,
        BearerKind::Deposit,
        verifier(&deposit),
        [7; REQUEST_ID_BYTES],
        now,
    )
    .await
    .unwrap();
    assert_eq!(again, ok);
    let next = register_with(
        &mut relay,
        NS,
        capability.clone(),
        WEEK + 1,
        BearerKind::Deposit,
        verifier(&deposit),
        [8; REQUEST_ID_BYTES],
        now,
    )
    .await
    .unwrap();
    assert_eq!(next.result, RegisterResult::Ok);
    assert_eq!(next.valid_until_unix, registration_valid_until(WEEK + 1));
    let too_far = register_with(
        &mut relay,
        NS,
        capability.clone(),
        WEEK + 2,
        BearerKind::Deposit,
        verifier(&deposit),
        [9; REQUEST_ID_BYTES],
        now,
    )
    .await
    .unwrap();
    assert_eq!(too_far.result, RegisterResult::WrongPeriod);
    assert_eq!(too_far.valid_until_unix, 0);
    assert_eq!(too_far.pack()[0], 2);
    assert!(relay
        .relay
        .key_store()
        .record(
            &NS,
            WEEK + 2,
            BearerKind::Deposit.byte(),
            &verifier(&deposit)
        )
        .unwrap()
        .is_none());

    // The registration is usable: a store presenting the credential of that secret is accepted by
    // the relay, and one presenting another secret is not (the verifier is what authorizes).
    let data = vec![0x6Bu8; 4096];
    let store = |c: &BearerCredential| StoreBlobRequest {
        version: PROTOCOL_VERSION,
        blob_hash: Sha256::digest(&data).to_vec(),
        data: data.clone(),
        capability: Some(Capability {
            token: c.encode().to_vec(),
        }),
        ttl_seconds: 604_800,
        request_id: vec![0x5A; REQUEST_ID_BYTES],
        namespace_id: NS.to_vec(),
    };
    assert!(relay.relay.store_at(store(&deposit), now).is_ok());
    let guessed = credential(BearerKind::Deposit, NS, secret("guess"));
    assert_eq!(
        relay
            .relay
            .store_at(store(&guessed), now)
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    assert_eq!(relay.calls, 5);
}

#[tokio::test]
async fn refusals_carry_one_category_and_record_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let mut relay = relay_b(dir.path());
    let now = relay.now;
    let capability = write_capability(&mut relay).await;
    let read = credential(BearerKind::Read, NS, secret("read"));
    let mut forged = capability.clone();
    forged[97] ^= 1; // the last MAC byte
    let foreign = {
        let mut r = relay_b(dir.path().join("other").as_path());
        // A capability minted by another relay (another key) for the same namespace.
        write_capability(&mut r).await
    };
    for (why, token) in [
        ("no capability", Vec::new()),
        ("a forged MAC", forged),
        ("another relay's capability", foreign),
        ("a truncated capability", capability[..97].to_vec()),
    ] {
        let err = register_with(
            &mut relay,
            NS,
            token,
            WEEK,
            BearerKind::Read,
            verifier(&read),
            [3; REQUEST_ID_BYTES],
            now,
        )
        .await
        .unwrap_err();
        assert_eq!(for_relay(&err), UNAUTHORIZED, "{why}: {err:?}");
    }
    // A capability of another namespace is refused by the relay as well (the T21 guard of
    // `NamespaceClient` refuses it before any I/O; here the seam is called directly).
    let err = register_with(
        &mut relay,
        OTHER_NS,
        capability,
        WEEK,
        BearerKind::Read,
        verifier(&read),
        [4; REQUEST_ID_BYTES],
        now,
    )
    .await
    .unwrap_err();
    assert_eq!(for_relay(&err), UNAUTHORIZED);
    assert!(relay
        .relay
        .key_store()
        .record(&NS, WEEK, BearerKind::Read.byte(), &verifier(&read))
        .unwrap()
        .is_none());
    assert_eq!(relay.relay.key_store().counts().unwrap(), (0, 0));
}

#[tokio::test]
async fn answers_that_disagree_with_the_request_are_malformed() {
    let dir = tempfile::tempdir().unwrap();
    let mut relay = relay_b(dir.path());
    let now = relay.now;
    let capability = write_capability(&mut relay).await;
    let fetch = credential(BearerKind::Fetch, NS, secret("fetch"));

    async fn register(
        relay: &mut InProcessRelay,
        capability: Vec<u8>,
        verifier: [u8; 32],
        now: u64,
    ) -> Result<RegisterOutcome, RelayError> {
        register_with(
            relay,
            NS,
            capability,
            WEEK,
            BearerKind::Fetch,
            verifier,
            [5; REQUEST_ID_BYTES],
            now,
        )
        .await
    }
    let v = verifier(&fetch);
    /// One rewrite of a `RegisterKey` answer (a hostile relay).
    type Tamper = Box<dyn Fn(&mut RegisterKeyResponse) + Send>;
    let tampered: Vec<(&str, Tamper)> = vec![
        (
            "an hour more validity than the period allows",
            Box::new(|r: &mut RegisterKeyResponse| r.valid_until_unix += 3_600),
        ),
        (
            "a week less validity",
            Box::new(|r: &mut RegisterKeyResponse| r.valid_until_unix -= 604_800),
        ),
        (
            "OK without validity",
            Box::new(|r: &mut RegisterKeyResponse| r.valid_until_unix = 0),
        ),
        (
            "WRONG_PERIOD carrying a validity",
            Box::new(|r: &mut RegisterKeyResponse| {
                r.result = RegisterResult::WrongPeriod as i32;
            }),
        ),
        (
            "an unspecified result",
            Box::new(|r: &mut RegisterKeyResponse| {
                r.result = RegisterResult::Unspecified as i32;
                r.valid_until_unix = 0;
            }),
        ),
        (
            "a result this build does not know",
            Box::new(|r: &mut RegisterKeyResponse| r.result = 7),
        ),
        (
            "a relay week two weeks from ours",
            Box::new(|r: &mut RegisterKeyResponse| {
                r.relay_period_id = WEEK + 2;
                r.relay_minute = (grid::week_start(WEEK + 2) + 60) / 60;
            }),
        ),
        (
            "a minute outside the answered week",
            Box::new(|r: &mut RegisterKeyResponse| {
                r.relay_minute = grid::week_start(WEEK) / 60 - 1
            }),
        ),
        (
            "a minute that overflows",
            Box::new(|r: &mut RegisterKeyResponse| r.relay_minute = u64::MAX),
        ),
    ];
    for (why, hook) in tampered {
        relay.tamper_register = Some(hook);
        let err = register(&mut relay, capability.clone(), v, now)
            .await
            .unwrap_err();
        assert_eq!(for_relay(&err), MALFORMED_RESPONSE, "{why}: {err:?}");
    }
    // Without the hook the same call is the honest OK, so every refusal above is the tampering.
    relay.tamper_register = None;
    let ok: RegisterOutcome = register(&mut relay, capability, v, now).await.unwrap();
    assert_eq!(ok.result, RegisterResult::Ok);
    assert_eq!(ok.valid_until_unix, registration_valid_until(WEEK));
}
