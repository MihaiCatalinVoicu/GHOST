//! Key registration at the relay beyond the conformance vectors (Phase 9 design §4.4–§4.6, §16.2
//! "relay RegisterKey unit, restart and loss tests"): `keys.redb` is created at every start and is
//! never a reason to refuse one, a nullifier reset leaves it untouched, a file of another schema
//! is refused, concurrent registrations accumulate exactly, and one capability racing to register
//! two verifiers binds exactly one.

mod common;

use common::{at, namespace, policy, request_id, test_schedule, VirtualClock, RELAY_B};
use ghost_relay_api::proto::{Capability as CapabilityMessage, RegisterKeyRequest, RegisterResult};
use ghost_relay_api::{BearerCredential, BearerKind, PROTOCOL_VERSION};
use ghost_relay_capability::{bearer_verifier, Capability, Kind, RelayKey};
use ghost_relay_node::redeem::capability_expiry;
use ghost_relay_node::register::KEYS_FILE;
use ghost_relay_node::{NullifierMode, Relay, RelayConfig};
use std::path::Path;
use std::sync::Arc;
use tonic::Code;

const KEY: [u8; 32] = [0x42; 32];

fn open(dir: &Path, clock: &VirtualClock, mode: NullifierMode) -> Arc<Relay> {
    Relay::open(
        dir,
        RelayKey::from_bytes(KEY),
        RelayConfig {
            entitlement: Some(policy(test_schedule(), 1, RELAY_B, mode)),
            clock: clock.clock(),
            ..RelayConfig::default()
        },
        None,
    )
    .unwrap()
}

fn capability(ns: [u8; 32], week: u64, serial: u8) -> Vec<u8> {
    RelayKey::from_bytes(KEY).mint_v2(
        &Capability {
            kind: Kind::Write,
            namespace: ns,
            quota_bytes: 1_000,
            expiry_unix: capability_expiry(week),
        },
        &[serial; 16],
    )
}

fn deposit_verifier(ns: [u8; 32], secret: u8) -> [u8; 32] {
    bearer_verifier(&BearerCredential {
        kind: BearerKind::Deposit,
        slot: 1,
        namespace: ns,
        secret: [secret; 32],
    })
}

fn register(
    relay: &Relay,
    ns: [u8; 32],
    verifier: [u8; 32],
    cap: Vec<u8>,
    now: u64,
) -> Result<i32, Code> {
    relay
        .register_key_at(
            RegisterKeyRequest {
                version: PROTOCOL_VERSION,
                namespace_id: ns.to_vec(),
                period_id: 2959,
                kind: BearerKind::Deposit.byte().into(),
                verifier: verifier.to_vec(),
                capability: Some(CapabilityMessage { token: cap }),
                request_id: request_id("r"),
            },
            now,
        )
        .map(|r| r.result)
        .map_err(|s| s.code())
}

#[test]
fn keys_redb_is_soft_state_created_at_start_and_untouched_by_a_nullifier_reset() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let clock = VirtualClock::new(at("2959+86400"));
    let now = clock.get();
    let ns = namespace("inbox");
    let verifier = deposit_verifier(ns, 1);
    let relay = open(&data, &clock, NullifierMode::Create);
    assert!(data.join(KEYS_FILE).exists(), "created at the first start");
    assert_eq!(
        register(&relay, ns, verifier, capability(ns, 2959, 1), now),
        Ok(RegisterResult::Ok as i32)
    );
    drop(relay);

    // A reset of the nullifier store (runbook O1) keeps every registration.
    let relay = open(&data, &clock, NullifierMode::Reset);
    let record = relay
        .key_store()
        .record(&ns, 2959, BearerKind::Deposit.byte(), &verifier)
        .unwrap()
        .expect("kept across a nullifier reset");
    assert_eq!(record.serials.len(), 1);
    drop(relay);

    // A lost keys.redb next to an existing relay key and nullifier store is no refusal to start:
    // the relay creates it empty.
    std::fs::remove_file(data.join(KEYS_FILE)).unwrap();
    let relay = open(&data, &clock, NullifierMode::Existing);
    assert!(data.join(KEYS_FILE).exists());
    assert_eq!(relay.key_store().counts().unwrap(), (0, 0));
    drop(relay);

    // Without redemption too.
    let plain = dir.path().join("plain");
    drop(
        Relay::open(
            &plain,
            RelayKey::from_bytes(KEY),
            RelayConfig::default(),
            None,
        )
        .unwrap(),
    );
    assert!(plain.join(KEYS_FILE).exists());
}

#[test]
fn a_keys_file_of_another_schema_is_a_refusal_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    {
        let db = redb::Database::create(data.join(KEYS_FILE)).unwrap();
        let txn = db.begin_write().unwrap();
        txn.open_table(redb::TableDefinition::<&str, u64>::new("meta"))
            .unwrap()
            .insert("schema_version", 7)
            .unwrap();
        txn.commit().unwrap();
    }
    let clock = VirtualClock::new(at("2959+86400"));
    let opened = Relay::open(
        &data,
        RelayKey::from_bytes(KEY),
        RelayConfig {
            entitlement: Some(policy(test_schedule(), 1, RELAY_B, NullifierMode::Create)),
            clock: clock.clock(),
            ..RelayConfig::default()
        },
        None,
    );
    assert!(
        opened.is_err(),
        "a keys.redb of another schema is never reinterpreted"
    );
}

#[test]
fn concurrent_registrations_accumulate_exactly_and_bind_one_verifier_per_capability() {
    let dir = tempfile::tempdir().unwrap();
    let clock = VirtualClock::new(at("2959+86400"));
    let now = clock.get();
    let relay = open(&dir.path().join("data"), &clock, NullifierMode::Create);
    let ns = namespace("inbox");
    let verifier = deposit_verifier(ns, 1);

    // Four capabilities register one verifier at once: four credits, whatever the order.
    let threads: Vec<_> = (1..=4u8)
        .map(|serial| {
            let relay = Arc::clone(&relay);
            std::thread::spawn(move || {
                register(&relay, ns, verifier, capability(ns, 2959, serial), now)
            })
        })
        .collect();
    for t in threads {
        assert_eq!(t.join().unwrap(), Ok(RegisterResult::Ok as i32));
    }
    let record = relay
        .key_store()
        .record(&ns, 2959, BearerKind::Deposit.byte(), &verifier)
        .unwrap()
        .unwrap();
    assert_eq!((record.serials.len(), record.quota_bytes), (4, 4_000));

    // One capability races to register eight verifiers: exactly one is bound.
    let cap = capability(ns, 2959, 9);
    let threads: Vec<_> = (10..18u8)
        .map(|secret| {
            let relay = Arc::clone(&relay);
            let cap = cap.clone();
            std::thread::spawn(move || {
                let v = deposit_verifier(ns, secret);
                (v, register(&relay, ns, v, cap, now))
            })
        })
        .collect();
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    let bound: Vec<_> = results
        .iter()
        .filter(|(_, r)| *r == Ok(RegisterResult::Ok as i32))
        .collect();
    assert_eq!(bound.len(), 1, "{results:?}");
    assert!(results
        .iter()
        .all(|(_, r)| *r == Ok(RegisterResult::Ok as i32) || *r == Err(Code::PermissionDenied)));
    let winner = bound[0].0;
    for (v, _) in &results {
        let record = relay
            .key_store()
            .record(&ns, 2959, BearerKind::Deposit.byte(), v)
            .unwrap();
        assert_eq!(record.is_some(), *v == winner);
    }
    // 4 serials of the first verifier, 1 of the winner.
    assert_eq!(relay.key_store().counts().unwrap(), (2, 5));
}
