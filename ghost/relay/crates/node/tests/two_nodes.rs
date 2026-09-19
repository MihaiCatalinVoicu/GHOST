//! Two-node integration suite (Phase 5 exit gate: "two-node fault and abuse suite; relay-capture
//! green"). Runs real gRPC servers on loopback, exercises store/get/check/list/gossip, the abuse
//! controls, a failover (node A stops, node B serves), and validates node A's privacy capture
//! against the normative allowed-observables schema (T1). Phase 8 (design §10.6, §14.1) adds token
//! redemption over gRPC: ok, identical retry, replay to another namespace, wrong slot, wrong week
//! and forged, with captures holding only the capability's scope hash, never the token, its
//! authenticator or the minted capability. Phase 9 (design §4.7, §10.2) adds key registrations,
//! deposits, reads and fetches with bearer credentials v3, and exact TTL buckets, with their
//! captures.

mod common;

use common::{
    at, namespace, outcome, policy, request, request_id, test_schedule, token, Outcome,
    VirtualClock, RELAY_A, RELAY_B,
};
use ghost_relay_api::proto::relay_service_client::RelayServiceClient;
use ghost_relay_api::proto::relay_service_server::RelayServiceServer;
use ghost_relay_api::proto::*;
use ghost_relay_api::{MAX_BATCH, PROTOCOL_VERSION};
use ghost_relay_capability::{Kind, RelayKey};
use ghost_relay_node::{EntitlementPolicy, NullifierMode, Relay, RelayConfig, RelayServer};
use ghost_relay_storage::sha256;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Channel;
use tonic::Code;

struct Node {
    relay: Arc<Relay>,
    addr: String,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    _dir: tempfile::TempDir,
    capture_path: std::path::PathBuf,
}

async fn start_node(gossip: bool) -> Node {
    start_node_with(gossip, None, None).await
}

/// A node with optional redemption, on the system clock or a shared virtual one.
async fn start_node_with(
    gossip: bool,
    entitlement: Option<EntitlementPolicy>,
    clock: Option<&VirtualClock>,
) -> Node {
    let dir = tempfile::tempdir().unwrap();
    let capture_path = dir.path().join("capture.ndjson");
    let mut config = RelayConfig {
        gossip_enabled: gossip,
        entitlement,
        ..RelayConfig::default()
    };
    if let Some(c) = clock {
        config.clock = c.clock();
    }
    let relay = Relay::open(
        &dir.path().join("data"),
        RelayKey::generate(),
        config,
        Some(&capture_path),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = format!("http://{}", listener.local_addr().unwrap());
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let svc = RelayServiceServer::new(RelayServer(Arc::clone(&relay)));
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                let _ = rx.await;
            })
            .await
            .unwrap();
    });
    Node {
        relay,
        addr,
        shutdown: Some(tx),
        _dir: dir,
        capture_path,
    }
}

async fn client(addr: &str) -> RelayServiceClient<Channel> {
    for _ in 0..50 {
        let endpoint = Channel::from_shared(addr.to_string()).expect("relay address");
        if let Ok(ch) = endpoint.connect().await {
            return RelayServiceClient::new(ch);
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("relay did not come up");
}

fn far_future() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3_600
}

fn cap(key: &RelayKey, kind: Kind, ns: [u8; 32], quota: u64) -> Option<Capability> {
    Some(Capability {
        token: key.mint(&ghost_relay_capability::Capability {
            kind,
            namespace: ns,
            quota_bytes: quota,
            expiry_unix: far_future(),
        }),
    })
}

fn store_req(ns: [u8; 32], data: &[u8], cap: Option<Capability>) -> StoreBlobRequest {
    StoreBlobRequest {
        version: PROTOCOL_VERSION,
        blob_hash: sha256(data).to_vec(),
        data: data.to_vec(),
        capability: cap,
        ttl_seconds: 86_400,
        request_id: vec![7u8; 16],
        namespace_id: ns.to_vec(),
    }
}

#[tokio::test]
async fn store_get_check_list_gossip_failover_and_capture() {
    let mut a = start_node(true).await;
    let b = start_node(true).await;
    let mut ca = client(&a.addr).await;
    let mut cb = client(&b.addr).await;
    let ns = [0x11u8; 32];
    let write_a = cap(a.relay.key(), Kind::Write, ns, 1 << 20);
    let read_a = cap(a.relay.key(), Kind::Read, ns, 0);
    let blob = vec![0xABu8; 4096];
    let hash = sha256(&blob).to_vec();

    // store (idempotent second call)
    let r1 = ca
        .store_blob(store_req(ns, &blob, write_a.clone()))
        .await
        .unwrap()
        .into_inner();
    assert!(r1.success && r1.stored_hash == hash);
    let r2 = ca
        .store_blob(store_req(ns, &blob, write_a.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(r2.expiry_unix_seconds, r1.expiry_unix_seconds);

    // get with read capability; uploaded time is minute-bucketed
    let g = ca
        .get_blob(GetBlobRequest {
            version: 1,
            blob_hash: hash.clone(),
            capability: read_a.clone(),
            request_id: vec![1; 16],
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(g.data, blob);
    assert_eq!(g.uploaded_at_unix_seconds % 60, 0);

    // check + list
    let c = ca
        .check_blobs(CheckBlobsRequest {
            version: 1,
            blob_hashes: vec![hash.clone(), vec![9; 32]],
            capability: read_a.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(c.available_hashes, vec![hash.clone()]);
    let l = ca
        .list_namespace(ListNamespaceRequest {
            version: 1,
            namespace_id: ns.to_vec(),
            capability: read_a.clone(),
            cursor: vec![],
            limit: 16,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(l.blob_hashes, vec![hash.clone()]);
    assert!(l.next_cursor.is_empty());

    // --- abuse controls ---
    let bad_hash = StoreBlobRequest {
        blob_hash: vec![0; 32],
        ..store_req(ns, &blob, write_a.clone())
    };
    assert_eq!(
        ca.store_blob(bad_hash).await.unwrap_err().code(),
        Code::InvalidArgument
    );
    let not_bucket = store_req(ns, &vec![1u8; 4095], write_a.clone());
    assert_eq!(
        ca.store_blob(not_bucket).await.unwrap_err().code(),
        Code::InvalidArgument
    );
    let oversize = store_req(ns, &vec![1u8; 65_537], write_a.clone());
    assert_eq!(
        ca.store_blob(oversize).await.unwrap_err().code(),
        Code::InvalidArgument
    );
    let no_cap = store_req(ns, &vec![2u8; 1024], None);
    assert_eq!(
        ca.store_blob(no_cap).await.unwrap_err().code(),
        Code::PermissionDenied
    );
    let wrong_ns_cap = store_req(
        ns,
        &vec![2u8; 1024],
        cap(a.relay.key(), Kind::Write, [0x22; 32], 1 << 20),
    );
    assert_eq!(
        ca.store_blob(wrong_ns_cap).await.unwrap_err().code(),
        Code::PermissionDenied
    );
    let read_only = store_req(ns, &vec![2u8; 1024], read_a.clone());
    assert_eq!(
        ca.store_blob(read_only).await.unwrap_err().code(),
        Code::PermissionDenied
    );
    let foreign_key = store_req(
        ns,
        &vec![2u8; 1024],
        cap(b.relay.key(), Kind::Write, ns, 1 << 20),
    );
    assert_eq!(
        ca.store_blob(foreign_key).await.unwrap_err().code(),
        Code::PermissionDenied
    );
    let bad_ttl = StoreBlobRequest {
        ttl_seconds: 0,
        ..store_req(ns, &vec![3u8; 1024], write_a.clone())
    };
    assert_eq!(
        ca.store_blob(bad_ttl).await.unwrap_err().code(),
        Code::InvalidArgument
    );
    let too_long_ttl = StoreBlobRequest {
        ttl_seconds: 91 * 86_400,
        ..store_req(ns, &vec![3u8; 1024], write_a.clone())
    };
    assert_eq!(
        ca.store_blob(too_long_ttl).await.unwrap_err().code(),
        Code::InvalidArgument
    );
    // quota: 1 KiB capability cannot store 4 KiB
    let tiny = cap(a.relay.key(), Kind::Write, [0x33; 32], 1024);
    let over_quota = store_req([0x33; 32], &vec![4u8; 4096], tiny.clone());
    assert_eq!(
        ca.store_blob(over_quota.clone()).await.unwrap_err().code(),
        Code::ResourceExhausted
    );
    // ... and nothing was persisted: the blob is not served, not listed, and a retry is charged
    // (and rejected) again instead of being confirmed as an idempotent success. The same holds
    // when the ciphertext already exists under another namespace.
    let tiny_read = cap(a.relay.key(), Kind::Read, [0x33; 32], 0);
    for data in [vec![4u8; 4096], blob.clone()] {
        let attempt = store_req([0x33; 32], &data, tiny.clone());
        assert_eq!(
            ca.store_blob(attempt).await.unwrap_err().code(),
            Code::ResourceExhausted
        );
        let g = ca
            .get_blob(GetBlobRequest {
                version: 1,
                blob_hash: sha256(&data).to_vec(),
                capability: tiny_read.clone(),
                request_id: vec![9; 16],
            })
            .await;
        assert_eq!(g.unwrap_err().code(), Code::NotFound);
    }
    assert_eq!(
        ca.store_blob(over_quota).await.unwrap_err().code(),
        Code::ResourceExhausted
    );
    let listed = ca
        .list_namespace(ListNamespaceRequest {
            version: 1,
            namespace_id: vec![0x33; 32],
            capability: tiny_read,
            cursor: vec![],
            limit: 16,
        })
        .await
        .unwrap()
        .into_inner();
    assert!(listed.blob_hashes.is_empty() && listed.next_cursor.is_empty());
    // batch bound
    let big_batch = CheckBlobsRequest {
        version: 1,
        blob_hashes: vec![hash.clone(); MAX_BATCH + 1],
        capability: read_a.clone(),
    };
    assert_eq!(
        ca.check_blobs(big_batch).await.unwrap_err().code(),
        Code::InvalidArgument
    );
    // a blob outside the capability's namespace is indistinguishable from a missing one
    let other_read = cap(a.relay.key(), Kind::Read, [0x22; 32], 0);
    let g2 = ca
        .get_blob(GetBlobRequest {
            version: 1,
            blob_hash: hash.clone(),
            capability: other_read,
            request_id: vec![1; 16],
        })
        .await;
    assert_eq!(g2.unwrap_err().code(), Code::NotFound);
    // wrong protocol version fails closed
    let v2 = StoreBlobRequest {
        version: 2,
        ..store_req(ns, &vec![5u8; 1024], write_a.clone())
    };
    assert_eq!(
        ca.store_blob(v2).await.unwrap_err().code(),
        Code::InvalidArgument
    );

    // --- gossip: B learns it lacks A's blob ---
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tx.send(GossipInventoryBatch {
        version: 1,
        blob_hashes: vec![hash.clone()],
        batch_id: vec![5; 16],
    })
    .await
    .unwrap();
    drop(tx);
    let mut acks = cb
        .gossip_sync(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    let ack = tokio_stream::StreamExt::next(&mut acks)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ack.missing_hashes, vec![hash.clone()]);

    // convergence step: B pulls the blob from A and stores it under its own write capability
    let pulled = ca
        .get_blob(GetBlobRequest {
            version: 1,
            blob_hash: hash.clone(),
            capability: read_a.clone(),
            request_id: vec![2; 16],
        })
        .await
        .unwrap()
        .into_inner();
    let write_b = cap(b.relay.key(), Kind::Write, ns, 1 << 20);
    cb.store_blob(store_req(ns, &pulled.data, write_b))
        .await
        .unwrap();

    // --- failover: A goes away, B still serves ---
    a.shutdown.take().unwrap().send(()).unwrap();
    let read_b = cap(b.relay.key(), Kind::Read, ns, 0);
    let g3 = cb
        .get_blob(GetBlobRequest {
            version: 1,
            blob_hash: hash.clone(),
            capability: read_b,
            request_id: vec![3; 16],
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(g3.data, blob);

    // --- T1: A's capture contains only allowed observables ---
    let schema_text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../test-harness/privacy/allowed-observables.json"
    ))
    .unwrap();
    let schema = ghost_capture_check::Schema::parse(&schema_text).unwrap();
    let capture = std::fs::read_to_string(&a.capture_path).unwrap();
    assert!(
        capture.lines().count() >= 15,
        "capture should hold one line per request"
    );
    let violations = schema.check_capture(&capture);
    assert!(violations.is_empty(), "capture violations: {violations:#?}");
    // and it never contains the blob content or the raw capability token
    assert!(!capture.contains(&hex::encode(&blob[..64])));
    assert!(!capture.contains(&hex::encode(&write_a.unwrap().token)));
}

#[tokio::test]
async fn redemptions_over_grpc_and_their_capture() {
    // Node A holds slot 1 (relay-b), node B slot 0 (relay-a), both on one virtual clock in week
    // 2959 of the test schedule.
    let clock = VirtualClock::new(at("2959+86400"));
    let now = clock.get();
    let a = start_node_with(
        false,
        Some(policy(test_schedule(), 1, RELAY_B, NullifierMode::Create)),
        Some(&clock),
    )
    .await;
    let b = start_node_with(
        false,
        Some(policy(test_schedule(), 0, RELAY_A, NullifierMode::Create)),
        Some(&clock),
    )
    .await;
    let mut ca = client(&a.addr).await;
    let mut cb = client(&b.addr).await;
    let ns = namespace("two-nodes");
    let other = namespace("two-nodes-other");
    let (a1, a2, s0, c4) = (token("a1"), token("a2"), token("s0"), token("c4"));
    let mut forged = a2.clone();
    forged[300] ^= 0x01;
    let answer = |r: Result<tonic::Response<RedeemTokenResponse>, tonic::Status>| {
        outcome(r.map(tonic::Response::into_inner), now)
    };

    // ok, and an identical retry gets identical bytes
    let cap = match answer(ca.redeem_token(request(&a1, &ns, &request_id("1"))).await) {
        Outcome::Ok(c) => c,
        o => panic!("expected OK, got {o:?}"),
    };
    assert_eq!(
        answer(ca.redeem_token(request(&a1, &ns, &request_id("1"))).await),
        Outcome::Ok(cap.clone())
    );
    // replay to another namespace
    assert_eq!(
        answer(
            ca.redeem_token(request(&a1, &other, &request_id("2")))
                .await
        ),
        Outcome::Replayed
    );
    // wrong slot at A; the same token is good at B, the relay of its slot
    assert_eq!(
        answer(ca.redeem_token(request(&s0, &ns, &request_id("3"))).await),
        Outcome::Denied(Code::PermissionDenied)
    );
    assert!(matches!(
        answer(cb.redeem_token(request(&s0, &ns, &request_id("3"))).await),
        Outcome::Ok(_)
    ));
    // wrong week, and a forged authenticator
    assert_eq!(
        answer(ca.redeem_token(request(&c4, &ns, &request_id("4"))).await),
        Outcome::WrongPeriod
    );
    assert_eq!(
        answer(
            ca.redeem_token(request(&forged, &ns, &request_id("5")))
                .await
        ),
        Outcome::Denied(Code::PermissionDenied)
    );

    // The minted capability writes and reads at A, and is worthless at B.
    let blob = vec![0x77u8; 1024];
    let redeemed = Some(Capability { token: cap.clone() });
    let stored = ca
        .store_blob(store_req(ns, &blob, redeemed.clone()))
        .await
        .unwrap()
        .into_inner();
    assert!(stored.success);
    let fetched = ca
        .get_blob(GetBlobRequest {
            version: 1,
            blob_hash: sha256(&blob).to_vec(),
            capability: redeemed.clone(),
            request_id: vec![6; 16],
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(fetched.data, blob);
    assert_eq!(
        cb.store_blob(store_req(ns, &blob, redeemed))
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );

    // T1: both captures hold only allowed observables; A's shows every redeem result it produced,
    // the capability's scope hash and the nullifier, and never a token, an authenticator or the
    // capability itself.
    let schema = ghost_capture_check::Schema::parse(include_str!(
        "../../../../test-harness/privacy/allowed-observables.json"
    ))
    .unwrap();
    for node in [&a, &b] {
        let capture = std::fs::read_to_string(&node.capture_path).unwrap();
        let violations = schema.check_capture(&capture);
        assert!(violations.is_empty(), "capture violations: {violations:#?}");
        for secret in [&a1, &a2, &s0, &c4, &forged] {
            assert!(
                !capture.contains(&hex::encode(secret)),
                "token in the capture"
            );
            assert!(
                !capture.contains(&hex::encode(&secret[98..])),
                "authenticator in the capture"
            );
        }
        assert!(
            !capture.contains(&hex::encode(&cap)),
            "capability in the capture"
        );
    }
    let capture_a = std::fs::read_to_string(&a.capture_path).unwrap();
    assert!(capture_a.contains(&hex::encode(sha256(&cap))), "scope hash");
    let results: Vec<String> = common::capture_results(&a.capture_path)
        .into_iter()
        .filter(|r| r != "ok")
        .collect();
    assert_eq!(
        results,
        [
            "rejected_nullifier",
            "rejected_token",
            "rejected_period",
            "rejected_token"
        ]
    );
    let redeem_events = capture_a
        .lines()
        .filter(|l| l.contains("\"op\":\"redeem\""))
        .count();
    assert_eq!(redeem_events, 6);
}

/// Phase 9 (design §4.2–§4.7, §10.2, §22.8.7): key registrations, deposits, reads and fetches with
/// bearer credentials v3 over gRPC, and their capture: a `register` event per registration with
/// its `key_kind`, `ttl_bucket_seconds` of every store (3600 included), `rejected_ttl` for a TTL
/// that is no bucket, one deposit scope for every sender of an inbox, week-coarse times on fetch,
/// and never a secret, a credential or a verifier.
#[tokio::test]
async fn registrations_deposits_and_fetches_over_grpc_and_their_capture() {
    use ghost_relay_api::{BearerCredential, BearerKind};
    use ghost_relay_capability::bearer_verifier;

    let clock = VirtualClock::new(at("2959+90000"));
    let now = clock.get();
    let a = start_node_with(
        false,
        Some(policy(test_schedule(), 1, RELAY_B, NullifierMode::Create)),
        Some(&clock),
    )
    .await;
    let mut owner = client(&a.addr).await;
    let inbox = namespace("two-nodes-inbox");
    let bundle = namespace("two-nodes-bundle");
    // The owner's write capabilities for its inbox and bundle: redeemed tokens of week 2959.
    let (inbox_cap, bundle_cap) = match (
        outcome(
            owner
                .redeem_token(request(&token("a1"), &inbox, &request_id("i")))
                .await
                .map(tonic::Response::into_inner),
            now,
        ),
        outcome(
            owner
                .redeem_token(request(&token("a2"), &bundle, &request_id("b")))
                .await
                .map(tonic::Response::into_inner),
            now,
        ),
    ) {
        (Outcome::Ok(i), Outcome::Ok(b)) => (i, b),
        other => panic!("redemptions: {other:?}"),
    };
    let credential = |kind, namespace, secret| BearerCredential {
        kind,
        slot: 1,
        namespace,
        secret: [secret; 32],
    };
    let deposit = credential(BearerKind::Deposit, inbox, 0xD1);
    let read = credential(BearerKind::Read, inbox, 0xD2);
    let fetch = credential(BearerKind::Fetch, bundle, 0xD3);
    let registrations = [
        (&deposit, &inbox, &inbox_cap),
        (&read, &inbox, &inbox_cap),
        (&fetch, &bundle, &bundle_cap),
    ];
    for (i, (c, ns, cap)) in registrations.iter().enumerate() {
        let r = owner
            .register_key(RegisterKeyRequest {
                version: PROTOCOL_VERSION,
                namespace_id: ns.to_vec(),
                period_id: 2959,
                kind: c.kind.byte().into(),
                verifier: bearer_verifier(c).to_vec(),
                capability: Some(Capability {
                    token: cap.to_vec(),
                }),
                request_id: request_id(&format!("register-{i}")),
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(r.result, RegisterResult::Ok as i32);
        assert_eq!(r.valid_until_unix, at("2961+3600"));
    }
    // A registration for a week its capability does not cover.
    let wrong = owner
        .register_key(RegisterKeyRequest {
            version: PROTOCOL_VERSION,
            namespace_id: inbox.to_vec(),
            period_id: 2961,
            kind: BearerKind::Deposit.byte().into(),
            verifier: bearer_verifier(&deposit).to_vec(),
            capability: Some(Capability {
                token: inbox_cap.clone(),
            }),
            request_id: request_id("register-wrong"),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(wrong.result, RegisterResult::WrongPeriod as i32);

    // Two senders deposit with the one inbox credential, on their own connections.
    let as_cap = |c: &BearerCredential| {
        Some(Capability {
            token: c.encode().to_vec(),
        })
    };
    let first = vec![0x31u8; 4096];
    let second = vec![0x32u8; 4096];
    for (data, ttl) in [(&first, 3_600), (&second, 604_800)] {
        let mut sender = client(&a.addr).await;
        let stored = sender
            .store_blob(StoreBlobRequest {
                ttl_seconds: ttl,
                ..store_req(inbox, data, as_cap(&deposit))
            })
            .await
            .unwrap()
            .into_inner();
        assert!(stored.success);
    }
    let mut sender = client(&a.addr).await;
    let not_a_bucket = sender
        .store_blob(StoreBlobRequest {
            ttl_seconds: 7_200,
            ..store_req(inbox, &vec![0x33u8; 4096], as_cap(&deposit))
        })
        .await
        .unwrap_err();
    assert_eq!(not_a_bucket.code(), Code::InvalidArgument);
    let get = |cap: Option<Capability>, data: &[u8]| GetBlobRequest {
        version: 1,
        blob_hash: sha256(data).to_vec(),
        capability: cap,
        request_id: vec![4; 16],
    };
    assert_eq!(
        sender
            .get_blob(get(as_cap(&deposit), &first))
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied,
        "a deposit credential never reads"
    );

    // The owner reads its inbox with its read credential: the upload week, the exact expiry.
    let listed = owner
        .list_namespace(ListNamespaceRequest {
            version: 1,
            namespace_id: inbox.to_vec(),
            capability: as_cap(&read),
            cursor: vec![],
            limit: 16,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        listed.blob_hashes,
        vec![sha256(&first).to_vec(), sha256(&second).to_vec()]
    );
    let got = owner
        .get_blob(get(as_cap(&read), &first))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(got.uploaded_at_unix_seconds, at("2959+0"));
    assert_eq!(got.expiry_unix_seconds, at("2959+93600"));

    // A card holder fetches the bundle: both times week-coarse.
    let bundle_blob = vec![0x44u8; 4096];
    owner
        .store_blob(StoreBlobRequest {
            ttl_seconds: 2_592_000,
            ..store_req(
                bundle,
                &bundle_blob,
                Some(Capability {
                    token: bundle_cap.clone(),
                }),
            )
        })
        .await
        .unwrap();
    let mut fetcher = client(&a.addr).await;
    let fetched = fetcher
        .get_blob(get(as_cap(&fetch), &bundle_blob))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(fetched.data, bundle_blob);
    assert_eq!(fetched.uploaded_at_unix_seconds, at("2959+0"));
    assert_eq!(fetched.expiry_unix_seconds, at("2964+0"));

    // T1: only allowed observables; the register events and the stores as the design lists them.
    let schema = ghost_capture_check::Schema::parse(include_str!(
        "../../../../test-harness/privacy/allowed-observables.json"
    ))
    .unwrap();
    let capture = std::fs::read_to_string(&a.capture_path).unwrap();
    let violations = schema.check_capture(&capture);
    assert!(violations.is_empty(), "capture violations: {violations:#?}");
    for c in [&deposit, &read, &fetch] {
        for secret in [
            hex::encode(c.secret),
            hex::encode(c.encode()),
            hex::encode(bearer_verifier(c)),
        ] {
            assert!(!capture.contains(&secret), "a credential in the capture");
        }
    }
    let events: Vec<serde_json::Value> = capture
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let registers: Vec<&serde_json::Value> =
        events.iter().filter(|e| e["op"] == "register").collect();
    assert_eq!(registers.len(), 4);
    let kinds: Vec<&str> = registers
        .iter()
        .filter(|e| e["result"] == "ok")
        .map(|e| e["key_kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["deposit", "read", "fetch"]);
    assert_eq!(registers[3]["result"], "rejected_period");
    for e in &registers {
        assert_eq!(e["period_id"].as_str().unwrap().len(), 16);
        assert!(e.get("capability_scope").is_some());
    }
    let deposit_scope = hex::encode(sha256(&deposit.encode()));
    let inbox_stores: Vec<&serde_json::Value> = events
        .iter()
        .filter(|e| e["op"] == "store" && e["namespace_id"] == hex::encode(inbox))
        .collect();
    assert_eq!(inbox_stores.len(), 3);
    assert!(
        inbox_stores
            .iter()
            .all(|e| e["capability_scope"] == deposit_scope.as_str()),
        "every sender of the inbox presents one scope"
    );
    let ttls: Vec<(&str, Option<u64>)> = inbox_stores
        .iter()
        .map(|e| {
            (
                e["result"].as_str().unwrap(),
                e["ttl_bucket_seconds"].as_u64(),
            )
        })
        .collect();
    assert_eq!(
        ttls,
        [
            ("ok", Some(3_600)),
            ("ok", Some(604_800)),
            ("rejected_ttl", None)
        ]
    );
    assert!(events
        .iter()
        .all(|e| e.get("key_kind").is_none() || e["op"] == "register"));
}

#[tokio::test]
async fn redeem_is_unimplemented_without_a_schedule() {
    let n = start_node(false).await;
    let mut c = client(&n.addr).await;
    let err = c
        .redeem_token(request(&token("a1"), &namespace("x"), &request_id("x")))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::Unimplemented);
    assert_eq!(
        common::capture_results(&n.capture_path),
        ["rejected_capability"]
    );
}

#[tokio::test]
async fn gossip_is_refused_when_disabled() {
    let n = start_node(false).await;
    let mut c = client(&n.addr).await;
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    drop(tx);
    let err = c
        .gossip_sync(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
}
