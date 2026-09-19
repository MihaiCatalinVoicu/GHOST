//! `ListNamespace` cursors are opaque to their holder (Phase 9 design §1.2, §21.9 point 4,
//! §22.8.7 point 1, L7-D10 "fetch reads return only week-coarse times").
//!
//! The blob store pages a namespace by a per-namespace sequence number seeded from the UTC hour of
//! the namespace's first store and counted up per store (`storage::seq_seed`). Handing that number
//! out as `next_cursor` would give every holder of a bearer credential — including the free shared
//! fetch secret of a bundle namespace, which every card holder has and which costs no token — the
//! namespace's activation hour and its publication count in one call, and accepting it back would
//! let the same caller search for that hour by probing cursors. The relay is the only party that
//! has to read a cursor, so the eight bytes on the wire are the sequence under a keyed permutation
//! of the relay key. These tests pin that the sequence never leaves the relay, that the cursor is
//! bound to its namespace and to the relay key, and that paging is unchanged.

mod common;

use common::{namespace, open_relay, policy, request_id, test_schedule, VirtualClock, RELAY_B};
use ghost_relay_api::proto::{
    Capability as CapabilityMessage, GetBlobRequest, ListNamespaceRequest, RegisterKeyRequest,
    RegisterResult, StoreBlobRequest,
};
use ghost_relay_api::{BearerCredential, BearerKind, PROTOCOL_VERSION};
use ghost_relay_capability::{bearer_verifier, Capability, Kind, RelayKey};
use ghost_relay_node::redeem::capability_expiry;
use ghost_relay_node::{NullifierMode, Relay};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tonic::Code;

/// Week 2959, Tuesday 07:15 UTC: a minute that is neither a week start nor an hour start.
const T0: u64 = 2959 * 604_800 + 345_600 + 112_500;
const WEEK: u64 = 604_800;
const BUNDLE_TTL: u32 = 2_592_000;

/// The sequence the blob store gives the first blob of a namespace whose first store is at `now`,
/// and the store counter after it: the value the cursor must never be.
fn raw_sequence(now: u64, stores_before: u64) -> [u8; 8] {
    (((now / 3_600) << 32) + stores_before).to_be_bytes()
}

struct Fixture {
    relay: Arc<Relay>,
    key: RelayKey,
    _dir: tempfile::TempDir,
}

fn open(key_byte: u8, clock: &VirtualClock) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let key = RelayKey::from_bytes([key_byte; 32]);
    let relay = open_relay(
        dir.path(),
        &key,
        Some(policy(test_schedule(), 1, RELAY_B, NullifierMode::Create)),
        clock,
        None,
    )
    .unwrap();
    Fixture {
        relay,
        key,
        _dir: dir,
    }
}

fn write_capability(key: &RelayKey, ns: [u8; 32], week: u64) -> Vec<u8> {
    key.mint_v2(
        &Capability {
            kind: Kind::Write,
            namespace: ns,
            quota_bytes: 268_435_456,
            expiry_unix: capability_expiry(week),
        },
        &[7; 16],
    )
}

fn fetch_credential(ns: [u8; 32]) -> BearerCredential {
    BearerCredential {
        kind: BearerKind::Fetch,
        slot: 1,
        namespace: ns,
        secret: Sha256::digest(b"ghost/test/secret/fetch").into(),
    }
}

/// Registers the fetch verifier of `ns` for `week` with a write capability of the same week.
fn register_fetch(f: &Fixture, ns: [u8; 32], week: u64, now: u64) {
    let answer = f
        .relay
        .register_key_at(
            RegisterKeyRequest {
                version: PROTOCOL_VERSION,
                namespace_id: ns.to_vec(),
                period_id: week,
                kind: BearerKind::Fetch.byte().into(),
                verifier: bearer_verifier(&fetch_credential(ns)).to_vec(),
                capability: Some(CapabilityMessage {
                    token: write_capability(&f.key, ns, week),
                }),
                request_id: request_id("fetch"),
            },
            now,
        )
        .unwrap();
    assert_eq!(answer.result, RegisterResult::Ok as i32);
}

fn blob(n: u8) -> Vec<u8> {
    let mut data = vec![0u8; 1024];
    data[0] = n;
    data
}

/// Stores `blob(n)` into `ns` with the namespace's write capability.
fn store(f: &Fixture, ns: [u8; 32], week: u64, n: u8, now: u64) -> Vec<u8> {
    let data = blob(n);
    let hash: [u8; 32] = Sha256::digest(&data).into();
    f.relay
        .store_at(
            StoreBlobRequest {
                version: PROTOCOL_VERSION,
                blob_hash: hash.to_vec(),
                data,
                capability: Some(CapabilityMessage {
                    token: write_capability(&f.key, ns, week),
                }),
                ttl_seconds: BUNDLE_TTL,
                request_id: request_id(&format!("store-{n}")),
                namespace_id: ns.to_vec(),
            },
            now,
        )
        .unwrap();
    hash.to_vec()
}

fn list(
    f: &Fixture,
    ns: [u8; 32],
    token: Vec<u8>,
    cursor: Vec<u8>,
    limit: u32,
    now: u64,
) -> Result<(Vec<Vec<u8>>, Vec<u8>), Code> {
    f.relay
        .list_at(
            ListNamespaceRequest {
                version: PROTOCOL_VERSION,
                namespace_id: ns.to_vec(),
                capability: Some(CapabilityMessage { token }),
                cursor,
                limit,
            },
            now,
        )
        .map(|r| (r.blob_hashes, r.next_cursor))
        .map_err(|s| s.code())
}

/// A bundle namespace with `count` blobs stored an hour apart from `first_store`, its fetch
/// verifier registered, and the fetch credential's bytes.
fn bundle_namespace(f: &Fixture, name: &str, first_store: u64, count: u8) -> ([u8; 32], Vec<u8>) {
    let ns = namespace(name);
    let week = (first_store - 345_600) / WEEK;
    register_fetch(f, ns, week, first_store);
    for n in 0..count {
        store(f, ns, week, n, first_store + u64::from(n) * 3_600);
    }
    (ns, fetch_credential(ns).encode().to_vec())
}

#[test]
fn a_fetch_list_cursor_is_neither_the_seed_hour_nor_the_store_count() {
    let clock = VirtualClock::new(T0);
    let f = open(0x42, &clock);
    let (ns, fetch) = bundle_namespace(&f, "bundle", T0, 3);

    // One hash per page, so the answer carries a cursor the holder could read.
    let (first, cursor) = list(&f, ns, fetch.clone(), Vec::new(), 1, T0 + 2 * 3_600).unwrap();
    assert_eq!(first.len(), 1, "one hash per page");
    assert_eq!(cursor.len(), 8, "the wire cursor keeps its eight bytes");
    assert_ne!(
        cursor[..],
        raw_sequence(T0, 0)[..],
        "the cursor is the raw per-namespace sequence: its high 32 bits are the hour of the \
         namespace's first store"
    );

    // The same at the second page: the low half must not be the store counter either.
    let (_, cursor2) = list(&f, ns, fetch, cursor.clone(), 1, T0 + 2 * 3_600).unwrap();
    assert_ne!(cursor2[..], raw_sequence(T0, 1)[..], "the store counter");
    assert_ne!(cursor2, cursor, "a later page has another cursor");
}

#[test]
fn a_cursor_is_bound_to_its_namespace_and_to_the_relay_key() {
    let clock = VirtualClock::new(T0);
    let f = open(0x42, &clock);
    let (one, fetch_one) = bundle_namespace(&f, "bundle-one", T0, 3);
    let (two, fetch_two) = bundle_namespace(&f, "bundle-two", T0, 3);

    let (_, cursor_one) = list(&f, one, fetch_one.clone(), Vec::new(), 1, T0 + 7_200).unwrap();
    let (_, cursor_two) = list(&f, two, fetch_two, Vec::new(), 1, T0 + 7_200).unwrap();
    assert_ne!(
        cursor_one, cursor_two,
        "two namespaces at the same sequence must not share a cursor"
    );

    // Another relay, same namespace, same sequence, another key.
    let other = open(0x43, &clock);
    let (same, fetch_same) = bundle_namespace(&other, "bundle-one", T0, 3);
    assert_eq!(same, one);
    let (_, cursor_other) = list(&other, same, fetch_same, Vec::new(), 1, T0 + 7_200).unwrap();
    assert_ne!(
        cursor_one, cursor_other,
        "the cursor must be keyed by the relay key"
    );
}

#[test]
fn cursors_page_the_namespace_exactly_once() {
    let clock = VirtualClock::new(T0);
    let f = open(0x42, &clock);
    let (ns, fetch) = bundle_namespace(&f, "bundle", T0, 5);
    let now = T0 + 5 * 3_600;

    let (all, tail) = list(&f, ns, fetch.clone(), Vec::new(), 256, now).unwrap();
    assert_eq!(all.len(), 5);
    assert!(tail.is_empty(), "an exhausted listing carries no cursor");

    let mut paged = Vec::new();
    let mut cursor = Vec::new();
    for _ in 0..5 {
        let (page, next) = list(&f, ns, fetch.clone(), cursor.clone(), 2, now).unwrap();
        paged.extend(page);
        if next.is_empty() {
            break;
        }
        assert_eq!(next.len(), 8);
        cursor = next;
    }
    assert_eq!(
        paged, all,
        "paging returns the listing exactly once, in order"
    );
}

#[test]
fn a_cursor_of_another_namespace_never_resumes_this_one() {
    let clock = VirtualClock::new(T0);
    let f = open(0x42, &clock);
    let (one, fetch_one) = bundle_namespace(&f, "bundle-one", T0, 4);
    let (two, fetch_two) = bundle_namespace(&f, "bundle-two", T0, 4);
    let now = T0 + 4 * 3_600;

    let (_, cursor_one) = list(&f, one, fetch_one, Vec::new(), 2, now).unwrap();
    let (page, _) = list(&f, two, fetch_two.clone(), cursor_one, 2, now).unwrap();
    let (own, _) = list(&f, two, fetch_two, Vec::new(), 2, now).unwrap();
    assert_ne!(
        page, own,
        "a cursor minted for another namespace must not address this one's sequence"
    );
}

#[test]
fn a_cursor_of_the_wrong_length_is_refused() {
    let clock = VirtualClock::new(T0);
    let f = open(0x42, &clock);
    let (ns, fetch) = bundle_namespace(&f, "bundle", T0, 2);
    for len in [1usize, 7, 9, 16] {
        assert_eq!(
            list(&f, ns, fetch.clone(), vec![0; len], 2, T0 + 3_600),
            Err(Code::InvalidArgument),
            "cursor of {len} bytes"
        );
    }
}

#[test]
fn a_capability_get_still_answers_the_upload_minute() {
    // The cursor change must not touch what a `get` answers (design §21.9 point 4, §22.8.7).
    let clock = VirtualClock::new(T0);
    let f = open(0x42, &clock);
    let ns = namespace("bundle");
    let week = (T0 - 345_600) / WEEK;
    let hash = store(&f, ns, week, 0, T0);
    let answer = f
        .relay
        .get_at(
            GetBlobRequest {
                version: PROTOCOL_VERSION,
                blob_hash: hash,
                capability: Some(CapabilityMessage {
                    token: write_capability(&f.key, ns, week),
                }),
                request_id: request_id("get"),
            },
            T0,
        )
        .unwrap();
    assert_eq!(answer.uploaded_at_unix_seconds, T0 - T0 % 60);
}
