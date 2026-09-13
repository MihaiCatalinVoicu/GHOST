//! Relay redemption negatives (Phase 8 design §13.1 relay column, §13.2 relay crash safety) and
//! the relay mutants of §13.5 this slice hosts (MM13, MM14, MM18). The conformance cases of
//! `redeem.txt` (window edges, wrong kind, slot and week, revocation, store reset) run in
//! `redeem_vectors.rs`; this file adds what a line-oriented script cannot express: crashes and
//! restarts, concurrency, all 354 flipped bytes, forged authenticators around n, the start-up
//! checks against remembered schedules, and the global token bucket.

mod common;

use common::*;
use ghost_entitlement::grid::Kind as TokenKind;
use ghost_entitlement::schedule::ScheduleError;
use ghost_relay_api::capability_header;
use ghost_relay_api::proto::StoreBlobRequest;
use ghost_relay_capability::{Capability, Kind, RelayKey};
use ghost_relay_node::redeem::{
    capability_expiry, COUNTS_HEADER, NULLIFIERS_FILE, REDEMPTION_MARKER_FILE,
};
use ghost_relay_node::{NullifierMode, RedeemRate, Relay, StartError};
use ghost_relay_storage::StoreError;
use std::path::PathBuf;
use std::sync::Arc;
use tonic::Code;

/// Tuesday 00:00 UTC of week 2959: tokens of 2959 are accepted, 2958 and 2960 are not.
fn tuesday() -> u64 {
    at("2959+86400")
}

struct TestRelay {
    dir: tempfile::TempDir,
    key: RelayKey,
    clock: VirtualClock,
    relay: Option<Arc<Relay>>,
}

impl TestRelay {
    /// A slot-1 relay (relay-b) with a fresh data directory at `now`.
    fn new(now: u64) -> Self {
        let mut r = TestRelay {
            dir: tempfile::tempdir().unwrap(),
            key: RelayKey::from_bytes([0x42; 32]),
            clock: VirtualClock::new(now),
            relay: None,
        };
        r.relay = Some(r.open(NullifierMode::Create).unwrap());
        r
    }

    fn data_dir(&self) -> PathBuf {
        self.dir.path().join("data")
    }

    fn open(&self, mode: NullifierMode) -> Result<Arc<Relay>, Box<dyn std::error::Error>> {
        open_relay(
            &self.data_dir(),
            &self.key,
            Some(policy(test_schedule(), 1, RELAY_B, mode)),
            &self.clock,
            None,
        )
    }

    fn relay(&self) -> &Relay {
        self.relay.as_deref().unwrap()
    }

    /// Drops every in-memory object and reopens the same files (a crash, then a restart).
    fn restart(&mut self) {
        drop(self.relay.take());
        self.relay = Some(self.open(NullifierMode::Existing).unwrap());
    }

    fn redeem(&self, token: &[u8], ns: &str, req: &str) -> Outcome {
        let now = self.clock.get();
        redeem(self.relay(), token, &namespace(ns), &request_id(req), now)
    }

    fn rows(&self) -> u64 {
        self.relay().nullifier_store().unwrap().count().unwrap()
    }
}

fn capability(o: Outcome) -> Vec<u8> {
    match o {
        Outcome::Ok(cap) => cap,
        other => panic!("expected OK, got {other:?}"),
    }
}

#[test]
fn a_crash_after_the_commit_gets_the_identical_capability_after_restart() {
    let mut r = TestRelay::new(tuesday());
    let a1 = token("a1");
    // The relay commits the nullifier and mints; the response is lost with the process.
    let lost = capability(r.redeem(&a1, "alpha", "r1"));
    r.restart();
    // The identical retry after the restart gets the identical capability (MS-8)...
    assert_eq!(capability(r.redeem(&a1, "alpha", "r1")), lost);
    // ... any other reuse stays REPLAYED, also after another restart (MS-3).
    assert_eq!(r.redeem(&a1, "beta", "r2"), Outcome::Replayed);
    r.restart();
    assert_eq!(r.redeem(&a1, "beta", "r2"), Outcome::Replayed);
    assert_eq!(capability(r.redeem(&a1, "alpha", "r1")), lost);
    // A crash before the commit left nothing: the first try after the restart mints normally.
    let a2 = token("a2");
    let first = capability(r.redeem(&a2, "alpha", "r3"));
    assert_ne!(
        first, lost,
        "each token has its own serial and quota ledger"
    );
    assert_eq!(r.rows(), 2);

    // The capability is a v2 write capability for the namespace, week-aligned, and it works.
    assert_eq!(first.len(), 98);
    let header = capability_header(&first).unwrap();
    assert_eq!(header.kind, Kind::Write);
    assert_eq!(header.namespace, namespace("alpha"));
    assert_eq!(header.quota_bytes, 268_435_456);
    assert_eq!(header.expiry_unix, capability_expiry(2959));
    assert_eq!(header.expiry_unix, at("2960+3600"));
    let data = vec![0x5Au8; 1024];
    let store = |cap: &[u8], now: u64| {
        r.relay().store_at(
            StoreBlobRequest {
                version: 1,
                blob_hash: ghost_relay_storage::sha256(&data).to_vec(),
                data: data.clone(),
                capability: Some(ghost_relay_api::proto::Capability {
                    token: cap.to_vec(),
                }),
                ttl_seconds: 86_400,
                request_id: vec![1; 16],
                namespace_id: namespace("alpha").to_vec(),
            },
            now,
        )
    };
    assert!(store(&first, tuesday()).is_ok());
    assert_eq!(
        store(&first, at("2960+3600")).unwrap_err().code(),
        Code::PermissionDenied,
        "expired at the end of the week plus one hour"
    );
}

/// Runbook R2 (design §6.9 check 2): the counts file holds the final count of every closed week
/// of this relay's slot and nothing else, is rewritten only when a sweep has counted a week, and
/// survives a restart through the store.
#[test]
fn the_counts_file_holds_the_final_count_of_each_closed_week() {
    let mut r = TestRelay::new(tuesday());
    let path = r.dir.path().join("redemption-counts.txt");
    let read = || std::fs::read_to_string(&path).unwrap();
    assert!(r.relay().write_redemption_counts(&path).unwrap());
    assert_eq!(read(), COUNTS_HEADER);
    assert!(!r.relay().write_redemption_counts(&path).unwrap());
    for (t, ns) in [("a1", "alpha"), ("a2", "beta"), ("a3", "gamma")] {
        capability(r.redeem(&token(t), ns, t));
    }
    // An identical retry and a replay are not redemptions.
    capability(r.redeem(&token("a1"), "alpha", "a1"));
    assert_eq!(r.redeem(&token("a1"), "delta", "x1"), Outcome::Replayed);
    // Week 2959 is open: not counted yet.
    r.relay().sweep(tuesday()).unwrap();
    assert!(!r.relay().write_redemption_counts(&path).unwrap());
    // Its window closes at start(2960) + 1 h; the sweep then counts it.
    r.relay().sweep(at("2960+3599")).unwrap();
    assert!(!r.relay().write_redemption_counts(&path).unwrap());
    r.clock.set(at("2960+3600"));
    r.relay().sweep(at("2960+3600")).unwrap();
    assert!(r.relay().write_redemption_counts(&path).unwrap());
    assert_eq!(
        read(),
        format!("{COUNTS_HEADER}week 2959 slot 1 redemptions 3\n")
    );
    r.clock.set(at("2960+86400"));
    capability(r.redeem(&token("b1"), "alpha", "b1"));
    r.restart();
    assert!(!r.relay().write_redemption_counts(&path).unwrap());
    r.relay().sweep(at("2961+3600")).unwrap();
    assert!(r.relay().write_redemption_counts(&path).unwrap());
    let text = read();
    assert_eq!(
        text,
        format!("{COUNTS_HEADER}week 2959 slot 1 redemptions 3\nweek 2960 slot 1 redemptions 1\n")
    );
    // Aggregates only: the header and count lines, nothing a token, a nullifier or a namespace
    // could be read from.
    for line in text.lines().skip(1) {
        let words: Vec<&str> = line.split(' ').collect();
        assert!(
            matches!(words.as_slice(), ["week", w, "slot", "1", "redemptions", n]
                if w.parse::<u64>().is_ok() && n.parse::<u64>().is_ok()),
            "{line}"
        );
    }
    assert!(!r.dir.path().join("redemption-counts.txt.writing").exists());
    // Without redemption there is no count to write.
    let plain = tempfile::tempdir().unwrap();
    let relay = open_relay(plain.path(), &r.key, None, &r.clock, None).unwrap();
    assert!(relay
        .write_redemption_counts(&plain.path().join("counts.txt"))
        .is_err());
}

#[test]
fn concurrent_duplicates_leave_exactly_one_row() {
    let r = TestRelay::new(tuesday());
    let relay = Arc::clone(r.relay.as_ref().unwrap());
    let now = tuesday();
    let a1 = token("a1");
    // Eight identical requests and eight replays for other namespaces, all at once.
    let handles: Vec<_> = (0..16)
        .map(|i| {
            let relay = Arc::clone(&relay);
            let a1 = a1.clone();
            std::thread::spawn(move || {
                let ns = if i % 2 == 0 {
                    "alpha".to_string()
                } else {
                    format!("other-{i}")
                };
                redeem(&relay, &a1, &namespace(&ns), &request_id("c"), now)
            })
        })
        .collect();
    let outcomes: Vec<Outcome> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let caps: std::collections::BTreeSet<Vec<u8>> = outcomes
        .iter()
        .filter_map(|o| match o {
            Outcome::Ok(c) => Some(c.clone()),
            _ => None,
        })
        .collect();
    // Exactly one binding won. If "alpha" won, its 8 requests got one capability and the 8
    // others were replays; if another namespace won, only that one got a capability.
    assert_eq!(caps.len(), 1, "{outcomes:?}");
    let oks = outcomes
        .iter()
        .filter(|o| matches!(o, Outcome::Ok(_)))
        .count();
    let replays = outcomes.iter().filter(|o| **o == Outcome::Replayed).count();
    assert_eq!(oks + replays, 16);
    assert!(oks == 8 || oks == 1, "{outcomes:?}");
    assert_eq!(r.rows(), 1);
}

#[test]
fn every_flipped_byte_is_refused_before_any_write() {
    let r = TestRelay::new(tuesday());
    let a1 = token("a1");
    for i in 0..a1.len() {
        let mut t = a1.clone();
        t[i] ^= 0x01;
        assert_eq!(
            r.redeem(&t, "alpha", "f"),
            Outcome::Denied(Code::PermissionDenied),
            "byte {i}"
        );
    }
    assert_eq!(r.rows(), 0);
    // The genuine token still redeems: nothing was bound by the forgeries.
    assert!(matches!(r.redeem(&a1, "alpha", "f"), Outcome::Ok(_)));
}

/// `x - 1` and `x + 1` of a big-endian number (no overflow at the values used here).
fn add(bytes: &[u8], delta: i8) -> Vec<u8> {
    let mut out = bytes.to_vec();
    for b in out.iter_mut().rev() {
        let (v, carry) = if delta > 0 {
            b.overflowing_add(1)
        } else {
            b.overflowing_sub(1)
        };
        *b = v;
        if !carry {
            break;
        }
    }
    out
}

#[test]
fn forged_authenticators_are_refused() {
    let r = TestRelay::new(tuesday());
    let a1 = token("a1");
    let schedule = test_schedule();
    let n = schedule
        .key(TokenKind::Access, 2959)
        .unwrap()
        .public_key
        .n_bytes()
        .to_vec();
    assert_eq!(n.len(), 256);
    let mut one = vec![0u8; 256];
    one[255] = 1;
    let authenticators = [
        vec![0u8; 256],
        one,
        add(&n, -1),
        n.clone(),
        add(&n, 1),
        vec![0xFF; 256],
        (0..=255u8).collect(),
        a1[98..].iter().rev().copied().collect(),
    ];
    for (i, auth) in authenticators.iter().enumerate() {
        let forged = [&a1[..98], auth.as_slice()].concat();
        assert_eq!(
            r.redeem(&forged, "alpha", "g"),
            Outcome::Denied(Code::PermissionDenied),
            "authenticator {i}"
        );
    }
    assert_eq!(r.rows(), 0);
}

#[test]
fn versions_and_lengths_are_refused_before_the_token_is_read() {
    let r = TestRelay::new(tuesday());
    let a1 = token("a1");
    let ns = namespace("alpha");
    let req = request_id("s");
    let mut bad = Vec::new();
    for version in [0, 2] {
        let mut q = request(&a1, &ns, &req);
        q.version = version;
        bad.push(q);
    }
    for len in [0usize, 353, 355] {
        let mut t = a1.clone();
        t.resize(len, 0);
        bad.push(request(&t, &ns, &req));
    }
    for len in [0usize, 31, 33] {
        let mut q = request(&a1, &ns, &req);
        q.namespace_id.resize(len, 0);
        bad.push(q);
    }
    for len in [0usize, 15, 17] {
        let mut q = request(&a1, &ns, &req);
        q.request_id.resize(len, 0);
        bad.push(q);
    }
    for q in bad {
        let now = r.clock.get();
        assert_eq!(
            outcome(r.relay().redeem_at(q, now), now),
            Outcome::Denied(Code::InvalidArgument)
        );
    }
    assert_eq!(r.rows(), 0);
}

#[test]
fn the_global_token_bucket_limits_redemptions() {
    let dir = tempfile::tempdir().unwrap();
    let clock = VirtualClock::new(tuesday());
    let mut p = policy(test_schedule(), 1, RELAY_B, NullifierMode::Create);
    p.rate = RedeemRate {
        per_second: 1,
        burst: 3,
    };
    let capture = dir.path().join("capture.ndjson");
    let relay = open_relay(
        &dir.path().join("data"),
        &RelayKey::generate(),
        Some(p),
        &clock,
        Some(&capture),
    )
    .unwrap();
    let now = tuesday();
    let short = vec![0u8; 10];
    // The bucket is checked before the sizes: three malformed requests spend the burst.
    for _ in 0..3 {
        assert_eq!(
            redeem(&relay, &short, &namespace("a"), &request_id("b"), now),
            Outcome::Denied(Code::InvalidArgument)
        );
    }
    assert_eq!(
        redeem(&relay, &token("a1"), &namespace("a"), &request_id("b"), now),
        Outcome::Denied(Code::ResourceExhausted)
    );
    // One second later one more request is admitted.
    assert!(matches!(
        redeem(
            &relay,
            &token("a1"),
            &namespace("a"),
            &request_id("b"),
            now + 1
        ),
        Outcome::Ok(_)
    ));
    assert_eq!(
        redeem(
            &relay,
            &token("a2"),
            &namespace("a"),
            &request_id("b"),
            now + 1
        ),
        Outcome::Denied(Code::ResourceExhausted)
    );
    assert_eq!(
        capture_results(&capture),
        [
            "rejected_size",
            "rejected_size",
            "rejected_size",
            "rejected_capability",
            "ok",
            "rejected_capability"
        ]
    );
}

/// A sweep that closes the week between steps 5 and 9 is answered at step 9 like step 5
/// (`WRONG_PERIOD`, `rejected_period`), and that capture event names no nullifier: only a nullifier
/// the store holds (`ok`, `rejected_nullifier`) is ever captured, so every `rejected_period` event
/// has one shape (review S3-PRIV-1). Identical retries run in a loop while the sweep commits; a
/// retry spends most of its time in steps 6 and 7 (the challenge and the RSA verification), so
/// one of them is between steps 5 and 9 when the week closes. The capture must hold whatever the
/// interleaving.
#[test]
fn a_week_closed_during_a_redemption_captures_no_nullifier() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let a1 = token("a1");
    let closing_sweep = at("2960+3600");
    for round in 0..10 {
        let dir = tempfile::tempdir().unwrap();
        let clock = VirtualClock::new(tuesday());
        let capture = dir.path().join("capture.ndjson");
        let relay = open_relay(
            &dir.path().join("data"),
            &RelayKey::from_bytes([0x42; 32]),
            Some(policy(test_schedule(), 1, RELAY_B, NullifierMode::Create)),
            &clock,
            Some(&capture),
        )
        .unwrap();
        let tries = Arc::new(AtomicUsize::new(0));
        let redeemer = {
            let (relay, tries, a1) = (Arc::clone(&relay), Arc::clone(&tries), a1.clone());
            std::thread::spawn(move || loop {
                let got = redeem(
                    &relay,
                    &a1,
                    &namespace("alpha"),
                    &request_id("race"),
                    tuesday(),
                );
                tries.fetch_add(1, Ordering::SeqCst);
                match got {
                    Outcome::Ok(_) => {}
                    Outcome::WrongPeriod => break,
                    other => panic!("{other:?}"),
                }
            })
        };
        while tries.load(Ordering::SeqCst) < 20 && !redeemer.is_finished() {
            std::thread::yield_now();
        }
        relay.sweep(closing_sweep).unwrap();
        redeemer.join().unwrap();
        let text = std::fs::read_to_string(&capture).unwrap();
        for line in text.lines() {
            let event: serde_json::Value = serde_json::from_str(line).unwrap();
            match event["result"].as_str().unwrap() {
                "ok" => assert!(event.get("nullifier").is_some(), "round {round}"),
                "rejected_period" => assert!(
                    event.get("nullifier").is_none(),
                    "round {round}: a rejected_period event named the nullifier"
                ),
                other => panic!("round {round}: {other}"),
            }
        }
        assert!(text.lines().count() > 20, "round {round}");
    }
}

/// `--nullifiers-init` is one-time (design §19.10 point 2): the redemption marker written with the
/// first store refuses it for good, and a lost store is never recreated empty, so no token redeemed
/// in an open week is spent twice at this relay (review S3-MR-1).
#[test]
fn init_is_one_time_and_a_lost_store_is_never_recreated_empty() {
    let mut r = TestRelay::new(tuesday());
    assert!(matches!(
        r.redeem(&token("a1"), "alpha", "1"),
        Outcome::Ok(_)
    ));
    assert!(r.data_dir().join(REDEMPTION_MARKER_FILE).exists());
    drop(r.relay.take());
    // Refused while the store exists, and after it is lost.
    assert!(matches!(
        start_error(r.open(NullifierMode::Init).err().unwrap()),
        StartError::InitAfterStore
    ));
    std::fs::remove_file(r.data_dir().join(NULLIFIERS_FILE)).unwrap();
    for mode in [
        NullifierMode::Init,
        NullifierMode::Create,
        NullifierMode::Existing,
    ] {
        let e = start_error(r.open(mode).err().unwrap());
        assert!(
            matches!(
                (mode, &e),
                (NullifierMode::Init, StartError::InitAfterStore)
                    | (_, StartError::NullifierStore(StoreError::Missing))
            ),
            "{mode:?}: {e}"
        );
    }
    assert!(!r.data_dir().join(NULLIFIERS_FILE).exists());
    // Only the reset starts it, and it refuses the week open at the reset: a1 is not spent again.
    r.relay = Some(r.open(NullifierMode::Reset).unwrap());
    assert_eq!(
        r.redeem(&token("a1"), "beta", "2"),
        Outcome::Denied(Code::Unavailable)
    );

    // A data directory that never had a store (the Phase 8 upgrade) is initialized once.
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let clock = VirtualClock::new(tuesday());
    let key = RelayKey::from_bytes([0x42; 32]);
    let open = |mode| {
        open_relay(
            &data,
            &key,
            Some(policy(test_schedule(), 1, RELAY_B, mode)),
            &clock,
            None,
        )
    };
    let relay = open(NullifierMode::Init).unwrap();
    assert!(matches!(
        redeem(
            &relay,
            &token("a1"),
            &namespace("a"),
            &request_id("x"),
            tuesday()
        ),
        Outcome::Ok(_)
    ));
    drop(relay);
    assert!(matches!(
        start_error(open(NullifierMode::Init).err().unwrap()),
        StartError::InitAfterStore
    ));
    drop(open(NullifierMode::Existing).unwrap());
}

/// The store keeps a check value of the relay key it was written under. A new key would change
/// every binding tag, so an identical retry would be answered `REPLAYED` and its token deleted by
/// the client (MS-8): the relay refuses to start until `--nullifiers-reset`, which adopts the new
/// key and refuses the open weeks (review S3-MR-3).
#[test]
fn a_store_kept_under_another_relay_key_is_refused_until_reset() {
    let mut r = TestRelay::new(tuesday());
    assert!(matches!(
        r.redeem(&token("a1"), "alpha", "1"),
        Outcome::Ok(_)
    ));
    drop(r.relay.take());
    r.key = RelayKey::from_bytes([0x43; 32]);
    for mode in [NullifierMode::Existing, NullifierMode::Create] {
        assert!(matches!(
            start_error(r.open(mode).err().unwrap()),
            StartError::NullifierStore(StoreError::KeyMismatch)
        ));
    }
    r.relay = Some(r.open(NullifierMode::Reset).unwrap());
    assert_eq!(
        r.redeem(&token("a1"), "alpha", "1"),
        Outcome::Denied(Code::Unavailable)
    );
    r.restart();
    assert_eq!(
        r.redeem(&token("a1"), "beta", "2"),
        Outcome::Denied(Code::Unavailable)
    );
    // The reset store now belongs to the new key; the old one is refused in turn.
    drop(r.relay.take());
    r.key = RelayKey::from_bytes([0x42; 32]);
    assert!(matches!(
        start_error(r.open(NullifierMode::Existing).err().unwrap()),
        StartError::NullifierStore(StoreError::KeyMismatch)
    ));
}

/// The quota ledger stays in memory and is bounded by restarts only (ADR-25): a clock excursion
/// past a capability's expiry, during which the sweep forgets its ledger, and back again must not
/// give its writer a fresh quota (review S3-MR-5).
#[test]
fn a_clock_excursion_never_restores_a_spent_quota() {
    let r = TestRelay::new(tuesday());
    let now = tuesday();
    let cap = r.key.mint(&Capability {
        kind: Kind::Write,
        namespace: namespace("alpha"),
        quota_bytes: 2_048,
        expiry_unix: now + 7_200,
    });
    let store = |fill: u8, t: u64| {
        let data = vec![fill; 1024];
        r.relay().store_at(
            StoreBlobRequest {
                version: 1,
                blob_hash: ghost_relay_storage::sha256(&data).to_vec(),
                data,
                capability: Some(ghost_relay_api::proto::Capability { token: cap.clone() }),
                ttl_seconds: 86_400,
                request_id: vec![fill; 16],
                namespace_id: namespace("alpha").to_vec(),
            },
            t,
        )
    };
    assert!(store(1, now).is_ok());
    assert!(store(2, now).is_ok());
    assert_eq!(
        store(3, now).unwrap_err().code(),
        Code::ResourceExhausted,
        "the quota is spent"
    );
    // The clock jumps past the expiry and a sweep runs, then the clock steps back.
    r.relay().sweep(now + 7_201).unwrap();
    assert_eq!(
        store(3, now + 10).map(|_| ()).map_err(|s| s.code()),
        Err(Code::PermissionDenied),
        "a writer regained its quota through a clock excursion"
    );
    // A capability that expires after the excursion is unaffected.
    let later = r.key.mint(&Capability {
        kind: Kind::Write,
        namespace: namespace("alpha"),
        quota_bytes: 2_048,
        expiry_unix: now + 86_400,
    });
    let data = vec![4u8; 1024];
    assert!(r
        .relay()
        .store_at(
            StoreBlobRequest {
                version: 1,
                blob_hash: ghost_relay_storage::sha256(&data).to_vec(),
                data,
                capability: Some(ghost_relay_api::proto::Capability { token: later }),
                ttl_seconds: 86_400,
                request_id: vec![4; 16],
                namespace_id: namespace("alpha").to_vec(),
            },
            now + 10,
        )
        .is_ok());
}

fn start_error(e: Box<dyn std::error::Error>) -> StartError {
    match e.downcast::<StartError>() {
        Ok(e) => *e,
        Err(e) => panic!("not a start refusal: {e}"),
    }
}

#[test]
fn the_relay_refuses_to_start_on_its_onion_its_slot_and_its_store() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let clock = VirtualClock::new(tuesday());
    let key = RelayKey::generate();
    let open = |slot: u8, label: &str, mode: NullifierMode, clock: &VirtualClock| {
        open_relay(
            &data,
            &key,
            Some(policy(test_schedule(), slot, label, mode)),
            clock,
            None,
        )
    };
    // An onion the schedule does not list, a slot another relay holds, a slot that does not exist.
    for (slot, label) in [
        (1, "ghost/test/relay-z"),
        (1, RELAY_A),
        (0, RELAY_B),
        (5, RELAY_B),
    ] {
        let e = start_error(
            open(slot, label, NullifierMode::Create, &clock)
                .err()
                .unwrap(),
        );
        assert!(
            matches!(e, StartError::OnionNotListed),
            "{slot} {label}: {e}"
        );
    }
    // Before the slot's first week, and relay-c in the week slot 2 moved to relay-d.
    let early = VirtualClock::new(at("2957-1"));
    assert!(matches!(
        start_error(
            open(1, RELAY_B, NullifierMode::Create, &early)
                .err()
                .unwrap()
        ),
        StartError::OnionNotListed
    ));
    let moved = VirtualClock::new(at("2967+0"));
    assert!(matches!(
        start_error(
            open(2, "ghost/test/relay-c", NullifierMode::Create, &moved)
                .err()
                .unwrap()
        ),
        StartError::OnionNotListed
    ));
    // No refusal wrote anything: the store of this data directory was never created.
    assert!(!data.join(NULLIFIERS_FILE).exists());
    assert!(matches!(
        EntitlementPolicyCheck::slot(32),
        Err(StartError::Slot)
    ));
    // A data directory that redeemed before and lost its store refuses to start (runbook O1).
    assert!(matches!(
        start_error(
            open(1, RELAY_B, NullifierMode::Existing, &clock)
                .err()
                .unwrap()
        ),
        StartError::NullifierStore(StoreError::Missing)
    ));
    // Created once, it opens as existing; the Phase 8 upgrade (create) over it keeps its rows.
    let relay = open(1, RELAY_B, NullifierMode::Create, &clock).unwrap();
    assert!(matches!(
        redeem(
            &relay,
            &token("a1"),
            &namespace("a"),
            &request_id("x"),
            tuesday()
        ),
        Outcome::Ok(_)
    ));
    drop(relay);
    for mode in [NullifierMode::Existing, NullifierMode::Create] {
        let relay = open(1, RELAY_B, mode, &clock).unwrap();
        assert_eq!(
            redeem(
                &relay,
                &token("a1"),
                &namespace("b"),
                &request_id("x"),
                tuesday()
            ),
            Outcome::Replayed
        );
    }
    // A reset over an existing store keeps its rows and refuses the open weeks.
    let relay = open(1, RELAY_B, NullifierMode::Reset, &clock).unwrap();
    assert_eq!(relay.nullifier_store().unwrap().count().unwrap(), 1);
    assert_eq!(
        redeem(
            &relay,
            &token("a2"),
            &namespace("a"),
            &request_id("x"),
            tuesday()
        ),
        Outcome::Denied(Code::Unavailable)
    );
}

/// `EntitlementPolicy::new` with a given slot (the slot rule of the policy constructor).
struct EntitlementPolicyCheck;

impl EntitlementPolicyCheck {
    fn slot(slot: u8) -> Result<(), StartError> {
        ghost_relay_node::EntitlementPolicy::new(test_schedule(), slot, onion(RELAY_B)).map(|_| ())
    }
}

#[test]
fn a_schedule_must_be_append_only_against_the_relays_memory() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let clock = VirtualClock::new(tuesday());
    let key = RelayKey::generate();
    let open = |schedule, mode| {
        open_relay(
            &data,
            &key,
            Some(policy(schedule, 1, RELAY_B, mode)),
            &clock,
            None,
        )
    };
    let refused = |schedule| start_error(open(schedule, NullifierMode::Existing).err().unwrap());
    // seq 2 revokes a future week: accepted, and remembered with the keys.
    let seq2 = schedule_variant(2, &[(TokenKind::Access, 2970)]);
    drop(open(seq2, NullifierMode::Create).unwrap());
    // Rolling back to seq 1 is refused, and seq 1 would also drop the remembered revocation.
    assert!(matches!(
        refused(test_schedule()),
        StartError::Schedule(ScheduleError::Rollback)
    ));
    // A later seq that drops the revocation is refused.
    assert!(matches!(
        refused(schedule_variant(3, &[])),
        StartError::Schedule(ScheduleError::RevocationDropped)
    ));
    // A later seq that moves a key to another week (two access keys swapped) is refused.
    let mut content = test_schedule().content().clone();
    content.seq = 3;
    content.revoked = vec![(TokenKind::Access, 2970)];
    let i = content
        .keys
        .iter()
        .position(|k| k.kind == TokenKind::Access && k.epoch == 2958)
        .unwrap();
    let j = content
        .keys
        .iter()
        .position(|k| k.kind == TokenKind::Access && k.epoch == 2959)
        .unwrap();
    let (spki_i, proof_i) = (content.keys[i].spki.clone(), content.keys[i].proof);
    content.keys[i].spki = content.keys[j].spki.clone();
    content.keys[i].proof = content.keys[j].proof;
    content.keys[j].spki = spki_i;
    content.keys[j].proof = proof_i;
    assert!(matches!(
        refused(resign(&content)),
        StartError::Schedule(ScheduleError::KeyChanged)
    ));
    // A valid successor (seq 3, one more revocation) is accepted and enforced.
    let seq3 = schedule_variant(3, &[(TokenKind::Access, 2970), (TokenKind::Access, 2959)]);
    let relay = open(seq3, NullifierMode::Existing).unwrap();
    assert_eq!(
        redeem(
            &relay,
            &token("a1"),
            &namespace("a"),
            &request_id("x"),
            tuesday()
        ),
        Outcome::Denied(Code::PermissionDenied)
    );
    drop(relay);
    // ... and the revocation it added is now remembered too.
    assert!(matches!(
        refused(schedule_variant(4, &[(TokenKind::Access, 2970)])),
        StartError::Schedule(ScheduleError::RevocationDropped)
    ));
}

// --- Relay mutants (design §13.5; implemented only here). Each detector returns an error when
// the relay under test breaks the property; it passes on the real relay and fails on its mutant.

/// A relay the detectors drive: the real one, or a mutant built around it.
trait UnderTest {
    fn inner(&mut self) -> &mut TestRelay;
    fn redeem(&mut self, token: &[u8], ns: &str, req: &str) -> Outcome {
        self.inner().redeem(token, ns, req)
    }
    fn restart(&mut self) {
        self.inner().restart();
    }
    fn sweep(&mut self) {
        let r = self.inner();
        r.relay().sweep(r.clock.get()).unwrap();
    }
    fn set_clock(&mut self, t: u64) {
        self.inner().clock.set(t);
    }
}

struct Real(TestRelay);

impl UnderTest for Real {
    fn inner(&mut self) -> &mut TestRelay {
        &mut self.0
    }
}

/// MM13 `NullifierMemoryOnly`: the nullifiers are not persisted, so a restart starts empty. Nothing
/// of the store survives, its redemption marker included.
struct NullifierMemoryOnly(TestRelay);

impl UnderTest for NullifierMemoryOnly {
    fn inner(&mut self) -> &mut TestRelay {
        &mut self.0
    }
    fn restart(&mut self) {
        let r = &mut self.0;
        drop(r.relay.take());
        std::fs::remove_file(r.data_dir().join(NULLIFIERS_FILE)).unwrap();
        std::fs::remove_file(r.data_dir().join(REDEMPTION_MARKER_FILE)).unwrap();
        r.relay = Some(r.open(NullifierMode::Create).unwrap());
    }
}

/// MM14 `RandomMint`: the capability serial is random (a valid capability, re-MACed).
struct RandomMint(TestRelay);

impl UnderTest for RandomMint {
    fn inner(&mut self) -> &mut TestRelay {
        &mut self.0
    }
    fn redeem(&mut self, token: &[u8], ns: &str, req: &str) -> Outcome {
        match self.0.redeem(token, ns, req) {
            Outcome::Ok(cap) => {
                let header = capability_header(&cap).unwrap();
                Outcome::Ok(self.0.key.mint_v2(&header, &rand::random::<[u8; 16]>()))
            }
            other => other,
        }
    }
}

/// MM18 `ClosedPeriodReopened`: no persisted high-water, so a restart forgets the closed periods.
struct ClosedPeriodReopened(TestRelay);

impl UnderTest for ClosedPeriodReopened {
    fn inner(&mut self) -> &mut TestRelay {
        &mut self.0
    }
    fn restart(&mut self) {
        let r = &mut self.0;
        drop(r.relay.take());
        let db = redb::Database::create(r.data_dir().join(NULLIFIERS_FILE)).unwrap();
        let txn = db.begin_write().unwrap();
        {
            let mut meta = txn
                .open_table(redb::TableDefinition::<&str, u64>::new("meta"))
                .unwrap();
            meta.remove("closed_through_period").unwrap();
            meta.remove("sweep_high_water_minute").unwrap();
        }
        txn.commit().unwrap();
        drop(db);
        r.relay = Some(r.open(NullifierMode::Existing).unwrap());
    }
}

/// MS-3 across a restart: a token redeemed before the restart is REPLAYED for another namespace.
fn detects_replay_after_restart(r: &mut dyn UnderTest) -> Result<(), String> {
    let a1 = token("a1");
    r.redeem(&a1, "alpha", "1");
    r.restart();
    match r.redeem(&a1, "beta", "2") {
        Outcome::Replayed => Ok(()),
        other => Err(format!("replay after restart answered {other:?}")),
    }
}

/// MS-8: an identical retry after a restart receives identical bytes.
fn detects_changed_bytes_after_restart(r: &mut dyn UnderTest) -> Result<(), String> {
    let a1 = token("a1");
    let before = r.redeem(&a1, "alpha", "1");
    r.restart();
    let after = r.redeem(&a1, "alpha", "1");
    if matches!(before, Outcome::Ok(_)) && before == after {
        Ok(())
    } else {
        Err(format!("identical retry: {before:?} then {after:?}"))
    }
}

/// §19.10: a swept period stays closed when the clock steps back, across a restart.
fn detects_reopened_period(r: &mut dyn UnderTest) -> Result<(), String> {
    let a1 = token("a1");
    r.set_clock(tuesday());
    r.redeem(&a1, "alpha", "1");
    r.set_clock(at("2960+3600"));
    r.sweep();
    r.restart();
    r.set_clock(at("2960-60"));
    match r.redeem(&a1, "beta", "2") {
        Outcome::WrongPeriod => Ok(()),
        other => Err(format!("a closed period answered {other:?}")),
    }
}

type Detector = fn(&mut dyn UnderTest) -> Result<(), String>;

fn detected(name: &str, detector: Detector, mutant: &mut dyn UnderTest) {
    assert_eq!(
        detector(&mut Real(TestRelay::new(tuesday()))),
        Ok(()),
        "{name}: the real relay"
    );
    let verdict = detector(mutant);
    assert!(verdict.is_err(), "{name} was not detected");
}

#[test]
fn mm13_nullifier_memory_only_is_detected() {
    detected(
        "MM13 NullifierMemoryOnly",
        detects_replay_after_restart,
        &mut NullifierMemoryOnly(TestRelay::new(tuesday())),
    );
}

#[test]
fn mm14_random_mint_is_detected() {
    detected(
        "MM14 RandomMint",
        detects_changed_bytes_after_restart,
        &mut RandomMint(TestRelay::new(tuesday())),
    );
}

#[test]
fn mm18_closed_period_reopened_is_detected() {
    detected(
        "MM18 ClosedPeriodReopened",
        detects_reopened_period,
        &mut ClosedPeriodReopened(TestRelay::new(tuesday())),
    );
}

#[test]
fn the_real_relay_passes_every_detector() {
    let detectors: [Detector; 3] = [
        detects_replay_after_restart,
        detects_changed_bytes_after_restart,
        detects_reopened_period,
    ];
    for d in detectors {
        assert_eq!(d(&mut Real(TestRelay::new(tuesday()))), Ok(()));
    }
}
