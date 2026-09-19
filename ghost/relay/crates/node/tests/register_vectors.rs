//! Replays `protocol/test-vectors/register.txt` (Phase 9 design §4.7) against the real relay with a
//! virtual clock, through `Relay::{register_key,store,get,check,list}_at`, `Relay::sweep` and
//! reopening the data directory. The Kotlin `ModelRelay` replays the same file (slice S2), so the
//! model cannot drift from the relay. The grammar is defined at the top of the vector file.
//!
//! Beyond each line's expectation, every request is checked for exactly one capture event with the
//! stated result and its identifying fields, and each section's capture for only allowed
//! observables and for never holding a secret, a credential or a verifier. Credentials, verifiers
//! and capabilities are built here from the documented formulas with independent hashes and MACs.

mod common;

use common::{at, namespace, policy, request_id, test_schedule, VirtualClock, RELAY_A, RELAY_B};
use ghost_entitlement::grid;
use ghost_relay_api::proto::{
    Capability as CapabilityMessage, CheckBlobsRequest, GetBlobRequest, ListNamespaceRequest,
    RegisterKeyRequest, RegisterKeyResponse, RegisterResult, StoreBlobRequest,
};
use ghost_relay_api::{PROTOCOL_VERSION, REQUEST_ID_BYTES};
use ghost_relay_capability::RelayKey;
use ghost_relay_node::{NullifierMode, Relay, RelayConfig};
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use tonic::{Code, Status};

type HmacSha256 = Hmac<Sha256>;

/// The vector file, compiled in: a change to it rebuilds and re-runs this test.
const VECTORS: &str = include_str!("../../../../protocol/test-vectors/register.txt");
const RELAY_KEY: [u8; 32] = [0x42; 32];
const DEFAULT_QUOTA: u64 = 268_435_456;

/// A credential v3 of the file, with everything the replayer derives from it.
#[derive(Clone)]
struct Credential {
    kind: u8,
    slot: u8,
    namespace: [u8; 32],
    secret: [u8; 32],
}

impl Credential {
    fn bytes(&self) -> Vec<u8> {
        let mut out = vec![3, self.kind, self.slot];
        out.extend_from_slice(&self.namespace);
        out.extend_from_slice(&self.secret);
        out
    }

    fn verifier(&self) -> [u8; 32] {
        let label: &[u8] = match self.kind {
            1 => b"ghost/v1/read-verifier",
            3 => b"ghost/v1/deposit-verifier",
            4 => b"ghost/v1/fetch-verifier",
            other => panic!("kind {other}"),
        };
        let mut h = Sha256::new();
        h.update(label);
        h.update([self.slot]);
        h.update(self.namespace);
        h.update(self.secret);
        h.finalize().into()
    }
}

struct Section {
    dir: tempfile::TempDir,
    slot: Option<u8>,
    clock: VirtualClock,
    relay: Option<Arc<Relay>>,
    capture: PathBuf,
    capture_lines: usize,
    tokens: HashMap<String, Vec<u8>>,
    credentials: HashMap<String, Credential>,
    blobs: HashMap<String, Vec<u8>>,
}

impl Section {
    fn data_dir(&self) -> PathBuf {
        self.dir.path().join("data")
    }

    fn open(&self, mode: NullifierMode) -> Arc<Relay> {
        let entitlement = self.slot.map(|slot| {
            let onion = if slot == 0 { RELAY_A } else { RELAY_B };
            assert!(slot <= 1, "the vectors use slots 0 and 1");
            policy(test_schedule(), slot, onion, mode)
        });
        Relay::open(
            &self.data_dir(),
            RelayKey::from_bytes(RELAY_KEY),
            RelayConfig {
                entitlement,
                clock: self.clock.clock(),
                ..RelayConfig::default()
            },
            Some(&self.capture),
        )
        .unwrap_or_else(|e| panic!("relay: {e}"))
    }

    fn relay(&self) -> &Relay {
        self.relay.as_deref().expect("no running relay")
    }

    fn token(&self, name: &str) -> Vec<u8> {
        self.tokens
            .get(name)
            .cloned()
            .unwrap_or_else(|| panic!("unknown token {name}"))
    }

    fn credential(&self, name: &str) -> &Credential {
        self.credentials
            .get(name)
            .unwrap_or_else(|| panic!("unknown credential {name}"))
    }

    fn blob(&self, name: &str) -> Vec<u8> {
        self.blobs
            .get(name)
            .cloned()
            .unwrap_or_else(|| panic!("unknown blob {name}"))
    }

    fn name_of_hash(&self, hash: &[u8]) -> String {
        let mut names: Vec<&String> = self
            .blobs
            .iter()
            .filter(|(_, data)| Sha256::digest(data)[..] == *hash)
            .map(|(name, _)| name)
            .collect();
        names.sort();
        names
            .first()
            .map(|n| n.to_string())
            .unwrap_or_else(|| "<undeclared>".into())
    }

    /// The one capture event the last request wrote.
    fn next_event(&mut self) -> serde_json::Value {
        let text = std::fs::read_to_string(&self.capture).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines.len(),
            self.capture_lines + 1,
            "exactly one capture event"
        );
        self.capture_lines += 1;
        serde_json::from_str(lines[lines.len() - 1]).unwrap()
    }

    /// The whole capture holds only allowed observables, and no secret, credential or verifier.
    fn check_capture(&self) {
        let text = std::fs::read_to_string(&self.capture).unwrap_or_default();
        let schema = ghost_capture_check::Schema::parse(include_str!(
            "../../../../test-harness/privacy/allowed-observables.json"
        ))
        .unwrap();
        let violations = schema.check_capture(&text);
        assert!(violations.is_empty(), "capture violations: {violations:#?}");
        for (name, c) in &self.credentials {
            for secret in [
                hex::encode(c.secret),
                hex::encode(c.bytes()),
                hex::encode(c.verifier()),
            ] {
                assert!(!text.contains(&secret), "credential {name} in the capture");
            }
        }
    }
}

fn split(line: &str) -> (Vec<&str>, Option<Vec<&str>>) {
    match line.split_once("->") {
        Some((op, expect)) => (
            op.split_whitespace().collect(),
            Some(expect.split_whitespace().collect()),
        ),
        None => (line.split_whitespace().collect(), None),
    }
}

fn args<'a>(words: &[&'a str]) -> HashMap<&'a str, &'a str> {
    words.iter().filter_map(|w| w.split_once('=')).collect()
}

fn arg<'a>(args: &HashMap<&'a str, &'a str>, key: &str) -> &'a str {
    args.get(key)
        .copied()
        .unwrap_or_else(|| panic!("missing argument {key}"))
}

fn number<T: std::str::FromStr>(s: &str) -> T {
    s.parse().unwrap_or_else(|_| panic!("not a number: {s}"))
}

fn names(list: &str) -> Vec<String> {
    if list == "none" {
        Vec::new()
    } else {
        list.split(',').map(str::to_string).collect()
    }
}

fn kind_byte(name: &str) -> u8 {
    match name {
        "read" => 1,
        "deposit" => 3,
        "fetch" => 4,
        other => panic!("unknown kind {other}"),
    }
}

/// A KeyKind wire value: a kind name, `none` (unspecified) or a raw number.
fn key_kind_value(name: &str) -> i32 {
    match name {
        "none" => 0,
        "read" | "deposit" | "fetch" => i32::from(kind_byte(name)),
        raw => number(raw),
    }
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(key).unwrap();
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

/// Relative notation of an instant for failure messages.
fn show(t: u64) -> String {
    let w = grid::week(t);
    format!("{w}+{}", t - grid::week_start(w))
}

fn assert_time(actual: u64, expected: &str, what: &str) {
    assert_eq!(
        actual,
        at(expected),
        "{what}: got {} ({actual}), expected {expected}",
        show(actual)
    );
}

/// The client category of a relay status (client-core `categories.rs::for_relay`).
fn category(status: &Status) -> &'static str {
    match status.code() {
        Code::PermissionDenied | Code::Unauthenticated => "unauthorized",
        Code::ResourceExhausted => "quota",
        Code::NotFound => "not_found",
        Code::InvalidArgument => "rejected",
        _ => "relay_unavailable",
    }
}

/// Checks a store/get/check/list outcome against its expectation and the capture event; returns
/// the ok fields.
fn outcome<'a, T>(
    s: &mut Section,
    op: &str,
    got: Result<T, Status>,
    expect: &[&'a str],
    seen: &mut BTreeSet<String>,
) -> Option<(T, HashMap<&'a str, &'a str>)> {
    let event = s.next_event();
    assert_eq!(event["op"], op);
    let want = expect[0];
    seen.insert(format!("{op}:{want}"));
    let capture_result = match want {
        "ok" => "ok",
        "unauthorized" | "quota" => "rejected_capability",
        "not_found" => "not_found",
        "rejected_ttl" => "rejected_ttl",
        other => panic!("unknown expectation {other}"),
    };
    assert_eq!(event["result"], capture_result, "capture result");
    match (got, want) {
        (Ok(v), "ok") => Some((v, args(&expect[1..]))),
        (Err(status), "rejected_ttl") => {
            assert_eq!(status.code(), Code::InvalidArgument);
            None
        }
        (Err(status), want) if want != "ok" => {
            assert_eq!(category(&status), want, "category");
            None
        }
        (Ok(_), want) => panic!("expected {want}, the call succeeded"),
        (Err(status), _) => panic!("expected ok, got {:?}", status.code()),
    }
}

fn run_line(
    section: &mut Option<Section>,
    words: &[&str],
    expect: Option<&[&str]>,
    seen: &mut BTreeSet<String>,
) -> &'static str {
    let op = words[0];
    let a = args(&words[1..]);
    if op == "relay" {
        if let Some(previous) = section.as_ref() {
            previous.check_capture();
        }
        let dir = tempfile::tempdir().unwrap();
        let slot = match arg(&a, "slot") {
            "none" => None,
            n => Some(number::<u8>(n)),
        };
        let mut s = Section {
            capture: dir.path().join("capture.ndjson"),
            dir,
            slot,
            clock: VirtualClock::new(at(arg(&a, "start"))),
            relay: None,
            capture_lines: 0,
            tokens: HashMap::new(),
            credentials: HashMap::new(),
            blobs: HashMap::new(),
        };
        s.relay = Some(s.open(NullifierMode::Create));
        *section = Some(s);
        return "relay";
    }
    let s = section.as_mut().expect("a `relay` line must come first");
    match op {
        "restart" | "lose-keys" => {
            drop(s.relay.take());
            if op == "lose-keys" {
                std::fs::remove_file(s.data_dir().join("keys.redb")).expect("keys.redb exists");
            }
            s.relay = Some(s.open(NullifierMode::Existing));
            if op == "restart" {
                "restart"
            } else {
                "lose-keys"
            }
        }
        "at" => {
            s.clock.set(at(words[1]));
            "at"
        }
        "blob" => {
            let name = words[1];
            let mut data = name.as_bytes().to_vec();
            data.resize(number(arg(&a, "size")), 0);
            assert!(s.blobs.insert(name.to_string(), data).is_none());
            "blob"
        }
        "cap" => {
            let name = words[1];
            let token = match words[2] {
                "v2" => {
                    let week: u64 = number(arg(&a, "week"));
                    let quota: u64 = a.get("quota").map_or(DEFAULT_QUOTA, |q| number(q));
                    let serial =
                        &Sha256::digest(format!("ghost/test/serial/{}", arg(&a, "serial")))[..16];
                    let mut body = vec![2u8, 2];
                    body.extend_from_slice(&namespace(arg(&a, "ns")));
                    body.extend_from_slice(&quota.to_be_bytes());
                    body.extend_from_slice(&(grid::week_start(week + 1) + 3_600).to_be_bytes());
                    body.extend_from_slice(serial);
                    let mac = hmac(&RELAY_KEY, &[&body]);
                    body.extend_from_slice(&mac);
                    body
                }
                "v1" => {
                    let kind = match arg(&a, "kind") {
                        "read" => 1u8,
                        "write" => 2,
                        other => panic!("kind {other}"),
                    };
                    let mut body = vec![1u8, kind];
                    body.extend_from_slice(&namespace(arg(&a, "ns")));
                    body.extend_from_slice(&number::<u64>(arg(&a, "quota")).to_be_bytes());
                    body.extend_from_slice(&at(arg(&a, "expiry")).to_be_bytes());
                    let mac = hmac(&RELAY_KEY, &[&body]);
                    body.extend_from_slice(&mac);
                    body
                }
                other => panic!("unknown capability layout {other}"),
            };
            assert!(s.tokens.insert(name.to_string(), token).is_none());
            "cap"
        }
        "credential" => {
            let name = words[1];
            let c = Credential {
                kind: kind_byte(arg(&a, "kind")),
                slot: number(arg(&a, "slot")),
                namespace: namespace(arg(&a, "ns")),
                secret: Sha256::digest(format!("ghost/test/secret/{}", arg(&a, "secret"))).into(),
            };
            assert!(s.tokens.insert(name.to_string(), c.bytes()).is_none());
            s.credentials.insert(name.to_string(), c);
            "credential"
        }
        "token" => {
            let name = words[1];
            let mut t = s.token(arg(&a, "from"));
            if let Some(i) = a.get("xor") {
                let mask = a
                    .get("mask")
                    .map(|m| u8::from_str_radix(m, 16).unwrap())
                    .unwrap_or(1);
                t[number::<usize>(i)] ^= mask;
            } else {
                t.resize(number(arg(&a, "len")), 0);
            }
            assert!(s.tokens.insert(name.to_string(), t).is_none());
            "token"
        }
        "register" => {
            let expect = expect.expect("register needs an expectation");
            let now = s.clock.get();
            let cut = a.get("cut").copied();
            let short = |mut v: Vec<u8>, field: &str| {
                if cut == Some(field) {
                    v.pop();
                }
                v
            };
            let ns = namespace(arg(&a, "ns"));
            let kind = key_kind_value(arg(&a, "kind"));
            let period: u64 = number(arg(&a, "period"));
            let req_id = request_id(arg(&a, "req"));
            let capability = match arg(&a, "cap") {
                "none" => None,
                c => Some(CapabilityMessage { token: s.token(c) }),
            };
            let request = RegisterKeyRequest {
                version: a.get("version").map_or(PROTOCOL_VERSION, |v| number(v)),
                namespace_id: short(ns.to_vec(), "namespace"),
                period_id: period,
                kind,
                verifier: short(
                    s.credential(arg(&a, "verifier")).verifier().to_vec(),
                    "verifier",
                ),
                capability: capability.clone(),
                request_id: short(req_id.clone(), "request"),
            };
            let got = s.relay().register_key_at(request.clone(), now);
            let event = s.next_event();
            assert_eq!(event["op"], "register");
            assert_eq!(event["time_bucket"], now - now % 60);
            assert_eq!(event["period_id"], hex::encode(period.to_be_bytes()));
            match cut {
                Some("namespace") => assert!(event.get("namespace_id").is_none()),
                _ => assert_eq!(event["namespace_id"], hex::encode(ns)),
            }
            match cut {
                Some("request") => assert!(event.get("request_id").is_none()),
                _ => assert_eq!(event["request_id"], hex::encode(&req_id)),
            }
            match arg(&a, "kind") {
                k @ ("read" | "deposit" | "fetch") => assert_eq!(event["key_kind"], k),
                _ => assert!(event.get("key_kind").is_none()),
            }
            match &capability {
                Some(c) => assert_eq!(
                    event["capability_scope"],
                    hex::encode(Sha256::digest(&c.token))
                ),
                None => assert!(event.get("capability_scope").is_none()),
            }
            assert!(event.get("verifier").is_none());
            let want = expect[0];
            seen.insert(format!("register:{want}"));
            let capture_result = match want {
                "ok" => "ok",
                "wrong_period" => "rejected_period",
                "rejected_capability" => "rejected_capability",
                "rejected_size" => "rejected_size",
                other => panic!("unknown expectation {other}"),
            };
            assert_eq!(event["result"], capture_result, "capture result");
            let answered = |r: &RegisterKeyResponse| {
                assert_eq!(r.relay_period_id, grid::week(now), "relay_period_id");
                assert_eq!(r.relay_minute, now / 60, "relay_minute");
            };
            match (got, want) {
                (Ok(r), "ok") => {
                    answered(&r);
                    assert_eq!(r.result, RegisterResult::Ok as i32);
                    let f = args(&expect[1..]);
                    assert_time(r.valid_until_unix, arg(&f, "valid_until"), "valid_until");
                }
                (Ok(r), "wrong_period") => {
                    answered(&r);
                    assert_eq!(r.result, RegisterResult::WrongPeriod as i32);
                    assert_eq!(r.valid_until_unix, 0);
                }
                (Err(status), "rejected_capability") => {
                    assert_eq!(status.code(), Code::PermissionDenied)
                }
                (Err(status), "rejected_size") => assert_eq!(status.code(), Code::InvalidArgument),
                (got, want) => panic!("expected {want}, got {got:?}"),
            }
            "register"
        }
        "store" => {
            let expect = expect.expect("store needs an expectation");
            let now = s.clock.get();
            let data = s.blob(arg(&a, "blob"));
            let token = s.token(arg(&a, "cred"));
            let hash = Sha256::digest(&data).to_vec();
            let got = s.relay().store_at(
                StoreBlobRequest {
                    version: PROTOCOL_VERSION,
                    blob_hash: hash.clone(),
                    data,
                    capability: Some(CapabilityMessage {
                        token: token.clone(),
                    }),
                    ttl_seconds: number(arg(&a, "ttl")),
                    request_id: vec![0x5A; REQUEST_ID_BYTES],
                    namespace_id: namespace(arg(&a, "ns")).to_vec(),
                },
                now,
            );
            if let Some((r, f)) = outcome(s, "store", got, expect, seen) {
                assert!(r.success);
                assert_eq!(r.stored_hash, hash);
                assert_time(r.expiry_unix_seconds, arg(&f, "expiry"), "store expiry");
            }
            "store"
        }
        "get" => {
            let expect = expect.expect("get needs an expectation");
            let now = s.clock.get();
            let blob = arg(&a, "blob");
            let data = s.blob(blob);
            let got = s.relay().get_at(
                GetBlobRequest {
                    version: PROTOCOL_VERSION,
                    blob_hash: Sha256::digest(&data).to_vec(),
                    capability: Some(CapabilityMessage {
                        token: s.token(arg(&a, "cred")),
                    }),
                    request_id: vec![0x5B; REQUEST_ID_BYTES],
                },
                now,
            );
            if let Some((r, f)) = outcome(s, "get", got, expect, seen) {
                assert_eq!(r.data, data, "get returns the stored bytes");
                assert_time(
                    r.uploaded_at_unix_seconds,
                    arg(&f, "uploaded"),
                    "uploaded_at",
                );
                assert_time(r.expiry_unix_seconds, arg(&f, "expiry"), "get expiry");
            }
            "get"
        }
        "check" => {
            let expect = expect.expect("check needs an expectation");
            let now = s.clock.get();
            let asked = names(arg(&a, "blobs"));
            let hashes = asked
                .iter()
                .map(|b| Sha256::digest(s.blob(b)).to_vec())
                .collect();
            let got = s.relay().check_at(
                CheckBlobsRequest {
                    version: PROTOCOL_VERSION,
                    blob_hashes: hashes,
                    capability: Some(CapabilityMessage {
                        token: s.token(arg(&a, "cred")),
                    }),
                },
                now,
            );
            if let Some((r, f)) = outcome(s, "check", got, expect, seen) {
                let available: Vec<String> = r
                    .available_hashes
                    .iter()
                    .map(|h| s.name_of_hash(h))
                    .collect();
                assert_eq!(available, names(arg(&f, "available")), "available");
            }
            "check"
        }
        "list" => {
            let expect = expect.expect("list needs an expectation");
            let now = s.clock.get();
            let got = s.relay().list_at(
                ListNamespaceRequest {
                    version: PROTOCOL_VERSION,
                    namespace_id: namespace(arg(&a, "ns")).to_vec(),
                    capability: Some(CapabilityMessage {
                        token: s.token(arg(&a, "cred")),
                    }),
                    cursor: Vec::new(),
                    limit: 256,
                },
                now,
            );
            if let Some((r, f)) = outcome(s, "list", got, expect, seen) {
                let hashes: Vec<String> = r.blob_hashes.iter().map(|h| s.name_of_hash(h)).collect();
                assert_eq!(hashes, names(arg(&f, "hashes")), "listed hashes");
                assert!(r.next_cursor.is_empty());
            }
            "list"
        }
        "record" => {
            let expect = expect.expect("record needs an expectation");
            let c = s.credential(arg(&a, "verifier")).clone();
            let record = s
                .relay()
                .key_store()
                .record(
                    &namespace(arg(&a, "ns")),
                    number(arg(&a, "period")),
                    kind_byte(arg(&a, "kind")),
                    &c.verifier(),
                )
                .unwrap();
            match (record, expect) {
                (None, ["none"]) => {}
                (Some(r), fields) if !fields.is_empty() && fields[0] != "none" => {
                    let f = args(fields);
                    assert_eq!(r.quota_bytes.to_string(), arg(&f, "quota"), "quota");
                    assert_eq!(r.serials.len().to_string(), arg(&f, "serials"), "serials");
                    assert_time(r.valid_until, arg(&f, "valid_until"), "valid_until");
                }
                (got, want) => panic!("expected {want:?}, got {got:?}"),
            }
            "record"
        }
        "deposits" => {
            let expect = expect.expect("deposits needs an expectation");
            let c = s.credential(arg(&a, "verifier")).clone();
            let key = (
                namespace(arg(&a, "ns")),
                number::<u64>(arg(&a, "period")),
                c.verifier(),
            );
            let (entries, _) = s.relay().deposit_ledger_snapshot();
            let used = entries
                .iter()
                .find(|(record, _, _)| *record == key)
                .map_or(0, |(_, used, _)| *used);
            let f = args(expect);
            assert_eq!(
                used.to_string(),
                arg(&f, "used"),
                "deposit ledger used bytes"
            );
            "deposits"
        }
        "ledger" => {
            let expect = expect.expect("ledger needs an expectation");
            let (entries, _) = s.relay().deposit_ledger_snapshot();
            assert_eq!(
                entries.len().to_string(),
                expect[0],
                "deposit ledger entries"
            );
            "ledger"
        }
        "sweep" => {
            let expect = expect.expect("sweep needs an expectation");
            let now = s.clock.get();
            let keys = s.relay().key_store();
            let before = (
                keys.sweep_high_water_minute().unwrap(),
                keys.counts().unwrap(),
            );
            let report = s.relay().sweep(now).unwrap();
            let after = (
                keys.sweep_high_water_minute().unwrap(),
                keys.counts().unwrap(),
            );
            match expect {
                ["skipped"] => {
                    assert!(before.0.is_some_and(|h| now / 60 < h));
                    assert_eq!(after, before, "a skipped sweep changes nothing");
                    assert_eq!(report.key_records_removed, 0);
                    seen.insert("sweep:skipped".into());
                }
                ["ok", fields @ ..] => {
                    assert_eq!(after.0, Some(now / 60));
                    let f = args(fields);
                    assert_eq!(
                        report.key_records_removed.to_string(),
                        arg(&f, "removed"),
                        "registrations removed"
                    );
                    seen.insert("sweep:ok".into());
                }
                other => panic!("unknown sweep expectation {other:?}"),
            }
            "sweep"
        }
        other => panic!("unknown operation {other}"),
    }
}

#[test]
fn the_real_relay_matches_the_register_vectors() {
    let mut section: Option<Section> = None;
    let mut ops = BTreeSet::new();
    let mut seen = BTreeSet::new();
    let mut sections = 0;
    let mut cases = 0;
    for (index, raw) in VECTORS.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let (words, expect) = split(line);
        let lineno = index + 1;
        let op = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_line(&mut section, &words, expect.as_deref(), &mut seen)
        }))
        .unwrap_or_else(|panic| {
            let msg = panic
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default();
            panic!("register.txt:{lineno}: `{line}`: {msg}")
        });
        if op == "relay" {
            sections += 1;
        }
        if expect.is_some() {
            cases += 1;
        }
        ops.insert(op);
    }
    if let Some(last) = &section {
        last.check_capture();
    }
    // Every operation and every expectation of the grammar is exercised, so a replayer that skips
    // one is noticed.
    let all: BTreeSet<&str> = [
        "relay",
        "restart",
        "lose-keys",
        "at",
        "blob",
        "cap",
        "credential",
        "token",
        "register",
        "store",
        "get",
        "check",
        "list",
        "record",
        "deposits",
        "ledger",
        "sweep",
    ]
    .into_iter()
    .collect();
    assert_eq!(ops, all);
    let expectations: BTreeSet<String> = [
        "register:ok",
        "register:wrong_period",
        "register:rejected_capability",
        "register:rejected_size",
        "store:ok",
        "store:unauthorized",
        "store:quota",
        "store:rejected_ttl",
        "get:ok",
        "get:unauthorized",
        "get:not_found",
        "check:ok",
        "check:unauthorized",
        "list:ok",
        "list:unauthorized",
        "sweep:ok",
        "sweep:skipped",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    assert_eq!(seen, expectations);
    assert!(sections >= 5, "the vector file lost a section");
    assert!(cases >= 45, "the vector file lost cases ({cases})");
}
