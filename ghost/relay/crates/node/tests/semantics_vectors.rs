//! Replays `protocol/test-vectors/relay_semantics.txt` (Phase 7 design §8.7) against the real
//! relay with a virtual clock, through `Relay::{store,get,check,list}_at` and `Relay::sweep`. The
//! Kotlin model relay of the sync harness replays the same file, so the model cannot drift from
//! the relay. The grammar is defined at the top of the vector file.

use ghost_relay_api::proto::{
    Capability as CapabilityToken, CheckBlobsRequest, GetBlobRequest, ListNamespaceRequest,
    StoreBlobRequest,
};
use ghost_relay_api::{PROTOCOL_VERSION, REQUEST_ID_BYTES};
use ghost_relay_capability::{Capability, Kind, RelayKey};
use ghost_relay_node::{Relay, RelayConfig};
use ghost_relay_storage::sha256;
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use tonic::{Code, Status};

/// The vector file, compiled in: a change to it rebuilds and re-runs this test.
const VECTORS: &str = include_str!("../../../../protocol/test-vectors/relay_semantics.txt");

/// `t` in the vector file is `BASE + t` unix seconds.
const BASE: u64 = 1_800_000_000;

/// Client category for a relay status, as `client-core/net/src/categories.rs::for_relay` maps it.
fn category(status: &Status) -> &'static str {
    match status.code() {
        Code::PermissionDenied | Code::Unauthenticated => "unauthorized",
        Code::ResourceExhausted => "quota",
        Code::NotFound => "not_found",
        Code::InvalidArgument => "rejected",
        _ => "relay_unavailable",
    }
}

fn namespace(name: &str) -> [u8; 32] {
    sha256(name.as_bytes())
}

fn blob_bytes(name: &str, size: usize) -> Vec<u8> {
    assert!(name.len() <= size, "blob {name} longer than its size");
    let mut data = name.as_bytes().to_vec();
    data.resize(size, 0);
    data
}

fn hex_decode(s: &str) -> Vec<u8> {
    if s == "empty" {
        return Vec::new();
    }
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
        .collect()
}

/// State of one `relay` section.
struct Section {
    relay: Arc<Relay>,
    _dir: tempfile::TempDir,
    now: u64,
    tokens: HashMap<String, Vec<u8>>,
    blobs: HashMap<String, Vec<u8>>,
    cursors: HashMap<String, Vec<u8>>,
}

impl Section {
    fn open(max_ttl_seconds: u32) -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let relay = Relay::open(
            &dir.path().join("data"),
            RelayKey::generate(),
            RelayConfig {
                max_ttl_seconds,
                ..RelayConfig::default()
            },
            None,
        )
        .expect("relay opens");
        Section {
            relay,
            _dir: dir,
            now: BASE,
            tokens: HashMap::new(),
            blobs: HashMap::new(),
            cursors: HashMap::new(),
        }
    }

    fn token(&self, name: &str) -> Vec<u8> {
        self.tokens
            .get(name)
            .unwrap_or_else(|| panic!("unknown capability {name}"))
            .clone()
    }

    fn blob(&self, name: &str) -> Vec<u8> {
        self.blobs
            .get(name)
            .unwrap_or_else(|| panic!("unknown blob {name}"))
            .clone()
    }

    fn hash_of(&self, name: &str) -> Vec<u8> {
        sha256(&self.blob(name)).to_vec()
    }

    fn name_of_hash(&self, hash: &[u8]) -> String {
        let mut names: Vec<&String> = self
            .blobs
            .iter()
            .filter(|(_, data)| sha256(data)[..] == *hash)
            .map(|(name, _)| name)
            .collect();
        names.sort();
        names
            .first()
            .map(|n| n.to_string())
            .unwrap_or_else(|| "<undeclared>".to_string())
    }

    fn relative(&self, unix: u64) -> String {
        unix.checked_sub(BASE)
            .map(|t| t.to_string())
            .unwrap_or_else(|| format!("<before BASE: {unix}>"))
    }

    fn store(&self, ns: &str, blob: &str, cap: &str, ttl: u32) -> Result<u64, Status> {
        let data = self.blob(blob);
        self.relay
            .store_at(
                StoreBlobRequest {
                    version: PROTOCOL_VERSION,
                    blob_hash: sha256(&data).to_vec(),
                    data,
                    capability: Some(CapabilityToken {
                        token: self.token(cap),
                    }),
                    ttl_seconds: ttl,
                    request_id: vec![0x5A; REQUEST_ID_BYTES],
                    namespace_id: namespace(ns).to_vec(),
                },
                self.now,
            )
            .map(|r| {
                assert!(r.success, "store answered without success");
                assert_eq!(r.stored_hash, self.hash_of(blob), "stored hash");
                r.expiry_unix_seconds
            })
    }
}

/// Splits `line` into the operation words and the expectation after "->".
fn split(line: &str) -> (Vec<&str>, Option<Vec<&str>>) {
    match line.split_once("->") {
        Some((op, expect)) => (
            op.split_whitespace().collect(),
            Some(expect.split_whitespace().collect()),
        ),
        None => (line.split_whitespace().collect(), None),
    }
}

/// `key=value` arguments of an operation.
fn args<'a>(words: &[&'a str]) -> HashMap<&'a str, &'a str> {
    words
        .iter()
        .filter_map(|w| w.split_once('='))
        .collect::<HashMap<_, _>>()
}

fn arg<'a>(args: &HashMap<&'a str, &'a str>, key: &str) -> &'a str {
    args.get(key)
        .copied()
        .unwrap_or_else(|| panic!("missing argument {key}"))
}

fn number<T: std::str::FromStr>(s: &str) -> T {
    s.parse().unwrap_or_else(|_| panic!("not a number: {s}"))
}

/// Symbol list `A,B,C`, or `none`.
fn names(list: &str) -> Vec<String> {
    if list == "none" {
        Vec::new()
    } else {
        list.split(',').map(str::to_string).collect()
    }
}

/// The expectation of a line: `Ok(fields)` for `ok k=v ...`, `Err(category)` otherwise.
fn expectation<'a>(expect: &[&'a str]) -> Result<HashMap<&'a str, &'a str>, &'a str> {
    match expect.first() {
        Some(&"ok") => Ok(args(&expect[1..])),
        Some(category) => {
            assert_eq!(expect.len(), 1, "a failure expectation is one category");
            Err(category)
        }
        None => panic!("empty expectation"),
    }
}

/// Compares an outcome with the expectation and returns the success fields to check further.
fn outcome<'a, T>(
    got: Result<T, Status>,
    expect: &[&'a str],
) -> Option<(T, HashMap<&'a str, &'a str>)> {
    match (got, expectation(expect)) {
        (Ok(v), Ok(fields)) => Some((v, fields)),
        (Err(status), Err(want)) => {
            assert_eq!(category(&status), want, "category");
            None
        }
        (Ok(_), Err(want)) => panic!("expected {want}, the call succeeded"),
        (Err(status), Ok(_)) => panic!(
            "expected ok, got {} ({:?})",
            category(&status),
            status.code()
        ),
    }
}

fn run_line(
    section: &mut Option<Section>,
    words: &[&str],
    expect: Option<&[&str]>,
) -> &'static str {
    let op = words[0];
    if op == "relay" {
        let a = args(&words[1..]);
        *section = Some(Section::open(number(arg(&a, "max_ttl"))));
        return "relay";
    }
    let s = section.as_mut().expect("a `relay` line must come first");
    let a = args(&words[1..]);
    match op {
        "at" => {
            let t: u64 = number(words.get(1).expect("at <t>"));
            assert!(BASE + t >= s.now, "the clock never moves back");
            s.now = BASE + t;
            "at"
        }
        "blob" => {
            let name = words[1];
            let size: usize = number(arg(&a, "size"));
            assert!(
                s.blobs
                    .insert(name.to_string(), blob_bytes(name, size))
                    .is_none(),
                "blob {name} declared twice"
            );
            "blob"
        }
        "cap" => {
            let name = words[1];
            let kind = match arg(&a, "kind") {
                "read" => Kind::Read,
                "write" => Kind::Write,
                other => panic!("unknown kind {other}"),
            };
            let token = s.relay.key().mint(&Capability {
                kind,
                namespace: namespace(arg(&a, "ns")),
                quota_bytes: number(arg(&a, "quota")),
                expiry_unix: BASE + number::<u64>(arg(&a, "expiry")),
            });
            assert!(
                !s.tokens.values().any(|t| *t == token),
                "two capabilities with identical fields share one quota ledger"
            );
            assert!(s.tokens.insert(name.to_string(), token).is_none());
            "cap"
        }
        "token" => {
            let name = words[1];
            let token = if let Some(hex) = a.get("hex") {
                hex_decode(hex)
            } else {
                let mut t = s.token(arg(&a, "from"));
                let i: usize = number(arg(&a, "xor"));
                t[i] ^= 0x01;
                t
            };
            assert!(s.tokens.insert(name.to_string(), token).is_none());
            "token"
        }
        "store" => {
            let expect = expect.expect("store needs an expectation");
            let got = s.store(
                arg(&a, "ns"),
                arg(&a, "blob"),
                arg(&a, "cap"),
                number(arg(&a, "ttl")),
            );
            if let Some((expiry, fields)) = outcome(got, expect) {
                assert_eq!(s.relative(expiry), arg(&fields, "expiry"), "store expiry");
            }
            "store"
        }
        "get" => {
            let expect = expect.expect("get needs an expectation");
            let blob = arg(&a, "blob");
            let got = s.relay.get_at(
                GetBlobRequest {
                    version: PROTOCOL_VERSION,
                    blob_hash: s.hash_of(blob),
                    capability: Some(CapabilityToken {
                        token: s.token(arg(&a, "cap")),
                    }),
                    request_id: vec![0x5B; REQUEST_ID_BYTES],
                },
                s.now,
            );
            if let Some((resp, fields)) = outcome(got, expect) {
                assert_eq!(resp.data, s.blob(blob), "get returns the stored bytes");
                assert_eq!(
                    s.relative(resp.expiry_unix_seconds),
                    arg(&fields, "expiry"),
                    "get expiry"
                );
            }
            "get"
        }
        "check" => {
            let expect = expect.expect("check needs an expectation");
            let asked = names(arg(&a, "blobs"));
            let got = s.relay.check_at(
                CheckBlobsRequest {
                    version: PROTOCOL_VERSION,
                    blob_hashes: asked.iter().map(|b| s.hash_of(b)).collect(),
                    capability: Some(CapabilityToken {
                        token: s.token(arg(&a, "cap")),
                    }),
                },
                s.now,
            );
            if let Some((resp, fields)) = outcome(got, expect) {
                let available: Vec<String> = resp
                    .available_hashes
                    .iter()
                    .map(|h| s.name_of_hash(h))
                    .collect();
                assert_eq!(available, names(arg(&fields, "available")), "available");
            }
            "check"
        }
        "list" => {
            let expect = expect.expect("list needs an expectation");
            let cursor = match arg(&a, "cursor") {
                "start" => Vec::new(),
                k => s
                    .cursors
                    .get(k)
                    .unwrap_or_else(|| panic!("unknown cursor {k}"))
                    .clone(),
            };
            let got = s.relay.list_at(
                ListNamespaceRequest {
                    version: PROTOCOL_VERSION,
                    namespace_id: namespace(arg(&a, "ns")).to_vec(),
                    capability: Some(CapabilityToken {
                        token: s.token(arg(&a, "cap")),
                    }),
                    cursor,
                    limit: number(arg(&a, "limit")),
                },
                s.now,
            );
            if let Some((resp, fields)) = outcome(got, expect) {
                let hashes: Vec<String> =
                    resp.blob_hashes.iter().map(|h| s.name_of_hash(h)).collect();
                assert_eq!(hashes, names(arg(&fields, "hashes")), "listed hashes");
                match arg(&fields, "next") {
                    "end" => assert!(resp.next_cursor.is_empty(), "expected an empty cursor"),
                    k => {
                        assert_eq!(resp.next_cursor.len(), 8, "expected an 8-byte cursor");
                        assert!(
                            s.cursors.insert(k.to_string(), resp.next_cursor).is_none(),
                            "cursor {k} bound twice"
                        );
                    }
                }
            }
            "list"
        }
        "fill" => {
            let expect = expect.expect("fill needs an expectation");
            assert_eq!(expect, ["ok"], "fill expects ok");
            let prefix = arg(&a, "prefix");
            let size: usize = number(arg(&a, "size"));
            let ttl: u32 = number(arg(&a, "ttl"));
            for i in 0..number::<usize>(arg(&a, "count")) {
                let name = format!("{prefix}{i}");
                let data = blob_bytes(&name, size);
                assert!(s.blobs.insert(name.clone(), data).is_none());
                if let Err(status) = s.store(arg(&a, "ns"), &name, arg(&a, "cap"), ttl) {
                    panic!("fill store {name} failed: {}", category(&status));
                }
            }
            "fill"
        }
        "prune" => {
            let expect = expect.expect("prune needs an expectation");
            let report = s.relay.sweep(s.now).expect("sweep");
            let fields = expectation(expect).expect("prune expects ok");
            assert_eq!(
                report.blobs_removed.to_string(),
                arg(&fields, "removed"),
                "memberships removed"
            );
            "prune"
        }
        other => panic!("unknown operation {other}"),
    }
}

#[test]
fn the_real_relay_matches_the_shared_semantics_vectors() {
    let mut section: Option<Section> = None;
    let mut seen = BTreeSet::new();
    let mut sections = 0;
    for (index, raw) in VECTORS.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let (words, expect) = split(line);
        let lineno = index + 1;
        let op = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_line(&mut section, &words, expect.as_deref())
        }))
        .unwrap_or_else(|panic| {
            let msg = panic
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default();
            panic!("relay_semantics.txt:{lineno}: `{line}`: {msg}")
        });
        if op == "relay" {
            sections += 1;
        }
        seen.insert(op);
    }
    // Every operation of the grammar is exercised, so a replayer that skips one is noticed.
    let all: BTreeSet<&str> = [
        "relay", "at", "blob", "cap", "token", "store", "get", "check", "list", "fill", "prune",
    ]
    .into_iter()
    .collect();
    assert_eq!(seen, all);
    assert!(sections >= 7, "the vector file lost a section");
}
