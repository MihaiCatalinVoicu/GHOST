//! Replays `protocol/test-vectors/redeem.txt` (Phase 8 design §10.8) against the real relay with a
//! virtual clock, through `Relay::redeem_at`, `Relay::sweep` and reopening the data directory. The
//! Kotlin `ModelRedeemRelay` of the entitlement harness replays the same file (slice S9), so the
//! model cannot drift from the relay. The grammar is defined at the top of the vector file.
//!
//! Beyond each line's expectation, every redemption is checked for: exactly one capture event with
//! the stated result and only allowed observables; neither the token, its authenticator nor a
//! minted capability in the capture; and, for `ok`, the capability bytes recomputed here from the
//! documented formulas with an independent HMAC.

mod common;

use common::*;
use ghost_blind_rsa::PublicKey;
use ghost_entitlement::challenge::challenge_digest;
use ghost_entitlement::grid::Kind as TokenKind;
use ghost_entitlement::token::{self, Token};
use ghost_entitlement::Schedule;
use ghost_relay_capability::RelayKey;
use ghost_relay_node::{NullifierMode, Relay, StartError};
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use tonic::Code;

type HmacSha256 = Hmac<Sha256>;

const ISSUER_NAME: &str = "ghost-issuer-test";
const QUOTA: u64 = 268_435_456;
const DEFAULT_KEY: [u8; 32] = [0x42; 32];

struct Section {
    dir: tempfile::TempDir,
    key: [u8; 32],
    schedule: Option<Schedule>,
    slot: u8,
    onion: String,
    clock: VirtualClock,
    relay: Option<Arc<Relay>>,
    capture: PathBuf,
    capture_lines: usize,
    caps: HashMap<String, Vec<u8>>,
}

impl Section {
    fn data_dir(&self) -> PathBuf {
        self.dir.path().join("data")
    }

    fn open(&self, mode: NullifierMode) -> Result<Arc<Relay>, Box<dyn std::error::Error>> {
        let policy = self
            .schedule
            .clone()
            .map(|s| policy(s, self.slot, &self.onion, mode));
        open_relay(
            &self.data_dir(),
            &RelayKey::from_bytes(self.key),
            policy,
            &self.clock,
            Some(&self.capture),
        )
    }

    fn relay(&self) -> &Relay {
        self.relay
            .as_deref()
            .expect("no running relay in this section")
    }

    /// Every capture line so far is an allowed observable (T1).
    fn check_capture(&self) {
        let text = std::fs::read_to_string(&self.capture).unwrap_or_default();
        let violations = schema().check_capture(&text);
        assert!(violations.is_empty(), "capture violations: {violations:#?}");
    }
}

fn schema() -> ghost_capture_check::Schema {
    ghost_capture_check::Schema::parse(include_str!(
        "../../../../test-harness/privacy/allowed-observables.json"
    ))
    .unwrap()
}

struct State {
    section: Option<Section>,
    tokens: HashMap<String, Vec<u8>>,
    expectations: BTreeSet<String>,
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

fn kind_of(name: &str) -> TokenKind {
    match name {
        "access" => TokenKind::Access,
        "invite" => TokenKind::Invite,
        "credit" => TokenKind::Credit,
        other => panic!("unknown kind {other}"),
    }
}

fn hmac(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(key).unwrap();
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

fn nullifier_of(token: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"ghost/v1/nullifier");
    h.update(&token[..98]);
    h.finalize().into()
}

/// A pinned token is what its line declares: nonce, challenge, key id, and a signature that
/// verifies under the declared signer (so the negative cases are correct signatures).
fn check_pinned(name: &str, a: &HashMap<&str, &str>, bytes: &[u8]) {
    let t = Token::parse(bytes).unwrap_or_else(|e| panic!("token {name}: {e}"));
    let nonce: [u8; 32] =
        Sha256::digest(format!("ghost/test/redeem-nonce/{name}").as_bytes()).into();
    assert_eq!(t.nonce(), nonce, "token {name}: nonce");
    let slot = a.get("slot").map(|s| number::<u8>(s));
    let digest = challenge_digest(
        ISSUER_NAME,
        kind_of(arg(a, "kind")),
        number(arg(a, "epoch")),
        slot,
    )
    .unwrap();
    assert_eq!(t.challenge_digest(), digest, "token {name}: challenge");
    let (signer_kind, signer) = arg(a, "signer").split_once(':').unwrap();
    let public_key = if signer_kind == "spki" {
        let spki = hex::decode(signer).unwrap();
        assert_eq!(t.key_id(), token::key_id(&spki), "token {name}: key id");
        assert!(test_schedule().key_by_id(t.key_id()).is_none());
        PublicKey::from_spki(&spki).unwrap()
    } else {
        let schedule = test_schedule();
        let key = schedule
            .key(kind_of(signer_kind), number(signer))
            .unwrap()
            .clone();
        assert_eq!(t.key_id(), key.key_id, "token {name}: key id");
        key.public_key
    };
    t.verify_signature(&public_key)
        .unwrap_or_else(|e| panic!("token {name}: {e}"));
}

/// The capability the documented formulas give for `token` redeemed for `ns` under `key`.
fn expected_capability(
    key: &[u8; 32],
    schedule: &Schedule,
    token: &[u8],
    ns: &[u8; 32],
) -> Vec<u8> {
    let p = schedule.key_by_id(&token[66..98]).unwrap().epoch;
    let n = nullifier_of(token);
    let serial = &hmac(key, &[b"ghost/v1/cap-serial", &p.to_be_bytes(), &n])[..16];
    let expiry = 345_600 + 604_800 * (p + 1) + 3_600;
    let mut body = vec![2u8, 2];
    body.extend_from_slice(ns);
    body.extend_from_slice(&QUOTA.to_be_bytes());
    body.extend_from_slice(&expiry.to_be_bytes());
    body.extend_from_slice(serial);
    let mac = hmac(key, &[&body]);
    body.extend_from_slice(&mac);
    body
}

fn run_line(state: &mut State, words: &[&str], expect: Option<&[&str]>) -> &'static str {
    let op = words[0];
    let a = args(&words[1..]);
    match op {
        "relay" => {
            if let Some(previous) = &state.section {
                previous.check_capture();
            }
            let schedule = match a.get("schedule") {
                Some(&"none") => None,
                Some(other) => panic!("unknown schedule={other}"),
                None => Some(match a.get("revoke") {
                    Some(list) => schedule_variant(
                        2,
                        &list
                            .split(',')
                            .map(|w| (TokenKind::Access, number(w)))
                            .collect::<Vec<_>>(),
                    ),
                    None => test_schedule(),
                }),
            };
            let mode = match a.get("nullifiers").copied().unwrap_or("create") {
                "create" => NullifierMode::Create,
                "reset" => NullifierMode::Reset,
                "existing" => NullifierMode::Existing,
                other => panic!("unknown nullifiers={other}"),
            };
            let dir = tempfile::tempdir().unwrap();
            let capture = dir.path().join("capture.ndjson");
            let mut section = Section {
                key: a
                    .get("key")
                    .map(|k| hex::decode(k).unwrap().try_into().unwrap())
                    .unwrap_or(DEFAULT_KEY),
                schedule,
                slot: a.get("slot").map(|s| number(s)).unwrap_or(0),
                onion: a.get("onion").copied().unwrap_or(RELAY_A).to_string(),
                clock: VirtualClock::new(at(arg(&a, "start"))),
                relay: None,
                capture,
                capture_lines: 0,
                caps: HashMap::new(),
                dir,
            };
            let opened = section.open(mode);
            match expect {
                None => section.relay = Some(opened.unwrap_or_else(|e| panic!("relay: {e}"))),
                Some(["refused"]) => {
                    let e = opened.err().expect("the relay started; expected a refusal");
                    assert!(
                        e.downcast_ref::<StartError>().is_some(),
                        "not a StartError: {e}"
                    );
                    state.expectations.insert("refused".into());
                }
                Some(other) => panic!("unknown relay expectation {other:?}"),
            }
            state.section = Some(section);
            "relay"
        }
        "restart" => {
            let s = state.section.as_mut().expect("restart before relay");
            let mode = match a.get("nullifiers").copied().unwrap_or("existing") {
                "existing" => NullifierMode::Existing,
                "reset" => NullifierMode::Reset,
                other => panic!("unknown nullifiers={other}"),
            };
            drop(s.relay.take());
            s.relay = Some(s.open(mode).unwrap_or_else(|e| panic!("restart: {e}")));
            "restart"
        }
        "at" => {
            let s = state.section.as_mut().expect("at before relay");
            s.clock.set(at(words[1]));
            "at"
        }
        "token" => {
            let name = words[1];
            if a.contains_key("hex") {
                let bytes = state.tokens.get(name).expect("pinned token").clone();
                check_pinned(name, &a, &bytes);
            } else {
                let mut t = state
                    .tokens
                    .get(arg(&a, "from"))
                    .unwrap_or_else(|| panic!("unknown token {}", arg(&a, "from")))
                    .clone();
                if let Some(i) = a.get("xor") {
                    let mask = a
                        .get("mask")
                        .map(|m| u8::from_str_radix(m, 16).unwrap())
                        .unwrap_or(1);
                    t[number::<usize>(i)] ^= mask;
                } else {
                    t.resize(number(arg(&a, "len")), 0);
                }
                assert!(
                    state.tokens.insert(name.to_string(), t).is_none(),
                    "token {name} twice"
                );
            }
            "token"
        }
        "redeem" => {
            let expect = expect.expect("redeem needs an expectation");
            let s = state.section.as_mut().expect("redeem before relay");
            let token = state
                .tokens
                .get(arg(&a, "token"))
                .unwrap_or_else(|| panic!("unknown token {}", arg(&a, "token")))
                .clone();
            let ns = namespace(arg(&a, "ns"));
            let req = request_id(arg(&a, "req"));
            let now = s.clock.get();
            let got = outcome(s.relay().redeem_at(request(&token, &ns, &req), now), now);

            let text = std::fs::read_to_string(&s.capture).unwrap();
            let lines: Vec<&str> = text.lines().collect();
            assert_eq!(
                lines.len(),
                s.capture_lines + 1,
                "exactly one capture event"
            );
            s.capture_lines += 1;
            let event: serde_json::Value = serde_json::from_str(lines[lines.len() - 1]).unwrap();
            assert_eq!(event["op"], "redeem");
            assert_eq!(event["namespace_id"], hex::encode(ns));
            assert_eq!(event["request_id"], hex::encode(&req));
            assert_eq!(event["time_bucket"], now - now % 60);
            // Neither the token nor its authenticator ever reaches the capture.
            if token.len() > 98 {
                assert!(
                    !text.contains(&hex::encode(&token[98..])),
                    "authenticator in the capture"
                );
            }
            assert!(!text.contains(&hex::encode(&token)), "token in the capture");

            let want = expect[0];
            state.expectations.insert(want.to_string());
            let capture_result = match want {
                "ok" => "ok",
                "replayed" => "rejected_nullifier",
                "wrong_period" => "rejected_period",
                "rejected_token" => "rejected_token",
                "rejected_size" => "rejected_size",
                "unavailable" | "unimplemented" => "rejected_capability",
                other => panic!("unknown expectation {other}"),
            };
            assert_eq!(event["result"], capture_result, "capture result");
            let schedule = s.schedule.clone();
            match (got, want) {
                (Outcome::Ok(cap), "ok") => {
                    let schedule = schedule.expect("ok needs a schedule");
                    assert_eq!(
                        cap,
                        expected_capability(&s.key, &schedule, &token, &ns),
                        "capability bytes"
                    );
                    assert!(
                        !text.contains(&hex::encode(&cap)),
                        "capability in the capture"
                    );
                    let n = nullifier_of(&token);
                    let p = schedule.key_by_id(&token[66..98]).unwrap().epoch;
                    assert_eq!(event["nullifier"], hex::encode(n));
                    assert_eq!(event["period_id"], hex::encode(p.to_be_bytes()));
                    assert_eq!(event["capability_scope"], hex::encode(Sha256::digest(&cap)));
                    let name = arg(&args(&expect[1..]), "cap").to_string();
                    match s.caps.get(&name) {
                        Some(bound) => assert_eq!(*bound, cap, "capability {name} changed"),
                        None => {
                            s.caps.insert(name, cap);
                        }
                    }
                }
                (Outcome::Replayed, "replayed") => {
                    assert_eq!(event["nullifier"], hex::encode(nullifier_of(&token)));
                    assert!(event.get("capability_scope").is_none());
                }
                (Outcome::WrongPeriod, "wrong_period") => {
                    assert!(
                        event.get("nullifier").is_none(),
                        "nothing verified, nothing recorded"
                    );
                    assert!(event.get("capability_scope").is_none());
                }
                (Outcome::Denied(code), status) => {
                    let wanted = match status {
                        "rejected_token" => Code::PermissionDenied,
                        "rejected_size" => Code::InvalidArgument,
                        "unavailable" => Code::Unavailable,
                        "unimplemented" => Code::Unimplemented,
                        other => panic!("expected {other}, got {code:?}"),
                    };
                    assert_eq!(code, wanted);
                    assert!(event.get("capability_scope").is_none());
                }
                (got, want) => panic!("expected {want}, got {got:?}"),
            }
            "redeem"
        }
        "capability" => {
            let s = state.section.as_ref().expect("capability before relay");
            let name = words[1];
            let actual = hex::encode(s.caps.get(name).unwrap_or_else(|| panic!("unbound {name}")));
            assert_eq!(
                arg(&a, "hex"),
                actual,
                "capability {name} pin (actual: {actual})"
            );
            "capability"
        }
        "distinct" => {
            let s = state.section.as_ref().expect("distinct before relay");
            let names: Vec<&str> = words[1].split(',').collect();
            let caps: BTreeSet<&Vec<u8>> = names
                .iter()
                .map(|n| s.caps.get(*n).unwrap_or_else(|| panic!("unbound {n}")))
                .collect();
            assert_eq!(
                caps.len(),
                names.len(),
                "capabilities {names:?} not distinct"
            );
            "distinct"
        }
        "sweep" => {
            let expect = expect.expect("sweep needs an expectation");
            let s = state.section.as_ref().expect("sweep before relay");
            let now = s.clock.get();
            let store = s.relay().nullifier_store().expect("a nullifier store");
            let before = store.state().unwrap();
            let report = s.relay().sweep(now).unwrap();
            let after = store.state().unwrap();
            match expect {
                ["skipped"] => {
                    assert!(before.sweep_high_water_minute.is_some_and(|h| now / 60 < h));
                    assert_eq!(after, before, "a skipped sweep changes nothing");
                    assert_eq!(report.nullifiers_removed, 0);
                    state.expectations.insert("skipped".into());
                }
                ["ok", fields @ ..] => {
                    let f = args(fields);
                    let closed = match arg(&f, "closed") {
                        "none" => None,
                        w => Some(number::<u64>(w)),
                    };
                    assert_eq!(after.closed_through_period, closed, "closed-through period");
                    assert_eq!(after.sweep_high_water_minute, Some(now / 60));
                    assert_eq!(
                        report.nullifiers_removed.to_string(),
                        arg(&f, "removed"),
                        "removed"
                    );
                }
                other => panic!("unknown sweep expectation {other:?}"),
            }
            "sweep"
        }
        "nullifiers" => {
            let expect = expect.expect("nullifiers needs an expectation");
            let s = state.section.as_ref().expect("nullifiers before relay");
            let count = s.relay().nullifier_store().unwrap().count().unwrap();
            assert_eq!(count.to_string(), expect[0], "nullifier rows");
            "nullifiers"
        }
        other => panic!("unknown operation {other}"),
    }
}

#[test]
fn the_real_relay_matches_the_redeem_vectors() {
    let mut state = State {
        section: None,
        tokens: pinned_tokens().into_iter().collect(),
        expectations: BTreeSet::new(),
    };
    assert_eq!(
        state.tokens.len(),
        15,
        "the vector file lost a pinned token"
    );
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
            run_line(&mut state, &words, expect.as_deref())
        }))
        .unwrap_or_else(|panic| {
            let msg = panic
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default();
            let short: String = line.chars().take(120).collect();
            panic!("redeem.txt:{lineno}: `{short}`: {msg}")
        });
        if op == "relay" {
            sections += 1;
        }
        seen.insert(op);
    }
    if let Some(last) = &state.section {
        last.check_capture();
    }
    // Every operation and every expectation of the grammar is exercised, so a replayer that skips
    // one is noticed.
    let all: BTreeSet<&str> = [
        "relay",
        "restart",
        "at",
        "token",
        "redeem",
        "capability",
        "distinct",
        "sweep",
        "nullifiers",
    ]
    .into_iter()
    .collect();
    assert_eq!(seen, all);
    let expectations: BTreeSet<String> = [
        "ok",
        "replayed",
        "wrong_period",
        "rejected_token",
        "rejected_size",
        "unavailable",
        "unimplemented",
        "refused",
        "skipped",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    assert_eq!(state.expectations, expectations);
    assert!(sections >= 12, "the vector file lost a section");
}
