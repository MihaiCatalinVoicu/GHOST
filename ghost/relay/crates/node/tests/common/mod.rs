//! Shared helpers of the relay redemption tests (`redeem.rs`, `redeem_vectors.rs`,
//! `two_nodes.rs`): the committed test Entitlement Schedule and re-signed variants of it, the
//! pinned tokens of `protocol/test-vectors/redeem.txt`, virtual clocks and test relays. Test
//! schedules are verified with `Schedule::verify_with_key` under the test schedule key; production
//! code only ever uses the pinned key.
#![allow(dead_code)]

use ed25519_dalek::{Signer as _, SigningKey};
use ghost_entitlement::grid::{self, Kind as TokenKind};
use ghost_entitlement::schedule::{ScheduleContent, SIGNATURE_DOMAIN};
use ghost_entitlement::Schedule;
use ghost_relay_api::proto::{RedeemResult, RedeemTokenRequest, RedeemTokenResponse};
use ghost_relay_api::PROTOCOL_VERSION;
use ghost_relay_capability::RelayKey;
use ghost_relay_node::{Clock, EntitlementPolicy, NullifierMode, Relay, RelayConfig};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tonic::{Code, Status};

/// The committed test Entitlement Schedule (regtest, issuer name `ghost-issuer-test`, access weeks
/// 2957..2982; slots 0 and 1 from week 2957, slot 2 moving from relay-c to relay-d at week 2967).
pub const TEST_SCHEDULE: &[u8] =
    include_bytes!("../../../../../issuer/crates/entitlement/tests/fixtures/test_schedule.ghes");
/// The conformance vectors, compiled in.
pub const VECTORS: &str = include_str!("../../../../../protocol/test-vectors/redeem.txt");

/// Onion labels of the test schedule's relays: the service key is SHA-256 of the label.
pub const RELAY_A: &str = "ghost/test/relay-a"; // slot 0
pub const RELAY_B: &str = "ghost/test/relay-b"; // slot 1
pub const RELAY_C: &str = "ghost/test/relay-c"; // slot 2, weeks 2957..2966
pub const RELAY_D: &str = "ghost/test/relay-d"; // slot 2, from week 2967

/// The test schedule key: Ed25519 from SHA-256("ghost/test/schedule-key"). Test schedules only.
pub fn schedule_key() -> SigningKey {
    SigningKey::from_bytes(&Sha256::digest(b"ghost/test/schedule-key").into())
}

pub fn test_schedule() -> Schedule {
    Schedule::verify_with_key(TEST_SCHEDULE, &schedule_key().verifying_key().to_bytes()).unwrap()
}

/// `content` signed with the test schedule key and verified like any schedule.
pub fn resign(content: &ScheduleContent) -> Schedule {
    let body = content.body().unwrap();
    let sig = schedule_key().sign(&[SIGNATURE_DOMAIN, &body].concat());
    let bytes = content.to_signed_bytes(&sig.to_bytes()).unwrap();
    Schedule::verify_with_key(&bytes, &schedule_key().verifying_key().to_bytes()).unwrap()
}

/// The test schedule under `seq`, revoking `revoked` (kind, epoch) entries.
pub fn schedule_variant(seq: u64, revoked: &[(TokenKind, u64)]) -> Schedule {
    let mut content = test_schedule().content().clone();
    content.seq = seq;
    content.revoked = revoked.to_vec();
    resign(&content)
}

/// Service key of a test onion.
pub fn onion(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

/// A time in the vector notation `<week>+<seconds>` or `<week>-<seconds>`: `start(week) ± s`.
pub fn at(spec: &str) -> u64 {
    let (week, sign, secs) = match spec.split_once('+') {
        Some((w, s)) => (w, 1i128, s),
        None => {
            let (w, s) = spec
                .split_once('-')
                .unwrap_or_else(|| panic!("time {spec}"));
            (w, -1i128, s)
        }
    };
    let start = grid::week_start(week.parse().unwrap()) as i128;
    let t = start + sign * secs.parse::<i128>().unwrap();
    u64::try_from(t).unwrap()
}

/// 32-byte namespace of a name: SHA-256 of the ASCII name.
pub fn namespace(name: &str) -> [u8; 32] {
    Sha256::digest(name.as_bytes()).into()
}

/// 16-byte request id of a name: the first 16 bytes of SHA-256("ghost/test/request/" || name).
pub fn request_id(name: &str) -> Vec<u8> {
    Sha256::digest(format!("ghost/test/request/{name}").as_bytes())[..16].to_vec()
}

/// The pinned tokens of the vector file (`token <name> ... hex=<hex>`), by name.
pub fn pinned_tokens() -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    for raw in VECTORS.lines() {
        let line = raw.split('#').next().unwrap_or_default().trim();
        let Some(rest) = line.strip_prefix("token ") else {
            continue;
        };
        let mut words = rest.split_whitespace();
        let name = words.next().unwrap().to_string();
        if let Some(hex) = words.find_map(|w| w.strip_prefix("hex=")) {
            assert!(out.insert(name, hex::decode(hex).unwrap()).is_none());
        }
    }
    out
}

/// One pinned token.
pub fn token(name: &str) -> Vec<u8> {
    pinned_tokens()
        .remove(name)
        .unwrap_or_else(|| panic!("no pinned token {name}"))
}

/// A virtual clock shared by a test and its relays.
#[derive(Clone)]
pub struct VirtualClock(Arc<AtomicU64>);

impl VirtualClock {
    pub fn new(t: u64) -> Self {
        VirtualClock(Arc::new(AtomicU64::new(t)))
    }

    pub fn set(&self, t: u64) {
        self.0.store(t, Ordering::SeqCst);
    }

    pub fn get(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }

    pub fn clock(&self) -> Clock {
        let cell = Arc::clone(&self.0);
        Arc::new(move || cell.load(Ordering::SeqCst))
    }
}

/// A redemption policy for `slot`, served by the test onion `label`.
pub fn policy(schedule: Schedule, slot: u8, label: &str, mode: NullifierMode) -> EntitlementPolicy {
    let mut p = EntitlementPolicy::new(schedule, slot, onion(label)).unwrap();
    p.nullifiers = mode;
    p
}

/// Opens a relay in `data_dir` at the clock's time.
pub fn open_relay(
    data_dir: &Path,
    key: &RelayKey,
    entitlement: Option<EntitlementPolicy>,
    clock: &VirtualClock,
    capture: Option<&Path>,
) -> Result<Arc<Relay>, Box<dyn std::error::Error>> {
    Relay::open(
        data_dir,
        key.clone(),
        RelayConfig {
            entitlement,
            clock: clock.clock(),
            ..RelayConfig::default()
        },
        capture,
    )
}

pub fn request(token: &[u8], ns: &[u8; 32], req: &[u8]) -> RedeemTokenRequest {
    RedeemTokenRequest {
        version: PROTOCOL_VERSION,
        token: token.to_vec(),
        namespace_id: ns.to_vec(),
        request_id: req.to_vec(),
    }
}

/// What a redemption answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// `OK` with the minted capability.
    Ok(Vec<u8>),
    Replayed,
    WrongPeriod,
    /// A gRPC status.
    Denied(Code),
}

/// The outcome of an answer at `now`; every answer must carry the relay's week and minute, and a
/// capability exactly when the result is `OK`.
pub fn outcome(answer: Result<RedeemTokenResponse, Status>, now: u64) -> Outcome {
    match answer {
        Err(status) => Outcome::Denied(status.code()),
        Ok(r) => {
            assert_eq!(r.relay_period_id, grid::week(now), "relay_period_id");
            assert_eq!(r.relay_minute, now / 60, "relay_minute");
            match RedeemResult::try_from(r.result).unwrap() {
                RedeemResult::Ok => {
                    Outcome::Ok(r.capability.expect("OK carries a capability").token)
                }
                RedeemResult::Replayed => {
                    assert!(r.capability.is_none());
                    Outcome::Replayed
                }
                RedeemResult::WrongPeriod => {
                    assert!(r.capability.is_none());
                    Outcome::WrongPeriod
                }
                RedeemResult::Unspecified => panic!("unspecified result"),
            }
        }
    }
}

/// Redeems at `now` and returns the outcome.
pub fn redeem(relay: &Relay, token: &[u8], ns: &[u8; 32], req: &[u8], now: u64) -> Outcome {
    outcome(relay.redeem_at(request(token, ns, req), now), now)
}

/// The `result` of every line of a capture file.
pub fn capture_results(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            v["result"].as_str().unwrap().to_string()
        })
        .collect()
}
