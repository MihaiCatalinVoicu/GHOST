//! Shared helpers of the operator-tool tests: the committed test Entitlement Schedule of
//! ghost-entitlement with its test keys, the ops fixtures, and a runner capturing report lines.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer as _, SigningKey};
use ghost_entitlement::onion::Onion;
use ghost_entitlement::schedule::ScheduleContent;
use ghost_entitlement::{Kind, Schedule};
use ghost_issuer::reconcile::{self, CounterId};
use ghost_issuer::store::{RedbStore, Store};
use ghost_issuer_ops::report::{Code, Field, Line, Value};
use ghost_issuer_ops::{execute, Status};
use sha2::{Digest, Sha256};

/// Price of the test schedule's price epoch 227.
pub const PACK_PRICE: u64 = 200_000_000_000;
/// Monday 2026-09-28 12:00 UTC, access week 2960: the reconciliation fixtures' `--now`.
pub const RECONCILE_NOW: &str = "1790596800";

/// An `issuer.redb` snapshot with the counters of one XMR pack of base week 2960 under the test
/// schedule (3 slots a week, 16 access positions per slot, 2 invites, 1 credit), plus `extra`.
pub fn snapshot(d: &Path, extra: &[(CounterId, u64, u64)]) -> PathBuf {
    let path = d.join("issuer.redb");
    fill(&RedbStore::open(&path).unwrap(), extra);
    path
}

/// Commits the counters of a small issuer (plus `extra`) in one write transaction.
pub fn fill(store: &RedbStore, extra: &[(CounterId, u64, u64)]) {
    let mut tx = store.write().unwrap();
    let mut counts = vec![
        (CounterId::PacksXmr, 2960, 1),
        (CounterId::XmrCreditedAtomic, 2960, PACK_PRICE),
        (CounterId::SignedInvite, 740, 2),
        (CounterId::SignedCredit, 227, 1),
    ];
    counts.extend((2960..2965).map(|w| (CounterId::SignedAccess, w, 48)));
    counts.extend_from_slice(extra);
    for (id, index, delta) in counts {
        reconcile::add(&mut *tx, id, index, delta).unwrap();
    }
    tx.commit().unwrap();
}

/// Access weeks of the test schedule.
pub const FIRST_WEEK: u64 = 2957;
pub const LAST_WEEK: u64 = 2982;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// `issuer/crates/entitlement/tests/fixtures` (test schedule and plain test keys).
pub fn entitlement_fixtures() -> PathBuf {
    manifest_dir().join("../entitlement/tests/fixtures")
}

/// `issuer/crates/ops/tests/fixtures` (schedule source and sealed test keys).
pub fn ops_fixtures() -> PathBuf {
    manifest_dir().join("tests/fixtures")
}

/// `test-harness/gates/entitlement-schedule` (the gate's fixture roots).
pub fn gate_fixtures() -> PathBuf {
    manifest_dir().join("../../../test-harness/gates/entitlement-schedule")
}

pub fn test_schedule_path() -> PathBuf {
    entitlement_fixtures().join("test_schedule.ghes")
}

pub fn test_schedule_bytes() -> Vec<u8> {
    std::fs::read(test_schedule_path()).unwrap()
}

/// The test schedule key: Ed25519 seed SHA-256("ghost/test/schedule-key"). Test schedules only.
pub fn schedule_seed() -> [u8; 32] {
    Sha256::digest(b"ghost/test/schedule-key").into()
}

pub fn schedule_public() -> [u8; 32] {
    SigningKey::from_bytes(&schedule_seed())
        .verifying_key()
        .to_bytes()
}

pub fn schedule_public_hex() -> String {
    hex(&schedule_public())
}

/// The test custody secret: SHA-256("ghost/test/custody-secret"). Test keys only.
pub fn custody_seed() -> [u8; 32] {
    Sha256::digest(b"ghost/test/custody-secret").into()
}

pub fn test_schedule() -> Schedule {
    Schedule::verify_with_key(&test_schedule_bytes(), &schedule_public()).unwrap()
}

pub fn test_content() -> ScheduleContent {
    test_schedule().content().clone()
}

/// Encodes `content` and signs it with the test schedule key.
pub fn resign(content: &ScheduleContent) -> Vec<u8> {
    let key = SigningKey::from_bytes(&schedule_seed());
    let signature = key.sign(&content.signing_message().unwrap());
    content.to_signed_bytes(&signature.to_bytes()).unwrap()
}

/// The plain test keys of the test schedule: (kind, epoch, PKCS #8 DER).
pub fn test_keys() -> Vec<(Kind, u64, Vec<u8>)> {
    let text = std::fs::read_to_string(entitlement_fixtures().join("test_keys.txt")).unwrap();
    text.lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|line| {
            let f: Vec<&str> = line.split(' ').collect();
            (
                Kind::from_byte(f[0].parse().unwrap()).unwrap(),
                f[1].parse().unwrap(),
                unhex(f[2]),
            )
        })
        .collect()
}

/// A test onion: SHA-256 of a label as the service key.
pub fn onion(label: &str, port: u16) -> String {
    Onion {
        pubkey: Sha256::digest(label.as_bytes()).into(),
        port,
    }
    .format()
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

pub fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

pub fn arg(path: &Path) -> String {
    path.to_str().unwrap().to_string()
}

/// Runs one command in process and returns its status and report lines.
pub fn run(args: &[&str]) -> (Status, Vec<Line>) {
    let argv: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let mut lines = Vec::new();
    let status = execute(&argv, &mut lines);
    (status, lines)
}

pub fn field(line: &Line, field: Field) -> Option<&Value> {
    line.fields
        .iter()
        .find(|(f, _)| *f == field)
        .map(|(_, v)| v)
}

pub fn word(line: &Line, f: Field) -> Option<&'static str> {
    match field(line, f) {
        Some(Value::Word(w)) => Some(w),
        _ => None,
    }
}

pub fn num(line: &Line, f: Field) -> Option<u64> {
    match field(line, f) {
        Some(Value::Num(n)) => Some(*n),
        _ => None,
    }
}

/// Asserts the command failed with exactly one line of `code` whose `reason` is `reason`.
pub fn assert_refused(result: &(Status, Vec<Line>), code: Code, reason: &str) {
    let (status, lines) = result;
    let rendered: Vec<String> = lines.iter().map(Line::render).collect();
    assert_ne!(*status, Status::Ok, "{rendered:?}");
    let last = lines.last().expect("a failure line");
    assert_eq!(last.code, code, "{rendered:?}");
    assert_eq!(word(last, Field::Reason), Some(reason), "{rendered:?}");
}

/// One directory line per (onion, operator byte).
pub fn directory_text(relays: &[(&str, u8)]) -> String {
    let mut out = String::from("# test relay directory\n");
    for (label, operator) in relays {
        let port = if *label == "ghost/test/relay-d" {
            9001
        } else {
            443
        };
        out.push_str(&format!(
            "relay {} {}\n",
            onion(label, port),
            hex(&[*operator; 16])
        ));
    }
    out
}
