//! The committed test Entitlement Schedule and its private keys
//! (`issuer/crates/entitlement/tests/fixtures`, never loaded by production code), and the small
//! crash-suite schedule derived from it.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::OnceLock;

use ed25519_dalek::{Signer as _, SigningKey};
use ghost_entitlement::{Kind, Schedule};
use ghost_issuer::custody::KeyWindow;
use ghost_issuer::signer::{CheckedSigner, ReferenceSigner};
use sha2::{Digest, Sha256};

/// First access week of the test schedule (Monday 2026-09-07) and its length.
pub const FIRST_WEEK: u64 = 2957;
pub const WEEKS: u64 = 26;

pub fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../entitlement/tests/fixtures")
}

/// The sealed test keys of the operator tools (`issuer/crates/ops/tests/fixtures/sealed`), sealed
/// under the test custody secret SHA-256("ghost/test/custody-secret").
pub fn sealed_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../ops/tests/fixtures/sealed")
}

pub fn custody_secret_bytes() -> [u8; 32] {
    Sha256::digest(b"ghost/test/custody-secret").into()
}

/// The test schedule key: Ed25519 from SHA-256("ghost/test/schedule-key"). Test schedules only.
pub fn schedule_signing_key() -> SigningKey {
    SigningKey::from_bytes(&Sha256::digest(b"ghost/test/schedule-key").into())
}

pub fn schedule_public_key() -> [u8; 32] {
    schedule_signing_key().verifying_key().to_bytes()
}

pub fn schedule_bytes() -> Vec<u8> {
    std::fs::read(dir().join("test_schedule.ghes")).expect("test_schedule.ghes (run fixture_gen)")
}

pub fn schedule() -> Schedule {
    Schedule::verify_with_key(&schedule_bytes(), &schedule_public_key()).unwrap()
}

/// Every private key of the test schedule, each behind its fault check.
pub fn signers(schedule: &Schedule) -> BTreeMap<(Kind, u64), CheckedSigner<ReferenceSigner>> {
    let text = std::fs::read_to_string(dir().join("test_keys.txt"))
        .expect("test_keys.txt (run fixture_gen)");
    let mut out = BTreeMap::new();
    for line in text
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let f: Vec<&str> = line.split(' ').collect();
        let kind = Kind::from_byte(f[0].parse().unwrap()).unwrap();
        let epoch: u64 = f[1].parse().unwrap();
        let signer =
            ReferenceSigner::from_pkcs8_der(kind, epoch, &hex::decode(f[2]).unwrap()).unwrap();
        let es_key = schedule.key(kind, epoch).unwrap().public_key.clone();
        out.insert((kind, epoch), CheckedSigner::new(signer, es_key).unwrap());
    }
    out
}

/// Re-signs schedule content with the test schedule key.
pub fn sign_content(content: &ghost_entitlement::schedule::ScheduleContent) -> Vec<u8> {
    let sig = schedule_signing_key().sign(&content.signing_message().unwrap());
    content.to_signed_bytes(&sig.to_bytes()).unwrap()
}

/// The crash-suite schedule: the committed test schedule (same keys, proofs, slots, prices) with
/// `access_per_slot = 1` and `trial_per_slot = 1`, re-signed with the test key, so a pack has
/// N = 1·3·5 + 2 + 1 = 18 positions and a trial 6 (the committed one: 243 and 48).
pub fn small_schedule_bytes() -> Vec<u8> {
    let mut content = schedule().content().clone();
    content.constants.access_per_slot = 1;
    content.constants.trial_per_slot = 1;
    sign_content(&content)
}

fn window_of(schedule: &Schedule) -> KeyWindow {
    let mut window = KeyWindow::new();
    for (_, signer) in signers(schedule) {
        window.insert(signer);
    }
    window
}

/// The committed test schedule and every one of its keys, loaded once per test binary.
pub fn full() -> &'static (Schedule, KeyWindow) {
    static FULL: OnceLock<(Schedule, KeyWindow)> = OnceLock::new();
    FULL.get_or_init(|| {
        let s = schedule();
        let w = window_of(&s);
        (s, w)
    })
}

/// The small crash-suite schedule and every one of its keys, loaded once per test binary.
pub fn small() -> &'static (Schedule, KeyWindow) {
    static SMALL: OnceLock<(Schedule, KeyWindow)> = OnceLock::new();
    SMALL.get_or_init(|| {
        let s = Schedule::verify_with_key(&small_schedule_bytes(), &schedule_public_key()).unwrap();
        let w = window_of(&s);
        (s, w)
    })
}
