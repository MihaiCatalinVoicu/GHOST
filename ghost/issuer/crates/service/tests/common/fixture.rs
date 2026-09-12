//! The committed test Entitlement Schedule and its private keys
//! (`issuer/crates/entitlement/tests/fixtures`, never loaded by production code).

use std::collections::BTreeMap;
use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use ghost_entitlement::{Kind, Schedule};
use ghost_issuer::signer::{CheckedSigner, ReferenceSigner};
use sha2::{Digest, Sha256};

/// First access week of the test schedule (Monday 2026-09-07) and its length.
pub const FIRST_WEEK: u64 = 2957;
pub const WEEKS: u64 = 26;

pub fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../entitlement/tests/fixtures")
}

/// The test schedule key: Ed25519 from SHA-256("ghost/test/schedule-key"). Test schedules only.
pub fn schedule_signing_key() -> SigningKey {
    SigningKey::from_bytes(&Sha256::digest(b"ghost/test/schedule-key").into())
}

pub fn schedule_bytes() -> Vec<u8> {
    std::fs::read(dir().join("test_schedule.ghes")).expect("test_schedule.ghes (run fixture_gen)")
}

pub fn schedule() -> Schedule {
    Schedule::verify_with_key(
        &schedule_bytes(),
        &schedule_signing_key().verifying_key().to_bytes(),
    )
    .unwrap()
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
