//! The nonce registry of design §3.7 point 5 (feature `nonce-registry`; always on in the crate's own
//! tests): every `(SHA-256(key), nonce)` the crate seals under, with the SHA-256 of the plaintext it
//! sealed. CS-M1 is "no (key, nonce) pair seals two plaintexts", so a second, **different**
//! plaintext under one pair is a violation; the same plaintext again is not (it is the same
//! ciphertext, which is what a deterministic vector sealed twice in one test process produces).
//!
//! This is the crate's only state, and it is test-only: G-R2 (`rust-feature-policy.sh`, G-M7)
//! keeps the feature out of every shipped graph, and `media-crate-purity.sh` allows a `static` in
//! this file alone. A poisoned lock is read through (a test that panicked while recording must not
//! hide the records of the others).

use std::collections::HashMap;
use std::sync::Mutex;

use sha2::{Digest, Sha256};

type Pair = ([u8; 32], [u8; 12]);

struct State {
    seals: HashMap<Pair, [u8; 32]>,
    violations: Vec<Violation>,
}

static REGISTRY: Mutex<Option<State>> = Mutex::new(None);

/// A second plaintext sealed under one `(key, nonce)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    /// SHA-256 of the key.
    pub key_digest: [u8; 32],
    /// The nonce.
    pub nonce: [u8; 12],
}

/// SHA-256 of a key: the registry never holds a key.
pub fn key_digest(key: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(key).into()
}

/// Records one seal of `plaintext` zero padded to `padded_len` under `(key, nonce)`.
pub(crate) fn record_padded(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8], padded_len: usize) {
    let mut h = Sha256::new();
    h.update(plaintext);
    let pad = padded_len.saturating_sub(plaintext.len());
    let zeros = [0u8; 4096];
    let mut left = pad;
    while left > 0 {
        let n = left.min(zeros.len());
        h.update(zeros.get(..n).unwrap_or(&[]));
        left = left.saturating_sub(n);
    }
    let digest: [u8; 32] = h.finalize().into();
    let pair = (key_digest(key), *nonce);
    let mut guard = REGISTRY.lock().unwrap_or_else(|p| p.into_inner());
    let state = guard.get_or_insert_with(|| State {
        seals: HashMap::new(),
        violations: Vec::new(),
    });
    match state.seals.get(&pair) {
        Some(previous) if *previous != digest => state.violations.push(Violation {
            key_digest: pair.0,
            nonce: pair.1,
        }),
        Some(_) => {}
        None => {
            state.seals.insert(pair, digest);
        }
    }
}

/// Every violation recorded so far whose key digest is `key_digest`.
pub fn violations_for(key_digest: &[u8; 32]) -> Vec<Violation> {
    let guard = REGISTRY.lock().unwrap_or_else(|p| p.into_inner());
    guard
        .as_ref()
        .map(|s| {
            s.violations
                .iter()
                .filter(|v| &v.key_digest == key_digest)
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

/// Every nonce recorded under the key whose digest is `key_digest`.
pub fn nonces_for(key_digest: &[u8; 32]) -> Vec<[u8; 12]> {
    let guard = REGISTRY.lock().unwrap_or_else(|p| p.into_inner());
    let mut out: Vec<[u8; 12]> = guard
        .as_ref()
        .map(|s| {
            s.seals
                .keys()
                .filter(|(k, _)| k == key_digest)
                .map(|(_, n)| *n)
                .collect()
        })
        .unwrap_or_default();
    out.sort_unstable();
    out
}
