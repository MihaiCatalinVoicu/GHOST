//! The nonce registry of design §3.7 point 5 (feature `nonce-registry`; always on in the crate's own
//! tests): every `(SHA-256(key), nonce)` the crate seals under, with the SHA-256 of the associated
//! data and the plaintext it sealed.
//!
//! - A **violation** is a second seal under one pair whose associated data or plaintext differs: a
//!   second plaintext reuses the keystream, and a second associated data over the same plaintext
//!   reuses the Poly1305 one-time key, which allows forgery (the review of S1: one `K_f` and
//!   `object_id` sealed as an image and as a video gave the padding chunks identical ciphertexts and
//!   different tags; the plaintext-only digest reported chunk 0 alone).
//! - A **repeat** is the same associated data and plaintext sealed again under one pair: the same
//!   ciphertext, harmless in itself, but §3.7 point 5 says "any repeat fails the run", so it is
//!   recorded too and the tests read both lists for their keys (CS-M1's property run requires both
//!   empty for every fresh key; the vector run requires both empty for the vector keys, whose
//!   hostile re-seals are the tests' own AEAD calls, not the crate's). S2's world runs fail on either
//!   list, with the vector keys allowlisted by name (§22.2).
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
    repeats: Vec<Violation>,
}

static REGISTRY: Mutex<Option<State>> = Mutex::new(None);

/// A second seal under one `(key, nonce)`.
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

/// Records one seal of `plaintext` zero padded to `padded_len` with associated data `ad` under
/// `(key, nonce)`. The digest covers `u64_be(|ad|) || ad || plaintext || zeros`, so no two
/// `(ad, plaintext)` pairs share one input.
pub(crate) fn record_padded(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ad: &[u8],
    plaintext: &[u8],
    padded_len: usize,
) {
    let mut h = Sha256::new();
    h.update(u64::try_from(ad.len()).unwrap_or(u64::MAX).to_be_bytes());
    h.update(ad);
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
        repeats: Vec::new(),
    });
    let entry = Violation {
        key_digest: pair.0,
        nonce: pair.1,
    };
    match state.seals.get(&pair) {
        Some(previous) if *previous != digest => state.violations.push(entry),
        Some(_) => state.repeats.push(entry),
        None => {
            state.seals.insert(pair, digest);
        }
    }
}

fn filtered(key_digest: &[u8; 32], pick: impl Fn(&State) -> &Vec<Violation>) -> Vec<Violation> {
    let guard = REGISTRY.lock().unwrap_or_else(|p| p.into_inner());
    guard
        .as_ref()
        .map(|s| {
            pick(s)
                .iter()
                .filter(|v| &v.key_digest == key_digest)
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

/// Every violation (a second associated data or plaintext under one pair) recorded so far whose
/// key digest is `key_digest`.
pub fn violations_for(key_digest: &[u8; 32]) -> Vec<Violation> {
    filtered(key_digest, |s| &s.violations)
}

/// Every repeat (the same associated data and plaintext sealed again under one pair) recorded so
/// far whose key digest is `key_digest`.
pub fn repeats_for(key_digest: &[u8; 32]) -> Vec<Violation> {
    filtered(key_digest, |s| &s.repeats)
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
