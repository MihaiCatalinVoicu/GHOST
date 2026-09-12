//! Signer benchmark (Phase 8 design §15.1 S1): budget <= 5 ms per 2048-bit blind signature on the
//! CI runner; above it, fallback 1 (in-house crypto-bigint signer) is due before S4. Ignored, and
//! meaningful only in the release profile:
//!
//!   cargo test --release -p ghost-issuer --test signer_bench -- --ignored --nocapture

use std::time::Instant;

use ghost_entitlement::token::AUTHENTICATOR_LEN;
use ghost_entitlement::Kind;
use ghost_issuer::signer::{CheckedSigner, ReferenceSigner, Signer};
use sha2::{Digest, Sha512};

const SIGNATURES: usize = 500;
const WARMUP: usize = 20;
const BUDGET_MS: f64 = 5.0;

/// Distinct blinded values below 2^2047 <= n, from a SHA-512 chain.
fn inputs() -> Vec<[u8; AUTHENTICATOR_LEN]> {
    (0..SIGNATURES + WARMUP)
        .map(|i| {
            let mut block = [0u8; AUTHENTICATOR_LEN];
            for (c, chunk) in block.chunks_mut(64).enumerate() {
                chunk.copy_from_slice(&Sha512::digest(
                    [&(i as u64).to_be_bytes()[..], &[c as u8]].concat(),
                ));
            }
            block[0] &= 0x7f;
            block
        })
        .collect()
}

fn ms_per_signature(signer: &dyn Signer, inputs: &[[u8; AUTHENTICATOR_LEN]]) -> f64 {
    for b in &inputs[..WARMUP] {
        signer.blind_sign(b).unwrap();
    }
    let start = Instant::now();
    for b in &inputs[WARMUP..] {
        signer.blind_sign(b).unwrap();
    }
    start.elapsed().as_secs_f64() * 1_000.0 / SIGNATURES as f64
}

#[test]
#[ignore = "benchmark: run in release with --ignored --nocapture"]
fn reference_signer_cost_per_blind_signature() {
    let inputs = inputs();
    let signer = ReferenceSigner::generate(Kind::Access, 0).unwrap();
    let pk = signer.public_key().clone();
    let raw = ms_per_signature(&signer, &inputs);
    let checked = CheckedSigner::new(signer, pk).unwrap();
    let with_check = ms_per_signature(&checked, &inputs);
    println!(
        "reference signer (blind-rsa-signatures 0.17.2, RSA-2048): {raw:.3} ms per blind signature"
    );
    println!("CheckedSigner (plus the num-bigint-dig s'^e == B check): {with_check:.3} ms per blind signature");
    println!(
        "pack of 643 positions (S = 8): {:.2} s signing",
        with_check * 643.0 / 1_000.0
    );
    assert!(
        with_check <= BUDGET_MS,
        "{with_check:.3} ms exceeds the {BUDGET_MS} ms budget"
    );
}
