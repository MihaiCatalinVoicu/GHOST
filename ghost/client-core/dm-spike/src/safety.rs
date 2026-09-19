//! Safety number v1 (design §8.4), only to show that a restore reproduces it (V-1).

use sha2::{Digest, Sha512};

pub const ITERATIONS: usize = 5200;

fn half(identity_pk: &[u8; 32], olm_identity: &[u8; 32]) -> [u8; 64] {
    let mut own = [0u8; 64];
    own[..32].copy_from_slice(identity_pk);
    own[32..].copy_from_slice(olm_identity);
    let mut hash: [u8; 64] = Sha512::new()
        .chain_update(b"ghost/v1/safety-number")
        .chain_update([1u8])
        .chain_update(own)
        .finalize()
        .into();
    for _ in 0..ITERATIONS {
        hash = Sha512::new()
            .chain_update(hash)
            .chain_update(own)
            .finalize()
            .into();
    }
    hash
}

fn digits(hash: &[u8; 64]) -> String {
    let mut out = String::with_capacity(30);
    for j in 0..6 {
        let mut chunk = [0u8; 8];
        chunk[3..].copy_from_slice(&hash[5 * j..5 * j + 5]);
        out.push_str(&format!("{:05}", u64::from_be_bytes(chunk) % 100_000));
    }
    out
}

/// The 60 displayed digits for two `(identity_pk, OI)` pairs.
pub fn display(a: (&[u8; 32], &[u8; 32]), b: (&[u8; 32], &[u8; 32])) -> String {
    let da = digits(&half(a.0, a.1));
    let db = digits(&half(b.0, b.1));
    if da <= db {
        da + &db
    } else {
        db + &da
    }
}
