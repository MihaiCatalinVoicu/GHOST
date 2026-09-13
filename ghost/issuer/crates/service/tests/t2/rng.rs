//! Deterministic randomness of the T2 world. Every draw comes from a labelled stream of one of seven
//! pinned seeds, so a twin world can change exactly one kind of randomness (§13.4 NI-1: issuer and
//! chain; NI-2: token-level client randomness and namespaces) and keep every other draw identical:
//!
//! | seed | draws |
//! |---|---|
//! | `user` | population, user behaviour (sessions, payments, purchases, writes, namespace activity) |
//! | `sched` | client scheduling (job cadence, process keys and quiet draws, flow ids, claim keys, retry and activation uniforms, drop times) |
//! | `token` | token-level client randomness (blinding seeds) |
//! | `ns` | namespaces, blob contents, redeem request ids, relay circuit keys |
//! | `issuer` | the issuer's random port (invoice ids), response latencies |
//! | `chain` | block times and mining delays |
//! | `fault` | injected faults (client crashes after a send, redeem timeouts, `UNAVAILABLE` answers) |

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Seeds {
    pub user: u64,
    pub sched: u64,
    pub token: u64,
    pub ns: u64,
    pub issuer: u64,
    pub chain: u64,
    pub fault: u64,
}

impl Seeds {
    /// The seven seeds of one pinned world seed.
    pub fn of(seed: u64) -> Self {
        let d = |i: u64| {
            let h = Sha256::digest(
                [
                    b"ghost/t2/seed".as_slice(),
                    &seed.to_be_bytes(),
                    &i.to_be_bytes(),
                ]
                .concat(),
            );
            u64::from_be_bytes(h[..8].try_into().unwrap())
        };
        Seeds {
            user: d(1),
            sched: d(2),
            token: d(3),
            ns: d(4),
            issuer: d(5),
            chain: d(6),
            fault: d(7),
        }
    }
}

/// 32 bytes derived from a seed and labelled parts (keys, seeds, ids).
pub fn derive32(seed: u64, parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"ghost/t2/derive");
    h.update(seed.to_be_bytes());
    for p in parts {
        h.update((p.len() as u32).to_be_bytes());
        h.update(p);
    }
    h.finalize().into()
}

/// A PRF output in [0, 1): the top 53 bits of HMAC-SHA256(key, input).
pub fn prf_unit(key: &[u8; 32], input: &[u8]) -> f64 {
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("any key");
    m.update(input);
    let out = m.finalize().into_bytes();
    (u64::from_be_bytes(out[..8].try_into().unwrap()) >> 11) as f64 * (1.0 / (1u64 << 53) as f64)
}

/// xoshiro256** seeded from a labelled derivation.
#[derive(Debug, Clone)]
pub struct Rng {
    s: [u64; 4],
}

impl Rng {
    pub fn new(seed: u64, parts: &[&[u8]]) -> Self {
        let k = derive32(seed, parts);
        let mut s = [0u64; 4];
        for (i, w) in s.iter_mut().enumerate() {
            *w = u64::from_le_bytes(k[i * 8..i * 8 + 8].try_into().unwrap());
        }
        if s == [0; 4] {
            s[0] = 1;
        }
        Rng { s }
    }

    pub fn next_u64(&mut self) -> u64 {
        let result = self.s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);
        result
    }

    /// Uniform in [0, 1) with 53 bits.
    pub fn uniform(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 * (1.0 / (1u64 << 53) as f64)
    }

    /// Uniform in [0, n), n > 0.
    pub fn below(&mut self, n: u64) -> u64 {
        let zone = u64::MAX - u64::MAX % n;
        loop {
            let x = self.next_u64();
            if x < zone {
                return x % n;
            }
        }
    }

    /// Uniform in [lo, hi).
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        if hi <= lo {
            lo
        } else {
            lo + self.below(hi - lo)
        }
    }

    pub fn chance(&mut self, p: f64) -> bool {
        self.uniform() < p
    }

    pub fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        for c in out.chunks_mut(8) {
            let w = self.next_u64().to_le_bytes();
            c.copy_from_slice(&w[..c.len()]);
        }
        out
    }

    pub fn fill(&mut self, out: &mut [u8]) {
        for c in out.chunks_mut(8) {
            let w = self.next_u64().to_le_bytes();
            c.copy_from_slice(&w[..c.len()]);
        }
    }

    /// Poisson(λ) (Knuth; λ small).
    pub fn poisson(&mut self, lambda: f64) -> u32 {
        let l = (-lambda).exp();
        let mut k = 0;
        let mut p = 1.0;
        loop {
            p *= self.uniform();
            if p <= l {
                return k;
            }
            k += 1;
        }
    }
}
