//! Timing evidence for the issuer's blind signer (Phase 8 design §2.8 point 6, §13.7; S12 review
//! CR-CT-1): a dudect-style Welch t-test on `CheckedSigner<ReferenceSigner>::blind_sign`, the
//! production signing path (base-blinded constant-time `crypto-bigint` exponentiation, then the
//! `num-bigint-dig` fault check). One class signs a fixed blinded value, the other a fresh random
//! one per sample; the classes are interleaved in a seeded random order, the inputs are drawn
//! before the measurement, and each sample times one `blind_sign`. The test fails when |t| > 4.5
//! on the raw samples or on those below the pooled 90th percentile (dudect's cropping of
//! scheduler outliers). It is evidence, not a gate: the nightly `signer-timing.yml` workflow runs
//! it in the release profile and opens an issue when it fails. Ignored, and meaningful only in the
//! release profile on an otherwise idle host:
//!
//!   cargo test --release -p ghost-issuer --test signer_timing -- --ignored --nocapture
//!
//! `GHOST_TIMING_SAMPLES` overrides the 10^5 samples (a quick local check).

use std::time::Instant;

use ghost_entitlement::token::AUTHENTICATOR_LEN;
use ghost_entitlement::Kind;
use ghost_issuer::signer::{CheckedSigner, ReferenceSigner, Signer};
use sha2::{Digest, Sha512};

const SAMPLES: usize = 100_000;
const WARMUP: usize = 200;
/// dudect's threshold: |t| above it is a timing difference between the classes.
const T_LIMIT: f64 = 4.5;
/// The cropped test keeps the samples below this pooled percentile.
const CROP_PERCENTILE: f64 = 0.90;

/// A pseudo-random stream: SHA-512 of a label and a counter.
struct Stream {
    label: &'static [u8],
    counter: u64,
}

impl Stream {
    fn next(&mut self) -> [u8; 64] {
        self.counter += 1;
        Sha512::digest([self.label, &self.counter.to_be_bytes()].concat()).into()
    }

    /// A blinded value below 2^2047 < n (every issuer modulus has its top bit set).
    fn blinded(&mut self) -> [u8; AUTHENTICATOR_LEN] {
        let mut block = [0u8; AUTHENTICATOR_LEN];
        for chunk in block.chunks_mut(64) {
            chunk.copy_from_slice(&self.next());
        }
        block[0] &= 0x7f;
        block[0] |= 0x40;
        block
    }

    fn bit(&mut self) -> bool {
        self.next()[0] & 1 == 1
    }
}

/// Welch's t over two classes of samples (Welford's running mean and variance).
#[derive(Default, Clone, Copy)]
struct Moments {
    n: f64,
    mean: f64,
    m2: f64,
}

impl Moments {
    fn push(&mut self, x: f64) {
        self.n += 1.0;
        let d = x - self.mean;
        self.mean += d / self.n;
        self.m2 += d * (x - self.mean);
    }

    fn variance(&self) -> f64 {
        self.m2 / (self.n - 1.0)
    }
}

fn welch(a: &Moments, b: &Moments) -> f64 {
    (a.mean - b.mean) / (a.variance() / a.n + b.variance() / b.n).sqrt()
}

/// (t, samples of class 0, samples of class 1) over the samples at or below `limit`.
fn t_below(samples: &[(bool, f64)], limit: f64) -> (f64, f64, f64) {
    let mut m = [Moments::default(); 2];
    for &(class, x) in samples.iter().filter(|(_, x)| *x <= limit) {
        m[usize::from(class)].push(x);
    }
    (welch(&m[0], &m[1]), m[0].n, m[1].n)
}

#[test]
fn welch_t_separates_shifted_classes_and_not_equal_ones() {
    // The statistic itself: equal classes stay near 0, a shift of 1 % of the mean with little
    // noise is far above the limit.
    let mut s = Stream {
        label: b"ghost/t/welch",
        counter: 0,
    };
    let noise = |s: &mut Stream| f64::from(s.next()[1]) / 255.0;
    let equal: Vec<(bool, f64)> = (0..20_000)
        .map(|_| (s.bit(), 100.0 + noise(&mut s)))
        .collect();
    assert!(t_below(&equal, f64::INFINITY).0.abs() < T_LIMIT);
    let shifted: Vec<(bool, f64)> = (0..20_000)
        .map(|_| {
            let c = s.bit();
            (c, 100.0 + noise(&mut s) + if c { 1.0 } else { 0.0 })
        })
        .collect();
    assert!(t_below(&shifted, f64::INFINITY).0.abs() > T_LIMIT);
}

#[test]
#[ignore = "timing evidence: nightly signer-timing.yml, release profile, --ignored --nocapture"]
fn blind_sign_time_does_not_depend_on_the_blinded_value() {
    let samples: usize = std::env::var("GHOST_TIMING_SAMPLES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(SAMPLES);
    let signer = ReferenceSigner::generate(Kind::Access, 0).unwrap();
    let pk = signer.public_key().clone();
    let signer = CheckedSigner::new(signer, pk).unwrap();
    let mut s = Stream {
        label: b"ghost/t/signer-timing",
        counter: 0,
    };
    let fixed = s.blinded();
    // Classes and inputs are drawn before any measurement.
    let plan: Vec<(bool, [u8; AUTHENTICATOR_LEN])> = (0..WARMUP + samples)
        .map(|_| {
            let random = s.bit();
            (random, if random { s.blinded() } else { fixed })
        })
        .collect();
    let mut measured = Vec::with_capacity(samples);
    for (i, (class, input)) in plan.iter().enumerate() {
        let start = Instant::now();
        let sig = signer.blind_sign(input).unwrap();
        let ns = start.elapsed().as_nanos() as f64;
        std::hint::black_box(sig);
        if i >= WARMUP {
            measured.push((*class, ns));
        }
    }
    let mut sorted: Vec<f64> = measured.iter().map(|&(_, x)| x).collect();
    sorted.sort_by(f64::total_cmp);
    let crop = sorted[((sorted.len() as f64 * CROP_PERCENTILE) as usize).min(sorted.len() - 1)];
    let (t_raw, n0, n1) = t_below(&measured, f64::INFINITY);
    let (t_crop, c0, c1) = t_below(&measured, crop);
    println!(
        "blind_sign (CheckedSigner<ReferenceSigner>, RSA-2048): {samples} samples ({n0} fixed, {n1} random), median {:.0} ns",
        sorted[sorted.len() / 2]
    );
    println!("Welch t, all samples: {t_raw:.3}");
    println!("Welch t, samples below the 90th percentile ({crop:.0} ns; {c0} fixed, {c1} random): {t_crop:.3}");
    assert!(
        t_raw.abs() <= T_LIMIT && t_crop.abs() <= T_LIMIT,
        "|t| above {T_LIMIT}: the signing time depends on the blinded value (raw {t_raw:.3}, cropped {t_crop:.3})"
    );
}
