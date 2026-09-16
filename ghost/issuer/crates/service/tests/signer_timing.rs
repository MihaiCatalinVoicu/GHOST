//! Timing evidence for the issuer's blind signer (Phase 8 design §2.8 point 6, §19.27 point 2,
//! §19.30): a dudect-style Welch t-test, one class signing a fixed blinded value and the other a
//! fresh random one per sample, the classes interleaved in a seeded random order and the inputs
//! drawn before the measurement.
//!
//! Each sample runs the production signing path of `CheckedSigner<ReferenceSigner>` stage by stage
//! on the production key object and times every stage separately (§19.30):
//!
//! - **private-key operation** (asserted): `rsa::hazmat::rsa_decrypt` with the library's random
//!   source, the call `blind-rsa-signatures` =0.17.2 `blind_sign` makes through
//!   `rsa_decrypt_and_check` (rsa 0.10.0-rc.18): base blinding with a fresh r, the CRT
//!   exponentiation on crypto-bigint, unblinding. It is the only stage that reads d, p, q, dP, dQ
//!   or qInv.
//! - **range checks**, **library re-encryption check** (`s'^e` and the comparison with B in rsa),
//!   **fault check** (`CheckedSigner`'s `s'^e == B` in num-bigint-dig) and the **whole production
//!   call** (reported, not asserted): they compute only on n, e, B and s'. The client sends B and
//!   receives s', so their time reveals nothing it does not already hold. Their arithmetic is
//!   variable-time in B and s' (num-bigint-dig's Montgomery reduction, rsa's `rem_vartime`), and
//!   the fixed class repeats one (B, s') pair whose cost differs from the random class's average:
//!   at 10^5 samples on a quiet runner that difference alone exceeds the limit (issue #1).
//! - **CRT exponentiation without base blinding** (reported, not a production call): the same
//!   exponentiation on B itself, which shows how much of the private-key operation's independence
//!   from B rests on base blinding.
//!
//! The test fails when the private-key operation's |t| > 4.5 on all its samples or on those below
//! its pooled 90th percentile (dudect's cropping of scheduler outliers), and when any stage's output
//! differs from the whole production call's. It is evidence, not a gate: the nightly
//! `signer-timing.yml` workflow runs it in the release profile and opens an issue when it fails.
//! Ignored, and meaningful only in the release profile on an otherwise idle host:
//!
//!   cargo test --release -p ghost-issuer --test signer_timing -- --ignored --nocapture
//!
//! `GHOST_TIMING_SAMPLES` overrides the 10^5 samples (a quick local check).

use std::time::Instant;

use blind_rsa_signatures::reexports::crypto_bigint::BoxedUint;
use blind_rsa_signatures::reexports::rsa::hazmat::{rsa_decrypt, rsa_encrypt};
use blind_rsa_signatures::reexports::rsa::traits::PublicKeyParts;
use blind_rsa_signatures::reexports::rsa::RsaPrivateKey;
use blind_rsa_signatures::{DefaultRng, Deterministic, SecretKey, Sha384, PSS};
use ghost_blind_rsa::BigUint;
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

/// One timed stage of the signing path: its samples as (random class, nanoseconds).
struct Stage {
    name: &'static str,
    asserted: bool,
    samples: Vec<(bool, f64)>,
}

/// The statistics of one stage.
struct Summary {
    median: f64,
    t_raw: f64,
    t_crop: f64,
    counts: (f64, f64),
    crop_counts: (f64, f64),
}

impl Stage {
    fn new(name: &'static str, asserted: bool, capacity: usize) -> Self {
        Self {
            name,
            asserted,
            samples: Vec::with_capacity(capacity),
        }
    }

    fn summary(&self) -> Summary {
        let mut sorted: Vec<f64> = self.samples.iter().map(|&(_, x)| x).collect();
        sorted.sort_by(f64::total_cmp);
        let crop = sorted[((sorted.len() as f64 * CROP_PERCENTILE) as usize).min(sorted.len() - 1)];
        let (t_raw, n0, n1) = t_below(&self.samples, f64::INFINITY);
        let (t_crop, c0, c1) = t_below(&self.samples, crop);
        Summary {
            median: sorted[sorted.len() / 2],
            t_raw,
            t_crop,
            counts: (n0, n1),
            crop_counts: (c0, c1),
        }
    }
}

/// Times `f` and records the sample when it is past the warm-up.
fn timed<T>(stage: &mut Stage, record: Option<bool>, f: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let out = f();
    let ns = start.elapsed().as_nanos() as f64;
    if let Some(class) = record {
        stage.samples.push((class, ns));
    }
    std::hint::black_box(out)
}

#[test]
#[ignore = "timing evidence: nightly signer-timing.yml, release profile, --ignored --nocapture"]
fn blind_sign_time_does_not_depend_on_the_blinded_value() {
    let samples: usize = std::env::var("GHOST_TIMING_SAMPLES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(SAMPLES);
    // One key, two objects: the library key the stages use and the production signer.
    let der = ReferenceSigner::generate(Kind::Access, 0)
        .unwrap()
        .to_pkcs8_der()
        .unwrap();
    let library_key = SecretKey::<Sha384, PSS, Deterministic>::from_der(&der).unwrap();
    let key: &RsaPrivateKey = library_key.as_ref();
    let reference = ReferenceSigner::from_pkcs8_der(Kind::Access, 0, &der).unwrap();
    let pk = reference.public_key().clone();
    let n = pk.n().clone();
    let signer = CheckedSigner::new(reference, pk.clone()).unwrap();
    let bits = key.n().bits_precision();

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

    let mut private = Stage::new(
        "private-key operation (rsa_decrypt: base blinding, CRT, unblinding)",
        true,
        samples,
    );
    let mut range = Stage::new(
        "range checks (0 < B < n, CheckedSigner and ReferenceSigner; public)",
        false,
        samples,
    );
    let mut library_check = Stage::new(
        "library re-encryption check (s'^e == B in rsa; public)",
        false,
        samples,
    );
    let mut fault_check = Stage::new(
        "fault check (CheckedSigner, s'^e == B in num-bigint-dig; public)",
        false,
        samples,
    );
    let mut whole = Stage::new(
        "whole CheckedSigner<ReferenceSigner>::blind_sign (includes the public stages)",
        false,
        samples,
    );
    let mut unblinded = Stage::new(
        "CRT exponentiation without base blinding (not a production call)",
        false,
        samples,
    );

    for (i, (class, input)) in plan.iter().enumerate() {
        let record = (i >= WARMUP).then_some(*class);
        let b = BoxedUint::from_be_slice(input, bits).unwrap();
        // The stages in the order of the production call.
        timed(&mut range, record, || {
            (0..2).all(|_| {
                let v = BigUint::from_bytes_be(input);
                v.bits() != 0 && v < n
            })
        });
        let sig = timed(&mut private, record, || {
            rsa_decrypt(Some(&mut DefaultRng), key, &b).unwrap()
        });
        let consistent = timed(&mut library_check, record, || {
            rsa_encrypt(key, &sig).unwrap() == b
        });
        let sig_bytes: [u8; AUTHENTICATOR_LEN] = sig.to_be_bytes()[..].try_into().unwrap();
        let checked = timed(&mut fault_check, record, || {
            ghost_blind_rsa::check_blind_signature(&pk, input, &sig_bytes)
        });
        let production = timed(&mut whole, record, || signer.blind_sign(input).unwrap());
        let plain = timed(&mut unblinded, record, || {
            rsa_decrypt::<DefaultRng>(None, key, &b).unwrap()
        });
        // The stages compute what the production call returns.
        assert!(consistent && checked, "sample {i}: a stage check failed");
        assert_eq!(
            production, sig_bytes,
            "sample {i}: stages differ from the production call"
        );
        assert!(plain == sig, "sample {i}: unblinded result differs");
    }

    let stages = [
        &private,
        &range,
        &library_check,
        &fault_check,
        &whole,
        &unblinded,
    ];
    let (n0, n1) = private.summary().counts;
    println!(
        "blind_sign stages (RSA-2048): {samples} samples ({n0} fixed, {n1} random); |t| above {T_LIMIT} fails only the asserted stage"
    );
    let mut failed = Vec::new();
    for stage in stages {
        let m = stage.summary();
        let tag = if stage.asserted {
            "asserted"
        } else {
            "reported"
        };
        println!(
            "[{tag}] {}: median {:.0} ns; Welch t, all samples: {:.3}; below the 90th percentile ({} fixed, {} random): {:.3}",
            stage.name, m.median, m.t_raw, m.crop_counts.0, m.crop_counts.1, m.t_crop
        );
        if stage.asserted && (m.t_raw.abs() > T_LIMIT || m.t_crop.abs() > T_LIMIT) {
            failed.push(format!(
                "{} (raw {:.3}, cropped {:.3})",
                stage.name, m.t_raw, m.t_crop
            ));
        }
    }
    assert!(
        failed.is_empty(),
        "|t| above {T_LIMIT}: the private-key operation's time depends on the blinded value: {}",
        failed.join("; ")
    );
}
