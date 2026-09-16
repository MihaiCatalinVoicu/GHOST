//! V-6: X-Wing draft-06 through `libcrux-kem` 0.0.9 (portable build, see `.cargo/config.toml`):
//! the published vectors, a differential test against RustCrypto `x-wing` 0.1.0, the low-order
//! and invalid-key vectors of design §22.8.2, and host timings.
//!
//! Timings print with `cargo test --release --test v6_xwing -- --nocapture`.

use ghost_dm_spike::codes::Code;
use ghost_dm_spike::olm::random_bytes;
use ghost_dm_spike::xwing;
use libcrux_kem::{Algorithm, Ct, PrivateKey, PublicKey};
use serde_json::Value;
use std::panic::catch_unwind;
use std::time::Instant;
use x_wing::{Decapsulate, Decapsulator, KeyExport};

const VECTORS: &str = include_str!("../vectors/xwing-draft06.json");

fn hex_field(v: &Value, name: &str) -> Vec<u8> {
    hex::decode(v[name].as_str().expect("hex field")).expect("hex")
}

#[test]
fn draft06_vectors() {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS).expect("json");
    assert_eq!(vectors.len(), 3);
    for v in &vectors {
        let seed: [u8; 32] = hex_field(v, "seed").try_into().expect("seed 32");
        assert_eq!(hex_field(v, "sk"), seed.to_vec(), "sk is the 32-byte seed");
        let pk = xwing::public_key(&seed).expect("keygen");
        assert_eq!(pk, hex_field(v, "pk"));
        let eseed: [u8; 64] = hex_field(v, "eseed").try_into().expect("eseed 64");
        let (ct, ss) = xwing::encapsulate_derand(&pk, &eseed).expect("encaps");
        assert_eq!(ct, hex_field(v, "ct"));
        assert_eq!(ss.to_vec(), hex_field(v, "ss"));
        assert_eq!(
            xwing::decapsulate(&seed, &ct).expect("decaps").to_vec(),
            hex_field(v, "ss")
        );
    }
}

#[test]
fn differential_against_rustcrypto_x_wing() {
    for _ in 0..256 {
        let seed: [u8; 32] = random_bytes();
        let eseed: [u8; 64] = random_bytes();
        let pk = xwing::public_key(&seed).expect("keygen");
        let other = x_wing::DecapsulationKey::from(seed);
        assert_eq!(
            pk.as_slice(),
            other.encapsulation_key().to_bytes().as_slice()
        );
        let (ct, ss) = xwing::encapsulate_derand(&pk, &eseed).expect("encaps");
        let (other_ct, other_ss) = other
            .encapsulation_key()
            .encapsulate_deterministic(&eseed.into());
        assert_eq!(ct.as_slice(), other_ct.as_slice());
        assert_eq!(ss.as_slice(), other_ss.as_slice());
        assert_eq!(
            xwing::decapsulate(&seed, &ct).expect("decaps").as_slice(),
            other.decapsulate(&other_ct).as_slice()
        );
    }
}

/// Small-order X25519 u-coordinates (the 8-torsion subgroup) and u = p (non-canonical zero).
fn low_order_points() -> Vec<[u8; 32]> {
    let mut out: Vec<[u8; 32]> = curve25519_dalek::constants::EIGHT_TORSION
        .iter()
        .map(|p| p.to_montgomery().to_bytes())
        .collect();
    let mut p = [0xffu8; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    out.push(p);
    let mut p_plus_one = p;
    p_plus_one[0] = 0xee;
    out.push(p_plus_one);
    out.sort();
    out.dedup();
    out
}

#[test]
fn low_order_x25519_half_of_a_public_key() {
    let seed: [u8; 32] = random_bytes();
    let eseed: [u8; 64] = random_bytes();
    let valid = xwing::public_key(&seed).expect("keygen");
    let points = low_order_points();
    println!("V6 low-order u-coordinates tested: {}", points.len());
    for point in points {
        let mut pk = valid.clone();
        pk[1184..].copy_from_slice(&point);
        // GHOST's whole-key validation refuses it.
        assert_eq!(xwing::validate_public_key(&pk).err().map(|_| ()), Some(()));
        assert_eq!(xwing::encapsulate(&pk).err(), Some(Code::InvalidKey));
        // libcrux alone decodes it (ML-KEM half only) and then fails encapsulation.
        assert!(PublicKey::decode(Algorithm::XWingKemDraft06, &pk).is_ok());
        assert_eq!(
            xwing::encapsulate_derand_library(&pk, &eseed).err(),
            Some(Code::InvalidKey)
        );
        // RustCrypto x-wing never fails: it returns a secret for the same input.
        let other = x_wing::EncapsulationKey::try_from(pk.as_slice()).expect("x-wing accepts");
        let _ = other.encapsulate_deterministic(&eseed.into());
    }
}

#[test]
fn low_order_x25519_half_of_a_ciphertext() {
    let seed: [u8; 32] = random_bytes();
    let pk = xwing::public_key(&seed).expect("keygen");
    let (ct, _) = xwing::encapsulate(&pk).expect("encaps");
    for point in low_order_points() {
        let mut bad = ct.clone();
        bad[1088..].copy_from_slice(&point);
        assert_eq!(xwing::decapsulate(&seed, &bad).err(), Some(Code::NotOpen));
        let other = x_wing::DecapsulationKey::from(seed);
        let ciphertext = x_wing::Ciphertext::try_from(bad.as_slice()).expect("1120 bytes");
        let _ = other.decapsulate(&ciphertext);
    }
}

#[test]
fn invalid_ml_kem_half_and_lengths() {
    let seed: [u8; 32] = random_bytes();
    let pk = xwing::public_key(&seed).expect("keygen");
    // A first coefficient of 0xFFF >= q = 3329 fails ML-KEM's modulus check.
    let mut bad = pk.clone();
    bad[0] = 0xff;
    bad[1] |= 0x0f;
    assert_eq!(xwing::validate_public_key(&bad).err().map(|_| ()), Some(()));
    assert!(PublicKey::decode(Algorithm::XWingKemDraft06, &bad).is_err());
    for len in [0, 32, 1183, 1215, 1217] {
        assert!(xwing::validate_public_key(&vec![1u8; len]).is_err());
    }
    let (ct, ss) = xwing::encapsulate(&pk).expect("encaps");
    for len in [0, 1119, 1121] {
        assert_eq!(
            xwing::decapsulate(&seed, &vec![0u8; len]).err(),
            Some(Code::NotOpen)
        );
    }
    // A flipped ML-KEM ciphertext byte: implicit rejection, a different secret, no error.
    let mut flipped = ct.clone();
    flipped[10] ^= 0x01;
    let other = xwing::decapsulate(&seed, &flipped).expect("implicit rejection returns a secret");
    assert_ne!(other, ss);
}

/// Library facts GHOST must guard against: `PublicKey::decode` indexes before checking the
/// length (a short key panics), and so does `encapsulate_derand` with a short seed.
#[test]
fn library_panics_on_short_inputs() {
    let short_key =
        catch_unwind(|| PublicKey::decode(Algorithm::XWingKemDraft06, &[0u8; 100]).is_ok());
    assert!(
        short_key.is_err(),
        "decode of a 100-byte X-Wing key did not panic"
    );
    let seed: [u8; 32] = random_bytes();
    let pk = PublicKey::decode(
        Algorithm::XWingKemDraft06,
        &xwing::public_key(&seed).expect("keygen"),
    )
    .expect("decode");
    let short_seed = catch_unwind(|| pk.encapsulate_derand(&[0u8; 10]).is_ok());
    assert!(
        short_seed.is_err(),
        "encapsulate_derand with a 10-byte seed did not panic"
    );
    // Length-checked decoders return errors.
    assert!(Ct::decode(Algorithm::XWingKemDraft06, &[0u8; 100]).is_err());
    assert!(PrivateKey::decode(Algorithm::XWingKemDraft06, &[0u8; 31]).is_err());
}

fn time<F: FnMut()>(label: &str, iterations: u32, mut f: F) -> f64 {
    // Batches of calls; the fastest batch is the least disturbed by other load on the host.
    let batches = 20;
    let per_batch = (iterations / batches).max(1);
    for _ in 0..per_batch {
        f();
    }
    let mut means: Vec<f64> = (0..batches)
        .map(|_| {
            let start = Instant::now();
            for _ in 0..per_batch {
                f();
            }
            start.elapsed().as_secs_f64() * 1e6 / f64::from(per_batch)
        })
        .collect();
    means.sort_by(f64::total_cmp);
    let (best, median) = (means[0], means[means.len() / 2]);
    println!("V6 timing {label}: best batch {best:.1} µs, median batch {median:.1} µs per call ({batches} × {per_batch} calls)");
    best
}

#[test]
fn host_timings() {
    let simd = if cfg!(debug_assertions) {
        "debug build (not a measurement)"
    } else {
        "release"
    };
    println!(
        "V6 build: {simd}; LIBCRUX_DISABLE_SIMD256={:?} LIBCRUX_DISABLE_SIMD128={:?} at compile time",
        option_env!("LIBCRUX_DISABLE_SIMD256"),
        option_env!("LIBCRUX_DISABLE_SIMD128")
    );
    let iterations = if cfg!(debug_assertions) { 20 } else { 2000 };
    let seed: [u8; 32] = random_bytes();
    let pk = xwing::public_key(&seed).expect("keygen");
    let (ct, _) = xwing::encapsulate(&pk).expect("encaps");
    time("keygen (seed -> public key)", iterations, || {
        let _ = xwing::public_key(&seed);
    });
    time(
        "encapsulate (whole-key validation included)",
        iterations,
        || {
            let _ = xwing::encapsulate(&pk);
        },
    );
    time("decapsulate (seed expansion included)", iterations, || {
        let _ = xwing::decapsulate(&seed, &ct);
    });
    // Components (libcrux-kem enum API), to separate ML-KEM-768, X25519 and the trial agreement.
    let mlkem_seed: [u8; 64] = random_bytes();
    let (mlkem_sk, mlkem_pk) =
        libcrux_kem::key_gen_derand(Algorithm::MlKem768, &mlkem_seed).expect("ml-kem keygen");
    let (_, mlkem_ct) = mlkem_pk
        .encapsulate(&mut rand::rng())
        .expect("ml-kem encaps");
    time("component ML-KEM-768 keygen", iterations, || {
        let _ = libcrux_kem::key_gen_derand(Algorithm::MlKem768, &mlkem_seed);
    });
    time("component ML-KEM-768 encapsulate", iterations, || {
        let _ = mlkem_pk.encapsulate(&mut rand::rng());
    });
    time("component ML-KEM-768 decapsulate", iterations, || {
        let _ = mlkem_ct.decapsulate(&mlkem_sk);
    });
    let x_seed: [u8; 32] = random_bytes();
    let (x_sk, x_pk) =
        libcrux_kem::key_gen_derand(Algorithm::X25519, &x_seed).expect("x25519 keygen");
    let (_, x_ct) = x_pk.encapsulate(&mut rand::rng()).expect("x25519 encaps");
    time(
        "component X25519 agreement (libcrux, HACL)",
        iterations,
        || {
            let _ = x_ct.decapsulate(&x_sk);
        },
    );
    let probe: [u8; 32] = random_bytes();
    time(
        "component contributory trial (x25519-dalek, fresh scalar)",
        iterations,
        || {
            let _ = ghost_dm_spike::olm::contributory(&probe);
        },
    );
}

/// The leaner call path for `ghost-client-dm` (S0-6, S0-9): `libcrux_kem::XWing` through the
/// `libcrux_traits::kem::slice::Kem` trait. It matches the vectors, returns typed length errors
/// instead of panicking, fails on a low-order X25519 half, and does **not** check the ML-KEM half
/// (no FIPS 203 input check), so `mlkem768::validate_public_key` must be called first.
#[test]
fn slice_trait_path() {
    use libcrux_kem::XWing;
    use libcrux_ml_kem::mlkem768::{validate_public_key, MlKem768PublicKey};
    use libcrux_traits::kem::slice::Kem;

    let vectors: Vec<Value> = serde_json::from_str(VECTORS).expect("json");
    for v in &vectors {
        let seed = hex_field(v, "seed");
        let mut ek = vec![0u8; 1216];
        let mut dk = vec![0u8; 2432];
        XWing::keygen(&mut ek, &mut dk, &seed).expect("keygen");
        assert_eq!(ek, hex_field(v, "pk"));
        let mut ct = vec![0u8; 1120];
        let mut ss = [0u8; 32];
        XWing::encaps(&mut ct, &mut ss, &ek, &hex_field(v, "eseed")).expect("encaps");
        assert_eq!(ct, hex_field(v, "ct"));
        assert_eq!(ss.to_vec(), hex_field(v, "ss"));
        let mut opened = [0u8; 32];
        XWing::decaps(&mut opened, &ct, &dk).expect("decaps");
        assert_eq!(opened, ss);
    }

    let seed: [u8; 32] = random_bytes();
    let mut ek = vec![0u8; 1216];
    let mut dk = vec![0u8; 2432];
    XWing::keygen(&mut ek, &mut dk, &seed).expect("keygen");
    let eseed: [u8; 64] = random_bytes();
    let mut ct = vec![0u8; 1120];
    let mut ss = [0u8; 32];
    // Wrong lengths are errors, not panics.
    assert!(XWing::encaps(&mut ct, &mut ss, &ek[..100], &eseed).is_err());
    assert!(XWing::encaps(&mut ct, &mut ss, &ek, &eseed[..10]).is_err());
    assert!(XWing::decaps(&mut ss, &ct[..10], &dk).is_err());
    // A low-order X25519 half fails encapsulation.
    for point in low_order_points() {
        let mut bad = ek.clone();
        bad[1184..].copy_from_slice(&point);
        assert!(XWing::encaps(&mut ct, &mut ss, &bad, &eseed).is_err());
    }
    // An invalid ML-KEM half is encapsulated to without complaint; only the explicit check refuses it.
    let mut bad = ek.clone();
    bad[0] = 0xff;
    bad[1] |= 0x0f;
    assert!(XWing::encaps(&mut ct, &mut ss, &bad, &eseed).is_ok());
    let half = MlKem768PublicKey::try_from(&bad[..1184]).expect("1184 bytes");
    assert!(!validate_public_key(&half));
    let good = MlKem768PublicKey::try_from(&ek[..1184]).expect("1184 bytes");
    assert!(validate_public_key(&good));
}
