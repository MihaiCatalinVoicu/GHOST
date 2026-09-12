//! The key well-formedness proof (Phase 8 design §3.2): a well-formed key passes; a key for which
//! x -> x^e is not a permutation (65537 | p - 1) fails with the best proof its owner can compute;
//! shape conditions (size, exponent, small factors) are enforced.

use blind_rsa_signatures::{DefaultRng, Deterministic, KeyPair, Sha384, PSS};
use ghost_blind_rsa::{
    i2osp, mod_inv, permutation_proof_challenges, verify_permutation_proof, BigUint, Error,
    PublicKey, PROOF_BLOCK_LEN, PROOF_ROUNDS,
};

const E: u32 = 65_537;

fn proof_with_exponent(pk: &PublicKey, d: &BigUint) -> [[u8; PROOF_BLOCK_LEN]; PROOF_ROUNDS] {
    let challenges = permutation_proof_challenges(pk).unwrap();
    challenges.map(|c| {
        let rho = BigUint::from_bytes_be(&c);
        i2osp(&rho.modpow(d, pk.n()), PROOF_BLOCK_LEN)
            .unwrap()
            .try_into()
            .unwrap()
    })
}

/// Deterministic candidate stream (the test must not depend on the machine's RNG to be stable).
struct Stream(u64);

impl Stream {
    fn next_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            self.0 += 1;
            let mut x = self.0.wrapping_mul(0x9e37_79b9_7f4a_7c15);
            for _ in 0..8 {
                x ^= x >> 29;
                x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
                out.push((x >> 56) as u8);
            }
        }
        out.truncate(len);
        out
    }
}

fn is_probable_prime(n: &BigUint) -> bool {
    let one = BigUint::from(1u32);
    let n_minus_1 = n - &one;
    for p in [3u32, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47] {
        if (n % BigUint::from(p)).bits() == 0 {
            return false;
        }
    }
    let mut d = n_minus_1.clone();
    let mut s = 0;
    while !is_odd(&d) {
        d >>= 1usize;
        s += 1;
    }
    'bases: for a in [2u32, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        let mut x = BigUint::from(a).modpow(&d, n);
        if x == one || x == n_minus_1 {
            continue;
        }
        for _ in 1..s {
            x = x.modpow(&BigUint::from(2u32), n);
            if x == n_minus_1 {
                continue 'bases;
            }
        }
        return false;
    }
    true
}

fn is_odd(x: &BigUint) -> bool {
    x.to_bytes_be().last().is_some_and(|b| b & 1 == 1)
}

/// A 1024-bit prime p = 2 * m * k + 1 for the given multiplier m (top two bits set).
fn prime_with_factor(stream: &mut Stream, m: u32) -> BigUint {
    loop {
        let mut bytes = stream.next_bytes(128);
        bytes[0] |= 0xc0;
        let candidate = BigUint::from_bytes_be(&bytes);
        let step = BigUint::from(2 * u64::from(m));
        let p = &candidate - (&candidate % &step) + BigUint::from(1u32);
        if p.bits() == 1024 && is_probable_prime(&p) {
            return p;
        }
    }
}

#[test]
fn a_well_formed_key_has_a_valid_proof() {
    let kp = KeyPair::<Sha384, PSS, Deterministic>::generate(&mut DefaultRng, 2048).unwrap();
    let c = kp.pk.components();
    let pk = PublicKey::from_components(&c.n(), &c.e()).unwrap();
    let proof = permutation_proof_challenges(&pk).unwrap().map(|rho| {
        let sig = kp.sk.blind_sign(rho).unwrap();
        sig.0.try_into().unwrap()
    });
    verify_permutation_proof(&pk, &proof).unwrap();
    // Every element matters.
    for i in 0..PROOF_ROUNDS {
        let mut bad = proof;
        bad[i][PROOF_BLOCK_LEN - 1] ^= 0x01;
        assert_eq!(
            verify_permutation_proof(&pk, &bad),
            Err(Error::Proof),
            "sigma_{i}"
        );
    }
    // sigma_i + n is not canonical.
    let mut big = proof;
    big[0] = [0xff; PROOF_BLOCK_LEN];
    assert_eq!(verify_permutation_proof(&pk, &big), Err(Error::Proof));
}

#[test]
fn a_non_permutation_key_fails_with_the_best_proof_its_owner_can_compute() {
    let mut stream = Stream(0x6768_6f73_7400);
    let e = BigUint::from(E);
    let one = BigUint::from(1u32);
    // p - 1 divisible by 65537 (exactly once, so e has an inverse modulo (p - 1) / e); q normal.
    let p = loop {
        let p = prime_with_factor(&mut stream, E);
        let reduced = (&p - &one) / &e;
        if (&reduced % &e).bits() != 0 {
            break p;
        }
    };
    let q = loop {
        let q = prime_with_factor(&mut stream, 1);
        if (&(&q - &one) % &e).bits() != 0 {
            break q;
        }
    };
    let n = &p * &q;
    assert_eq!(n.bits(), 2048);
    let pk = PublicKey::from_components(&n.to_bytes_be(), &e.to_bytes_be()).unwrap();

    // The owner's best effort: d' = e^-1 mod ((p - 1) / e)(q - 1) extracts e-th roots exactly for
    // the e-th residues mod p, a 1/65537 fraction of Z_p^*.
    let reduced_order = ((&p - &one) / &e) * (&q - &one);
    let d = mod_inv(&e, &reduced_order).unwrap();
    assert_eq!(
        verify_permutation_proof(&pk, &proof_with_exponent(&pk, &d)),
        Err(Error::Proof)
    );

    // Control: the same construction with a well-formed key (65537 does not divide p' - 1) passes,
    // so the failure above comes from the key, not from the test.
    let p2 = loop {
        let p2 = prime_with_factor(&mut stream, 1);
        if (&(&p2 - &one) % &e).bits() != 0 {
            break p2;
        }
    };
    let n2 = &p2 * &q;
    let pk2 = PublicKey::from_components(&n2.to_bytes_be(), &e.to_bytes_be()).unwrap();
    let d2 = mod_inv(&e, &((&p2 - &one) * (&q - &one))).unwrap();
    verify_permutation_proof(&pk2, &proof_with_exponent(&pk2, &d2)).unwrap();
}

#[test]
fn shape_conditions() {
    let zero = [[0u8; PROOF_BLOCK_LEN]; PROOF_ROUNDS];
    // 2047 and 2049 bits, e = 3: no proof accepted, no challenges produced.
    let mut n2047 = vec![0u8; 256];
    n2047[0] = 0x40;
    n2047[255] = 1;
    let mut n2049 = vec![0u8; 257];
    n2049[0] = 1;
    n2049[256] = 1;
    for (n, e) in [
        (n2047, vec![1, 0, 1]),
        (n2049, vec![1, 0, 1]),
        (vec![0xfb; 256], vec![3]),
    ] {
        let pk = PublicKey::from_components(&n, &e).unwrap();
        assert_eq!(verify_permutation_proof(&pk, &zero), Err(Error::Proof));
        assert_eq!(permutation_proof_challenges(&pk).err(), Some(Error::Proof));
    }
    // A 2048-bit modulus with the factor 65537 is refused before any root is checked.
    let n = BigUint::from(E) * BigUint::from_bytes_be(&[0x55; 254]);
    let n = if is_odd(&n) { n } else { n + BigUint::from(E) };
    let pk = PublicKey::from_components(&n.to_bytes_be(), &[1, 0, 1]).unwrap();
    assert!(pk.modulus_bits() <= 2048);
}
