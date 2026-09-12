//! The key well-formedness proof (Phase 8 design §3.2): a well-formed key passes; a key for which
//! x -> x^e is not a permutation (65537 | p - 1) fails with the best proof its owner can compute;
//! shape conditions (size, exponent, small factors) and the canonical encoding of every proof
//! element are enforced, each by a case that no other condition refuses.

mod common;

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

/// A prime of exactly `bits` bits (a multiple of 8; top two bits set), p = 2 * m * k + 1.
fn prime_with_factor(stream: &mut Stream, m: u32, bits: usize) -> BigUint {
    loop {
        let mut bytes = stream.next_bytes(bits / 8);
        bytes[0] |= 0xc0;
        let candidate = BigUint::from_bytes_be(&bytes);
        let step = BigUint::from(2 * u64::from(m));
        let p = &candidate - (&candidate % &step) + BigUint::from(1u32);
        if p.bits() == bits && is_probable_prime(&p) {
            return p;
        }
    }
}

/// A prime of `bits` bits with 65537 not dividing p - 1 (so e is invertible modulo p - 1).
fn prime_coprime_to_e(stream: &mut Stream, bits: usize) -> BigUint {
    let e = BigUint::from(E);
    loop {
        let p = prime_with_factor(stream, 1, bits);
        if (&(&p - BigUint::from(1u32)) % &e).bits() != 0 {
            return p;
        }
    }
}

fn blocks(bytes: &[u8]) -> [[u8; PROOF_BLOCK_LEN]; PROOF_ROUNDS] {
    assert_eq!(bytes.len(), PROOF_BLOCK_LEN * PROOF_ROUNDS);
    std::array::from_fn(|i| {
        bytes[i * PROOF_BLOCK_LEN..(i + 1) * PROOF_BLOCK_LEN]
            .try_into()
            .unwrap()
    })
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
}

/// σ_i + n is an e-th root of ρ_i modulo n as well, but not the canonical σ_i < n: accepting it
/// would give one key two proof encodings (ES rule 1, canonical bytes). Uses the committed
/// `[ghost] perm-proof` vector, so the indices where σ_i + n fits 256 bytes are fixed.
#[test]
fn a_non_canonical_proof_element_is_refused() {
    let v = common::section("ghost")
        .into_iter()
        .find(|v| v.id == "perm-proof")
        .unwrap();
    let pk = PublicKey::from_spki(&v.hex("spki")).unwrap();
    let proof = blocks(&v.hex("proof"));
    verify_permutation_proof(&pk, &proof).unwrap();
    let challenges = permutation_proof_challenges(&pk).unwrap();
    let mut refused = 0;
    for i in 0..PROOF_ROUNDS {
        let lifted = BigUint::from_bytes_be(&proof[i]) + pk.n();
        let Ok(bytes) = i2osp(&lifted, PROOF_BLOCK_LEN) else {
            continue; // σ_i + n >= 2^2048 has no 256-byte encoding
        };
        // Still a valid root: only the range check σ_i < n can refuse it.
        assert_eq!(
            lifted.modpow(pk.e(), pk.n()),
            BigUint::from_bytes_be(&challenges[i])
        );
        let mut bad = proof;
        bad[i].copy_from_slice(&bytes);
        assert_eq!(
            verify_permutation_proof(&pk, &bad),
            Err(Error::Proof),
            "sigma_{i} + n"
        );
        refused += 1;
    }
    assert!(refused >= 1, "no sigma_i + n fits 256 bytes");
}

#[test]
fn a_non_permutation_key_fails_with_the_best_proof_its_owner_can_compute() {
    let mut stream = Stream(0x6768_6f73_7400);
    let e = BigUint::from(E);
    let one = BigUint::from(1u32);
    // p - 1 divisible by 65537 (exactly once, so e has an inverse modulo (p - 1) / e); q normal.
    let p = loop {
        let p = prime_with_factor(&mut stream, E, 1024);
        let reduced = (&p - &one) / &e;
        if (&reduced % &e).bits() != 0 {
            break p;
        }
    };
    let q = prime_coprime_to_e(&mut stream, 1024);
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
    let p2 = prime_coprime_to_e(&mut stream, 1024);
    let n2 = &p2 * &q;
    let pk2 = PublicKey::from_components(&n2.to_bytes_be(), &e.to_bytes_be()).unwrap();
    let d2 = mod_inv(&e, &((&p2 - &one) * (&q - &one))).unwrap();
    verify_permutation_proof(&pk2, &proof_with_exponent(&pk2, &d2)).unwrap();
}

/// Keys n = f * p * q (2048 bits, f in {65521, 65537}) for which x -> x^e does permute Z_n^*
/// (65537 divides none of f - 1, p - 1, q - 1), so the owner publishes a mathematically valid
/// proof: every ρ_i is a unit, every σ_i < n and σ_i^e == ρ_i. The key is refused anyway, by the
/// trial division "no prime factor <= 65 537" alone (design §3.1 rule 2, §3.2). The f = 65537 key
/// is committed as `[perm-proof-negative] small-factor-65537` for the ES case `key-small-factor`.
#[test]
fn a_small_factor_is_refused_by_trial_division_alone() {
    let mut stream = Stream(0x6768_6f73_7401);
    let e = BigUint::from(E);
    let one = BigUint::from(1u32);
    let limit = BigUint::from(1u32) << 2048usize;
    // p, q of 1016 bits each: 65521 * p * q >= 2^2047 always; 65537 * p * q < 2^2048 is checked.
    let (p, q) = loop {
        let p = prime_coprime_to_e(&mut stream, 1016);
        let q = prime_coprime_to_e(&mut stream, 1016);
        if p != q && &e * &p * &q < limit {
            break (p, q);
        }
    };
    for f in [65_521u32, E] {
        let f_big = BigUint::from(f);
        let n = &f_big * &p * &q;
        assert_eq!(n.bits(), 2048, "f = {f}");
        let pk = PublicKey::from_components(&n.to_bytes_be(), &e.to_bytes_be()).unwrap();
        let order = (&f_big - &one) * (&p - &one) * (&q - &one);
        let d = mod_inv(&e, &order).unwrap();
        let proof = proof_with_exponent(&pk, &d);
        let challenges = permutation_proof_challenges(&pk).unwrap();
        for (rho, sigma) in challenges.iter().zip(&proof) {
            let rho = BigUint::from_bytes_be(rho);
            let sigma = BigUint::from_bytes_be(sigma);
            assert!(mod_inv(&rho, &n).is_some(), "f = {f}: rho is a unit");
            assert!(sigma < n);
            assert_eq!(sigma.modpow(&e, &n), rho, "f = {f}: sigma^e == rho");
        }
        assert_eq!(
            verify_permutation_proof(&pk, &proof),
            Err(Error::Proof),
            "f = {f}"
        );
        if f == E {
            let expected = format!(
                "vector small-factor-65537 n = 65537 * p * q with a valid permutation proof\n\
                 f = {}\np = {}\nq = {}\nn = {}\nproof = {}\n",
                hex::encode(f_big.to_bytes_be()),
                hex::encode(p.to_bytes_be()),
                hex::encode(q.to_bytes_be()),
                hex::encode(n.to_bytes_be()),
                hex::encode(proof.concat())
            );
            let committed = common::section("perm-proof-negative")
                .into_iter()
                .find(|v| v.id == "small-factor-65537")
                .unwrap_or_else(|| panic!("blind_rsa_pp2.txt lacks:\n{expected}"));
            for (field, value) in [
                ("f", f_big.to_bytes_be()),
                ("p", p.to_bytes_be()),
                ("q", q.to_bytes_be()),
                ("n", n.to_bytes_be()),
                ("proof", proof.concat()),
            ] {
                assert_eq!(
                    committed.hex(field),
                    value,
                    "{field}; expected:\n{expected}"
                );
            }
        }
    }
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
}
