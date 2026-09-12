//! The key ceremony's prime checks (runbook K1, design §3.3): two primes, p * q = n, p != q,
//! |p - q| > 2^1000, gcd(e, p - 1) = gcd(e, q - 1) = 1.

mod common;

use ghost_blind_rsa::BigUint;
use ghost_entitlement::Kind;
use ghost_issuer::signer::{check_prime_conditions, PrimeCheck, ReferenceSigner};

fn pow2(k: usize) -> BigUint {
    BigUint::from(1u32) << k
}

fn e() -> BigUint {
    BigUint::from(65_537u32)
}

fn check(primes: &[BigUint]) -> Result<(), PrimeCheck> {
    let n = primes.iter().fold(BigUint::from(1u32), |acc, p| acc * p);
    check_prime_conditions(&n, &e(), primes)
}

#[test]
fn crafted_factors_hit_each_condition() {
    // p - 1 = 2^1023 and q - 1 = 2^1024 are coprime to 65 537; |p - q| is about 2^1023.
    let p = pow2(1023) + BigUint::from(1u32);
    let q = pow2(1024) + BigUint::from(1u32);
    assert_eq!(check(&[p.clone(), q.clone()]), Ok(()));
    assert_eq!(check(&[q.clone(), p.clone()]), Ok(()));

    assert_eq!(check(std::slice::from_ref(&p)), Err(PrimeCheck::PrimeCount));
    assert_eq!(
        check(&[p.clone(), q.clone(), BigUint::from(3u32)]),
        Err(PrimeCheck::PrimeCount)
    );
    assert_eq!(
        check(&[BigUint::from(1u32), &p * &q]),
        Err(PrimeCheck::PrimeCount)
    );
    let n = &p * &q;
    assert_eq!(
        check_prime_conditions(&(n + BigUint::from(2u32)), &e(), &[p.clone(), q.clone()]),
        Err(PrimeCheck::Product)
    );
    assert_eq!(check(&[p.clone(), p.clone()]), Err(PrimeCheck::Equal));
    assert_eq!(
        check(&[p.clone(), &p + BigUint::from(2u32)]),
        Err(PrimeCheck::TooClose)
    );
    // Exactly 2^1000 apart is still refused (the bound is strict).
    assert_eq!(
        check(&[p.clone(), &p + pow2(1000)]),
        Err(PrimeCheck::TooClose)
    );
    assert_ne!(
        check(&[p.clone(), &p + pow2(1000) + BigUint::from(2u32)]),
        Err(PrimeCheck::TooClose)
    );
    // 65 537 | p - 1: x -> x^e is not a permutation.
    let bad = BigUint::from(65_537u32) * pow2(1000) + BigUint::from(1u32);
    assert_eq!(
        check(&[bad.clone(), q.clone()]),
        Err(PrimeCheck::ExponentNotCoprime)
    );
    assert_eq!(check(&[q, bad]), Err(PrimeCheck::ExponentNotCoprime));
}

#[test]
fn every_committed_test_key_passes() {
    let text = std::fs::read_to_string(common::fixture::dir().join("test_keys.txt")).unwrap();
    let mut count = 0;
    for line in text
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let f: Vec<&str> = line.split(' ').collect();
        let kind = Kind::from_byte(f[0].parse().unwrap()).unwrap();
        let signer = ReferenceSigner::from_pkcs8_der(
            kind,
            f[1].parse().unwrap(),
            &hex::decode(f[2]).unwrap(),
        )
        .unwrap();
        assert_eq!(signer.check_prime_conditions(), Ok(()), "{line:.12}");
        count += 1;
    }
    assert_eq!(count, 36);
}
