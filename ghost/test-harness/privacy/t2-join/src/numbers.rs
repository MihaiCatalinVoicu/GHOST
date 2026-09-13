//! Small numeric tools of the analyzer: a deterministic generator (SplitMix64), a Bloom filter
//! over 8-byte windows, the Jacobi symbol of 2048-bit values (binary algorithm on 64-bit limbs,
//! no division in the loop) and `s^e mod n` (J5 a).

use ghost_blind_rsa::BigUint;
use num_bigint_dig::ModInverse;

/// SplitMix64 (Steele, Lea, Flood 2014): a small, fast, deterministic generator. Used for the
/// permutation tests and the sampling of false pairs; every stream is seeded from a pinned seed.
#[derive(Debug, Clone)]
pub struct SplitMix(u64);

impl SplitMix {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in [0, n) (n > 0), by rejection.
    pub fn below(&mut self, n: u64) -> u64 {
        let zone = u64::MAX - u64::MAX % n;
        loop {
            let x = self.next_u64();
            if x < zone {
                return x % n;
            }
        }
    }

    /// Fisher–Yates.
    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = self.below(i as u64 + 1) as usize;
            items.swap(i, j);
        }
    }
}

fn mix(mut z: u64) -> u64 {
    z = (z ^ (z >> 33)).wrapping_mul(0xFF51_AFD7_ED55_8CCD);
    z = (z ^ (z >> 33)).wrapping_mul(0xC4CE_B9FE_1A85_EC53);
    z ^ (z >> 33)
}

/// A Bloom filter of 8-byte windows (as little-endian `u64`), 7 probes by double hashing.
pub struct Bloom {
    bits: Vec<u64>,
    mask: u64,
}

const PROBES: u64 = 7;

impl Bloom {
    /// About `bits_per_item` bits per expected item, rounded up to a power of two.
    pub fn with_capacity(items: usize, bits_per_item: usize) -> Self {
        let want = (items.max(1) * bits_per_item)
            .next_power_of_two()
            .max(1 << 16);
        Self {
            bits: vec![0; want / 64],
            mask: want as u64 - 1,
        }
    }

    pub fn insert(&mut self, w: u64) {
        let (h1, h2) = (mix(w), mix(w ^ 0x5555_5555_5555_5555) | 1);
        for i in 0..PROBES {
            let b = h1.wrapping_add(i.wrapping_mul(h2)) & self.mask;
            self.bits[(b >> 6) as usize] |= 1 << (b & 63);
        }
    }

    pub fn contains(&self, w: u64) -> bool {
        let (h1, h2) = (mix(w), mix(w ^ 0x5555_5555_5555_5555) | 1);
        (0..PROBES).all(|i| {
            let b = h1.wrapping_add(i.wrapping_mul(h2)) & self.mask;
            self.bits[(b >> 6) as usize] & (1 << (b & 63)) != 0
        })
    }
}

/// The 8-byte window of `v` at `i` as a little-endian `u64`.
pub fn window(v: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(v[i..i + 8].try_into().expect("8 bytes"))
}

/// A window is structural (not a join value) when it has four or more zero bytes or all its bytes
/// are equal: the big-endian encodings of small integers and padding. A random 8-byte value is
/// structural with probability below 2^-24.
pub fn structural_window(w: u64) -> bool {
    let b = w.to_le_bytes();
    b.iter().filter(|&&x| x == 0).count() >= 4 || b.iter().all(|&x| x == b[0])
}

/// A value is informative (a candidate join value) when it has at least four non-zero bytes and
/// not all bytes equal.
pub fn informative(v: &[u8]) -> bool {
    v.len() >= 4 && v.iter().filter(|&&x| x != 0).count() >= 4 && !v.iter().all(|&x| x == v[0])
}

// -------------------------------------------------------------------------------------------------
// Limb arithmetic for the Jacobi symbol.
// -------------------------------------------------------------------------------------------------

fn limbs(x: &BigUint) -> Vec<u64> {
    let bytes = x.to_bytes_le();
    let mut out: Vec<u64> = bytes
        .chunks(8)
        .map(|c| {
            let mut b = [0u8; 8];
            b[..c.len()].copy_from_slice(c);
            u64::from_le_bytes(b)
        })
        .collect();
    trim(&mut out);
    out
}

fn trim(x: &mut Vec<u64>) {
    while x.last() == Some(&0) {
        x.pop();
    }
}

fn less(a: &[u64], b: &[u64]) -> bool {
    if a.len() != b.len() {
        return a.len() < b.len();
    }
    for i in (0..a.len()).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

/// a -= b, a >= b.
fn sub_assign(a: &mut Vec<u64>, b: &[u64]) {
    let mut borrow = 0u64;
    for (i, ai) in a.iter_mut().enumerate() {
        let bi = b.get(i).copied().unwrap_or(0);
        let (d1, o1) = ai.overflowing_sub(bi);
        let (d2, o2) = d1.overflowing_sub(borrow);
        *ai = d2;
        borrow = u64::from(o1 || o2);
    }
    trim(a);
}

fn shr_assign(a: &mut Vec<u64>, s: u32) {
    let words = (s / 64) as usize;
    let bits = s % 64;
    if words > 0 {
        a.drain(..words.min(a.len()));
    }
    if bits > 0 {
        for i in 0..a.len() {
            let hi = a.get(i + 1).copied().unwrap_or(0);
            a[i] = (a[i] >> bits) | (hi << (64 - bits));
        }
    }
    trim(a);
}

fn trailing_zeros(a: &[u64]) -> u32 {
    let mut n = 0;
    for &w in a {
        if w == 0 {
            n += 64;
        } else {
            return n + w.trailing_zeros();
        }
    }
    n
}

/// The Jacobi symbol (a / n) for odd n > 0: 1, -1, or 0 when gcd(a, n) > 1.
pub fn jacobi(a: &BigUint, n: &BigUint) -> i8 {
    let mut a = limbs(&(a % n));
    let mut n = limbs(n);
    assert!(n.first().is_some_and(|w| w & 1 == 1), "n must be odd");
    let mut t = 1i8;
    loop {
        if a.is_empty() {
            return if n.len() == 1 && n[0] == 1 { t } else { 0 };
        }
        let v = trailing_zeros(&a);
        shr_assign(&mut a, v);
        if v & 1 == 1 {
            let r = n[0] & 7;
            if r == 3 || r == 5 {
                t = -t;
            }
        }
        if less(&a, &n) {
            std::mem::swap(&mut a, &mut n);
            if a[0] & 3 == 3 && n[0] & 3 == 3 {
                t = -t;
            }
        }
        sub_assign(&mut a, &n);
    }
}

/// `s^e mod n` as 256 bytes (the encoded message a relay-seen authenticator opens to).
pub fn open_signature(s: &[u8], n: &BigUint, e: &BigUint, len: usize) -> Vec<u8> {
    let m = BigUint::from_bytes_be(s).modpow(e, n);
    ghost_blind_rsa::i2osp(&m, len).unwrap_or_default()
}

/// `a^-1 mod n` (used by the tests of the Jacobi symbol).
pub fn inverse(a: &BigUint, n: &BigUint) -> Option<BigUint> {
    a.clone().mod_inverse(n).and_then(|x| x.to_biguint())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slow_jacobi(mut a: u64, mut n: u64) -> i8 {
        // The textbook algorithm on machine words.
        a %= n;
        let mut t = 1i8;
        while a != 0 {
            while a.is_multiple_of(2) {
                a /= 2;
                if n % 8 == 3 || n % 8 == 5 {
                    t = -t;
                }
            }
            std::mem::swap(&mut a, &mut n);
            if a % 4 == 3 && n % 4 == 3 {
                t = -t;
            }
            a %= n;
        }
        if n == 1 {
            t
        } else {
            0
        }
    }

    #[test]
    fn jacobi_matches_the_textbook_algorithm() {
        let mut r = SplitMix::new(1);
        for _ in 0..20_000 {
            let n = r.next_u64() >> 1 | 1;
            let a = r.next_u64();
            assert_eq!(
                jacobi(&BigUint::from(a), &BigUint::from(n)),
                slow_jacobi(a, n),
                "({a} / {n})"
            );
        }
        // Multi-limb: (a^2 / n) = 1 when gcd = 1, and (a b / n) = (a / n)(b / n).
        let n = BigUint::from_bytes_be(&[0xC3; 256]) | BigUint::from(1u32);
        for i in 1..50u64 {
            let a = BigUint::from_bytes_be(&[i as u8; 200]) + BigUint::from(i * 7919);
            let b = BigUint::from_bytes_be(&[(i * 3) as u8 | 1; 255]);
            let ja = jacobi(&a, &n);
            let jb = jacobi(&b, &n);
            assert_eq!(jacobi(&(&a * &b), &n), ja * jb);
            if ja != 0 {
                assert_eq!(jacobi(&(&a * &a), &n), 1);
            }
        }
    }

    #[test]
    fn the_bloom_filter_has_no_false_negatives() {
        let mut b = Bloom::with_capacity(10_000, 12);
        let mut r = SplitMix::new(2);
        let items: Vec<u64> = (0..10_000).map(|_| r.next_u64()).collect();
        for &w in &items {
            b.insert(w);
        }
        assert!(items.iter().all(|&w| b.contains(w)));
        let fp = (0..100_000).filter(|_| b.contains(r.next_u64())).count();
        assert!(fp < 2_000, "false positives {fp}");
    }
}
