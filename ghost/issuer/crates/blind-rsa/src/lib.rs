//! Public-side RSA blind signatures: RFC 9474 RSABSSA-SHA384-PSS (the variant Privacy Pass type
//! 0x0002 uses, RFC 9578 §6), plus the verifier of the GHOST key well-formedness proof (Phase 8
//! design §2.5, §2.7, §3.2).
//!
//! Only public-key work lives here; there is no private-key operation in this crate (the issuer
//! signs through `ghost-issuer`'s `Signer`). The arithmetic is generic in the modulus length, so
//! the 4096-bit RFC 9474 Appendix A vectors replay through the same functions as production; the
//! 2048-bit rule of type 0x0002 lives in the Entitlement Schedule and token parsers
//! (`ghost-entitlement`). EMSA-PSS runs on `sha2`, blinding and unblinding on `num-bigint-dig`,
//! and every signature verification on `ring` (`RSA_PSS_2048_8192_SHA384`), all already linked into
//! the Android library.
//!
//! Blinding is not constant-time: `r` is secret only against a local observer (residue R13).
#![forbid(unsafe_code)]

use std::fmt;
use std::sync::OnceLock;

pub use num_bigint_dig::BigUint;
use num_bigint_dig::{BigInt, ModInverse};
use ring::signature::{RsaPublicKeyComponents, RSA_PSS_2048_8192_SHA384};
use sha2::{Digest, Sha384, Sha512};

/// SHA-384 output length, which is also the PSS salt length (sLen = hLen = 48, RFC 9578 §6).
pub const HASH_LEN: usize = 48;
/// PSS salt length.
pub const SALT_LEN: usize = 48;
/// Number of e-th roots in a permutation proof (soundness <= 65537^-8 < 2^-128, design §3.2).
pub const PROOF_ROUNDS: usize = 8;
/// The only public exponent the permutation proof (and the Entitlement Schedule) accepts.
pub const PROOF_EXPONENT: u32 = 65_537;
/// The only modulus size the permutation proof accepts (type 0x0002, Nk = 256).
pub const PROOF_MODULUS_BITS: usize = 2048;
/// Byte length of one proof element (and of a type-0x0002 signature).
pub const PROOF_BLOCK_LEN: usize = PROOF_MODULUS_BITS / 8;

const PROOF_DOMAIN: &[u8] = b"ghost/v1/perm-proof";
/// Hash blocks per proof challenge: 5 x SHA-512 = 320 bytes, reduced mod n (bias <= 2^-512).
const PROOF_HASH_BLOCKS: u8 = 5;
/// Largest SPKI accepted (an 8192-bit key encodes in about 1 060 bytes).
const MAX_SPKI_LEN: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Key components are malformed: n even or below 3, e outside [3, n), or e even.
    InvalidKey,
    /// The SPKI is not the canonical DER of an id-RSASSA-PSS key with SHA-384, MGF1-SHA-384 and
    /// saltLength 48 (RFC 9578 §6.5).
    InvalidSpki,
    /// An input has the wrong length for this key or operation.
    BadLength,
    /// A value is outside its admissible range (0 < x < n and, where required, gcd(x, n) = 1).
    OutOfRange,
    /// `em_bits` is too small for EMSA-PSS with SHA-384 and a 48-byte salt.
    Encoding,
    /// The RSASSA-PSS signature does not verify (`ring`).
    Verification,
    /// The key fails the well-formedness conditions or its permutation proof.
    Proof,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::InvalidKey => "malformed RSA public key",
            Error::InvalidSpki => "not a canonical RSASSA-PSS SHA-384 SPKI",
            Error::BadLength => "input has the wrong length",
            Error::OutOfRange => "value outside the admissible range",
            Error::Encoding => "EMSA-PSS encoding error",
            Error::Verification => "signature verification failed",
            Error::Proof => "key well-formedness proof failed",
        })
    }
}

impl std::error::Error for Error {}

/// An RSA public key (n, e). Any modulus length; callers enforce their own size rules.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey {
    n: BigUint,
    e: BigUint,
    /// Big-endian n without leading zeros (the form `ring` requires).
    n_be: Vec<u8>,
    /// Big-endian e without leading zeros.
    e_be: Vec<u8>,
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PublicKey({} bits, e = 0x{})",
            self.n.bits(),
            to_hex(&self.e_be)
        )
    }
}

impl PublicKey {
    /// Builds a key from big-endian n and e (leading zeros are ignored).
    pub fn from_components(n: &[u8], e: &[u8]) -> Result<Self, Error> {
        let n = BigUint::from_bytes_be(n);
        let e = BigUint::from_bytes_be(e);
        if n.bits() < 2 || !is_odd(&n) || e.bits() < 2 || !is_odd(&e) || e >= n {
            return Err(Error::InvalidKey);
        }
        let n_be = n.to_bytes_be();
        let e_be = e.to_bytes_be();
        Ok(Self { n, e, n_be, e_be })
    }

    /// Parses the SubjectPublicKeyInfo of an RSASSA-PSS key with SHA-384, MGF1-SHA-384 and a
    /// 48-byte salt, the encoding RFC 9578 §6.5 prescribes for `token_key_id`. Only the canonical
    /// DER is accepted: re-encoding (n, e) must give back exactly the input bytes.
    pub fn from_spki(der: &[u8]) -> Result<Self, Error> {
        if der.len() > MAX_SPKI_LEN {
            return Err(Error::InvalidSpki);
        }
        let (outer, rest) = der_read(der, 0x30)?;
        if !rest.is_empty() {
            return Err(Error::InvalidSpki);
        }
        let alg = outer
            .get(..PSS_SHA384_ALGORITHM.len())
            .ok_or(Error::InvalidSpki)?;
        if alg != PSS_SHA384_ALGORITHM {
            return Err(Error::InvalidSpki);
        }
        let (bits, rest) = der_read(&outer[PSS_SHA384_ALGORITHM.len()..], 0x03)?;
        if !rest.is_empty() {
            return Err(Error::InvalidSpki);
        }
        let (&unused, rsa_key) = bits.split_first().ok_or(Error::InvalidSpki)?;
        if unused != 0 {
            return Err(Error::InvalidSpki);
        }
        let (seq, rest) = der_read(rsa_key, 0x30)?;
        if !rest.is_empty() {
            return Err(Error::InvalidSpki);
        }
        let (n, rest) = der_read(seq, 0x02)?;
        let (e, rest) = der_read(rest, 0x02)?;
        if !rest.is_empty() {
            return Err(Error::InvalidSpki);
        }
        let key = Self::from_components(n, e).map_err(|_| Error::InvalidSpki)?;
        if key.to_spki() != der {
            return Err(Error::InvalidSpki);
        }
        Ok(key)
    }

    /// The canonical SPKI DER (RFC 9578 §6.5): `token_key_id` is SHA-256 of these bytes.
    pub fn to_spki(&self) -> Vec<u8> {
        let rsa_key = der_tlv(
            0x30,
            &[der_integer(&self.n_be), der_integer(&self.e_be)].concat(),
        );
        let mut bit_string = Vec::with_capacity(rsa_key.len() + 1);
        bit_string.push(0);
        bit_string.extend_from_slice(&rsa_key);
        let body = [PSS_SHA384_ALGORITHM, &der_tlv(0x03, &bit_string)].concat();
        der_tlv(0x30, &body)
    }

    /// Modulus length in bits.
    pub fn modulus_bits(&self) -> usize {
        self.n.bits()
    }

    /// Modulus length in bytes (the length of blinded messages and signatures).
    pub fn modulus_len(&self) -> usize {
        self.n.bits().div_ceil(8)
    }

    pub fn n(&self) -> &BigUint {
        &self.n
    }

    pub fn e(&self) -> &BigUint {
        &self.e
    }

    /// Big-endian n without leading zeros.
    pub fn n_bytes(&self) -> &[u8] {
        &self.n_be
    }

    /// Big-endian e without leading zeros.
    pub fn e_bytes(&self) -> &[u8] {
        &self.e_be
    }
}

/// AlgorithmIdentifier of id-RSASSA-PSS with explicit SHA-384 / MGF1-SHA-384 / saltLength 48
/// parameters (RFC 4055 §3.1, as RFC 9578 §6.5 encodes it; the hash AlgorithmIdentifiers carry no
/// NULL parameters), DER.
const PSS_SHA384_ALGORITHM: &[u8] = &[
    0x30, 0x3d, // SEQUENCE (61)
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, // id-RSASSA-PSS
    0x30, 0x30, // RSASSA-PSS-params (48)
    0xa0, 0x0d, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
    0x02, // [0] hashAlgorithm: id-sha384
    0xa1, 0x1a, 0x30, 0x18, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30,
    0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
    0x02, // [1] maskGenAlgorithm: id-mgf1 with id-sha384
    0xa2, 0x03, 0x02, 0x01, 0x30, // [2] saltLength: 48
];

/// EMSA-PSS-ENCODE (RFC 8017 §9.1.1) with SHA-384, MGF1-SHA-384 and a 48-byte salt.
/// `em_bits` is modBits - 1 for RSASSA-PSS; the result is ceil(em_bits / 8) bytes.
pub fn emsa_pss_encode_sha384(
    msg: &[u8],
    salt: &[u8; SALT_LEN],
    em_bits: usize,
) -> Result<Vec<u8>, Error> {
    let em_len = em_bits.div_ceil(8);
    if em_len < HASH_LEN + SALT_LEN + 2 {
        return Err(Error::Encoding);
    }
    let m_hash = Sha384::digest(msg);
    let mut prime = Sha384::new();
    prime.update([0u8; 8]);
    prime.update(m_hash);
    prime.update(salt);
    let h = prime.finalize();

    let db_len = em_len - HASH_LEN - 1;
    let mut em = vec![0u8; em_len];
    em[db_len - SALT_LEN - 1] = 0x01;
    em[db_len - SALT_LEN..db_len].copy_from_slice(salt);
    mgf1_sha384_xor(&h, &mut em[..db_len]);
    em[0] &= 0xff >> (8 * em_len - em_bits);
    em[db_len..em_len - 1].copy_from_slice(&h);
    em[em_len - 1] = 0xbc;
    Ok(em)
}

fn mgf1_sha384_xor(seed: &[u8], out: &mut [u8]) {
    for (counter, chunk) in out.chunks_mut(HASH_LEN).enumerate() {
        let mut h = Sha384::new();
        h.update(seed);
        h.update((counter as u32).to_be_bytes());
        for (o, m) in chunk.iter_mut().zip(h.finalize()) {
            *o ^= m;
        }
    }
}

/// RFC 9474 §4.2 Blind with a caller-supplied blinding factor r: returns
/// `blinded_msg = I2OSP(em * r^e mod n, modulus_len)` and `inv = r^-1 mod n`.
/// `em` is the EMSA-PSS output for em_bits = modBits - 1. Fails if gcd(em, n) != 1, or unless
/// 0 < r < n with gcd(r, n) = 1.
pub fn blind_raw(pk: &PublicKey, em: &[u8], r: &BigUint) -> Result<(Vec<u8>, BigUint), Error> {
    if em.len() != (pk.modulus_bits() - 1).div_ceil(8) {
        return Err(Error::BadLength);
    }
    let m = BigUint::from_bytes_be(em);
    if m >= pk.n || mod_inv(&m, &pk.n).is_none() {
        return Err(Error::OutOfRange);
    }
    if r.bits() == 0 || r >= &pk.n {
        return Err(Error::OutOfRange);
    }
    let inv = mod_inv(r, &pk.n).ok_or(Error::OutOfRange)?;
    let z = (&m * r.modpow(&pk.e, &pk.n)) % &pk.n;
    Ok((i2osp(&z, pk.modulus_len())?, inv))
}

/// RFC 9474 §4.4 Finalize: `sig = blind_sig * inv mod n`, then verifies `sig` over `msg` with
/// `ring`. A signature that does not verify is never returned.
pub fn finalize_raw(
    pk: &PublicKey,
    msg: &[u8],
    blind_sig: &[u8],
    inv: &BigUint,
) -> Result<Vec<u8>, Error> {
    let k = pk.modulus_len();
    if blind_sig.len() != k {
        return Err(Error::BadLength);
    }
    let z = BigUint::from_bytes_be(blind_sig);
    if z >= pk.n || inv.bits() == 0 || inv >= &pk.n {
        return Err(Error::OutOfRange);
    }
    let sig = i2osp(&((&z * inv) % &pk.n), k)?;
    verify(pk, msg, &sig)?;
    Ok(sig)
}

/// RSASSA-PSS verification (SHA-384, MGF1-SHA-384, sLen = 48) by `ring`, which accepts moduli of
/// 2048 to 8192 bits.
pub fn verify(pk: &PublicKey, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
    if sig.len() != pk.modulus_len() {
        return Err(Error::BadLength);
    }
    RsaPublicKeyComponents {
        n: pk.n_bytes(),
        e: pk.e_bytes(),
    }
    .verify(&RSA_PSS_2048_8192_SHA384, msg, sig)
    .map_err(|_| Error::Verification)
}

/// The signer-side fault check (RFC 9474 §4.3): true iff both inputs are modulus-length,
/// 0 < blinded < n, blind_sig < n and blind_sig^e == blinded (mod n). Computed with
/// `num-bigint-dig`, independently of whichever implementation produced `blind_sig`.
pub fn check_blind_signature(pk: &PublicKey, blinded: &[u8], blind_sig: &[u8]) -> bool {
    let k = pk.modulus_len();
    if blinded.len() != k || blind_sig.len() != k {
        return false;
    }
    let b = BigUint::from_bytes_be(blinded);
    let s = BigUint::from_bytes_be(blind_sig);
    b.bits() != 0 && b < pk.n && s < pk.n && s.modpow(&pk.e, &pk.n) == b
}

/// The 8 hash-derived challenges ρ_0..ρ_7 of the permutation proof of `pk` (design §3.2), each as
/// a 256-byte block: `ρ_i = OS2IP(H_i,0 || ... || H_i,4) mod n` with
/// `H_i,c = SHA-512("ghost/v1/perm-proof" || I2OSP(n, 256) || I2OSP(e, 4) || u8(i) || u8(c))`.
/// The key owner proves well-formedness by publishing `σ_i = ρ_i^d mod n` (a blind signature on
/// ρ_i). Only 2048-bit keys with e = 65537 have a proof.
pub fn permutation_proof_challenges(
    pk: &PublicKey,
) -> Result<[[u8; PROOF_BLOCK_LEN]; PROOF_ROUNDS], Error> {
    check_proof_key_shape(pk)?;
    let mut out = [[0u8; PROOF_BLOCK_LEN]; PROOF_ROUNDS];
    for (i, block) in out.iter_mut().enumerate() {
        let rho = proof_challenge(pk, i as u8);
        block.copy_from_slice(&i2osp(&rho, PROOF_BLOCK_LEN)?);
    }
    Ok(out)
}

/// Verifies the key well-formedness proof (design §3.2): n odd and exactly 2048 bits, e = 65537,
/// no prime factor <= 65 537, and for i = 0..7: gcd(ρ_i, n) = 1 and σ_i^e == ρ_i (mod n) with
/// σ_i < n. A key for which x -> x^e does not permute Z_n^* passes with probability <= 65537^-8.
pub fn verify_permutation_proof(
    pk: &PublicKey,
    proof: &[[u8; PROOF_BLOCK_LEN]; PROOF_ROUNDS],
) -> Result<(), Error> {
    check_proof_key_shape(pk)?;
    if has_small_factor(pk.n_bytes()) {
        return Err(Error::Proof);
    }
    for (i, sigma) in proof.iter().enumerate() {
        let rho = proof_challenge(pk, i as u8);
        if mod_inv(&rho, &pk.n).is_none() {
            return Err(Error::Proof);
        }
        let sigma = BigUint::from_bytes_be(sigma);
        if sigma >= pk.n || sigma.modpow(&pk.e, &pk.n) != rho {
            return Err(Error::Proof);
        }
    }
    Ok(())
}

fn check_proof_key_shape(pk: &PublicKey) -> Result<(), Error> {
    if pk.modulus_bits() != PROOF_MODULUS_BITS || pk.e != BigUint::from(PROOF_EXPONENT) {
        return Err(Error::Proof);
    }
    Ok(())
}

fn proof_challenge(pk: &PublicKey, i: u8) -> BigUint {
    let n_fixed = i2osp(&pk.n, PROOF_BLOCK_LEN).unwrap_or_default();
    let mut wide = Vec::with_capacity(64 * PROOF_HASH_BLOCKS as usize);
    for c in 0..PROOF_HASH_BLOCKS {
        let mut h = Sha512::new();
        h.update(PROOF_DOMAIN);
        h.update(&n_fixed);
        h.update(PROOF_EXPONENT.to_be_bytes());
        h.update([i, c]);
        wide.extend_from_slice(&h.finalize());
    }
    BigUint::from_bytes_be(&wide) % &pk.n
}

/// True iff n (big-endian) is divisible by a prime <= 65 537.
fn has_small_factor(n_be: &[u8]) -> bool {
    small_primes().iter().any(|&p| {
        let rem = n_be
            .iter()
            .fold(0u64, |acc, &b| ((acc << 8) | u64::from(b)) % u64::from(p));
        rem == 0
    })
}

fn small_primes() -> &'static [u32] {
    static PRIMES: OnceLock<Vec<u32>> = OnceLock::new();
    PRIMES.get_or_init(|| {
        let limit = PROOF_EXPONENT as usize;
        let mut composite = vec![false; limit + 1];
        let mut primes = Vec::new();
        for i in 2..=limit {
            if !composite[i] {
                primes.push(i as u32);
                let mut j = i * i;
                while j <= limit {
                    composite[j] = true;
                    j += i;
                }
            }
        }
        primes
    })
}

/// I2OSP (RFC 8017 §4.1): big-endian, left-padded to exactly `len` bytes.
pub fn i2osp(x: &BigUint, len: usize) -> Result<Vec<u8>, Error> {
    let bytes = if x.bits() == 0 {
        Vec::new()
    } else {
        x.to_bytes_be()
    };
    if bytes.len() > len {
        return Err(Error::OutOfRange);
    }
    let mut out = vec![0u8; len - bytes.len()];
    out.extend_from_slice(&bytes);
    Ok(out)
}

/// a^-1 mod n, or None when gcd(a, n) != 1.
pub fn mod_inv(a: &BigUint, n: &BigUint) -> Option<BigUint> {
    // num-bigint-dig normalises the inverse into [0, n); to_biguint refuses a negative value.
    let inv: BigInt = a.mod_inverse(n)?;
    inv.to_biguint()
}

fn is_odd(x: &BigUint) -> bool {
    x.to_bytes_be().last().is_some_and(|b| b & 1 == 1)
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn der_len(len: usize) -> Vec<u8> {
    match len {
        0..=0x7f => vec![len as u8],
        0x80..=0xff => vec![0x81, len as u8],
        _ => vec![0x82, (len >> 8) as u8, len as u8],
    }
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&der_len(content.len()));
    out.extend_from_slice(content);
    out
}

/// DER INTEGER of a non-negative big-endian magnitude without leading zeros.
fn der_integer(magnitude: &[u8]) -> Vec<u8> {
    if magnitude.first().is_some_and(|b| b & 0x80 != 0) {
        der_tlv(0x02, &[&[0u8][..], magnitude].concat())
    } else {
        der_tlv(0x02, magnitude)
    }
}

/// Reads one TLV with the expected tag; returns (content, rest). Lengths up to two bytes; any
/// non-minimal form is caught by the canonical re-encoding check of the caller.
fn der_read(input: &[u8], tag: u8) -> Result<(&[u8], &[u8]), Error> {
    let (&t, rest) = input.split_first().ok_or(Error::InvalidSpki)?;
    if t != tag {
        return Err(Error::InvalidSpki);
    }
    let (&first, rest) = rest.split_first().ok_or(Error::InvalidSpki)?;
    let (len, rest) = match first {
        0..=0x7f => (usize::from(first), rest),
        0x81 => {
            let (&b, rest) = rest.split_first().ok_or(Error::InvalidSpki)?;
            (usize::from(b), rest)
        }
        0x82 => {
            let b = rest.get(..2).ok_or(Error::InvalidSpki)?;
            ((usize::from(b[0]) << 8) | usize::from(b[1]), &rest[2..])
        }
        _ => return Err(Error::InvalidSpki),
    };
    if rest.len() < len {
        return Err(Error::InvalidSpki);
    }
    Ok(rest.split_at(len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_prime_table_ends_at_65537() {
        let primes = small_primes();
        assert_eq!(primes.len(), 6_543);
        assert_eq!(primes.first(), Some(&2));
        assert_eq!(primes.last(), Some(&65_537));
    }

    #[test]
    fn i2osp_pads_and_refuses_overflow() {
        assert_eq!(
            i2osp(&BigUint::from(0x0102u32), 4).unwrap(),
            vec![0, 0, 1, 2]
        );
        assert_eq!(i2osp(&BigUint::from(0u32), 2).unwrap(), vec![0, 0]);
        assert_eq!(
            i2osp(&BigUint::from(0x010203u32), 2),
            Err(Error::OutOfRange)
        );
    }

    #[test]
    fn der_integer_adds_a_sign_byte_only_when_needed() {
        assert_eq!(
            der_integer(&[0x01, 0x00, 0x01]),
            vec![0x02, 0x03, 0x01, 0x00, 0x01]
        );
        assert_eq!(der_integer(&[0x80]), vec![0x02, 0x02, 0x00, 0x80]);
    }

    #[test]
    fn components_are_checked() {
        assert_eq!(
            PublicKey::from_components(&[0x10], &[0x03]),
            Err(Error::InvalidKey)
        );
        assert_eq!(
            PublicKey::from_components(&[0x11], &[0x02]),
            Err(Error::InvalidKey)
        );
        assert_eq!(
            PublicKey::from_components(&[0x11], &[0x13]),
            Err(Error::InvalidKey)
        );
        assert!(PublicKey::from_components(&[0x00, 0x11], &[0x03]).is_ok());
    }
}
