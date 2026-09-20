//! PQ-A: the X-Wing hybrid KEM (design §9.2), one suite, no negotiation, no standalone KEM.
//!
//! X-Wing draft-06 (wire-identical to draft-10) over `libcrux-kem` 0.0.9, reached **only** through
//! [`libcrux_kem::XWing`] and the `libcrux_traits::kem::slice::Kem` trait. The enum API of the same
//! crate is not used: `PublicKey::decode` panics on fewer than 1 184 bytes and `encapsulate_derand`
//! on a seed shorter than 64 bytes (`libcrux-kem-0.0.9/src/kem.rs:246,574`; evidence V-6), and the
//! enum dispatch links every KEM of the crate (+415 KB arm64-v8a, +514 KB x86_64; V-9).
//!
//! The slice trait performs no ML-KEM input check, so [`validate_public_key`] calls
//! `libcrux_ml_kem::mlkem768::validate_public_key` on the first 1 184 bytes itself and adds a
//! contributory X25519 trial agreement on the last 32 (§22.8.2 rule 3). libcrux **errors** where
//! RustCrypto `x-wing` returns a secret; every such error is typed here (§22.8.2 rule 4):
//! `INVALID_KEY` on the sealing side, `NOT_OPEN` on the opening side.

use crate::derive::KemSecret;
use crate::result::{DmCode, DmResult};
use libcrux_kem::XWing;
use libcrux_ml_kem::mlkem768::{validate_public_key as validate_ml_kem, MlKem768PublicKey};
use libcrux_traits::kem::slice::Kem;
use rand::TryRng;
use zeroize::Zeroize;

/// Length of an X-Wing decapsulation seed (the private key GHOST stores).
pub const SEED_BYTES: usize = 32;
/// Length of an X-Wing encapsulation key.
pub const PUBLIC_KEY_BYTES: usize = 1216;
/// Length of the expanded decapsulation key the slice trait works on.
pub const DECAPS_KEY_BYTES: usize = 2432;
/// Length of an X-Wing ciphertext.
pub const CIPHERTEXT_BYTES: usize = 1120;
/// Length of the encapsulation randomness.
pub const ENCAPS_RANDOMNESS_BYTES: usize = 64;
/// Length of an X-Wing shared secret.
pub const SHARED_SECRET_BYTES: usize = 32;
/// Length of the ML-KEM-768 half of an encapsulation key.
pub const ML_KEM_PUBLIC_KEY_BYTES: usize = 1184;
/// Length of the ML-KEM-768 half of a ciphertext; the last 32 bytes are `ct_X` (§22.8.2 rule 5 d).
pub const ML_KEM_CIPHERTEXT_BYTES: usize = 1088;

/// An X-Wing key pair: the encapsulation key that travels in a bundle, and the expanded
/// decapsulation key the slice trait needs. Both are derived from the stored 32-byte seed.
pub struct KeyPair {
    /// The 1 216-byte encapsulation key `Q_g`.
    pub public: Vec<u8>,
    decapsulation: Vec<u8>,
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        self.decapsulation.zeroize();
    }
}

impl core::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KeyPair(..)")
    }
}

/// Expands a stored 32-byte seed into its key pair (§3.1: private keys are seeds).
pub fn keygen(seed: &KemSecret) -> DmResult<KeyPair> {
    let mut public = vec![0u8; PUBLIC_KEY_BYTES];
    let mut decapsulation = vec![0u8; DECAPS_KEY_BYTES];
    XWing::keygen(&mut public, &mut decapsulation, seed.as_bytes())
        .map_err(|_| DmCode::InvalidKey)?;
    Ok(KeyPair {
        public,
        decapsulation,
    })
}

/// The encapsulation key of a stored seed.
pub fn public_key(seed: &KemSecret) -> DmResult<Vec<u8>> {
    Ok(keygen(seed)?.public.clone())
}

/// A trial X25519 agreement of a fresh random scalar with `point` is contributory: it is not the
/// all-zero output a low-order or non-canonical point gives (§22.8.2 rule 1).
pub fn contributory(point: &[u8; 32]) -> bool {
    let mut scalar = [0u8; 32];
    fill_random(&mut scalar);
    let shared = x25519_dalek::x25519(scalar, *point);
    scalar.zeroize();
    shared != [0u8; 32]
}

/// Whole-key validation of a 1 216-byte encapsulation key (§22.8.2 rule 3): the exact length, then
/// FIPS 203 modulus validation of the ML-KEM half, then a contributory trial on the X25519 half.
pub fn validate_public_key(bytes: &[u8]) -> DmResult<()> {
    if bytes.len() != PUBLIC_KEY_BYTES {
        return Err(DmCode::InvalidKey);
    }
    let ml_kem = MlKem768PublicKey::try_from(&bytes[..ML_KEM_PUBLIC_KEY_BYTES])
        .map_err(|_| DmCode::InvalidKey)?;
    if !validate_ml_kem(&ml_kem) {
        return Err(DmCode::InvalidKey);
    }
    let mut x25519 = [0u8; 32];
    x25519.copy_from_slice(&bytes[ML_KEM_PUBLIC_KEY_BYTES..]);
    if !contributory(&x25519) {
        return Err(DmCode::InvalidKey);
    }
    Ok(())
}

/// Encapsulation to a validated key with OS randomness. Every error is `INVALID_KEY`.
pub fn encapsulate(public: &[u8]) -> DmResult<(Vec<u8>, KemSecret)> {
    let mut randomness = [0u8; ENCAPS_RANDOMNESS_BYTES];
    fill_random(&mut randomness);
    let out = encapsulate_with(public, &randomness);
    randomness.zeroize();
    out
}

/// Encapsulation with given randomness: the vector and equivalence-fixture path (§15.9 item 7).
pub fn encapsulate_with(
    public: &[u8],
    randomness: &[u8; ENCAPS_RANDOMNESS_BYTES],
) -> DmResult<(Vec<u8>, KemSecret)> {
    validate_public_key(public)?;
    let mut ciphertext = vec![0u8; CIPHERTEXT_BYTES];
    let mut shared = [0u8; SHARED_SECRET_BYTES];
    XWing::encaps(&mut ciphertext, &mut shared, public, randomness)
        .map_err(|_| DmCode::InvalidKey)?;
    let secret = KemSecret::from_bytes(shared);
    shared.zeroize();
    Ok((ciphertext, secret))
}

/// Decapsulation from the stored seed. Every error, including a wrong length, is `NOT_OPEN`: a
/// ciphertext that does not open is a blob that is dropped, never a crash (§22.8.2 rule 4).
pub fn decapsulate(seed: &KemSecret, ciphertext: &[u8]) -> DmResult<KemSecret> {
    if ciphertext.len() != CIPHERTEXT_BYTES {
        return Err(DmCode::NotOpen);
    }
    let pair = keygen(seed).map_err(|_| DmCode::NotOpen)?;
    let mut shared = [0u8; SHARED_SECRET_BYTES];
    XWing::decaps(&mut shared, ciphertext, &pair.decapsulation).map_err(|_| DmCode::NotOpen)?;
    let secret = KemSecret::from_bytes(shared);
    shared.zeroize();
    Ok(secret)
}

/// Fills `out` from the **OS CSPRNG**, which is what §9.2 requires of the encapsulation randomness
/// and what keeps §22.8.10 point 7 exact: `SysRng` is `getrandom`'s own reader, so the
/// custom-backend routing of the `ghost-dm-host` world reaches every byte this crate draws. A
/// user-space generator seeded from the OS (`rand::fill`, which is `ThreadRng`, a reseeding
/// ChaCha12) would sit between the two and replay a different stream.
///
/// Every salt, nonce, root and KEM randomness of this crate is drawn here and nowhere else, which
/// is what makes the deterministic equivalence fixture of §15.9 item 7 possible: the paths that a
/// fixture replays take their randomness as an argument instead.
pub(crate) fn fill_random(out: &mut [u8]) {
    rand::rngs::SysRng
        .try_fill_bytes(out)
        .expect("the OS CSPRNG is unavailable");
}

/// Every u-coordinate of the 8-torsion subgroup of Curve25519, plus the non-canonical encodings
/// u = p and u = p + 1: the six distinct values of evidence V-6 §6.1 point 3. Test-only, and
/// reachable from the seal tests, which need the same set for the `ct_X` cases of §22.8.2 rule 5.
#[cfg(test)]
pub(crate) fn low_order_points() -> Vec<[u8; 32]> {
    let mut out: Vec<[u8; 32]> = curve25519_dalek::constants::EIGHT_TORSION
        .iter()
        .map(|point| point.to_montgomery().to_bytes())
        .collect();
    let mut p = [0xffu8; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    out.push(p);
    let mut p_plus_one = p;
    p_plus_one[0] = 0xee;
    out.push(p_plus_one);
    out.sort_unstable();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(byte: u8) -> KemSecret {
        KemSecret::from_bytes([byte; 32])
    }

    #[test]
    fn a_seed_expands_to_one_key_pair_and_round_trips() {
        let secret = seed(1);
        let pair = keygen(&secret).expect("keygen");
        assert_eq!(pair.public.len(), PUBLIC_KEY_BYTES);
        assert_eq!(public_key(&secret).expect("public"), pair.public);
        let (ciphertext, shared) = encapsulate(&pair.public).expect("encaps");
        assert_eq!(ciphertext.len(), CIPHERTEXT_BYTES);
        let opened = decapsulate(&secret, &ciphertext).expect("decaps");
        assert_eq!(opened.as_bytes(), shared.as_bytes());
    }

    #[test]
    fn another_seed_does_not_open_it() {
        let pair = keygen(&seed(1)).expect("keygen");
        let (ciphertext, shared) = encapsulate(&pair.public).expect("encaps");
        // ML-KEM implicit rejection returns a different secret rather than an error.
        let other = decapsulate(&seed(2), &ciphertext).expect("implicit rejection");
        assert_ne!(other.as_bytes(), shared.as_bytes());
    }

    #[test]
    fn wrong_lengths_are_typed_refusals_and_never_panics() {
        for len in [0usize, 32, 1183, 1184, 1215, 1217, 2432] {
            assert_eq!(
                validate_public_key(&vec![0u8; len]).err(),
                Some(DmCode::InvalidKey),
                "public key length {len}"
            );
        }
        let secret = seed(3);
        for len in [0usize, 1119, 1121] {
            assert_eq!(
                decapsulate(&secret, &vec![0u8; len]).err(),
                Some(DmCode::NotOpen),
                "ciphertext length {len}"
            );
        }
    }

    #[test]
    fn a_low_order_x25519_half_is_refused_before_encapsulation() {
        let pair = keygen(&seed(4)).expect("keygen");
        for point in low_order_points() {
            let mut bad = pair.public.clone();
            bad[ML_KEM_PUBLIC_KEY_BYTES..].copy_from_slice(&point);
            assert_eq!(validate_public_key(&bad).err(), Some(DmCode::InvalidKey));
            assert_eq!(encapsulate(&bad).err(), Some(DmCode::InvalidKey));
        }
    }

    #[test]
    fn an_invalid_ml_kem_half_is_refused_although_the_trait_would_encapsulate_to_it() {
        let pair = keygen(&seed(5)).expect("keygen");
        let mut bad = pair.public.clone();
        // A first coefficient of 0xFFF, above q = 3 329.
        bad[0] = 0xff;
        bad[1] |= 0x0f;
        assert_eq!(validate_public_key(&bad).err(), Some(DmCode::InvalidKey));
        let mut ciphertext = vec![0u8; CIPHERTEXT_BYTES];
        let mut shared = [0u8; SHARED_SECRET_BYTES];
        assert!(
            XWing::encaps(&mut ciphertext, &mut shared, &bad, &[0u8; 64]).is_ok(),
            "the slice trait has no FIPS 203 input check; only the explicit call refuses it"
        );
    }

    #[test]
    fn a_flipped_ciphertext_byte_gives_another_secret_without_an_error() {
        let secret = seed(6);
        let pair = keygen(&secret).expect("keygen");
        let (mut ciphertext, shared) = encapsulate(&pair.public).expect("encaps");
        ciphertext[0] ^= 1;
        let opened = decapsulate(&secret, &ciphertext).expect("implicit rejection");
        assert_ne!(opened.as_bytes(), shared.as_bytes());
    }

    /// §22.8.2 rule 5 (d): a low-order X25519 half in the **ciphertext**, `ct_X`, on the intro
    /// path. A sender can put one there, and the opening runs inside a peek, which commits no
    /// offer counter, so the poison guard would not stop a crash loop: every such ciphertext must
    /// be a typed `NOT_OPEN` and never a panic.
    #[test]
    fn a_low_order_x25519_half_in_the_ciphertext_is_not_open() {
        let secret = seed(9);
        let pair = keygen(&secret).expect("keygen");
        let (ciphertext, _) = encapsulate(&pair.public).expect("encaps");
        for point in low_order_points() {
            let mut bad = ciphertext.clone();
            bad[ML_KEM_CIPHERTEXT_BYTES..].copy_from_slice(&point);
            assert_eq!(
                decapsulate(&secret, &bad).err(),
                Some(DmCode::NotOpen),
                "ct_X = {}",
                hex_of(&point)
            );
        }
        // The all-zero half is the same refusal, and a valid half still opens.
        let mut zeroed = ciphertext.clone();
        zeroed[ML_KEM_CIPHERTEXT_BYTES..].copy_from_slice(&[0u8; 32]);
        assert_eq!(decapsulate(&secret, &zeroed).err(), Some(DmCode::NotOpen));
        assert!(decapsulate(&secret, &ciphertext).is_ok());
    }

    fn hex_of(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn deterministic_encapsulation_is_reproducible() {
        let pair = keygen(&seed(7)).expect("keygen");
        let randomness = [9u8; ENCAPS_RANDOMNESS_BYTES];
        let (first_ct, first_ss) = encapsulate_with(&pair.public, &randomness).expect("encaps");
        let (second_ct, second_ss) = encapsulate_with(&pair.public, &randomness).expect("encaps");
        assert_eq!(first_ct, second_ct);
        assert_eq!(first_ss.as_bytes(), second_ss.as_bytes());
    }

    #[test]
    fn contributory_refuses_every_low_order_point() {
        for point in low_order_points() {
            assert!(!contributory(&point));
        }
        let pair = keygen(&seed(8)).expect("keygen");
        let mut good = [0u8; 32];
        good.copy_from_slice(&pair.public[ML_KEM_PUBLIC_KEY_BYTES..]);
        assert!(contributory(&good));
    }
}
