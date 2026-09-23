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
//! canonical-encoding check and a contributory X25519 trial agreement on the last 32 (§22.8.2
//! rule 3; the encoding check since the slice S13 review). libcrux **errors** where
//! RustCrypto `x-wing` returns a secret; every such error is typed here (§22.8.2 rule 4):
//! `INVALID_KEY` on the sealing side, `NOT_OPEN` on the opening side.

use crate::derive::KemSecret;
use crate::result::{DmCode, DmResult};
use libcrux_kem::XWing;
use libcrux_ml_kem::mlkem768::{validate_public_key as validate_ml_kem, MlKem768PublicKey};
use libcrux_traits::kem::slice::{DecapsError, EncapsError, Kem, KeyGenError};
use rand::TryRng;
use zeroize::Zeroize;

// -------------------------------------------------------------------------------------------
// §22.8.2 rule 4: every KEM error is typed, and the matches below carry no wildcard, so a variant
// added at a libcrux bump fails the build instead of collapsing into a generic code (the
// compile-time half of `DmResultCodesTest`; `every_kem_error_has_a_code` is its runtime half).
//
// The error types are the ones GHOST actually receives. The §22.8.2 text names `libcrux-kem`'s
// `Error`, which belongs to the **enum API**; the S0′ forward note of that section replaced that
// call path with `libcrux_kem::XWing` through `libcrux_traits::kem::slice::Kem` (V-6, V-9), whose
// errors are `KeyGenError`, `EncapsError` and `DecapsError`. None of the three is
// `#[non_exhaustive]` in `libcrux-traits` 0.0.8.
// -------------------------------------------------------------------------------------------

/// Key expansion: a seed that does not expand is a key GHOST cannot seal to or open with. The
/// sealing side reports it as [`DmCode::InvalidKey`]; [`decapsulate`] re-maps it to
/// [`DmCode::NotOpen`], because there the seed is ours and the blob is the one that is dropped.
const fn keygen_code(error: &KeyGenError) -> DmCode {
    match error {
        KeyGenError::InvalidRandomness
        | KeyGenError::InvalidRandomnessLength
        | KeyGenError::InvalidEncapsKeyLength
        | KeyGenError::InvalidDecapsKeyLength
        | KeyGenError::Unknown => DmCode::InvalidKey,
    }
}

/// Encapsulation: every error is [`DmCode::InvalidKey`] — the candidate key is dropped and the
/// attempt continues (§22.8.2 rule 4).
const fn encaps_code(error: &EncapsError) -> DmCode {
    match error {
        EncapsError::InvalidEncapsKey
        | EncapsError::InvalidRandomness
        | EncapsError::InvalidRandomnessLength
        | EncapsError::InvalidEncapsKeyLength
        | EncapsError::InvalidCiphertextLength
        | EncapsError::InvalidSharedSecretLength
        | EncapsError::Unknown => DmCode::InvalidKey,
    }
}

/// Decapsulation: every error is [`DmCode::NotOpen`] — a ciphertext that does not open is a blob
/// that is dropped, never a crash (§22.8.2 rule 4).
const fn decaps_code(error: &DecapsError) -> DmCode {
    match error {
        DecapsError::InvalidCiphertext
        | DecapsError::InvalidDecapsKey
        | DecapsError::InvalidDecapsKeyLength
        | DecapsError::InvalidCiphertextLength
        | DecapsError::InvalidSharedSecretLength
        | DecapsError::Unknown => DmCode::NotOpen,
    }
}

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
        .map_err(|error| keygen_code(&error))?;
    Ok(KeyPair {
        public,
        decapsulation,
    })
}

/// The encapsulation key of a stored seed.
pub fn public_key(seed: &KemSecret) -> DmResult<Vec<u8>> {
    Ok(keygen(seed)?.public.clone())
}

/// The scalar of the trial agreement in [`contributory`]: any value, since X25519 clamps it.
const TRIAL_SCALAR: [u8; 32] = [0x5a; 32];

/// A trial X25519 agreement with `point` is contributory: it is not the all-zero output a
/// low-order point gives (§22.8.2 rule 1).
///
/// **Why a fixed scalar is exact (slice S13 review).** X25519 clamps every scalar to `k = 2^254 +
/// 8m`, `m < 2^251`, and the ladder answers zero exactly when `[k]P` is the identity or the point
/// of order 2. The curve group is `Z/8 × Z/ℓ` and the twist's `Z/4 × Z/p'`, with `ℓ ≈ 2^252` and
/// `p' ≈ 2^253` prime; for `[k]P` to vanish on a point whose order has the large prime factor, `k`
/// would have to be a multiple of `8ℓ` or `8p'`, both above `2^255 > k`, and "the point of order 2"
/// would need a 2-power of order 16, which neither group has. So the output is zero **for every
/// clamped scalar** exactly when the point's order divides 8 (curve) or 4 (twist). The earlier
/// random scalar decided nothing a constant does not, and it drew on the OS generator — with a
/// panic if that failed — on paths that parse a peer's bytes (`l0Decode`'s `pq_key`).
pub fn contributory(point: &[u8; 32]) -> bool {
    x25519_dalek::x25519(TRIAL_SCALAR, *point) != [0u8; 32]
}

/// The Curve25519 field prime `p = 2^255 - 19`, little-endian: the bound a canonical u-coordinate
/// encoding stays under.
pub const CURVE25519_P: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

/// Whether a 32-byte u-coordinate is the **canonical** encoding of its point: the little-endian
/// value is below [`CURVE25519_P`] (review round 2, R2-06).
///
/// RFC 7748 masks the top bit and reduces mod `p` before use, so `k`, `k | 2^255` and `k + p` are
/// one point to X25519 and to `curve25519-dalek`'s `MontgomeryPoint::ct_eq`, which compares field
/// elements. Anything that **hashes or compares the bytes** — an Olm session id, a receiver
/// chain's ratchet key, a pinned identity — therefore needs the encoding pinned as well as the
/// point. The values are public, so a data-dependent exit is not a leak.
pub fn canonical_u_coordinate(point: &[u8; 32]) -> bool {
    for index in (0..32).rev() {
        if point[index] != CURVE25519_P[index] {
            return point[index] < CURVE25519_P[index];
        }
    }
    // Exactly `p`, which encodes the point 0.
    false
}

/// Whole-key validation of a 1 216-byte encapsulation key (§22.8.2 rule 3): the exact length, then
/// FIPS 203 modulus validation of the ML-KEM half, then the X25519 half — a **canonical** encoding
/// ([`canonical_u_coordinate`]) of a point that is not low-order ([`contributory`]).
///
/// The canonical check was added by the slice S13 review. X25519 reduces a non-canonical `u`
/// (the top bit set, or `p ≤ u < 2^255`) to the point it encodes, so such a key encapsulates —
/// but the X-Wing combiner and the PQ-C root's salt (§9.4) hash the key's **bytes**, and the key's
/// owner recomputes the canonical ones from its seed: the two sides would derive different
/// secrets from one encapsulation, silently. Only the key's owner can publish such a key (keys
/// built in this crate are canonical), so it is refused here as an invalid key rather than left to
/// fail as "the peer never opens it".
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
    if !canonical_u_coordinate(&x25519) || !contributory(&x25519) {
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
        .map_err(|error| encaps_code(&error))?;
    #[cfg(any(test, feature = "pq-spy"))]
    spy::encapsulated(&mut shared);
    let secret = KemSecret::from_bytes(shared);
    shared.zeroize();
    Ok((ciphertext, secret))
}

/// Decapsulation from the stored seed. Every error, including a wrong length, is `NOT_OPEN`: a
/// ciphertext that does not open is a blob that is dropped, never a crash (§22.8.2 rule 4).
pub fn decapsulate(seed: &KemSecret, ciphertext: &[u8]) -> DmResult<KemSecret> {
    decapsulate_expanded(seed, ciphertext).map(|(secret, _)| secret)
}

/// Decapsulation that also returns the generation's own encapsulation key, from **one** seed
/// expansion: the PQ-C root binds `Q_c` into its salt (§9.4), and the opener must take that key
/// from its own seed rather than from anything a peer sent. Every error is `NOT_OPEN`, as for
/// [`decapsulate`].
pub fn decapsulate_with_public(
    seed: &KemSecret,
    ciphertext: &[u8],
) -> DmResult<(KemSecret, Vec<u8>)> {
    let (secret, pair) = decapsulate_expanded(seed, ciphertext)?;
    Ok((secret, pair.public.clone()))
}

/// The one decapsulation both public entry points run, and the one place PQ1's spy (`spy`, test
/// builds only) counts: every call is counted on entry, whatever it returns, and the secret it
/// hands back is the one the spy may perturb.
fn decapsulate_expanded(seed: &KemSecret, ciphertext: &[u8]) -> DmResult<(KemSecret, KeyPair)> {
    #[cfg(any(test, feature = "pq-spy"))]
    spy::decapsulation_started();
    if ciphertext.len() != CIPHERTEXT_BYTES {
        return Err(DmCode::NotOpen);
    }
    let pair = keygen(seed).map_err(|_| DmCode::NotOpen)?;
    let mut shared = [0u8; SHARED_SECRET_BYTES];
    XWing::decaps(&mut shared, ciphertext, &pair.decapsulation)
        .map_err(|error| decaps_code(&error))?;
    #[cfg(any(test, feature = "pq-spy"))]
    spy::decapsulated(&mut shared);
    let secret = KemSecret::from_bytes(shared);
    shared.zeroize();
    Ok((secret, pair))
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

/// PQ1's spy on the KEM boundary (design §15.5 PQ1 and PQ5, RG-5; §22.19). **Test builds only**:
/// the crate's own tests (`cfg(test)`) and the `pq-spy` feature, which only `ghost-dm-host`
/// enables; G-R2 refuses the feature in the shipped graph (its allowed list is `default` and
/// `jni-bridge`).
///
/// It counts, per thread, every decapsulation ([`decapsulate`] and [`decapsulate_with_public`] go
/// through one function) and every successful encapsulation, and it can **perturb** the next
/// shared secret one of them produces — bit 0 of byte 0 flipped, one-shot. The perturbation is
/// what makes "`k_in` depends on `ss`" a differential test of the code as it stands rather than a
/// property of HKDF: the ciphertext, the transcript and every other input stay exactly as they
/// were, only the secret the KEM handed back changes, so an opener whose key does not depend on
/// that secret opens the envelope anyway, and one that does refuses it.
///
/// The counters are thread-local because a JNI call and a test both run on one thread from the
/// open to its result, and parallel tests must not see each other's decapsulations; every check
/// reads a **difference** of the counter around the call it checks.
#[cfg(any(test, feature = "pq-spy"))]
pub mod spy {
    use crate::result::{DmCode, DmResult};
    use std::cell::Cell;

    thread_local! {
        static DECAPSULATIONS: Cell<u64> = const { Cell::new(0) };
        static ENCAPSULATIONS: Cell<u64> = const { Cell::new(0) };
        static PERTURB_DECAPSULATION: Cell<bool> = const { Cell::new(false) };
        static PERTURB_ENCAPSULATION: Cell<bool> = const { Cell::new(false) };
    }

    /// The decapsulations this thread has started, successful or not.
    pub fn decapsulations() -> u64 {
        DECAPSULATIONS.with(Cell::get)
    }

    /// The encapsulations this thread has completed.
    pub fn encapsulations() -> u64 {
        ENCAPSULATIONS.with(Cell::get)
    }

    /// Arms a one-shot perturbation of the next shared secret a decapsulation on this thread
    /// returns.
    pub fn perturb_next_decapsulation() {
        PERTURB_DECAPSULATION.with(|armed| armed.set(true));
    }

    /// Arms a one-shot perturbation of the next shared secret an encapsulation on this thread
    /// returns: the sender seals under a secret the ciphertext does not carry.
    pub fn perturb_next_encapsulation() {
        PERTURB_ENCAPSULATION.with(|armed| armed.set(true));
    }

    /// Disarms both perturbations and reports whether either was still armed, that is, whether a
    /// perturbation the caller armed was **not** consumed by a KEM operation.
    pub fn disarm() -> bool {
        let decapsulation = PERTURB_DECAPSULATION.with(|armed| armed.replace(false));
        let encapsulation = PERTURB_ENCAPSULATION.with(|armed| armed.replace(false));
        decapsulation || encapsulation
    }

    pub(super) fn decapsulation_started() {
        DECAPSULATIONS.with(|count| count.set(count.get() + 1));
    }

    pub(super) fn decapsulated(shared: &mut [u8; super::SHARED_SECRET_BYTES]) {
        if PERTURB_DECAPSULATION.with(|armed| armed.replace(false)) {
            shared[0] ^= 1;
        }
    }

    pub(super) fn encapsulated(shared: &mut [u8; super::SHARED_SECRET_BYTES]) {
        ENCAPSULATIONS.with(|count| count.set(count.get() + 1));
        if PERTURB_ENCAPSULATION.with(|armed| armed.replace(false)) {
            shared[0] ^= 1;
        }
    }

    /// PQ1 as an **assertion** around one intro open (§2.6 function 12 in `ghost-dm-host`): the
    /// open that succeeds performed exactly one decapsulation, the open that is refused performed
    /// at most one, and the same open run again with the decapsulated secret perturbed is
    /// `NOT_OPEN` — `k_in` depends on `ss`. A violation panics with a `PQ1:` message, which the JNI
    /// guard turns into `INTERNAL`, so every intro open of every JVM world run against the host
    /// library is checked, and the world fails on the first open that breaks it.
    ///
    /// `open` must be repeatable (it is run twice after a success). The second run draws no
    /// randomness: an intro open reads its randomness only for the `reply_seed` envelope it wraps
    /// **after** the inner layer has opened, which the perturbed run never reaches, so the seeded
    /// worlds' random streams are the ones a build without the spy draws.
    pub fn assert_intro_open<T>(open: impl Fn() -> DmResult<T>) -> DmResult<T> {
        let before = decapsulations();
        let result = open();
        let used = decapsulations() - before;
        match result {
            Ok(_) => {
                assert!(
                    used == 1,
                    "PQ1: an intro open that succeeded performed {used} decapsulations, not one"
                );
                disarm();
                perturb_next_decapsulation();
                let before = decapsulations();
                let perturbed = open();
                let used = decapsulations() - before;
                let unconsumed = disarm();
                assert!(
                    used == 1 && !unconsumed,
                    "PQ1: the perturbed intro open performed {used} decapsulations and left the \
                     perturbation unconsumed: {unconsumed}"
                );
                assert!(
                    matches!(perturbed, Err(DmCode::NotOpen)),
                    "PQ1: an intro open succeeded with its decapsulated secret perturbed: k_in does \
                     not depend on ss"
                );
            }
            Err(_) => assert!(
                used <= 1,
                "PQ1: a refused intro open performed {used} decapsulations"
            ),
        }
        result
    }
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

    /// R2-06: the canonical range is exactly `0 ..= p - 1`, and both ways out of it — the top bit
    /// and the 19 values from `p` up — are refused.
    #[test]
    fn a_u_coordinate_is_canonical_below_the_field_prime() {
        assert!(canonical_u_coordinate(&[0u8; 32]));
        let mut p_minus_one = CURVE25519_P;
        p_minus_one[0] -= 1;
        assert!(canonical_u_coordinate(&p_minus_one));
        assert!(!canonical_u_coordinate(&CURVE25519_P), "p itself");
        // `p ..= 2^255 - 1`: the 19 values that reduce to `0 ..= 18`.
        for extra in 0..19u8 {
            let mut over = CURVE25519_P;
            over[0] += extra;
            assert!(!canonical_u_coordinate(&over), "p + {extra}");
        }
        // The top bit, on a value that is canonical without it.
        let mut high = [7u8; 32];
        assert!(canonical_u_coordinate(&high));
        high[31] |= 0x80;
        assert!(!canonical_u_coordinate(&high));
        assert!(!canonical_u_coordinate(&[0xff; 32]));
        // A real key is canonical.
        let public =
            crate::derive::olm_identity_public(&crate::derive::OlmSecret::from_bytes([0x31; 32]));
        assert!(canonical_u_coordinate(&public));
    }

    /// The runtime half of §22.8.2 rule 4: every variant of the three KEM error types GHOST
    /// receives is named here with the code it maps to. The compile-time half is the wildcard-free
    /// `match` of each function above, which a bump that adds a variant fails.
    #[test]
    fn every_kem_error_has_a_code() {
        for error in [
            KeyGenError::InvalidRandomness,
            KeyGenError::InvalidRandomnessLength,
            KeyGenError::InvalidEncapsKeyLength,
            KeyGenError::InvalidDecapsKeyLength,
            KeyGenError::Unknown,
        ] {
            assert_eq!(keygen_code(&error), DmCode::InvalidKey, "{error:?}");
        }
        for error in [
            EncapsError::InvalidEncapsKey,
            EncapsError::InvalidRandomness,
            EncapsError::InvalidRandomnessLength,
            EncapsError::InvalidEncapsKeyLength,
            EncapsError::InvalidCiphertextLength,
            EncapsError::InvalidSharedSecretLength,
            EncapsError::Unknown,
        ] {
            assert_eq!(encaps_code(&error), DmCode::InvalidKey, "{error:?}");
        }
        for error in [
            DecapsError::InvalidCiphertext,
            DecapsError::InvalidDecapsKey,
            DecapsError::InvalidDecapsKeyLength,
            DecapsError::InvalidCiphertextLength,
            DecapsError::InvalidSharedSecretLength,
            DecapsError::Unknown,
        ] {
            assert_eq!(decaps_code(&error), DmCode::NotOpen, "{error:?}");
        }
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

    /// The slice S13 review: an X25519 half that encodes a valid point non-canonically is refused.
    /// X25519 itself accepts it — the encapsulation succeeds — but the key's bytes are hashed by
    /// the combiner and the PQ-C salt, and its owner holds the canonical ones.
    #[test]
    fn a_non_canonical_x25519_half_is_refused_although_x25519_accepts_it() {
        let pair = keygen(&seed(10)).expect("keygen");
        assert!(validate_public_key(&pair.public).is_ok());
        // The top bit: the same point to X25519.
        let mut high = pair.public.clone();
        high[PUBLIC_KEY_BYTES - 1] |= 0x80;
        let mut point = [0u8; 32];
        point.copy_from_slice(&high[ML_KEM_PUBLIC_KEY_BYTES..]);
        assert!(
            contributory(&point),
            "a valid point, only encoded differently"
        );
        assert_eq!(validate_public_key(&high).err(), Some(DmCode::InvalidKey));
        assert_eq!(encapsulate(&high).err(), Some(DmCode::InvalidKey));
        // `u + p` for a small valid u: 9 is the base point's u, and 9 + p < 2^255.
        let mut plus_p = pair.public.clone();
        let mut nine_plus_p = CURVE25519_P;
        nine_plus_p[0] += 9;
        plus_p[ML_KEM_PUBLIC_KEY_BYTES..].copy_from_slice(&nine_plus_p);
        assert!(
            contributory(&nine_plus_p),
            "the base point, non-canonically"
        );
        assert_eq!(validate_public_key(&plus_p).err(), Some(DmCode::InvalidKey));
    }

    /// The trial scalar is fixed, and the answer is the same for any clamped scalar (the proof is
    /// on [`contributory`]): checked here against a spread of random ones.
    #[test]
    fn contributory_does_not_depend_on_the_scalar() {
        let pair = keygen(&seed(11)).expect("keygen");
        let mut good = [0u8; 32];
        good.copy_from_slice(&pair.public[ML_KEM_PUBLIC_KEY_BYTES..]);
        let mut points = low_order_points();
        points.push(good);
        for _ in 0..32 {
            let mut scalar = [0u8; 32];
            fill_random(&mut scalar);
            for point in &points {
                assert_eq!(
                    x25519_dalek::x25519(scalar, *point) != [0u8; 32],
                    contributory(point),
                    "{}",
                    hex_of(point)
                );
            }
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
