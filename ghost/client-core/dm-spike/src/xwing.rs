//! V-6: X-Wing (draft-06) through `libcrux-kem` 0.0.9 with the typed rules of design §22.8.2.
//!
//! libcrux validates only the ML-KEM half of a public key and fails (instead of returning a
//! pseudo-random secret) when the X25519 half gives an all-zero agreement, and its decoders index
//! into the input before checking the length. GHOST therefore checks lengths first, validates the
//! whole key (ML-KEM half through libcrux, X25519 half by a contributory trial agreement) and
//! maps every library error to a typed code.

use crate::codes::Code;
use crate::olm::contributory;
use libcrux_kem::{Algorithm, Ct, PrivateKey, PublicKey};

pub const SEED_LEN: usize = 32;
pub const PUBLIC_KEY_LEN: usize = 1216;
pub const CIPHERTEXT_LEN: usize = 1120;
pub const ENCAPS_SEED_LEN: usize = 64;
pub const SHARED_SECRET_LEN: usize = 32;

const ALG: Algorithm = Algorithm::XWingKemDraft06;

/// The public key of a 32-byte decapsulation seed.
pub fn public_key(seed: &[u8; SEED_LEN]) -> Result<Vec<u8>, Code> {
    let (_, public) = libcrux_kem::key_gen_derand(ALG, seed).map_err(|_| Code::InvalidKey)?;
    Ok(public.encode())
}

/// Whole-key validation (§22.8.2 rule 3).
pub fn validate_public_key(bytes: &[u8]) -> Result<PublicKey, Code> {
    if bytes.len() != PUBLIC_KEY_LEN {
        return Err(Code::InvalidKey);
    }
    let mut x25519 = [0u8; 32];
    x25519.copy_from_slice(&bytes[PUBLIC_KEY_LEN - 32..]);
    if !contributory(&x25519) {
        return Err(Code::InvalidKey);
    }
    PublicKey::decode(ALG, bytes).map_err(|_| Code::InvalidKey)
}

/// Encapsulation with OS randomness; every library error is `INVALID_KEY` (§22.8.2 rule 4).
pub fn encapsulate(public: &[u8]) -> Result<(Vec<u8>, [u8; SHARED_SECRET_LEN]), Code> {
    let key = validate_public_key(public)?;
    let (ss, ct) = key
        .encapsulate(&mut rand::rng())
        .map_err(|_| Code::InvalidKey)?;
    shared(ss.encode()).map(|ss| (ct.encode(), ss))
}

/// Deterministic encapsulation from a 64-byte `eseed` (vectors only).
pub fn encapsulate_derand(
    public: &[u8],
    eseed: &[u8; ENCAPS_SEED_LEN],
) -> Result<(Vec<u8>, [u8; SHARED_SECRET_LEN]), Code> {
    let key = validate_public_key(public)?;
    let (ss, ct) = key
        .encapsulate_derand(eseed)
        .map_err(|_| Code::InvalidKey)?;
    shared(ss.encode()).map(|ss| (ct.encode(), ss))
}

/// Deterministic encapsulation without GHOST's whole-key validation (to show the library's own
/// behaviour on a low-order X25519 half).
pub fn encapsulate_derand_library(
    public: &[u8],
    eseed: &[u8; ENCAPS_SEED_LEN],
) -> Result<(Vec<u8>, [u8; SHARED_SECRET_LEN]), Code> {
    if public.len() != PUBLIC_KEY_LEN {
        return Err(Code::InvalidKey);
    }
    let key = PublicKey::decode(ALG, public).map_err(|_| Code::InvalidKey)?;
    let (ss, ct) = key
        .encapsulate_derand(eseed)
        .map_err(|_| Code::InvalidKey)?;
    shared(ss.encode()).map(|ss| (ct.encode(), ss))
}

/// Decapsulation; a wrong length or any library error is `NOT_OPEN` (§22.8.2 rule 4).
pub fn decapsulate(
    seed: &[u8; SEED_LEN],
    ciphertext: &[u8],
) -> Result<[u8; SHARED_SECRET_LEN], Code> {
    if ciphertext.len() != CIPHERTEXT_LEN {
        return Err(Code::NotOpen);
    }
    let ct = Ct::decode(ALG, ciphertext).map_err(|_| Code::NotOpen)?;
    let sk = PrivateKey::decode(ALG, seed).map_err(|_| Code::NotOpen)?;
    let ss = ct.decapsulate(&sk).map_err(|_| Code::NotOpen)?;
    shared(ss.encode())
}

fn shared(bytes: Vec<u8>) -> Result<[u8; SHARED_SECRET_LEN], Code> {
    <[u8; SHARED_SECRET_LEN]>::try_from(bytes.as_slice()).map_err(|_| Code::NotOpen)
}
