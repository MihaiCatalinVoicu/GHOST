//! X-Wing known-answer and differential tests (design §9.2, evidence V-6 §6.1).
//!
//! `vectors/xwing-draft06.json` is a byte-identical copy of `tests/test-vectors.json` of the
//! RustCrypto `x-wing` 0.1.0 crate (both SHA-256
//! `a8726596f4c7629590f727b1bbeb483f6932292fbf5fd85c9cbb803190014f00`, checked by
//! `the_vector_file_is_the_pinned_copy` below). That crate names the origin of the file it ships:
//! `x-wing-0.1.0/tests/kats.rs:59`, the doc comment of `rfc_test_vectors`, which reads the same
//! file through `include_str!`, cites
//! `https://github.com/dconnolly/draft-connolly-cfrg-xwing-kem/blob/main/spec/test-vectors.json`,
//! and its README adds "matches the draft RFC version 06". The values therefore come from the
//! draft repository and not from RustCrypto's implementation, which is what keeps the vector check
//! independent of the differential check below.
//!
//! **Still outstanding (declared, S4a could not close it here):** the byte comparison of this file
//! with the draft-06 Appendix text, and the draft-10 vectors. Both need the IETF documents, which
//! this host does not fetch; draft-06 and draft-10 are wire-identical (draft-10's change log
//! Appendix G.1–G.2 lists only an ASN.1 module, the SHAKE-256 output length written in bits,
//! implementation lists and a PEM header fix), so the vectors below cover both wire formats and
//! the outstanding item is a provenance check, not a behaviour check.
//!
//! **Also outstanding: the ML-KEM-768 known-answer tests of §9.2 and §15.2.** The FIPS 203 / ACVP
//! vector files are not on this host and are not fetched here. What covers ML-KEM-768 meanwhile is
//! recorded and checked below by `the_ml_kem_halves_are_pinned_by_the_x_wing_vectors`: the X-Wing
//! vectors pin every ML-KEM-768 output byte for byte through the combiner (the encapsulation key's
//! first 1 184 bytes, the ciphertext's first 1 088, and a shared secret that is a hash over the
//! ML-KEM shared secret), and `ghost_and_rust_crypto_agree_on_valid_inputs` is a differential test
//! against RustCrypto's independent ML-KEM-768. That is a strictly weaker check than a direct KAT
//! on the ML-KEM decapsulation of an **invalid** ciphertext, which only implicit rejection
//! exercises, so the item stays declared in `README.md` rather than treated as closed.

use ghost_client_dm::derive::KemSecret;
use ghost_client_dm::pq;
use ghost_client_dm::result::DmCode;
use sha2::{Digest, Sha256};

const VECTORS: &str = include_str!("vectors/xwing-draft06.json");
const VECTORS_SHA256: &str = "a8726596f4c7629590f727b1bbeb483f6932292fbf5fd85c9cbb803190014f00";

fn field(vector: &serde_json::Value, name: &str) -> Vec<u8> {
    hex::decode(vector[name].as_str().expect("field")).expect("hex")
}

fn vectors() -> Vec<serde_json::Value> {
    serde_json::from_str(VECTORS).expect("json")
}

fn seed_of(bytes: &[u8]) -> KemSecret {
    let mut seed = [0u8; 32];
    seed.copy_from_slice(bytes);
    KemSecret::from_bytes(seed)
}

#[test]
fn the_vector_file_is_the_pinned_copy() {
    // The file is read through include_str!, so compare the bytes on disk, not a re-encoding.
    let bytes = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/xwing-draft06.json"
    ))
    .expect("read");
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    assert_eq!(hex::encode(digest), VECTORS_SHA256);
}

#[test]
fn the_draft_06_vectors_replay() {
    let vectors = vectors();
    assert_eq!(vectors.len(), 3);
    for vector in &vectors {
        let seed = seed_of(&field(vector, "seed"));
        let pair = pq::keygen(&seed).expect("keygen");
        assert_eq!(pair.public, field(vector, "pk"));
        // The private key is the 32-byte seed itself.
        assert_eq!(field(vector, "sk"), seed.as_bytes());

        let mut randomness = [0u8; pq::ENCAPS_RANDOMNESS_BYTES];
        randomness.copy_from_slice(&field(vector, "eseed"));
        let (ciphertext, shared) = pq::encapsulate_with(&pair.public, &randomness).expect("encaps");
        assert_eq!(ciphertext, field(vector, "ct"));
        assert_eq!(shared.as_bytes(), field(vector, "ss").as_slice());

        let opened = pq::decapsulate(&seed, &ciphertext).expect("decaps");
        assert_eq!(opened.as_bytes(), shared.as_bytes());
    }
}

#[test]
fn the_sizes_are_the_ones_the_design_freezes() {
    let vector = &vectors()[0];
    assert_eq!(field(vector, "pk").len(), pq::PUBLIC_KEY_BYTES);
    assert_eq!(field(vector, "ct").len(), pq::CIPHERTEXT_BYTES);
    assert_eq!(field(vector, "seed").len(), pq::SEED_BYTES);
    assert_eq!(field(vector, "ss").len(), pq::SHARED_SECRET_BYTES);
    assert_eq!(field(vector, "eseed").len(), pq::ENCAPS_RANDOMNESS_BYTES);
    assert_eq!(pq::PUBLIC_KEY_BYTES, 1216);
    assert_eq!(pq::CIPHERTEXT_BYTES, 1120);
}

/// What the draft-06 vectors pin of ML-KEM-768 itself, in place of the FIPS 203 KATs §9.2 lists:
/// the ML-KEM halves of the key and of the ciphertext are inside the vector bytes at fixed
/// offsets, so a keygen or encapsulation regression in `libcrux-ml-kem` changes them and fails the
/// replay above. The last 32 bytes of each are the X25519 halves and are excluded.
#[test]
fn the_ml_kem_halves_are_pinned_by_the_x_wing_vectors() {
    for vector in &vectors() {
        let seed = seed_of(&field(vector, "seed"));
        let pair = pq::keygen(&seed).expect("keygen");
        let expected_pk = field(vector, "pk");
        assert_eq!(
            &pair.public[..pq::ML_KEM_PUBLIC_KEY_BYTES],
            &expected_pk[..pq::ML_KEM_PUBLIC_KEY_BYTES],
            "the ML-KEM-768 encapsulation key of the vector"
        );

        let mut randomness = [0u8; pq::ENCAPS_RANDOMNESS_BYTES];
        randomness.copy_from_slice(&field(vector, "eseed"));
        let (ciphertext, _) = pq::encapsulate_with(&pair.public, &randomness).expect("encaps");
        let expected_ct = field(vector, "ct");
        assert_eq!(
            &ciphertext[..pq::ML_KEM_CIPHERTEXT_BYTES],
            &expected_ct[..pq::ML_KEM_CIPHERTEXT_BYTES],
            "the ML-KEM-768 ciphertext of the vector"
        );

        // And the decapsulation reads that half: changing one of its bytes changes the secret,
        // which is ML-KEM's implicit rejection and not an error.
        let mut mutated = ciphertext.clone();
        mutated[7] ^= 1;
        let honest = pq::decapsulate(&seed, &ciphertext).expect("decaps");
        let rejected = pq::decapsulate(&seed, &mutated).expect("implicit rejection");
        assert_ne!(honest.as_bytes(), rejected.as_bytes());
    }
    assert_eq!(pq::ML_KEM_PUBLIC_KEY_BYTES, 1184);
    assert_eq!(pq::ML_KEM_CIPHERTEXT_BYTES, 1088);
}

/// A differential test against RustCrypto's independent implementation, on valid inputs.
#[test]
fn ghost_and_rust_crypto_agree_on_valid_inputs() {
    use x_wing::{Decapsulate, Decapsulator, KeyExport};

    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next_byte = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        (state & 0xff) as u8
    };
    for _ in 0..64 {
        let mut seed = [0u8; 32];
        for byte in seed.iter_mut() {
            *byte = next_byte();
        }
        let mut randomness = [0u8; pq::ENCAPS_RANDOMNESS_BYTES];
        for byte in randomness.iter_mut() {
            *byte = next_byte();
        }
        let secret = KemSecret::from_bytes(seed);
        let pair = pq::keygen(&secret).expect("keygen");

        let other_secret = x_wing::DecapsulationKey::from(seed);
        assert_eq!(
            pair.public.as_slice(),
            other_secret.encapsulation_key().to_bytes().as_slice()
        );

        let (ciphertext, shared) = pq::encapsulate_with(&pair.public, &randomness).expect("encaps");
        let (other_ct, other_ss) = other_secret
            .encapsulation_key()
            .encapsulate_deterministic(&randomness.into());
        assert_eq!(ciphertext.as_slice(), other_ct.as_slice());
        assert_eq!(shared.as_bytes().as_slice(), other_ss.as_slice());

        let opened = pq::decapsulate(&secret, &ciphertext).expect("decaps");
        assert_eq!(
            opened.as_bytes().as_slice(),
            other_secret.decapsulate(&other_ct).as_slice()
        );
    }
}

/// The documented difference (§22.8.2 rule 3): libcrux errors where `x-wing` returns a secret, and
/// GHOST must refuse those inputs before either implementation sees them.
#[test]
fn ghost_refuses_the_inputs_rust_crypto_accepts() {
    use x_wing::{Decapsulator, KeyExport};

    let secret = KemSecret::from_bytes([0x33; 32]);
    let pair = pq::keygen(&secret).expect("keygen");
    let randomness = [0x44u8; pq::ENCAPS_RANDOMNESS_BYTES];

    let mut low_order = [0u8; 32];
    low_order[0] = 0x01; // u = 1, an 8-torsion coordinate
    let mut bad = pair.public.clone();
    bad[pq::ML_KEM_PUBLIC_KEY_BYTES..].copy_from_slice(&low_order);

    assert_eq!(
        pq::validate_public_key(&bad).err(),
        Some(DmCode::InvalidKey)
    );
    assert_eq!(pq::encapsulate(&bad).err(), Some(DmCode::InvalidKey));

    // RustCrypto accepts the same key and returns a secret for it.
    let other = x_wing::EncapsulationKey::try_from(bad.as_slice()).expect("x-wing accepts");
    let (_, other_ss) = other.encapsulate_deterministic(&randomness.into());
    assert_eq!(other_ss.len(), pq::SHARED_SECRET_BYTES);

    // And the other way round: a valid key both accept.
    let good = x_wing::DecapsulationKey::from([0x33u8; 32]);
    assert_eq!(
        good.encapsulation_key().to_bytes().as_slice(),
        pair.public.as_slice()
    );
}
