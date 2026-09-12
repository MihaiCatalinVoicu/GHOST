//! Differential test against the reference implementation, blind-rsa-signatures =0.17.2 (Phase 8
//! design §2.9): our blind with their sign, their blind with our finalize, every signature verified
//! by `ring` (inside `finalize_raw`/`verify`) and by the reference verifier. 10 000 random
//! (key, message) pairs over a pool of RSA-2048 keys; `GHOST_DIFFERENTIAL_PAIRS` overrides the count.

use blind_rsa_signatures::{DefaultRng, Deterministic, KeyPair, Sha384, Signature, PSS};
use ghost_blind_rsa::{
    blind_raw, check_blind_signature, emsa_pss_encode_sha384, finalize_raw, mod_inv, verify,
    BigUint, PublicKey, SALT_LEN,
};

type RefKeyPair = KeyPair<Sha384, PSS, Deterministic>;

const KEYS: usize = 4;
const DEFAULT_PAIRS: usize = 10_000;

fn random_r(pk: &PublicKey) -> BigUint {
    loop {
        let mut buf = vec![0u8; pk.modulus_len()];
        rand::fill(&mut buf[..]);
        let r = BigUint::from_bytes_be(&buf) % pk.n();
        if r.bits() > 1 && mod_inv(&r, pk.n()).is_some() {
            return r;
        }
    }
}

#[test]
fn differential_against_the_reference_implementation() {
    let pairs = std::env::var("GHOST_DIFFERENTIAL_PAIRS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_PAIRS);
    let keys: Vec<(RefKeyPair, PublicKey)> = (0..KEYS)
        .map(|_| {
            let kp = RefKeyPair::generate(&mut DefaultRng, 2048).unwrap();
            let c = kp.pk.components();
            let pk = PublicKey::from_components(&c.n(), &c.e()).unwrap();
            // Both implementations encode the same RSASSA-PSS SPKI (RFC 9578 §6.5).
            let spki = kp.pk.to_spki().unwrap();
            assert_eq!(pk.to_spki(), spki);
            assert_eq!(PublicKey::from_spki(&spki).unwrap(), pk);
            (kp, pk)
        })
        .collect();

    for i in 0..pairs {
        let (kp, pk) = &keys[i % KEYS];
        let mut msg = vec![0u8; usize::from(rand::random::<u8>())];
        rand::fill(&mut msg[..]);

        // Our blind, their blind signature, our finalize.
        let mut salt = [0u8; SALT_LEN];
        rand::fill(&mut salt[..]);
        let em = emsa_pss_encode_sha384(&msg, &salt, pk.modulus_bits() - 1).unwrap();
        let (blinded, inv) = blind_raw(pk, &em, &random_r(pk)).unwrap();
        let blind_sig = kp.sk.blind_sign(&blinded).unwrap();
        assert!(
            check_blind_signature(pk, &blinded, &blind_sig.0),
            "pair {i}"
        );
        let sig = finalize_raw(pk, &msg, &blind_sig.0, &inv).unwrap();
        kp.pk.verify(&Signature(sig), None, &msg).unwrap();

        // Their blind, their blind signature, our finalize (and theirs: both must agree).
        let blinding = kp.pk.blind(&mut DefaultRng, &msg).unwrap();
        let blind_sig = kp.sk.blind_sign(&blinding.blind_message).unwrap();
        assert!(
            check_blind_signature(pk, &blinding.blind_message.0, &blind_sig.0),
            "pair {i}"
        );
        let inv = BigUint::from_bytes_be(&blinding.secret.0);
        let ours = finalize_raw(pk, &msg, &blind_sig.0, &inv).unwrap();
        let theirs = kp.pk.finalize(&blind_sig, &blinding, &msg).unwrap();
        assert_eq!(ours, theirs.0, "pair {i}");
        verify(pk, &msg, &ours).unwrap();
    }
}
