//! RFC 9474 Appendix A (4096-bit, RSABSSA-SHA384-PSS-Randomized A.1 and -Deterministic A.3)
//! replayed through the generic raw functions and directly through the reference implementation
//! (Phase 8 design §2.9, §19.18).

mod common;

use blind_rsa_signatures::reexports::rsa::{BoxedUint, RsaPrivateKey};
use blind_rsa_signatures::{
    Deterministic, MessageRandomizer, Randomized, SecretKey, Sha384, Signature, PSS,
};
use ghost_blind_rsa::{
    blind_raw, check_blind_signature, emsa_pss_encode_sha384, finalize_raw, i2osp, mod_inv, verify,
    BigUint, Error, PublicKey,
};

fn vectors() -> Vec<common::Vector> {
    let v = common::section("rfc9474-a");
    assert_eq!(
        v.iter().map(|v| v.id.as_str()).collect::<Vec<_>>(),
        ["A.1", "A.3"]
    );
    v
}

#[test]
fn appendix_a_through_the_raw_functions() {
    for v in vectors() {
        let n = v.hex("n");
        assert_eq!(n.len(), 512, "RFC 9474 Appendix A uses a 4096-bit modulus");
        let pk = PublicKey::from_components(&n, &v.hex("e")).unwrap();
        assert_eq!(pk.modulus_bits(), 4096);

        // prepared_msg = msg_prefix || msg (the prefix is empty for the Deterministic variant).
        let prepared = v.hex("prepared_msg");
        assert_eq!(prepared, [v.hex("msg_prefix"), v.hex("msg")].concat());
        let salt: [u8; 48] = v.hex("salt").try_into().unwrap();

        let em = emsa_pss_encode_sha384(&prepared, &salt, pk.modulus_bits() - 1).unwrap();
        assert_eq!(em, v.hex("encoded_msg"), "{}: encoded_msg", v.id);

        let inv = BigUint::from_bytes_be(&v.hex("inv"));
        let r = mod_inv(&inv, pk.n()).unwrap();
        let (blinded, inv_out) = blind_raw(&pk, &em, &r).unwrap();
        assert_eq!(blinded, v.hex("blinded_msg"), "{}: blinded_msg", v.id);
        assert_eq!(inv_out, inv);

        let blind_sig = v.hex("blind_sig");
        assert!(check_blind_signature(&pk, &blinded, &blind_sig));
        // The vector's blind signature is blinded^d mod n (the private operation, computed here only
        // to pin the vector's internal consistency).
        let d = BigUint::from_bytes_be(&v.hex("d"));
        let s = BigUint::from_bytes_be(&blinded).modpow(&d, pk.n());
        assert_eq!(i2osp(&s, 512).unwrap(), blind_sig);

        let sig = finalize_raw(&pk, &prepared, &blind_sig, &inv).unwrap();
        assert_eq!(sig, v.hex("sig"), "{}: sig", v.id);
        verify(&pk, &prepared, &sig).unwrap();
    }
}

#[test]
fn appendix_a_negatives() {
    for v in vectors() {
        let pk = PublicKey::from_components(&v.hex("n"), &v.hex("e")).unwrap();
        let prepared = v.hex("prepared_msg");
        let sig = v.hex("sig");
        let blinded = v.hex("blinded_msg");
        let blind_sig = v.hex("blind_sig");
        let inv = BigUint::from_bytes_be(&v.hex("inv"));
        for i in [0, 100, sig.len() - 1] {
            let mut bad = sig.clone();
            bad[i] ^= 0x01;
            assert_eq!(verify(&pk, &prepared, &bad), Err(Error::Verification));
            let mut bad = blind_sig.clone();
            bad[i] ^= 0x01;
            assert!(!check_blind_signature(&pk, &blinded, &bad));
            assert!(finalize_raw(&pk, &prepared, &bad, &inv).is_err());
        }
        let mut msg = prepared.clone();
        msg[0] ^= 0x80;
        assert_eq!(verify(&pk, &msg, &sig), Err(Error::Verification));
        assert_eq!(verify(&pk, &prepared, &sig[1..]), Err(Error::BadLength));
        // B = 0, B = n and B > n are not blinded messages.
        let n = v.hex("n");
        assert!(!check_blind_signature(&pk, &[0u8; 512], &[0u8; 512]));
        assert!(!check_blind_signature(&pk, &n, &blind_sig));
        assert!(!check_blind_signature(&pk, &[0xff; 512], &blind_sig));
    }
}

fn boxed(bytes: &[u8]) -> BoxedUint {
    BoxedUint::from_be_slice_vartime(bytes)
}

#[test]
fn appendix_a_through_the_reference_implementation() {
    for v in vectors() {
        let key = RsaPrivateKey::from_components(
            boxed(&v.hex("n")),
            boxed(&v.hex("e")),
            boxed(&v.hex("d")),
            vec![boxed(&v.hex("p")), boxed(&v.hex("q"))],
        )
        .unwrap();
        let (blinded, msg, sig) = (v.hex("blinded_msg"), v.hex("msg"), Signature(v.hex("sig")));
        let blind_sig = match v.id.as_str() {
            "A.1" => {
                let sk = SecretKey::<Sha384, PSS, Randomized>::new(key);
                let prefix: [u8; 32] = v.hex("msg_prefix").try_into().unwrap();
                sk.public_key()
                    .unwrap()
                    .verify(&sig, Some(MessageRandomizer(prefix)), &msg)
                    .unwrap();
                sk.blind_sign(&blinded).unwrap()
            }
            _ => {
                let sk = SecretKey::<Sha384, PSS, Deterministic>::new(key);
                sk.public_key().unwrap().verify(&sig, None, &msg).unwrap();
                sk.blind_sign(&blinded).unwrap()
            }
        };
        assert_eq!(
            blind_sig.0,
            v.hex("blind_sig"),
            "{}: reference blind signature",
            v.id
        );
    }
}
