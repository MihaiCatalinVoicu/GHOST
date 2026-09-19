//! V-14 (Rust half): Ed25519 vectors for the Kotlin/JDK and Rust equivalence check (design §2.4,
//! X-21, R-37). `ed25519-dalek` 2.2.0 signs deterministic seeds and messages and records its
//! strict and legacy verification results on edge cases built with `curve25519-dalek` 4.1.3:
//! non-canonical scalars and encodings, small-order and mixed-order keys and nonces.
//!
//! The vector file `vectors/ed25519-v14.txt` is generated deterministically; this test fails if
//! the committed file differs (delete it to regenerate). `jvm/Ed25519Equivalence.java` replays it
//! with BouncyCastle through the exact `Ed25519KeyPair` code path of `:identity`.

use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2_10::{Digest, Sha256, Sha512};
use std::fmt::Write as _;

const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

fn h256(label: &str, i: u32) -> [u8; 32] {
    Sha256::new()
        .chain_update(label)
        .chain_update(i.to_be_bytes())
        .finalize()
        .into()
}

fn k(r: &[u8; 32], a: &[u8; 32], m: &[u8]) -> Scalar {
    let hash: [u8; 64] = Sha512::new()
        .chain_update(r)
        .chain_update(a)
        .chain_update(m)
        .finalize()
        .into();
    Scalar::from_bytes_mod_order_wide(&hash)
}

/// The expanded secret of a seed: (clamped scalar a, nonce prefix).
fn expand(seed: &[u8; 32]) -> (Scalar, [u8; 32]) {
    let h: [u8; 64] = Sha512::digest(seed).into();
    let mut a = [0u8; 32];
    a.copy_from_slice(&h[..32]);
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;
    let mut prefix = [0u8; 32];
    prefix.copy_from_slice(&h[32..]);
    (Scalar::from_bytes_mod_order(a), prefix)
}

fn add_le(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in 0..32 {
        let s = u16::from(a[i]) + u16::from(b[i]) + carry;
        out[i] = s as u8;
        carry = s >> 8;
    }
    (carry == 0).then_some(out)
}

fn dalek(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> (bool, bool) {
    let Ok(key) = VerifyingKey::from_bytes(pk) else {
        return (false, false);
    };
    let signature = Signature::from_bytes(sig);
    (
        key.verify_strict(msg, &signature).is_ok(),
        ed25519_dalek::Verifier::verify(&key, msg, &signature).is_ok(),
    )
}

struct Out(String);

impl Out {
    fn verify(&mut self, name: &str, pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) {
        let (strict, legacy) = dalek(pk, msg, sig);
        writeln!(
            self.0,
            "verify {name} {} {} {} {} {}",
            hex::encode(pk),
            if msg.is_empty() {
                "-".to_owned()
            } else {
                hex::encode(msg)
            },
            hex::encode(sig),
            u8::from(strict),
            u8::from(legacy)
        )
        .expect("write");
    }
}

fn signature(r: &[u8; 32], s: &[u8; 32]) -> [u8; 64] {
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(r);
    sig[32..].copy_from_slice(s);
    sig
}

fn generate() -> String {
    let mut out = Out(String::from(
        "# V-14 Ed25519 vectors (ghost-dm-spike, ed25519-dalek 2.2.0, curve25519-dalek 4.1.3).\n\
         # sign <seed> <message|-> <public key> <signature>\n\
         # verify <case> <public key> <message|-> <signature> <dalek verify_strict> <dalek verify>\n",
    ));
    for i in 0..64u32 {
        let seed = h256("ghost/v14/seed", i);
        let msg_full = h256("ghost/v14/message", i);
        let len = (i as usize * 7) % 33;
        let msg: Vec<u8> = msg_full.iter().copied().cycle().take(len * 3).collect();
        let key = SigningKey::from_bytes(&seed);
        let sig = key.sign(&msg).to_bytes();
        writeln!(
            out.0,
            "sign {} {} {} {}",
            hex::encode(seed),
            if msg.is_empty() {
                "-".to_owned()
            } else {
                hex::encode(&msg)
            },
            hex::encode(key.verifying_key().to_bytes()),
            hex::encode(sig)
        )
        .expect("write");
    }

    let seed = h256("ghost/v14/edge-seed", 0);
    let (a, prefix) = expand(&seed);
    let a_point = ED25519_BASEPOINT_POINT * a;
    let a_bytes = a_point.compress().to_bytes();
    let msg = b"ghost v14 edge case".to_vec();
    let sign_with =
        |r_point: EdwardsPoint, a_enc: &[u8; 32], secret: Scalar, r_scalar: Scalar, m: &[u8]| {
            let r_enc = r_point.compress().to_bytes();
            let s = r_scalar + k(&r_enc, a_enc, m) * secret;
            signature(&r_enc, &s.to_bytes())
        };
    let r_scalar = {
        let h: [u8; 64] = Sha512::new()
            .chain_update(prefix)
            .chain_update(&msg)
            .finalize()
            .into();
        Scalar::from_bytes_mod_order_wide(&h)
    };
    let valid = sign_with(
        ED25519_BASEPOINT_POINT * r_scalar,
        &a_bytes,
        a,
        r_scalar,
        &msg,
    );
    out.verify("valid", &a_bytes, &msg, &valid);
    let mut tampered = msg.clone();
    tampered[0] ^= 1;
    out.verify("wrong-message", &a_bytes, &tampered, &valid);

    // S + L and S + 2L: non-canonical scalars (malleability).
    let mut s = [0u8; 32];
    s.copy_from_slice(&valid[32..]);
    let mut r = [0u8; 32];
    r.copy_from_slice(&valid[..32]);
    if let Some(s1) = add_le(&s, &L) {
        out.verify("s-plus-l", &a_bytes, &msg, &signature(&r, &s1));
        if let Some(s2) = add_le(&s1, &L) {
            out.verify("s-plus-2l", &a_bytes, &msg, &signature(&r, &s2));
        }
    }
    let mut s_top = s;
    s_top[31] |= 0x80;
    out.verify("s-high-bit", &a_bytes, &msg, &signature(&r, &s_top));

    // Small-order public keys: with A of small order, (R = S·B, S) verifies (cofactorless and
    // cofactored) for any message when k·A = identity; the identity makes that always true.
    let identity = EdwardsPoint::default();
    let s_any = Scalar::from_bytes_mod_order(h256("ghost/v14/s", 1));
    for (j, t) in EIGHT_TORSION.iter().enumerate() {
        let t_enc = t.compress().to_bytes();
        let r_enc = (ED25519_BASEPOINT_POINT * s_any
            - *t * k(
                &(ED25519_BASEPOINT_POINT * s_any).compress().to_bytes(),
                &t_enc,
                &msg,
            ))
        .compress()
        .to_bytes();
        out.verify(
            &format!("small-order-a-{j}"),
            &t_enc,
            &msg,
            &signature(&r_enc, &s_any.to_bytes()),
        );
    }
    // The identity public key in a non-canonical encoding (y = p + 1) and with the sign bit set.
    let mut identity_noncanonical = [0xffu8; 32];
    identity_noncanonical[0] = 0xee;
    identity_noncanonical[31] = 0x7f;
    let mut identity_signbit = identity.compress().to_bytes();
    identity_signbit[31] |= 0x80;
    for (name, enc) in [
        ("noncanonical-identity-a", identity_noncanonical),
        ("signbit-identity-a", identity_signbit),
    ] {
        let r_enc = (ED25519_BASEPOINT_POINT * s_any).compress().to_bytes();
        out.verify(name, &enc, &msg, &signature(&r_enc, &s_any.to_bytes()));
    }

    // Mixed-order public keys A' = a·B + T with an honest signature under a: cofactored
    // verification accepts, cofactorless accepts only when k·T = identity.
    for (j, t) in EIGHT_TORSION.iter().enumerate().skip(1) {
        let a_mixed = (a_point + *t).compress().to_bytes();
        for variant in 0..3u8 {
            let mut m = msg.clone();
            m.push(variant);
            let sig = sign_with(
                ED25519_BASEPOINT_POINT * r_scalar,
                &a_mixed,
                a,
                r_scalar,
                &m,
            );
            out.verify(&format!("mixed-order-a-{j}-{variant}"), &a_mixed, &m, &sig);
        }
    }
    // Mixed-order nonces R' = r·B + T.
    for (j, t) in EIGHT_TORSION.iter().enumerate().skip(1) {
        let sig = sign_with(
            ED25519_BASEPOINT_POINT * r_scalar + *t,
            &a_bytes,
            a,
            r_scalar,
            &msg,
        );
        out.verify(&format!("mixed-order-r-{j}"), &a_bytes, &msg, &sig);
    }
    // Small-order nonce R = T with S = k·a (S·B = k·A, so R + k·A = T + S·B).
    for (j, t) in EIGHT_TORSION.iter().enumerate() {
        let t_enc = t.compress().to_bytes();
        let s_small = k(&t_enc, &a_bytes, &msg) * a;
        out.verify(
            &format!("small-order-r-{j}"),
            &a_bytes,
            &msg,
            &signature(&t_enc, &s_small.to_bytes()),
        );
    }
    // R = identity in the non-canonical encoding.
    let s_id = k(&identity_noncanonical, &a_bytes, &msg) * a;
    out.verify(
        "noncanonical-identity-r",
        &a_bytes,
        &msg,
        &signature(&identity_noncanonical, &s_id.to_bytes()),
    );
    // A public key that does not decode (y not on the curve): try y = 2.
    let mut off_curve = [0u8; 32];
    off_curve[0] = 2;
    if CompressedEdwardsY(off_curve).decompress().is_none() {
        out.verify("off-curve-a", &off_curve, &msg, &valid);
    }
    out.0
}

#[test]
fn v14_vectors_are_current() {
    let generated = generate();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("vectors")
        .join("ed25519-v14.txt");
    match std::fs::read_to_string(&path) {
        Ok(committed) => assert_eq!(
            committed.replace("\r\n", "\n"),
            generated,
            "vectors changed; delete the file to regenerate"
        ),
        Err(_) => std::fs::write(&path, &generated).expect("write vectors"),
    }
    // Every `sign` line re-verifies strictly in Rust, so a bump of ed25519-dalek that changes
    // signing fails here and not only through the BouncyCastle comparison of the JVM half.
    let mut signed = 0;
    for line in generated.lines().filter(|l| l.starts_with("sign ")) {
        let field: Vec<&str> = line.split(' ').collect();
        assert_eq!(field.len(), 5, "sign line shape: {line}");
        let message = if field[2] == "-" {
            Vec::new()
        } else {
            hex::decode(field[2]).expect("message hex")
        };
        let public: [u8; 32] = hex::decode(field[3])
            .expect("public key hex")
            .try_into()
            .expect("32-byte public key");
        let signature: [u8; 64] = hex::decode(field[4])
            .expect("signature hex")
            .try_into()
            .expect("64-byte signature");
        VerifyingKey::from_bytes(&public)
            .expect("public key on the curve")
            .verify_strict(&message, &Signature::from_bytes(&signature))
            .expect("the recorded signature verifies strictly");
        signed += 1;
    }
    assert_eq!(signed, 64);
}
