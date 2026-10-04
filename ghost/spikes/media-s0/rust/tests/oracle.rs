//! V-M8: `aead-stream` 0.6.0 as the differential oracle of the chunk layer (design §3.3 R-O2,
//! §16.3), beside `chacha20poly1305` 0.11.0 on `aead` 0.6.1; plus the RFC 8439 and RFC 5869
//! vectors of the two primitives, which neither implementation of the format controls.

use aead_stream::{DecryptorBE32, EncryptorBE32, NewStream, StreamBE32, StreamPrimitive};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ghost_media_spike::format::*;
use ghost_media_spike::vectors::{build, cases};
use ghost_media_spike::{hex, unhex};

fn padded_chunks(content: &[u8], n: usize) -> Vec<Vec<u8>> {
    let mut p = content.to_vec();
    p.resize(n * CHUNK_PT, 0);
    p.chunks(CHUNK_PT).map(|c| c.to_vec()).collect()
}

#[test]
fn every_chunk_equals_aead_stream_be32() {
    for c in cases() {
        let b = build(&c);
        let keys = derive(&c.k_f, &c.object_id);
        let n = CLASSES[b.object.class_code as usize] / 4;
        let ad = chunk_ad(&c.object_id, c.kind);
        let chunks = padded_chunks(&b.content, n);
        let key = chacha20poly1305::Key::from(keys.k_p);
        let prefix =
            aead_stream::Nonce::<ChaCha20Poly1305, StreamBE32<ChaCha20Poly1305>>::from([0u8; 7]);
        // The stateless primitive, position by position.
        let stream = StreamBE32::<ChaCha20Poly1305>::new(&key, &prefix);
        for (i, pt) in chunks.iter().enumerate() {
            let last = i == n - 1;
            let ct = stream
                .encrypt(i as u32, last, Payload { msg: pt, aad: &ad })
                .expect("oracle");
            let ours: Vec<u8> = b.object.fragments[4 * i..4 * i + 4].concat();
            assert_eq!(ct, ours, "{} chunk {i}", c.name);
        }
        // The stateful encryptor: encrypt_next … encrypt_last.
        let mut enc = EncryptorBE32::<ChaCha20Poly1305>::new(&key, &prefix);
        let mut all = Vec::new();
        for pt in &chunks[..n - 1] {
            all.extend(
                enc.encrypt_next(Payload { msg: pt, aad: &ad })
                    .expect("next"),
            );
        }
        all.extend(
            enc.encrypt_last(Payload {
                msg: &chunks[n - 1],
                aad: &ad,
            })
            .expect("last"),
        );
        assert_eq!(all, b.object.fragments.concat(), "{}", c.name);
        // The decryptor opens our fragments; a prefix without the last flag does not verify as last.
        let mut dec = DecryptorBE32::<ChaCha20Poly1305>::new(&key, &prefix);
        for (i, chunk) in chunks.iter().enumerate().take(n - 1) {
            let ct: Vec<u8> = b.object.fragments[4 * i..4 * i + 4].concat();
            assert_eq!(
                dec.decrypt_next(Payload { msg: &ct, aad: &ad })
                    .expect("dec"),
                *chunk
            );
        }
        let last: Vec<u8> = b.object.fragments[4 * (n - 1)..].concat();
        assert_eq!(
            dec.decrypt_last(Payload {
                msg: &last,
                aad: &ad
            })
            .expect("dec last"),
            chunks[n - 1]
        );
        if n >= 2 {
            let first: Vec<u8> = b.object.fragments[..4].concat();
            let dec2 = DecryptorBE32::<ChaCha20Poly1305>::new(&key, &prefix);
            assert!(
                dec2.decrypt_last(Payload {
                    msg: &first,
                    aad: &ad
                })
                .is_err(),
                "truncation must not authenticate"
            );
        }
    }
}

#[test]
fn rfc8439_aead_vector() {
    // RFC 8439 §2.8.2.
    let key = unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
    let nonce = unhex("070000004041424344454647").unwrap();
    let aad = unhex("50515253c0c1c2c3c4c5c6c7").unwrap();
    let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let expected = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116\
1ae10b594f09e26a7e902ecbd0600691";
    let k: [u8; 32] = key.try_into().unwrap();
    let cipher = ChaCha20Poly1305::new(&k.into());
    let ct = cipher
        .encrypt(
            &Nonce::try_from(nonce.as_slice()).unwrap(),
            Payload { msg: pt, aad: &aad },
        )
        .unwrap();
    assert_eq!(hex(&ct), expected);
}

#[test]
fn rfc5869_hkdf_vector() {
    // RFC 5869 A.1.
    use hkdf::Hkdf;
    use sha2::Sha256;
    let ikm = [0x0bu8; 22];
    let salt = unhex("000102030405060708090a0b0c").unwrap();
    let info = unhex("f0f1f2f3f4f5f6f7f8f9").unwrap();
    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut okm = [0u8; 42];
    hk.expand(&info, &mut okm).unwrap();
    assert_eq!(
        hex(&okm),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );
}
