//! The chunk layer against two references (design §3.3 R-O2, §3.9, §15.2 item 1, §16.3; ADR-44
//! point 10):
//!
//! - **the differential oracle**, RustCrypto's `aead-stream` 0.6.0 (`StreamBE32`: a 7-byte prefix,
//!   here zero, a big-endian 32-bit counter, one last-block byte) over `chacha20poly1305` 0.11.0, in
//!   the dev graph only, as the S0 spike ran it (V-M8, 145 of 145 values): its stateless primitive
//!   position by position, its stateful encryptor and decryptor over whole objects, and its refusal
//!   of a truncated object, for the three vector objects and for seeded objects of every kind and
//!   of classes 0 to 2 sealed in random pieces (`GHOST_MEDIA_ORACLE_OBJECTS`, default 24);
//! - a re-derivation written here from the text of §3.3, calling ChaCha20-Poly1305 directly and no
//!   code of the crate's `stream` module, with the primitive's own known answers (RFC 8439 §2.8.2
//!   in the unit tests).
//!
//! Neither reads the crate's `AD_c`, nonce or padding: each builds them from §3.3's text.
#![allow(clippy::disallowed_methods)]

mod support;

use aead_stream::{DecryptorBE32, EncryptorBE32, NewStream, StreamBE32, StreamPrimitive};
use chacha20poly1305::aead::{AeadInOut, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce, Tag};

use ghost_client_media::consts::{CHUNK_CT, CHUNK_PT};
use ghost_client_media::keys::derive;
use ghost_client_media::{FileKey, MediaKind, ObjectId, Sealer, SizeClass};
use support::replay::{honest, specs};
use support::*;

/// StreamBE32 with a zero prefix: `0^7 || be32(i) || last`.
fn stream_be32_nonce(i: u32, last: bool) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[7..11].copy_from_slice(&i.to_be_bytes());
    n[11] = last as u8;
    n
}

/// AD_c from §3.3's text.
fn ad(object_id: &[u8; 16], kind: u8) -> Vec<u8> {
    let mut v = b"ghost/v1/media/ad/chunk".to_vec();
    v.push(1);
    v.extend_from_slice(object_id);
    v.push(kind);
    v
}

/// `content || 0x00^(n·CHUNK_PT − |content|)` cut into its `n` chunks (§3.3).
fn padded_chunks(content: &[u8], n: usize) -> Vec<Vec<u8>> {
    let mut p = content.to_vec();
    p.resize(n * CHUNK_PT, 0);
    p.chunks(CHUNK_PT).map(|c| c.to_vec()).collect()
}

/// Checks one sealed object's chunks against `aead-stream`: every position through the stateless
/// primitive, the whole object through the stateful encryptor and decryptor, and a truncation.
/// Returns how many chunks were compared.
fn agrees_with_aead_stream(
    name: &str,
    k_p: &[u8; 32],
    object_id: &[u8; 16],
    kind: u8,
    content: &[u8],
    chunks: &[Vec<u8>],
) -> usize {
    let n = chunks.len();
    let plaintexts = padded_chunks(content, n);
    let aad = ad(object_id, kind);
    let key = Key::from(*k_p);
    let prefix =
        aead_stream::Nonce::<ChaCha20Poly1305, StreamBE32<ChaCha20Poly1305>>::from([0u8; 7]);
    let stream = StreamBE32::<ChaCha20Poly1305>::new(&key, &prefix);
    for (i, pt) in plaintexts.iter().enumerate() {
        let ct = stream
            .encrypt(i as u32, i + 1 == n, Payload { msg: pt, aad: &aad })
            .expect("oracle");
        assert_eq!(&ct, &chunks[i], "{name} chunk {i}: the oracle's chunk");
        assert_eq!(ct.len(), CHUNK_CT);
    }
    let mut enc = EncryptorBE32::<ChaCha20Poly1305>::new(&key, &prefix);
    let mut all = Vec::new();
    for pt in &plaintexts[..n - 1] {
        all.extend(
            enc.encrypt_next(Payload { msg: pt, aad: &aad })
                .expect("next"),
        );
    }
    all.extend(
        enc.encrypt_last(Payload {
            msg: &plaintexts[n - 1],
            aad: &aad,
        })
        .expect("last"),
    );
    assert!(all == chunks.concat(), "{name}: the oracle's stream");
    let mut dec = DecryptorBE32::<ChaCha20Poly1305>::new(&key, &prefix);
    for (i, pt) in plaintexts.iter().enumerate().take(n - 1) {
        let back = dec
            .decrypt_next(Payload {
                msg: &chunks[i],
                aad: &aad,
            })
            .expect("the oracle opens the crate's chunk");
        assert!(&back == pt, "{name} chunk {i}: the oracle's plaintext");
    }
    let back = dec
        .decrypt_last(Payload {
            msg: &chunks[n - 1],
            aad: &aad,
        })
        .expect("the oracle opens the crate's last chunk");
    assert!(
        back == plaintexts[n - 1],
        "{name}: the oracle's last plaintext"
    );
    // A prefix of an object never authenticates as complete: chunk 0 as the last one fails.
    let dec = DecryptorBE32::<ChaCha20Poly1305>::new(&key, &prefix);
    assert!(
        dec.decrypt_last(Payload {
            msg: &chunks[0],
            aad: &aad,
        })
        .is_err(),
        "{name}: truncation authenticated"
    );
    n
}

#[test]
fn every_chunk_of_the_vector_objects_equals_aead_stream() {
    let mut compared = 0;
    for spec in specs() {
        let o = honest(&spec);
        compared += agrees_with_aead_stream(
            spec.name,
            o.derived.payload.as_bytes(),
            &spec.object_id,
            spec.kind.byte(),
            &o.content,
            &o.chunks,
        );
    }
    assert_eq!(compared, 4 + 4 + 9);
}

#[test]
fn seeded_objects_agree_with_aead_stream() {
    let objects: usize = std::env::var("GHOST_MEDIA_ORACLE_OBJECTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(24);
    let mut rng = Seeded::new(0x0a5e_0dac_1e00_0006);
    let (mut compared, mut classes) = (0, [0usize; 3]);
    for trial in 0..objects {
        let (kind, content) = match trial % 3 {
            0 => (
                MediaKind::Image,
                jpeg_of_len(1024, 768, 2_000 + rng.below(1_040_000)),
            ),
            1 => (MediaKind::Video, fmp4_of_len(120_000 + rng.below(900_000))),
            _ => (
                MediaKind::Video,
                fmp4_of_len(1_048_600 + rng.below(1_300_000)),
            ),
        };
        let input = match kind {
            MediaKind::Image => content.clone(),
            MediaKind::Video => without_mfra(&content),
        };
        let key = FileKey::from_bytes(rng.key32());
        let id = rng.id16();
        let k_p = *derive(&key, &ObjectId::from_bytes(id)).payload.as_bytes();
        let mut sealer = Sealer::begin(
            key,
            ObjectId::from_bytes(id),
            kind,
            false,
            SizeClass::LARGEST,
        );
        let mut chunks = Vec::new();
        let mut at = 0;
        while at < input.len() {
            let piece = (1 + rng.below(400_000)).min(input.len() - at);
            chunks.extend(sealer.append(&input[at..at + piece]).expect("append"));
            at += piece;
        }
        let sealed = sealer.finish(&[]).expect("finish");
        chunks.extend(sealed.chunks.iter().cloned());
        classes[usize::from(sealed.manifest.fields.class.code()).min(2)] += 1;
        let ciphertexts: Vec<Vec<u8>> = chunks.into_iter().map(|c| c.ciphertext).collect();
        compared += agrees_with_aead_stream(
            &format!("seeded object {trial}"),
            &k_p,
            &id,
            kind.byte(),
            &content,
            &ciphertexts,
        );
    }
    eprintln!(
        "aead-stream oracle: {objects} seeded objects, {compared} chunks, classes {classes:?}"
    );
    assert!(
        classes.iter().all(|c| *c > 0),
        "classes 0, 1 and 2: {classes:?}"
    );
}

#[test]
fn every_chunk_of_the_vector_objects_is_the_texts_stream_be32() {
    let mut chunks = 0;
    for spec in specs() {
        let o = honest(&spec);
        let n = o.chunks.len() as u32;
        let cipher = ChaCha20Poly1305::new(o.derived.payload.as_bytes().into());
        for (i, ct) in o.chunks.iter().enumerate() {
            let i = i as u32;
            // Encrypting the plaintext gives the crate's chunk byte for byte.
            let mut buf = o.plaintexts[i as usize].clone();
            assert_eq!(buf.len(), CHUNK_PT);
            let tag = cipher
                .encrypt_inout_detached(
                    &Nonce::from(stream_be32_nonce(i, i + 1 == n)),
                    &ad(&spec.object_id, spec.kind.byte()),
                    buf.as_mut_slice().into(),
                )
                .expect("seal");
            buf.extend_from_slice(tag.as_slice());
            assert_eq!(&buf, ct, "{} chunk {i}", spec.name);
            // Decryption refuses the chunk under the other last flag (a prefix is never complete).
            let (body, t) = ct.split_at(CHUNK_PT);
            let mut b = body.to_vec();
            let tag: [u8; 16] = t.try_into().expect("16");
            assert!(cipher
                .decrypt_inout_detached(
                    &Nonce::from(stream_be32_nonce(i, i + 1 != n)),
                    &ad(&spec.object_id, spec.kind.byte()),
                    b.as_mut_slice().into(),
                    &Tag::from(tag),
                )
                .is_err());
            assert_eq!(ct.len(), CHUNK_CT);
            chunks += 1;
        }
    }
    assert_eq!(chunks, 4 + 4 + 9);
}
