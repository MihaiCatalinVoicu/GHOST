//! The chunk layer against a re-derivation written here from the text of §3.3 R-O2 (`aead-stream`
//! 0.6.0's `StreamBE32`: a 7-byte prefix, here zero, a big-endian 32-bit counter, one last-block
//! byte), calling ChaCha20-Poly1305 directly and no code of the crate's `stream` module; and against
//! the primitive's own known answers (RFC 8439 §2.8.2 in the unit tests). It stands in for the
//! `aead-stream` differential oracle of §15.2 item 1, which the S1 brief did not allow as a new
//! crate (§22.2): the S0 spike ran that oracle on the same layout (V-M8, 145 of 145 values).
#![allow(clippy::disallowed_methods)]

mod support;

use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, Tag};

use ghost_client_media::consts::{CHUNK_CT, CHUNK_PT};
use support::replay::{honest, specs};

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

#[test]
fn every_chunk_of_the_vector_objects_is_stream_be32() {
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
