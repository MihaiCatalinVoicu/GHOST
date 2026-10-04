//! The chunk layer (design §3.3): STREAM over ChaCha20-Poly1305 in exactly `aead-stream` 0.6.0's
//! `StreamBE32` layout with a zero prefix (R-O2):
//!
//! ```text
//! nonce_i = 0x00^7 || u32_be(i) || u8(last_i)          last_i = 0x01 iff i = n − 1
//! AD_c    = "ghost/v1/media/ad/chunk" || 0x01 || object_id(16) || u8(kind)
//! C_i     = ChaCha20-Poly1305(K_p, nonce_i, AD_c, P_i)  |P_i| = CHUNK_PT, |C_i| = CHUNK_CT
//! ```
//!
//! A fragment is a headerless 64 KiB slice of a chunk's ciphertext (R-O1): fragment `4i + k` is
//! `C_i[k·FRAG .. (k+1)·FRAG]`.

use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, Tag};
use zeroize::Zeroizing;

use crate::consts::{MediaKind, CHUNK_CT, CHUNK_PT, TAG};
use crate::error::{Code, MediaError, MediaResult};
use crate::keys::{ObjectId, PayloadKey};
use crate::labels;

/// The ChaCha20-Poly1305 nonce length.
pub const NONCE_BYTES: usize = 12;

/// `nonce_i` (§3.3).
pub fn chunk_nonce(index: u32, last: bool) -> [u8; NONCE_BYTES] {
    let mut n = [0u8; NONCE_BYTES];
    let i = index.to_be_bytes();
    for (dst, src) in n.iter_mut().skip(7).zip(i.iter()) {
        *dst = *src;
    }
    if let Some(l) = n.last_mut() {
        *l = u8::from(last);
    }
    n
}

/// `AD_c` (§3.3).
pub fn chunk_ad(object_id: &ObjectId, kind: MediaKind) -> Vec<u8> {
    let mut ad = Vec::with_capacity(labels::AD_CHUNK.len().saturating_add(18));
    ad.extend_from_slice(labels::AD_CHUNK.as_bytes());
    ad.push(labels::AD_VERSION);
    ad.extend_from_slice(object_id.as_bytes());
    ad.push(kind.byte());
    ad
}

/// Seals one chunk: `plaintext` is at most `CHUNK_PT` bytes and is zero padded to `CHUNK_PT`; the
/// result is the chunk's `CHUNK_CT` bytes (its four fragments in order).
pub(crate) fn seal_chunk(
    key: &PayloadKey,
    ad: &[u8],
    index: u32,
    last: bool,
    plaintext: &[u8],
) -> MediaResult<Vec<u8>> {
    if plaintext.len() > CHUNK_PT {
        return Err(MediaError::new(
            Code::Oversize,
            "a chunk holds CHUNK_PT bytes",
        ));
    }
    let nonce = chunk_nonce(index, last);
    #[cfg(any(test, feature = "nonce-registry"))]
    crate::registry::record_padded(key.as_bytes(), &nonce, ad, plaintext, CHUNK_PT);
    // Plaintext until it is encrypted in place: wiped if a refusal drops it, moved out once sealed.
    let mut out = Zeroizing::new(vec![0u8; CHUNK_CT]);
    let (body, tag_out) = out.split_at_mut(CHUNK_PT);
    for (dst, src) in body.iter_mut().zip(plaintext.iter()) {
        *dst = *src;
    }
    let cipher = ChaCha20Poly1305::new(key.as_bytes().into());
    let tag = cipher
        .encrypt_inout_detached(&Nonce::from(nonce), ad, body.into())
        .map_err(|_| MediaError::new(Code::Oversize, "ChaCha20-Poly1305 refused the chunk"))?;
    tag_out.copy_from_slice(tag.as_slice());
    Ok(core::mem::take(&mut *out))
}

/// Opens one chunk's `CHUNK_CT` bytes into a zeroising buffer of `CHUNK_PT` bytes; `NOT_OPEN` when
/// the tag does not verify (nothing is decrypted then).
pub(crate) fn open_chunk(
    key: &PayloadKey,
    ad: &[u8],
    index: u32,
    last: bool,
    ciphertext: &[u8],
) -> MediaResult<Zeroizing<Vec<u8>>> {
    if ciphertext.len() != CHUNK_CT {
        return Err(MediaError::new(
            Code::HashMismatch,
            "a chunk is four 64 KiB fragments",
        ));
    }
    let (body, tag) = ciphertext.split_at(CHUNK_PT);
    let mut tag_bytes = [0u8; TAG];
    tag_bytes.copy_from_slice(tag);
    let mut buf = Zeroizing::new(body.to_vec());
    let cipher = ChaCha20Poly1305::new(key.as_bytes().into());
    cipher
        .decrypt_inout_detached(
            &Nonce::from(chunk_nonce(index, last)),
            ad,
            buf.as_mut_slice().into(),
            &Tag::from(tag_bytes),
        )
        .map_err(|_| MediaError::new(Code::NotOpen, "the chunk's tag does not verify"))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_nonce_layout_is_stream_be32() {
        assert_eq!(
            hex::encode(chunk_nonce(0, false)),
            "000000000000000000000000"
        );
        assert_eq!(
            hex::encode(chunk_nonce(3, true)),
            "000000000000000000000301"
        );
        assert_eq!(
            hex::encode(chunk_nonce(200, true)),
            "00000000000000000000c801"
        );
        assert_eq!(
            hex::encode(chunk_nonce(0x0102_0304, false)),
            "000000000000000102030400"
        );
    }

    #[test]
    fn rfc8439_section_2_8_2_through_the_same_primitive() {
        // The AEAD test vector of RFC 8439 §2.8.2: the primitive this module calls, checked with
        // values neither GHOST implementation chose.
        let key: Vec<u8> = (0x80u8..=0x9f).collect();
        let nonce = hex::decode("070000004041424344454647").expect("hex");
        let ad = hex::decode("50515253c0c1c2c3c4c5c6c7").expect("hex");
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let mut buf = pt.to_vec();
        let k: [u8; 32] = key.as_slice().try_into().expect("32");
        let n: [u8; 12] = nonce.as_slice().try_into().expect("12");
        let tag = ChaCha20Poly1305::new(&k.into())
            .encrypt_inout_detached(&Nonce::from(n), &ad, buf.as_mut_slice().into())
            .expect("seal");
        assert_eq!(
            hex::encode(tag.as_slice()),
            "1ae10b594f09e26a7e902ecbd0600691"
        );
        assert_eq!(hex::encode(&buf[..16]), "d31a8d34648e60db7b86afbc53ef7ec2");
    }

    #[test]
    fn a_chunk_round_trips_and_binds_index_last_and_ad() {
        let key = PayloadKey::from_bytes([9; 32]);
        let ad = chunk_ad(&ObjectId::from_bytes([1; 16]), MediaKind::Video);
        let ct = seal_chunk(&key, &ad, 5, false, b"hello").expect("seal");
        assert_eq!(ct.len(), CHUNK_CT);
        let pt = open_chunk(&key, &ad, 5, false, &ct).expect("open");
        assert_eq!(&pt[..5], b"hello");
        assert!(pt[5..].iter().all(|b| *b == 0));
        for (i, last) in [(4, false), (5, true), (6, false)] {
            let e = open_chunk(&key, &ad, i, last, &ct).expect_err("binding");
            assert_eq!(e.code(), Code::NotOpen);
        }
        let other = chunk_ad(&ObjectId::from_bytes([1; 16]), MediaKind::Image);
        assert_eq!(
            open_chunk(&key, &other, 5, false, &ct)
                .expect_err("kind")
                .code(),
            Code::NotOpen
        );
    }
}
