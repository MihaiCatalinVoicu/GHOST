//! Padding framing for bucketed blobs (FR-2.5, ADR-09).
//!
//! The frame is `len(4, big-endian) || payload || zeros`. It MUST be applied to the plaintext
//! *before* authenticated encryption, never to the ciphertext: a cleartext length prefix and a
//! trailing zero run would hand every relay the exact payload size, defeating the padding
//! control. The encrypting layer (messaging/media, later phases) therefore calls
//! [`pad_plaintext`] with its AEAD overhead so that `frame + overhead` is exactly a bucket size,
//! encrypts the frame, and hands the resulting bucket-sized ciphertext to the relay client.
//! Relays refuse anything that is not exactly bucket-sized, so the only sizes observable on the
//! wire or in storage are the four bucket sizes, and the bytes they see are indistinguishable
//! from random. Onion-service ingress and relay-to-relay Noise sessions are configured at
//! deployment level (infra/), not here.

use ghost_relay_api::{padding_bucket, PADDING_BUCKETS};

const LEN_PREFIX: usize = 4;

/// Smallest accepted AEAD overhead: a 16-byte authentication tag. An overhead below this means
/// the frame is not being encrypted with an AEAD, and a bucket-sized frame sent as is would expose
/// its cleartext length prefix and zero run to the relay.
pub const MIN_AEAD_OVERHEAD: usize = 16;

#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    /// Payload plus prefix and AEAD overhead does not fit in the largest bucket; fragment first.
    TooLarge,
    /// Frame length is not `bucket - overhead`, or the prefix is inconsistent with it.
    Malformed,
    /// `aead_overhead` is below [`MIN_AEAD_OVERHEAD`]: the frame would not be AEAD-encrypted.
    NotEncrypted,
}

/// Builds the plaintext frame for `payload` so that `frame.len() + aead_overhead` equals the
/// smallest bucket that fits. Encrypt the returned frame; do not send it as is.
pub fn pad_plaintext(payload: &[u8], aead_overhead: usize) -> Result<Vec<u8>, FrameError> {
    if aead_overhead < MIN_AEAD_OVERHEAD {
        return Err(FrameError::NotEncrypted);
    }
    let needed = payload
        .len()
        .checked_add(LEN_PREFIX)
        .and_then(|n| n.checked_add(aead_overhead))
        .ok_or(FrameError::TooLarge)?;
    let bucket = padding_bucket(needed).ok_or(FrameError::TooLarge)?;
    let mut out = vec![0u8; bucket - aead_overhead];
    out[..LEN_PREFIX].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    out[LEN_PREFIX..LEN_PREFIX + payload.len()].copy_from_slice(payload);
    Ok(out)
}

/// Inverse of [`pad_plaintext`], applied to the *decrypted* frame. Rejects frames whose length is
/// not `bucket - aead_overhead`, whose declared length does not fit, or whose padding is not
/// all-zero (a single canonical frame per payload).
pub fn unpad_plaintext(frame: &[u8], aead_overhead: usize) -> Result<&[u8], FrameError> {
    if aead_overhead < MIN_AEAD_OVERHEAD {
        return Err(FrameError::NotEncrypted);
    }
    if !PADDING_BUCKETS
        .iter()
        .any(|&b| b > aead_overhead && b - aead_overhead == frame.len())
        || frame.len() < LEN_PREFIX
    {
        return Err(FrameError::Malformed);
    }
    let len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    if len > frame.len() - LEN_PREFIX {
        return Err(FrameError::Malformed);
    }
    if frame[LEN_PREFIX + len..].iter().any(|&b| b != 0) {
        return Err(FrameError::Malformed);
    }
    Ok(&frame[LEN_PREFIX..LEN_PREFIX + len])
}

/// Largest payload that fits in a single blob for a given AEAD overhead (0 if nothing fits).
pub fn max_payload_bytes(aead_overhead: usize) -> usize {
    PADDING_BUCKETS[PADDING_BUCKETS.len() - 1]
        .saturating_sub(LEN_PREFIX)
        .saturating_sub(aead_overhead)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_relay_api::is_bucket_size;

    // e.g. a 24-byte nonce + 16-byte tag
    const OVERHEAD: usize = 40;

    #[test]
    fn frame_plus_overhead_is_always_a_bucket() {
        for len in [
            0usize,
            1,
            979,
            980,
            981,
            4_000,
            16_000,
            60_000,
            max_payload_bytes(OVERHEAD),
        ] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let frame = pad_plaintext(&payload, OVERHEAD).unwrap();
            assert!(
                is_bucket_size(frame.len() + OVERHEAD),
                "len {len} -> frame {}",
                frame.len()
            );
            assert_eq!(unpad_plaintext(&frame, OVERHEAD).unwrap(), &payload[..]);
        }
        // The minimum overhead (a bare 16-byte tag) works too.
        let frame = pad_plaintext(b"x", MIN_AEAD_OVERHEAD).unwrap();
        assert!(is_bucket_size(frame.len() + MIN_AEAD_OVERHEAD));
    }

    #[test]
    fn oversize_and_malformed_are_rejected() {
        assert_eq!(
            pad_plaintext(&vec![0u8; max_payload_bytes(OVERHEAD) + 1], OVERHEAD),
            Err(FrameError::TooLarge)
        );
        assert_eq!(pad_plaintext(b"x", usize::MAX), Err(FrameError::TooLarge));
        assert_eq!(max_payload_bytes(usize::MAX), 0);
        // No AEAD (overhead 0) or a truncated tag: the frame would reach the relay unencrypted.
        for overhead in [0, 1, MIN_AEAD_OVERHEAD - 1] {
            assert_eq!(pad_plaintext(b"x", overhead), Err(FrameError::NotEncrypted));
            assert_eq!(
                unpad_plaintext(&[0u8; 1_024], overhead),
                Err(FrameError::NotEncrypted)
            );
        }
        assert_eq!(
            unpad_plaintext(&[0u8; 1_000], OVERHEAD),
            Err(FrameError::Malformed)
        );
        let mut p = pad_plaintext(b"hi", OVERHEAD).unwrap();
        p[0] = 0xff; // declared length larger than frame
        assert_eq!(unpad_plaintext(&p, OVERHEAD), Err(FrameError::Malformed));
        let mut q = pad_plaintext(b"hi", OVERHEAD).unwrap();
        q[500] = 1; // non-canonical padding
        assert_eq!(unpad_plaintext(&q, OVERHEAD), Err(FrameError::Malformed));
        // A frame sized for a different overhead is not accepted.
        let r = pad_plaintext(b"hi", 16).unwrap();
        assert_eq!(unpad_plaintext(&r, OVERHEAD), Err(FrameError::Malformed));
    }
}
