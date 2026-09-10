//! Padding framing shared by clients and relays (FR-2.5, ADR-09).
//!
//! A padded packet is `len(4, big-endian) || payload || zeros` with total length equal to the
//! smallest bucket that fits. Relays refuse to store anything that is not exactly bucket-sized,
//! so the only sizes observable on the wire or in storage are the four bucket sizes. Onion-service
//! ingress and relay-to-relay Noise sessions are configured at deployment level (infra/), not here.

use ghost_relay_api::{is_bucket_size, padding_bucket, MAX_BLOB_BYTES};

const LEN_PREFIX: usize = 4;

#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    /// Payload plus the length prefix does not fit in the largest bucket; fragment first.
    TooLarge,
    /// Packet length is not a bucket size, or the prefix is inconsistent with it.
    Malformed,
}

/// Pads `payload` to the smallest bucket that fits the 4-byte prefix plus the payload.
pub fn pad(payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    let bucket = padding_bucket(payload.len() + LEN_PREFIX).ok_or(FrameError::TooLarge)?;
    let mut out = vec![0u8; bucket];
    out[..LEN_PREFIX].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    out[LEN_PREFIX..LEN_PREFIX + payload.len()].copy_from_slice(payload);
    Ok(out)
}

/// Inverse of [`pad`]; rejects packets that are not exactly bucket-sized or whose declared length
/// does not fit, and refuses non-zero padding so every payload has a single canonical packet.
pub fn unpad(packet: &[u8]) -> Result<&[u8], FrameError> {
    if !is_bucket_size(packet.len()) {
        return Err(FrameError::Malformed);
    }
    let len = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]) as usize;
    if len + LEN_PREFIX > packet.len() {
        return Err(FrameError::Malformed);
    }
    if packet[LEN_PREFIX + len..].iter().any(|&b| b != 0) {
        return Err(FrameError::Malformed);
    }
    Ok(&packet[LEN_PREFIX..LEN_PREFIX + len])
}

/// Largest payload that fits in a single packet.
pub const MAX_PAYLOAD_BYTES: usize = MAX_BLOB_BYTES - LEN_PREFIX;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_every_bucket() {
        for len in [
            0usize,
            1,
            1_019,
            1_020,
            1_021,
            4_000,
            16_000,
            60_000,
            MAX_PAYLOAD_BYTES,
        ] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let packet = pad(&payload).unwrap();
            assert!(
                is_bucket_size(packet.len()),
                "len {len} -> {}",
                packet.len()
            );
            assert_eq!(unpad(&packet).unwrap(), &payload[..]);
        }
    }

    #[test]
    fn oversize_and_malformed_are_rejected() {
        assert_eq!(
            pad(&vec![0u8; MAX_PAYLOAD_BYTES + 1]),
            Err(FrameError::TooLarge)
        );
        assert_eq!(unpad(&[0u8; 1_000]), Err(FrameError::Malformed));
        let mut p = pad(b"hi").unwrap();
        p[0] = 0xff; // declared length larger than packet
        assert_eq!(unpad(&p), Err(FrameError::Malformed));
        let mut q = pad(b"hi").unwrap();
        q[500] = 1; // non-canonical padding
        assert_eq!(unpad(&q), Err(FrameError::Malformed));
    }
}
