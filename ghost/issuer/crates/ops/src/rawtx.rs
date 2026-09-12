//! The key images of a signed Monero transaction's inputs (design §19.7: the workstation ledger
//! records them per payout entry, so that no two entries spend the same output). The input is the
//! transaction `sign_transfer` returns in `tx_raw_list` (hex); only its prefix is read:
//!
//! ```text
//! version varint (= 2, RingCT) || unlock_time varint || input count varint (1..256)
//! || input count x (0x02 txin_to_key || amount varint || offset count varint (1..1024)
//!                   || offset count x varint || key image 32)
//! ```
//! Varints are Monero's little-endian base-128 encoding, canonical (no trailing zero group, at
//! most 64 bits). Any other input type, version, bound or a truncated prefix is refused.

pub const MAX_INPUTS: u64 = 256;
pub const MAX_RING: u64 = 1_024;
const TXIN_TO_KEY: u8 = 0x02;
const RINGCT_VERSION: u64 = 2;

fn varint(r: &mut &[u8]) -> Option<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let (&byte, rest) = r.split_first()?;
        *r = rest;
        let bits = u64::from(byte & 0x7f);
        if shift == 63 && bits > 1 {
            return None;
        }
        value |= bits << shift;
        if byte & 0x80 == 0 {
            if shift > 0 && bits == 0 {
                return None;
            }
            return Some(value);
        }
    }
    None
}

/// The key images of the inputs, in order, or `None` for anything but a RingCT transaction whose
/// inputs are all `txin_to_key` with distinct key images.
pub fn key_images(raw: &[u8]) -> Option<Vec<[u8; 32]>> {
    let mut r = raw;
    if varint(&mut r)? != RINGCT_VERSION {
        return None;
    }
    varint(&mut r)?;
    let inputs = varint(&mut r)?;
    if inputs == 0 || inputs > MAX_INPUTS {
        return None;
    }
    let mut images = Vec::new();
    for _ in 0..inputs {
        let (&tag, rest) = r.split_first()?;
        r = rest;
        if tag != TXIN_TO_KEY {
            return None;
        }
        varint(&mut r)?;
        let offsets = varint(&mut r)?;
        if offsets == 0 || offsets > MAX_RING {
            return None;
        }
        for _ in 0..offsets {
            varint(&mut r)?;
        }
        let image: [u8; 32] = r.get(..32)?.try_into().ok()?;
        r = &r[32..];
        if images.contains(&image) {
            return None;
        }
        images.push(image);
    }
    Some(images)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put_varint(out: &mut Vec<u8>, mut v: u64) {
        while v >= 0x80 {
            out.push((v as u8 & 0x7f) | 0x80);
            v >>= 7;
        }
        out.push(v as u8);
    }

    fn tx(images: &[[u8; 32]]) -> Vec<u8> {
        let mut out = Vec::new();
        put_varint(&mut out, 2);
        put_varint(&mut out, 0);
        put_varint(&mut out, images.len() as u64);
        for image in images {
            out.push(TXIN_TO_KEY);
            put_varint(&mut out, 0);
            put_varint(&mut out, 16);
            for i in 0..16u64 {
                put_varint(&mut out, 1_000 + 300 * i);
            }
            out.extend_from_slice(image);
        }
        // vout and the RingCT part follow; they are not read.
        out.extend_from_slice(&[0x02, 0x00, 0x03]);
        out
    }

    #[test]
    fn reads_the_key_images_of_every_input() {
        let images = [[1u8; 32], [2u8; 32]];
        assert_eq!(key_images(&tx(&images)), Some(images.to_vec()));
    }

    #[test]
    fn refuses_other_shapes() {
        let good = tx(&[[1u8; 32]]);
        assert!(key_images(&good[..good.len() - 36]).is_none(), "truncated");
        let mut v1 = good.clone();
        v1[0] = 1;
        assert!(key_images(&v1).is_none(), "version 1");
        let mut gen = good.clone();
        gen[3] = 0xff;
        assert!(key_images(&gen).is_none(), "another input type");
        assert!(key_images(&tx(&[])).is_none(), "no input");
        assert!(
            key_images(&tx(&[[3u8; 32], [3u8; 32]])).is_none(),
            "a repeated key image"
        );
    }

    #[test]
    fn varints_are_canonical_and_bounded() {
        assert_eq!(varint(&mut &[0x80, 0x01][..]), Some(128));
        assert_eq!(
            varint(&mut &[0x80, 0x00][..]),
            None,
            "a trailing zero group"
        );
        assert_eq!(varint(&mut &[0xff; 10][..]), None, "above 64 bits");
        let mut max = vec![0xff; 9];
        max.push(0x01);
        assert_eq!(varint(&mut max.as_slice()), Some(u64::MAX));
        assert_eq!(varint(&mut &[0x80][..]), None, "truncated");
    }
}
