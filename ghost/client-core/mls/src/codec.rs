//! Byte helpers: RFC 9420 §2.1 presentation language (fixed-width big-endian integers and
//! variable-length vectors with the QUIC-style varint prefix of §2.1.2) and a strict reader whose
//! every read fails on a short input. Every GHOST format of the crate is built on these.

/// Appends `v` as a variable-length vector (`opaque x<V>`). Vectors of GHOST's formats are far
/// below the 2^30 limit; a longer one is refused by the caller's bounds before it gets here.
pub fn put_vec(out: &mut Vec<u8>, v: &[u8]) {
    put_varint(out, v.len());
    out.extend_from_slice(v);
}

/// RFC 9420 §2.1.2 variable-length integer in its minimal encoding (1, 2 or 4 bytes).
pub fn put_varint(out: &mut Vec<u8>, n: usize) {
    if n < 1 << 6 {
        out.push(n as u8);
    } else if n < 1 << 14 {
        out.extend_from_slice(&((n as u16) | 0x4000).to_be_bytes());
    } else {
        // Callers bound their vectors far below 2^30 (the largest GHOST vector is a few KiB).
        let n = (n as u32) & 0x3fff_ffff;
        out.extend_from_slice(&(n | 0x8000_0000).to_be_bytes());
    }
}

/// Encoded size of a varint length prefix.
pub fn varint_len(n: usize) -> usize {
    if n < 1 << 6 {
        1
    } else if n < 1 << 14 {
        2
    } else {
        4
    }
}

pub fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

pub fn put_u24(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes()[1..]);
}

pub fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

pub fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// A strict reader over a byte slice.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    pub fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    pub fn u16(&mut self) -> Option<u16> {
        self.fixed::<2>().map(u16::from_be_bytes)
    }

    pub fn u24(&mut self) -> Option<u32> {
        let b = self.take(3)?;
        Some(u32::from_be_bytes([0, b[0], b[1], b[2]]))
    }

    pub fn u32(&mut self) -> Option<u32> {
        self.fixed::<4>().map(u32::from_be_bytes)
    }

    pub fn u64(&mut self) -> Option<u64> {
        self.fixed::<8>().map(u64::from_be_bytes)
    }

    /// A varint in its minimal encoding (RFC 9420 §2.1.2 requires minimal encodings); the
    /// reserved 8-byte form (prefix `11`) is refused.
    pub fn varint(&mut self) -> Option<usize> {
        let first = *self.buf.get(self.pos)?;
        let (len, v) = match first >> 6 {
            0 => (1usize, usize::from(first & 0x3f)),
            1 => {
                let b = self.buf.get(self.pos..self.pos.checked_add(2)?)?;
                (2, usize::from(u16::from_be_bytes([b[0] & 0x3f, b[1]])))
            }
            2 => {
                let b = self.buf.get(self.pos..self.pos.checked_add(4)?)?;
                let v = u32::from_be_bytes([b[0] & 0x3f, b[1], b[2], b[3]]);
                (4, usize::try_from(v).ok()?)
            }
            _ => return None,
        };
        if varint_len(v) != len {
            return None;
        }
        self.pos += len;
        Some(v)
    }

    /// `opaque x<V>`: a minimal varint length and that many bytes.
    pub fn vec(&mut self) -> Option<&'a [u8]> {
        let n = self.varint()?;
        self.take(n)
    }

    pub fn fixed<const N: usize>(&mut self) -> Option<[u8; N]> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N)?);
        Some(a)
    }

    pub fn rest(&mut self) -> &'a [u8] {
        let r = &self.buf[self.pos..];
        self.pos = self.buf.len();
        r
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn done(&self) -> bool {
        self.pos == self.buf.len()
    }
}

/// RFC 4648 base32, lowercase, unpadded: the `ghost://` link alphabet of ADR-05 (§5.9).
pub fn base32_lower(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &b in data {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// The inverse of [`base32_lower`]: lowercase letters and digits 2–7 only, no padding, and the
/// unused low bits of the last character must be zero (one encoding per byte string).
pub fn base32_lower_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for c in s.bytes() {
        let v = match c {
            b'a'..=b'z' => c - b'a',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        };
        acc = (acc << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
        acc &= (1 << bits) - 1;
    }
    // A trailing group of 5 or more bits would be a whole extra character; leftover bits must be 0.
    if bits >= 5 || acc != 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints_are_minimal_both_ways() {
        for n in [0usize, 1, 63, 64, 16_383, 16_384, 1 << 20] {
            let mut o = Vec::new();
            put_varint(&mut o, n);
            assert_eq!(o.len(), varint_len(n));
            let mut r = Reader::new(&o);
            assert_eq!(r.varint(), Some(n));
            assert!(r.done());
        }
        // 5 in a 2-byte form, and the reserved 8-byte prefix, are refused.
        assert_eq!(Reader::new(&[0x40, 0x05]).varint(), None);
        assert_eq!(Reader::new(&[0xc0, 0, 0, 0, 0, 0, 0, 1]).varint(), None);
        assert_eq!(Reader::new(&[0x40]).varint(), None);
    }

    #[test]
    fn base32_round_trips_and_is_canonical() {
        // RFC 4648 §10 test vectors, lowercased and unpadded.
        for (i, o) in [
            ("", ""),
            ("f", "my"),
            ("fo", "mzxq"),
            ("foo", "mzxw6"),
            ("foob", "mzxw6yq"),
            ("fooba", "mzxw6ytb"),
            ("foobar", "mzxw6ytboi"),
        ] {
            assert_eq!(base32_lower(i.as_bytes()), o);
            assert_eq!(base32_lower_decode(o).as_deref(), Some(i.as_bytes()));
        }
        assert_eq!(base32_lower_decode("mz"), None, "non-zero leftover bits");
        assert_eq!(base32_lower_decode("MZXQ"), None, "uppercase");
        assert_eq!(base32_lower_decode("mzxq="), None, "padding");
        assert_eq!(base32_lower_decode("m"), None, "a lone character");
    }
}
