//! TLS presentation-language helpers (RFC 9420 §2.1): fixed-width big-endian integers and
//! variable-length vectors with the QUIC-style varint length prefix of §2.1.2.

/// Appends `v` as a variable-length vector (`opaque x<V>`).
pub fn put_vec(out: &mut Vec<u8>, v: &[u8]) {
    put_varint(out, v.len() as u64);
    out.extend_from_slice(v);
}

/// RFC 9420 §2.1.2 variable-length integer (1, 2 or 4 bytes; 30-bit maximum).
pub fn put_varint(out: &mut Vec<u8>, n: u64) {
    if n < 1 << 6 {
        out.push(n as u8);
    } else if n < 1 << 14 {
        out.extend_from_slice(&((n as u16) | 0x4000).to_be_bytes());
    } else {
        assert!(n < 1 << 30, "vector longer than 2^30");
        out.extend_from_slice(&((n as u32) | 0x8000_0000).to_be_bytes());
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

/// A strict reader over a byte slice; every read fails on a short input.
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
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64(&mut self) -> Option<u64> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Some(u64::from_be_bytes(a))
    }

    /// A varint in its minimal encoding (RFC 9420 §2.1.2 requires minimal encodings).
    pub fn varint(&mut self) -> Option<u64> {
        let first = *self.buf.get(self.pos)?;
        let (len, v) = match first >> 6 {
            0 => (1usize, u64::from(first & 0x3f)),
            1 => {
                let b = self.take(2)?;
                self.pos -= 2;
                (2, u64::from(u16::from_be_bytes([b[0] & 0x3f, b[1]])))
            }
            2 => {
                let b = self.take(4)?;
                self.pos -= 4;
                (
                    4,
                    u64::from(u32::from_be_bytes([b[0] & 0x3f, b[1], b[2], b[3]])),
                )
            }
            _ => return None,
        };
        if varint_len(v as usize) != len {
            return None;
        }
        self.pos += len;
        Some(v)
    }

    pub fn vec(&mut self) -> Option<&'a [u8]> {
        let n = usize::try_from(self.varint()?).ok()?;
        self.take(n)
    }

    pub fn fixed<const N: usize>(&mut self) -> Option<[u8; N]> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N)?);
        Some(a)
    }

    pub fn done(&self) -> bool {
        self.pos == self.buf.len()
    }
}
