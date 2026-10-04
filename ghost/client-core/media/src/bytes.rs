//! Checked reading of untrusted bytes: every read is bounds-checked and every failure is a typed
//! refusal, so no parser of the crate can over-read or panic (§15.1's "never panics, never
//! over-reads").

use crate::error::{MediaError, MediaResult};

/// A forward reader over a byte slice.
#[derive(Clone, Copy)]
pub(crate) struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
    rule: &'static str,
}

impl<'a> Cursor<'a> {
    /// A reader whose refusals name `rule`.
    pub(crate) fn new(data: &'a [u8], rule: &'static str) -> Self {
        Cursor { data, pos: 0, rule }
    }

    fn short(&self) -> MediaError {
        MediaError::non_canonical(self.rule)
    }

    /// The next `n` bytes.
    pub(crate) fn take(&mut self, n: usize) -> MediaResult<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or_else(|| self.short())?;
        let out = self.data.get(self.pos..end).ok_or_else(|| self.short())?;
        self.pos = end;
        Ok(out)
    }

    /// The next `N` bytes as an array.
    pub(crate) fn array<const N: usize>(&mut self) -> MediaResult<[u8; N]> {
        let s = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(s);
        Ok(out)
    }

    pub(crate) fn u8(&mut self) -> MediaResult<u8> {
        Ok(u8::from_be_bytes(self.array::<1>()?))
    }

    pub(crate) fn u16(&mut self) -> MediaResult<u16> {
        Ok(u16::from_be_bytes(self.array::<2>()?))
    }

    pub(crate) fn u32(&mut self) -> MediaResult<u32> {
        Ok(u32::from_be_bytes(self.array::<4>()?))
    }

    pub(crate) fn u64(&mut self) -> MediaResult<u64> {
        Ok(u64::from_be_bytes(self.array::<8>()?))
    }

    /// Everything not read yet.
    pub(crate) fn rest(&mut self) -> &'a [u8] {
        let out = self.data.get(self.pos..).unwrap_or(&[]);
        self.pos = self.data.len();
        out
    }

    /// Whether every byte has been read.
    pub(crate) fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// Refuses unless every byte has been read (one encoding: nothing left unread).
    pub(crate) fn finish(&self) -> MediaResult<()> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(self.short())
        }
    }

    /// Bytes read so far.
    pub(crate) fn position(&self) -> usize {
        self.pos
    }
}

/// A big-endian `u32` at `off`, or `None` past the end.
pub(crate) fn be_u32(data: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let s = data.get(off..end)?;
    Some(u32::from_be_bytes([
        *s.first()?,
        *s.get(1)?,
        *s.get(2)?,
        *s.get(3)?,
    ]))
}

/// `a + b`, refusing on overflow.
pub(crate) fn add(a: u64, b: u64, rule: &'static str) -> MediaResult<u64> {
    a.checked_add(b).ok_or(MediaError::non_canonical(rule))
}

/// Whether every byte is zero.
pub(crate) fn all_zero(data: &[u8]) -> bool {
    data.iter().all(|b| *b == 0)
}
