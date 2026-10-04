//! The eleven size classes of design §3.6 (T42): fragment counts in ×1.5 steps, a multiple of four
//! each, the last capped at 50 MiB. The class is a function of the content length only.

use crate::consts::{CHUNK_PT, CLASSES, FRAGMENTS_PER_CHUNK, MAX_CONTENT};

/// A size class, `class_code` 0 … 10.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SizeClass(u8);

impl SizeClass {
    /// Class 0 (16 fragments): every image and every video of at most 1 048 512 bytes.
    pub const SMALLEST: SizeClass = SizeClass(0);
    /// Class 10 (804 fragments): content up to `MAX_CONTENT`.
    pub const LARGEST: SizeClass = SizeClass(10);

    /// The class of a `class_code`, or `None` above 10.
    pub fn from_code(code: u8) -> Option<SizeClass> {
        let index = usize::from(code);
        (index < CLASSES.len()).then_some(SizeClass(code))
    }

    /// The `class_code`.
    pub fn code(self) -> u8 {
        self.0
    }

    /// `F`, the fragment count.
    pub fn fragments(self) -> u32 {
        CLASSES.get(usize::from(self.0)).copied().unwrap_or(0)
    }

    /// `n = F / 4`, the chunk count.
    pub fn chunks(self) -> u32 {
        // Every F is a multiple of the four fragments of a chunk.
        const _: () = assert!(FRAGMENTS_PER_CHUNK == 4);
        self.fragments() / 4
    }

    /// The most content the class holds: `n · CHUNK_PT`, capped at `MAX_CONTENT` for class 10.
    pub fn capacity(self) -> u64 {
        let full = u64::from(self.chunks()).saturating_mul(CHUNK_PT as u64);
        full.min(MAX_CONTENT)
    }

    /// `class(L) = min{F : (F / 4) · 262 128 ≥ L}`, or `None` for `L = 0` and `L > MAX_CONTENT`.
    pub fn for_content_len(len: u64) -> Option<SizeClass> {
        if len == 0 || len > MAX_CONTENT {
            return None;
        }
        SizeClass::all().find(|c| c.capacity() >= len)
    }

    /// Every class, smallest first.
    pub fn all() -> impl Iterator<Item = SizeClass> {
        (0u8..11).map(SizeClass)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_of_section_3_6() {
        let caps: Vec<u64> = SizeClass::all().map(|c| c.capacity()).collect();
        assert_eq!(
            caps,
            [
                1_048_512, 1_572_768, 2_359_152, 3_669_792, 5_504_688, 8_388_096, 12_582_144,
                18_873_216, 28_309_824, 42_464_736, 52_428_800
            ]
        );
        let chunks: Vec<u32> = SizeClass::all().map(|c| c.chunks()).collect();
        assert_eq!(chunks, [4, 6, 9, 14, 21, 32, 48, 72, 108, 162, 201]);
        for c in SizeClass::all() {
            assert_eq!(c.fragments() % 4, 0);
            assert_eq!(SizeClass::from_code(c.code()), Some(c));
        }
        assert_eq!(SizeClass::from_code(11), None);
    }

    #[test]
    fn every_boundary() {
        assert_eq!(SizeClass::for_content_len(0), None);
        assert_eq!(SizeClass::for_content_len(1), Some(SizeClass::SMALLEST));
        for c in SizeClass::all() {
            assert_eq!(SizeClass::for_content_len(c.capacity()), Some(c));
            let next = SizeClass::for_content_len(c.capacity() + 1);
            if c == SizeClass::LARGEST {
                assert_eq!(next, None, "52 428 801 bytes are refused");
            } else {
                assert_eq!(next, SizeClass::from_code(c.code() + 1));
            }
        }
    }
}
