//! The outer seal's size rule (design §5.6, §5.7): `|blob| = B ∈ {4096, 16384, 65536}`, capacity
//! `C(B) = B − 68` for the body (the MLS message bytes), a class floor of 4 KiB (small, ≤ 32
//! members) or 16 KiB (large, ≤ 100 members).

pub const BUCKETS: [usize; 3] = [4096, 16_384, 65_536];
/// `salt(16) ‖ hint(16) ‖ AEAD tag(16)` outside P, `mode(1) ‖ body_len(3) ‖ order(16)` inside.
pub const OVERHEAD: usize = 68;

pub fn capacity(bucket: usize) -> usize {
    bucket - OVERHEAD
}

/// Class floor: 0 small (4 KiB), 1 large (16 KiB).
pub fn floor(class: u8) -> usize {
    if class == 0 {
        4096
    } else {
        16_384
    }
}

/// `bucket(len)` of §5.7, or `None` (`NO_FIT`) above `C(65536)`.
pub fn bucket(len: usize, class: u8) -> Option<usize> {
    BUCKETS
        .iter()
        .copied()
        .find(|&b| b >= floor(class) && capacity(b) >= len)
}
