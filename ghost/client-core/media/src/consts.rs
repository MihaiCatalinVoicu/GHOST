//! The constants of design §3.1, §3.5, §4.1, §6.6 and §8.3, the walkers' bounds, and the two kinds.

/// Relay blob size of every media blob (the 64 KiB bucket).
pub const FRAG: usize = 65_536;
/// The Poly1305 tag.
pub const TAG: usize = 16;
/// Fragments per chunk: a chunk's ciphertext is exactly four relay blobs (D2).
pub const FRAGMENTS_PER_CHUNK: usize = 4;
/// Ciphertext of one chunk.
pub const CHUNK_CT: usize = FRAGMENTS_PER_CHUNK * FRAG;
/// Plaintext of one chunk ("256 KiB chunk", X-M2).
pub const CHUNK_PT: usize = CHUNK_CT - TAG;
/// The fragment counts `F` of the eleven size classes (§3.6); `class_code` is the index.
pub const CLASSES: [u32; 11] = [16, 24, 36, 56, 84, 128, 192, 288, 432, 648, 804];
/// 50 MiB (FR-3.4; the v1 schema bound).
pub const MAX_CONTENT: u64 = 52_428_800;
/// An image always fits class 0 (F = 16): four full chunks.
pub const IMAGE_MAX_CONTENT: u64 = 4 * CHUNK_PT as u64;

/// The key commitment at the head of the manifest blob (§3.5).
pub const COMMIT_BYTES: usize = 32;
/// The manifest plaintext `MP`: the blob less the commitment and the tag.
pub const MANIFEST_PT: usize = FRAG - COMMIT_BYTES - TAG;
/// Offset of the preview in `MP`.
pub const PREVIEW_OFFSET: usize = 38;
/// The preview field's size: a canonical JPEG of at most this length, zero padded.
pub const PREVIEW_MAX: usize = 32_768;
/// Offset of the fragment hash list in `MP`.
pub const HASHES_OFFSET: usize = PREVIEW_OFFSET + PREVIEW_MAX;
/// A SHA-256 digest.
pub const HASH_BYTES: usize = 32;

/// The longest video, in milliseconds (§6.1, §3.5).
pub const VIDEO_MAX_MS: u32 = 160_000;
/// One fragment's `moof` + `mdat`, at most (§8.3 point 5, S0-2, Q46).
pub const FRAGMENT_MAX_BYTES: u64 = 16 * 1024 * 1024;
/// The descriptor's fixed part (§4.1).
pub const DESCRIPTOR_FIXED: usize = 86;
/// The longest caption (§4.1, §6.6).
pub const MAX_CAPTION_BYTES: usize = 1_024;
/// The longest descriptor body (R-D1).
pub const DESCRIPTOR_MAX: usize = DESCRIPTOR_FIXED + MAX_CAPTION_BYTES;
/// What `sniff` reads of a picked source (§9.2, §13.2 M10).
pub const SNIFF_BYTES: usize = 64;

/// The long edges an image object may have (D29, §8.2).
pub const IMAGE_LONG_EDGES: [u16; 3] = [512, 1_024, 2_048];
/// The long edge of every preview (D29).
pub const PREVIEW_LONG_EDGE: u16 = 320;
/// Every short edge is a multiple of this, at least this, and at most the long edge (D29).
pub const EDGE_STEP: u16 = 16;
/// The coded width of every canonical video (D29, S0-20).
pub const VIDEO_CODED_WIDTH: u16 = 1_280;
/// The coded height of every canonical video.
pub const VIDEO_CODED_HEIGHT: u16 = 720;

/// Walker bound (S1): the largest `moov` (the canonical one is about 1 120 bytes).
pub const MOOV_MAX_BYTES: u32 = 64 * 1024;
/// Walker bound (S1): the largest `moof`. A 16-MiB fragment of an honest stream holds a few
/// thousand samples at 12 bytes each (§8.3 point 4: 63 s of a 16-fps 1 000-frame-IDR encoder is
/// about 47 KiB of `trun` rows); the bound is five times that.
pub const MOOF_MAX_BYTES: u32 = 256 * 1024;
/// Walker bound (S1): the most fragments one object may hold. Fragments close at the first key
/// frame two seconds after their start (§8.3 point 4), so a 160-s video has at most about 80.
pub const MAX_FRAGMENTS: usize = 1_024;
/// Walker bound (S1): the largest SEI NAL unit (buffering period, picture timing and recovery
/// point messages are tens of bytes).
pub const SEI_MAX_BYTES: u32 = 1_024;
/// Walker bound (S1): the largest SPS or PPS NAL unit in `avcC`.
pub const PARAMETER_SET_MAX_BYTES: u16 = 512;
/// The largest AAC-LC stereo access unit: 6 144 bits per channel (ISO/IEC 14496-3).
pub const AAC_MAX_FRAME_BYTES: u32 = 1_536;

/// The two media kinds (§3.5 `kind`, §4.1 `kind`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MediaKind {
    /// A canonical baseline JPEG (§8.2).
    Image = 0x01,
    /// A canonical fragmented MP4 with one H.264 and one AAC-LC track (§8.3).
    Video = 0x02,
}

impl MediaKind {
    /// The wire byte.
    pub fn byte(self) -> u8 {
        self as u8
    }

    /// The kind of a wire byte, or `None` for any other byte.
    pub fn from_byte(b: u8) -> Option<MediaKind> {
        match b {
            0x01 => Some(MediaKind::Image),
            0x02 => Some(MediaKind::Video),
            _ => None,
        }
    }
}
