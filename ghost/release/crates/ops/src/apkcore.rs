//! The §6.5 core rule: extract the unsigned core of a signed APK and check it equals the
//! attested unsigned build byte for byte. Same code in `ghost-release-ops apk-core`, the
//! client's install step (D10) and `ghost-verify` (normative, §6.5).
//!
//! The rule (from the signed file's EOCD record, the block's footer and the release's
//! `unsigned_length`):
//! 1. `cd_offset + cd_size = length − 22` (central directory runs to the end record, comment 0);
//! 2. `E := unsigned_length − cd_size − 22` and `B := cd_offset − s − 8` satisfy
//!    `0 < E ≤ B` and `B = E + ((4096 − E mod 4096) mod 4096)`;
//! 3. every byte of `[E, B)` is zero;
//! 4. core := `file[0, E) ‖ file[cd_offset, length)` with the EOCD central-directory offset
//!    field set to `E`.

use sha2::{Digest, Sha256};

/// Everything that can be wrong with a signed APK's shape, one enum (no panics).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CoreError {
    #[error("file smaller than an end-of-central-directory record")]
    TooSmall,
    #[error("end-of-central-directory record not found (or a comment is present)")]
    Eocd,
    #[error("central directory does not run to the end record")]
    CdLayout,
    #[error("EOCD comment length is not zero")]
    Comment,
    #[error("APK Signing Block footer (magic) not found before the central directory")]
    BlockFooter,
    #[error("block size fields disagree")]
    BlockSize,
    #[error("the core rule's inequality fails (0 < E <= B and the 4096 alignment)")]
    Rule,
    #[error("non-zero byte in the signing padding [E, B)")]
    Padding,
    #[error("core SHA-256 mismatch against the expected unsigned build")]
    CoreMismatch,
    #[error("truncated or overlapping structure")]
    Bounds,
}

const EOCD_LEN: usize = 22;
const SIG_MAGIC: &[u8; 16] = b"APK Sig Block 42";
const PAGE: u64 = 4096;

/// Parsed layout of a signed APK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub length: u64,
    pub cd_offset: u64,
    pub cd_size: u64,
    /// Block size `s` (the value in the footer's two size fields, excluding them and the magic).
    pub block_s: u64,
    /// Pair ids present in the signing block, ascending.
    pub block_ids: Vec<u32>,
    /// Offset where the signing block starts (including its leading size field).
    pub block_start: u64,
}

// ZIP and the APK Signing Block are little-endian (the GHOST documents above are big-endian).
fn le16(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}
fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}
fn le64(b: &[u8]) -> u64 {
    u64::from_le_bytes(b.try_into().expect("8 bytes"))
}

/// Parse the EOCD and the signing-block footer (steps of the §6.5 rule that do not need the
/// unsigned length).
pub fn layout(file: &[u8]) -> Result<Layout, CoreError> {
    let length = file.len() as u64;
    if length < EOCD_LEN as u64 + 16 + 8 + 8 {
        return Err(CoreError::TooSmall);
    }
    // EOCD: scan the last EOCD_LEN + 65536 bytes for the signature at the right place; the rule
    // requires comment length 0, so the signature sits exactly at length − 22.
    let eocd_at = (length - EOCD_LEN as u64) as usize;
    if &file[eocd_at..eocd_at + 4] != b"PK\x05\x06" {
        return Err(CoreError::Eocd);
    }
    let eocd = &file[eocd_at..];
    let comment = le16(&eocd[20..22]);
    if comment != 0 {
        return Err(CoreError::Comment);
    }
    let cd_size = le32(&eocd[12..16]) as u64;
    let cd_offset = le32(&eocd[16..20]) as u64;
    if cd_offset + cd_size + EOCD_LEN as u64 != length {
        return Err(CoreError::CdLayout);
    }
    // Block footer: [size2(Q)][magic(16)] ends at cd_offset. `s` counts everything after the
    // first size field (pairs + size2 + magic), so the block is [cd_offset - 8 - s, cd_offset).
    if cd_offset < 8 + 24 {
        return Err(CoreError::BlockFooter);
    }
    let footer = cd_offset as usize - 24;
    if &file[footer + 8..footer + 24] != SIG_MAGIC {
        return Err(CoreError::BlockFooter);
    }
    let s2 = le64(&file[footer..footer + 8]);
    let block_start_u = cd_offset
        .checked_sub(8)
        .and_then(|x| x.checked_sub(s2))
        .ok_or(CoreError::Bounds)?;
    let block_start = block_start_u as usize;
    if block_start + 8 > footer || le64(&file[block_start..block_start + 8]) != s2 {
        return Err(CoreError::BlockSize);
    }
    // Pair ids inside the block (the `blocks=` report).
    let mut ids = Vec::new();
    let mut pos = block_start + 8;
    while pos + 8 <= footer {
        let len = le64(&file[pos..pos + 8]) as usize;
        let id = le32(&file[pos + 8..pos + 12]);
        ids.push(id);
        pos += 8 + len;
    }
    ids.sort_unstable();
    Ok(Layout {
        length,
        cd_offset,
        cd_size,
        block_s: s2,
        block_ids: ids,
        block_start: block_start_u,
    })
}

/// The E of the rule: where the unsigned APK's central directory began.
pub fn e_of(layout: &Layout, unsigned_length: u64) -> Result<u64, CoreError> {
    let e = unsigned_length
        .checked_sub(layout.cd_size)
        .and_then(|x| x.checked_sub(EOCD_LEN as u64))
        .ok_or(CoreError::Bounds)?;
    let b = layout
        .cd_offset
        .checked_sub(layout.block_s)
        .and_then(|x| x.checked_sub(8))
        .ok_or(CoreError::Bounds)?;
    if !(0 < e && e <= b) {
        return Err(CoreError::Rule);
    }
    let aligned = e + ((PAGE - e % PAGE) % PAGE);
    if b != aligned {
        return Err(CoreError::Rule);
    }
    Ok(e)
}

/// Extract the core (step 4) and compare it with the expected unsigned build.
///
/// On success returns `padding = B − E` and the sorted block ids for the `CORE_EQUAL` line.
pub fn check_core(file: &[u8], unsigned: &[u8]) -> Result<(u64, Vec<u32>), CoreError> {
    let l = layout(file)?;
    let e = e_of(&l, unsigned.len() as u64)?;
    let b = l.cd_offset - l.block_s - 8;
    // Step 3: the padding is all zero.
    if file[e as usize..b as usize].iter().any(|&x| x != 0) {
        return Err(CoreError::Padding);
    }
    // Step 4: core = file[0,E) + file[cd_offset, length) with the EOCD cd-offset field set to E.
    let mut core = Vec::with_capacity(e as usize + (l.length - l.cd_offset) as usize);
    core.extend_from_slice(&file[..e as usize]);
    core.extend_from_slice(&file[l.cd_offset as usize..]);
    let eocd_at = core.len() - EOCD_LEN;
    core[eocd_at + 16..eocd_at + 20].copy_from_slice(&(e as u32).to_le_bytes());
    if core != unsigned {
        return Err(CoreError::CoreMismatch);
    }
    Ok((b - e, l.block_ids))
}

/// Extract the core given the unsigned build's length (step 4 without the bytes).
pub fn extract_core(file: &[u8], unsigned_length: u64) -> Result<Vec<u8>, CoreError> {
    let l = layout(file)?;
    let e = e_of(&l, unsigned_length)?;
    let b = l.cd_offset - l.block_s - 8;
    if file[e as usize..b as usize].iter().any(|&x| x != 0) {
        return Err(CoreError::Padding);
    }
    let mut core = Vec::with_capacity(e as usize + (l.length - l.cd_offset) as usize);
    core.extend_from_slice(&file[..e as usize]);
    core.extend_from_slice(&file[l.cd_offset as usize..]);
    let eocd_at = core.len() - EOCD_LEN;
    core[eocd_at + 16..eocd_at + 20].copy_from_slice(&(e as u32).to_le_bytes());
    Ok(core)
}

/// `apk-core --apk signed.apk --unsigned-length <n> --expect <sha256>`: extract the core with the
/// manifest's `unsigned_length`, hash it, compare. Returns (padding, block ids).
pub fn check_core_sha256(
    file: &[u8],
    unsigned_length: u64,
    expect_sha256: &[u8; 32],
) -> Result<(u64, Vec<u32>), CoreError> {
    let l = layout(file)?;
    let b = l.cd_offset - l.block_s - 8;
    let padding = b - e_of(&l, unsigned_length)?;
    let core = extract_core(file, unsigned_length)?;
    let got: [u8; 32] = Sha256::digest(&core).into();
    if got != *expect_sha256 {
        return Err(CoreError::CoreMismatch);
    }
    Ok((padding, l.block_ids))
}
