//! The ZIP reader of `ghost-verify` (the verifier tool only — the client never parses ZIPs in
//! Kotlin, and this code is not in the shipped graph). Only what `libs` needs: the central
//! directory and the decompressed payload of named entries.

use sha2::{Digest, Sha256};

pub struct Entry {
    pub name: Vec<u8>,
    pub method: u16,
    pub compressed: Vec<u8>,
    /// The CRC-32 the entry declares; checked after decompression (a hostile ZIP lies).
    pub crc32: u32,
    pub uncompressed_len: u64,
}

/// Every entry of the ZIP, in central-directory order.
pub fn entries(apk: &[u8]) -> Result<Vec<Entry>, String> {
    let n = apk.len();
    if n < 22 {
        return Err("file smaller than an end-of-central-directory record".into());
    }
    let tail = &apk[n - 22..];
    if &tail[..4] != b"PK\x05\x06" {
        return Err("end-of-central-directory record not found".into());
    }
    let le16 = |b: &[u8]| u16::from_le_bytes([b[0], b[1]]);
    let le32 = |b: &[u8]| u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let count = le16(&tail[10..12]) as usize;
    let cd_size = le32(&tail[12..16]) as usize;
    let cd_offset = le32(&tail[16..20]) as usize;
    if cd_offset + cd_size > n - 22 {
        return Err("central directory outside the file".into());
    }
    let cd = &apk[cd_offset..cd_offset + cd_size];
    let mut out = Vec::with_capacity(count);
    let mut pos = 0usize;
    for _ in 0..count {
        if pos + 46 > cd.len() || &cd[pos..pos + 4] != b"PK\x01\x02" {
            return Err("central directory entry does not parse".into());
        }
        let method = le16(&cd[pos + 10..pos + 12]);
        let crc32 = le32(&cd[pos + 16..pos + 20]);
        let csize = le32(&cd[pos + 20..pos + 24]) as usize;
        let usize_ = le32(&cd[pos + 24..pos + 28]) as u64;
        let nlen = le16(&cd[pos + 28..pos + 30]) as usize;
        let xlen = le16(&cd[pos + 30..pos + 32]) as usize;
        let clen = le16(&cd[pos + 32..pos + 34]) as usize;
        let lho = le32(&cd[pos + 42..pos + 46]) as usize;
        let name = cd[pos + 46..pos + 46 + nlen].to_vec();
        pos += 46 + nlen + xlen + clen;
        // The local header re-states the name and its own extra field: sizes can differ from the
        // central entry's, so the data offset is computed from the local record.
        if lho + 30 > apk.len() || &apk[lho..lho + 4] != b"PK\x03\x04" {
            return Err("local header does not parse".into());
        }
        let l_nlen = le16(&apk[lho + 26..lho + 28]) as usize;
        let l_xlen = le16(&apk[lho + 28..lho + 30]) as usize;
        let start = lho + 30 + l_nlen + l_xlen;
        let end = start.checked_add(csize).ok_or("entry size overflow")?;
        if end > apk.len() {
            return Err("entry data outside the file".into());
        }
        out.push(Entry {
            name,
            method,
            compressed: apk[start..end].to_vec(),
            crc32,
            uncompressed_len: usize_,
        });
    }
    if pos != cd.len() {
        return Err("central directory has trailing bytes".into());
    }
    Ok(out)
}

/// The decompressed payload, with the declared length and CRC-32 enforced.
pub fn inflate(e: &Entry) -> Result<Vec<u8>, String> {
    let out = match e.method {
        0 => e.compressed.clone(),
        8 => {
            use std::io::Read;
            let mut out = Vec::with_capacity(e.uncompressed_len as usize);
            flate2::read::DeflateDecoder::new(&e.compressed[..])
                .read_to_end(&mut out)
                .map_err(|_| "deflate decompression failed")?;
            out
        }
        other => return Err(format!("unsupported compression method {other}")),
    };
    if out.len() as u64 != e.uncompressed_len {
        return Err("decompressed length does not match the directory".into());
    }
    if crc32(&out) != e.crc32 {
        return Err("CRC-32 mismatch".into());
    }
    Ok(out)
}

fn crc32(data: &[u8]) -> u32 {
    // CRC-32 (ISO 3309), the ZIP flavour: reflected, polynomial 0xEDB88320, no final xor input.
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & (0u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}
