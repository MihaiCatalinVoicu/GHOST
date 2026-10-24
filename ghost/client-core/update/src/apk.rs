//! The Android-equivalent APK check (§7.4 steps 9–10): the layout and padding rule of §6.5,
//! the whole-file and core hashes, the platform's signer selection by SDK, and the release
//! binding. Lengths only for the certificate — the platform verifies signatures; this crate
//! only hashes what the platform would install. Same normative rule as `apkcore.rs` in
//! `ghost-release-ops` (§6.5: the code lives in the ops tool, the client's step 9 and
//! `ghost-verify`).

use ghost_client_release::manifest::GHRM;
use ghost_client_release::root::GHRT;
use sha2::{Digest, Sha256};

use crate::UpdateError;

const EOCD_LEN: usize = 22;
const SIG_MAGIC: &[u8; 16] = b"APK Sig Block 42";
const PAGE: u64 = 4096;
const ID_V2: u32 = 0x7109_871a;
const ID_V3: u32 = 0xf053_68c0;
const ID_V31: u32 = 0x1b93_ad61;
/// The `maxSdk` an unbounded v3 signer carries (Java's `Integer.MAX_VALUE`).
const SDK_MAX: u32 = 0x7fff_ffff;

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
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

/// The parsed layout facts a run needs more than once.
#[derive(Debug, Clone)]
struct Layout {
    length: u64,
    cd_offset: u64,
    cd_size: u64,
    block_s: u64,
    block_start: u64,
    /// The signing block pairs `(id, value range)` in file order.
    pairs: Vec<(u32, u64, u64)>,
}

/// Step 9a–9c: EOCD at exactly `length − 22`, comment 0, single disk (no ZIP64), the block
/// footer with both size copies equal.
fn layout(file: &[u8]) -> Result<Layout, UpdateError> {
    let length = file.len() as u64;
    if length < EOCD_LEN as u64 + 16 + 8 + 8 {
        return Err(UpdateError::ApkLayout);
    }
    let eocd_at = (length - EOCD_LEN as u64) as usize;
    if &file[eocd_at..eocd_at + 4] != b"PK\x05\x06" {
        return Err(UpdateError::ApkLayout);
    }
    let eocd = &file[eocd_at..];
    if le16(&eocd[20..22]) != 0 {
        return Err(UpdateError::ApkLayout); // comment length must be 0
    }
    if le16(&eocd[4..6]) != 0 || le16(&eocd[6..8]) != 0 {
        return Err(UpdateError::ApkLayout); // a single disk, no ZIP64 EOCD
    }
    let cd_size = le32(&eocd[12..16]) as u64;
    let cd_offset = le32(&eocd[16..20]) as u64;
    if cd_offset + cd_size + EOCD_LEN as u64 != length {
        return Err(UpdateError::ApkLayout);
    }
    if cd_offset < 8 + 24 {
        return Err(UpdateError::ApkLayout);
    }
    let footer = cd_offset as usize - 24;
    if &file[footer + 8..footer + 24] != SIG_MAGIC {
        return Err(UpdateError::ApkLayout);
    }
    let s = le64(&file[footer..footer + 8]);
    let block_start = cd_offset
        .checked_sub(8)
        .and_then(|x| x.checked_sub(s))
        .ok_or(UpdateError::ApkLayout)?;
    if block_start + 8 > footer as u64 || le64(&file[block_start as usize..block_start as usize + 8]) != s {
        return Err(UpdateError::ApkLayout);
    }
    // The pairs: [len u64][id u32][value] until the footer.
    let mut pairs = Vec::new();
    let mut pos = block_start as usize + 8;
    while pos + 12 <= footer {
        let len = le64(&file[pos..pos + 8]);
        let id = le32(&file[pos + 8..pos + 12]);
        let start = pos + 12;
        let end = start.checked_add(len as usize).ok_or(UpdateError::ApkLayout)?;
        if end > footer {
            return Err(UpdateError::ApkLayout);
        }
        pairs.push((id, start as u64, end as u64));
        pos = end;
    }
    if pos != footer {
        return Err(UpdateError::ApkLayout);
    }
    Ok(Layout { length, cd_offset, cd_size, block_s: s, block_start, pairs })
}

/// Steps 9c–9d: E, the zero padding and the core bytes (EOCD cd-offset field rewritten to E).
fn core(file: &[u8], l: &Layout, unsigned_length: u64) -> Result<Vec<u8>, UpdateError> {
    let e = unsigned_length
        .checked_sub(l.cd_size)
        .and_then(|x| x.checked_sub(EOCD_LEN as u64))
        .ok_or(UpdateError::ApkLayout)?;
    let b = l
        .cd_offset
        .checked_sub(l.block_s)
        .and_then(|x| x.checked_sub(8))
        .ok_or(UpdateError::ApkLayout)?;
    if !(0 < e && e <= b) || b != e + ((PAGE - e % PAGE) % PAGE) {
        return Err(UpdateError::ApkLayout);
    }
    if file[e as usize..b as usize].iter().any(|&x| x != 0) {
        return Err(UpdateError::ApkLayout);
    }
    let mut out = Vec::with_capacity(e as usize + (l.length - l.cd_offset) as usize);
    out.extend_from_slice(&file[..e as usize]);
    out.extend_from_slice(&file[l.cd_offset as usize..]);
    let eocd_at = out.len() - EOCD_LEN;
    out[eocd_at + 16..eocd_at + 20].copy_from_slice(&(e as u32).to_le_bytes());
    Ok(out)
}

/// A bounds-checked little-endian u32-length-prefixed reader over one signing-block value.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], UpdateError> {
        let end = self.pos.checked_add(n).ok_or(UpdateError::ApkSigner)?;
        if end > self.buf.len() {
            return Err(UpdateError::ApkSigner);
        }
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }
    fn lp32(&mut self) -> Result<&'a [u8], UpdateError> {
        let n = le32(self.take(4)?) as usize;
        self.take(n)
    }
    fn done(&self) -> Result<(), UpdateError> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(UpdateError::ApkSigner)
        }
    }
}

/// One signer of a v2/v3/v3.1 block: the SDK range and the first certificate's bytes.
struct Signer {
    min_sdk: u32,
    max_sdk: u32,
    cert: Vec<u8>,
}

/// Parse the first signer of a block value. `v3_layout` selects the signed-data grammar
/// (v3/v3.1 carry min/max SDK; v2 does not).
fn first_signer(value: &[u8], v3_layout: bool) -> Result<Signer, UpdateError> {
    // value = [u32 len][signer]… (the signers sequence is length-prefixed)
    let mut top = Cursor::new(value);
    let signer = top.lp32()?;
    top.done().map_err(|_| UpdateError::ApkSigner)?;
    let mut c = Cursor::new(signer);
    let signed = c.lp32()?;
    c.lp32()?; // signatures (not checked: the platform verifies them)
    c.lp32()?; // public key
    c.done().map_err(|_| UpdateError::ApkSigner)?;
    let mut s = Cursor::new(signed);
    s.lp32()?; // digests
    let certs = s.lp32()?;
    let (min_sdk, max_sdk) = if v3_layout {
        (le32(s.take(4)?), le32(s.take(4)?))
    } else {
        (0, SDK_MAX)
    };
    // The first certificate, lengths only.
    let mut cc = Cursor::new(certs);
    let cert = cc.lp32()?.to_vec();
    Ok(Signer { min_sdk, max_sdk, cert })
}

/// Step 9e: the signer the platform uses at this SDK — v3.1 whose [minSdk, maxSdk] contains
/// the SDK, else v3's, else v2's — and the SHA-256 of its first certificate.
fn signer_digest(file: &[u8], l: &Layout, sdk: u8) -> Result<[u8; 32], UpdateError> {
    let sdk = u32::from(sdk);
    let find = |id: u32| -> Option<Signer> {
        l.pairs
            .iter()
            .find(|(pid, _, _)| *pid == id)
            .and_then(|(_, s, e)| first_signer(&file[*s as usize..*e as usize], true).ok())
    };
    for id in [ID_V31, ID_V3] {
        if let Some(s) = find(id) {
            if s.min_sdk <= sdk && sdk <= s.max_sdk {
                return Ok(sha256(&s.cert));
            }
        }
    }
    if let Some((_, s, e)) = l.pairs.iter().find(|(pid, _, _)| *pid == ID_V2) {
        let signer = first_signer(&file[*s as usize..*e as usize], false)?;
        return Ok(sha256(&signer.cert));
    }
    Err(UpdateError::ApkSigner)
}

/// Steps 9–10: check a downloaded or staged APK against the offered release and the trusted
/// root. `release_index` is the release's index in `manifest` (its attestation block is part
/// of the binding).
pub fn check_apk(
    file: &[u8],
    manifest: &GHRM,
    release_index: usize,
    r: &GHRT,
    sdk: u8,
) -> Result<(), UpdateError> {
    let release = manifest
        .body
        .releases
        .get(release_index)
        .ok_or(UpdateError::Malformed)?;
    let l = layout(file)?;
    if l.length != release.apk_length {
        return Err(UpdateError::ApkLength);
    }
    if sha256(file) != release.apk_sha256 {
        return Err(UpdateError::ApkHash);
    }
    let core = core(file, &l, release.unsigned_length)?;
    if core.len() as u64 != release.unsigned_length || sha256(&core) != release.unsigned_sha256 {
        return Err(UpdateError::ApkCore);
    }
    if !r.body.apk_signers.contains(&signer_digest(file, &l, sdk)?) {
        return Err(UpdateError::ApkSigner);
    }
    let at = manifest
        .attestations
        .get(release_index)
        .ok_or(UpdateError::AttestationQuorum)?;
    at.meets(
        &r.body.attest.keys,
        r.body.attest.threshold,
        &ghost_client_release::statement_bytes(
            ghost_client_release::StatementType::BuildAttestation,
            manifest.body.network,
            &release.attestation(manifest.body.network).to_bytes(),
        ),
    )
    .map_err(|_| UpdateError::AttestationQuorum)
}

/// The block ids present in a signed APK (the `blocks=` vocabulary), for tests and reports.
pub fn block_ids(file: &[u8]) -> Result<Vec<u32>, UpdateError> {
    Ok(layout(file)?.pairs.iter().map(|(id, _, _)| *id).collect())
}
