//! The Android-equivalent APK check (§7.4 steps 9–10): the layout and padding rule of §6.5,
//! the whole-file and core hashes, the platform's signer selection by SDK, and the release
//! binding. Lengths only for the certificate — the platform verifies signatures; this crate
//! only hashes what the platform would install. Same normative rule as `apkcore.rs` in
//! `ghost-release-ops` (§6.5: the code lives in the ops tool, the client's step 9 and
//! `ghost-verify`).
//!
//! The check streams (§9.2's `ApkCheck`): `begin` reads the end record from the file's last
//! 22 bytes (Kotlin passes them), names the 24-byte footer range it must read next, then
//! `update` consumes the body in order — the caller (the download loop, the staging pass, the
//! installer stream) feeds exactly the bytes it has, and the crate never seeks. The one-shot
//! `check_apk` is the same machine over an in-memory file.

use ghost_client_release::manifest::{GHRM, Release};
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

/// What `begin` still needs: the 24 bytes before the central directory (the block footer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Need {
    Footer { offset: u64 },
}

/// The streaming APK check (§9.2 `ApkCheck`). Feeding bytes out of order is `OUT_OF_ORDER`.
/// Owns the release, manifest and root (small documents, ≤ ~64 KiB each) so a check can live
/// in a JNI handle registry without lifetimes.
pub struct ApkCheck {
    release_index: usize,
    release: Release,
    manifest: GHRM,
    root: GHRT,
    sdk: u8,
    length: u64,
    cd_offset: u64,
    cd_size: u64,
    e: u64,
    b: u64,
    tail: [u8; EOCD_LEN],
    full: Sha256,
    core: Sha256,
    block: Vec<u8>,
    next: u64,
    footer_seen: bool,
}

impl ApkCheck {
    /// Step 9(a): read the end-of-central-directory record from the file's last 22 bytes.
    /// `length` is the file's length (Kotlin knows it from the download/staging row), and
    /// `release_index` the offered release's index in `manifest` (its attestation block is
    /// part of the step-10 binding).
    pub fn begin(
        release_index: usize,
        release: Release,
        manifest: GHRM,
        root: GHRT,
        sdk: u8,
        length: u64,
        tail: &[u8; EOCD_LEN],
    ) -> Result<(Self, Need), UpdateError> {
        if length < EOCD_LEN as u64 + 16 + 8 + 8 {
            return Err(UpdateError::ApkLayout);
        }
        if &tail[..4] != b"PK\x05\x06" {
            return Err(UpdateError::ApkLayout);
        }
        if le16(&tail[20..22]) != 0 {
            return Err(UpdateError::ApkLayout); // comment length must be 0
        }
        if le16(&tail[4..6]) != 0 || le16(&tail[6..8]) != 0 {
            return Err(UpdateError::ApkLayout); // a single disk, no ZIP64 EOCD
        }
        let cd_size = le32(&tail[12..16]) as u64;
        let cd_offset = le32(&tail[16..20]) as u64;
        if cd_offset + cd_size + EOCD_LEN as u64 != length {
            return Err(UpdateError::ApkLayout);
        }
        let this = ApkCheck {
            release_index,
            release,
            manifest,
            root,
            sdk,
            length,
            cd_offset,
            cd_size,
            e: 0,
            b: 0,
            tail: *tail,
            full: Sha256::new(),
            core: Sha256::new(),
            block: Vec::new(),
            next: 0,
            footer_seen: false,
        };
        let need = Need::Footer {
            offset: cd_offset - 24,
        };
        Ok((this, need))
    }

    /// Steps 9(b), 9(c): the 24 bytes before `cd_offset` — the block footer with its size
    /// field and magic. Computes E and B and the padding-alignment rule.
    pub fn footer(&mut self, bytes: &[u8; 24]) -> Result<(), UpdateError> {
        if self.footer_seen {
            return Err(UpdateError::OutOfOrder);
        }
        if &bytes[8..24] != SIG_MAGIC {
            return Err(UpdateError::ApkLayout);
        }
        let s = le64(&bytes[..8]);
        let block_start = self
            .cd_offset
            .checked_sub(8)
            .and_then(|x| x.checked_sub(s))
            .ok_or(UpdateError::ApkLayout)
            .map_err(|e| {
                e
            })?;
        if block_start + 8 > self.cd_offset - 24 {
            return Err(UpdateError::ApkLayout);
        }
        // E and the §6.5 rule (unsigned_length comes from the offered release).
        let e = self
            .release
            .unsigned_length
            .checked_sub(self.cd_size)
            .and_then(|x| x.checked_sub(EOCD_LEN as u64))
            .ok_or(UpdateError::ApkLayout)?;
        // MC-D21 (the `mutants` feature, host libraries only): the block is located from the
        // release's unsigned length, not from the file's footer — the padding is treated as
        // block. The selector's default keeps the file-derived rule.
        #[cfg(feature = "mutants")]
        let b = if crate::mutants::active(crate::mutants::BLOCK_FROM_MANIFEST) {
            e
        } else {
            block_start
        };
        #[cfg(not(feature = "mutants"))]
        let b = block_start;
        if !(0 < e && e <= b) || b != e + ((PAGE - e % PAGE) % PAGE) {
            return Err(UpdateError::ApkLayout);
        }
        self.e = e;
        self.b = b;
        self.footer_seen = true;
        Ok(())
    }

    /// Steps 9(d), 9(e): the body in order — `[0, cd_offset + cd_size)`, i.e. everything
    /// before the end record. The whole-file hash takes every byte; the core hash takes
    /// `[0, E)` and the central directory; the signing block is buffered for `finish`.
    pub fn update(&mut self, offset: u64, chunk: &[u8]) -> Result<(), UpdateError> {
        if !self.footer_seen {
            return Err(UpdateError::OutOfOrder);
        }
        let body_end = self.cd_offset + self.cd_size;
        if offset != self.next || offset + chunk.len() as u64 > body_end {
            return Err(UpdateError::OutOfOrder);
        }
        // Split the chunk at the region boundaries and hash each span once.
        let mut pos = offset;
        let mut rest = chunk;
        let boundaries = [self.e, self.b, self.cd_offset, body_end];
        for boundary in boundaries {
            if pos >= boundary {
                continue;
            }
            let take = ((boundary - pos) as usize).min(rest.len());
            let (head, tail) = rest.split_at(take);
            match pos {
                p if p < self.e || p >= self.cd_offset => {
                    self.full.update(head);
                    self.core.update(head);
                }
                p if p < self.b => {
                    if head.iter().any(|&x| x != 0) {
                        return Err(UpdateError::ApkLayout);
                    }
                    // MC-D26 (the `mutants` feature, host libraries only): the core is "the
                    // file minus the block" — the padding is hashed into it. The selector's
                    // default keeps the padding out of the core.
                    #[cfg(feature = "mutants")]
                    if crate::mutants::active(crate::mutants::CORE_MINUS_BLOCK) {
                        self.core.update(head);
                    }
                    self.full.update(head);
                }
                _ => {
                    self.block.extend_from_slice(head);
                    self.full.update(head);
                }
            }
            pos += take as u64;
            rest = tail;
            if rest.is_empty() {
                break;
            }
        }
        self.next = pos;
        Ok(())
    }

    /// Step 10: hash comparisons, the signer selection and the attestation clause. The file
    /// must have been consumed exactly to `cd_offset + cd_size` (the end record itself was
    /// given to `begin`).
    pub fn finish(self) -> Result<(), UpdateError> {
        if !self.footer_seen || self.next != self.cd_offset + self.cd_size {
            return Err(UpdateError::OutOfOrder);
        }
        if self.length != self.release.apk_length {
            return Err(UpdateError::ApkLength);
        }
        // Whole-file SHA-256: streamed bytes + the end record. MC-D14 (the `mutants` feature,
        // host libraries only): the whole-file hash is not compared — swapped bytes pass. The
        // selector's default keeps the shipped check.
        #[cfg(feature = "mutants")]
        let full_hash_checked = !crate::mutants::active(crate::mutants::FULL_HASH_SKIPPED);
        #[cfg(not(feature = "mutants"))]
        let full_hash_checked = true;
        let mut full = self.full;
        full.update(self.tail);
        let full: [u8; 32] = full.finalize().into();
        if full_hash_checked && full != self.release.apk_sha256 {
            return Err(UpdateError::ApkHash);
        }
        // Core: [0, E) and the central directory, end record with its cd-offset field set to E.
        let mut core_tail = self.tail;
        core_tail[16..20].copy_from_slice(&(self.e as u32).to_le_bytes());
        let mut core = self.core;
        core.update(core_tail);
        let core: [u8; 32] = core.finalize().into();
        // MC-D15 (the `mutants` feature, host libraries only): the core comparison and the
        // attestation clause are skipped. The selector's default keeps the shipped checks.
        #[cfg(feature = "mutants")]
        let core_attestation_checked = !crate::mutants::active(crate::mutants::CORE_ATTESTATION_SKIPPED);
        #[cfg(not(feature = "mutants"))]
        let core_attestation_checked = true;
        if core_attestation_checked
            && (self.release.unsigned_length != self.cd_size + EOCD_LEN as u64 + self.e
                || core != self.release.unsigned_sha256)
        {
            return Err(UpdateError::ApkCore);
        }
        // MC-D27 (the `mutants` feature, host libraries only): the signer is read from the
        // v3.1 block whatever the SDK — the [minSdk, maxSdk] window is ignored. The selector's
        // default keeps the shipped selection.
        #[cfg(feature = "mutants")]
        let sdk = if crate::mutants::active(crate::mutants::SIGNER_FROM_V31) {
            u32::MAX as u8
        } else {
            self.sdk
        };
        #[cfg(not(feature = "mutants"))]
        let sdk = self.sdk;
        let signer = signer_digest(&self.block, sdk)?;
        if !self.root.body.apk_signers.contains(&signer) {
            return Err(UpdateError::ApkSigner);
        }
        if !core_attestation_checked {
            return Ok(());
        }
        let index = self.release_index;
        let at = self
            .manifest
            .attestations
            .get(index)
            .ok_or(UpdateError::AttestationQuorum)?;
        at.meets(
            &self.root.body.attest.keys,
            self.root.body.attest.threshold,
            &ghost_client_release::statement_bytes(
                ghost_client_release::StatementType::BuildAttestation,
                self.manifest.body.network,
                &self.release.attestation(self.manifest.body.network).to_bytes(),
            ),
        )
        .map_err(|_| UpdateError::AttestationQuorum)
    }
}

/// Steps 9–10 over a whole in-memory file (the staging re-check and the tests).
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
    if file.len() < EOCD_LEN + 24 {
        return Err(UpdateError::ApkLayout);
    }
    let n = file.len();
    let tail: [u8; EOCD_LEN] = file[n - EOCD_LEN..].try_into().expect("22 bytes");
    let (mut check, need) = ApkCheck::begin(
        release_index,
        release.clone(),
        manifest.clone(),
        r.clone(),
        sdk,
        n as u64,
        &tail,
    )?;
    let Need::Footer { offset } = need;
    let footer: [u8; 24] = file[offset as usize..offset as usize + 24]
        .try_into()
        .expect("24 bytes");
    check.footer(&footer)?;
    check.update(0, &file[..n - EOCD_LEN])?;
    check.finish()
}

/// The one-shot signer digest of a whole in-memory file (`ghost-verify`'s `signer=` line): the
/// SHA-256 of the certificate the platform would select at `sdk`, per the §9(e) rule.
pub fn signer_digest_of(file: &[u8], sdk: u8) -> Result<[u8; 32], UpdateError> {
    if file.len() < EOCD_LEN + 24 {
        return Err(UpdateError::ApkLayout);
    }
    let n = file.len();
    let tail = &file[n - EOCD_LEN..];
    if &tail[..4] != b"PK" {
        return Err(UpdateError::ApkLayout);
    }
    let cd_offset = le32(&tail[16..20]) as usize;
    if cd_offset < 24 || cd_offset > n - EOCD_LEN {
        return Err(UpdateError::ApkLayout);
    }
    let footer = cd_offset - 24;
    if &file[footer + 8..footer + 24] != SIG_MAGIC {
        return Err(UpdateError::ApkLayout);
    }
    let s = le64(&file[footer..footer + 8]);
    let block_start = cd_offset
        .checked_sub(8)
        .and_then(|x| x.checked_sub(s as usize))
        .ok_or(UpdateError::ApkLayout)?;
    signer_digest(&file[block_start..cd_offset], sdk)
}

/// The block ids present in a signed APK (the `blocks=` vocabulary), for tests and reports.
pub fn block_ids(file: &[u8]) -> Result<Vec<u32>, UpdateError> {
    if file.len() < EOCD_LEN + 24 {
        return Err(UpdateError::ApkLayout);
    }
    let n = file.len();
    let tail = &file[n - EOCD_LEN..];
    if &tail[..4] != b"PK\x05\x06" {
        return Err(UpdateError::ApkLayout);
    }
    let cd_offset = le32(&tail[16..20]) as usize;
    if cd_offset < 24 {
        return Err(UpdateError::ApkLayout);
    }
    let footer = cd_offset - 24;
    if &file[footer + 8..footer + 24] != SIG_MAGIC {
        return Err(UpdateError::ApkLayout);
    }
    let s = le64(&file[footer..footer + 8]);
    let block_start = cd_offset
        .checked_sub(8)
        .and_then(|x| x.checked_sub(s as usize))
        .ok_or(UpdateError::ApkLayout)?;
    let mut ids = Vec::new();
    let mut pos = block_start + 8;
    while pos + 12 <= footer {
        let len = le64(&file[pos..pos + 8]) as usize;
        ids.push(le32(&file[pos + 8..pos + 12]));
        pos = pos.checked_add(12).and_then(|x| x.checked_add(len)).ok_or(UpdateError::ApkLayout)?;
    }
    if pos != footer {
        return Err(UpdateError::ApkLayout);
    }
    Ok(ids)
}

/// Step 9e: the signer the platform uses at this SDK — v3.1 whose [minSdk, maxSdk] contains
/// the SDK, else v3's, else v2's — and the SHA-256 of its first certificate. `block` is the
/// raw signing block: [size u64][pairs][size u64][magic(16)].
fn signer_digest(block: &[u8], sdk: u8) -> Result<[u8; 32], UpdateError> {
    if block.len() < 8 + 24 + 16 {
        return Err(UpdateError::ApkLayout);
    }
    let s = le64(&block[..8]);
    // The block is [size u64][pairs][size u64][magic]: `s` counts everything after the
    // first size field, so the total is s + 8.
    if block.len() as u64 != s + 8 || &block[block.len() - 16..] != SIG_MAGIC {
        return Err(UpdateError::ApkLayout);
    }
    let s2 = le64(&block[block.len() - 24..block.len() - 16]);
    if s != s2 {
        return Err(UpdateError::ApkLayout);
    }
    let pairs_region = &block[8..block.len() - 24];
    let mut pairs: Vec<(u32, &[u8])> = Vec::new();
    let mut pos = 0usize;
    while pos + 12 <= pairs_region.len() {
        // The pair size counts the id AND the value (the spec excludes only the size field);
        // apksigner 37 also prepends a verity padding pair (0x7109871a), which a value-only
        // reading desynchronizes on — the emulator drill caught this against real apksigner
        // output (ghost-release-ops' apkcore walks the same region correctly, pos += 8 + len).
        let len = le64(&pairs_region[pos..pos + 8]) as usize;
        let id = le32(&pairs_region[pos + 8..pos + 12]);
        let value_len = len.checked_sub(4).ok_or(UpdateError::ApkLayout)?;
        let start = pos + 12;
        let end = start.checked_add(value_len).ok_or(UpdateError::ApkLayout)?;
        if end > pairs_region.len() {
            return Err(UpdateError::ApkLayout);
        }
        pairs.push((id, &pairs_region[start..end]));
        pos += 8 + len;
    }
    if pos != pairs_region.len() {
        return Err(UpdateError::ApkLayout);
    }
    let sdk = u32::from(sdk);
    let find = |id: u32, v3_layout: bool| -> Option<Signer> {
        pairs
            .iter()
            .find(|(pid, _)| *pid == id)
            .and_then(|(_, value)| first_signer(value, v3_layout).ok())
    };
    for id in [ID_V31, ID_V3] {
        if let Some(s) = find(id, true) {
            if s.min_sdk <= sdk && sdk <= s.max_sdk {
                return Ok(sha256(&s.cert));
            }
        }
    }
    if let Some(s) = find(ID_V2, false) {
        return Ok(sha256(&s.cert));
    }
    Err(UpdateError::ApkSigner)
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
    // value = [lp32 signers]; signers = [lp32 signer]… (the signers sequence is length-prefixed,
    // and each signer inside it is too — apksigner's real output carries BOTH levels; missing
    // the inner one misreads the signer length as the signed-data length and dies at the
    // signatures field — caught by the emulator drill against apksigner 37.0.0 output).
    let mut top = Cursor::new(value);
    let signers = top.lp32()?;
    top.done().map_err(|_| UpdateError::ApkSigner)?;
    let mut c = Cursor::new(signers);
    let signer = c.lp32()?;
    let mut s = Cursor::new(signer);
    let signed = s.lp32()?;
    s.lp32()?; // signatures (not checked: the platform verifies them)
    s.lp32()?; // public key
    // No `done()` here: v3.1 signers carry additional attributes after the public key in
    // real apksigner 37 output (the lineage drill's crafted suite caught the strict reader
    // refusing rotated APKs at APK_SIGNER); the platform's parser is lenient about them, and
    // this reader takes the first signer only. The outer `top.done()` still pins the value. 
    let mut d = Cursor::new(signed);
    d.lp32()?; // digests
    let certs = d.lp32()?;
    let (min_sdk, max_sdk) = if v3_layout {
        (le32(d.take(4)?), le32(d.take(4)?))
    } else {
        (0, SDK_MAX)
    };
    // The first certificate, lengths only.
    let mut cc = Cursor::new(certs);
    let cert = cc.lp32()?.to_vec();
    Ok(Signer { min_sdk, max_sdk, cert })
}
