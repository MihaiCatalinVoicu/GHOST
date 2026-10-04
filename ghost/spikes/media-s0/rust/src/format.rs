//! Reference implementation of the media object of design §3 (constants, keys, chunks and
//! fragments, manifest, classes, sealer discipline), the MEDIA descriptor of §4.1 and `key_env` of
//! §4.2, written from the design text alone. S0 evidence tooling: it exists to find out whether
//! the text is implementable exactly as written and to produce the §3.9 vectors that S1's
//! `ghost-client-media` and the independent JDK implementation must replay.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::BTreeSet;

/// Relay blob size of every media blob (§3.1).
pub const FRAG: usize = 65_536;
/// Poly1305 tag.
pub const TAG: usize = 16;
/// Ciphertext of one chunk.
pub const CHUNK_CT: usize = 4 * FRAG;
/// Plaintext of one chunk.
pub const CHUNK_PT: usize = CHUNK_CT - TAG;
/// Fragment counts `F` per class code.
pub const CLASSES: [usize; 11] = [16, 24, 36, 56, 84, 128, 192, 288, 432, 648, 804];
/// 50 MiB.
pub const MAX_CONTENT: u64 = 52_428_800;
/// Every image fits class 0.
pub const IMAGE_MAX_CONTENT: u64 = 4 * CHUNK_PT as u64;
/// The commitment at the head of the manifest blob.
pub const COMMIT_BYTES: usize = 32;
/// `|MP|` = 65 488.
pub const MANIFEST_PT: usize = FRAG - COMMIT_BYTES - TAG;
/// Offset of the preview in `MP` (§3.5 table).
pub const PREVIEW_OFFSET: usize = 38;
/// Largest preview.
pub const PREVIEW_MAX: usize = 32_768;
/// Offset of the hash list in `MP` (32 806).
pub const HASHES_OFFSET: usize = PREVIEW_OFFSET + PREVIEW_MAX;
/// `VIDEO_MAX_MS` of §6.1.
pub const VIDEO_MAX_MS: u32 = 160_000;
/// Largest caption (§4.1).
pub const MAX_CAPTION_BYTES: usize = 1_024;
/// Fixed part of the MEDIA descriptor body (§4.1).
pub const DESCRIPTOR_FIXED: usize = 86;

pub const KIND_IMAGE: u8 = 0x01;
pub const KIND_VIDEO: u8 = 0x02;
pub const FLAG_VIEW_ONCE: u8 = 0x01;
pub const ROLE_OUT: u8 = 0x01;
pub const ROLE_IN: u8 = 0x02;

/// HKDF info labels (§3.2).
pub const LABEL_PAYLOAD: &[u8] = b"ghost/v1/media/payload";
pub const LABEL_MANIFEST: &[u8] = b"ghost/v1/media/manifest";
pub const LABEL_COMMIT: &[u8] = b"ghost/v1/media/commit";
/// Associated-data prefixes (§3.3, §3.5). Review I13 (2026-10-04): under `ghost/v1/media/ad/`, so
/// that no label of the format is a prefix of another (the 2026-09-25 spike used
/// `ghost/v1/media/manifest`, the HKDF info of `K_m`, as `AD_m`'s prefix too).
pub const AD_CHUNK: &[u8] = b"ghost/v1/media/ad/chunk";
pub const AD_MANIFEST: &[u8] = b"ghost/v1/media/ad/manifest";
/// `op_id` label (§6.4).
pub const LABEL_OP: &[u8] = b"ghost/v1/media/op";
/// Wrap prefix and name of `key_env` (§4.2, F9 §2.5).
pub const WRAP_LABEL: &[u8] = b"ghost/v1/wrap/";
pub const WRAP_NAME_MEDIA_FILE_KEY: &[u8] = b"media-file-key";

/// The typed codes of §13.2 that the format itself can produce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
    NotOpen,
    CommitMismatch,
    HashMismatch,
    NonCanonical,
    IndexRange,
    IndexReused,
    Oversize,
    StateCorrupt,
}

/// `K_p`, `K_m` and the commitment of one object (§3.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectKeys {
    pub k_p: [u8; 32],
    pub k_m: [u8; 32],
    pub commit: [u8; 32],
}

/// §3.2: HKDF-SHA256 with `ikm = K_f`, `salt = object_id`.
pub fn derive(k_f: &[u8; 32], object_id: &[u8; 16]) -> ObjectKeys {
    let hk = Hkdf::<Sha256>::new(Some(object_id), k_f);
    let mut k_p = [0u8; 32];
    let mut k_m = [0u8; 32];
    let mut commit = [0u8; 32];
    hk.expand(LABEL_PAYLOAD, &mut k_p).expect("32 <= 255 * 32");
    hk.expand(LABEL_MANIFEST, &mut k_m).expect("32 <= 255 * 32");
    hk.expand(LABEL_COMMIT, &mut commit)
        .expect("32 <= 255 * 32");
    ObjectKeys { k_p, k_m, commit }
}

/// `class(L) = min{F : (F/4)·262 128 ≥ L}` as a class code; `None` for `L = 0` or `L > MAX_CONTENT`.
pub fn class_code_for(len: u64) -> Option<u8> {
    if len == 0 || len > MAX_CONTENT {
        return None;
    }
    CLASSES
        .iter()
        .position(|&f| (f as u64 / 4) * CHUNK_PT as u64 >= len)
        .map(|p| p as u8)
}

/// Largest content of a class (`(F/4)·CHUNK_PT`, before the 50 MiB cap).
pub fn class_capacity(code: u8) -> u64 {
    (CLASSES[code as usize] as u64 / 4) * CHUNK_PT as u64
}

/// §3.3: `0x00^7 ‖ u32_be(i) ‖ u8(last)`.
pub fn chunk_nonce(i: u32, last: bool) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[7..11].copy_from_slice(&i.to_be_bytes());
    n[11] = last as u8;
    n
}

/// §3.3: `"ghost/v1/media/ad/chunk" ‖ 0x01 ‖ object_id ‖ u8(kind)`.
pub fn chunk_ad(object_id: &[u8; 16], kind: u8) -> Vec<u8> {
    let mut ad = Vec::with_capacity(AD_CHUNK.len() + 18);
    ad.extend_from_slice(AD_CHUNK);
    ad.push(0x01);
    ad.extend_from_slice(object_id);
    ad.push(kind);
    ad
}

/// §3.5: `"ghost/v1/media/ad/manifest" ‖ 0x01 ‖ object_id ‖ commit`.
pub fn manifest_ad(object_id: &[u8; 16], commit: &[u8; 32]) -> Vec<u8> {
    let mut ad = Vec::with_capacity(AD_MANIFEST.len() + 49);
    ad.extend_from_slice(AD_MANIFEST);
    ad.push(0x01);
    ad.extend_from_slice(object_id);
    ad.extend_from_slice(commit);
    ad
}

/// Seals one chunk: `ChaCha20-Poly1305(K_p, nonce_i, AD_c, P_i)`, `|P_i| = CHUNK_PT`.
pub fn seal_chunk(
    k_p: &[u8; 32],
    object_id: &[u8; 16],
    kind: u8,
    i: u32,
    last: bool,
    pt: &[u8],
) -> Vec<u8> {
    assert_eq!(pt.len(), CHUNK_PT, "a chunk is always full");
    let cipher = ChaCha20Poly1305::new(k_p.into());
    let nonce = chunk_nonce(i, last);
    cipher
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: pt,
                aad: &chunk_ad(object_id, kind),
            },
        )
        .expect("chunk within the ChaCha20-Poly1305 limit")
}

/// Splits one chunk ciphertext into its four headerless fragments (§3.3).
pub fn fragments_of(chunk_ct: &[u8]) -> Vec<Vec<u8>> {
    assert_eq!(chunk_ct.len(), CHUNK_CT);
    chunk_ct.chunks(FRAG).map(|f| f.to_vec()).collect()
}

/// What the stream walker reports to the sealer and the reader (§3.5: Kotlin supplies none of it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamFacts {
    pub width: u16,
    pub height: u16,
    pub duration_ms: u32,
}

/// D29 geometry of an object (not of a preview, whose long edge is 320).
pub fn object_geometry_ok(kind: u8, w: u16, h: u16) -> bool {
    match kind {
        KIND_IMAGE => {
            let (long, short) = if w >= h { (w, h) } else { (h, w) };
            matches!(long, 512 | 1024 | 2048) && short >= 16 && short % 16 == 0 && short <= long
        }
        KIND_VIDEO => (w, h) == (1280, 720) || (w, h) == (720, 1280),
        _ => false,
    }
}

/// D29 geometry of a preview: long edge 320, short edge a multiple of 16 in 16 … 320.
pub fn preview_geometry_ok(w: u16, h: u16) -> bool {
    let (long, short) = if w >= h { (w, h) } else { (h, w) };
    long == 320 && short >= 16 && short % 16 == 0
}

/// The decrypted manifest `MP` (§3.5 table).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub kind: u8,
    pub flags: u8,
    pub class_code: u8,
    pub object_id: [u8; 16],
    pub content_len: u64,
    pub width: u16,
    pub height: u16,
    pub duration_ms: u32,
    pub preview: Vec<u8>,
    pub hashes: Vec<[u8; 32]>,
}

impl Manifest {
    /// Every rule of the §3.5 table that the manifest alone can check.
    pub fn check(&self) -> Result<(), Code> {
        let nc = Err(Code::NonCanonical);
        if !(self.kind == KIND_IMAGE || self.kind == KIND_VIDEO)
            || self.flags & !FLAG_VIEW_ONCE != 0
        {
            return nc;
        }
        if self.class_code > 10 || (self.kind == KIND_IMAGE && self.class_code != 0) {
            return nc;
        }
        let f = CLASSES[self.class_code as usize];
        let cap = class_capacity(self.class_code).min(MAX_CONTENT);
        if self.content_len < 1
            || self.content_len > cap
            || class_code_for(self.content_len) != Some(self.class_code)
        {
            return nc;
        }
        if self.kind == KIND_IMAGE && self.content_len > IMAGE_MAX_CONTENT {
            return nc;
        }
        if !object_geometry_ok(self.kind, self.width, self.height) {
            return nc;
        }
        match self.kind {
            KIND_IMAGE if self.duration_ms != 0 => return nc,
            KIND_VIDEO if self.duration_ms == 0 || self.duration_ms > VIDEO_MAX_MS => return nc,
            _ => {}
        }
        if self.preview.len() > PREVIEW_MAX
            || (self.flags & FLAG_VIEW_ONCE != 0 && !self.preview.is_empty())
        {
            return nc;
        }
        if self.hashes.len() != f {
            return nc;
        }
        let distinct: BTreeSet<&[u8; 32]> = self.hashes.iter().collect();
        if distinct.len() != f {
            return nc;
        }
        Ok(())
    }

    /// Encodes `MP` (65 488 B) after checking every rule.
    pub fn encode(&self) -> Result<Vec<u8>, Code> {
        self.check()?;
        let mut mp = vec![0u8; MANIFEST_PT];
        mp[0] = 0x01;
        mp[1] = self.kind;
        mp[2] = self.flags;
        mp[3] = self.class_code;
        mp[4..20].copy_from_slice(&self.object_id);
        mp[20..28].copy_from_slice(&self.content_len.to_be_bytes());
        mp[28..30].copy_from_slice(&self.width.to_be_bytes());
        mp[30..32].copy_from_slice(&self.height.to_be_bytes());
        mp[32..36].copy_from_slice(&self.duration_ms.to_be_bytes());
        mp[36..38].copy_from_slice(&(self.preview.len() as u16).to_be_bytes());
        mp[PREVIEW_OFFSET..PREVIEW_OFFSET + self.preview.len()].copy_from_slice(&self.preview);
        for (j, h) in self.hashes.iter().enumerate() {
            mp[HASHES_OFFSET + 32 * j..HASHES_OFFSET + 32 * (j + 1)].copy_from_slice(h);
        }
        Ok(mp)
    }

    /// Strict parse of `MP`: every rule, the zero preview pad and the zero tail.
    pub fn decode(mp: &[u8]) -> Result<Manifest, Code> {
        let nc = Err(Code::NonCanonical);
        if mp.len() != MANIFEST_PT || mp[0] != 0x01 {
            return nc;
        }
        let class_code = mp[3];
        if class_code > 10 {
            return nc;
        }
        let f = CLASSES[class_code as usize];
        let preview_len = u16::from_be_bytes([mp[36], mp[37]]) as usize;
        if preview_len > PREVIEW_MAX {
            return nc;
        }
        if mp[PREVIEW_OFFSET + preview_len..HASHES_OFFSET]
            .iter()
            .any(|&b| b != 0)
        {
            return nc;
        }
        let tail = HASHES_OFFSET + 32 * f;
        if mp[tail..].iter().any(|&b| b != 0) {
            return nc;
        }
        let mut object_id = [0u8; 16];
        object_id.copy_from_slice(&mp[4..20]);
        let m = Manifest {
            kind: mp[1],
            flags: mp[2],
            class_code,
            object_id,
            content_len: u64::from_be_bytes(mp[20..28].try_into().expect("8")),
            width: u16::from_be_bytes([mp[28], mp[29]]),
            height: u16::from_be_bytes([mp[30], mp[31]]),
            duration_ms: u32::from_be_bytes(mp[32..36].try_into().expect("4")),
            preview: mp[PREVIEW_OFFSET..PREVIEW_OFFSET + preview_len].to_vec(),
            hashes: (0..f)
                .map(|j| {
                    mp[HASHES_OFFSET + 32 * j..HASHES_OFFSET + 32 * (j + 1)]
                        .try_into()
                        .expect("32")
                })
                .collect(),
        };
        m.check()?;
        Ok(m)
    }
}

/// `commit ‖ ChaCha20-Poly1305(K_m, 0^12, AD_m, MP)` (§3.5).
pub fn seal_manifest(keys: &ObjectKeys, object_id: &[u8; 16], mp: &[u8]) -> Vec<u8> {
    assert_eq!(mp.len(), MANIFEST_PT);
    let cipher = ChaCha20Poly1305::new((&keys.k_m).into());
    let ct = cipher
        .encrypt(
            &Nonce::from([0u8; 12]),
            Payload {
                msg: mp,
                aad: &manifest_ad(object_id, &keys.commit),
            },
        )
        .expect("manifest within the limit");
    let mut blob = Vec::with_capacity(FRAG);
    blob.extend_from_slice(&keys.commit);
    blob.extend_from_slice(&ct);
    assert_eq!(blob.len(), FRAG);
    blob
}

/// The sealed result of one object.
#[derive(Clone, Debug)]
pub struct SealedObject {
    pub class_code: u8,
    pub content_len: u64,
    /// Every fragment, ordinal 0 … F − 1.
    pub fragments: Vec<Vec<u8>>,
    pub manifest_blob: Vec<u8>,
    pub manifest_hash: [u8; 32],
    pub manifest: Manifest,
}

/// The native sealer of §3.7: one pass with a one-chunk lookahead, an index registry, the running
/// hash list; `finish` learns `content_len`, computes `F` and seals the held chunk and the zero
/// padding chunks with the last flag on index `n − 1` only.
pub struct Sealer {
    keys: ObjectKeys,
    object_id: [u8; 16],
    kind: u8,
    flags: u8,
    max_class: u8,
    held: Vec<u8>,
    index: u32,
    total: u64,
    fragments: Vec<Vec<u8>>,
    keep_fragments: bool,
    hashes: Vec<[u8; 32]>,
    used: BTreeSet<u32>,
    /// Every `(SHA-256(K_p), nonce)` this sealer used: the `nonce-registry` feature of §3.7 point 5.
    pub nonce_log: Vec<([u8; 32], [u8; 12])>,
}

impl Sealer {
    /// `sealBegin` (M1) with a given `K_f` (`testSealBeginWithKey` of §13.2; production draws it).
    pub fn begin(
        k_f: &[u8; 32],
        object_id: &[u8; 16],
        kind: u8,
        flags: u8,
        max_class: u8,
    ) -> Sealer {
        Sealer {
            keys: derive(k_f, object_id),
            object_id: *object_id,
            kind,
            flags,
            max_class,
            held: Vec::with_capacity(CHUNK_PT),
            index: 0,
            total: 0,
            fragments: Vec::new(),
            keep_fragments: true,
            hashes: Vec::new(),
            used: BTreeSet::new(),
            nonce_log: Vec::new(),
        }
    }

    fn limit(&self) -> u64 {
        let class_cap = class_capacity(self.max_class).min(MAX_CONTENT);
        if self.kind == KIND_IMAGE {
            class_cap.min(IMAGE_MAX_CONTENT)
        } else {
            class_cap
        }
    }

    /// Seals index `i` once; a second attempt is `INDEX_REUSED`.
    pub fn seal_index(&mut self, i: u32, last: bool, pt: &[u8]) -> Result<usize, Code> {
        if !self.used.insert(i) {
            return Err(Code::IndexReused);
        }
        let mut full = vec![0u8; CHUNK_PT];
        full[..pt.len()].copy_from_slice(pt);
        let ct = seal_chunk(&self.keys.k_p, &self.object_id, self.kind, i, last, &full);
        self.nonce_log
            .push((crate::sha256(&self.keys.k_p), chunk_nonce(i, last)));
        let mut n = 0;
        for f in fragments_of(&ct) {
            self.hashes.push(crate::sha256(&f));
            if self.keep_fragments {
                self.fragments.push(f);
            }
            n += 1;
        }
        Ok(n)
    }

    /// The product's shape: fragments leave the sealer at once (written to files by Kotlin), so
    /// only the hash list and one held chunk stay in memory (bench only; `fragments` stays empty).
    pub fn streaming(mut self) -> Sealer {
        self.keep_fragments = false;
        self
    }

    /// `sealAppend` (M2): returns how many fragments this call completed.
    pub fn append(&mut self, mut data: &[u8]) -> Result<usize, Code> {
        if self.total + data.len() as u64 > self.limit() {
            return Err(Code::Oversize);
        }
        let mut sealed = 0;
        while !data.is_empty() {
            if self.held.len() == CHUNK_PT {
                // Chunk `index + 1` begins now, so `index` is not the last chunk.
                let held = std::mem::take(&mut self.held);
                sealed += self.seal_index(self.index, false, &held)?;
                self.index += 1;
                self.held = Vec::with_capacity(CHUNK_PT);
            }
            let take = (CHUNK_PT - self.held.len()).min(data.len());
            self.held.extend_from_slice(&data[..take]);
            self.total += take as u64;
            data = &data[take..];
        }
        Ok(sealed)
    }

    /// `sealFinish` (M3).
    pub fn finish(mut self, facts: StreamFacts, preview: &[u8]) -> Result<SealedObject, Code> {
        let class_code = class_code_for(self.total).ok_or(Code::Oversize)?;
        if class_code > self.max_class {
            return Err(Code::Oversize);
        }
        let n = (CLASSES[class_code as usize] / 4) as u32;
        let held = std::mem::take(&mut self.held);
        self.seal_index(self.index, self.index == n - 1, &held)?;
        for j in self.index + 1..n {
            self.seal_index(j, j == n - 1, &[])?;
        }
        let manifest = Manifest {
            kind: self.kind,
            flags: self.flags,
            class_code,
            object_id: self.object_id,
            content_len: self.total,
            width: facts.width,
            height: facts.height,
            duration_ms: facts.duration_ms,
            preview: preview.to_vec(),
            hashes: self.hashes.clone(),
        };
        let mp = manifest.encode()?;
        let manifest_blob = seal_manifest(&self.keys, &self.object_id, &mp);
        let manifest_hash = crate::sha256(&manifest_blob);
        Ok(SealedObject {
            class_code,
            content_len: self.total,
            fragments: self.fragments,
            manifest_blob,
            manifest_hash,
            manifest,
        })
    }
}

/// Convenience: seals `content` through the streaming sealer in pieces of `piece` bytes.
#[allow(clippy::too_many_arguments)]
pub fn seal_object(
    k_f: &[u8; 32],
    object_id: &[u8; 16],
    kind: u8,
    flags: u8,
    content: &[u8],
    facts: StreamFacts,
    preview: &[u8],
    piece: usize,
) -> Result<SealedObject, Code> {
    let mut s = Sealer::begin(k_f, object_id, kind, flags, 10);
    for p in content.chunks(piece.max(1)) {
        s.append(p)?;
    }
    s.finish(facts, preview)
}

/// The fields of a MEDIA descriptor a reader compares with the manifest (§7.2 `MEDIA-BIND`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Descriptor {
    pub kind: u8,
    pub flags: u8,
    pub class_code: u8,
    pub object_id: [u8; 16],
    pub key_slot: [u8; 32],
    pub manifest_hash: [u8; 32],
    pub caption: Vec<u8>,
}

impl Descriptor {
    /// §4.1 body: 86 B fixed plus the caption.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(DESCRIPTOR_FIXED + self.caption.len());
        b.push(0x01);
        b.push(self.kind);
        b.push(self.flags);
        b.push(self.class_code);
        b.extend_from_slice(&self.object_id);
        b.extend_from_slice(&self.key_slot);
        b.extend_from_slice(&self.manifest_hash);
        b.extend_from_slice(&(self.caption.len() as u16).to_be_bytes());
        b.extend_from_slice(&self.caption);
        b
    }

    /// Strict parse (R-D3); the key slot is returned as found (the zero-slot rule is the caller's).
    pub fn decode(b: &[u8]) -> Result<Descriptor, Code> {
        let nc = Err(Code::NonCanonical);
        if b.len() < DESCRIPTOR_FIXED || b[0] != 0x01 {
            return nc;
        }
        let (kind, flags, class_code) = (b[1], b[2], b[3]);
        if !(kind == KIND_IMAGE || kind == KIND_VIDEO)
            || flags & !FLAG_VIEW_ONCE != 0
            || class_code > 10
        {
            return nc;
        }
        if kind == KIND_IMAGE && class_code != 0 {
            return nc;
        }
        let caption_len = u16::from_be_bytes([b[84], b[85]]) as usize;
        if caption_len > MAX_CAPTION_BYTES || b.len() != DESCRIPTOR_FIXED + caption_len {
            return nc;
        }
        let caption = b[DESCRIPTOR_FIXED..].to_vec();
        if std::str::from_utf8(&caption).is_err() {
            return nc;
        }
        Ok(Descriptor {
            kind,
            flags,
            class_code,
            object_id: b[4..20].try_into().expect("16"),
            key_slot: b[20..52].try_into().expect("32"),
            manifest_hash: b[52..84].try_into().expect("32"),
            caption,
        })
    }
}

/// `u8(role) ‖ dest_id(16) ‖ object_id(16) ‖ manifest_hash(32)` (§4.2).
pub fn key_env_binding(
    role: u8,
    dest_id: &[u8; 16],
    object_id: &[u8; 16],
    manifest_hash: &[u8; 32],
) -> Vec<u8> {
    let mut b = Vec::with_capacity(65);
    b.push(role);
    b.extend_from_slice(dest_id);
    b.extend_from_slice(object_id);
    b.extend_from_slice(manifest_hash);
    b
}

fn wrap_ad(binding: &[u8]) -> Vec<u8> {
    let mut ad =
        Vec::with_capacity(WRAP_LABEL.len() + WRAP_NAME_MEDIA_FILE_KEY.len() + binding.len());
    ad.extend_from_slice(WRAP_LABEL);
    ad.extend_from_slice(WRAP_NAME_MEDIA_FILE_KEY);
    ad.extend_from_slice(binding);
    ad
}

/// `key_env = nonce(12) ‖ ChaCha20-Poly1305(state_key, nonce, "ghost/v1/wrap/" ‖ "media-file-key" ‖ binding, K_f)` (60 B).
pub fn wrap_key_env(
    state_key: &[u8; 32],
    nonce: &[u8; 12],
    binding: &[u8],
    k_f: &[u8; 32],
) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(state_key.into());
    let ct = cipher
        .encrypt(
            &Nonce::from(*nonce),
            Payload {
                msg: k_f,
                aad: &wrap_ad(binding),
            },
        )
        .expect("32 bytes");
    let mut env = nonce.to_vec();
    env.extend_from_slice(&ct);
    env
}

/// Opens a `key_env` under its binding; anything else is `STATE_CORRUPT` (§13.2 M5).
pub fn unwrap_key_env(state_key: &[u8; 32], binding: &[u8], env: &[u8]) -> Result<[u8; 32], Code> {
    if env.len() != 60 {
        return Err(Code::StateCorrupt);
    }
    let cipher = ChaCha20Poly1305::new(state_key.into());
    let pt = cipher
        .decrypt(
            &Nonce::from(<[u8; 12]>::try_from(&env[..12]).expect("12")),
            Payload {
                msg: &env[12..],
                aad: &wrap_ad(binding),
            },
        )
        .map_err(|_| Code::StateCorrupt)?;
    pt.as_slice().try_into().map_err(|_| Code::StateCorrupt)
}

/// A reader over one object (§13.2 M5 … M8), after `readerOpen`.
pub struct Reader {
    keys: ObjectKeys,
    pub manifest: Manifest,
}

impl Reader {
    /// `readerOpen`: manifest hash, commitment, AEAD, strict parse, descriptor comparison.
    pub fn open(k_f: &[u8; 32], desc: &Descriptor, manifest_blob: &[u8]) -> Result<Reader, Code> {
        if manifest_blob.len() != FRAG {
            return Err(Code::NonCanonical);
        }
        if crate::sha256(manifest_blob) != desc.manifest_hash {
            return Err(Code::HashMismatch);
        }
        let keys = derive(k_f, &desc.object_id);
        if manifest_blob[..COMMIT_BYTES] != keys.commit {
            return Err(Code::CommitMismatch);
        }
        let cipher = ChaCha20Poly1305::new((&keys.k_m).into());
        let mp = cipher
            .decrypt(
                &Nonce::from([0u8; 12]),
                Payload {
                    msg: &manifest_blob[COMMIT_BYTES..],
                    aad: &manifest_ad(&desc.object_id, &keys.commit),
                },
            )
            .map_err(|_| Code::NotOpen)?;
        let manifest = Manifest::decode(&mp)?;
        if manifest.object_id != desc.object_id
            || manifest.kind != desc.kind
            || manifest.flags != desc.flags
            || manifest.class_code != desc.class_code
        {
            return Err(Code::NonCanonical);
        }
        Ok(Reader { keys, manifest })
    }

    /// Chunks of this object.
    pub fn chunks(&self) -> u32 {
        (CLASSES[self.manifest.class_code as usize] / 4) as u32
    }

    /// `readerChunk`: hashes, tag, pad; returns the chunk's content bytes.
    pub fn read_chunk(&self, i: u32, frags: &[&[u8]]) -> Result<Vec<u8>, Code> {
        let n = self.chunks();
        if i >= n {
            return Err(Code::IndexRange);
        }
        if frags.len() != 4 || frags.iter().any(|f| f.len() != FRAG) {
            return Err(Code::NonCanonical);
        }
        for (k, f) in frags.iter().enumerate() {
            if crate::sha256(f) != self.manifest.hashes[4 * i as usize + k] {
                return Err(Code::HashMismatch);
            }
        }
        let mut ct = Vec::with_capacity(CHUNK_CT);
        for f in frags {
            ct.extend_from_slice(f);
        }
        let cipher = ChaCha20Poly1305::new((&self.keys.k_p).into());
        let nonce = chunk_nonce(i, i == n - 1);
        let pt = cipher
            .decrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: &ct,
                    aad: &chunk_ad(&self.manifest.object_id, self.manifest.kind),
                },
            )
            .map_err(|_| Code::NotOpen)?;
        let start = i as u64 * CHUNK_PT as u64;
        let content_end = self
            .manifest
            .content_len
            .saturating_sub(start)
            .min(CHUNK_PT as u64) as usize;
        if pt[content_end..].iter().any(|&b| b != 0) {
            return Err(Code::NonCanonical);
        }
        Ok(pt[..content_end].to_vec())
    }
}

/// Deterministic test content: `SHA-256(seed ‖ u32_be(i))` blocks, truncated to `len`.
pub fn sha256ctr(seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 32);
    let mut i: u32 = 0;
    while out.len() < len {
        let mut input = seed.to_vec();
        input.extend_from_slice(&i.to_be_bytes());
        out.extend_from_slice(&crate::sha256(&input));
        i += 1;
    }
    out.truncate(len);
    out
}

/// §6.4: `op_id = SHA-256("ghost/v1/media/op" ‖ object_id ‖ i16_be(ordinal) ‖ u8(retry_gen) ‖ u8(resend_count))[0..16]`.
pub fn op_id(object_id: &[u8; 16], ordinal: i16, retry_gen: u8, resend_count: u8) -> [u8; 16] {
    let mut input = LABEL_OP.to_vec();
    input.extend_from_slice(object_id);
    input.extend_from_slice(&ordinal.to_be_bytes());
    input.push(retry_gen);
    input.push(resend_count);
    crate::sha256(&input)[..16].try_into().expect("16")
}

/// Padmé (Nikitin et al., PETS 2019): rounds `l` up to a multiple of `2^(E − S)`.
pub fn padme(l: u64) -> u64 {
    if l < 2 {
        return l;
    }
    let e = 63 - l.leading_zeros() as u64; // floor(log2 l)
    let s = 64 - e.leading_zeros() as u64; // floor(log2 e) + 1
    let last_bits = e - s;
    let mask = (1u64 << last_bits) - 1;
    (l + mask) & !mask
}
