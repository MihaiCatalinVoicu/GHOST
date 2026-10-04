//! The manifest blob (design §3.5): exactly one 65 536-byte relay blob,
//!
//! ```text
//! manifest_blob = commit(32) || ChaCha20-Poly1305(K_m, nonce = 0^12, AD_m, MP)     |MP| = 65 488
//! AD_m          = "ghost/v1/media/ad/manifest" || 0x01 || object_id(16) || commit(32)
//! ```
//!
//! | Offset | Size | Field | Rule |
//! |---|---|---|---|
//! | 0 | 1 | `m_version` | `0x01` |
//! | 1 | 1 | `kind` | `0x01` image, `0x02` video |
//! | 2 | 1 | `flags` | bit 0 `view_once`; other bits 0 |
//! | 3 | 1 | `class_code` | 0 … 10; an image is class 0 |
//! | 4 | 16 | `object_id` | the descriptor's |
//! | 20 | 8 | `content_len` | `1 ≤ L ≤ cap(class)`, `class(L) = class`; an image `≤ IMAGE_MAX_CONTENT` |
//! | 28 | 2 | `width` | the canonical geometry of D29 (and, checked by the reader, the walked one) |
//! | 30 | 2 | `height` | same |
//! | 32 | 4 | `duration_ms` | 0 for an image; 1 … `VIDEO_MAX_MS` for a video (and the walked one) |
//! | 36 | 2 | `preview_len` | ≤ 32 768; 0 when `view_once` |
//! | 38 | 32 768 | `preview` | a canonical JPEG with the preview geometry, then zeros |
//! | 32 806 | 32 · F | `hashes` | SHA-256 of fragments 0 … F − 1, pairwise distinct |
//! | 32 806 + 32F | rest | zeros | |

use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, Tag};
use zeroize::Zeroizing;

use crate::bytes::{all_zero, Cursor};
use crate::class::SizeClass;
use crate::consts::{
    MediaKind, COMMIT_BYTES, FRAG, HASHES_OFFSET, HASH_BYTES, IMAGE_MAX_CONTENT, MANIFEST_PT,
    PREVIEW_MAX, TAG, VIDEO_MAX_MS,
};
use crate::error::{Code, MediaError, MediaResult};
use crate::geometry;
use crate::jpeg;
use crate::keys::{Commitment, Derived, ObjectId};
use crate::labels;

/// The manifest's version byte.
pub const M_VERSION: u8 = 0x01;

/// The fixed fields of a manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManifestFields {
    /// `kind`.
    pub kind: MediaKind,
    /// `flags` bit 0.
    pub view_once: bool,
    /// `class_code`.
    pub class: SizeClass,
    /// `object_id`.
    pub object_id: ObjectId,
    /// `content_len`.
    pub content_len: u64,
    /// `width` (displayed).
    pub width: u16,
    /// `height` (displayed).
    pub height: u16,
    /// `duration_ms`.
    pub duration_ms: u32,
}

/// A manifest: its fields, its preview and its fragment hashes.
#[derive(Clone, PartialEq, Eq)]
pub struct Manifest {
    /// The fixed fields.
    pub fields: ManifestFields,
    /// The preview (a canonical JPEG, or empty).
    pub preview: Zeroizing<Vec<u8>>,
    /// SHA-256 of fragments 0 … F − 1.
    pub hashes: Vec<[u8; HASH_BYTES]>,
}

impl core::fmt::Debug for Manifest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The preview is a picture of the content: only its length renders, so a panic payload or
        // a caught assertion never carries it.
        f.debug_struct("Manifest")
            .field("fields", &self.fields)
            .field("preview_len", &self.preview.len())
            .field("hashes", &self.hashes.len())
            .finish()
    }
}

fn nc(rule: &'static str) -> MediaError {
    MediaError::non_canonical(rule)
}

impl Manifest {
    /// Every rule of §3.5 that the manifest can be checked against by itself (the walked
    /// dimensions and duration are the reader's, §7.3).
    pub fn validate(&self) -> MediaResult<()> {
        let f = &self.fields;
        if f.kind == MediaKind::Image && f.class != SizeClass::SMALLEST {
            return Err(nc("an image whose class is not 0"));
        }
        if SizeClass::for_content_len(f.content_len) != Some(f.class) {
            return Err(nc(
                "a content_len outside its class (or 0, or above MAX_CONTENT)",
            ));
        }
        match f.kind {
            MediaKind::Image => {
                if f.content_len > IMAGE_MAX_CONTENT {
                    return Err(nc("an image above IMAGE_MAX_CONTENT"));
                }
                geometry::check_image(f.width, f.height)?;
                if f.duration_ms != 0 {
                    return Err(nc("an image with a duration"));
                }
            }
            MediaKind::Video => {
                geometry::check_video(f.width, f.height)?;
                if f.duration_ms == 0 || f.duration_ms > VIDEO_MAX_MS {
                    return Err(nc("a video duration outside 1 … VIDEO_MAX_MS"));
                }
            }
        }
        if self.preview.len() > PREVIEW_MAX {
            return Err(nc("a preview above 32 768 bytes"));
        }
        if f.view_once && !self.preview.is_empty() {
            return Err(nc("a view-once object with a preview"));
        }
        if !self.preview.is_empty() {
            let info = jpeg::check(&self.preview)?;
            geometry::check_preview(info.width, info.height)?;
        }
        if self.hashes.len() != usize::try_from(f.class.fragments()).unwrap_or(0) {
            return Err(nc("a hash list whose length is not the class's F"));
        }
        let mut sorted = self.hashes.clone();
        sorted.sort_unstable();
        if sorted.windows(2).any(|w| w.first() == w.get(1)) {
            return Err(nc("a repeated fragment hash"));
        }
        Ok(())
    }

    /// `MP`, the 65 488-byte plaintext; refuses a manifest [`Manifest::validate`] refuses.
    pub fn encode_plaintext(&self) -> MediaResult<Zeroizing<Vec<u8>>> {
        self.validate()?;
        let f = &self.fields;
        let mut mp = Zeroizing::new(Vec::with_capacity(MANIFEST_PT));
        mp.push(M_VERSION);
        mp.push(f.kind.byte());
        mp.push(u8::from(f.view_once));
        mp.push(f.class.code());
        mp.extend_from_slice(f.object_id.as_bytes());
        mp.extend_from_slice(&f.content_len.to_be_bytes());
        mp.extend_from_slice(&f.width.to_be_bytes());
        mp.extend_from_slice(&f.height.to_be_bytes());
        mp.extend_from_slice(&f.duration_ms.to_be_bytes());
        let preview_len =
            u16::try_from(self.preview.len()).map_err(|_| nc("a preview above 32 768 bytes"))?;
        mp.extend_from_slice(&preview_len.to_be_bytes());
        mp.extend_from_slice(&self.preview);
        mp.resize(HASHES_OFFSET, 0);
        for h in &self.hashes {
            mp.extend_from_slice(h);
        }
        mp.resize(MANIFEST_PT, 0);
        Ok(mp)
    }

    /// Parses `MP` strictly (§3.5): every field, the zero preview pad, the zero tail.
    pub fn decode_plaintext(mp: &[u8]) -> MediaResult<Manifest> {
        if mp.len() != MANIFEST_PT {
            return Err(nc("a manifest plaintext that is not 65 488 bytes"));
        }
        let mut c = Cursor::new(mp, "a malformed manifest");
        if c.u8()? != M_VERSION {
            return Err(nc("a manifest version other than 1"));
        }
        let kind =
            MediaKind::from_byte(c.u8()?).ok_or_else(|| nc("a manifest kind other than 1 or 2"))?;
        let flags = c.u8()?;
        if flags & !1 != 0 {
            return Err(nc("a manifest flag other than view_once"));
        }
        let class = SizeClass::from_code(c.u8()?).ok_or_else(|| nc("a class_code above 10"))?;
        let object_id = ObjectId::from_bytes(c.array()?);
        let content_len = c.u64()?;
        let width = c.u16()?;
        let height = c.u16()?;
        let duration_ms = c.u32()?;
        let preview_len = usize::from(c.u16()?);
        if preview_len > PREVIEW_MAX {
            return Err(nc("a preview above 32 768 bytes"));
        }
        let field = c.take(PREVIEW_MAX)?;
        let (preview, pad) = field.split_at(preview_len);
        if !all_zero(pad) {
            return Err(nc("a non-zero byte in the preview pad"));
        }
        let fragments = usize::try_from(class.fragments()).unwrap_or(0);
        let mut hashes = Vec::with_capacity(fragments);
        for _ in 0..fragments {
            hashes.push(c.array::<HASH_BYTES>()?);
        }
        if !all_zero(c.rest()) {
            return Err(nc("a non-zero byte after the hash list"));
        }
        let m = Manifest {
            fields: ManifestFields {
                kind,
                view_once: flags & 1 == 1,
                class,
                object_id,
                content_len,
                width,
                height,
                duration_ms,
            },
            preview: Zeroizing::new(preview.to_vec()),
            hashes,
        };
        m.validate()?;
        Ok(m)
    }
}

/// `AD_m` (§3.5).
pub fn manifest_ad(object_id: &ObjectId, commitment: &Commitment) -> Vec<u8> {
    let mut ad = Vec::with_capacity(labels::AD_MANIFEST.len().saturating_add(49));
    ad.extend_from_slice(labels::AD_MANIFEST.as_bytes());
    ad.push(labels::AD_VERSION);
    ad.extend_from_slice(object_id.as_bytes());
    ad.extend_from_slice(commitment.as_bytes());
    ad
}

/// Seals `MP` into the 65 536-byte blob: `K_m` seals exactly one manifest, so the nonce is zero
/// (the F9 seal pattern).
pub fn seal_blob(derived: &Derived, object_id: &ObjectId, mp: &[u8]) -> MediaResult<Vec<u8>> {
    if mp.len() != MANIFEST_PT {
        return Err(nc("a manifest plaintext that is not 65 488 bytes"));
    }
    let nonce = [0u8; 12];
    let ad = manifest_ad(object_id, &derived.commitment);
    #[cfg(any(test, feature = "nonce-registry"))]
    crate::registry::record_padded(derived.manifest.as_bytes(), &nonce, &ad, mp, MANIFEST_PT);
    // Plaintext until it is encrypted in place: wiped if a refusal drops it, moved out once sealed.
    let mut blob = Zeroizing::new(Vec::with_capacity(FRAG));
    blob.extend_from_slice(derived.commitment.as_bytes());
    blob.extend_from_slice(mp);
    let body = blob
        .get_mut(COMMIT_BYTES..)
        .ok_or_else(|| nc("a manifest plaintext that is not 65 488 bytes"))?;
    let tag = ChaCha20Poly1305::new(derived.manifest.as_bytes().into())
        .encrypt_inout_detached(&Nonce::from(nonce), &ad, body.into())
        .map_err(|_| MediaError::new(Code::Oversize, "ChaCha20-Poly1305 refused the manifest"))?;
    blob.extend_from_slice(tag.as_slice());
    Ok(core::mem::take(&mut *blob))
}

/// Opens a manifest blob: `COMMIT_MISMATCH` when its commitment is not the one the key derives
/// (checked first: a manifest opens under at most one key, §3.4), `NOT_OPEN` when the tag does not
/// verify. Returns `MP`.
pub fn open_blob(
    derived: &Derived,
    object_id: &ObjectId,
    blob: &[u8],
) -> MediaResult<Zeroizing<Vec<u8>>> {
    if blob.len() != FRAG {
        return Err(MediaError::new(
            Code::HashMismatch,
            "a manifest blob that is not 65 536 bytes",
        ));
    }
    let (commit, rest) = blob.split_at(COMMIT_BYTES);
    if commit != derived.commitment.as_bytes() {
        return Err(MediaError::new(
            Code::CommitMismatch,
            "a manifest commitment other than the key's",
        ));
    }
    let (ct, tag) = rest.split_at(MANIFEST_PT);
    let mut tag_bytes = [0u8; TAG];
    tag_bytes.copy_from_slice(tag);
    let mut mp = Zeroizing::new(ct.to_vec());
    let ad = manifest_ad(object_id, &derived.commitment);
    ChaCha20Poly1305::new(derived.manifest.as_bytes().into())
        .decrypt_inout_detached(
            &Nonce::from([0u8; 12]),
            &ad,
            mp.as_mut_slice().into(),
            &Tag::from(tag_bytes),
        )
        .map_err(|_| MediaError::new(Code::NotOpen, "the manifest's tag does not verify"))?;
    Ok(mp)
}
