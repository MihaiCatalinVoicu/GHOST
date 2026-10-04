//! The body of L0 kind 0x05 MEDIA (design §4.1): 86 fixed bytes and a caption of at most 1 024.
//!
//! | Offset | Size | Field | Rule |
//! |---|---|---|---|
//! | 0 | 1 | `d_version` | `0x01` |
//! | 1 | 1 | `kind` | `0x01` image, `0x02` video |
//! | 2 | 1 | `flags` | bit 0 `view_once`; others 0 |
//! | 3 | 1 | `class_code` | 0 … 10; an image is class 0 |
//! | 4 | 16 | `object_id` | |
//! | 20 | 32 | `key_slot` | zero in every L0 Kotlin builds or reads (§4.2; enforced by S2's `l0Decode`) |
//! | 52 | 32 | `manifest_hash` | SHA-256 of the exact manifest blob |
//! | 84 | 2 | `caption_len` | u16 BE, ≤ 1 024 |
//! | 86 | n | `caption` | strict UTF-8 |
//!
//! R-D3: a body that does not parse exactly (no trailing byte), has an out-of-range `class_code`,
//! `kind` or flag, an image with `class_code ≠ 0`, or a caption over 1 024 bytes or not strict UTF-8
//! is `NON_CANONICAL`. The key slot is carried as it is: filling and zeroing it is the S2 native
//! surface's (`encrypt`, `decrypt`, `sessionInbound`), and `l0Decode` there accepts kind 5 only with
//! a zero slot.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::bytes::Cursor;
use crate::class::SizeClass;
use crate::consts::{MediaKind, DESCRIPTOR_FIXED, DESCRIPTOR_MAX, HASH_BYTES, MAX_CAPTION_BYTES};
use crate::error::{MediaError, MediaResult};
use crate::keys::{ObjectId, KEY_BYTES};

/// The descriptor's version byte.
pub const D_VERSION: u8 = 0x01;

/// The 32-byte key slot: zero outside the S2 native surface; inside it, `K_f` for the length of one
/// `encrypt` or `decrypt` call. Zeroised on drop either way.
#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct KeySlot([u8; KEY_BYTES]);

impl KeySlot {
    /// The zero slot.
    pub fn zero() -> Self {
        KeySlot([0; KEY_BYTES])
    }

    /// A slot holding these bytes.
    pub fn from_bytes(bytes: [u8; KEY_BYTES]) -> Self {
        KeySlot(bytes)
    }

    /// The bytes.
    pub fn as_bytes(&self) -> &[u8; KEY_BYTES] {
        &self.0
    }

    /// Whether every byte is zero.
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|b| *b == 0)
    }
}

impl core::fmt::Debug for KeySlot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // A filled slot holds K_f: it never renders.
        f.write_str(if self.is_zero() {
            "KeySlot(zero)"
        } else {
            "KeySlot(..)"
        })
    }
}

/// A MEDIA descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Descriptor {
    /// `kind`.
    pub kind: MediaKind,
    /// `flags` bit 0.
    pub view_once: bool,
    /// `class_code`.
    pub class: SizeClass,
    /// `object_id`.
    pub object_id: ObjectId,
    /// `key_slot`.
    pub key_slot: KeySlot,
    /// `manifest_hash`.
    pub manifest_hash: [u8; HASH_BYTES],
    /// `caption`.
    pub caption: String,
}

fn nc(rule: &'static str) -> MediaError {
    MediaError::non_canonical(rule)
}

impl Descriptor {
    fn check(&self) -> MediaResult<()> {
        if self.kind == MediaKind::Image && self.class != SizeClass::SMALLEST {
            return Err(nc("an image descriptor whose class is not 0"));
        }
        if self.caption.len() > MAX_CAPTION_BYTES {
            return Err(nc("a caption above 1 024 bytes"));
        }
        Ok(())
    }

    /// The body (R-D1: at most 1 110 bytes).
    pub fn encode(&self) -> MediaResult<Vec<u8>> {
        self.check()?;
        let caption = self.caption.as_bytes();
        let caption_len =
            u16::try_from(caption.len()).map_err(|_| nc("a caption above 1 024 bytes"))?;
        let mut out = Vec::with_capacity(DESCRIPTOR_FIXED.saturating_add(caption.len()));
        out.push(D_VERSION);
        out.push(self.kind.byte());
        out.push(u8::from(self.view_once));
        out.push(self.class.code());
        out.extend_from_slice(self.object_id.as_bytes());
        out.extend_from_slice(self.key_slot.as_bytes());
        out.extend_from_slice(&self.manifest_hash);
        out.extend_from_slice(&caption_len.to_be_bytes());
        out.extend_from_slice(caption);
        Ok(out)
    }

    /// Parses a body exactly (R-D3).
    pub fn decode(body: &[u8]) -> MediaResult<Descriptor> {
        if body.len() > DESCRIPTOR_MAX {
            return Err(nc("a descriptor above 1 110 bytes"));
        }
        let mut c = Cursor::new(body, "a malformed descriptor");
        if c.u8()? != D_VERSION {
            return Err(nc("a descriptor version other than 1"));
        }
        let kind = MediaKind::from_byte(c.u8()?)
            .ok_or_else(|| nc("a descriptor kind other than 1 or 2"))?;
        let flags = c.u8()?;
        if flags & !1 != 0 {
            return Err(nc("a descriptor flag other than view_once"));
        }
        let class = SizeClass::from_code(c.u8()?).ok_or_else(|| nc("a class_code above 10"))?;
        let object_id = ObjectId::from_bytes(c.array()?);
        let key_slot = KeySlot::from_bytes(c.array()?);
        let manifest_hash = c.array::<HASH_BYTES>()?;
        let caption_len = usize::from(c.u16()?);
        if caption_len > MAX_CAPTION_BYTES {
            return Err(nc("a caption above 1 024 bytes"));
        }
        let caption = c.take(caption_len)?;
        c.finish()?;
        let caption = core::str::from_utf8(caption)
            .map_err(|_| nc("a caption that is not strict UTF-8"))?
            .to_owned();
        let d = Descriptor {
            kind,
            view_once: flags & 1 == 1,
            class,
            object_id,
            key_slot,
            manifest_hash,
            caption,
        };
        d.check()?;
        Ok(d)
    }
}
