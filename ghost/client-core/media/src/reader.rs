//! The reader (design §3.4, §7.3, CS-M2; §13.2 M5 … M8).
//!
//! [`Reader::open`] checks, in this order: the blob is the one the descriptor names
//! (`HASH_MISMATCH`), the key commits to it (`COMMIT_MISMATCH`), its tag verifies (`NOT_OPEN`), it
//! parses strictly under every rule of §3.5 (`NON_CANONICAL`), and its `object_id`, `kind`, flags
//! and class are the descriptor's (`NON_CANONICAL`). Then each chunk: its index is inside the
//! object (`INDEX_RANGE`), its four fragments are the blobs the manifest names in order
//! (`HASH_MISMATCH`), its tag verifies under its index and the last flag of index `n − 1` only
//! (`NOT_OPEN`), and its bytes after `content_len` are zero (`NON_CANONICAL`).
//!
//! The validation pass (`MEDIA-VERIFY`, §7.3) is [`Reader::validate_chunk`] for every index in order
//! then [`Reader::validate_finish`]: the walker sees the whole content, and the walked dimensions and
//! duration must be the manifest's. Nothing is exposed by it. [`Reader::read_chunk`] (playback and
//! display, any order) writes a chunk's content into the caller's buffer only once every check of
//! that chunk passed: a refused chunk leaves the buffer untouched.

use zeroize::Zeroizing;

use crate::class::SizeClass;
use crate::consts::{MediaKind, CHUNK_CT, CHUNK_PT, FRAG, FRAGMENTS_PER_CHUNK, HASH_BYTES};
use crate::descriptor::Descriptor;
use crate::error::{Code, MediaError, MediaResult};
use crate::keys::{derive, sha256, FileKey, ObjectId, PayloadKey};
use crate::manifest::{open_blob, Manifest};
use crate::stream::{chunk_ad, open_chunk};
use crate::walk::ContentWalker;

/// What the descriptor says about the object (§4.1, §7.2): the reader refuses a manifest that
/// disagrees.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Expected {
    /// `object_id`.
    pub object_id: ObjectId,
    /// `kind`.
    pub kind: MediaKind,
    /// `flags` bit 0.
    pub view_once: bool,
    /// `class_code`.
    pub class: SizeClass,
    /// `manifest_hash`.
    pub manifest_hash: [u8; HASH_BYTES],
}

impl Expected {
    /// The fields of a parsed descriptor.
    pub fn from_descriptor(d: &Descriptor) -> Expected {
        Expected {
            object_id: d.object_id,
            kind: d.kind,
            view_once: d.view_once,
            class: d.class,
            manifest_hash: d.manifest_hash,
        }
    }
}

/// What the validation pass walked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Walked {
    /// The displayed width.
    pub width: u16,
    /// The displayed height.
    pub height: u16,
    /// The duration (0 for an image).
    pub duration_ms: u32,
}

/// The reader of one object.
pub struct Reader {
    payload: PayloadKey,
    ad: Vec<u8>,
    manifest: Manifest,
    chunks: u32,
    validate_next: u32,
    walker: ContentWalker,
    validation: Validation,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Validation {
    Open,
    Failed,
    Done,
}

impl core::fmt::Debug for Reader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Reader({:?})", self.manifest.fields.object_id)
    }
}

fn nc(rule: &'static str) -> MediaError {
    MediaError::non_canonical(rule)
}

impl Reader {
    /// `readerOpen` (§13.2 M5) with the unwrapped `K_f` (the `key_env` unwrap is S2's).
    pub fn open(
        file_key: &FileKey,
        expected: &Expected,
        manifest_blob: &[u8],
    ) -> MediaResult<Reader> {
        if manifest_blob.len() != FRAG || sha256(manifest_blob) != expected.manifest_hash {
            return Err(MediaError::new(
                Code::HashMismatch,
                "a manifest blob other than the one the descriptor names",
            ));
        }
        let derived = derive(file_key, &expected.object_id);
        let mp = open_blob(&derived, &expected.object_id, manifest_blob)?;
        let manifest = Manifest::decode_plaintext(&mp)?;
        let f = &manifest.fields;
        if f.object_id != expected.object_id {
            return Err(nc("a manifest object_id other than the descriptor's"));
        }
        if f.kind != expected.kind || f.view_once != expected.view_once || f.class != expected.class
        {
            return Err(nc(
                "a manifest kind, flags or class other than the descriptor's",
            ));
        }
        let chunks = f.class.chunks();
        Ok(Reader {
            payload: derived.payload.clone(),
            ad: chunk_ad(&expected.object_id, expected.kind),
            walker: ContentWalker::for_reader(expected.kind),
            manifest,
            chunks,
            validate_next: 0,
            validation: Validation::Open,
        })
    }

    /// The manifest: its fields, its preview, its hashes.
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// `n`, the object's chunk count.
    pub fn chunk_count(&self) -> u32 {
        self.chunks
    }

    /// Opens chunk `index` from its four fragments: the plaintext and how many of its bytes are
    /// content.
    fn open_index(&self, index: u32, fragments: &[u8]) -> MediaResult<(Zeroizing<Vec<u8>>, usize)> {
        if index >= self.chunks {
            return Err(MediaError::new(
                Code::IndexRange,
                "a chunk index outside the object",
            ));
        }
        if fragments.len() != CHUNK_CT {
            return Err(MediaError::new(
                Code::HashMismatch,
                "fragments that are not four 64 KiB blobs",
            ));
        }
        let first = usize::try_from(index)
            .ok()
            .and_then(|i| i.checked_mul(FRAGMENTS_PER_CHUNK))
            .ok_or(MediaError::new(
                Code::IndexRange,
                "a chunk index outside the object",
            ))?;
        for (k, fragment) in fragments.chunks(FRAG).enumerate() {
            let want = self.manifest.hashes.get(first.saturating_add(k));
            if want != Some(&sha256(fragment)) {
                return Err(MediaError::new(
                    Code::HashMismatch,
                    "a fragment other than the one the manifest names at its position",
                ));
            }
        }
        let last = index == self.chunks.saturating_sub(1);
        let plaintext = open_chunk(&self.payload, &self.ad, index, last, fragments)?;
        let start = u64::from(index).saturating_mul(CHUNK_PT as u64);
        let content = self
            .manifest
            .fields
            .content_len
            .saturating_sub(start)
            .min(CHUNK_PT as u64);
        let content = usize::try_from(content).map_err(|_| nc("a chunk too large"))?;
        if !plaintext
            .get(content..)
            .unwrap_or(&[])
            .iter()
            .all(|b| *b == 0)
        {
            return Err(nc("a non-zero byte after content_len (R-O3)"));
        }
        Ok((plaintext, content))
    }

    /// `readerChunk` in `validate` mode (§13.2 M6): every index, in order; nothing is exposed.
    pub fn validate_chunk(&mut self, index: u32, fragments: &[u8]) -> MediaResult<()> {
        if self.validation != Validation::Open {
            return Err(MediaError::new(
                Code::Sequence,
                "a validation pass already ended",
            ));
        }
        if index >= self.chunks {
            self.validation = Validation::Failed;
            return Err(MediaError::new(
                Code::IndexRange,
                "a chunk index outside the object",
            ));
        }
        if index != self.validate_next {
            self.validation = Validation::Failed;
            return Err(MediaError::new(
                Code::Sequence,
                "a validation pass out of order (a chunk repeated or skipped)",
            ));
        }
        let result = self
            .open_index(index, fragments)
            .and_then(|(plaintext, content)| {
                self.walker.feed(plaintext.get(..content).unwrap_or(&[]))
            });
        match result {
            Ok(()) => {
                self.validate_next = self.validate_next.saturating_add(1);
                Ok(())
            }
            Err(e) => {
                self.validation = Validation::Failed;
                Err(e)
            }
        }
    }

    /// `readerValidateFinish` (§13.2 M7): every chunk validated, the walk complete, and the walked
    /// dimensions and duration are the manifest's.
    pub fn validate_finish(&mut self) -> MediaResult<Walked> {
        if self.validation != Validation::Open {
            return Err(MediaError::new(
                Code::Sequence,
                "a validation pass already ended",
            ));
        }
        self.validation = Validation::Failed;
        if self.validate_next != self.chunks {
            return Err(nc("a validation pass with chunks missing"));
        }
        let walked = self.walker.finish()?;
        let f = &self.manifest.fields;
        if (walked.width, walked.height, walked.duration_ms) != (f.width, f.height, f.duration_ms) {
            return Err(nc(
                "manifest dimensions or duration other than the walked stream's",
            ));
        }
        self.validation = Validation::Done;
        Ok(Walked {
            width: walked.width,
            height: walked.height,
            duration_ms: walked.duration_ms,
        })
    }

    /// `readerChunk` in `read` mode (§13.2 M6): the chunk's content bytes into `out`, which must hold
    /// them; returns how many. `out` is written only when every check passed.
    pub fn read_chunk(&self, index: u32, fragments: &[u8], out: &mut [u8]) -> MediaResult<usize> {
        let (plaintext, content) = self.open_index(index, fragments)?;
        let src = plaintext
            .get(..content)
            .ok_or(nc("a chunk shorter than its content"))?;
        let dst = out.get_mut(..content).ok_or(MediaError::new(
            Code::Oversize,
            "an out buffer smaller than the chunk's content",
        ))?;
        dst.copy_from_slice(src);
        Ok(content)
    }
}
