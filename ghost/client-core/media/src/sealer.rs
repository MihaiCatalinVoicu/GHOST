//! The sealer (design §3.7, CS-M1; §13.2 M1 … M4).
//!
//! 1. A sealer owns `K_f`, `object_id`, the used-index set and the running hash list; the caller
//!    never chooses an index or sees a derived key.
//! 2. One pass with a one-chunk lookahead: [`Sealer::append`] seals chunk `i` (with `last = 0`) once
//!    chunk `i + 1` has begun, so at most one plaintext chunk (262 128 B) waits; [`Sealer::finish`]
//!    learns `content_len`, computes `F`, seals the held chunk and the zero padding chunks with
//!    `last = 1` on index `n − 1` only, and builds the manifest. An index is sealed at most once (a
//!    second attempt is `INDEX_REUSED`, a bug).
//! 3. The walker of the object's kind validates every byte before it is sealed (D16): a stream
//!    outside the canonical profile is refused at `append` with `NON_CANONICAL`, and the sealer is
//!    spent. `width`, `height` and `duration_ms` come from the walk, never from the caller (§3.5,
//!    MC-M21); for a video, `finish` appends the `mfra` built from the walked fragments (§8.3).
//! 4. A sealer is spent by `finish`, by `abort` (dropping it) or by any refusal; a spent sealer
//!    seals nothing more (`SEQUENCE`). Resuming an interrupted preparation always begins a new
//!    sealer with a new `K_f` and `object_id` (§3.7 point 3): the caller draws both, this crate has
//!    no randomness.
//! 5. RAM (§10.5, §15.2 item 8): `K_f`, the derived keys and the held chunk are wiped when they are
//!    dropped, and the held chunk is never reallocated in place: a full chunk moves out to be sealed
//!    and a new buffer of a whole chunk's capacity replaces it, so no freed block keeps plaintext
//!    (the walkers' buffers grow the same way, `bytes::extend_wiped`; `tests/zeroize.rs` scans every
//!    freed block for a canary). Not wiped here: the caller's input slices, and the key copies inside
//!    the AEAD and HKDF instances (§22.2 row 21).

use zeroize::Zeroizing;

use crate::bytes::extend_wiped;
use crate::class::SizeClass;
use crate::consts::{
    MediaKind, CHUNK_PT, FRAG, FRAGMENTS_PER_CHUNK, HASH_BYTES, IMAGE_MAX_CONTENT, PREVIEW_MAX,
};
use crate::error::{Code, MediaError, MediaResult};
use crate::fmp4;
use crate::geometry;
use crate::jpeg;
use crate::keys::{derive, sha256, Derived, FileKey, ObjectId};
use crate::manifest::{seal_blob, Manifest, ManifestFields};
use crate::stream::{chunk_ad, seal_chunk};
use crate::walk::ContentWalker;

/// One sealed chunk: its index, its four fragments in order, and their hashes.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedChunk {
    /// `i`.
    pub index: u32,
    /// `C_i`: fragments `4i … 4i + 3`, `CHUNK_CT` bytes.
    pub ciphertext: Vec<u8>,
    /// SHA-256 of each fragment.
    pub hashes: [[u8; HASH_BYTES]; FRAGMENTS_PER_CHUNK],
}

impl SealedChunk {
    /// Fragment `4i + k`, `k` in 0 … 3.
    pub fn fragment(&self, k: usize) -> Option<&[u8]> {
        let start = k.checked_mul(FRAG)?;
        self.ciphertext.get(start..start.checked_add(FRAG)?)
    }
}

impl core::fmt::Debug for SealedChunk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SealedChunk({})", self.index)
    }
}

/// What `finish` returns: the last chunks, the manifest and the walked fields. `K_f` stays inside
/// (the S2 native surface wraps it into `key_env`, §4.2, and drops this value).
pub struct SealedObject {
    /// The chunks `finish` sealed: the held chunk and the zero padding chunks.
    pub chunks: Vec<SealedChunk>,
    /// The 65 536-byte manifest blob.
    pub manifest_blob: Vec<u8>,
    /// SHA-256 of the manifest blob (the descriptor's `manifest_hash`).
    pub manifest_hash: [u8; HASH_BYTES],
    /// The manifest (its fields are the walked ones).
    pub manifest: Manifest,
    file_key: FileKey,
}

impl SealedObject {
    /// `K_f`, for the S2 wrap into `key_env` (and the tests) only.
    pub fn file_key(&self) -> &FileKey {
        &self.file_key
    }
}

impl core::fmt::Debug for SealedObject {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The manifest's preview is a picture of the content: the manifest renders without it (its
        // own Debug), the key never renders, and the blob is not dumped.
        f.debug_struct("SealedObject")
            .field("chunks", &self.chunks)
            .field("manifest", &self.manifest)
            .field("manifest_blob_len", &self.manifest_blob.len())
            .field("file_key", &self.file_key)
            .finish_non_exhaustive()
    }
}

/// The sealer of one object.
pub struct Sealer {
    file_key: FileKey,
    object_id: ObjectId,
    derived: Derived,
    kind: MediaKind,
    view_once: bool,
    cap: u64,
    walker: ContentWalker,
    ad: Vec<u8>,
    held: Zeroizing<Vec<u8>>,
    next_index: u32,
    used: [u64; 4],
    hashes: Vec<[u8; HASH_BYTES]>,
    content_len: u64,
    spent: bool,
}

impl core::fmt::Debug for Sealer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Sealer({:?}, {:?})", self.object_id, self.kind)
    }
}

fn sequence(rule: &'static str) -> MediaError {
    MediaError::new(Code::Sequence, rule)
}

impl Sealer {
    /// `sealBegin` (§13.2 M1): `K_f` and `object_id` are the caller's fresh random values; content
    /// above `max_class` (or, for an image, above `IMAGE_MAX_CONTENT`) is refused with `OVERSIZE`.
    pub fn begin(
        file_key: FileKey,
        object_id: ObjectId,
        kind: MediaKind,
        view_once: bool,
        max_class: SizeClass,
    ) -> Sealer {
        let cap = match kind {
            MediaKind::Image => IMAGE_MAX_CONTENT,
            MediaKind::Video => max_class.capacity(),
        };
        let derived = derive(&file_key, &object_id);
        Sealer {
            file_key,
            object_id,
            derived,
            kind,
            view_once,
            cap,
            walker: ContentWalker::for_sealer(kind),
            ad: chunk_ad(&object_id, kind),
            held: Zeroizing::new(Vec::with_capacity(CHUNK_PT)),
            next_index: 0,
            used: [0; 4],
            hashes: Vec::new(),
            content_len: 0,
            spent: false,
        }
    }

    /// The object's identifier.
    pub fn object_id(&self) -> ObjectId {
        self.object_id
    }

    /// Seals index `index` once: the used-index set refuses a second seal (`INDEX_REUSED`).
    fn seal_index(&mut self, index: u32, last: bool, plaintext: &[u8]) -> MediaResult<SealedChunk> {
        let word = usize::try_from(index / 64).unwrap_or(usize::MAX);
        let bit = 1u64 << (index % 64);
        let slot = self.used.get_mut(word).ok_or(MediaError::new(
            Code::IndexReused,
            "a chunk index beyond 255",
        ))?;
        if *slot & bit != 0 {
            return Err(MediaError::new(
                Code::IndexReused,
                "a chunk index sealed twice",
            ));
        }
        *slot |= bit;
        let ciphertext = seal_chunk(&self.derived.payload, &self.ad, index, last, plaintext)?;
        let mut hashes = [[0u8; HASH_BYTES]; FRAGMENTS_PER_CHUNK];
        for (k, h) in hashes.iter_mut().enumerate() {
            let start = k.saturating_mul(FRAG);
            *h = sha256(
                ciphertext
                    .get(start..start.saturating_add(FRAG))
                    .unwrap_or(&[]),
            );
        }
        self.hashes.extend_from_slice(&hashes);
        Ok(SealedChunk {
            index,
            ciphertext,
            hashes,
        })
    }

    /// Adds plaintext bytes that the walker has already accepted, sealing every chunk this
    /// completes except the one held for the lookahead.
    fn push_plaintext(&mut self, data: &[u8]) -> MediaResult<Vec<SealedChunk>> {
        let mut out = Vec::new();
        let mut rest = data;
        while !rest.is_empty() {
            if self.held.len() == CHUNK_PT {
                // The full chunk moves out (wiped when sealed) and a buffer of a whole chunk's
                // capacity takes its place, so the held chunk never grows in place.
                let held = core::mem::replace(
                    &mut self.held,
                    Zeroizing::new(Vec::with_capacity(CHUNK_PT)),
                );
                let index = self.next_index;
                out.push(self.seal_index(index, false, &held)?);
                self.next_index = index.saturating_add(1);
            }
            let room = CHUNK_PT.saturating_sub(self.held.len());
            let n = room.min(rest.len());
            let (now, later) = rest.split_at(n);
            extend_wiped(&mut self.held, now);
            rest = later;
        }
        Ok(out)
    }

    fn grow(&mut self, by: usize) -> MediaResult<()> {
        let len = u64::try_from(by)
            .ok()
            .and_then(|b| self.content_len.checked_add(b))
            .filter(|l| *l <= self.cap)
            .ok_or(MediaError::new(
                Code::Oversize,
                "content above the sealer's class (or MAX_CONTENT, or IMAGE_MAX_CONTENT)",
            ))?;
        self.content_len = len;
        Ok(())
    }

    /// `sealAppend` (§13.2 M2): walks `data`, then seals every chunk it completes but the last
    /// one begun (the lookahead). Refusals spend the sealer.
    pub fn append(&mut self, data: &[u8]) -> MediaResult<Vec<SealedChunk>> {
        if self.spent {
            return Err(sequence("a sealer used after finish or a refusal"));
        }
        let result = self
            .grow(data.len())
            .and_then(|()| self.walker.feed(data))
            .and_then(|()| self.push_plaintext(data));
        if result.is_err() {
            self.spent = true;
        }
        result
    }

    /// `sealFinish` (§13.2 M3): completes the walk, appends a video's `mfra`, computes the class,
    /// seals the held chunk and the padding chunks (the last flag on index `n − 1` only) and builds
    /// the manifest with the walked fields and `preview` (empty for a view-once object).
    pub fn finish(mut self, preview: &[u8]) -> MediaResult<SealedObject> {
        if self.spent {
            return Err(sequence("a sealer used after finish or a refusal"));
        }
        self.spent = true;
        let walked = self.walker.finish()?;
        if preview.len() > PREVIEW_MAX {
            return Err(MediaError::non_canonical("a preview above 32 768 bytes"));
        }
        if self.view_once && !preview.is_empty() {
            return Err(MediaError::non_canonical(
                "a view-once object with a preview",
            ));
        }
        if !preview.is_empty() {
            let info = jpeg::check(preview)?;
            geometry::check_preview(info.width, info.height)?;
        }
        let mut chunks = Vec::new();
        if let Some(video) = walked.video.as_ref() {
            let mfra = Zeroizing::new(fmp4::build_mfra(video.video_track, &video.moofs));
            self.grow(mfra.len())?;
            chunks.extend(self.push_plaintext(&mfra)?);
        }
        let class = SizeClass::for_content_len(self.content_len)
            .ok_or(MediaError::non_canonical("an empty object"))?;
        let n = class.chunks();
        let held = core::mem::take(&mut self.held);
        let mut index = self.next_index;
        let last_index = n.saturating_sub(1);
        if index > last_index {
            return Err(MediaError::new(
                Code::IndexReused,
                "more chunks than the class holds",
            ));
        }
        chunks.push(self.seal_index(index, index == last_index, &held)?);
        while index < last_index {
            index = index.saturating_add(1);
            chunks.push(self.seal_index(index, index == last_index, &[])?);
        }
        if self.hashes.len() != usize::try_from(class.fragments()).unwrap_or(0) {
            return Err(MediaError::new(
                Code::IndexReused,
                "a chunk count other than the class's",
            ));
        }
        let manifest = Manifest {
            fields: ManifestFields {
                kind: self.kind,
                view_once: self.view_once,
                class,
                object_id: self.object_id,
                content_len: self.content_len,
                width: walked.width,
                height: walked.height,
                duration_ms: walked.duration_ms,
            },
            preview: Zeroizing::new(preview.to_vec()),
            hashes: self.hashes.clone(),
        };
        let mp = manifest.encode_plaintext()?;
        let manifest_blob = seal_blob(&self.derived, &self.object_id, &mp)?;
        let manifest_hash = sha256(&manifest_blob);
        Ok(SealedObject {
            chunks,
            manifest_blob,
            manifest_hash,
            manifest,
            file_key: self.file_key.clone(),
        })
    }

    /// `sealAbort` (§13.2 M4): drops the sealer, wiping `K_f`, the derived keys and the held chunk.
    pub fn abort(self) {}

    /// Test hook: seals `index` again, which the used-index set must refuse.
    #[cfg(test)]
    pub(crate) fn reseal_for_test(&mut self, index: u32) -> MediaResult<SealedChunk> {
        self.seal_index(index, false, &[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_seal_of_one_index_is_index_reused() {
        let mut s = Sealer::begin(
            FileKey::from_bytes([3; 32]),
            ObjectId::from_bytes([4; 16]),
            MediaKind::Video,
            false,
            SizeClass::LARGEST,
        );
        s.reseal_for_test(7).expect("first seal");
        assert_eq!(
            s.reseal_for_test(7).expect_err("second").code(),
            Code::IndexReused
        );
        assert_eq!(
            s.reseal_for_test(300).expect_err("range").code(),
            Code::IndexReused
        );
    }

    #[test]
    fn a_spent_sealer_seals_nothing() {
        let mut s = Sealer::begin(
            FileKey::from_bytes([3; 32]),
            ObjectId::from_bytes([5; 16]),
            MediaKind::Image,
            false,
            SizeClass::SMALLEST,
        );
        assert_eq!(
            s.append(b"not a jpeg").expect_err("walker").code(),
            Code::NonCanonical
        );
        assert_eq!(
            s.append(&[0xFF, 0xD8]).expect_err("spent").code(),
            Code::Sequence
        );
        assert_eq!(s.finish(&[]).expect_err("spent").code(), Code::Sequence);
    }
}
