//! The closed JNI surface `org.ghost.crypto.bridge.MediaNative` (Phase 11 design §13.2, gate
//! G-M5): the media sealer and reader of `ghost-client-media`, exported from `ghost-client-dm`
//! behind `jni-bridge`, because the two surfaces share the one DM context and its registries
//! (§13.1). Everything the design's table fixes holds: every function is `static native`, takes
//! the DM context handle `h` (M9 and M10 are stateless, like `safetyNumber` — their rows name no
//! handle), performs no I/O, reads no clock, logs nothing, and a Rust panic is caught under the
//! silent hook and returned as [`MediaCode::Internal`].
//!
//! **The reply shape** is the DM surface's: `code(1) || TLV fields`, decoded by Kotlin's
//! `MediaResult`. [`MediaCode`] is the wire numbering of the enumeration §13.2 names (the design
//! fixes the names, not the bytes — the same freedom `result.rs` used for `DmCode`).
//!
//! **Value state (§4.2).** Sealers and readers are registry entries inside the DM context; `K_f`
//! exists in native memory only, from `sealBegin` until `sealFinish` wraps it into `key_env`, and
//! as the unwrapped argument of `readerOpen` for the length of that call. `ctxClose` drops the
//! context and zeroises every entry with it.
//!
//! **Recorded deviation from §13.2 (slice S2).** M2 and M6 cross their large buffers as byte
//! arrays rather than direct `ByteBuffer`s: the whole shipped graph forbids `unsafe_code`, and
//! JNI's `GetDirectBufferAddress` hands back a raw pointer that cannot be read without an `unsafe`
//! seam. The byte-array crossing is safe, testable and correct; it copies where the design wanted
//! zero-copy. The direct-buffer form needs one decision — a documented, capacity-checked `unsafe`
//! helper in a crate that may contain it — and is recorded in §22.3 as a pending owner toggle.
//!
//! **The key slot.** `encrypt`, `decrypt` and `sessionInbound` hold the key-slot rule (§4.2); this
//! module only ever sees `K_f` inside `key_env` (M5 unwraps it) or inside a sealer (M1–M3).

use ghost_client_media as media;
use jni::objects::{JByteArray, JClass};
use jni::sys::{jbyteArray, jint, jlong};
use jni::JNIEnv;
use std::panic::{catch_unwind, AssertUnwindSafe};
use zeroize::{Zeroize, Zeroizing};

use crate::jni as dm_jni;
use crate::jni::DmContext;
use crate::pq;
use crate::wrap;
use crate::wrap::WrapName;

/// A media result code: the wire numbering of §13.2's enumeration. `Ok` is the absence of an
/// error; `Internal` is a caught panic and nothing else.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum MediaCode {
    /// The call succeeded.
    Ok = 0x00,
    /// The native library is missing, or the context handle is closed or foreign.
    CryptoUnavailable = 0x01,
    /// Bytes that do not parse exactly, break a canonical-format rule, or disagree with the
    /// descriptor or the walked stream.
    NonCanonical = 0x02,
    /// A chunk or manifest whose ChaCha20-Poly1305 tag does not verify.
    NotOpen = 0x03,
    /// A manifest whose commitment is not the one the key derives.
    CommitMismatch = 0x04,
    /// A fragment or manifest that is not the blob its hash names.
    HashMismatch = 0x05,
    /// A chunk index outside the object.
    IndexRange = 0x06,
    /// A second seal of one chunk index: a GHOST bug, never a peer's doing.
    IndexReused = 0x07,
    /// Content above `MAX_CONTENT`, the image bound, the sealer's largest class, or an out buffer
    /// that cannot hold what the call returns.
    Oversize = 0x08,
    /// A source outside the allowlist (`sniff`, §6.1).
    Unsupported = 0x09,
    /// A call the sealer or reader state machine does not allow at this point — a sealer used
    /// after `finish` or a refusal, a validation pass out of order, a read on a reader whose
    /// object the database does not hold readable (§22.2 row 28a).
    Sequence = 0x0a,
    /// A registry cap: two live sealers, eight live readers.
    Limit = 0x0b,
    /// Stored state that does not open under its binding: M5's `key_env` unwrap (§4.2), the
    /// same refusal the DM surface's `STATE_CORRUPT` names — the object goes `corrupt`.
    StateCorrupt = 0x0c,
    /// A caught Rust panic, and nothing else.
    Internal = 0xff,
}

/// The result of every fallible media operation.
pub type MediaResult<T> = Result<T, MediaCode>;

impl MediaCode {
    /// The wire byte of this code.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// The code of a wire byte, or `None` for a byte this version does not define.
    pub const fn from_u8(byte: u8) -> Option<Self> {
        Some(match byte {
            0x00 => MediaCode::Ok,
            0x01 => MediaCode::CryptoUnavailable,
            0x02 => MediaCode::NonCanonical,
            0x03 => MediaCode::NotOpen,
            0x04 => MediaCode::CommitMismatch,
            0x05 => MediaCode::HashMismatch,
            0x06 => MediaCode::IndexRange,
            0x07 => MediaCode::IndexReused,
            0x08 => MediaCode::Oversize,
            0x09 => MediaCode::Unsupported,
            0x0a => MediaCode::Sequence,
            0x0b => MediaCode::Limit,
            0x0c => MediaCode::StateCorrupt,
            0xff => MediaCode::Internal,
            _ => return None,
        })
    }

    /// The code's name as §13.2 spells it: the form the Kotlin `MediaResult` decoder, the
    /// counters and `MediaResultCodesTest` use.
    pub const fn name(self) -> &'static str {
        match self {
            MediaCode::Ok => "OK",
            MediaCode::CryptoUnavailable => "CRYPTO_UNAVAILABLE",
            MediaCode::NonCanonical => "NON_CANONICAL",
            MediaCode::NotOpen => "NOT_OPEN",
            MediaCode::CommitMismatch => "COMMIT_MISMATCH",
            MediaCode::HashMismatch => "HASH_MISMATCH",
            MediaCode::IndexRange => "INDEX_RANGE",
            MediaCode::IndexReused => "INDEX_REUSED",
            MediaCode::Oversize => "OVERSIZE",
            MediaCode::Unsupported => "UNSUPPORTED",
            MediaCode::Sequence => "SEQUENCE",
            MediaCode::Limit => "LIMIT",
            MediaCode::StateCorrupt => "STATE_CORRUPT",
            MediaCode::Internal => "INTERNAL",
        }
    }

    /// Every code of the closed list, in wire order.
    pub const ALL: [MediaCode; 14] = [
        MediaCode::Ok,
        MediaCode::CryptoUnavailable,
        MediaCode::NonCanonical,
        MediaCode::NotOpen,
        MediaCode::CommitMismatch,
        MediaCode::HashMismatch,
        MediaCode::IndexRange,
        MediaCode::IndexReused,
        MediaCode::Oversize,
        MediaCode::Unsupported,
        MediaCode::Sequence,
        MediaCode::Limit,
        MediaCode::StateCorrupt,
        MediaCode::Internal,
    ];

    /// The surface code of a crate error: one to one by the crate's code (the same list without
    /// the surface-only `CRYPTO_UNAVAILABLE`, `LIMIT`, `STATE_CORRUPT` and `INTERNAL`).
    fn from_media(error: media::MediaError) -> Self {
        match error.code() {
            media::Code::NonCanonical => MediaCode::NonCanonical,
            media::Code::NotOpen => MediaCode::NotOpen,
            media::Code::CommitMismatch => MediaCode::CommitMismatch,
            media::Code::HashMismatch => MediaCode::HashMismatch,
            media::Code::IndexRange => MediaCode::IndexRange,
            media::Code::IndexReused => MediaCode::IndexReused,
            media::Code::Oversize => MediaCode::Oversize,
            media::Code::Unsupported => MediaCode::Unsupported,
            media::Code::Sequence => MediaCode::Sequence,
        }
    }
}

/// The codes each exported function can return besides [`MediaCode::Ok`], for the same closed-list
/// discipline `FUNCTION_CODES` holds on the DM surface: it is the set a caller has to answer, JNI
/// argument-shape failures included. [`MediaCode::Internal`] is not listed — a caught panic
/// belongs to every function and is the one outcome the typed facade throws on.
pub const MEDIA_FUNCTION_CODES: &[(&str, &[MediaCode])] = &[
    (
        "sealBegin",
        &[
            MediaCode::NonCanonical,
            MediaCode::Limit,
            MediaCode::CryptoUnavailable,
        ],
    ),
    (
        "sealAppend",
        &[
            MediaCode::NonCanonical,
            MediaCode::Oversize,
            MediaCode::IndexReused,
            MediaCode::Sequence,
            MediaCode::CryptoUnavailable,
        ],
    ),
    (
        "sealFinish",
        &[
            MediaCode::NonCanonical,
            MediaCode::Oversize,
            MediaCode::Sequence,
            MediaCode::CryptoUnavailable,
        ],
    ),
    ("sealAbort", &[MediaCode::CryptoUnavailable]),
    (
        "readerOpen",
        &[
            MediaCode::NonCanonical,
            MediaCode::NotOpen,
            MediaCode::CommitMismatch,
            MediaCode::HashMismatch,
            MediaCode::StateCorrupt,
            MediaCode::Limit,
            MediaCode::CryptoUnavailable,
        ],
    ),
    (
        "readerChunk",
        &[
            MediaCode::NonCanonical,
            MediaCode::NotOpen,
            MediaCode::HashMismatch,
            MediaCode::IndexRange,
            MediaCode::Sequence,
            MediaCode::CryptoUnavailable,
        ],
    ),
    (
        "readerValidateFinish",
        &[
            MediaCode::NonCanonical,
            MediaCode::Sequence,
            MediaCode::CryptoUnavailable,
        ],
    ),
    ("readerClose", &[MediaCode::CryptoUnavailable]),
    ("jpegCanonicalize", &[MediaCode::NonCanonical]),
    ("sniff", &[MediaCode::Unsupported]),
    // Host-only entries (G-M5): same discipline for the test surface.
    (
        "testVectors",
        &[
            MediaCode::NonCanonical,
            MediaCode::StateCorrupt,
            MediaCode::CryptoUnavailable,
        ],
    ),
    (
        "testSealBeginWithKey",
        &[
            MediaCode::NonCanonical,
            MediaCode::Limit,
            MediaCode::CryptoUnavailable,
        ],
    ),
];

/// The TLV field tags of a `MediaNative` reply: `tag(1) || len(u32_be) || value`, decoded
/// strictly by Kotlin's `MediaResult` — a repeated or unknown tag is a surface disagreement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MediaField {
    /// M1/M3: the sealer's registry id, `i64` big-endian.
    SealerId = 0x01,
    /// M5: the reader's registry id, `i64` big-endian.
    ReaderId = 0x02,
    /// M1: the object's 16-byte id.
    ObjectId = 0x03,
    /// M2/M3: `u32_be(count) || (u32_be(index) || frag(65 536)×4 || hash(32)×4)*` — the fragments
    /// of every chunk the call completed, and their hashes.
    Chunks = 0x04,
    /// M3: the 65 536-byte manifest blob.
    ManifestBlob = 0x05,
    /// M3: SHA-256 of the manifest blob.
    ManifestHash = 0x06,
    /// M3/M5: the class code, one byte.
    ClassCode = 0x07,
    /// M3/M5: `content_len`, `u64` big-endian.
    ContentLen = 0x08,
    /// M3/M5: the walked width, `u16` big-endian.
    Width = 0x09,
    /// M3/M5: the walked height, `u16` big-endian.
    Height = 0x0a,
    /// M3/M5: the walked duration, `u32` big-endian.
    DurationMs = 0x0b,
    /// M3: the object's `key_env` (60 bytes), bound to `(out, destId, objectId, manifestHash)`.
    KeyEnv = 0x0c,
    /// M5: the manifest's preview (a canonical JPEG, or absent for view-once).
    Preview = 0x0d,
    /// M5: `32 × F` bytes, the manifest's ordered fragment hashes.
    Hashes = 0x0e,
    /// M5: the manifest's kind, one byte (1 image, 2 video).
    Kind = 0x0f,
    /// M5: the manifest's flags, one byte (bit 0 view-once).
    Flags = 0x10,
    /// M6 (read mode): the content bytes written, at most `CHUNK_PT`.
    ChunkContent = 0x11,
    /// M9: the canonical JPEG.
    Canonical = 0x12,
    /// M10: the source type, one byte (1 JPEG, 2 PNG, 3 WebP, 4 ISO-BMFF video).
    SourceType = 0x13,
    // Host-only fields (G-M5's `testVectors`).
    /// `K_p` for the request's `(K_f, object_id)`.
    PayloadKey = 0x14,
    /// `K_m` for the request's `(K_f, object_id)`.
    ManifestKey = 0x15,
    /// The key commitment for the request's `(K_f, object_id)`.
    Commitment = 0x16,
    /// An `op_id`, 16 bytes.
    OpId = 0x17,
}

impl MediaField {
    /// Every tag of the reply codec, in wire order. Kotlin's `MediaField` holds the same list and
    /// `MediaResultCodesTest` compares the two — the same drill `DmResultCodesTest` runs for the
    /// DM surface.
    pub const ALL: &'static [MediaField] = &[
        MediaField::SealerId,
        MediaField::ReaderId,
        MediaField::ObjectId,
        MediaField::Chunks,
        MediaField::ManifestBlob,
        MediaField::ManifestHash,
        MediaField::ClassCode,
        MediaField::ContentLen,
        MediaField::Width,
        MediaField::Height,
        MediaField::DurationMs,
        MediaField::KeyEnv,
        MediaField::Preview,
        MediaField::Hashes,
        MediaField::Kind,
        MediaField::Flags,
        MediaField::ChunkContent,
        MediaField::Canonical,
        MediaField::SourceType,
        MediaField::PayloadKey,
        MediaField::ManifestKey,
        MediaField::Commitment,
        MediaField::OpId,
    ];

    /// The wire tag.
    pub const fn tag(self) -> u8 {
        self as u8
    }
}

/// The closed list of §13.2: `(function number, name)`. Every entry is exported by this slice;
/// G-M5 checks both directions — no export outside the list, every entry really exported from
/// `libghost_client_net.so` — and that `testVectors` and `testSealBeginWithKey` exist only in
/// host and test libraries (the `DmEquivalence` precedent).
pub const MEDIA_CLOSED_LIST: &[(u8, &str)] = &[
    (1, "sealBegin"),
    (2, "sealAppend"),
    (3, "sealFinish"),
    (4, "sealAbort"),
    (5, "readerOpen"),
    (6, "readerChunk"),
    (7, "readerValidateFinish"),
    (8, "readerClose"),
    (9, "jpegCanonicalize"),
    (10, "sniff"),
];

/// The test-only entries of the host build (§13.2, §15.6): exported by `ghost-dm-host` alone.
#[cfg(feature = "test-vectors")]
pub const MEDIA_TEST_LIST: &[(u8, &str)] = &[(0, "testVectors"), (0, "testSealBeginWithKey")];

/// One live sealer (§3.7 point 1: a native object that owns `K_f`, `object_id`, the used-index
/// set and the running hash list) with the destination its `key_env` will be bound to.
pub(crate) struct SealerEntry {
    sealer: media::Sealer,
    dest_id: [u8; 16],
}

/// One live reader with the read-mode gate of §22.2 row 28a: `readerChunk(mode = read)` refuses
/// with `SEQUENCE` unless the caller attests the object is one the database holds readable — a
/// recipient's `verified` object, or the sender's own `out` object in `uploading`, `uploaded` or
/// `failed`. The attestation is the caller's (`:media` holds the database); the native side keeps
/// the rule close to the key.
pub(crate) struct ReaderEntry {
    reader: media::Reader,
    readable: bool,
}

/// The registry caps of §13.2.
const MAX_SEALERS: usize = 2;
const MAX_READERS: usize = 8;

/// A reply under construction: `code(1) || (tag(1) || len(u32_be) || value)*`. Like the DM
/// surface's reply it grows by hand — a finished object's reply carries a `key_env` and a
/// preview, so the old buffer is erased before it is freed at every regrowth.
struct Reply(Vec<u8>);

impl Reply {
    fn ok() -> Self {
        Self(vec![MediaCode::Ok.as_u8()])
    }

    fn field(mut self, tag: MediaField, value: &[u8]) -> Self {
        let needed = self.0.len() + 5 + value.len();
        if needed > self.0.capacity() {
            let mut grown = Vec::with_capacity(needed.max(2 * self.0.capacity()));
            grown.extend_from_slice(&self.0);
            self.0.zeroize();
            self.0 = grown;
        }
        self.0.push(tag.tag());
        let len = u32::try_from(value.len()).unwrap_or(u32::MAX);
        self.0.extend_from_slice(&len.to_be_bytes());
        self.0.extend_from_slice(value);
        self
    }

    fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

fn code_only(code: MediaCode) -> Vec<u8> {
    vec![code.as_u8()]
}

/// Runs a JNI body and turns its outcome into the reply array: a panic becomes `INTERNAL`, a
/// failed reply allocation leaves a null, which Kotlin reads as `INTERNAL`. The reply is erased
/// once the Java array holds its copy — a `sealFinish` reply carries `key_env`.
fn guarded(
    env: &mut JNIEnv,
    body: impl FnOnce(&mut JNIEnv) -> Result<Vec<u8>, MediaCode>,
) -> jbyteArray {
    dm_jni::quiet_panics();
    let reply = Zeroizing::new(match catch_unwind(AssertUnwindSafe(|| body(env))) {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(code)) => code_only(code),
        Err(_) => code_only(MediaCode::Internal),
    });
    match env.byte_array_from_slice(&reply) {
        Ok(array) => array.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// The native copy of a Java byte array, erased on drop, as on the DM surface; a conversion
/// failure is an argument-shape refusal, [`MediaCode::NonCanonical`].
fn bytes(env: &JNIEnv, array: &JByteArray) -> Result<Zeroizing<Vec<u8>>, MediaCode> {
    dm_jni::bytes(env, array).map_err(|_| MediaCode::NonCanonical)
}

/// The same copy as a fixed-size array.
fn fixed<const N: usize>(env: &JNIEnv, array: &JByteArray) -> Result<[u8; N], MediaCode> {
    let raw = bytes(env, array)?;
    <[u8; N]>::try_from(raw.as_slice()).map_err(|_| MediaCode::NonCanonical)
}

/// Runs `body` with the named context under the registry guard, or reports
/// [`MediaCode::CryptoUnavailable`] for a closed or foreign handle. The guard serialises every
/// caller of the context — the same discipline `jni::with_context` holds — and a panic does not
/// latch: the guard is recovered from poisoning (`jni::registry_guard`).
fn with_media<T>(
    handle: jlong,
    body: impl FnOnce(&mut DmContext) -> Result<T, MediaCode>,
) -> Result<T, MediaCode> {
    let mut guard = dm_jni::registry_guard();
    let context = guard.get_mut(&handle).ok_or(MediaCode::CryptoUnavailable)?;
    dm_jni::in_hook_scope(handle, || body(context))
}

/// The sealer/reader id space: one counter for both registries and the DM context's handles, so
/// an id is never reused across any of them.
fn insert_sealer(context: &mut DmContext, entry: SealerEntry) -> Result<i64, MediaCode> {
    if context.media_sealers.len() >= MAX_SEALERS {
        return Err(MediaCode::Limit);
    }
    let id = dm_jni::next_handle();
    context.media_sealers.insert(id, entry);
    Ok(id)
}

fn insert_reader(context: &mut DmContext, entry: ReaderEntry) -> Result<i64, MediaCode> {
    if context.media_readers.len() >= MAX_READERS {
        return Err(MediaCode::Limit);
    }
    let id = dm_jni::next_handle();
    context.media_readers.insert(id, entry);
    Ok(id)
}

/// The kind argument of M1/M5 and the test entry: 1 image, 2 video.
fn media_kind(kind: jint) -> Result<media::MediaKind, MediaCode> {
    u8::try_from(kind)
        .ok()
        .and_then(media::MediaKind::from_byte)
        .ok_or(MediaCode::NonCanonical)
}

/// The class argument of M1: 0 … 10.
fn size_class(code: jint) -> Result<media::SizeClass, MediaCode> {
    u8::try_from(code)
        .ok()
        .and_then(media::SizeClass::from_code)
        .ok_or(MediaCode::NonCanonical)
}

/// The role argument of M5: [`wrap::MEDIA_ROLE_OUT`] or [`wrap::MEDIA_ROLE_IN`].
fn media_role(role: jint) -> Result<u8, MediaCode> {
    let role = u8::try_from(role).map_err(|_| MediaCode::NonCanonical)?;
    if role == wrap::MEDIA_ROLE_OUT || role == wrap::MEDIA_ROLE_IN {
        Ok(role)
    } else {
        Err(MediaCode::NonCanonical)
    }
}

/// The readable attestation of M5: 0 or 1.
fn readable(readable: jint) -> Result<bool, MediaCode> {
    match readable {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(MediaCode::NonCanonical),
    }
}

/// Packs the sealed chunks M2/M3 return: `u32_be(count) || (u32_be(index) || ciphertext ||
/// hash(32)×4)*`. The ciphertext is exactly `CHUNK_CT` bytes (four 65 536-byte fragments); the
/// Kotlin side slices the fragments and hashes by their fixed sizes.
fn pack_chunks(chunks: &[media::SealedChunk]) -> Result<Vec<u8>, MediaCode> {
    let count = u32::try_from(chunks.len()).map_err(|_| MediaCode::Oversize)?;
    let mut out = Vec::new();
    out.extend_from_slice(&count.to_be_bytes());
    for chunk in chunks {
        out.extend_from_slice(&chunk.index.to_be_bytes());
        out.extend_from_slice(&chunk.ciphertext);
        for hash in &chunk.hashes {
            out.extend_from_slice(hash);
        }
    }
    Ok(out)
}

/// M1 `sealBegin(h, destId, kind, viewOnce, maxClass) -> sealerId, objectId` (§13.2). `K_f` and
/// `object_id` are drawn here, per object and per destination, from the OS CSPRNG — the crate
/// takes both as inputs and draws no randomness (§3.7 point 3); this surface is the one place the
/// design lets native code draw them. Kotlin never chooses an index or sees a key.
pub fn seal_begin(
    env: &mut JNIEnv,
    handle: jlong,
    dest_id: &JByteArray,
    kind: jint,
    view_once: jint,
    max_class: jint,
) -> Result<Vec<u8>, MediaCode> {
    let dest_id = fixed::<16>(env, dest_id)?;
    let kind = media_kind(kind)?;
    let max_class = size_class(max_class)?;
    with_media(handle, |context| {
        let mut key_f = [0u8; 32];
        let mut object_id = [0u8; 16];
        pq::fill_random(&mut key_f);
        pq::fill_random(&mut object_id);
        let sealer = media::Sealer::begin(
            media::FileKey::from_bytes(key_f),
            media::ObjectId::from_bytes(object_id),
            kind,
            view_once != 0,
            max_class,
        );
        key_f.zeroize();
        let id = insert_sealer(context, SealerEntry { sealer, dest_id })?;
        Ok(Reply::ok()
            .field(MediaField::SealerId, &id.to_be_bytes())
            .field(MediaField::ObjectId, &object_id)
            .into_bytes())
    })
}

/// M2 `sealAppend(h, sealerId, plaintext) -> chunks` (§13.2). The plaintext bytes are walked
/// before they are sealed, so a refusal spends the sealer and never seals a refused byte. The
/// fragments of every chunk this call completed — but the one held for the one-chunk lookahead —
/// return in the reply.
pub fn seal_append(
    env: &mut JNIEnv,
    handle: jlong,
    sealer_id: jlong,
    plaintext: &JByteArray,
) -> Result<Vec<u8>, MediaCode> {
    let plaintext = bytes(env, plaintext)?;
    with_media(handle, |context| {
        let entry = context
            .media_sealers
            .get_mut(&sealer_id)
            .ok_or(MediaCode::CryptoUnavailable)?;
        let chunks = entry
            .sealer
            .append(&plaintext)
            .map_err(MediaCode::from_media)?;
        Ok(Reply::ok()
            .field(MediaField::Chunks, &pack_chunks(&chunks)?)
            .into_bytes())
    })
}

/// M3 `sealFinish(h, sealerId, preview) -> chunks, manifest, keyEnv` (§13.2). The reply carries
/// the padding chunks' fragments and hashes, the manifest blob and its hash, the walked
/// dimensions and duration, and `key_env`: `K_f` wrapped under the context's `session_state_key`,
/// bound to `(out, destId, objectId, manifestHash)` — the only durable form the key ever takes.
pub fn seal_finish(
    env: &mut JNIEnv,
    handle: jlong,
    sealer_id: jlong,
    preview: &JByteArray,
) -> Result<Vec<u8>, MediaCode> {
    let preview = bytes(env, preview)?;
    with_media(handle, |context| {
        let entry = context
            .media_sealers
            .remove(&sealer_id)
            .ok_or(MediaCode::CryptoUnavailable)?;
        let object_id = *entry.sealer.object_id().as_bytes();
        let sealed = entry
            .sealer
            .finish(&preview)
            .map_err(MediaCode::from_media)?;
        let binding = wrap::media_file_key_binding(
            wrap::MEDIA_ROLE_OUT,
            &entry.dest_id,
            &object_id,
            &sealed.manifest_hash,
        );
        let key_env = wrap::wrap(
            &context.state_key,
            WrapName::MediaFileKey,
            &binding,
            sealed.file_key().as_bytes(),
        )
        .map_err(|_| MediaCode::StateCorrupt)?;
        let f = &sealed.manifest.fields;
        let mut hashes = Vec::with_capacity(sealed.manifest.hashes.len() * 32);
        for hash in &sealed.manifest.hashes {
            hashes.extend_from_slice(hash);
        }
        Ok(Reply::ok()
            .field(MediaField::Chunks, &pack_chunks(&sealed.chunks)?)
            .field(MediaField::ManifestBlob, &sealed.manifest_blob)
            .field(MediaField::ManifestHash, &sealed.manifest_hash)
            .field(MediaField::ClassCode, &[f.class.code()])
            .field(MediaField::ContentLen, &f.content_len.to_be_bytes())
            .field(MediaField::Width, &f.width.to_be_bytes())
            .field(MediaField::Height, &f.height.to_be_bytes())
            .field(MediaField::DurationMs, &f.duration_ms.to_be_bytes())
            .field(MediaField::KeyEnv, &key_env)
            .field(MediaField::Preview, &sealed.manifest.preview)
            .into_bytes())
    })
}

/// M4 `sealAbort(h, sealerId)` (§13.2). Drops the sealer; `K_f`, the derived keys and the held
/// chunk are wiped with it. Idempotent in effect — an unknown id is `CRYPTO_UNAVAILABLE`.
pub fn seal_abort(handle: jlong, sealer_id: jlong) -> Result<Vec<u8>, MediaCode> {
    with_media(handle, |context| {
        if context.media_sealers.remove(&sealer_id).is_none() {
            return Err(MediaCode::CryptoUnavailable);
        }
        Ok(Reply::ok().into_bytes())
    })
}

/// M5 `readerOpen(h, keyEnv, role, destId, objectId, manifestHash, manifestBlob, kind, viewOnce,
/// classCode, readable) -> readerId, manifestFields` (§13.2). The `key_env` unwrap is S2's
/// binding rule: it must open under `(role, destId, objectId, manifestHash)`, else the reply is
/// the wrap layer's refusal. The reader then checks the blob's hash, the commitment, the tag and
/// every manifest rule, and the descriptor's agreement.
#[allow(clippy::too_many_arguments)]
pub fn reader_open(
    env: &mut JNIEnv,
    handle: jlong,
    key_env: &JByteArray,
    role: jint,
    dest_id: &JByteArray,
    object_id: &JByteArray,
    manifest_hash: &JByteArray,
    manifest_blob: &JByteArray,
    kind: jint,
    view_once: jint,
    class_code: jint,
    readable_flag: jint,
) -> Result<Vec<u8>, MediaCode> {
    let key_env = bytes(env, key_env)?;
    let role = media_role(role)?;
    let dest_id = fixed::<16>(env, dest_id)?;
    let object_id = fixed::<16>(env, object_id)?;
    let manifest_hash = fixed::<32>(env, manifest_hash)?;
    let manifest_blob = bytes(env, manifest_blob)?;
    let kind = media_kind(kind)?;
    let class = size_class(class_code)?;
    let readable = readable(readable_flag)?;
    if manifest_blob.len() != media::consts::FRAG {
        return Err(MediaCode::HashMismatch);
    }
    with_media(handle, |context| {
        let binding = wrap::media_file_key_binding(role, &dest_id, &object_id, &manifest_hash);
        // A key_env that does not open under its binding is `STATE_CORRUPT` (§4.2): the object
        // goes `corrupt`, the message's other effects roll back with the transaction.
        let plain = wrap::unwrap(
            &context.state_key,
            WrapName::MediaFileKey,
            &binding,
            &key_env,
        )
        .map_err(|_| MediaCode::StateCorrupt)?;
        let key_f = <[u8; 32]>::try_from(plain.as_slice()).map_err(|_| MediaCode::StateCorrupt)?;
        let expected = media::Expected {
            object_id: media::ObjectId::from_bytes(object_id),
            kind,
            view_once: view_once != 0,
            class,
            manifest_hash,
        };
        let reader = media::Reader::open(
            &media::FileKey::from_bytes(key_f),
            &expected,
            &manifest_blob,
        )
        .map_err(MediaCode::from_media)?;
        let id = insert_reader(context, ReaderEntry { reader, readable })?;
        // The manifest fields come from the entry just opened: the reader was moved into the
        // registry, so read them back out of it.
        let entry = context
            .media_readers
            .get(&id)
            .ok_or(MediaCode::CryptoUnavailable)?;
        let manifest = entry.reader.manifest();
        let f = &manifest.fields;
        let mut hashes = Vec::with_capacity(manifest.hashes.len() * 32);
        for hash in &manifest.hashes {
            hashes.extend_from_slice(hash);
        }
        let mut reply = Reply::ok()
            .field(MediaField::ReaderId, &id.to_be_bytes())
            .field(MediaField::Kind, &[f.kind.byte()])
            .field(MediaField::Flags, &[u8::from(f.view_once)])
            .field(MediaField::ClassCode, &[f.class.code()])
            .field(MediaField::ContentLen, &f.content_len.to_be_bytes())
            .field(MediaField::Width, &f.width.to_be_bytes())
            .field(MediaField::Height, &f.height.to_be_bytes())
            .field(MediaField::DurationMs, &f.duration_ms.to_be_bytes())
            .field(MediaField::Hashes, &hashes);
        if !manifest.preview.is_empty() {
            reply = reply.field(MediaField::Preview, &manifest.preview);
        }
        Ok(reply.into_bytes())
    })
}

/// M6 `readerChunk(h, readerId, index, fragments, mode)` (§13.2): `mode` 0 validates (every
/// index, in order, through the content's walker; nothing is exposed) and 1 reads (random
/// access; the chunk's content bytes return in the reply, and only when every check passed — a
/// refused chunk exposes nothing). Read mode on a reader whose object the database does not hold
/// readable is `SEQUENCE` (§22.2 row 28a).
pub fn reader_chunk(
    env: &mut JNIEnv,
    handle: jlong,
    reader_id: jlong,
    index: jint,
    fragments: &JByteArray,
    mode: jint,
) -> Result<Vec<u8>, MediaCode> {
    let fragments = bytes(env, fragments)?;
    let index = u32::try_from(index).map_err(|_| MediaCode::IndexRange)?;
    if fragments.len() != media::consts::CHUNK_CT {
        return Err(MediaCode::HashMismatch);
    }
    with_media(handle, |context| match mode {
        0 => {
            let entry = context
                .media_readers
                .get_mut(&reader_id)
                .ok_or(MediaCode::CryptoUnavailable)?;
            entry
                .reader
                .validate_chunk(index, &fragments)
                .map_err(MediaCode::from_media)?;
            Ok(Reply::ok().into_bytes())
        }
        1 => {
            let entry = context
                .media_readers
                .get(&reader_id)
                .ok_or(MediaCode::CryptoUnavailable)?;
            if !entry.readable {
                return Err(MediaCode::Sequence);
            }
            let mut out = Zeroizing::new(vec![0u8; media::consts::CHUNK_PT]);
            let len = entry
                .reader
                .read_chunk(index, &fragments, &mut out)
                .map_err(MediaCode::from_media)?;
            let content = out.get(..len).ok_or(MediaCode::Oversize)?;
            Ok(Reply::ok()
                .field(MediaField::ChunkContent, content)
                .into_bytes())
        }
        _ => Err(MediaCode::NonCanonical),
    })
}

/// M7 `readerValidateFinish(h, readerId)` (§13.2): every chunk validated, the walk complete, and
/// the walked width, height and duration are the manifest's.
pub fn reader_validate_finish(handle: jlong, reader_id: jlong) -> Result<Vec<u8>, MediaCode> {
    with_media(handle, |context| {
        let entry = context
            .media_readers
            .get_mut(&reader_id)
            .ok_or(MediaCode::CryptoUnavailable)?;
        entry
            .reader
            .validate_finish()
            .map_err(MediaCode::from_media)?;
        Ok(Reply::ok().into_bytes())
    })
}

/// M8 `readerClose(h, readerId)` (§13.2). Drops the reader and wipes its derived key. An unknown
/// id is `CRYPTO_UNAVAILABLE`.
pub fn reader_close(handle: jlong, reader_id: jlong) -> Result<Vec<u8>, MediaCode> {
    with_media(handle, |context| {
        if context.media_readers.remove(&reader_id).is_none() {
            return Err(MediaCode::CryptoUnavailable);
        }
        Ok(Reply::ok().into_bytes())
    })
}

/// M9 `jpegCanonicalize(bytes)` (§13.2): the canonical baseline JPEG of §8.2. Stateless: no
/// handle.
pub fn jpeg_canonicalize(env: &mut JNIEnv, input: &JByteArray) -> Result<Vec<u8>, MediaCode> {
    let bytes = bytes(env, input)?;
    let canonical = media::jpeg::canonicalize(&bytes).map_err(MediaCode::from_media)?;
    Ok(Reply::ok()
        .field(MediaField::Canonical, &canonical)
        .into_bytes())
}

/// M10 `sniff(first64)` (§13.2): the source type from the allowlist of §6.1, or `UNSUPPORTED`.
/// Stateless: no handle.
pub fn sniff(env: &mut JNIEnv, first: &JByteArray) -> Result<Vec<u8>, MediaCode> {
    let first = bytes(env, first)?;
    let source = media::sniff::sniff(&first).map_err(MediaCode::from_media)?;
    let code = match source {
        media::SourceType::Jpeg => 1u8,
        media::SourceType::Png => 2,
        media::SourceType::Webp => 3,
        media::SourceType::IsoBmffVideo => 4,
    };
    Ok(Reply::ok()
        .field(MediaField::SourceType, &[code])
        .into_bytes())
}

/// `testSealBeginWithKey` (§13.2, §15.6): the host-only `sealBegin` whose `K_f` and `object_id`
/// come from the arguments — the world's seeded generator — so the model relay can re-derive a
/// media blob on `get` instead of storing its bytes. Production code never sees a chosen key
/// (G-M5 keeps this symbol out of shipped libraries).
#[cfg(feature = "test-vectors")]
pub fn test_seal_begin_with_key(
    env: &mut JNIEnv,
    handle: jlong,
    file_key: &JByteArray,
    object_id: &JByteArray,
    kind: jint,
    view_once: jint,
    max_class: jint,
) -> Result<Vec<u8>, MediaCode> {
    let file_key = fixed::<32>(env, file_key)?;
    let object_id = fixed::<16>(env, object_id)?;
    let kind = media_kind(kind)?;
    let max_class = size_class(max_class)?;
    with_media(handle, |context| {
        let sealer = media::Sealer::begin(
            media::FileKey::from_bytes(file_key),
            media::ObjectId::from_bytes(object_id),
            kind,
            view_once != 0,
            max_class,
        );
        let id = insert_sealer(
            context,
            SealerEntry {
                sealer,
                dest_id: [0u8; 16],
            },
        )?;
        Ok(Reply::ok()
            .field(MediaField::SealerId, &id.to_be_bytes())
            .field(MediaField::ObjectId, &object_id)
            .into_bytes())
    })
}

/// `testVectors` (§13.2): the host-only deterministic oracle the JVM side drives to re-derive
/// media values through the real library — the same role `MlsVectors.run` plays for the channel
/// crate's JDK replay. One request byte selects the case:
///
/// - `0x01 || K_f(32) || object_id(16)` → the derivations: [`MediaField::PayloadKey`],
///   [`MediaField::ManifestKey`] and [`MediaField::Commitment`];
/// - `0x02 || object_id(16) || ordinal(i16 BE) || retry_gen(1) || resend_count(1)` →
///   [`MediaField::OpId`];
/// - `0x03 || state_key(32) || role(1) || dest_id(16) || object_id(16) || manifest_hash(32) ||
///   nonce(12) || K_f(32)` → [`MediaField::KeyEnv`]: the `key_env` of §4.2 with the caller's
///   nonce, so the vector file's `[key_env]` section replays through the shipped wrap code.
///
/// Anything else is [`MediaCode::NonCanonical`].
#[cfg(feature = "test-vectors")]
pub fn test_vectors(
    env: &mut JNIEnv,
    _handle: jlong,
    request: &JByteArray,
) -> Result<Vec<u8>, MediaCode> {
    let request = bytes(env, request)?;
    let take = |range: std::ops::Range<usize>| -> Result<&[u8], MediaCode> {
        request.get(range).ok_or(MediaCode::NonCanonical)
    };
    match request.first().copied().ok_or(MediaCode::NonCanonical)? {
        0x01 => {
            let file_key =
                <[u8; 32]>::try_from(take(1..33)?).map_err(|_| MediaCode::NonCanonical)?;
            let object_id =
                <[u8; 16]>::try_from(take(33..49)?).map_err(|_| MediaCode::NonCanonical)?;
            if request.len() != 49 {
                return Err(MediaCode::NonCanonical);
            }
            let derived = media::keys::derive(
                &media::FileKey::from_bytes(file_key),
                &media::ObjectId::from_bytes(object_id),
            );
            Ok(Reply::ok()
                .field(MediaField::PayloadKey, derived.payload.as_bytes())
                .field(MediaField::ManifestKey, derived.manifest.as_bytes())
                .field(MediaField::Commitment, derived.commitment.as_bytes())
                .into_bytes())
        }
        0x02 => {
            let object_id =
                <[u8; 16]>::try_from(take(1..17)?).map_err(|_| MediaCode::NonCanonical)?;
            let ordinal = i16::from_be_bytes(
                <[u8; 2]>::try_from(take(17..19)?).map_err(|_| MediaCode::NonCanonical)?,
            );
            let retry_gen = *request.get(19).ok_or(MediaCode::NonCanonical)?;
            let resend_count = *request.get(20).ok_or(MediaCode::NonCanonical)?;
            if request.len() != 21 {
                return Err(MediaCode::NonCanonical);
            }
            let op = media::keys::op_id(
                &media::ObjectId::from_bytes(object_id),
                ordinal,
                retry_gen,
                resend_count,
            );
            Ok(Reply::ok().field(MediaField::OpId, &op).into_bytes())
        }
        0x03 => {
            let state_key =
                <[u8; 32]>::try_from(take(1..33)?).map_err(|_| MediaCode::NonCanonical)?;
            let role = media_role(i32::from(*request.get(33).ok_or(MediaCode::NonCanonical)?))?;
            let dest_id =
                <[u8; 16]>::try_from(take(34..50)?).map_err(|_| MediaCode::NonCanonical)?;
            let object_id =
                <[u8; 16]>::try_from(take(50..66)?).map_err(|_| MediaCode::NonCanonical)?;
            let manifest_hash =
                <[u8; 32]>::try_from(take(66..98)?).map_err(|_| MediaCode::NonCanonical)?;
            let nonce =
                <[u8; 12]>::try_from(take(98..110)?).map_err(|_| MediaCode::NonCanonical)?;
            let file_key =
                <[u8; 32]>::try_from(take(110..142)?).map_err(|_| MediaCode::NonCanonical)?;
            if request.len() != 142 {
                return Err(MediaCode::NonCanonical);
            }
            let binding = wrap::media_file_key_binding(role, &dest_id, &object_id, &manifest_hash);
            let key_env = wrap::wrap_with_nonce(
                &crate::derive::StateKey::from_bytes(state_key),
                WrapName::MediaFileKey,
                &binding,
                &file_key,
                &nonce,
            )
            .map_err(|_| MediaCode::StateCorrupt)?;
            Ok(Reply::ok().field(MediaField::KeyEnv, &key_env).into_bytes())
        }
        _ => Err(MediaCode::NonCanonical),
    }
}

/// The entry points, for the export macros. Each is `pub` so `ghost-client-net` and
/// `ghost-dm-host` re-export exactly these bodies.
pub mod entry {
    use super::*;

    /// `sealBegin`
    pub fn seal_begin<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
        dest_id: JByteArray<'local>,
        kind: jint,
        view_once: jint,
        max_class: jint,
    ) -> jbyteArray {
        guarded(&mut env, |env| {
            super::seal_begin(env, handle, &dest_id, kind, view_once, max_class)
        })
    }

    /// `sealAppend`
    pub fn seal_append<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
        sealer_id: jlong,
        plaintext: JByteArray<'local>,
    ) -> jbyteArray {
        guarded(&mut env, |env| {
            super::seal_append(env, handle, sealer_id, &plaintext)
        })
    }

    /// `sealFinish`
    pub fn seal_finish<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
        sealer_id: jlong,
        preview: JByteArray<'local>,
    ) -> jbyteArray {
        guarded(&mut env, |env| {
            super::seal_finish(env, handle, sealer_id, &preview)
        })
    }

    /// `sealAbort`
    pub fn seal_abort<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
        sealer_id: jlong,
    ) -> jbyteArray {
        guarded(&mut env, |_| super::seal_abort(handle, sealer_id))
    }

    /// `readerOpen`
    #[allow(clippy::too_many_arguments)]
    pub fn reader_open<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
        key_env: JByteArray<'local>,
        role: jint,
        dest_id: JByteArray<'local>,
        object_id: JByteArray<'local>,
        manifest_hash: JByteArray<'local>,
        manifest_blob: JByteArray<'local>,
        kind: jint,
        view_once: jint,
        class_code: jint,
        readable: jint,
    ) -> jbyteArray {
        guarded(&mut env, |env| {
            super::reader_open(
                env,
                handle,
                &key_env,
                role,
                &dest_id,
                &object_id,
                &manifest_hash,
                &manifest_blob,
                kind,
                view_once,
                class_code,
                readable,
            )
        })
    }

    /// `readerChunk`
    pub fn reader_chunk<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
        reader_id: jlong,
        index: jint,
        fragments: JByteArray<'local>,
        mode: jint,
    ) -> jbyteArray {
        guarded(&mut env, |env| {
            super::reader_chunk(env, handle, reader_id, index, &fragments, mode)
        })
    }

    /// `readerValidateFinish`
    pub fn reader_validate_finish<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
        reader_id: jlong,
    ) -> jbyteArray {
        guarded(&mut env, |_| {
            super::reader_validate_finish(handle, reader_id)
        })
    }

    /// `readerClose`
    pub fn reader_close<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
        reader_id: jlong,
    ) -> jbyteArray {
        guarded(&mut env, |_| super::reader_close(handle, reader_id))
    }

    /// `jpegCanonicalize`
    pub fn jpeg_canonicalize<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        bytes: JByteArray<'local>,
    ) -> jbyteArray {
        guarded(&mut env, |env| super::jpeg_canonicalize(env, &bytes))
    }

    /// `sniff`
    pub fn sniff<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        first: JByteArray<'local>,
    ) -> jbyteArray {
        guarded(&mut env, |env| super::sniff(env, &first))
    }

    /// `testSealBeginWithKey` (host-only)
    #[cfg(feature = "test-vectors")]
    #[allow(clippy::too_many_arguments)]
    pub fn test_seal_begin_with_key<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
        file_key: JByteArray<'local>,
        object_id: JByteArray<'local>,
        kind: jint,
        view_once: jint,
        max_class: jint,
    ) -> jbyteArray {
        guarded(&mut env, |env| {
            super::test_seal_begin_with_key(
                env, handle, &file_key, &object_id, kind, view_once, max_class,
            )
        })
    }

    /// `testVectors` (host-only)
    #[cfg(feature = "test-vectors")]
    pub fn test_vectors<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
        request: JByteArray<'local>,
    ) -> jbyteArray {
        guarded(&mut env, |env| super::test_vectors(env, handle, &request))
    }
}

/// Exports the media JNI entry points from the calling crate (Phase 11 design §13.1, §13.2).
/// `ghost-client-net` invokes this beside `export_jni!` so `libghost_client_net.so` carries the
/// closed media list, and `ghost-dm-host` invokes it too so the JVM tests call exactly the
/// shipped code.
#[macro_export]
macro_rules! export_media_jni {
    () => {
        /// One entry point of the closed media JNI surface (Phase 11 design §13.2); the body is
        /// in [`ghost_client_dm::jni_media::entry`].
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MediaNative_sealBegin<'local>(
            env: ::jni::JNIEnv<'local>,
            class: ::jni::objects::JClass<'local>,
            handle: ::jni::sys::jlong,
            dest_id: ::jni::objects::JByteArray<'local>,
            kind: ::jni::sys::jint,
            view_once: ::jni::sys::jint,
            max_class: ::jni::sys::jint,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni_media::entry::seal_begin(
                env, class, handle, dest_id, kind, view_once, max_class,
            )
        }

        /// One entry point of the closed media JNI surface (Phase 11 design §13.2).
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MediaNative_sealAppend<'local>(
            env: ::jni::JNIEnv<'local>,
            class: ::jni::objects::JClass<'local>,
            handle: ::jni::sys::jlong,
            sealer_id: ::jni::sys::jlong,
            plaintext: ::jni::objects::JByteArray<'local>,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni_media::entry::seal_append(env, class, handle, sealer_id, plaintext)
        }

        /// One entry point of the closed media JNI surface (Phase 11 design §13.2).
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MediaNative_sealFinish<'local>(
            env: ::jni::JNIEnv<'local>,
            class: ::jni::objects::JClass<'local>,
            handle: ::jni::sys::jlong,
            sealer_id: ::jni::sys::jlong,
            preview: ::jni::objects::JByteArray<'local>,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni_media::entry::seal_finish(env, class, handle, sealer_id, preview)
        }

        /// One entry point of the closed media JNI surface (Phase 11 design §13.2).
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MediaNative_sealAbort<'local>(
            env: ::jni::JNIEnv<'local>,
            class: ::jni::objects::JClass<'local>,
            handle: ::jni::sys::jlong,
            sealer_id: ::jni::sys::jlong,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni_media::entry::seal_abort(env, class, handle, sealer_id)
        }

        /// One entry point of the closed media JNI surface (Phase 11 design §13.2).
        #[no_mangle]
        #[allow(clippy::too_many_arguments)]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MediaNative_readerOpen<'local>(
            env: ::jni::JNIEnv<'local>,
            class: ::jni::objects::JClass<'local>,
            handle: ::jni::sys::jlong,
            key_env: ::jni::objects::JByteArray<'local>,
            role: ::jni::sys::jint,
            dest_id: ::jni::objects::JByteArray<'local>,
            object_id: ::jni::objects::JByteArray<'local>,
            manifest_hash: ::jni::objects::JByteArray<'local>,
            manifest_blob: ::jni::objects::JByteArray<'local>,
            kind: ::jni::sys::jint,
            view_once: ::jni::sys::jint,
            class_code: ::jni::sys::jint,
            readable: ::jni::sys::jint,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni_media::entry::reader_open(
                env,
                class,
                handle,
                key_env,
                role,
                dest_id,
                object_id,
                manifest_hash,
                manifest_blob,
                kind,
                view_once,
                class_code,
                readable,
            )
        }

        /// One entry point of the closed media JNI surface (Phase 11 design §13.2).
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MediaNative_readerChunk<'local>(
            env: ::jni::JNIEnv<'local>,
            class: ::jni::objects::JClass<'local>,
            handle: ::jni::sys::jlong,
            reader_id: ::jni::sys::jlong,
            index: ::jni::sys::jint,
            fragments: ::jni::objects::JByteArray<'local>,
            mode: ::jni::sys::jint,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni_media::entry::reader_chunk(
                env, class, handle, reader_id, index, fragments, mode,
            )
        }

        /// One entry point of the closed media JNI surface (Phase 11 design §13.2).
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MediaNative_readerValidateFinish<
            'local,
        >(
            env: ::jni::JNIEnv<'local>,
            class: ::jni::objects::JClass<'local>,
            handle: ::jni::sys::jlong,
            reader_id: ::jni::sys::jlong,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni_media::entry::reader_validate_finish(env, class, handle, reader_id)
        }

        /// One entry point of the closed media JNI surface (Phase 11 design §13.2).
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MediaNative_readerClose<'local>(
            env: ::jni::JNIEnv<'local>,
            class: ::jni::objects::JClass<'local>,
            handle: ::jni::sys::jlong,
            reader_id: ::jni::sys::jlong,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni_media::entry::reader_close(env, class, handle, reader_id)
        }

        /// One entry point of the closed media JNI surface (Phase 11 design §13.2).
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MediaNative_jpegCanonicalize<'local>(
            env: ::jni::JNIEnv<'local>,
            class: ::jni::objects::JClass<'local>,
            bytes: ::jni::objects::JByteArray<'local>,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni_media::entry::jpeg_canonicalize(env, class, bytes)
        }

        /// One entry point of the closed media JNI surface (Phase 11 design §13.2).
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MediaNative_sniff<'local>(
            env: ::jni::JNIEnv<'local>,
            class: ::jni::objects::JClass<'local>,
            first: ::jni::objects::JByteArray<'local>,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni_media::entry::sniff(env, class, first)
        }
    };
}

/// Exports the **test-only** media entry points (`testVectors`, `testSealBeginWithKey`, §13.2,
/// §15.6) in the invoking crate. Only `ghost-dm-host` invokes this — it is the only build with
/// `ghost-client-dm`'s `test-vectors` feature, whose absence from every shipped graph G-R2
/// checks and whose symbols' absence from every shipped library G-M5 checks.
#[cfg(feature = "test-vectors")]
#[macro_export]
macro_rules! export_media_test_jni {
    () => {
        /// The host-only media test entry (Phase 11 design §13.2, §15.6); test libraries only.
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MediaNative_testSealBeginWithKey<
            'local,
        >(
            env: ::jni::JNIEnv<'local>,
            class: ::jni::objects::JClass<'local>,
            handle: ::jni::sys::jlong,
            file_key: ::jni::objects::JByteArray<'local>,
            object_id: ::jni::objects::JByteArray<'local>,
            kind: ::jni::sys::jint,
            view_once: ::jni::sys::jint,
            max_class: ::jni::sys::jint,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni_media::entry::test_seal_begin_with_key(
                env, class, handle, file_key, object_id, kind, view_once, max_class,
            )
        }

        /// The host-only media vector oracle (Phase 11 design §13.2); test libraries only.
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MediaNative_testVectors<'local>(
            env: ::jni::JNIEnv<'local>,
            class: ::jni::objects::JClass<'local>,
            handle: ::jni::sys::jlong,
            request: ::jni::objects::JByteArray<'local>,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni_media::entry::test_vectors(env, class, handle, request)
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_bytes_round_trip_and_are_distinct() {
        let mut seen = Vec::new();
        for code in MediaCode::ALL {
            assert_eq!(MediaCode::from_u8(code.as_u8()), Some(code));
            assert!(!seen.contains(&code.as_u8()), "duplicate wire byte");
            seen.push(code.as_u8());
        }
        assert_eq!(seen.len(), MediaCode::ALL.len());
    }

    #[test]
    fn undefined_bytes_have_no_code() {
        for byte in 0x0du8..=0xfe {
            assert_eq!(MediaCode::from_u8(byte), None);
        }
    }

    #[test]
    fn names_are_distinct_and_screaming_snake_case() {
        let mut names: Vec<&str> = MediaCode::ALL.iter().map(|c| c.name()).collect();
        for name in &names {
            assert!(
                name.bytes().all(|b| b.is_ascii_uppercase() || b == b'_'),
                "{name}"
            );
        }
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count);
    }

    #[test]
    fn media_field_tags_are_distinct_and_dense() {
        let mut tags: Vec<u8> = MediaField::ALL.iter().map(|f| f.tag()).collect();
        tags.sort_unstable();
        assert_eq!(tags, (0x01..=0x17).collect::<Vec<u8>>());
    }

    /// §13.2's list is the table's M1 … M10 in order.
    #[test]
    fn the_closed_list_is_the_tables_m1_to_m10() {
        let names: Vec<&str> = MEDIA_CLOSED_LIST.iter().map(|(_, n)| *n).collect();
        assert_eq!(
            names,
            [
                "sealBegin",
                "sealAppend",
                "sealFinish",
                "sealAbort",
                "readerOpen",
                "readerChunk",
                "readerValidateFinish",
                "readerClose",
                "jpegCanonicalize",
                "sniff",
            ]
        );
    }

    /// The function-code table names only codes of the closed list, and every function on the
    /// closed list has a row.
    #[test]
    fn function_codes_reference_only_defined_codes() {
        for (name, codes) in MEDIA_FUNCTION_CODES {
            assert!(
                MEDIA_CLOSED_LIST.iter().any(|(_, n)| n == name)
                    || matches!(*name, "testVectors" | "testSealBeginWithKey"),
                "{name} is not a function of the surface"
            );
            for code in *codes {
                assert_ne!(*code, MediaCode::Ok);
                assert_ne!(*code, MediaCode::Internal);
                assert!(MediaCode::ALL.contains(code));
            }
        }
    }
}
