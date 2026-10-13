package org.ghost.crypto.bridge

/**
 * The typed facade over [MediaNative] (Phase 11 design §13.1, §13.2; slice S2): the only way
 * `:media` reaches the media cryptography. Each function decodes the native reply into a typed
 * result, maps every code the function can produce (the `MEDIA_FUNCTION_CODES` table of
 * `jni_media.rs`), and throws `IllegalStateException` on [MediaCode.INTERNAL] or any other
 * disagreement — a caught panic or a surface mismatch means roll back and treat the state as
 * poison, exactly like `DmSessions`.
 *
 * Nothing here decides a protocol value: indices, nonces, keys, the class, the walked dimensions
 * and the binding all stay in Rust (ADR-19). The caller supplies files, fragments and database
 * rows; this facade moves bytes and registry ids.
 *
 * Key custody (§4.2): `K_f` never crosses this boundary. `begin` returns only a sealer id and
 * the object id; `finish` returns `key_env`, already bound to `(out, destId, objectId,
 * manifestHash)`; `openReader` takes `key_env` back and unwraps it natively. The one thing that
 * ever resembles a key here is the envelope, which opens only inside Rust.
 */
object MediaCrypto {

    /** The media kind argument of [begin] and `readerOpen` (§3.5). */
    enum class Kind(val wire: Int) {
        /** A canonical baseline JPEG (§8.2); always class 0. */
        IMAGE(1),

        /** A canonical fragmented MP4 (§8.3). */
        VIDEO(2),
    }

    /** The chunk mode of [chunk] (§13.2 M6). */
    enum class Mode(val wire: Int) {
        /** The validation pass: every index in order, through the content's walker; nothing is exposed. */
        VALIDATE(0),

        /**
         * Random access for display and playback. The object must be one the database holds
         * readable — a recipient's `verified` object, or the sender's own `out` object in
         * `uploading`, `uploaded` or `failed` — else the call refuses with
         * [Chunked.Sequence] (§22.2 row 28a); attest it through `openReader`'s `readable`.
         */
        READ(1),
    }

    /** The source types of `sniff` (§6.1). */
    enum class SourceType(val wire: Int) {
        JPEG(1),
        PNG(2),
        WEBP(3),
        ISO_BMFF_VIDEO(4),
    }

    /** The role byte of `readerOpen` (§4.2). */
    enum class Role(val wire: Int) {
        /** The sender's object; `key_env` bound with role 0x01. */
        OUT(1),

        /** The recipient's object; `key_env` bound with role 0x02. */
        IN(2),
    }

    /** One sealed chunk as [append] and [finish] return it: its index, four fragments, four hashes. */
    class SealedChunk(
        /** `i`. */
        val index: Int,
        /** The four 65 536-byte fragments of `C_i`, in order. */
        val fragments: List<ByteArray>,
        /** SHA-256 of each fragment, in order. */
        val hashes: List<ByteArray>,
    )

    /** What [begin] returns besides the refusals: the sealer's registry id and the object id. */
    class Sealer(
        /** The id every further call of this object names. */
        val id: Long,
        /** The object's 16-byte id; the caller stores it before the first append. */
        val objectId: ByteArray,
    )

    /** What [finish] returns: the tail of the object and the only durable form of its key. */
    class Finished(
        /** The padding chunks' fragments and hashes (the held chunk and the zero chunks). */
        val chunks: List<SealedChunk>,
        /** The 65 536-byte manifest blob (a relay blob of its own). */
        val manifestBlob: ByteArray,
        /** SHA-256 of [manifestBlob]: the descriptor's `manifest_hash`. */
        val manifestHash: ByteArray,
        /** The class the walked `content_len` chose (§3.6). */
        val classCode: Int,
        /** The exact content length, in bytes. */
        val contentLen: Long,
        /** The walked (displayed) width. */
        val width: Int,
        /** The walked (displayed) height. */
        val height: Int,
        /** The walked duration in milliseconds (0 for an image). */
        val durationMs: Long,
        /**
         * `key_env` (60 bytes): `K_f` wrapped under `session_state_key`, bound to
         * `(out, destId, objectId, manifestHash)`. The caller stores it in `media_object.key_env`
         * at `MEDIA-COMMIT`; it is the only form in which the key ever persists.
         */
        val keyEnv: ByteArray,
        /** The preview the caller supplied, as the manifest now carries it (empty for view-once). */
        val preview: ByteArray,
    )

    /** What [openReader] returns: the reader's id and the manifest fields it opened to. */
    class OpenedReader(
        /** The id every further call of this object names. */
        val id: Long,
        /** The manifest's kind. */
        val kind: Kind,
        /** The manifest's view-once flag. */
        val viewOnce: Boolean,
        /** The manifest's class code. */
        val classCode: Int,
        /** The manifest's exact content length. */
        val contentLen: Long,
        /** The walked (displayed) width. */
        val width: Int,
        /** The walked (displayed) height. */
        val height: Int,
        /** The walked duration in milliseconds (0 for an image). */
        val durationMs: Long,
        /** The manifest's preview, empty for a view-once object. */
        val preview: ByteArray,
        /** The manifest's ordered fragment hashes, `F` of them. */
        val hashes: List<ByteArray>,
    )

    /** M1 `sealBegin`: a new sealer for one object to one destination (§3.7). */
    sealed interface Begun {
        /** The sealer. At most two live at once per context ([Limited] beyond that). */
        class Ok(val sealer: Sealer) : Begun

        /** Two sealers are already live (§13.2 M1). */
        data object Limited : Begun

        /** A kind or class argument the surface does not take. */
        data object NonCanonical : Begun

        /** The native library is missing or the context is closed. */
        data object Unavailable : Begun
    }

    fun begin(handle: Long, destId: ByteArray, kind: Kind, viewOnce: Boolean, maxClass: Int): Begun {
        if (!MediaNative.isAvailable()) return Begun.Unavailable
        val result = call {
            MediaNative.sealBegin(handle, destId, kind.wire, if (viewOnce) 1 else 0, maxClass)
        }
        return when (result.code) {
            MediaCode.OK -> Begun.Ok(
                Sealer(
                    id = result.i64(MediaField.SEALER_ID),
                    objectId = result.bytes(MediaField.OBJECT_ID),
                )
            )
            MediaCode.LIMIT -> Begun.Limited
            MediaCode.NON_CANONICAL -> Begun.NonCanonical
            MediaCode.CRYPTO_UNAVAILABLE -> Begun.Unavailable
            else -> unexpected(result.code, "sealBegin")
        }
    }

    /** M2 `sealAppend`: the fragments of every chunk this call completed (§13.2 M2). */
    sealed interface Appended {
        /** The completed chunks; possibly empty when the lookahead still holds the only chunk begun. */
        class Ok(val chunks: List<SealedChunk>) : Appended

        /** The walker refused the stream (`NON_CANONICAL`): the sealer is spent. */
        data object NonCanonical : Appended

        /** Above the class cap, `MAX_CONTENT` or `IMAGE_MAX_CONTENT`. */
        data object Oversize : Appended

        /** A GHOST bug: an index sealed twice. */
        data object IndexReused : Appended

        /** The sealer was used after `finish` or a refusal. */
        data object Sequence : Appended

        /** The native library is missing, the context is closed, or the sealer id is foreign. */
        data object Unavailable : Appended
    }

    fun append(handle: Long, sealerId: Long, plaintext: ByteArray): Appended {
        if (!MediaNative.isAvailable()) return Appended.Unavailable
        val result = call { MediaNative.sealAppend(handle, sealerId, plaintext) }
        return when (result.code) {
            MediaCode.OK -> Appended.Ok(chunks(result.bytes(MediaField.CHUNKS)))
            MediaCode.NON_CANONICAL -> Appended.NonCanonical
            MediaCode.OVERSIZE -> Appended.Oversize
            MediaCode.INDEX_REUSED -> Appended.IndexReused
            MediaCode.SEQUENCE -> Appended.Sequence
            MediaCode.CRYPTO_UNAVAILABLE -> Appended.Unavailable
            else -> unexpected(result.code, "sealAppend")
        }
    }

    /** M3 `sealFinish`: the padding chunks, the manifest and `key_env` (§13.2 M3). */
    sealed interface FinishedResult {
        /** The object is finished; the sealer is gone. */
        class Ok(val finished: Finished) : FinishedResult

        /** The walker never completed, or the preview is not a canonical JPEG of the preview geometry. */
        data object NonCanonical : FinishedResult

        /** The `mfra` pushed the content above the cap. */
        data object Oversize : FinishedResult

        /** The sealer was used after a refusal. */
        data object Sequence : FinishedResult

        /** The native library is missing, the context is closed, or the sealer id is foreign. */
        data object Unavailable : FinishedResult
    }

    fun finish(handle: Long, sealerId: Long, preview: ByteArray): FinishedResult {
        if (!MediaNative.isAvailable()) return FinishedResult.Unavailable
        val result = call { MediaNative.sealFinish(handle, sealerId, preview) }
        return when (result.code) {
            MediaCode.OK -> FinishedResult.Ok(
                Finished(
                    chunks = chunks(result.bytes(MediaField.CHUNKS)),
                    manifestBlob = result.bytes(MediaField.MANIFEST_BLOB),
                    manifestHash = result.bytes(MediaField.MANIFEST_HASH),
                    classCode = result.byte(MediaField.CLASS_CODE),
                    contentLen = result.u64(MediaField.CONTENT_LEN),
                    width = result.u16(MediaField.WIDTH),
                    height = result.u16(MediaField.HEIGHT),
                    durationMs = result.u32(MediaField.DURATION_MS),
                    keyEnv = result.bytes(MediaField.KEY_ENV),
                    preview = result.bytesOrNull(MediaField.PREVIEW) ?: ByteArray(0),
                )
            )
            MediaCode.NON_CANONICAL -> FinishedResult.NonCanonical
            MediaCode.OVERSIZE -> FinishedResult.Oversize
            MediaCode.SEQUENCE -> FinishedResult.Sequence
            MediaCode.CRYPTO_UNAVAILABLE -> FinishedResult.Unavailable
            else -> unexpected(result.code, "sealFinish")
        }
    }

    /** M4 `sealAbort`: discard the sealer and its key (§13.2 M4). Idempotent in effect. */
    fun abort(handle: Long, sealerId: Long): Boolean {
        if (!MediaNative.isAvailable()) return false
        val result = call { MediaNative.sealAbort(handle, sealerId) }
        return when (result.code) {
            MediaCode.OK -> true
            MediaCode.CRYPTO_UNAVAILABLE -> false
            else -> unexpected(result.code, "sealAbort")
        }
    }

    /** M5 `readerOpen`: unwrap `key_env`, open the manifest, return its fields (§13.2 M5). */
    sealed interface Opened {
        /** The reader. At most eight live at once per context ([Limited] beyond that). */
        class Ok(val reader: OpenedReader) : Opened

        /** The manifest blob is not the one `manifestHash` names. */
        data object HashMismatch : Opened

        /** The commitment does not match the key. */
        data object CommitMismatch : Opened

        /** The manifest's tag does not verify under `K_m`. */
        data object NotOpen : Opened

        /**
         * Every other manifest rule, or disagreement with the descriptor arguments
         * (kind, flags, class, object id) the caller passes from the L0 it parsed.
         */
        data object NonCanonical : Opened

        /** `key_env` does not open under `(role, destId, objectId, manifestHash)` (§4.2). */
        data object StateCorrupt : Opened

        /** Eight readers are already live (§13.2 M5). */
        data object Limited : Opened

        /** The native library is missing, the context is closed, or an argument has the wrong shape. */
        data object Unavailable : Opened
    }

    /**
     * Opens a reader. [readable] attests the object is one the database holds readable — a
     * recipient's `verified` object, or the sender's own `out` object in `uploading`,
     * `uploaded` or `failed` — without which [chunk] in [Mode.READ] refuses with `SEQUENCE`
     * (§22.2 row 28a). The manifest blob is the exact 65 536-byte relay blob; the fragment hashes
     * to fetch come back in [OpenedReader.hashes].
     */
    fun openReader(
        handle: Long,
        keyEnv: ByteArray,
        role: Role,
        destId: ByteArray,
        objectId: ByteArray,
        manifestHash: ByteArray,
        manifestBlob: ByteArray,
        kind: Kind,
        viewOnce: Boolean,
        classCode: Int,
        readable: Boolean,
    ): Opened {
        if (!MediaNative.isAvailable()) return Opened.Unavailable
        val result = call {
            MediaNative.readerOpen(
                handle,
                keyEnv,
                role.wire,
                destId,
                objectId,
                manifestHash,
                manifestBlob,
                kind.wire,
                if (viewOnce) 1 else 0,
                classCode,
                if (readable) 1 else 0,
            )
        }
        return when (result.code) {
            MediaCode.OK -> Opened.Ok(
                OpenedReader(
                    id = result.i64(MediaField.READER_ID),
                    kind = kind,
                    viewOnce = result.byte(MediaField.FLAGS) and 1 != 0,
                    classCode = result.byte(MediaField.CLASS_CODE),
                    contentLen = result.u64(MediaField.CONTENT_LEN),
                    width = result.u16(MediaField.WIDTH),
                    height = result.u16(MediaField.HEIGHT),
                    durationMs = result.u32(MediaField.DURATION_MS),
                    preview = result.bytesOrNull(MediaField.PREVIEW) ?: ByteArray(0),
                    hashes = hashes(result.bytes(MediaField.HASHES)),
                )
            )
            MediaCode.HASH_MISMATCH -> Opened.HashMismatch
            MediaCode.COMMIT_MISMATCH -> Opened.CommitMismatch
            MediaCode.NOT_OPEN -> Opened.NotOpen
            MediaCode.NON_CANONICAL -> Opened.NonCanonical
            MediaCode.STATE_CORRUPT -> Opened.StateCorrupt
            MediaCode.LIMIT -> Opened.Limited
            MediaCode.CRYPTO_UNAVAILABLE -> Opened.Unavailable
            else -> unexpected(result.code, "readerOpen")
        }
    }

    /** M6 `readerChunk`: validate one chunk in order, or read one chunk's content (§13.2 M6). */
    sealed interface Chunked {
        /** The chunk passed (validate), or its content bytes (read). */
        class Ok(val content: ByteArray) : Chunked

        /** The tag does not verify, or the chunk's bytes break a canonical rule. */
        data object NonCanonical : Chunked

        /** The chunk's tag does not verify under its index and the last flag. */
        data object NotOpen : Chunked

        /** A fragment is not the blob the manifest names at its position. */
        data object HashMismatch : Chunked

        /** The index is outside the object. */
        data object IndexRange : Chunked

        /** A validate pass out of order or repeated, or a read on an object not attested readable. */
        data object Sequence : Chunked

        /** The native library is missing, the context is closed, or the reader id is foreign. */
        data object Unavailable : Chunked
    }

    /**
     * One chunk from its four fragments (`4 × 65 536` bytes, in order). In [Mode.READ] the
     * content is at most 262 128 bytes; in [Mode.VALIDATE] it is empty and nothing is exposed.
     * A refusal exposes nothing.
     */
    fun chunk(
        handle: Long,
        readerId: Long,
        index: Int,
        fragments: ByteArray,
        mode: Mode,
    ): Chunked {
        if (!MediaNative.isAvailable()) return Chunked.Unavailable
        val result = call { MediaNative.readerChunk(handle, readerId, index, fragments, mode.wire) }
        return when (result.code) {
            MediaCode.OK -> Chunked.Ok(
                result.bytesOrNull(MediaField.CHUNK_CONTENT) ?: ByteArray(0)
            )
            MediaCode.NON_CANONICAL -> Chunked.NonCanonical
            MediaCode.NOT_OPEN -> Chunked.NotOpen
            MediaCode.HASH_MISMATCH -> Chunked.HashMismatch
            MediaCode.INDEX_RANGE -> Chunked.IndexRange
            MediaCode.SEQUENCE -> Chunked.Sequence
            MediaCode.CRYPTO_UNAVAILABLE -> Chunked.Unavailable
            else -> unexpected(result.code, "readerChunk")
        }
    }

    /** M7 `readerValidateFinish`: the walk's end against the manifest (§13.2 M7). */
    sealed interface Validated {
        /** Every chunk validated and the walked geometry is the manifest's. */
        data object Ok : Validated

        /** Chunks missing, the walk incomplete, or the walked geometry unlike the manifest's. */
        data object NonCanonical : Validated

        /** A validation pass already ended. */
        data object Sequence : Validated

        /** The native library is missing, the context is closed, or the reader id is foreign. */
        data object Unavailable : Validated
    }

    fun validateFinish(handle: Long, readerId: Long): Validated {
        if (!MediaNative.isAvailable()) return Validated.Unavailable
        val result = call { MediaNative.readerValidateFinish(handle, readerId) }
        return when (result.code) {
            MediaCode.OK -> Validated.Ok
            MediaCode.NON_CANONICAL -> Validated.NonCanonical
            MediaCode.SEQUENCE -> Validated.Sequence
            MediaCode.CRYPTO_UNAVAILABLE -> Validated.Unavailable
            else -> unexpected(result.code, "readerValidateFinish")
        }
    }

    /** M8 `readerClose`: discard the reader and its derived key (§13.2 M8). */
    fun closeReader(handle: Long, readerId: Long): Boolean {
        if (!MediaNative.isAvailable()) return false
        val result = call { MediaNative.readerClose(handle, readerId) }
        return when (result.code) {
            MediaCode.OK -> true
            MediaCode.CRYPTO_UNAVAILABLE -> false
            else -> unexpected(result.code, "readerClose")
        }
    }

    /** M9 `jpegCanonicalize`: the canonical baseline JPEG (§8.2). Stateless. */
    sealed interface Canonical {
        /** The canonical bytes: equal to the input exactly when the input was already canonical. */
        class Ok(val bytes: ByteArray) : Canonical

        /** Not a baseline JPEG the profile accepts. */
        data object NonCanonical : Canonical

        /** The native library is missing. */
        data object Unavailable : Canonical
    }

    fun jpegCanonicalize(bytes: ByteArray): Canonical {
        if (!MediaNative.isAvailable()) return Canonical.Unavailable
        val result = call { MediaNative.jpegCanonicalize(bytes) }
        return when (result.code) {
            MediaCode.OK -> Canonical.Ok(result.bytes(MediaField.CANONICAL))
            MediaCode.NON_CANONICAL -> Canonical.NonCanonical
            MediaCode.CRYPTO_UNAVAILABLE -> Canonical.Unavailable
            else -> unexpected(result.code, "jpegCanonicalize")
        }
    }

    /** M10 `sniff`: the source type from the first bytes (§6.1). Stateless. */
    sealed interface Sniffed {
        /** The allowlist's type. */
        class Ok(val type: SourceType) : Sniffed

        /** Outside the allowlist. */
        data object Unsupported : Sniffed

        /** The native library is missing. */
        data object Unavailable : Sniffed
    }

    fun sniff(first64: ByteArray): Sniffed {
        if (!MediaNative.isAvailable()) return Sniffed.Unavailable
        val result = call { MediaNative.sniff(first64) }
        return when (result.code) {
            MediaCode.OK -> {
                val wire = result.byte(MediaField.SOURCE_TYPE)
                val type = SourceType.entries.firstOrNull { it.wire == wire }
                    ?: unexpected(MediaCode.INTERNAL, "sniff")
                Sniffed.Ok(type)
            }
            MediaCode.UNSUPPORTED -> Sniffed.Unsupported
            MediaCode.CRYPTO_UNAVAILABLE -> Sniffed.Unavailable
            else -> unexpected(result.code, "sniff")
        }
    }

    private const val FRAGMENT_BYTES = 65_536
    private const val HASH_BYTES = 32
    private const val FRAGMENTS_PER_CHUNK = 4

    /** Slices the packed `CHUNKS` field: `u32 count || (u32 index || frag×4 || hash×4)*`. */
    private fun chunks(packed: ByteArray): List<SealedChunk> {
        if (packed.size < 4) throw IllegalStateException("CHUNKS is shorter than its count")
        val count = u32At(packed, 0)
        val chunks = ArrayList<SealedChunk>(count)
        var at = 4
        repeat(count) {
            if (at + 4 > packed.size) throw IllegalStateException("CHUNKS truncated at its index")
            val index = u32At(packed, at)
            at += 4
            val fragments = ArrayList<ByteArray>(FRAGMENTS_PER_CHUNK)
            repeat(FRAGMENTS_PER_CHUNK) {
                fragments += packed.copyOfRange(at, at + FRAGMENT_BYTES)
                at += FRAGMENT_BYTES
            }
            val hashes = ArrayList<ByteArray>(FRAGMENTS_PER_CHUNK)
            repeat(FRAGMENTS_PER_CHUNK) {
                hashes += packed.copyOfRange(at, at + HASH_BYTES)
                at += HASH_BYTES
            }
            chunks += SealedChunk(index, fragments, hashes)
        }
        if (at != packed.size) throw IllegalStateException("CHUNKS has trailing bytes")
        return chunks
    }

    /** Slices the concatenated 32-byte hashes of the `HASHES` field. */
    private fun hashes(packed: ByteArray): List<ByteArray> {
        if (packed.size % HASH_BYTES != 0) {
            throw IllegalStateException("HASHES is not a multiple of 32")
        }
        val out = ArrayList<ByteArray>(packed.size / HASH_BYTES)
        var at = 0
        while (at < packed.size) {
            out += packed.copyOfRange(at, at + HASH_BYTES)
            at += HASH_BYTES
        }
        return out
    }

    private fun u32At(bytes: ByteArray, at: Int): Int {
        if (at + 4 > bytes.size) throw IllegalStateException("u32 overruns the buffer")
        return ((bytes[at].toInt() and 0xff) shl 24) or
            ((bytes[at + 1].toInt() and 0xff) shl 16) or
            ((bytes[at + 2].toInt() and 0xff) shl 8) or
            (bytes[at + 3].toInt() and 0xff)
    }

    /** The shared decoder of the facade's calls; see `DmFacade.kt` for why it lives here. */
    private inline fun call(body: () -> ByteArray?): MediaResult = try {
        MediaResult.decode(body())
    } catch (e: UnsatisfiedLinkError) {
        MediaResult.unavailable()
    }

    /**
     * A code the surface cannot produce for this function: a caught panic or a disagreement
     * between the facade and the native library, which `MediaResultCodesTest` fails the build on.
     * The caller must roll back and treat the state as poison; a code a peer can provoke must
     * never arrive here.
     */
    private fun unexpected(code: MediaCode, function: String): Nothing =
        throw IllegalStateException("Media native $function returned ${code.name}")
}
