package org.ghost.messaging.port

import org.ghost.crypto.bridge.MediaCrypto

/**
 * The recipient-side reader surface of §13.2 (M5–M8) behind one port, exactly the shape
 * [DmCrypto.beginMediaSealer] sets for M1: the steps of `MEDIA-BIND`, `MEDIA-VERIFY` and the
 * preview path run against this, the device binding resolves the DM context's handle per call
 * (a lock between two calls is the routine `Unavailable`), and the media worlds stand a
 * contract-faithful fake here (§15.1) so the ingest/bind/verify machines are proved without a
 * Rust toolchain in the loop. `K_f` never crosses this boundary — `key_env` in, plaintext out
 * of [chunk] only in a read the caller asks for.
 */
interface MediaReaders {

    /** M5 `readerOpen`: unwrap `key_env` under its binding, open the manifest, compare it with the descriptor's fields. */
    fun open(spec: OpenSpec): Opened

    /** M6 `readerChunk`: validate one chunk in order ([validate] = the VERIFY pass), or read its plaintext. */
    fun chunk(reader: Long, index: Int, fragments: ByteArray, validate: Boolean): Chunked

    /** M7 `readerValidateFinish`: the walk's end against the manifest (dimensions and duration). */
    fun finish(reader: Long): Validated

    /** M8 `readerClose`: discard the reader and its derived key. Idempotent in effect. */
    fun close(reader: Long)

    /** The descriptor-side arguments the caller parsed from the L0, plus the manifest blob the hash names. */
    class OpenSpec(
        /** The object's `key_env` (60 bytes), bound to (role, destId, objectId, manifestHash). */
        val keyEnv: ByteArray,
        val role: MediaCrypto.Role,
        /** The contact: the destination the envelope is bound to. */
        val destId: ByteArray,
        val objectId: ByteArray,
        val manifestHash: ByteArray,
        /** The exact 65 536-byte relay blob the hash names. */
        val manifestBlob: ByteArray,
        val kind: MediaCrypto.Kind,
        val viewOnce: Boolean,
        val classCode: Int,
        /**
         * True when the database holds the object readable — a recipient's `verified` object, or
         * the sender's own in `uploading`/`uploaded`/`failed` — without which a read-mode chunk
         * refuses with [Chunked.Sequence] (§22.2 row 28a). Bind and verify pass false.
         */
        val readable: Boolean,
    ) {
        override fun toString(): String = "OpenSpec(role=$role, kind=$kind, class=$classCode, readable=$readable)"
    }

    sealed interface Opened {
        /** The reader: its manifest-parsed fields and the fragment hashes to fetch. */
        class Ok(
            /** What every further call names; opaque to the caller. */
            val reader: Long,
            val kind: MediaCrypto.Kind,
            val viewOnce: Boolean,
            val classCode: Int,
            val contentLen: Long,
            val width: Int,
            val height: Int,
            val durationMs: Long,
            /** The manifest's preview JPEG (empty for view-once). */
            val preview: ByteArray,
            /** The manifest's fragment hashes, in ordinal order. */
            val hashes: List<ByteArray>,
        ) : Opened

        /** The manifest blob is not the one `manifestHash` names. */
        data object HashMismatch : Opened

        /** The commitment does not match the key. */
        data object CommitMismatch : Opened

        /** The manifest's tag does not verify under `K_m`. */
        data object NotOpen : Opened

        /** A manifest rule, or disagreement with the descriptor arguments. */
        data object NonCanonical : Opened

        /** `key_env` does not open under its binding (§4.2). */
        data object StateCorrupt : Opened

        /** Eight readers are already live (§13.2 M5). */
        data object Limited : Opened

        /** The native library is missing or the context is closed. */
        data object Unavailable : Opened
    }

    sealed interface Chunked {
        /** The chunk passed ([content] empty), or its plaintext in a read. */
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
}

/**
 * [MediaReaders] over the real JNI surface. It holds the [DmContext] rather than a handle, so a
 * context closed between two calls — a lock, a wipe — is the routine `Unavailable` of §2.7 and
 * never a call on a stale handle (the same shape [NativeDmCrypto] sets).
 */
class NativeMediaReaders(private val context: DmContext) : MediaReaders {

    override fun open(spec: MediaReaders.OpenSpec): MediaReaders.Opened {
        val handle = context.handleOrNull() ?: return MediaReaders.Opened.Unavailable
        return when (
            val opened = MediaCrypto.openReader(
                handle = handle,
                keyEnv = spec.keyEnv,
                role = spec.role,
                destId = spec.destId,
                objectId = spec.objectId,
                manifestHash = spec.manifestHash,
                manifestBlob = spec.manifestBlob,
                kind = spec.kind,
                viewOnce = spec.viewOnce,
                classCode = spec.classCode,
                readable = spec.readable,
            )
        ) {
            is MediaCrypto.Opened.Ok -> MediaReaders.Opened.Ok(
                reader = opened.reader.id,
                kind = opened.reader.kind,
                viewOnce = opened.reader.viewOnce,
                classCode = opened.reader.classCode,
                contentLen = opened.reader.contentLen,
                width = opened.reader.width,
                height = opened.reader.height,
                durationMs = opened.reader.durationMs,
                preview = opened.reader.preview,
                hashes = opened.reader.hashes,
            )
            MediaCrypto.Opened.HashMismatch -> MediaReaders.Opened.HashMismatch
            MediaCrypto.Opened.CommitMismatch -> MediaReaders.Opened.CommitMismatch
            MediaCrypto.Opened.NotOpen -> MediaReaders.Opened.NotOpen
            MediaCrypto.Opened.NonCanonical -> MediaReaders.Opened.NonCanonical
            MediaCrypto.Opened.StateCorrupt -> MediaReaders.Opened.StateCorrupt
            MediaCrypto.Opened.Limited -> MediaReaders.Opened.Limited
            MediaCrypto.Opened.Unavailable -> MediaReaders.Opened.Unavailable
        }
    }

    override fun chunk(reader: Long, index: Int, fragments: ByteArray, validate: Boolean): MediaReaders.Chunked {
        val handle = context.handleOrNull() ?: return MediaReaders.Chunked.Unavailable
        return when (
            val chunked = MediaCrypto.chunk(
                handle, reader, index, fragments,
                if (validate) MediaCrypto.Mode.VALIDATE else MediaCrypto.Mode.READ,
            )
        ) {
            is MediaCrypto.Chunked.Ok -> MediaReaders.Chunked.Ok(chunked.content)
            MediaCrypto.Chunked.NonCanonical -> MediaReaders.Chunked.NonCanonical
            MediaCrypto.Chunked.NotOpen -> MediaReaders.Chunked.NotOpen
            MediaCrypto.Chunked.HashMismatch -> MediaReaders.Chunked.HashMismatch
            MediaCrypto.Chunked.IndexRange -> MediaReaders.Chunked.IndexRange
            MediaCrypto.Chunked.Sequence -> MediaReaders.Chunked.Sequence
            MediaCrypto.Chunked.Unavailable -> MediaReaders.Chunked.Unavailable
        }
    }

    override fun finish(reader: Long): MediaReaders.Validated {
        val handle = context.handleOrNull() ?: return MediaReaders.Validated.Unavailable
        return when (MediaCrypto.validateFinish(handle, reader)) {
            MediaCrypto.Validated.Ok -> MediaReaders.Validated.Ok
            MediaCrypto.Validated.NonCanonical -> MediaReaders.Validated.NonCanonical
            MediaCrypto.Validated.Sequence -> MediaReaders.Validated.Sequence
            MediaCrypto.Validated.Unavailable -> MediaReaders.Validated.Unavailable
        }
    }

    override fun close(reader: Long) {
        val handle = context.handleOrNull() ?: return
        MediaCrypto.closeReader(handle, reader)
    }

    override fun toString(): String = "NativeMediaReaders"
}
