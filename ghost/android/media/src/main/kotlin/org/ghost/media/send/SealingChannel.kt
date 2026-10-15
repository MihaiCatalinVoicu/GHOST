package org.ghost.media.send

import org.ghost.media.store.CiphertextFiles
import org.ghost.media.store.CiphertextFilesException
import org.ghost.media.store.MediaLimits
import org.ghost.media.store.PreparingFiles
import org.ghost.media.store.WriteResult
import java.nio.ByteBuffer
import java.nio.channels.WritableByteChannel

/**
 * What `SealingChannel` seals into: the begun sealer of §6.2, behind a port so the channel is
 * tested on the JVM without the native library. The production implementation is
 * `NativeStreamSealer` over `org.ghost.crypto.bridge.MediaCrypto`; the world's fake returns
 * golden-derived bytes (§15.1).
 */
interface StreamSealer {
    /** M2 `sealAppend`: the fragments of every chunk this call completed. */
    fun append(plaintext: ByteArray): List<SealedFragmentGroup>

    /** M3 `sealFinish`: the padding chunks' fragments, the manifest, the walked fields, `key_env`. */
    fun finish(preview: ByteArray): SealedObject

    /** M4 `sealAbort`: discard the sealer and its key. Idempotent in effect. */
    fun abort()
}

/** One sealed chunk as [StreamSealer.append] returns it: its index, four fragments, four hashes. */
class SealedFragmentGroup(
    /** `i` (unused by the channel; the fragments arrive in order). */
    val index: Int,
    /** The four 65 536-byte fragments, in order. */
    val fragments: List<ByteArray>,
    /** SHA-256 of each fragment, in order. */
    val hashes: List<ByteArray>,
)

/**
 * What [StreamSealer.finish] returns: the tail of the object and the only durable form of its key.
 * [fragments] and [fragmentHashes] hold **all** F fragments of the object in ordinal order (the
 * groups of [StreamSealer.append] plus [finish]'s own padding groups concatenated by the channel).
 */
class SealedObject(
    val classCode: Int,
    val contentLen: Long,
    val width: Int,
    val height: Int,
    val durationMs: Long,
    /** `key_env` (60 bytes), bound to `(out, destId, objectId, manifestHash)`. */
    val keyEnv: ByteArray,
    /** The 65 536-byte manifest blob. */
    val manifestBlob: ByteArray,
    val manifestHash: ByteArray,
    /** The preview as the manifest now carries it (empty for view-once). */
    val preview: ByteArray,
    /** The padding chunks' fragment groups, in order (the channel appends them to the list). */
    val finishGroups: List<SealedFragmentGroup>,
)

/** A refusal of the sealing: the preparation fails with this typed reason (§6.2, §6.5). */
sealed class SealException(message: String, cause: Throwable? = null) : IllegalStateException(message, cause) {
    /** The walker's refusal (`NON_CANONICAL`): the stream is not a canonical fMP4. */
    class NonCanonical : SealException("the stream is not canonical")

    /** Above the class cap, `MAX_CONTENT` or `IMAGE_MAX_CONTENT` (`OVERSIZE`). */
    class Oversize : SealException("above the class cap")

    /** The file store failed (`DISK_FULL` or `IO`): the preparation answers `STORAGE_FULL`. */
    class Storage(cause: CiphertextFilesException?) :
        SealException("the ciphertext store failed", cause)

    /** The native library or the context went away (`CRYPTO_UNAVAILABLE`). */
    class Unavailable : SealException("the media cryptography is unavailable")

    /** A caller bug (`SEQUENCE`, `INDEX_REUSED`): never expected; poisons the run like `DmFacade`. */
    class Internal(detail: String) : SealException(detail)
}

/**
 * The channel of Phase 11 design §8.3: `GhostMuxer`'s `WritableByteChannel`, wrapping
 * [Mp4Tfdt.Mp4Stream] (the `tfdt` insertion) and the chunking sealer of §3.3. Every completed
 * 262 128-byte chunk of plaintext is handed to [StreamSealer.append]; the four returned fragments
 * are written as ciphertext files (§10.4), each under a name reserved in [PreparingFiles] **before
 * the first byte is written**, so a concurrent reconcile keeps them (§22.5 row 25). After the
 * export completes and [Mp4Tfdt.Mp4Stream.finish] validated the box graph, [finish] appends the
 * last partial chunk and calls [StreamSealer.finish]; the manifest becomes ordinal −1's file.
 *
 * Memory: the plaintext chunk buffer is zeroed before release; the fragments are ciphertext and
 * carry no key. Nothing here logs or touches a clock (§13.1).
 */
class SealingChannel private constructor(
    private val sealer: StreamSealer,
    private val files: CiphertextFiles,
    private val preparing: PreparingFiles,
    /** Null in [raw] mode (images): bytes feed the chunker without a box graph. */
    private val mp4: Mp4Tfdt.Mp4Stream?,
) : WritableByteChannel {

    /** The chunk buffer: plaintext of the current chunk, at most [MediaLimits.CHUNK_PLAINTEXT]. */
    private var chunk = ByteArray(MediaLimits.CHUNK_PLAINTEXT)
    private var chunkLen = 0
    private var open = true
    private var failed = false

    /** The F fragment hashes and their files, in ordinal order. */
    private val fragmentHashes = ArrayList<ByteArray>()
    private val fragmentFiles = ArrayList<ByteArray>()

    /** The manifest's file name (written by [finish]). */
    private var manifestFile: ByteArray? = null

    override fun write(src: ByteBuffer): Int {
        check(open) { "the channel is closed" }
        val n = src.remaining()
        val bytes = ByteArray(n)
        src.get(bytes)
        val stream = mp4
        if (stream == null) {
            feed(bytes)
        } else {
            try {
                stream.offer(bytes)
            } catch (e: Mp4Tfdt.MalformedStream) {
                fail(SealException.NonCanonical())
            }
        }
        return n
    }

    override fun isOpen(): Boolean = open

    /** The muxer closed its stream; the box graph, when there is one, must be complete. */
    override fun close() {
        if (!open) return
        open = false
        try {
            mp4?.finish()
        } catch (e: Mp4Tfdt.MalformedStream) {
            fail(SealException.NonCanonical())
        }
    }

    /** The bytes accepted so far: the sealed stream's length (GhostMuxer's class-cap check, §6.2). */
    fun sealedBytes(): Long = mp4?.sealedBytes ?: sealedRaw

    /** Raw-mode byte count (images: no box graph to count). */
    private var sealedRaw = 0L

    /**
     * The end of the export: appends the buffered tail, seals the padding and the manifest, and
     * returns what `MEDIA-COMMIT` stores. [preview] is the canonical preview JPEG (empty for
     * view-once). Throws [SealException] on every failure; the caller then [abort]s.
     */
    fun finish(preview: ByteArray): SealedResult {
        check(!open) { "the muxer stream is still open" }
        if (failed) throw SealException.NonCanonical()
        appendChunkBuffer(flush = true)
        val sealed = try {
            sealer.finish(preview)
        } catch (e: SealException) {
            throw e
        }
        for (group in sealed.finishGroups) writeGroup(group)
        manifestFile = writeBlob(sealed.manifestBlob)
        return SealedResult(
            classCode = sealed.classCode,
            contentLen = sealed.contentLen,
            width = sealed.width,
            height = sealed.height,
            durationMs = sealed.durationMs,
            keyEnv = sealed.keyEnv,
            manifestBlob = sealed.manifestBlob,
            manifestHash = sealed.manifestHash,
            preview = sealed.preview,
            fragmentHashes = fragmentHashes.toList(),
            fragmentFiles = fragmentFiles.toList(),
            manifestFile = manifestFile!!,
        )
    }

    /** Discards the sealer and its key; the written files stay orphans for the reconcile. */
    fun abort() {
        open = false
        failed = true
        wipe(chunk)
        sealer.abort()
    }

    /** Releases every reserved name still held (after `MEDIA-COMMIT` or an abort). */
    fun releaseNames() {
        for (name in fragmentFiles) preparing.release(name)
        manifestFile?.let { preparing.release(it) }
        fragmentFiles.clear()
        manifestFile = null
    }

    private fun feed(bytes: ByteArray) {
        if (mp4 == null) sealedRaw += bytes.size
        var at = 0
        while (at < bytes.size) {
            val take = minOf(chunk.size - chunkLen, bytes.size - at)
            System.arraycopy(bytes, at, chunk, chunkLen, take)
            chunkLen += take
            at += take
            if (chunkLen == chunk.size) appendChunkBuffer(flush = false)
        }
    }

    /** Appends the buffer when full, or the tail when [flush] and non-empty. */
    private fun appendChunkBuffer(flush: Boolean) {
        if (chunkLen == 0) {
            if (flush) wipe(chunk)
            return
        }
        if (!flush && chunkLen < chunk.size) return
        val piece = if (chunkLen == chunk.size) {
            val full = chunk
            chunk = ByteArray(MediaLimits.CHUNK_PLAINTEXT)
            full
        } else {
            val tail = chunk.copyOfRange(0, chunkLen)
            wipe(chunk)
            chunk = ByteArray(MediaLimits.CHUNK_PLAINTEXT)
            tail
        }
        chunkLen = 0
        val groups = try {
            sealer.append(piece)
        } finally {
            // The piece may hold the last content bytes; the sealer copied what it needs.
            wipe(piece)
        }
        for (group in groups) writeGroup(group)
    }

    private fun writeGroup(group: SealedFragmentGroup) {
        for (k in group.fragments.indices) {
            val file = writeBlob(group.fragments[k])
            fragmentHashes += group.hashes[k]
            fragmentFiles += file
        }
    }

    /** Reserves the name, writes the blob, returns the name; every failure is typed. */
    private fun writeBlob(blob: ByteArray): ByteArray {
        val name = preparing.reserve(files)
        return try {
            when (val result = files.write(name, blob, enforceFloor = false)) {
                is WriteResult.Written -> result.fileName
                // A sealer passes enforceFloor = false, so BelowFloor is unreachable; a store that
                // answers it anyway is the defect this exception says it is.
                WriteResult.BelowFloor -> throw SealException.Internal("the store refused a sealer write with BelowFloor")
            }
        } catch (e: CiphertextFilesException) {
            preparing.release(name)
            throw SealException.Storage(e)
        }
    }

    private fun fail(e: SealException): Nothing {
        failed = true
        throw e
    }

    private fun wipe(bytes: ByteArray) {
        if (bytes.isNotEmpty()) java.util.Arrays.fill(bytes, 0.toByte())
    }

    companion object {
        /** The video path: a `FragmentedMp4Muxer` stream, `tfdt`-inserted, then chunked. */
        fun of(sealer: StreamSealer, files: CiphertextFiles, preparing: PreparingFiles): SealingChannel {
            lateinit var channel: SealingChannel
            val stream = Mp4Tfdt.Mp4Stream { bytes -> channel.feed(bytes) }
            channel = SealingChannel(sealer, files, preparing, stream)
            return channel
        }

        /** The image path: raw canonical-JPEG bytes, no box graph. */
        fun raw(sealer: StreamSealer, files: CiphertextFiles, preparing: PreparingFiles): SealingChannel =
            SealingChannel(sealer, files, preparing, null)
    }
}

/** What [SealingChannel.finish] returns for `MEDIA-COMMIT` (§6.3): files, rows and the envelope. */
class SealedResult(
    val classCode: Int,
    val contentLen: Long,
    val width: Int,
    val height: Int,
    val durationMs: Long,
    val keyEnv: ByteArray,
    val manifestBlob: ByteArray,
    val manifestHash: ByteArray,
    val preview: ByteArray,
    /** F fragment hashes in ordinal order, as the manifest names them. */
    val fragmentHashes: List<ByteArray>,
    /** The file of each fragment of [fragmentHashes] (same order). */
    val fragmentFiles: List<ByteArray>,
    /** The manifest's file (ordinal −1). */
    val manifestFile: ByteArray,
)
