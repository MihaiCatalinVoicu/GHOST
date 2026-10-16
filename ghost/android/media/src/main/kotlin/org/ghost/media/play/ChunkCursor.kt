package org.ghost.media.play

import java.io.IOException

/**
 * The position-to-chunk mapping behind [GhostMediaDataSource] (Phase 11 design §10.2, slice
 * S7), free of Android types so the JVM suite exercises it directly: `seekTo` positions the
 * cursor (Media3 re-opens the data source at a new position after a seek; the reader's
 * random-access `READ` mode serves the same cursor), `read` serves the stream sequentially
 * across chunk boundaries, and the JVM-held chunk copy is erased before it is evicted and
 * at [close] (§10.5 — the native plaintext copy is zeroised by the reader itself).
 *
 * The playable's typed refusals surface unchanged: [MediaPlayException.Corrupt] (a hash or
 * tag failure — the engine records `verified → corrupt` before the player sees it), the
 * lock's [MediaPlayException.Closed], and [MediaPlayException.Defect] for a sequencing
 * refusal random access must not produce.
 */
internal class ChunkCursor(private val playable: MediaPlayable) {

    /** The absolute stream position the next [read] serves. */
    var position: Long = 0
        private set

    private var chunkIndex: Int = -1

    /** The cached plaintext chunk; erased before it is replaced and at [close]. */
    private var chunk: ByteArray = ByteArray(0)

    val contentLength: Long get() = playable.contentLength

    /**
     * Positions the cursor at [position] and answers the remaining length. A position past
     * the content is an `IOException` (a typed playback error), never a fatal.
     */
    @Throws(IOException::class)
    fun seekTo(position: Long): Long {
        val length = playable.contentLength
        if (position < 0 || position > length) {
            throw IOException("position $position outside the object's $length bytes")
        }
        this.position = position
        eraseChunk()
        return length - position
    }

    /**
     * Copies up to [length] bytes at [offset] in [buffer] and answers the count, or [EOF]
     * at the end of the stream (`C.RESULT_END_OF_INPUT`).
     */
    fun read(buffer: ByteArray, offset: Int, length: Int): Int {
        if (length == 0) return 0
        val contentLength = playable.contentLength
        if (position >= contentLength) return EOF

        val index = (position / CHUNK_PLAINTEXT).toInt()
        if (index != chunkIndex) {
            eraseChunk()
            chunk = playable.readChunk(index)
            chunkIndex = index
        }
        val within = (position % CHUNK_PLAINTEXT).toInt()
        val available = chunk.size - within
        val toCopy = minOf(length, available, (contentLength - position).toInt())
        System.arraycopy(chunk, within, buffer, offset, toCopy)
        position += toCopy
        return toCopy
    }

    /** Erase the cached copy and close the playable (the native reader, §13.2 M8). */
    fun close() {
        eraseChunk()
        playable.close()
    }

    /** §10.5: overwrite the JVM-held copy before it is dropped. */
    private fun eraseChunk() {
        if (chunkIndex != -1) chunk.fill(0)
        chunk = ByteArray(0)
        chunkIndex = -1
    }

    private companion object {
        /** [org.ghost.media.store.MediaLimits.CHUNK_PLAINTEXT]: the plaintext served per chunk. */
        const val CHUNK_PLAINTEXT: Int = 4 * 65_536 - 4 * 16

        /** `C.RESULT_END_OF_INPUT`. */
        const val EOF: Int = -1
    }
}
