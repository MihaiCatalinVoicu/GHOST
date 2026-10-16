package org.ghost.media.play

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * [ChunkCursor] over a recording [MediaPlayable] (Phase 11 design §10.2, slice S7): the
 * seek answers the remaining length and positions the cursor; `read` serves the stream
 * sequentially across chunk boundaries; a re-seek is the seek shape (§10.2: the reader's
 * random-access `READ` mode serves the same cursor); the JVM-held chunk copy is erased on
 * eviction and at [ChunkCursor.close] (§10.5); the playable's typed refusals surface
 * unchanged — the player ends with a typed error, never a crash (§15.8 item 3).
 */
class ChunkCursorTest {

    private class FakePlayable(val content: ByteArray) : MediaPlayable {
        val handedOut = ArrayList<ByteArray>()
        var closeCount = 0
        val requested = ArrayList<Int>()

        override val contentLength: Long get() = content.size.toLong()

        override fun readChunk(index: Int): ByteArray {
            if (index < 0 || index.toLong() * CHUNK >= content.size) {
                throw MediaPlayException.Defect("chunk $index outside ${content.size}")
            }
            requested += index
            val from = index * CHUNK
            val to = minOf(from + CHUNK, content.size)
            return content.copyOfRange(from, to).also(handedOut::add)
        }

        override fun close() {
            closeCount++
        }
    }

    private fun content(bytes: Int): ByteArray = ByteArray(bytes) { (it * 31 + 7).toByte() }

    private fun readAll(cursor: ChunkCursor): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(1_000_003)
        while (true) {
            val n = cursor.read(buffer, 0, buffer.size)
            if (n == -1) break
            out.write(buffer, 0, n)
        }
        return out.toByteArray()
    }

    @Test
    fun seekAnswersTheRemainingLengthAndReadServesTheWholeStream() {
        val content = content(2 * CHUNK + 123_457)
        val playable = FakePlayable(content)
        val cursor = ChunkCursor(playable)

        assertEquals(content.size.toLong(), cursor.seekTo(0))
        assertArrayEquals(content, readAll(cursor))
        assertEquals(-1, cursor.read(ByteArray(10), 0, 10))
        cursor.close()
        assertEquals("close reaches the playable (the native reader)", 1, playable.closeCount)
    }

    @Test
    fun readsAcrossChunkBoundariesWithASmallBuffer() {
        val content = content(2 * CHUNK + 100)
        val playable = FakePlayable(content)
        val cursor = ChunkCursor(playable)

        cursor.seekTo(0)
        val out = ByteArray(content.size)
        var at = 0
        val buffer = ByteArray(999)
        while (true) {
            val n = cursor.read(buffer, 0, buffer.size)
            if (n == -1) break
            System.arraycopy(buffer, 0, out, at, n)
            at += n
        }
        assertEquals(content.size, at)
        assertArrayEquals(content, out)
        // The last chunk held only 100 bytes: the tail of the stream is honoured exactly.
        assertEquals(listOf(0, 1, 2), playable.requested)
        cursor.close()
    }

    @Test
    fun reseekingIsTheSeekShape() {
        val content = content(3 * CHUNK)
        val playable = FakePlayable(content)
        val cursor = ChunkCursor(playable)

        val at = CHUNK.toLong() + 77_777
        assertEquals(content.size - at, cursor.seekTo(at))
        assertArrayEquals(content.copyOfRange(at.toInt(), content.size), readAll(cursor))
        assertEquals(listOf(1, 2), playable.requested)
        cursor.close()
    }

    @Test
    fun theEvictedChunkCopyIsErasedBeforeTheNextIsLoaded() {
        val content = content(2 * CHUNK)
        val playable = FakePlayable(content)
        val cursor = ChunkCursor(playable)

        cursor.seekTo(0)
        val buffer = ByteArray(CHUNK)
        assertEquals(CHUNK, cursor.read(buffer, 0, CHUNK))
        // The boundary: chunk 0 must be erased before chunk 1 is fetched.
        assertEquals(42, cursor.read(buffer, 0, 42))
        assertTrue("chunk 0's copy is erased on eviction (§10.5)", playable.handedOut[0].all { it == 0.toByte() })
        assertArrayEquals("chunk 1's first bytes are right", content.copyOfRange(CHUNK, CHUNK + 42), buffer.copyOfRange(0, 42))
        cursor.close()
    }

    @Test
    fun closeErasesTheCachedChunkCopy() {
        val content = content(2 * CHUNK)
        val playable = FakePlayable(content)
        val cursor = ChunkCursor(playable)

        cursor.seekTo(0)
        val buffer = ByteArray(100)
        cursor.read(buffer, 0, 100)
        cursor.close()
        assertTrue("close erases the cached copy", playable.handedOut[0].all { it == 0.toByte() })
        assertEquals(1, playable.closeCount)
    }

    @Test
    fun thePlayableRefusalsSurfaceAsTypedErrors() {
        val closed = object : MediaPlayable {
            override val contentLength: Long = CHUNK.toLong()
            override fun readChunk(index: Int): ByteArray = throw MediaPlayException.Closed()
            override fun close() = Unit
        }
        val closedCursor = ChunkCursor(closed)
        closedCursor.seekTo(0)
        try {
            closedCursor.read(ByteArray(10), 0, 10)
            fail("the lock's Closed must reach the player")
        } catch (e: MediaPlayException.Closed) {
            // the typed shape §13.7 promises
        }

        val corrupt = object : MediaPlayable {
            override val contentLength: Long = CHUNK.toLong()
            override fun readChunk(index: Int): ByteArray = throw MediaPlayException.Corrupt()
            override fun close() = Unit
        }
        val corruptCursor = ChunkCursor(corrupt)
        corruptCursor.seekTo(0)
        try {
            corruptCursor.read(ByteArray(10), 0, 10)
            fail("a hash failure must reach the player as the corrupt error")
        } catch (e: MediaPlayException.Corrupt) {
            // §15.8 item 3: the player ends with a typed error, not a crash
        }
    }

    @Test
    fun seekPastTheEndRefusesAndZeroLengthReadIsNotEof() {
        val playable = FakePlayable(content(CHUNK))
        val cursor = ChunkCursor(playable)
        assertEquals(0, cursor.read(ByteArray(10), 0, 0))
        assertEquals(CHUNK.toLong(), cursor.seekTo(0))
        val buffer = ByteArray(CHUNK)
        assertEquals(CHUNK, cursor.read(buffer, 0, CHUNK))
        assertEquals(-1, cursor.read(ByteArray(1), 0, 1))
        // Seeking exactly at the end is legal and answers nothing more.
        assertEquals(0, cursor.seekTo(CHUNK.toLong()))
        assertEquals(-1, cursor.read(ByteArray(1), 0, 1))
        try {
            cursor.seekTo(CHUNK + 1L)
            fail("a position past the content length is an I/O error, not a crash")
        } catch (e: java.io.IOException) {
            // typed, not fatal
        }
        cursor.close()
    }

    private companion object {
        /** [org.ghost.media.store.MediaLimits.CHUNK_PLAINTEXT]. */
        const val CHUNK: Int = 4 * 65_536 - 4 * 16
    }
}
