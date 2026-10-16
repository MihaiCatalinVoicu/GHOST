package org.ghost.media.play

import androidx.media3.common.C
import androidx.media3.common.util.UnstableApi
import androidx.media3.datasource.BaseDataSource
import androidx.media3.datasource.DataSpec
import java.io.IOException

/**
 * Media3's `DataSource` over one open reader (Phase 11 design §10.2, slice S7): the only
 * data path the player's `ProgressiveMediaSource` sees. `open` answers the remaining length
 * and positions the [ChunkCursor] at the spec's position (Media3 re-opens with a new
 * position after a seek; the reader's random-access `READ` mode serves the same cursor,
 * §10.2); `read` copies from the cursor's current chunk into Media3's array. Nothing here
 * touches a file, a cache or the network: the bytes come from the native reader chunk by
 * chunk and live in RAM only.
 *
 * A refusal of the playable surfaces as the typed [MediaPlayException] — the player ends
 * with a playback error (the UI shows "media unavailable"), the process does not crash,
 * and the corrupt half has already been recorded by the engine (§7.3's `verified → corrupt`).
 *
 * `close` releases only this source's cached chunk copy: Media3 closes and re-opens its
 * data sources around its own needs (the `mfra` seek-map load rewinds the stream — the
 * extractor seeks to the index and back before playback starts), and the reader the
 * [androidx.media3.datasource.DataSource] reads through outlives any one source instance —
 * it closes with the handle's owner (the engine's lock/trim, §13.7), never with a source
 * close (F-S7's device re-run found this: the first rewind closed the reader and every
 * subsequent read answered the typed `Closed`).
 */
@UnstableApi
class GhostMediaDataSource(
    playable: MediaPlayable,
) : BaseDataSource(/* isNetwork = */ false) {

    private val cursor = ChunkCursor(playable)

    private var uri: android.net.Uri? = null

    private var opened: Boolean = false

    @Throws(IOException::class)
    override fun open(dataSpec: DataSpec): Long {
        uri = dataSpec.uri
        val remaining = cursor.seekTo(dataSpec.position)
        opened = true
        transferInitializing(dataSpec)
        transferStarted(dataSpec)
        return remaining
    }

    @Throws(IOException::class)
    override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
        check(opened) { "read before open" }
        val read = cursor.read(buffer, offset, length)
        if (read != C.RESULT_END_OF_INPUT) bytesTransferred(read)
        return read
    }

    override fun getUri(): android.net.Uri? = uri

    @Throws(IOException::class)
    override fun close() {
        if (!opened) return
        opened = false
        // Not cursor.close(): the reader outlives this source (see the class KDoc) — only
        // the JVM-held plaintext copy is erased here (§10.5).
        cursor.releaseBuffer()
        transferEnded()
    }
}
