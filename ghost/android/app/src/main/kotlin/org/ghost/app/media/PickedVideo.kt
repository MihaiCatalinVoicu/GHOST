package org.ghost.app.media

import android.content.Context
import android.media.MediaMetadataRetriever
import android.net.Uri
import androidx.media3.common.MediaItem
import androidx.media3.common.util.BitmapLoader
import com.google.common.util.concurrent.Futures
import com.google.common.util.concurrent.ListenableFuture
import android.graphics.Bitmap
import org.ghost.media.send.VideoSource

/**
 * The picked video source (§6.5's `MediaSource` wraps a content URI and nothing else): the one
 * place the content handle is named, here in `:app` — G-DM1 bans `android.net` from the DM
 * modules, so `:media` sees this only through the [VideoSource] port. The metadata reads
 * (§6.1's duration bounds, the display rotation of §8.3) parse the container here, before any
 * byte is re-encoded. **F-S7 finding**: G-M3's source rule names the platform metadata
 * retriever for the sandbox alone; this file is the one counted exemption (the gate counts it),
 * because container probing of a content URI needs a platform parser and the alternative
 * (Media3's extractor over a content data source) has different rotation semantics across API
 * levels. The review may demand the rewrite.
 */
class PickedVideo(private val context: Context, private val uri: Uri) : VideoSource {
    override fun mediaItem(): MediaItem = MediaItem.fromUri(uri)

    override fun durationUs(): Long {
        val retriever = MediaMetadataRetriever()
        return try {
            retriever.setDataSource(context, uri)
            retriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_DURATION)?.toLongOrNull()
                ?.let { it * 1_000 } ?: -1
        } catch (e: RuntimeException) {
            -1
        } finally {
            retriever.release()
        }
    }

    override fun rotationDegrees(): Int {
        val retriever = MediaMetadataRetriever()
        return try {
            retriever.setDataSource(context, uri)
            retriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_VIDEO_ROTATION)?.toIntOrNull() ?: 0
        } catch (e: RuntimeException) {
            0
        } finally {
            retriever.release()
        }
    }
}

/**
 * The `BitmapLoader` Transformer's asset loader requires, refusing every image: the sender
 * pipeline never decodes bitmaps through the asset loader (images go through the sandbox,
 * previews come from the sealed output). Lives in `:app` because the interface's signature names
 * `android.net.Uri`, which G-DM1 bans from `:media` (GhostTranscoder takes this as a constructor
 * argument).
 */
@androidx.annotation.OptIn(androidx.media3.common.util.UnstableApi::class)
object NoBitmapsLoader : BitmapLoader {
    override fun supportsMimeType(mimeType: String): Boolean = false
    override fun decodeBitmap(data: ByteArray): ListenableFuture<Bitmap> =
        Futures.immediateFailedFuture(UnsupportedOperationException("no images"))
    override fun loadBitmap(uri: Uri): ListenableFuture<Bitmap> =
        Futures.immediateFailedFuture(UnsupportedOperationException("no images"))
}
