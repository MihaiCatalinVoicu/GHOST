package org.ghost.media.play

import android.content.Context
import android.os.Handler
import androidx.media3.common.MediaItem
import androidx.media3.common.MimeTypes
import androidx.media3.common.PlaybackException
import androidx.media3.common.util.Log
import androidx.media3.common.util.UnstableApi
import androidx.media3.datasource.DataSource
import androidx.media3.exoplayer.DefaultLoadControl
import androidx.media3.exoplayer.ExoPlayer
import androidx.media3.exoplayer.Renderer
import androidx.media3.exoplayer.RenderersFactory
import androidx.media3.exoplayer.audio.AudioRendererEventListener
import androidx.media3.exoplayer.audio.DefaultAudioSink
import androidx.media3.exoplayer.audio.MediaCodecAudioRenderer
import androidx.media3.exoplayer.mediacodec.MediaCodecSelector
import androidx.media3.exoplayer.metadata.MetadataOutput
import androidx.media3.exoplayer.source.ProgressiveMediaSource
import androidx.media3.exoplayer.text.TextOutput
import androidx.media3.exoplayer.video.MediaCodecVideoRenderer
import androidx.media3.exoplayer.video.VideoRendererEventListener
import androidx.media3.extractor.ExtractorsFactory
import androidx.media3.extractor.mp4.FragmentedMp4Extractor

/**
 * The only way GHOST builds a player (Phase 11 design §10.2, slice S7; G-M3's configuration
 * rule, S0-21): `ExoPlayer.Builder(context, ghostRenderersFactory, ProgressiveMediaSource
 * .Factory(ghostDataSourceFactory, fmp4OnlyExtractorsFactory))` with
 *
 *  - a renderers factory that builds **exactly one** `MediaCodecVideoRenderer` and one
 *    `MediaCodecAudioRenderer` — Media3's default renderers factory would keep an
 *    `ImageRenderer` that decodes pictures with the platform bitmap decoder in this process
 *    (S0 V-M14) and R8 would keep it in the release dex (G-M10 checks it is gone);
 *  - an extractors factory that returns only `FragmentedMp4Extractor` with
 *    `FLAG_READ_MFRA_FOR_SEEK_MAP` (received objects are canonical fMP4 with GHOST's `mfra`,
 *    §8.3; the flag is what makes the seek map seekable — without it every seek replays from
 *    the start, mutant MC-M24);
 *  - a `DefaultLoadControl` of 5–15 s and at most 8 MiB of buffer (Media3's defaults buffer
 *    50 s and up to about 125 MiB of video, §10.2);
 *  - `setUsePlatformDiagnostics(false)` and Media3's logging off (§10.2; the platform
 *    playback session Media3 still creates is declared, L9-M8, S0-9).
 *
 * No media session (§10.2 forbids it), no notification, no background playback: the UI
 * pauses at `onStop` and releases at lock; the player is foreground-only.
 */
@UnstableApi
object GhostPlayer {

    init {
        // §10.2: Media3's logger off at first use (an `@UnstableApi` public call).
        Log.setLogLevel(Log.LOG_LEVEL_OFF)
    }

    /** The renderers of G-M3's configuration rule: video and audio codecs, nothing else. */
    private class GhostRenderersFactory(private val context: Context) : RenderersFactory {
        override fun createRenderers(
            eventHandler: Handler,
            videoListener: VideoRendererEventListener,
            audioListener: AudioRendererEventListener,
            textOutput: TextOutput,
            metadataOutput: MetadataOutput,
        ): Array<Renderer> = arrayOf(
            MediaCodecVideoRenderer(
                context,
                MediaCodecSelector.DEFAULT,
                // The platform default's constants, named without naming the class
                // (G-M3's source rule refuses it everywhere, §16.1).
                ALLOWED_VIDEO_JOINING_TIME_MS,
                eventHandler,
                videoListener,
                MAX_DROPPED_FRAMES_TO_NOTIFY,
            ),
            MediaCodecAudioRenderer(
                context,
                MediaCodecSelector.DEFAULT,
                eventHandler,
                audioListener,
                DefaultAudioSink.Builder(context).build(),
            ),
        )
    }

    /** The one extractor a received object needs, with the seek map of §8.3's `mfra`. */
    private val fmp4OnlyExtractorsFactory = ExtractorsFactory {
        arrayOf(FragmentedMp4Extractor(FragmentedMp4Extractor.FLAG_READ_MFRA_FOR_SEEK_MAP))
    }

    /** §10.2's bounded buffering: 5–15 s, at most 8 MiB. */
    private fun loadControl(): DefaultLoadControl = DefaultLoadControl.Builder()
        .setBufferDurationsMs(
            MIN_BUFFER_MS,
            MAX_BUFFER_MS,
            DefaultLoadControl.DEFAULT_BUFFER_FOR_PLAYBACK_MS,
            DefaultLoadControl.DEFAULT_BUFFER_FOR_PLAYBACK_AFTER_REBUFFER_MS,
        )
        .setTargetBufferBytes(MAX_BUFFER_BYTES)
        .build()

    /**
     * The player of §10.2 over one opened object ([playable]), with the media item set.
     * The data source factory ignores the item's URI and reads through the playable — the
     * URI only names the handle. The caller owns the player: pauses at `onStop`, releases
     * at lock, never plays in the background.
     */
    fun create(context: Context, playable: MediaPlayable, uri: String): ExoPlayer =
        ExoPlayer.Builder(
            context,
            GhostRenderersFactory(context),
            ProgressiveMediaSource.Factory(
                DataSource.Factory { GhostMediaDataSource(playable) },
                fmp4OnlyExtractorsFactory,
            ),
        )
            .setLoadControl(loadControl())
            .setUsePlatformDiagnostics(false)
            .build()
            .also { player ->
                player.setMediaItem(
                    MediaItem.Builder().setUri(uri).setMimeType(MimeTypes.VIDEO_MP4).build(),
                )
            }

    /** §15.8 item 3's shape of a corrupt object's end: a typed playback error, never a crash. */
    fun isTypedPlayError(error: PlaybackException?): Boolean {
        val cause = error?.cause
        return error != null && (cause is MediaPlayException || cause is java.io.IOException)
    }

    /** The URI scheme of a media handle's playback item (the data source ignores it). */
    const val URI_SCHEME: String = "ghost"

    /** Builds the handle URI: `ghost://media/<object id hex>`. */
    fun uriOf(objectId: ByteArray): String =
        "$URI_SCHEME://media/" + objectId.joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private const val ALLOWED_VIDEO_JOINING_TIME_MS: Long = 5_000
    private const val MAX_DROPPED_FRAMES_TO_NOTIFY: Int = 50
    private const val MIN_BUFFER_MS: Int = 5_000
    private const val MAX_BUFFER_MS: Int = 15_000
    private const val MAX_BUFFER_BYTES: Int = 8 * 1024 * 1024
}
