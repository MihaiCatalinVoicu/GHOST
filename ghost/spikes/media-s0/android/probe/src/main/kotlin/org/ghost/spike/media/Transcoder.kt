package org.ghost.spike.media

import android.content.Context
import android.graphics.Bitmap
import android.media.MediaCodecInfo
import android.media.MediaCodecList
import android.media.metrics.LogSessionId
import android.net.Uri
import android.os.Handler
import android.os.HandlerThread
import android.os.SystemClock
import androidx.media3.common.Format
import androidx.media3.common.MediaItem
import androidx.media3.common.MimeTypes
import androidx.media3.common.audio.AudioProcessor
import androidx.media3.common.audio.ChannelMixingAudioProcessor
import androidx.media3.common.audio.ChannelMixingMatrix
import androidx.media3.common.audio.SonicAudioProcessor
import androidx.media3.common.util.BitmapLoader
import androidx.media3.common.util.Clock
import androidx.media3.datasource.ContentDataSource
import androidx.media3.datasource.DataSource
import androidx.media3.effect.FrameDropEffect
import androidx.media3.effect.Presentation
import androidx.media3.exoplayer.source.ProgressiveMediaSource
import androidx.media3.extractor.DefaultExtractorsFactory
import androidx.media3.transformer.AudioEncoderSettings
import androidx.media3.transformer.Codec
import androidx.media3.transformer.Composition
import androidx.media3.transformer.DefaultAssetLoaderFactory
import androidx.media3.transformer.DefaultDecoderFactory
import androidx.media3.transformer.DefaultEncoderFactory
import androidx.media3.transformer.EditedMediaItem
import androidx.media3.transformer.EditedMediaItemSequence
import androidx.media3.transformer.Effects
import androidx.media3.transformer.ExportException
import androidx.media3.transformer.ExportResult
import androidx.media3.transformer.Transformer
import androidx.media3.transformer.VideoEncoderSettings
import com.google.common.util.concurrent.Futures
import com.google.common.util.concurrent.ListenableFuture
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * `GhostTranscoder` of design §8.3 in three configurations:
 *  - [Mode.DESIGN]: forced encoding (`videoNeedsEncoding`/`audioNeedsEncoding` = true), H.264 +
 *    AAC-LC 128 kbit/s, 2 Mbit/s (CBR where the encoder supports it), `Presentation` to 1280 x 720
 *    or 720 x 1280 with `LAYOUT_SCALE_TO_FIT`, `FrameDropEffect(30)`, `SonicAudioProcessor` at
 *    48 kHz, a channel mixer to stereo, HDR tone-mapping, platform diagnostics off, source through
 *    `ContentDataSource` only, `GhostMuxer`;
 *  - [Mode.UNFORCED_EFFECTS]: the same without forcing (what the design protects against);
 *  - [Mode.PLAIN]: Transformer's defaults except the MIME types and the muxer (PM-M18's world).
 *  - [Mode.PLAIN_KEEP_HDR]: the same without the HDR tone-mapping mode (Transformer's true default).
 */
object Transcoder {
    enum class Mode { DESIGN, UNFORCED_EFFECTS, PLAIN, PLAIN_KEEP_HDR, PLAIN_DEFAULTS }

    class Result(
        val ok: Boolean,
        val bytes: ByteArray,
        val summary: String,
        val rec: MuxRecord,
        val wallMs: Long,
    )

    fun avcEncoder(): MediaCodecInfo? = MediaCodecList(MediaCodecList.REGULAR_CODECS).codecInfos
        .firstOrNull { it.isEncoder && it.supportedTypes.any { t -> t.equals(MimeTypes.VIDEO_H264, true) } }

    fun cbrSupported(): Boolean = avcEncoder()?.getCapabilitiesForType(MimeTypes.VIDEO_H264)?.encoderCapabilities
        ?.isBitrateModeSupported(MediaCodecInfo.EncoderCapabilities.BITRATE_MODE_CBR) == true

    private class NoBitmaps : BitmapLoader {
        override fun supportsMimeType(mimeType: String) = false
        override fun decodeBitmap(data: ByteArray): ListenableFuture<Bitmap> = Futures.immediateFailedFuture(UnsupportedOperationException("no images"))
        override fun loadBitmap(uri: Uri): ListenableFuture<Bitmap> = Futures.immediateFailedFuture(UnsupportedOperationException("no images"))
    }

    private class Forcing(private val d: Codec.EncoderFactory, private val bt709: Boolean) : Codec.EncoderFactory {
        override fun createForAudioEncoding(format: Format, logSessionId: LogSessionId?): Codec = d.createForAudioEncoding(format, logSessionId)
        override fun createForVideoEncoding(format: Format, logSessionId: LogSessionId?): Codec =
            // V-M17 fix under test: a fixed SDR BT.709 limited-range colour description instead of
            // the one Transformer carries over from the source.
            d.createForVideoEncoding(if (bt709) format.buildUpon().setColorInfo(androidx.media3.common.ColorInfo.SDR_BT709_LIMITED).build() else format, logSessionId)
        override fun isVideoFormatSupported(format: Format) = d.isVideoFormatSupported(format)
        override fun audioNeedsEncoding() = true
        override fun videoNeedsEncoding() = true
    }

    private var notedMixing = false

    fun audioProcessors(): List<AudioProcessor> {
        val sonic = SonicAudioProcessor()
        sonic.setOutputSampleRateHz(48_000)
        val mixer = ChannelMixingAudioProcessor()
        for (inCh in 1..8) {
            try {
                mixer.putChannelMixingMatrix(ChannelMixingMatrix.createForConstantGain(inCh, 2))
            } catch (e: RuntimeException) {
                // Media3 1.11.1 has default coefficients only for 1 and 2 input channels ("Default
                // channel mixing coefficients for 3->2 are not yet implemented"), so GHOST must
                // supply its own downmix: 5.1 (FL FR FC LFE BL BR) as ITU-R BS.775 without LFE,
                // any other count alternating left/right; row-major [input][output], normalised.
                val m = FloatArray(inCh * 2)
                if (inCh == 6) {
                    val k = 0.7071f
                    val n = 1f / (1f + 2 * k)
                    m[0 * 2 + 0] = n; m[1 * 2 + 1] = n
                    m[2 * 2 + 0] = k * n; m[2 * 2 + 1] = k * n
                    m[4 * 2 + 0] = k * n; m[5 * 2 + 1] = k * n
                } else {
                    for (i in 0 until inCh) m[i * 2 + (i % 2)] = 2f / inCh
                }
                mixer.putChannelMixingMatrix(ChannelMixingMatrix(inCh, 2, m))
                if (!notedMixing) report("note: ChannelMixingMatrix.createForConstantGain($inCh, 2) unsupported (${e.message}); explicit matrix supplied")
            }
        }
        notedMixing = true
        return listOf(sonic, mixer)
    }

    /**
     * Runs one export. [displayLandscape] says whether the source is displayed landscape (after
     * its rotation), which picks 1280 x 720 or 720 x 1280. [portraitEncoding] null leaves
     * Transformer's default.
     */
    fun run(
        ctx: Context,
        sourceName: String,
        mode: Mode,
        displayLandscape: Boolean,
        cbr: Boolean = true,
        portraitEncoding: Boolean? = null,
        seiFilter: Boolean = true,
        timeoutS: Long = 900,
        orientationFix: Boolean = false,
        bt709: Boolean = false,
        keepBytes: Boolean = true,
    ): Result {
        val rec = MuxRecord()
        val factory = GhostMuxerFactory(rec, seiFilter, orientationFix, keepBytes)
        val useCbr = cbr && cbrSupported()
        val videoSettings = VideoEncoderSettings.Builder()
            .setBitrate(2_000_000)
            .setBitrateMode(if (useCbr) MediaCodecInfo.EncoderCapabilities.BITRATE_MODE_CBR else MediaCodecInfo.EncoderCapabilities.BITRATE_MODE_VBR)
            .build()
        val audioSettings = AudioEncoderSettings.Builder().setBitrate(128_000).setProfile(MediaCodecInfo.CodecProfileLevel.AACObjectLC).build()
        val defaultEncoders = DefaultEncoderFactory.Builder(ctx)
            .setRequestedVideoEncoderSettings(videoSettings)
            .setRequestedAudioEncoderSettings(audioSettings)
            .build()
        // DefaultEncoderFactory.videoNeedsEncoding()/audioNeedsEncoding() return true as soon as
        // encoder settings other than the defaults are requested (1.11.1 source), so only
        // PLAIN_DEFAULTS, with no requested settings, can reach Transformer's transmux path.
        val encoders: Codec.EncoderFactory = when (mode) {
            Mode.DESIGN -> Forcing(defaultEncoders, bt709)
            Mode.PLAIN_DEFAULTS -> DefaultEncoderFactory.Builder(ctx).build()
            else -> defaultEncoders
        }
        val contentOnly = DataSource.Factory { ContentDataSource(ctx) }
        val assetLoader = DefaultAssetLoaderFactory(
            ctx,
            DefaultDecoderFactory.Builder(ctx).build(),
            Clock.DEFAULT,
            ProgressiveMediaSource.Factory(contentOnly, DefaultExtractorsFactory()),
            NoBitmaps(),
        )
        val item = MediaItem.fromUri(SourceProvider.uri(sourceName))
        val edited = if (mode == Mode.PLAIN || mode == Mode.PLAIN_KEEP_HDR || mode == Mode.PLAIN_DEFAULTS) {
            EditedMediaItem.Builder(item).build()
        } else {
            val (w, h) = if (displayLandscape) Pair(1280, 720) else Pair(720, 1280)
            EditedMediaItem.Builder(item)
                .setEffects(
                    Effects(
                        audioProcessors(),
                        listOf(Presentation.createForWidthAndHeight(w, h, Presentation.LAYOUT_SCALE_TO_FIT), FrameDropEffect.createDefaultFrameDropEffect(30f)),
                    ),
                )
                .build()
        }
        val cb = Composition.Builder(EditedMediaItemSequence.Builder(edited).build())
        // PLAIN_KEEP_HDR leaves Transformer's default HDR mode (KEEP_HDR): the only configuration in
        // which 1.11.1 may transmux video at all (TransformerUtil.shouldTranscodeVideo returns true
        // for any other HDR mode).
        if (mode != Mode.PLAIN_KEEP_HDR && mode != Mode.PLAIN_DEFAULTS) cb.setHdrMode(Composition.HDR_MODE_TONE_MAP_HDR_TO_SDR_USING_OPEN_GL)
        val composition = cb.build()
        // A path Transformer requires and GhostMuxer ignores; nothing may ever appear there (V-M1).
        val neverWritten = File(ctx.filesDir, "never-written-" + IsoClient.randomHex(4) + ".mp4")
        val done = CountDownLatch(1)
        var export: ExportResult? = null
        var error: ExportException? = null
        val thread = HandlerThread("transformer").apply { start() }
        val t0 = SystemClock.elapsedRealtime()
        Handler(thread.looper).post {
            val b = Transformer.Builder(ctx)
                .setLooper(thread.looper)
                .setVideoMimeType(MimeTypes.VIDEO_H264)
                .setAudioMimeType(MimeTypes.AUDIO_AAC)
                .setEncoderFactory(encoders)
                .setAssetLoaderFactory(assetLoader)
                .setMuxerFactory(factory)
                .setUsePlatformDiagnostics(false)
                .addListener(object : Transformer.Listener {
                    override fun onCompleted(composition: Composition, exportResult: ExportResult) {
                        export = exportResult
                        done.countDown()
                    }
                    override fun onError(composition: Composition, exportResult: ExportResult, exportException: ExportException) {
                        export = exportResult
                        error = exportException
                        done.countDown()
                    }
                })
            if (portraitEncoding != null) b.setPortraitEncodingEnabled(portraitEncoding)
            b.build().start(composition, neverWritten.path)
        }
        val finished = done.await(timeoutS, TimeUnit.SECONDS)
        val wall = SystemClock.elapsedRealtime() - t0
        thread.quitSafely()
        val bytes = if (finished && error == null) factory.channel.out.toByteArray() else ByteArray(0)
        val e = export
        val conv = { p: Int -> when (p) { ExportResult.CONVERSION_PROCESS_TRANSCODED -> "TRANSCODED"; ExportResult.CONVERSION_PROCESS_TRANSMUXED -> "TRANSMUXED"; ExportResult.CONVERSION_PROCESS_TRANSMUXED_AND_TRANSCODED -> "BOTH"; else -> "NA($p)" } }
        val summary = buildString {
            append("transcode src=$sourceName mode=$mode landscape=$displayLandscape cbrRequested=$cbr cbrUsed=$useCbr portraitEncoding=$portraitEncoding orientationFix=$orientationFix bt709=$bt709")
            append(" finished=$finished error=${error?.errorCodeName}:${error?.message}")
            // The cause chain (the API 29 emulator answers ERROR_CODE_VIDEO_FRAME_PROCESSING_FAILED
            // with the reason two causes down: EGL_BAD_CONFIG, no OpenGL ES 3 context).
            error?.let { ex ->
                val chain = generateSequence(ex.cause) { it.cause }.map { "${it.javaClass.simpleName}: ${it.message?.replace('\n', ' ')?.take(200)}" }.toList()
                if (chain.isNotEmpty()) append(" cause=[${chain.joinToString(" <- ")}]")
            }
            if (e != null) {
                append(" videoEncoder=${e.videoEncoderName} audioEncoder=${e.audioEncoderName} videoProcess=${conv(e.videoConversionProcess)} audioProcess=${conv(e.audioConversionProcess)}")
                append(" out=${e.width}x${e.height} frames=${e.videoFrameCount} durationMs=${e.durationMs} avgVideoBitrate=${e.averageVideoBitrate} avgAudioBitrate=${e.averageAudioBitrate} rate=${e.sampleRate} ch=${e.channelCount} color=${e.colorInfo}")
            }
            append(" bytes=${bytes.size} streamBytes=${rec.channelBytes} wallMs=$wall neverWrittenExists=${neverWritten.exists()} pathOffered=${rec.pathOffered?.let { File(it).name }}")
        }
        return Result(finished && error == null, bytes, summary, rec, wall)
    }
}
