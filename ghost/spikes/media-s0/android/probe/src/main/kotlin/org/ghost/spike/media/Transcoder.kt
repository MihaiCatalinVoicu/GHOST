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
import androidx.media3.extractor.ExtractorsFactory
import androidx.media3.extractor.mp4.Mp4Extractor
import androidx.media3.extractor.text.SubtitleParser
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
    /**
     * [Mode.FINAL] (review fixes, 2026-10-04): DESIGN plus every correction of the evidence document
     * at once (the BT.709 limited colour of S0-13, the rotation of S0-20, the Mp4Extractor-only
     * source of review I2, the profile/level and B-frame pins of review I1, Media3's forced silent
     * audio track of review I10, an explicit 1-s key-frame interval, VBR, and GhostMuxer's fragment
     * bound of review I7). Every flag can also be set alone through [Opts].
     */
    enum class Mode { DESIGN, UNFORCED_EFFECTS, PLAIN, PLAIN_KEEP_HDR, PLAIN_DEFAULTS, FINAL }

    class Opts(
        /** VideoEncoderSettings.setEncodingProfileLevel(AVCProfileBaseline, AVCLevel31) (review I1). */
        val profilePin: Boolean = false,
        /** VideoEncoderSettings.setMaxBFrames(0) (review I1). */
        val maxB0: Boolean = false,
        /** VideoEncoderSettings.setiFrameIntervalSeconds(1f), explicitly (Media3's default is 1 s). */
        val iFrame1: Boolean = false,
        /** Composition.Builder.experimentalSetForceAudioTrack(true) (review I10). */
        val forceAudio: Boolean = false,
        /** The asset loader parses sources with Mp4Extractor only (review I2). */
        val mp4Only: Boolean = false,
        val bitrate: Int = 2_000_000,
        /** GhostMuxer's fragment bound in bytes (0 = off; review I7). */
        val fragmentBound: Long = 0,
        /** The encoder gets the output frame rate (<= 30), not the source's (review fix 2026-10-04). */
        val clampFps: Boolean = false,
        /** FrameDropEffect target (30 by D29; 15 for the retry experiment of review I5). */
        val maxFps: Float = 30f,
        /**
         * The encoder format's colour is SDR BT.601 limited instead of BT.709 limited (review pass,
         * 2026-10-04: API 29's `OMX.google.h264.encoder` converts the frame processor's RGB with
         * BT.601 coefficients whatever is requested, so its BT.709 label was wrong for chroma).
         */
        val colour601: Boolean = false,
    ) {
        override fun toString() = "profilePin=$profilePin maxB0=$maxB0 iFrame1=$iFrame1 forceAudio=$forceAudio mp4Only=$mp4Only bitrate=$bitrate fragmentBound=$fragmentBound clampFps=$clampFps maxFps=$maxFps colour601=$colour601"
        companion object {
            val FINAL = Opts(profilePin = true, maxB0 = true, iFrame1 = true, forceAudio = true, mp4Only = true, fragmentBound = 16L * 1024 * 1024, clampFps = true)
        }
    }

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

    private class Forcing(private val d: Codec.EncoderFactory, private val bt709: Boolean, private val clampFps: Boolean = false, private val maxFps: Float = 30f, private val colour601: Boolean = false) : Codec.EncoderFactory {
        override fun createForAudioEncoding(format: Format, logSessionId: LogSessionId?): Codec = d.createForAudioEncoding(format, logSessionId)
        override fun createForVideoEncoding(format: Format, logSessionId: LogSessionId?): Codec {
            var f = format
            // V-M17 fix under test: a fixed SDR BT.709 limited-range colour description instead of
            // the one Transformer carries over from the source.
            if (colour601) {
                f = f.buildUpon().setColorInfo(
                    androidx.media3.common.ColorInfo.Builder()
                        .setColorSpace(androidx.media3.common.C.COLOR_SPACE_BT601)
                        .setColorRange(androidx.media3.common.C.COLOR_RANGE_LIMITED)
                        .setColorTransfer(androidx.media3.common.C.COLOR_TRANSFER_SDR)
                        .build(),
                ).build()
            } else if (bt709) {
                f = f.buildUpon().setColorInfo(androidx.media3.common.ColorInfo.SDR_BT709_LIMITED).build()
            }
            // Review fix (2026-10-04, found while running review I1): Transformer configures the
            // encoder with the *source's* frame rate (60 for a 60-fps source, before FrameDropEffect
            // drops half the frames), so the 1-s key-frame interval becomes 60 frames = 2 s of the
            // 30-fps output and the encoder raises the level to 3.2: both tell the recipient that the
            // source ran above 30 fps. The encoder is given the output's rate instead.
            if (clampFps && f.frameRate > maxFps) f = f.buildUpon().setFrameRate(maxFps).build()
            return d.createForVideoEncoding(f, logSessionId)
        }
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
        opts0: Opts? = null,
    ): Result {
        val final = mode == Mode.FINAL
        val opts = opts0 ?: if (final) Opts.FINAL else Opts()
        val orientationFix = orientationFix || final
        val bt709 = bt709 || final
        val rec = MuxRecord()
        val factory = GhostMuxerFactory(rec, seiFilter, orientationFix, keepBytes, opts.fragmentBound)
        val useCbr = cbr && cbrSupported()
        val vb = VideoEncoderSettings.Builder()
            .setBitrate(opts.bitrate)
            .setBitrateMode(if (useCbr) MediaCodecInfo.EncoderCapabilities.BITRATE_MODE_CBR else MediaCodecInfo.EncoderCapabilities.BITRATE_MODE_VBR)
        if (opts.profilePin) vb.setEncodingProfileLevel(MediaCodecInfo.CodecProfileLevel.AVCProfileBaseline, MediaCodecInfo.CodecProfileLevel.AVCLevel31)
        if (opts.maxB0) vb.setMaxBFrames(0)
        if (opts.iFrame1) vb.setiFrameIntervalSeconds(1f)
        val videoSettings = vb.build()
        val audioSettings = AudioEncoderSettings.Builder().setBitrate(128_000).setProfile(MediaCodecInfo.CodecProfileLevel.AACObjectLC).build()
        val defaultEncoders = DefaultEncoderFactory.Builder(ctx)
            .setRequestedVideoEncoderSettings(videoSettings)
            .setRequestedAudioEncoderSettings(audioSettings)
            .build()
        // DefaultEncoderFactory.videoNeedsEncoding()/audioNeedsEncoding() return true as soon as
        // encoder settings other than the defaults are requested (1.11.1 source), so only
        // PLAIN_DEFAULTS, with no requested settings, can reach Transformer's transmux path.
        val encoders: Codec.EncoderFactory = when (mode) {
            Mode.DESIGN, Mode.FINAL -> Forcing(defaultEncoders, bt709, opts.clampFps, opts.maxFps, opts.colour601)
            Mode.PLAIN_DEFAULTS -> DefaultEncoderFactory.Builder(ctx).build()
            else -> defaultEncoders
        }
        val contentOnly = DataSource.Factory { ContentDataSource(ctx) }
        // Review I2: sources parsed by Mp4Extractor alone (MP4/3GP/QuickTime), never by the
        // image, Matroska, AVI, FLV, Ogg, TS/PS, MP3, FLAC or AMR extractors that
        // DefaultExtractorsFactory instantiates.
        val extractors: ExtractorsFactory = if (opts.mp4Only) ExtractorsFactory { arrayOf(Mp4Extractor(SubtitleParser.Factory.UNSUPPORTED)) } else DefaultExtractorsFactory()
        val assetLoader = DefaultAssetLoaderFactory(
            ctx,
            DefaultDecoderFactory.Builder(ctx).build(),
            Clock.DEFAULT,
            ProgressiveMediaSource.Factory(contentOnly, extractors),
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
                        listOf(Presentation.createForWidthAndHeight(w, h, Presentation.LAYOUT_SCALE_TO_FIT), FrameDropEffect.createDefaultFrameDropEffect(opts.maxFps)),
                    ),
                )
                .build()
        }
        // Review I10: a source without audio still gets a (silent) AAC track, so every canonical
        // fMP4 has exactly one audio and one video track. 1.11.1 offers the flag on the sequence
        // (for a sequence built from items, whose track types are "inferred") and on the
        // Composition; the Composition's rebuilds the sequences with explicit track types and
        // throws for an item-built sequence ("trackTypes must only contain TRACK_TYPE_AUDIO and/or
        // TRACK_TYPE_VIDEO", seen on API 35), so the sequence's is the one that works.
        val seqBuilder = EditedMediaItemSequence.Builder(edited)
        if (opts.forceAudio) seqBuilder.experimentalSetForceAudioTrack(true)
        val cb = Composition.Builder(seqBuilder.build())
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
            append("transcode src=$sourceName mode=$mode landscape=$displayLandscape cbrRequested=$cbr cbrUsed=$useCbr portraitEncoding=$portraitEncoding orientationFix=$orientationFix bt709=$bt709 $opts")
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
