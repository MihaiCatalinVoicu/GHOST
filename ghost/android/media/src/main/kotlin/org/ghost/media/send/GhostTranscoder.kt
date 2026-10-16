package org.ghost.media.send

import android.content.Context
import android.media.MediaCodecInfo
import android.media.metrics.LogSessionId
import android.os.Handler
import android.os.HandlerThread
import android.os.SystemClock
import androidx.media3.common.C
import androidx.media3.common.ColorInfo
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
import androidx.media3.effect.FrameDropEffect
import androidx.media3.effect.Presentation
import androidx.media3.exoplayer.source.ProgressiveMediaSource
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
import androidx.media3.transformer.ProgressHolder
import androidx.media3.transformer.Transformer
import androidx.media3.transformer.VideoEncoderSettings
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * `GhostTranscoder` of Phase 11 design §8.3 (corrected by S0: S0-3, S0-13, S0-18, S0-20, S0-21,
 * S0-22): one forced re-encode of a picked video source into the canonical fMP4 profile, through
 * [GhostMuxer] into a [SealingChannel]. What GHOST pins, and why, is documented at each choice;
 * the spike this productionizes is `ghost/spikes/media-s0` `Transcoder.kt` (measured on the API
 * 29, 35 and 37 emulators).
 *
 * **Encoding is forced (D15).** `Forcing.videoNeedsEncoding()`/`audioNeedsEncoding()` return true
 * so Transformer cannot transmux a source that already matches the output (its SPS/VUI fingerprint
 * and bitrate would reach the recipient; §8.3). The wrapper and the encoder-name check guard the
 * setting against a future Media3 version (S0 V-M17).
 *
 * **GHOST's encoder settings, not Media3's or the source's (S0-22).** VBR (S0-18: CBR overshot
 * more on API 35 and API 29 has no CBR); profile/level Baseline/3.1 requested (Media3 raises the
 * profile to High on High-capable encoders — accepted, Q44; the walker accepts both); `maxBFrames
 * 0` explicit; a 1-s key-frame interval explicit; and the encoder is told the **output's** frame
 * rate — `min(source, 30)`, or 15 on the retry — because Transformer configures it with the
 * source's rate before `FrameDropEffect` drops frames (a 60-fps source otherwise got 2-s key
 * frames and level 3.2, both revealing the source).
 *
 * **Colour (S0-13, Q48).** The request is SDR BT.601 limited range (which both measured encoders
 * code as labelled); which matrix an encoder *codes* is its choice, so [calibrate] transcodes a
 * 1-s colour-grid clip through the same configuration once per process and compares the first
 * output frame's patches with both conversions ([ColourGrid]): keep BT.601, switch to BT.709
 * limited, or refuse video on the device (`COLOUR_UNVERIFIED`).
 *
 * Everything runs on the caller's thread (the media worker, §13.7); the Transformer itself runs
 * on a private looper. The stall watchdog (R-M19) polls progress and cancels an export that has
 * not advanced for [MediaSendLimits.EXPORT_STALL_MS].
 */
class GhostTranscoder(
    private val context: Context,
    /** The bundled 1-s colour-grid clip (§8.3 point 5(d)); null where calibration cannot run. */
    private val calibrationClip: ByteArray?,
    /**
     * The no-images `BitmapLoader` Transformer requires: its interface names the platform's
     * content-URI class, which G-DM1 bans from the DM modules, so the instance is built in
     * `:app` and injected (the type itself is media3's, not a network package's).
     */
    private val bitmapLoader: BitmapLoader,
) {
    /** The colour request the calibration chose for this process's encoder. */
    enum class ColourRequest { BT_601, BT_709 }

    @Volatile
    private var colour: ColourRequest? = null

    /**
     * Calibrates the encoder once per process (§8.3 point 5(d)); the answer every export of this
     * process uses. Returns the refusal when the calibration export itself failed, or when the
     * encoder coded neither BT.601 nor BT.709 within tolerance.
     */
    fun calibrate(): PrepFailure? {
        colour?.let { return null }
        val clip = calibrationClip ?: return PrepFailure.UnsupportedSource(
            PrepFailure.UnsupportedSource.Detail.COLOUR_UNVERIFIED,
        )
        val file = File(context.cacheDir, "ghost-calibration-clip-${System.nanoTime()}.mp4")
        val calibration = try {
            file.writeBytes(clip)
            CalibrationExport.run(context, file, this)
        } finally {
            file.delete()
        }
        colour = when (calibration) {
            is CalibrationExport.Result.Ok -> {
                val verdict = ColourGrid.compare(
                    calibration.frame,
                    CalibrationExport.GRID_CENTERS,
                    CalibrationExport.GRID_COLOURS,
                ).verdict
                when (verdict) {
                    ColourGrid.Verdict.BT_601 -> ColourRequest.BT_601
                    ColourGrid.Verdict.BT_709 -> ColourRequest.BT_709
                    ColourGrid.Verdict.NEITHER -> return PrepFailure.UnsupportedSource(
                        PrepFailure.UnsupportedSource.Detail.COLOUR_UNVERIFIED,
                    )
                }
            }
            is CalibrationExport.Result.Failed -> return calibration.failure
        }
        return null
    }

    /** What [export] decided. On [Ok] the channel holds the sealed stream; the caller [SealingChannel.finish]es it. */
    sealed class Outcome {
        class Ok(
            /** The preview JPEG built from the output (empty when the decode failed, S0-19). */
            val previewBytes: ByteArray,
            /** The output's displayed width and height (from the export result). */
            val width: Int,
            val height: Int,
        ) : Outcome()

        /**
         * The class cap tripped while writing (§6.2): [projection] is
         * `bytes × source duration ÷ media time written` at the tripping moment. The caller
         * retries once at 15 fps when it is at most twice the cap, else fails `TOO_LARGE`.
         */
        class Oversized(val projection: Long) : Outcome()

        class Failed(val failure: PrepFailure) : Outcome()
    }

    /**
     * One export attempt at [maxFps] (30 for the first run, 15 for the retry of §6.2). The
     * source's displayed orientation picks the `Presentation` geometry; [channel] receives the
     * sealed stream. [cancelled] lets the caller stop the export (a user cancel or a teardown).
     */
    fun export(
        source: VideoSource,
        displayLandscape: Boolean,
        sourceDurationUs: Long,
        maxFps: Float,
        maxClass: Int,
        channel: SealingChannel,
        cancelled: () -> Boolean = { false },
    ): Outcome {
        val request = colour
            ?: return Outcome.Failed(
                PrepFailure.UnsupportedSource(PrepFailure.UnsupportedSource.Detail.COLOUR_UNVERIFIED),
            )
        val muxer = GhostMuxer(channel, sourceDurationUs, maxClass)
        val factory = GhostMuxerFactory(channel, sourceDurationUs, maxClass)
        val thread = HandlerThread("ghost-transcoder").apply { start() }
        val latch = CountDownLatch(1)
        var completed: ExportResult? = null
        var failed: ExportException? = null
        val transformer = runOn(thread) {
            Transformer.Builder(context)
                .setLooper(thread.looper)
                .setVideoMimeType(MimeTypes.VIDEO_H264)
                .setAudioMimeType(MimeTypes.AUDIO_AAC)
                .setPortraitEncodingEnabled(false)
                .setEncoderFactory(forcingFactory(request, maxFps))
                .setAssetLoaderFactory(assetLoader())
                .setMuxerFactory(factory)
                .setUsePlatformDiagnostics(false)
                .addListener(object : Transformer.Listener {
                    override fun onCompleted(composition: Composition, exportResult: ExportResult) {
                        completed = exportResult
                        latch.countDown()
                    }

                    override fun onError(
                        composition: Composition,
                        exportResult: ExportResult,
                        exportException: ExportException,
                    ) {
                        completed = exportResult
                        failed = exportException
                        latch.countDown()
                    }
                })
                .build()
        }
        // The watchdog runs on its OWN thread: posting it to the transformer's HandlerThread
        // would leave it unfireable when that thread stalls inside a codec call — the exact
        // R-M19 scenario it exists for (found on the WHPX emulator, 2026-10-16).
        val progress = ProgressHolder()
        var lastProgress = -1
        var lastAdvanceMs = SystemClock.elapsedRealtime()
        val stalled = booleanArrayOf(false)
        val watchdog = Thread {
            while (latch.count > 0L) {
                Thread.sleep(2_000)
                if (cancelled()) {
                    transformer.cancel()
                    latch.countDown()
                    break
                }
                if (transformer.getProgress(progress) == Transformer.PROGRESS_STATE_AVAILABLE) {
                    if (progress.progress != lastProgress) {
                        lastProgress = progress.progress
                        lastAdvanceMs = SystemClock.elapsedRealtime()
                    } else if (SystemClock.elapsedRealtime() - lastAdvanceMs > MediaSendLimits.EXPORT_STALL_MS) {
                        stalled[0] = true
                        transformer.cancel()
                        latch.countDown()
                        break
                    }
                }
            }
        }.apply { isDaemon = true; name = "ghost-transcoder-watchdog"; start() }
        runOn(thread) { transformer.start(composition(source.mediaItem(), displayLandscape, maxFps), scratchPath()) }
        latch.await(MediaSendLimits.EXPORT_STALL_MS * 8, TimeUnit.MILLISECONDS)
        watchdog.join(2_000)
        thread.quitSafely()

        val error = failed
        when {
            cancelled() -> return Outcome.Failed(PrepFailure.Cancelled)
            stalled[0] -> return Outcome.Failed(
                PrepFailure.UnsupportedSource(PrepFailure.UnsupportedSource.Detail.STALLED),
            )
            error != null -> {
                // The class cap while writing (§6.2) is not a failure: it carries the retry
                // projection. The fragment bound is a failure (FRAGMENT_TOO_LARGE).
                for (cause in generateSequence(error.cause) { it.cause }) {
                    if (cause is GhostMuxer.Oversize) return Outcome.Oversized(cause.projection)
                }
                return Outcome.Failed(mapError(error))
            }
        }
        val result = completed ?: return Outcome.Failed(
            PrepFailure.UnsupportedSource(PrepFailure.UnsupportedSource.Detail.STALLED),
        )
        // Forced encoding's guard (§8.3 point 3): each name is null when no encoder ran for its
        // track — a transmuxed output — and the preparation fails (`NOT_ENCODED`).
        if (result.videoEncoderName == null || result.audioEncoderName == null) {
            return Outcome.Failed(
                PrepFailure.UnsupportedSource(PrepFailure.UnsupportedSource.Detail.NOT_ENCODED),
            )
        }
        val input = muxer.previewInput() ?: return Outcome.Failed(
            PrepFailure.UnsupportedSource(PrepFailure.UnsupportedSource.Detail.NOT_ENCODED),
        )
        // The preview comes from the output (S0-19): the first sync sample decoded with the
        // output's `avcC`, converted with the output's colour label, turned by the output's
        // rotation. A decode failure means no preview (preview_len = 0), never a failed send.
        val preview = PreviewBuilder.build(
            input,
            muxer.rotationDegrees(),
            if (request == ColourRequest.BT_709) Yuv420.Matrix.BT_709 else Yuv420.Matrix.BT_601,
        ) ?: ByteArray(0)
        return Outcome.Ok(preview, result.width, result.height)
    }

    // ------------------------------------------------------------- pieces

    /** The forcing encoder factory (D15) with GHOST's colour and frame rate on the video format. */
    internal fun forcingFactory(request: ColourRequest, maxFps: Float): Codec.EncoderFactory {
        val defaults = DefaultEncoderFactory.Builder(context)
            .setRequestedVideoEncoderSettings(videoSettings())
            .setRequestedAudioEncoderSettings(audioSettings())
            .build()
        return Forcing(defaults, request, maxFps)
    }

    private class Forcing(
        private val inner: Codec.EncoderFactory,
        private val request: ColourRequest,
        private val maxFps: Float,
    ) : Codec.EncoderFactory {
        override fun createForAudioEncoding(format: Format, logSessionId: LogSessionId?): Codec =
            inner.createForAudioEncoding(format, logSessionId)

        override fun createForVideoEncoding(format: Format, logSessionId: LogSessionId?): Codec {
            var f = format
            val colour = if (request == ColourRequest.BT_709) {
                ColorInfo.SDR_BT709_LIMITED
            } else {
                ColorInfo.Builder()
                    .setColorSpace(C.COLOR_SPACE_BT601)
                    .setColorRange(C.COLOR_RANGE_LIMITED)
                    .setColorTransfer(C.COLOR_TRANSFER_SDR)
                    .build()
            }
            f = f.buildUpon().setColorInfo(colour).build()
            // The encoder is told the output's rate (S0-22 point c), not the source's.
            if (f.frameRate > maxFps) f = f.buildUpon().setFrameRate(maxFps).build()
            return inner.createForVideoEncoding(f, logSessionId)
        }

        override fun isVideoFormatSupported(format: Format): Boolean = inner.isVideoFormatSupported(format)
        override fun audioNeedsEncoding(): Boolean = true
        override fun videoNeedsEncoding(): Boolean = true
    }

    private fun videoSettings(): VideoEncoderSettings =
        VideoEncoderSettings.Builder()
            .setBitrate(MediaSendLimits.VIDEO_TARGET_BITRATE)
            .setBitrateMode(MediaCodecInfo.EncoderCapabilities.BITRATE_MODE_VBR)
            .setEncodingProfileLevel(
                MediaCodecInfo.CodecProfileLevel.AVCProfileBaseline,
                MediaCodecInfo.CodecProfileLevel.AVCLevel31,
            )
            .setMaxBFrames(0)
            .setiFrameIntervalSeconds(MediaSendLimits.KEY_FRAME_INTERVAL_S)
            .build()

    private fun audioSettings(): AudioEncoderSettings =
        AudioEncoderSettings.Builder()
            .setBitrate(MediaSendLimits.AUDIO_TARGET_BITRATE)
            .setProfile(MediaCodecInfo.CodecProfileLevel.AACObjectLC)
            .build()

    /** Sources parse through `Mp4Extractor` alone (S0-21): nothing else reaches a decoder. */
    internal fun assetLoader(): DefaultAssetLoaderFactory {
        val contentOnly = androidx.media3.datasource.DataSource.Factory { ContentDataSource(context) }
        val extractors = ExtractorsFactory { arrayOf(Mp4Extractor(SubtitleParser.Factory.UNSUPPORTED)) }
        return DefaultAssetLoaderFactory(
            context,
            DefaultDecoderFactory.Builder(context).build(),
            Clock.DEFAULT,
            ProgressiveMediaSource.Factory(contentOnly, extractors),
            bitmapLoader,
        )
    }

    /**
     * The composition (§8.3): the source item with `Presentation` to 1 280 × 720 (or 720 × 1 280
     * for a displayed-portrait source) fitted with bars, `FrameDropEffect` at [maxFps], the audio
     * processors (Sonic at 48 kHz and the explicit down-mix matrices), a forced silent track so
     * every output has exactly one audio and one video track (S0-3), HDR tone-mapped to SDR.
     */
    internal fun composition(source: MediaItem, displayLandscape: Boolean, maxFps: Float): Composition {
        val (w, h) = if (displayLandscape) Pair(1_280, 720) else Pair(720, 1_280)
        val edited = EditedMediaItem.Builder(source)
            .setEffects(
                Effects(
                    audioProcessors(),
                    listOf(
                        Presentation.createForWidthAndHeight(w, h, Presentation.LAYOUT_SCALE_TO_FIT),
                        FrameDropEffect.createDefaultFrameDropEffect(maxFps),
                    ),
                ),
            )
            .build()
        // The sequence's flag is the one that works for an item-built sequence (1.11.1, S0-3).
        val sequence = EditedMediaItemSequence.Builder(edited)
            .experimentalSetForceAudioTrack(true)
            .build()
        return Composition.Builder(sequence)
            .setHdrMode(Composition.HDR_MODE_TONE_MAP_HDR_TO_SDR_USING_OPEN_GL)
            .build()
    }

    internal fun audioProcessors(): List<AudioProcessor> {
        val sonic = SonicAudioProcessor()
        sonic.setOutputSampleRateHz(48_000)
        val mixer = ChannelMixingAudioProcessor()
        for (channels in 1..MediaSendLimits.MAX_AUDIO_CHANNELS) {
            val constantGain = try {
                ChannelMixingMatrix.createForConstantGain(channels, 2)
            } catch (e: UnsupportedOperationException) {
                // 1.11.1 has default coefficients only for 1 and 2 input channels (S0-20):
                // the explicit matrix of DownMix replaces exactly this refusal.
                null
            }
            if (constantGain != null) {
                mixer.putChannelMixingMatrix(constantGain)
            } else {
                mixer.putChannelMixingMatrix(ChannelMixingMatrix(channels, 2, DownMix.matrix(channels)!!))
            }
        }
        return listOf(sonic, mixer)
    }

    /** A path Transformer requires and `GhostMuxer` ignores; the file must never exist (V-M1). */
    private fun scratchPath(): String =
        File(context.cacheDir, "ghost-muxer-never-written-${System.nanoTime()}.mp4").path

    internal fun <T> runOn(thread: HandlerThread, block: () -> T): T {
        val latch = CountDownLatch(1)
        var out: T? = null
        Handler(thread.looper).post {
            out = block()
            latch.countDown()
        }
        latch.await()
        return out!!
    }

    internal fun mapError(error: ExportException): PrepFailure {
        val cause = generateSequence(error.cause) { it.cause }.toList()
        for (c in cause) {
            if (c is GhostMuxer.FragmentTooLarge) {
                return PrepFailure.UnsupportedSource(
                    PrepFailure.UnsupportedSource.Detail.FRAGMENT_TOO_LARGE,
                )
            }
        }
        return when (error.errorCode) {
            ExportException.ERROR_CODE_VIDEO_FRAME_PROCESSING_FAILED ->
                PrepFailure.UnsupportedSource(PrepFailure.UnsupportedSource.Detail.GL_UNAVAILABLE)
            ExportException.ERROR_CODE_DECODING_FAILED,
            ExportException.ERROR_CODE_DECODING_FORMAT_UNSUPPORTED,
            ExportException.ERROR_CODE_AUDIO_PROCESSING_FAILED,
            ->
                PrepFailure.UnsupportedSource(PrepFailure.UnsupportedSource.Detail.CODEC)
            ExportException.ERROR_CODE_DECODER_INIT_FAILED,
            ExportException.ERROR_CODE_ENCODING_FAILED,
            ExportException.ERROR_CODE_ENCODING_FORMAT_UNSUPPORTED,
            ExportException.ERROR_CODE_MUXING_FAILED,
            ExportException.ERROR_CODE_MUXING_TIMEOUT,
            ->
                PrepFailure.UnsupportedSource(PrepFailure.UnsupportedSource.Detail.ENCODER_FAILED)
            ExportException.ERROR_CODE_IO_FILE_NOT_FOUND,
            ExportException.ERROR_CODE_IO_READ_POSITION_OUT_OF_RANGE,
            ExportException.ERROR_CODE_IO_UNSPECIFIED,
            ->
                PrepFailure.UnsupportedSource(PrepFailure.UnsupportedSource.Detail.CONTAINER)
            else -> PrepFailure.UnsupportedSource(PrepFailure.UnsupportedSource.Detail.CODEC)
        }
    }

    companion object
}

/**
 * The calibration export (§8.3 point 5(d)): the colour-grid clip re-encoded with GHOST's settings
 * (the BT.601 request) into a throwaway in-memory muxer — nothing is sealed, no file is written —
 * and the first output frame decoded into the raw YUV planes. The comparison lives in
 * `GhostTranscoder.calibrate` ([ColourGrid]).
 */
internal object CalibrationExport {
    sealed class Result {
        class Ok(val frame: Yuv420.Frame) : Result()
        class Failed(val failure: PrepFailure) : Result()
    }

    /** The grid the bundled clip carries: patch centers (1 280 × 720, 3 × 2) and sRGB colours. */
    val GRID_CENTERS: List<Pair<Int, Int>> = listOf(
        213 to 180, 640 to 180, 1066 to 180,
        213 to 540, 640 to 540, 1066 to 540,
    )

    /** The source colours of the calibration grid, in the same order as [GRID_CENTERS]. */
    val GRID_COLOURS: List<Triple<Int, Int, Int>> = listOf(
        Triple(255, 0, 0), Triple(0, 255, 0), Triple(0, 0, 255),
        Triple(255, 255, 0), Triple(0, 255, 255), Triple(255, 0, 255),
    )

    fun run(context: Context, clip: java.io.File, transcoder: GhostTranscoder): Result {
        val out = java.io.ByteArrayOutputStream()
        val channel = object : java.nio.channels.WritableByteChannel {
            private var open = true
            override fun write(src: java.nio.ByteBuffer): Int {
                val n = src.remaining()
                val b = ByteArray(n)
                src.get(b)
                out.write(b)
                return n
            }
            override fun isOpen(): Boolean = open
            override fun close() {
                open = false
            }
        }
        val muxer = androidx.media3.muxer.FragmentedMp4Muxer.Builder(channel).build().apply {
            addMetadataEntry(androidx.media3.container.Mp4TimestampData(0, 0))
        }
        val memoryMuxer = object : androidx.media3.muxer.Muxer.Factory {
            override fun create(path: String): androidx.media3.muxer.Muxer = muxer
            override fun getSupportedSampleMimeTypes(trackType: Int): com.google.common.collect.ImmutableList<String> =
                com.google.common.collect.ImmutableList.of(androidx.media3.common.MimeTypes.VIDEO_H264, androidx.media3.common.MimeTypes.AUDIO_AAC)
        }
        val thread = HandlerThread("ghost-calibration").apply { start() }
        val latch = CountDownLatch(1)
        var completed: ExportResult? = null
        var failed: ExportException? = null
        val transformer = transcoder.runOn(thread) {
            Transformer.Builder(context)
                .setLooper(thread.looper)
                .setVideoMimeType(MimeTypes.VIDEO_H264)
                .setAudioMimeType(MimeTypes.AUDIO_AAC)
                .setPortraitEncodingEnabled(false)
                .setEncoderFactory(transcoder.forcingFactory(GhostTranscoder.ColourRequest.BT_601, MediaSendLimits.OUTPUT_FPS))
                .setAssetLoaderFactory(transcoder.assetLoader())
                .setMuxerFactory(memoryMuxer)
                .setUsePlatformDiagnostics(false)
                .addListener(object : Transformer.Listener {
                    override fun onCompleted(composition: Composition, exportResult: ExportResult) {
                        completed = exportResult
                        latch.countDown()
                    }

                    override fun onError(
                        composition: Composition,
                        exportResult: ExportResult,
                        exportException: ExportException,
                    ) {
                        completed = exportResult
                        failed = exportException
                        latch.countDown()
                    }
                })
                .build()
        }
        transcoder.runOn(thread) {
            transformer.start(
                transcoder.composition(
                    // The string form of `MediaItem.fromUri` keeps the content-handle package
                    // out of the DM modules (G-DM1).
                    MediaItem.fromUri("file://${clip.absolutePath}"),
                    displayLandscape = true,
                    MediaSendLimits.OUTPUT_FPS,
                ),
                java.io.File(context.cacheDir, "ghost-calibration-never-written-${System.nanoTime()}.mp4").path,
            )
        }
        latch.await(120, TimeUnit.SECONDS)
        thread.quitSafely()
        val error = failed
        if (error != null) return Result.Failed(transcoder.mapError(error))
        val result = completed ?: return Result.Failed(
            PrepFailure.UnsupportedSource(PrepFailure.UnsupportedSource.Detail.STALLED),
        )
        if (result.videoEncoderName == null) {
            return Result.Failed(
                PrepFailure.UnsupportedSource(PrepFailure.UnsupportedSource.Detail.NOT_ENCODED),
            )
        }
        val stream = out.toByteArray()
        val (avcC, sample) = FrameProbe.firstVideoSample(stream)
            ?: return Result.Failed(PrepFailure.UnsupportedSource(PrepFailure.UnsupportedSource.Detail.CONTAINER))
        val frame = FrameProbe.decodeSample(avcC, sample)
            ?: return Result.Failed(PrepFailure.UnsupportedSource(PrepFailure.UnsupportedSource.Detail.CODEC))
        return Result.Ok(frame)
    }
}
