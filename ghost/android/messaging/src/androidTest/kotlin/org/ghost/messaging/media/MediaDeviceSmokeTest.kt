package org.ghost.messaging.media

import android.content.Context
import android.graphics.Bitmap
import androidx.media3.common.MediaItem
import androidx.media3.common.util.BitmapLoader
import com.google.common.util.concurrent.Futures
import com.google.common.util.concurrent.ListenableFuture
import org.ghost.media.sandbox.MediaSandbox
import org.ghost.media.send.GhostTranscoder
import org.ghost.media.send.MediaSealerFactory
import org.ghost.media.send.SealedFragmentGroup
import org.ghost.media.send.SealedObject
import org.ghost.media.send.SealingChannel
import org.ghost.media.send.StreamSealer
import org.ghost.media.send.VideoSource
import org.ghost.media.store.CiphertextFiles
import org.ghost.media.store.MediaLimits
import org.ghost.media.store.NameSource
import org.ghost.media.store.NioCiphertextFileSystem
import org.ghost.media.store.PreparingFiles
import org.ghost.device.DeviceRunner
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicInteger

/**
 * The S5 device smoke (Phase 11 design §17.1 row S5): one image and one video through the real
 * Android halves on an emulator, one of them a **matching source** — `quad_land.fmp4` is already a
 * canonical output (H.264 + AAC, ≤ 720p), and D15's forcing wrapper must re-encode it anyway.
 *
 *  1. **Image, sandbox**: `MediaSandbox.stripImage` runs in a real fresh `:mdec` isolated process
 *     (the manifest above declares the service; `GhostApp`'s early return is the production half);
 *     the answer is the canonical-geometry JPEG, checked on this side after the instance died.
 *  2. **Video, matching source**: `GhostTranscoder` re-encodes the golden through the real
 *     `GhostMuxer` (SEI filter, rotation, the `tfdt` insertion) into a real `SealingChannel` whose
 *     sealer records the stream — the recorded bytes carry `ftyp` and `tfdt` — and the fragments
 *     land as whole files in the real ciphertext store.
 *  3. **Calibration**: the 1-s colour-grid clip is generated on the device (a `MediaCodec`
 *     encoder over the grid of §8.3 point 5(d)) and `GhostTranscoder.calibrate()` runs the full
 *     export-decode-compare over it — the encoder's matrix is answered BT.601 or BT.709, never
 *     `COLOUR_UNVERIFIED` on the emulator's known encoders.
 *
 * No JNI: the sealer is a test double (the channel, muxer, transcoder and sandbox are the shipped
 * classes). Runs as a self-instrumenting library test APK (§15.9's precedent).
 */
class MediaDeviceSmokeTest {

    private fun asset(context: Context, name: String): ByteArray =
        context.assets.open(name).use { it.readBytes() }

    private fun context(): Context = DeviceRunner.current.context

    @Test
    fun sandboxStripsAnImageInAFreshIsolatedProcess() {
        val context = context()
        val sandbox = MediaSandbox(context)
        val source = asset(context, "strip_orient1.jpg")
        val result = sandbox.stripImage(source, preview = false, maxBytes = 1_048_512)
        val why = (result as? MediaSandbox.Result.Failure)?.reason
        assertTrue("strip refused: $why", result is MediaSandbox.Result.Ok)
        val ok = result as MediaSandbox.Result.Ok
        assertTrue("the answer is a JPEG", ok.bytes.size > 100 && ok.bytes[0] == 0xFF.toByte() && ok.bytes[1] == 0xD8.toByte())
        assertTrue("the geometry is canonical", ok.width == 512 && ok.height == 336)
        assertTrue("the output fits the image bound", ok.bytes.size <= 1_048_512)
    }

    @Test
    fun theMatchingSourceIsReencodedIntoTheCanonicalStream() {
        val context = context()
        val golden = asset(context, "quad_land.fmp4")
        val sourceFile = File(context.cacheDir, "matching-source.mp4").apply { writeBytes(golden) }

        val sealer = RecordingSealer()
        val dir = File(context.cacheDir, "smoke").apply { mkdirs() }
        val files = CiphertextFiles(File(dir, "m"), NioCiphertextFileSystem(), TestNames(), 0L).also { it.open() }
        val channel = SealingChannel.of(sealer, files, PreparingFiles())

        // The calibration clip is generated on the device (the third test owns the flow); a
        // transcoder without it refuses every export with COLOUR_UNVERIFIED (F-S5-6(b)).
        val transcoder = GhostTranscoder(context, generateCalibrationClip(context), NoImages)
        assertEquals(null, transcoder.calibrate())
        val outcome = transcoder.export(
            source = object : VideoSource {
                override fun mediaItem(): MediaItem = MediaItem.fromUri("file://${sourceFile.absolutePath}")
                override fun durationUs(): Long = 1_000_000L
                override fun rotationDegrees(): Int = 0
            },
            displayLandscape = true,
            sourceDurationUs = 1_000_000L,
            maxFps = 30f,
            maxClass = 10,
            channel = channel,
        )
        val failure = (outcome as? GhostTranscoder.Outcome.Failed)?.failure
        val detail = (failure as? org.ghost.media.send.PrepFailure.UnsupportedSource)?.detail
        assertTrue("export refused: $failure $detail", outcome is GhostTranscoder.Outcome.Ok)

        // The stream the sealer saw is the tfdt-inserted canonical fMP4.
        val stream = sealer.received()
        assertTrue("the stream starts with a box header", stream.size > 32)
        assertTrue("an ftyp is present", finds(stream, "ftyp"))
        assertTrue("a moof is present", finds(stream, "moof"))
        assertTrue("the tfdt the muxer never writes is inserted", finds(stream, "tfdt"))

        // The export completed: the channel's finish sealed the manifest and the fragments.
        val sealed = channel.finish(ByteArray(0))
        assertEquals(4, sealed.fragmentHashes.size % 4) // whole groups
        for (file in sealed.fragmentFiles + sealed.manifestFile) {
            val bytes = files.read(file)
            assertEquals(MediaLimits.FRAGMENT_BYTES.toLong(), bytes.size.toLong())
        }
    }

    @Test
    fun theCalibrationClipGeneratesAndTheEncoderIsVerified() {
        val context = context()
        val clip = generateCalibrationClip(context)
        val transcoder = GhostTranscoder(context, clip, NoImages)
        val refusal = transcoder.calibrate()
        assertEquals(null, refusal)
    }

    // ---------------------------------------------------------------- the colour-grid clip

    /**
     * The 1-s calibration clip of §8.3 point 5(d): 30 frames of the 1280 × 720 six-colour grid
     * (the centres and colours of `CalibrationExport.GRID_CENTERS/COLOURS`), H.264, encoded by the
     * platform encoder — generated on the device because no host-side H.264 encoder exists here.
     */
    private fun generateCalibrationClip(context: Context): ByteArray {
        val width = 1280
        val height = 720
        val frames = 30
        val colors = intArrayOf(
            0xFF0000, 0x00FF00, 0x0000FF,
            0xFFFF00, 0x00FFFF, 0xFF00FF,
        )
        val outFile = File(context.cacheDir, "calibration-raw.mp4")
        val format = android.media.MediaFormat.createVideoFormat(
            android.media.MediaFormat.MIMETYPE_VIDEO_AVC, width, height,
        ).apply {
            setInteger(
                android.media.MediaFormat.KEY_COLOR_FORMAT,
                android.media.MediaCodecInfo.CodecCapabilities.COLOR_FormatSurface,
            )
            setInteger(
                android.media.MediaFormat.KEY_BITRATE_MODE,
                android.media.MediaCodecInfo.EncoderCapabilities.BITRATE_MODE_VBR,
            )
            setInteger(android.media.MediaFormat.KEY_BIT_RATE, 2_000_000)
            setInteger(android.media.MediaFormat.KEY_FRAME_RATE, 30)
            setInteger(android.media.MediaFormat.KEY_I_FRAME_INTERVAL, 1)
        }
        val encoder = android.media.MediaCodec.createEncoderByType(android.media.MediaFormat.MIMETYPE_VIDEO_AVC)
        val muxer = android.media.MediaMuxer(outFile.absolutePath, android.media.MediaMuxer.OutputFormat.MUXER_OUTPUT_MPEG_4)
        var track = -1
        var encoded = 0
        try {
            encoder.configure(format, null, null, android.media.MediaCodec.CONFIGURE_FLAG_ENCODE)
            val surface = encoder.createInputSurface()
            encoder.start()
            val paint = android.graphics.Paint()
            val cellW = width / 3
            val cellH = height / 2
            for (frame in 0 until frames) {
                val canvas = surface.lockCanvas(null)
                for (i in 0 until 6) {
                    paint.color = colors[i] or 0xFF000000.toInt()
                    canvas.drawRect(
                        ((i % 3) * cellW).toFloat(),
                        ((i / 3) * cellH).toFloat(),
                        (((i % 3) + 1) * cellW).toFloat(),
                        (((i / 3) + 1) * cellH).toFloat(),
                        paint,
                    )
                }
                surface.unlockCanvasAndPost(canvas)
            }
            encoder.signalEndOfInputStream()
            val info = android.media.MediaCodec.BufferInfo()
            var sawEos = false
            while (!sawEos) {
                val id = encoder.dequeueOutputBuffer(info, 100_000)
                when {
                    id == android.media.MediaCodec.INFO_OUTPUT_FORMAT_CHANGED -> {
                        track = muxer.addTrack(encoder.outputFormat)
                        muxer.start()
                    }
                    id >= 0 -> {
                        if (info.flags and android.media.MediaCodec.BUFFER_FLAG_CODEC_CONFIG == 0 && track >= 0) {
                            val buf = encoder.getOutputBuffer(id)!!
                            buf.position(info.offset)
                            buf.limit(info.offset + info.size)
                            muxer.writeSampleData(track, buf, info)
                            encoded++
                        }
                        if (info.flags and android.media.MediaCodec.BUFFER_FLAG_END_OF_STREAM != 0) sawEos = true
                        encoder.releaseOutputBuffer(id, false)
                    }
                }
            }
            muxer.stop()
        } finally {
            runCatching { encoder.stop() }
            encoder.release()
            runCatching { muxer.release() }
        }
        assertTrue("the clip encoded $encoded frames", encoded >= frames / 2)
        return outFile.readBytes()
    }

    private fun finds(bytes: ByteArray, what: String): Boolean {
        val w = what.toByteArray(Charsets.ISO_8859_1)
        outer@ for (i in 0..bytes.size - w.size) {
            for (j in w.indices) if (bytes[i + j] != w[j]) continue@outer
            return true
        }
        return false
    }

    /** The no-images loader Transformer's asset loader requires (the `:app` copy's twin). */
    private object NoImages : BitmapLoader {
        override fun supportsMimeType(mimeType: String): Boolean = false
        override fun decodeBitmap(data: ByteArray): ListenableFuture<Bitmap> =
            Futures.immediateFailedFuture(UnsupportedOperationException("no images"))
        override fun loadBitmap(uri: android.net.Uri): ListenableFuture<Bitmap> =
            Futures.immediateFailedFuture(UnsupportedOperationException("no images"))
    }

    private class TestNames : NameSource {
        private val random = SecureRandom()
        override fun next16(): ByteArray = ByteArray(16).also { random.nextBytes(it) }
    }

    /** The sealer seam: records the stream, seals deterministic whole groups (like the world's). */
    private class RecordingSealer : StreamSealer {
        private val received = java.io.ByteArrayOutputStream()
        private var next = 0

        fun received(): ByteArray = received.toByteArray()

        override fun append(plaintext: ByteArray): List<SealedFragmentGroup> {
            received.write(plaintext)
            val completed = (received.size() / MediaLimits.CHUNK_PLAINTEXT)
            val out = ArrayList<SealedFragmentGroup>()
            while (next < completed) out += group(next++)
            return out
        }

        override fun finish(preview: ByteArray): SealedObject {
            val manifest = ByteArray(MediaLimits.FRAGMENT_BYTES) { 0x4D }
            val finishGroups = ArrayList<SealedFragmentGroup>()
            if (next == 0) finishGroups += group(next++)
            while (next < 4) finishGroups += group(next++)
            return SealedObject(
                classCode = 0,
                contentLen = received.size().toLong(),
                width = 1_280,
                height = 720,
                durationMs = 1_000,
                keyEnv = ByteArray(60),
                manifestBlob = manifest,
                manifestHash = MessageDigest.getInstance("SHA-256").digest(manifest),
                preview = preview,
                finishGroups = finishGroups,
            )
        }

        override fun abort() = Unit

        private fun group(index: Int): SealedFragmentGroup {
            val fragments = List(4) { k ->
                ByteArray(MediaLimits.FRAGMENT_BYTES) { i -> ((index * 7 + k * 13 + (i % 251)) and 0xFF).toByte() }
            }
            val digests = fragments.map { MessageDigest.getInstance("SHA-256").digest(it) }
            return SealedFragmentGroup(index, fragments, digests)
        }
    }
}
