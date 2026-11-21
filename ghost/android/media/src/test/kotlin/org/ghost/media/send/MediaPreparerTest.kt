package org.ghost.media.send

import org.ghost.crypto.bridge.MediaCrypto
import org.ghost.media.store.MediaLimits
import org.ghost.media.store.MediaWorld
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File

/**
 * `MediaPreparer` over fakes: the stripper, the transcoder, the sealer factory and the
 * canonicaliser are test doubles; the [SealingChannel] and the [org.ghost.media.store.CiphertextFiles]
 * are real. The properties (§6.2):
 *
 *  1. the image path strips once, canonicalises its own copy, seals it, and builds the preview
 *     through the same path — the sealer sees exactly the canonical bytes;
 *  2. a sandbox refusal is `UNDECODABLE`;
 *  3. the video path retries once at 15 fps when the projection allows it, and fails `TOO_LARGE`
 *     otherwise;
 *  4. every failure aborts the sealer and releases nothing the commit still needs (the caller
 *     reconciles the orphans).
 */
class MediaPreparerTest {

    private class FakeStripper(
        var refuse: Boolean = false,
        var canonicalJpeg: ByteArray = byteArrayOf(1, 2, 3, 4),
        val previewJpeg: ByteArray = byteArrayOf(5, 6, 7),
    ) : ImageStripper {
        var objectCalls = 0
        var previewCalls = 0
        var previewMaxBytes = 0

        override fun strip(source: ByteArray, preview: Boolean, maxBytes: Int): ImageStripper.StripResult {
            if (refuse) return ImageStripper.StripResult.Failed("refused")
            if (preview) previewMaxBytes = maxBytes
            return if (preview) {
                previewCalls++
                ImageStripper.StripResult.Ok(previewJpeg, 320, 208)
            } else {
                objectCalls++
                ImageStripper.StripResult.Ok(canonicalJpeg, 512, 336)
            }
        }
    }

    private class FakeVideo(
        vararg outcomes: GhostTranscoder.Outcome,
        var calibrateFails: PrepFailure? = null,
    ) : VideoExport {
        private val queue = ArrayDeque(outcomes.toList())
        val fps = ArrayList<Float>()
        override fun calibrate(): PrepFailure? = calibrateFails
        override fun export(
            source: VideoSource,
            displayLandscape: Boolean,
            sourceDurationUs: Long,
            maxFps: Float,
            maxClass: Int,
            channel: SealingChannel,
            cancelled: () -> Boolean,
        ): GhostTranscoder.Outcome {
            fps += maxFps
            // The fake writes a small valid box stream so the channel has bytes to seal.
            val ftyp = Mp4Tfdt.box("ftyp", ByteArray(20))
            channel.write(java.nio.ByteBuffer.wrap(ftyp))
            channel.close()
            return queue.removeFirst()
        }
    }

    private class FakeSealerFactory(
        val sealer: FakeSealer = FakeSealer(),
    ) : MediaSealerFactory {
        val begun = ArrayList<MediaCrypto.Kind>()
        var aborts = 0
        val wrapped = object : StreamSealer by sealer {
            override fun abort() {
                aborts++
                sealer.abort()
            }
        }

        override fun begin(destId: ByteArray, kind: MediaCrypto.Kind, viewOnce: Boolean, maxClass: Int):
            MediaSealerFactory.Begun {
            begun += kind
            return MediaSealerFactory.Begun.Ok(wrapped, ByteArray(16) { 0x0A })
        }
    }

    private class FakeSealer : StreamSealer {
        val received = java.io.ByteArrayOutputStream()
        var aborted = false
        override fun append(plaintext: ByteArray): List<SealedFragmentGroup> {
            received.write(plaintext)
            return emptyList()
        }
        override fun finish(preview: ByteArray): SealedObject =
            SealedObject(
                classCode = 0,
                contentLen = 4,
                width = 512,
                height = 336,
                durationMs = 0,
                keyEnv = ByteArray(60),
                manifestBlob = ByteArray(MediaLimits.FRAGMENT_BYTES),
                manifestHash = ByteArray(32),
                preview = preview,
                finishGroups = emptyList(),
            )
        override fun abort() {
            aborted = true
        }
    }

    /** The pipeline never asks the source anything the fake video port does not answer itself. */
    private object FakeVideoSource : VideoSource {
        override fun mediaItem(): androidx.media3.common.MediaItem = error("unused by the fake")
        override fun durationUs(): Long = 10_000_000L
        override fun rotationDegrees(): Int = 0
    }

    private fun preparer(
        stripper: FakeStripper,
        video: FakeVideo,
        factory: FakeSealerFactory,
        world: MediaWorld,
    ): MediaPreparer {
        val canonicalizer = JpegCanonicalizer { bytes -> bytes.copyOf() }
        return MediaPreparer(stripper, video, factory, canonicalizer, world.files, world.preparing)
    }

    @Test
    fun theImagePathSealsTheCanonicalBytesAndBuildsThePreview() {
        val stripper = FakeStripper()
        MediaWorld().use { world ->
            val factory = FakeSealerFactory()
            val prepared = preparer(stripper, FakeVideo(GhostTranscoder.Outcome.Failed(PrepFailure.Cancelled)), factory, world)
                .prepareImage(byteArrayOf(9, 9), ByteArray(16), viewOnce = false)
            assertEquals(MediaCrypto.Kind.IMAGE, prepared.kind)
            assertEquals(1, stripper.objectCalls)
            assertEquals(1, stripper.previewCalls)
            assertEquals(MediaPreparer.PREVIEW_MAX_BYTES, stripper.previewMaxBytes)
            // The sealer saw the canonical object bytes through the channel's box graph:
            // ftyp is not part of the image stream (images are not fMP4), so the received bytes
            // are exactly the canonical JPEG.
            assertArrayEquals(stripper.canonicalJpeg, factory.sealer.received.toByteArray())
            assertArrayEquals(stripper.previewJpeg, prepared.sealed.preview)
            // Names are still reserved for MEDIA-COMMIT; the caller releases them after.
            assertTrue(!world.preparing.isEmpty)
        }
    }

    @Test
    fun viewOnceCarriesNoPreview() {
        val stripper = FakeStripper()
        MediaWorld().use { world ->
            val prepared = preparer(stripper, FakeVideo(GhostTranscoder.Outcome.Failed(PrepFailure.Cancelled)), FakeSealerFactory(), world)
                .prepareImage(byteArrayOf(9), ByteArray(16), viewOnce = true)
            assertEquals(0, stripper.previewCalls)
            assertEquals(0, prepared.sealed.preview.size)
        }
    }

    @Test
    fun aSandboxRefusalIsUndecodable() {
        MediaWorld().use { world ->
            val preparer = preparer(FakeStripper(refuse = true), FakeVideo(GhostTranscoder.Outcome.Failed(PrepFailure.Cancelled)), FakeSealerFactory(), world)
            try {
                preparer.prepareImage(byteArrayOf(9), ByteArray(16), viewOnce = false)
                fail("the refusal surfaced")
            } catch (e: MediaPreparer.Refused) {
                assertEquals(PrepFailure.Undecodable, e.failure)
            }
        }
    }

    @Test
    fun anOversizeProjectionRetriesOnceAtFifteenFps() {
        MediaWorld().use { world ->
            val ok = GhostTranscoder.Outcome.Ok(byteArrayOf(1), 1_280, 720)
            val video = FakeVideo(GhostTranscoder.Outcome.Oversized(projection = 100), ok)
            val factory = FakeSealerFactory()
            val prepared = preparer(FakeStripper(), video, factory, world)
                .prepareVideo(FakeVideoSource, ByteArray(16), viewOnce = false, maxClass = 10)
            assertEquals(listOf(30f, 15f), video.fps)
            assertEquals(2, factory.begun.size)
            assertEquals(1, factory.aborts)
            assertEquals(MediaCrypto.Kind.VIDEO, prepared.kind)
        }
    }

    @Test
    fun aProjectionAboveTwiceTheCapFailsAtOnce() {
        val cap = MediaSendLimits.contentCapBytes(10)
        MediaWorld().use { world ->
            val video = FakeVideo(GhostTranscoder.Outcome.Oversized(projection = 2 * cap + 1))
            val factory = FakeSealerFactory()
            val preparer = preparer(FakeStripper(), video, factory, world)
            try {
                preparer.prepareVideo(FakeVideoSource, ByteArray(16), viewOnce = false, maxClass = 10)
                fail("the refusal surfaced")
            } catch (e: MediaPreparer.Refused) {
                assertEquals(PrepFailure.TooLarge, e.failure)
            }
            assertEquals(listOf(30f), video.fps)
            assertEquals(1, factory.aborts)
        }
    }

    @Test
    fun underRMT2TheFailureIsTooLargeForTimer() {
        MediaWorld().use { world ->
            val video = FakeVideo(
                GhostTranscoder.Outcome.Oversized(projection = 100),
                GhostTranscoder.Outcome.Oversized(projection = 100),
            )
            val factory = FakeSealerFactory()
            val preparer = preparer(FakeStripper(), video, factory, world)
            try {
                preparer.prepareVideo(FakeVideoSource, ByteArray(16), viewOnce = false, maxClass = 8)
                fail("the refusal surfaced")
            } catch (e: MediaPreparer.Refused) {
                assertEquals(PrepFailure.TooLargeForTimer, e.failure)
            }
        }
    }
}
