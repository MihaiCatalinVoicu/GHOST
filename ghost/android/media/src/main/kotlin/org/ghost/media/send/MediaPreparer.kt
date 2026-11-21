package org.ghost.media.send

import androidx.media3.common.MediaItem
import org.ghost.crypto.bridge.MediaCrypto
import org.ghost.media.store.CiphertextFiles
import org.ghost.media.store.PreparingFiles

/**
 * The picked video source, opaque to `:media` (§6.5's `MediaSource` wraps a content URI): the
 * production implementation lives in `:app` — G-DM1 bans the platform's content-handle package
 * from the DM modules, so the handle never crosses into `:media`; the transformer sees only the
 * `MediaItem`, and the metadata reads (duration, rotation) sit behind this port too.
 */
interface VideoSource {
    /** The `MediaItem` Transformer exports. */
    fun mediaItem(): MediaItem

    /** The source's duration in microseconds, -1 when unknown (the send is refused). */
    fun durationUs(): Long

    /** The source's display rotation degrees (0, 90, 180 or 270). */
    fun rotationDegrees(): Int
}

/**
 * The ports [MediaPreparer] runs behind (§15.1's fakes in the worlds): the image stripper is the
 * sandbox in production and a seeded generator in tests; the video transcoder is `GhostTranscoder`
 * and a golden-stream fake; the sealer factory is `NativeStreamSealer` and the host build.
 */
interface ImageStripper {
    /** `STRIP_IMAGE`: the canonical-geometry JPEG (or the preview when [preview]). */
    fun strip(source: ByteArray, preview: Boolean, maxBytes: Int): StripResult

    sealed interface StripResult {
        class Ok(val jpeg: ByteArray, val width: Int, val height: Int) : StripResult
        class Failed(val reason: String) : StripResult
    }
}

/** The video half: calibration plus one export attempt at a frame rate. */
interface VideoExport {
    fun calibrate(): PrepFailure?
    fun export(
        source: VideoSource,
        displayLandscape: Boolean,
        sourceDurationUs: Long,
        maxFps: Float,
        maxClass: Int,
        channel: SealingChannel,
        cancelled: () -> Boolean,
    ): GhostTranscoder.Outcome
}

/** M1's begin: the caller maps [NativeStreamSealer.Begun] onto this. */
interface MediaSealerFactory {
    sealed interface Begun {
        class Ok(val sealer: StreamSealer, val objectId: ByteArray) : Begun
        data object Limited : Begun
        data object Unavailable : Begun
    }

    fun begin(destId: ByteArray, kind: MediaCrypto.Kind, viewOnce: Boolean, maxClass: Int): Begun
}

/** M9 `jpegCanonicalize` as a port (the main process's own-copy check, §6.2). */
fun interface JpegCanonicalizer {
    /** The canonical bytes, or null when the input is not canonical (unreachable for our own output). */
    fun canonicalize(bytes: ByteArray): ByteArray?
}

/**
 * `MediaPreparer` of Phase 11 design §6.2: the media worker's orchestration with **no database
 * transaction** — sniff, limits, the sandbox or Transformer, the sealing channel, and the typed
 * failures every stage can produce. After this returns, the caller runs `MEDIA-COMMIT` (the one
 * transaction, on the DM actor) and then releases the reserved names.
 *
 * **Image:** the sandbox strips the source to the canonical geometry (a fresh isolated instance,
 * §9.2); the main process canonicalises its own copy in Rust (the bytes it seals are the bytes it
 * checked); the preview goes through the same path unless view-once; the canonical bytes feed the
 * sealer (§8.2).
 *
 * **Video:** `GhostTranscoder` exports the canonical fMP4 through `GhostMuxer` into the channel;
 * the class cap is enforced while writing, and the one 15-fps retry of §6.2 runs when the
 * projection allows it; the preview is built from the output (S0-19). Every run's sealer is
 * begun fresh and aborted on failure — a retried burst re-seals from scratch (CS-M1's registry
 * would catch a resumed sealer under one key).
 */
class MediaPreparer(
    private val stripper: ImageStripper,
    private val video: VideoExport,
    private val sealers: MediaSealerFactory,
    private val canonicalizer: JpegCanonicalizer,
    private val files: CiphertextFiles,
    private val preparing: PreparingFiles,
) {
    /** What a finished preparation hands to `MEDIA-COMMIT` (plus the identity of the object). */
    class Prepared internal constructor(
        val kind: MediaCrypto.Kind,
        val viewOnce: Boolean,
        val objectId: ByteArray,
        val sealed: SealedResult,
        /** Releases the reserved file names: after `MEDIA-COMMIT`, or on abandonment. */
        val releaseNames: () -> Unit,
    )

    /** The one refusal shape: [PrepFailure], mapped once at the boundary. */
    class Refused(val failure: PrepFailure) : IllegalStateException("preparation refused")

    /**
     * The image pipeline. [source] is the sniffed JPEG/PNG/WebP bytes (≤ 64 MiB, checked by the
     * caller before any work); [shortTimer] is the R-MT2 class-8 cap (a 1-hour bucket).
     */
    fun prepareImage(
        source: ByteArray,
        destId: ByteArray,
        viewOnce: Boolean,
    ): Prepared {
        val strip = stripper.strip(source, preview = false, MediaSendLimits.IMAGE_MAX_CONTENT)
        val jpeg = when (strip) {
            is ImageStripper.StripResult.Ok -> strip.jpeg
            is ImageStripper.StripResult.Failed -> throw Refused(PrepFailure.Undecodable)
        }
        // The canonical check on our own copy, after the instance died (§6.2, §9.2).
        val canonical = canonicalizer.canonicalize(jpeg)
            ?: throw Refused(PrepFailure.Undecodable)
        val preview = if (viewOnce) {
            ByteArray(0)
        } else {
            imagePreview(source)
        }
        val sealer = begin(destId, MediaCrypto.Kind.IMAGE, viewOnce, maxClass = 0)
        val channel = SealingChannel.raw(sealer.sealer, files, preparing)
        try {
            feed(channel, canonical)
            val sealed = channel.finish(preview)
            return Prepared(MediaCrypto.Kind.IMAGE, viewOnce, sealer.objectId, sealed, channel::releaseNames)
        } catch (e: SealException) {
            channel.abort()
            throw Refused(e.toFailure(shortTimer = false))
        }
    }

    /**
     * The video pipeline. [sourceDurationMsBound] is `VIDEO_MAX_MS` or `VIDEO_MAX_MS_SHORT`
     * (R-MT2), checked by the caller against the source duration before any work; [maxClass] is
     * 10, or 8 under R-MT2.
     */
    fun prepareVideo(
        source: VideoSource,
        destId: ByteArray,
        viewOnce: Boolean,
        maxClass: Int,
        cancelled: () -> Boolean = { false },
    ): Prepared {
        video.calibrate()?.let { throw Refused(it) }
        val durationUs = source.durationUs()
        if (durationUs < 0) {
            throw Refused(PrepFailure.UnsupportedSource(PrepFailure.UnsupportedSource.Detail.CONTAINER))
        }
        val landscape = source.rotationDegrees().let { it == 0 || it == 180 }
        return runExport(source, destId, viewOnce, durationUs, landscape, maxClass, MediaSendLimits.OUTPUT_FPS, cancelled)
    }

    @Suppress("LongParameterList")
    private fun runExport(
        source: VideoSource,
        destId: ByteArray,
        viewOnce: Boolean,
        durationUs: Long,
        landscape: Boolean,
        maxClass: Int,
        fps: Float,
        cancelled: () -> Boolean,
        retried: Boolean = false,
    ): Prepared {
        val sealer = begin(destId, MediaCrypto.Kind.VIDEO, viewOnce, maxClass)
        val channel = SealingChannel.of(sealer.sealer, files, preparing)
        try {
            when (val outcome = video.export(source, landscape, durationUs, fps, maxClass, channel, cancelled)) {
                is GhostTranscoder.Outcome.Ok -> {
                    val preview = if (viewOnce) ByteArray(0) else outcome.previewBytes
                    val sealed = channel.finish(preview)
                    return Prepared(MediaCrypto.Kind.VIDEO, viewOnce, sealer.objectId, sealed, channel::releaseNames)
                }
                is GhostTranscoder.Outcome.Oversized -> {
                    channel.abort()
                    // §6.2's retry rule: at most twice the cap projects to fit at 15 fps.
                    val cap = MediaSendLimits.contentCapBytes(maxClass)
                    if (!retried && outcome.projection <= 2 * cap) {
                        return runExport(
                            source, destId, viewOnce, durationUs, landscape, maxClass,
                            MediaSendLimits.RETRY_FPS, cancelled, retried = true,
                        )
                    }
                    throw Refused(
                        if (maxClass < MediaSendLimits.MAX_CLASS) PrepFailure.TooLargeForTimer else PrepFailure.TooLarge,
                    )
                }
                is GhostTranscoder.Outcome.Failed -> {
                    channel.abort()
                    throw Refused(outcome.failure)
                }
            }
        } catch (e: SealException) {
            channel.abort()
            throw Refused(e.toFailure(shortTimer = maxClass < MediaSendLimits.MAX_CLASS))
        }
    }

    /** The 320-px preview through the same strip path (§6.2); a failure means no preview. */
    private fun imagePreview(source: ByteArray): ByteArray {
        val strip = stripper.strip(source, preview = true, PREVIEW_MAX_BYTES)
        if (strip is ImageStripper.StripResult.Ok) {
            return canonicalizer.canonicalize(strip.jpeg) ?: ByteArray(0)
        }
        return ByteArray(0)
    }

    private fun begin(destId: ByteArray, kind: MediaCrypto.Kind, viewOnce: Boolean, maxClass: Int) =
        when (val begun = sealers.begin(destId, kind, viewOnce, maxClass)) {
            is MediaSealerFactory.Begun.Ok -> begun
            // Two sealers live (the registry's bound): nothing about the source — surface as the
            // cancellation-shaped refusal; the facade counts it, the UI retries.
            MediaSealerFactory.Begun.Limited -> throw Refused(PrepFailure.Cancelled)
            // The context closed or the library is missing mid-preparation (a lock): the
            // preparation is gone, not failed on the source. `CRYPTO_UNAVAILABLE` was answerable
            // only before `QUEUED`.
            MediaSealerFactory.Begun.Unavailable -> throw Refused(PrepFailure.Cancelled)
        }

    private fun feed(channel: SealingChannel, bytes: ByteArray) {
        var at = 0
        while (at < bytes.size) {
            val end = minOf(bytes.size, at + org.ghost.media.store.MediaLimits.CHUNK_PLAINTEXT)
            channel.write(java.nio.ByteBuffer.wrap(bytes, at, end - at))
            at = end
        }
        channel.close()
    }

    companion object {
        /** The fixed preview field of the manifest (Phase 11 §3.5). */
        const val PREVIEW_MAX_BYTES: Int = 32_768
    }
}

/** The [SealException] → [PrepFailure] mapping at the preparation boundary (§6.2). */
internal fun SealException.toFailure(shortTimer: Boolean): PrepFailure = when (this) {
    is SealException.NonCanonical -> PrepFailure.UnsupportedSource(
        PrepFailure.UnsupportedSource.Detail.CODEC,
    )
    is SealException.Oversize ->
        if (shortTimer) PrepFailure.TooLargeForTimer else PrepFailure.TooLarge
    is SealException.Storage -> PrepFailure.StorageFull
    is SealException.Unavailable -> PrepFailure.StorageFull
    is SealException.Internal -> PrepFailure.UnsupportedSource(
        PrepFailure.UnsupportedSource.Detail.NOT_ENCODED,
    )
}
