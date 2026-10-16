package org.ghost.media.send

import android.content.Context
import org.ghost.media.sandbox.MediaSandbox

/**
 * The production adapters of [MediaPreparer]'s ports: the sandbox behind [ImageStripper], and
 * `GhostTranscoder` behind [VideoExport] (the Android halves the worlds fake, §15.1).
 */
class SandboxStripper(private val sandbox: MediaSandbox) : ImageStripper {
    override fun strip(source: ByteArray, preview: Boolean, maxBytes: Int): ImageStripper.StripResult =
        when (val result = sandbox.stripImage(source, preview, maxBytes)) {
            is MediaSandbox.Result.Ok ->
                ImageStripper.StripResult.Ok(result.bytes, result.width, result.height)
            is MediaSandbox.Result.Failure -> ImageStripper.StripResult.Failed(result.reason.name)
        }
}

/**
 * `DECODE_IMAGE` as a port (§9.2; the recipient-side half of the sandbox seam, slice S6): a
 * canonical JPEG (already validated by the reader) decoded to ARGB_8888 pixels within
 * [maxW] × [maxH]. The facade's preview path runs behind this so a world can prove the
 * zero-click rules with a recording fake (§9.3, T46) and so a decode failure maps onto the
 * object's two-strikes rule (CS-M8) without a sandbox bind in the loop.
 */
interface ImageDecoder {
    /** The `w × h × 4` pixels, or null for any sandbox failure (typed reasons live in `:app`). */
    fun decode(jpeg: ByteArray, maxW: Int, maxH: Int): Decoded?

    class Decoded(val pixels: ByteArray, val width: Int, val height: Int) {
        override fun toString(): String = "Decoded(${width}x$height)"
    }
}

/** `MediaSandbox.decodeImage` as the [ImageDecoder] port. */
class SandboxDecoder(private val sandbox: MediaSandbox) : ImageDecoder {
    override fun decode(jpeg: ByteArray, maxW: Int, maxH: Int): ImageDecoder.Decoded? =
        when (val result = sandbox.decodeImage(jpeg, maxW, maxH)) {
            is MediaSandbox.Result.Ok -> ImageDecoder.Decoded(result.bytes, result.width, result.height)
            is MediaSandbox.Result.Failure -> null
        }
}

/** `GhostTranscoder` as the [VideoExport] port. */
class GhostVideoExport(
    private val context: Context,
    private val transcoder: GhostTranscoder,
) : VideoExport {
    override fun calibrate(): PrepFailure? = transcoder.calibrate()

    override fun export(
        source: VideoSource,
        displayLandscape: Boolean,
        sourceDurationUs: Long,
        maxFps: Float,
        maxClass: Int,
        channel: SealingChannel,
        cancelled: () -> Boolean,
    ): GhostTranscoder.Outcome =
        transcoder.export(source, displayLandscape, sourceDurationUs, maxFps, maxClass, channel, cancelled)
}
