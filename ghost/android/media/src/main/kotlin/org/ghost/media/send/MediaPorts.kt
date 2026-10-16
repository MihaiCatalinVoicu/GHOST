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
