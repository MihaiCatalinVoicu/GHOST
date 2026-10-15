package org.ghost.media.send

import android.graphics.Bitmap
import android.graphics.Matrix
import java.io.ByteArrayOutputStream

/**
 * The preview from the canonical output (§6.2, S0-19): the output's first video sample decoded by
 * [FrameProbe] with the output's `avcC`, converted with the output's colour label (the
 * calibration's matrix), turned by the output's `tkhd` rotation (S0-20), scaled to the 320-px
 * preview geometry of D29 and compressed baseline JPEG at q85. The caller canonicalises the
 * result in Rust (§8.2); a decode failure means no preview (`preview_len = 0`).
 */
object PreviewBuilder {

    /**
     * Builds the preview JPEG, or null when the first sample would not decode. [matrix] is the
     * calibration's verdict for this process's encoder; [rotationDegrees] the output track's
     * rotation.
     */
    fun build(
        previewInput: GhostMuxer.PreviewInput,
        rotationDegrees: Int,
        matrix: Yuv420.Matrix,
    ): ByteArray? {
        val frame = FrameProbe.decodeSample(previewInput.avcC, previewInput.firstSyncSample)
            ?: return null
        val rgba = Yuv420.toRgba(frame, matrix)
        val bitmap = try {
            Bitmap.createBitmap(frame.width, frame.height, Bitmap.Config.ARGB_8888).apply {
                copyPixelsFromBuffer(java.nio.ByteBuffer.wrap(rgba))
            }
        } catch (e: IllegalArgumentException) {
            // A decoder lied about its frame size: no preview, never a failed send (§6.2).
            return null
        }
        val rotated = rotate(bitmap, rotationDegrees)
        val displayed = if (rotationDegrees == 90 || rotationDegrees == 270) {
            Pair(rotated.height, rotated.width)
        } else {
            Pair(rotated.width, rotated.height)
        }
        val (tw, th) = MediaGeometry.previewTarget(displayed.first, displayed.second)
        val scaled = Bitmap.createScaledBitmap(rotated, tw, th, true)
        val out = ByteArrayOutputStream()
        scaled.compress(Bitmap.CompressFormat.JPEG, 85, out)
        erase(bitmap)
        if (scaled !== rotated) erase(rotated)
        erase(scaled)
        return out.toByteArray()
    }

    private fun rotate(bitmap: Bitmap, degrees: Int): Bitmap {
        if (degrees == 0) return bitmap
        val m = Matrix().apply { postRotate(degrees.toFloat()) }
        return Bitmap.createBitmap(bitmap, 0, 0, bitmap.width, bitmap.height, m, true)
    }

    /** §10.5's RAM hygiene, applied to the pixels this class created (each bitmap erased once). */
    private fun erase(bitmap: Bitmap) {
        bitmap.eraseColor(0)
        bitmap.recycle()
    }
}
