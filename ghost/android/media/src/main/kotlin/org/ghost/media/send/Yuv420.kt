package org.ghost.media.send

/**
 * The YUV 4:2:0 → RGBA conversion of the preview path (§6.2): the first output frame is decoded
 * into buffers (never a surface), converted with the **output's** colour label (limited range,
 * the matrix of §8.3 point 5(d): BT.601 by default, BT.709 for an encoder the calibration found
 * coding BT.709, S0-13), turned by the output's `tkhd` rotation (S0-20), then scaled to the
 * 320-px preview geometry and compressed (the main process canonicalises the result, §8.2).
 *
 * The pixel model is plain planes ([yPlane], [uPlane], [vPlane] as ByteArrays) so the conversion
 * is unit-tested on the JVM without a codec; the Android glue maps `MediaCodec` output images
 * (semi-planar included) onto it.
 */
object Yuv420 {
    /** Which matrix the pixels are coded with: the calibration's verdict (§8.3 point 5(d)). */
    enum class Matrix { BT_601, BT_709 }

    /**
     * One 4:2:0 frame as separate planes with strides (the `MediaCodec` output image model).
     * [width] × [height] pixels; chroma is quarter resolution, so chroma sample (`cx`, `cy`)
     * covers luma (2cx..2cx+1, 2cy..2cy+1).
     */
    class Frame(
        val width: Int,
        val height: Int,
        val yPlane: ByteArray,
        val yStride: Int,
        val uPlane: ByteArray,
        val uStride: Int,
        val vPlane: ByteArray,
        val vStride: Int,
    )

    /**
     * Converts [frame] to RGBA (`width × height × 4`, order R, G, B, A; alpha 255), chroma
     * sampled at the nearest 2×2 luma center.
     */
    fun toRgba(frame: Frame, matrix: Matrix): ByteArray {
        val out = ByteArray(frame.width * frame.height * 4)
        val code = if (matrix == Matrix.BT_601) 601 else 709
        for (y in 0 until frame.height) {
            val cy = y shr 1
            for (x in 0 until frame.width) {
                val cx = x shr 1
                val yy = frame.yPlane[y * frame.yStride + x].toInt() and 0xff
                val uu = frame.uPlane[cy * frame.uStride + cx].toInt() and 0xff
                val vv = frame.vPlane[cy * frame.vStride + cx].toInt() and 0xff
                val (r, g, b) = ColourGrid.yuvToRgb(code, yy, uu, vv)
                val at = (y * frame.width + x) * 4
                out[at] = r.toByte()
                out[at + 1] = g.toByte()
                out[at + 2] = b.toByte()
                out[at + 3] = 255.toByte()
            }
        }
        return out
    }
}
