package org.ghost.media.send

/**
 * The colour calibration of Phase 11 design §8.3 point 5(d) (S0-13, revised in the review pass):
 * which matrix a given encoder *codes* is the encoder's choice, not the request's (API 29's
 * `OMX.google.h264.encoder` codes BT.601 limited whatever it is asked; API 35's
 * `c2.android.avc.encoder` codes what is asked), so `GhostTranscoder` calibrates each encoder once
 * per process: it transcodes a 1-s colour-grid clip through the same configuration, decodes the
 * first output frame **into buffers (YUV planes, never a surface)**, and compares every patch
 * against **both** conversions.
 *
 * Pure and unit-tested on the JVM: [compare] takes the decoded frame as [Yuv420.Frame] (the
 * `MediaCodec` output model), means each patch's luma at full resolution and its chroma at the
 * 4:2:0 half resolution, converts the means with the BT.601 and the BT.709 limited-range
 * matrices, and returns the worst per-channel level deviation from each. The caller keeps the
 * BT.601 request when that is within [TOLERANCE_LEVELS] per channel, switches to a BT.709 limited
 * request when the encoder coded BT.709, and refuses video on the device when neither matches
 * (`COLOUR_UNVERIFIED`). Measured in S0: honest encoders sit 2–4 levels from their matrix and up
 * to 41 from the wrong one, so a tolerance of 8 is an order below the error and an order above
 * the noise.
 */
object ColourGrid {
    /** §8.3 point 5(d): the match tolerance, in levels per channel. */
    const val TOLERANCE_LEVELS: Int = 8

    /** The verdict: which conversion the frame matches within [TOLERANCE_LEVELS]. */
    enum class Verdict {
        /** BT.601 limited matches within tolerance; keep the BT.601 request. */
        BT_601,

        /** BT.709 limited matches; switch the request to BT.709 limited. */
        BT_709,

        /** Neither matches: refuse video on this device. */
        NEITHER,
    }

    /**
     * The worst per-channel deviation of [frame]'s patches from the grid's [sourceColours],
     * converted with BT.601 and BT.709 (limited range), and the verdict.
     *
     * [patchCenters] holds one `(x, y)` pixel center per patch, in the same order as
     * [sourceColours]; luma is read at full resolution, chroma at the 4:2:0 half resolution,
     * over [patchRadius] pixels around the center. [sourceColours] are the sRGB 0–255 levels the
     * grid was built with.
     */
    fun compare(
        frame: Yuv420.Frame,
        patchCenters: List<Pair<Int, Int>>,
        sourceColours: List<Triple<Int, Int, Int>>,
        patchRadius: Int = 8,
    ): Result {
        require(patchCenters.size == sourceColours.size) { "one center per patch" }
        var worst601 = 0
        var worst709 = 0
        for (i in patchCenters.indices) {
            val (x, y) = patchCenters[i]
            val (yy, uu, vv) = meanPatch(frame, x, y, patchRadius)
            val (c601r, c601g, c601b) = yuvToRgb(601, yy, uu, vv)
            val (c709r, c709g, c709b) = yuvToRgb(709, yy, uu, vv)
            val s = sourceColours[i]
            worst601 = maxOf(worst601, abs(c601r - s.first), abs(c601g - s.second), abs(c601b - s.third))
            worst709 = maxOf(worst709, abs(c709r - s.first), abs(c709g - s.second), abs(c709b - s.third))
        }
        val verdict = when {
            worst601 <= TOLERANCE_LEVELS && worst601 <= worst709 -> Verdict.BT_601
            worst709 <= TOLERANCE_LEVELS -> Verdict.BT_709
            else -> Verdict.NEITHER
        }
        return Result(worst601, worst709, verdict)
    }

    class Result(val deviation601: Int, val deviation709: Int, val verdict: Verdict)

    /** The patch's mean (Y, U, V): luma at full resolution, chroma at half. */
    private fun meanPatch(frame: Yuv420.Frame, cx: Int, cy: Int, radius: Int): Triple<Int, Int, Int> {
        var ySum = 0L
        var n = 0L
        val y0 = maxOf(0, cy - radius)
        val y1 = minOf(frame.height - 1, cy + radius)
        val x0 = maxOf(0, cx - radius)
        val x1 = minOf(frame.width - 1, cx + radius)
        for (y in y0..y1) {
            for (x in x0..x1) {
                ySum += frame.yPlane[y * frame.yStride + x].toInt() and 0xff
                n++
            }
        }
        val cy0 = maxOf(0, cy / 2 - radius / 2)
        val cy1 = minOf(frame.height / 2 - 1, cy / 2 + radius / 2)
        val cx0 = maxOf(0, cx / 2 - radius / 2)
        val cx1 = minOf(frame.width / 2 - 1, cx / 2 + radius / 2)
        var uSum = 0L
        var vSum = 0L
        var m = 0L
        for (y in cy0..cy1) {
            for (x in cx0..cx1) {
                uSum += frame.uPlane[y * frame.uStride + x].toInt() and 0xff
                vSum += frame.vPlane[y * frame.vStride + x].toInt() and 0xff
                m++
            }
        }
        return Triple((ySum / n).toInt(), (uSum / m).toInt(), (vSum / m).toInt())
    }

    /**
     * YUV limited-range to RGB with the matrix's coefficients, then to 0–255 levels: BT.601
     * (`Kr = 0.299`, `Kb = 0.114`) and BT.709 (`Kr = 0.2126`, `Kb = 0.0722`), studio range
     * (Y 16–235, U/V 16–240). Returns the nearest 0–255 level per channel.
     */
    internal fun yuvToRgb(matrix: Int, y: Int, u: Int, v: Int): Triple<Int, Int, Int> {
        val yy = (y - 16) / 219.0
        val uu = (u - 128) / 224.0
        val vv = (v - 128) / 224.0
        val kr: Double
        val kb: Double
        when (matrix) {
            601 -> {
                kr = 0.299
                kb = 0.114
            }
            709 -> {
                kr = 0.2126
                kb = 0.0722
            }
            else -> throw IllegalArgumentException("matrix")
        }
        val kg = 1 - kr - kb
        val r = yy + vv * 2 * (1 - kr)
        val b = yy + uu * 2 * (1 - kb)
        val g = (yy - kr * r - kb * b) / kg
        fun level(x: Double) = (x * 255.0).toInt().coerceIn(0, 255)
        return Triple(level(r), level(g), level(b))
    }

    private fun abs(x: Int): Int = if (x < 0) -x else x
}
