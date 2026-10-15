package org.ghost.media.send

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The calibration comparison of §8.3 point 5(d): the decoded frame's patches (YUV planes, the
 * `MediaCodec` output model) are compared against both conversions, and the verdict keeps BT.601,
 * switches to BT.709, or refuses (`NEITHER`) at the 8-level tolerance. The frames are built by
 * converting the source colours **to** YUV with one matrix (an honest encoder's behaviour,
 * S0-13) — the round trip is exact within a level, and the wrong matrix is off by far more than
 * the tolerance.
 */
class ColourGridTest {

    private val grid = listOf(
        Triple(255, 0, 0),
        Triple(0, 255, 0),
        Triple(0, 0, 255),
        Triple(255, 255, 0),
        Triple(0, 255, 255),
        Triple(255, 0, 255),
    )
    private val centers = listOf(24 to 24, 72 to 24, 24 to 72, 72 to 72, 24 to 120, 72 to 120)

    /** A 96×144 frame whose patches are [grid] coded with [matrix] (601 or 709), 4:2:0. */
    private fun frame(matrix: Int, radius: Int = 12): Yuv420.Frame {
        val w = 96
        val h = 144
        val yPlane = ByteArray(w * h)
        val uPlane = ByteArray(w * h / 4)
        val vPlane = ByteArray(w * h / 4)
        for (i in centers.indices) {
            val (sr, sg, sb) = grid[i]
            val rn = sr / 255.0
            val gn = sg / 255.0
            val bn = sb / 255.0
            val kr: Double
            val kb: Double
            if (matrix == 601) {
                kr = 0.299; kb = 0.114
            } else {
                kr = 0.2126; kb = 0.0722
            }
            val kg = 1 - kr - kb
            val yLuma = 16 + 219 * (kr * rn + kg * gn + kb * bn)
            val uChroma = 128 + 224 * (bn - (kr * rn + kg * gn + kb * bn)) / (2 * (1 - kb))
            val vChroma = 128 + 224 * (rn - (kr * rn + kg * gn + kb * bn)) / (2 * (1 - kr))
            val (cx, cy) = centers[i]
            for (yy in maxOf(0, cy - radius) until minOf(h, cy + radius)) {
                for (xx in maxOf(0, cx - radius) until minOf(w, cx + radius)) {
                    yPlane[yy * w + xx] = yLuma.toInt().toByte()
                }
            }
            // 4:2:0: one chroma sample per 2×2 block.
            for (yy in maxOf(0, cy - radius) until minOf(h, cy + radius) step 2) {
                for (xx in maxOf(0, cx - radius) until minOf(w, cx + radius) step 2) {
                    val at = (yy / 2) * (w / 2) + (xx / 2)
                    if (at in uPlane.indices) {
                        uPlane[at] = uChroma.toInt().toByte()
                        vPlane[at] = vChroma.toInt().toByte()
                    }
                }
            }
        }
        return Yuv420.Frame(w, h, yPlane, w, uPlane, w / 2, vPlane, w / 2)
    }

    @Test
    fun aFrameCodedWith601KeepsThe601Request() {
        val result = ColourGrid.compare(frame(601), centers, grid)
        assertEquals(ColourGrid.Verdict.BT_601, result.verdict)
        assertTrue(result.deviation601 <= ColourGrid.TOLERANCE_LEVELS)
    }

    @Test
    fun aFrameCodedWith709SwitchesTheRequest() {
        val result = ColourGrid.compare(frame(709), centers, grid)
        assertEquals(ColourGrid.Verdict.BT_709, result.verdict)
        assertTrue(result.deviation709 <= ColourGrid.TOLERANCE_LEVELS)
    }

    @Test
    fun aFrameOffBothMatricesRefusesVideo() {
        // Source colours shifted 40 levels from what the frame carries: neither matrix can match.
        val shifted = grid.map { (r, g, b) ->
            Triple((r + 40).coerceAtMost(255), (g + 40).coerceAtMost(255), (b + 40).coerceAtMost(255))
        }
        val result = ColourGrid.compare(frame(601), centers, shifted)
        assertEquals(ColourGrid.Verdict.NEITHER, result.verdict)
    }

    @Test
    fun the601FrameIsCloserTo601ThanTo709() {
        val result = ColourGrid.compare(frame(601), centers, grid)
        assertTrue(result.deviation601 < result.deviation709)
    }
}
