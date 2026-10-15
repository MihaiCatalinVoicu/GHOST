package org.ghost.media.send

/**
 * The canonical geometry of D29 (Phase 11 design §6.2, §8.2), the size `STRIP_IMAGE` re-encodes a
 * source to and the sealer's JPEG profile admits: the long edge is the largest of 512, 1 024 and
 * 2 048 not above the source's long edge (512 for a smaller source), the short edge
 * `max(16, 16 · round(long · ratio / 16))`.
 *
 * **The rounding is pinned by S1** (§22.2 row 7a): "rounds half up, in integers", and the 18 sizes
 * of `protocol/test-vectors/media_object.txt` `[ladder]` are the contract, replayed by the JDK
 * (`MediaGeometryTest` parses that file, so this code and the Rust `geometry::image_target` cannot
 * drift apart). "In integers" is realised exactly: no floating point, so a tie (a remainder of
 * exactly half the divisor) rounds up and nothing else does. `STRIP_IMAGE` runs in the isolated
 * process **without** the native library, so this file is the one implementation of the ladder on
 * the device.
 */
object MediaGeometry {

    /** The long-edge steps of an object's image (§8.2), largest first. */
    private val LADDER: IntArray = intArrayOf(2_048, 1_024, 512)

    /** The long edge of a canonical preview (§6.2). */
    const val PREVIEW_LONG_EDGE: Int = 320

    /**
     * The target size of an object's image for a source of [width] × [height] pixels **after
     * orientation**: `Pair(targetW, targetH)` with the long edge on the ladder and the short edge
     * a multiple of 16 (at least 16), never above the source's aspect.
     */
    fun imageTarget(width: Int, height: Int): Pair<Int, Int> = target(width, height, ladderStep(width, height))

    /** The target size of a preview (long edge [PREVIEW_LONG_EDGE], §6.2) for a canonical [width] × [height]. */
    fun previewTarget(width: Int, height: Int): Pair<Int, Int> = target(width, height, PREVIEW_LONG_EDGE)

    /**
     * The ladder step for a source whose long edge is [long]: the largest ladder entry not above
     * it, 512 when the source is smaller than 512 (§8.2).
     */
    internal fun ladderStep(width: Int, height: Int): Int {
        val long = maxOf(width, height)
        for (step in LADDER) if (step <= long) return step
        return LADDER[LADDER.size - 1]
    }

    /** The target size at an explicit long edge (the sandbox's retry ladder, §8.2). */
    internal fun targetAt(width: Int, height: Int, longEdge: Int): Pair<Int, Int> =
        target(width, height, longEdge)

    /**
     * `Pair(targetW, targetH)`: the long edge is [longEdge], the short edge
     * `max(16, 16 · roundHalfUp(long · short / (16 · long)))` computed in integers, the aspect held
     * (the source's wider side stays wider; a square source stays square).
     */
    internal fun target(width: Int, height: Int, longEdge: Int): Pair<Int, Int> {
        require(width > 0 && height > 0) { "source size is not positive" }
        val landscape = width >= height
        val longSrc = maxOf(width, height).toLong()
        val shortSrc = minOf(width, height).toLong()
        // roundHalfUp(a / b) in integers, a, b > 0: (2a + b) / (2b).
        val numerator = 2L * longEdge * shortSrc
        val divisor = 2L * 16L * longSrc
        val rounded = ((numerator + 16L * longSrc) / divisor).toInt()
        val short = maxOf(16, 16 * rounded)
        return if (landscape) Pair(longEdge, short) else Pair(short, longEdge)
    }
}
