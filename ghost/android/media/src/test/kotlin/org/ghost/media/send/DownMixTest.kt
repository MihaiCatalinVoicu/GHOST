package org.ghost.media.send

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The down-mix matrices of §8.3 (S0-20): every input count 1 … 8 has one; 5.1 is ITU-R BS.775
 * without LFE; other counts alternate left/right at gain 2/n. `ChannelMixingMatrix` is row-major
 * `[input][output]`, two outputs.
 */
class DownMixTest {

    @Test
    fun everyInputCountFromOneToEightHasAMatrix() {
        for (n in 1..8) {
            val m = DownMix.matrix(n)
            assertNotNull("matrix for $n inputs", m)
            assertEquals(n * 2, m!!.size)
        }
        assertNull(DownMix.matrix(0))
        assertNull(DownMix.matrix(9))
    }

    @Test
    fun monoAndStereoAreTheIdentityShapes() {
        assertEquals(listOf(1f, 1f), DownMix.matrix(1)!!.toList())
        assertEquals(listOf(1f, 0f, 0f, 1f), DownMix.matrix(2)!!.toList())
    }

    @Test
    fun fiveOneIsBs775WithoutLfe() {
        val m = DownMix.matrix(6)!!
        val k = 0.7071f
        val n = 1f / (1f + 2f * k)
        val want = floatArrayOf(
            n, 0f,        // FL -> L
            0f, n,        // FR -> R
            k * n, k * n, // FC -> L+R
            0f, 0f,       // LFE dropped
            k * n, 0f,    // BL -> L
            0f, k * n,    // BR -> R
        )
        for (i in want.indices) {
            assertEquals("m[$i]", want[i], m[i], 1e-6f)
        }
    }

    @Test
    fun otherCountsAlternateAtGainTwoOverN() {
        for (count in listOf(3, 4, 5, 7, 8)) {
            val m = DownMix.matrix(count)!!
            for (i in 0 until count) {
                for (o in 0..1) {
                    val want = if (i % 2 == o) 2f / count else 0f
                    assertEquals("m[$i][$o] for $count", want, m[i * 2 + o], 1e-6f)
                }
            }
        }
    }

    @Test
    fun noGainExceedsOne() {
        for (n in 1..8) for (g in DownMix.matrix(n)!!) assertTrue(g <= 1f + 1e-6f)
    }
}
