package org.ghost.app.ui

import org.ghost.ui.design.GhostColors
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Phase 13 design §9.1, §9.2: the contrast arithmetic over the fixed semantic colours — WCAG
 * 2.2 AA on both scheme surfaces (4.5:1 for body text; the same floor applied to every pair,
 * so a large-text relaxation can never hide a regression). The light values are checked on
 * white, the dark values on the Material dark scheme's surface #1C1B1F — through the same
 * [GhostColors] selectors the composables use, so the test cannot drift from the call sites.
 */
class DesignTokensTest {
    /** WCAG relative luminance. */
    private fun luminance(color: Long): Double {
        fun channel(v: Int): Double {
            val c = v / 255.0
            return if (c <= 0.04045) c / 12.92 else Math.pow((c + 0.055) / 1.055, 2.4)
        }
        val r = channel(((color shr 16) and 0xFF).toInt())
        val g = channel(((color shr 8) and 0xFF).toInt())
        val b = channel((color and 0xFF).toInt())
        return 0.2126 * r + 0.7152 * g + 0.0722 * b
    }

    private fun contrast(foreground: Long, background: Long): Double {
        val l1 = luminance(foreground)
        val l2 = luminance(background)
        val (hi, lo) = if (l1 >= l2) l1 to l2 else l2 to l1
        return (hi + 0.05) / (lo + 0.05)
    }

    @Test
    fun theSemanticColoursReachAaonBothSurfaces() {
        val lightSurface = 0xFFFFFFFF
        val darkSurface = 0xFF1C1B1F
        val pairs = listOf(
            Triple("danger", GhostColors.dangerFor(false).value.toLong() ushr 32, GhostColors.dangerFor(true).value.toLong() ushr 32),
            Triple("warning", GhostColors.warningFor(false).value.toLong() ushr 32, GhostColors.warningFor(true).value.toLong() ushr 32),
            Triple("verified", GhostColors.verifiedFor(false).value.toLong() ushr 32, GhostColors.verifiedFor(true).value.toLong() ushr 32),
            Triple("neutral", GhostColors.neutralFor(false).value.toLong() ushr 32, GhostColors.neutralFor(true).value.toLong() ushr 32),
        )
        for ((name, onLight, onDark) in pairs) {
            val lightRatio = contrast(onLight, lightSurface)
            val darkRatio = contrast(onDark, darkSurface)
            assertTrue(
                "$name reaches AA on the light surface (4.5:1, got %.2f:1)".format(lightRatio),
                lightRatio >= 4.5,
            )
            assertTrue(
                "$name reaches AA on the dark surface (4.5:1, got %.2f:1)".format(darkRatio),
                darkRatio >= 4.5,
            )
        }
    }
}
