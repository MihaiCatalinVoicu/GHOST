package org.ghost.ui.design

import androidx.compose.ui.graphics.Color

/**
 * Phase 13 design §9.1: the semantic colours — fixed in both modes, contrast-checked (the
 * arithmetic lives in DesignTokensTest). Dynamic colour (Material You, Q28) may move the
 * chrome, but a key change is always the same red: `danger`, `warning` and `verified` never
 * follow the dynamic palette.
 */
object GhostColors {
    val danger = Color(0xFFB3261E)
    val warning = Color(0xFF8A5100)
    val verified = Color(0xFF146C2E)
    val neutral = Color(0xFF5F6368)
}
