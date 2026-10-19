package org.ghost.ui.design

import androidx.compose.ui.graphics.Color

/**
 * Phase 13 design §9.1: the semantic colours, contrast-checked in both modes (the arithmetic
 * lives in DesignTokensTest). Dynamic colour (Material You, Q28) may move the chrome, but a
 * key change is always the same red: `danger`, `warning` and `verified` never follow the
 * dynamic palette.
 *
 * S9 found the skeleton's gap: one fixed mid tone cannot reach WCAG AA on both the light
 * surface (white) and the dark surface (#1C1B1F) — the light values sit at 2.6–2.8:1 on dark.
 * The semantics stay fixed; the value is per-mode, picked with [dangerFor] and its siblings.
 */
object GhostColors {
    /** The values on light surfaces. */
    val danger = Color(0xFFB3261E)
    val warning = Color(0xFF8A5100)
    val verified = Color(0xFF146C2E)
    val neutral = Color(0xFF5F6368)

    /** The same semantics on dark surfaces (AA 10:1 on the dark scheme's surface). */
    object OnDark {
        val danger = Color(0xFFF2B8B5)
        val warning = Color(0xFFFABC49)
        val verified = Color(0xFF7BDA8D)
        val neutral = Color(0xFFC3C7CF)
    }

    fun dangerFor(dark: Boolean): Color = if (dark) OnDark.danger else danger
    fun warningFor(dark: Boolean): Color = if (dark) OnDark.warning else warning
    fun verifiedFor(dark: Boolean): Color = if (dark) OnDark.verified else verified
    fun neutralFor(dark: Boolean): Color = if (dark) OnDark.neutral else neutral
}
