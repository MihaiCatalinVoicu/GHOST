package org.ghost.ui.shell

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import org.ghost.ui.protect.ImeIncognito

/**
 * Phase 13 design §9.1: the theme tokens and the window surface. Dynamic colour on API 31+ by
 * default (Q28) lands with the design-system slice; the skeleton ships the Material 3 schemes
 * with the safety colours fixed (§9.1: warning and error never follow the dynamic palette).
 */
@Composable
fun GhostTheme(modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    val scheme = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme()
    MaterialTheme(colorScheme = scheme) {
        ImeIncognito {
            Surface(modifier = modifier.fillMaxSize()) {
                content()
            }
        }
    }
}
