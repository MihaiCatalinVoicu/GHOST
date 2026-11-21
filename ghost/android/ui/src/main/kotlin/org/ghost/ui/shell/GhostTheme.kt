package org.ghost.ui.shell

import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalConfiguration
import java.util.Locale

/** Midnight/mint product theme. English is deliberate product copy, independent of the OS locale. */
private val MidnightMint = darkColorScheme(
    primary = Color(0xFF82F6C8),
    onPrimary = Color(0xFF003B2A),
    primaryContainer = Color(0xFF164E3D),
    onPrimaryContainer = Color(0xFFC0FBE3),
    secondary = Color(0xFFAAC7FF),
    onSecondary = Color(0xFF102A4C),
    secondaryContainer = Color(0xFF22354B),
    onSecondaryContainer = Color(0xFFD9E5FF),
    background = Color(0xFF080D12),
    onBackground = Color(0xFFE3E9ED),
    surface = Color(0xFF080D12),
    onSurface = Color(0xFFE3E9ED),
    surfaceVariant = Color(0xFF182128),
    onSurfaceVariant = Color(0xFFAAB8C0),
    surfaceContainer = Color(0xFF111920),
    surfaceContainerHigh = Color(0xFF18232B),
    outline = Color(0xFF3B4A53),
    error = Color(0xFFFFB4AB),
    onError = Color(0xFF690005),
    errorContainer = Color(0xFF93000A),
    onErrorContainer = Color(0xFFFFDAD6),
)

@Composable
fun GhostTheme(modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    val current = LocalConfiguration.current
    val context = androidx.compose.ui.platform.LocalContext.current
    val english = android.content.res.Configuration(current).apply { setLocale(Locale.ENGLISH) }
    val localizedContext = context.createConfigurationContext(english)
    CompositionLocalProvider(
        LocalConfiguration provides english,
        androidx.compose.ui.platform.LocalContext provides localizedContext,
    ) {
        MaterialTheme(colorScheme = MidnightMint) {
            Surface(modifier = modifier.fillMaxSize(), color = MidnightMint.background) {
                content()
            }
        }
    }
}
