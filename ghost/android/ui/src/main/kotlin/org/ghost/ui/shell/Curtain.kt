package org.ghost.ui.shell

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import org.ghost.ui.R

/**
 * Phase 13 design §3.3, §5.1: the curtain — the neutral panel shown while the app is hidden or
 * locked. It carries no content state: at every hide every screen model drops its `UiState` and
 * the composition shows this panel until the app is shown again, so no decrypted list or text
 * waits in a hidden process (D5). At a lock the same panel is the lock screen's backdrop; the
 * PIN entry content (S2) renders above it only while CHECKING.
 */
@Composable
fun Curtain(modifier: Modifier = Modifier) {
    Box(modifier = modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Text(
            text = stringResource(R.string.curtain_label),
            style = MaterialTheme.typography.titleMedium,
        )
    }
}
