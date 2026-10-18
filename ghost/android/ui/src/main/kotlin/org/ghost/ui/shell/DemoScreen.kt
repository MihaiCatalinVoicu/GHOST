package org.ghost.ui.shell

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import org.ghost.ui.R

/**
 * Phase 13 design §14.1 S0b: the one demo screen the skeleton ships, so the gates scan real
 * sources and the emulator smoke suite has something to render before S1's foundation lands.
 * It shows only build-stage copy — no engine state, no secrets (CP-10: claims match evidence).
 */
@Composable
fun DemoScreen() {
    Column(modifier = Modifier.padding(24.dp)) {
        Text(
            text = stringResource(R.string.demo_title),
            style = MaterialTheme.typography.headlineSmall,
        )
        Spacer(modifier = Modifier.height(12.dp))
        Text(
            text = stringResource(R.string.demo_body),
            style = MaterialTheme.typography.bodyMedium,
        )
    }
}
