package org.ghost.ui.feature.media

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.ghost.ui.R

/**
 * Phase 13 design §6.6 (J5): the media rows the settings and the composer host. The download
 * pause is a row with its residue sentence (L9-M3) — the relays see the listing stop — and the
 * attach is a button whose picker intent the caller launches ([org.ghost.ui.platform.SystemIntents.pickImage]);
 * the picked URI comes back to [MediaAttachModel.onSendMedia]. The transfer progress, the
 * preview, the viewer and the view-once screen land with Phase 11's facade slice — the gateway
 * carries no read for them yet, and nothing here pretends otherwise.
 */
@Composable
fun DownloadPauseRow(model: MediaDownloadsModel, modifier: Modifier = Modifier) {
    val scope = rememberCoroutineScope()
    var paused by remember { mutableStateOf(model.paused) }
    Row(
        modifier = modifier.fillMaxWidth().padding(vertical = 12.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(text = stringResource(R.string.media_pause_downloads), style = MaterialTheme.typography.titleMedium)
            Text(text = stringResource(R.string.media_pause_note), style = MaterialTheme.typography.bodyMedium)
        }
        Switch(
            checked = paused,
            onCheckedChange = { next ->
                paused = next
                scope.launch { model.onSetDownloadsPaused(next) }
            },
        )
    }
}
