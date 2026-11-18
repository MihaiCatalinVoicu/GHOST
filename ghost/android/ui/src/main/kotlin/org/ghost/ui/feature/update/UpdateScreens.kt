package org.ghost.ui.feature.update

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import org.ghost.ui.R
import org.ghost.ui.gateway.UpdateStatusView

/** J6: the update state, explicit network actions and the platform-confirmed install. */
@Composable
fun UpdateScreen(
    status: UpdateStatusView,
    installedVersion: String,
    onCheck: () -> Unit,
    onDownload: () -> Unit,
    onInstall: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
        Text(
            text = stringResource(R.string.update_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        Text(text = installedVersion, style = MaterialTheme.typography.bodyMedium)
        Text(text = stringResource(status.copyId), style = MaterialTheme.typography.titleMedium)
        status.version?.takeIf { it.isNotEmpty() }?.let { detail ->
            Text(text = detail, style = MaterialTheme.typography.bodyLarge)
        }
        when (status.state) {
            "CONFLICT", "ROOT_CONFLICT" -> Text(
                text = stringResource(R.string.update_conflict_body),
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyMedium,
            )
            "NO_UPDATER" -> Text(text = stringResource(R.string.update_store_body), style = MaterialTheme.typography.bodyMedium)
            else -> Text(text = stringResource(R.string.update_check_body), style = MaterialTheme.typography.bodyMedium)
        }
        if (status.state != "NO_UPDATER") {
            Button(onClick = onCheck, enabled = status.state != "DOWNLOADING" && status.state != "INSTALLING") {
                Text(text = stringResource(R.string.update_check_now))
            }
        }
        if (status.state == "AVAILABLE") {
            Button(onClick = onDownload) { Text(text = stringResource(R.string.update_download)) }
        }
        if (status.state == "READY") {
            Text(text = stringResource(R.string.update_install_body), style = MaterialTheme.typography.bodyMedium)
            Button(onClick = onInstall) { Text(text = stringResource(R.string.update_install)) }
        }
        OutlinedButton(onClick = onBack) { Text(text = stringResource(R.string.payment_back)) }
    }
}

private val UpdateStatusView.copyId: Int
    get() = when (state) {
        "UP_TO_DATE" -> R.string.update_up_to_date
        "AVAILABLE" -> R.string.update_available
        "DOWNLOADING" -> R.string.update_downloading
        "READY" -> R.string.update_ready
        "INSTALLING" -> R.string.update_installing
        "INSTALLED" -> R.string.update_installed
        "STALE" -> R.string.update_stale
        "UNSUPPORTED" -> R.string.update_unsupported
        "SDK_UNSUPPORTED" -> R.string.update_sdk_unsupported
        "NO_MANIFEST" -> R.string.update_no_manifest
        "CONFLICT", "ROOT_CONFLICT" -> R.string.update_conflict
        "NO_CHANNEL" -> R.string.update_no_channel
        "NO_UPDATER" -> R.string.update_store
        else -> R.string.update_failed
    }
