package org.ghost.ui.feature.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import org.ghost.ui.R
import org.ghost.ui.design.HoldToConfirm

/**
 * Phase 13 design §5.5 (W1): the wipe confirmation — the user reads what a wipe does and does
 * not do (DC-5, both halves: what leaves, what stays with others, relay copies until TTL, tokens
 * and credits lost, identity recoverable only from the 24 words, and the storage/Keystore
 * finality), re-enters the PIN, and confirms with [HoldToConfirm] or its accessible alternative.
 */
@Composable
fun WipeScreen(
    onConfirmed: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text(
            text = stringResource(R.string.wipe_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        Text(text = stringResource(R.string.wipe_body_what), style = MaterialTheme.typography.bodyMedium)
        Text(text = stringResource(R.string.wipe_body_how), style = MaterialTheme.typography.bodyMedium)
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = stringResource(R.string.wipe_reenter_pin),
            style = MaterialTheme.typography.bodyLarge,
        )
        HoldToConfirm(
            onConfirmed = onConfirmed,
            holdLabelId = R.string.wipe_confirm_hold,
            alternativeLabelId = R.string.confirm_alternative,
        )
    }
}

/**
 * §5.4's full screen: the Keystore no longer opens the data. "Try again" re-attempts an open;
 * "Delete and restore" runs the wipe and then the restore journey.
 */
@Composable
fun KeystoreLostScreen(
    onRetry: () -> Unit,
    onWipeAndRestore: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text(
            text = stringResource(R.string.keystore_lost_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        Text(text = stringResource(R.string.keystore_lost_body), style = MaterialTheme.typography.bodyMedium)
        Button(onClick = onRetry) {
            Text(text = stringResource(R.string.keystore_lost_retry))
        }
        Button(onClick = onWipeAndRestore) {
            Text(text = stringResource(R.string.keystore_lost_wipe))
        }
    }
}
