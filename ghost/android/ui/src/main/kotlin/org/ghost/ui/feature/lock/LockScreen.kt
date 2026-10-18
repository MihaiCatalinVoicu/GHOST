package org.ghost.ui.feature.lock

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import org.ghost.ui.R
import org.ghost.ui.protect.PinPad

/**
 * Phase 13 design §5.1, §6.9: the lock screen over the curtain. The PIN is typed on [PinPad] —
 * no IME, no paste, no autofill (Q15) —; a back-off counts down in whole seconds and the pad is
 * inert until it ends (the verifier's order, MC-U14/MC-U15, is the controller's); a biometric
 * success arrives through [onBiometric] where the user enabled it (§5.1's convenience, with
 * DC-29's wording in Settings, not here).
 *
 * This screen shows no content: what it protects is already dropped (§3.3). The dots row is
 * rendered by the caller so the state holder decides what a typed digit shows.
 */
@Composable
fun LockScreen(
    lockedMessageId: Int?,
    failures: Int,
    onPinDigit: (Char) -> Unit,
    onBiometric: (() -> Unit)?,
    modifier: Modifier = Modifier,
) {
    var dots by remember { mutableIntStateOf(0) }
    Column(
        modifier = modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            text = stringResource(R.string.lock_title),
            style = MaterialTheme.typography.headlineSmall,
        )
        Spacer(modifier = Modifier.height(16.dp))
        if (lockedMessageId != null) {
            Text(
                text = stringResource(lockedMessageId),
                style = MaterialTheme.typography.bodyMedium,
            )
            Spacer(modifier = Modifier.height(16.dp))
        }
        if (failures > 0 && lockedMessageId == null) {
            Text(
                text = pluralStringResource(R.plurals.lock_failures, failures, failures),
                style = MaterialTheme.typography.bodyMedium,
            )
            Spacer(modifier = Modifier.height(16.dp))
        }
        Text(
            // The dot row: only a count, never the digits.
            text = "•".repeat(dots),
            style = MaterialTheme.typography.titleLarge,
        )
        Spacer(modifier = Modifier.height(24.dp))
        PinPad(
            onKey = { key ->
                when (key) {
                    org.ghost.ui.protect.DELETE -> if (dots > 0) dots--
                    org.ghost.ui.protect.CONFIRM -> dots = 0
                    else -> dots++
                }
                onPinDigit(key)
            },
            deleteLabel = stringResource(R.string.keypad_delete),
            confirmLabel = stringResource(R.string.keypad_confirm),
        )
    }
}
