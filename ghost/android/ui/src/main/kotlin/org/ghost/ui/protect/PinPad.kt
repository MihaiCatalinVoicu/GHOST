package org.ghost.ui.protect

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.isSensitiveData
import androidx.compose.ui.semantics.semantics

/**
 * Phase 13 design §4.5: the digit keypad for the app PIN. No IME, no paste, no autofill: digits
 * are tapped, held in a [CharArray] owned by the caller, and zeroed after the check (the caller
 * runs `Arrays.fill(digits, '0')` — the keypad never copies the array). Keys are ordinary
 * Compose buttons, readable by TalkBack and usable by Switch Access; each key is marked
 * sensitive (§4.3: a non-tool service sees a key press only if the user opted into showing
 * keypads to services).
 *
 * [onKey] receives one character: a digit, [DELETE] (⌫) or [CONFIRM] (✓). The two special
 * keys' labels come from the caller as string resources (G-U12: no literal user-visible string
 * in composables).
 */
@Composable
fun PinPad(
    onKey: (Char) -> Unit,
    deleteLabel: String,
    confirmLabel: String,
    modifier: Modifier = Modifier,
) {
    val rows = listOf(
        listOf('1', '2', '3'),
        listOf('4', '5', '6'),
        listOf('7', '8', '9'),
        listOf(DELETE, '0', CONFIRM),
    )
    Column(modifier = modifier.fillMaxWidth(), verticalArrangement = Arrangement.SpaceEvenly) {
        for (row in rows) {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
                for (key in row) {
                    Button(
                        onClick = { onKey(key) },
                        modifier = Modifier
                            .weight(1f)
                            .aspectRatio(1.6f)
                            .semantics { isSensitiveData = true },
                    ) {
                        Text(
                            text = if (key == DELETE) deleteLabel else if (key == CONFIRM) confirmLabel else key.toString(),
                            style = MaterialTheme.typography.titleLarge,
                        )
                    }
                }
            }
        }
    }
}

/** The delete key's [onKey] character (a private-use code point: never rendered, only signalled). */
const val DELETE: Char = '\uE001'

/** The confirm key's [onKey] character (a private-use code point: never rendered, only signalled). */
const val CONFIRM: Char = '\uE002'
