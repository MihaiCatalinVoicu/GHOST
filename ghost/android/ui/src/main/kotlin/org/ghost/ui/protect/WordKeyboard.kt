package org.ghost.ui.protect

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import org.ghost.ui.R
import androidx.compose.ui.semantics.isSensitiveData
import androidx.compose.ui.semantics.semantics

/**
 * Phase 13 design §4.5: the word keyboard for the 24 words at restore and backup verification
 * and for channel passphrases. 26 letter keys, delete, and suggestion chips from the BIP-39 list
 * (the gateway supplies the list — :ui holds no copy of its own, §3.2). A word completes as soon
 * as the typed prefix matches exactly one list word (four letters always suffice in the BIP-39
 * English list); a three-letter word that begins longer ones (such as "act") is picked from its
 * chip. The chosen word is always the list's constant — the keyboard never accepts free text.
 *
 * No IME, no paste, no autofill (Q15). Ordinary Compose buttons, readable by TalkBack.
 */
@Composable
fun WordKeyboard(
    suggestions: List<String>,
    onLetter: (Char) -> Unit,
    onDelete: () -> Unit,
    onPick: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    val rows = listOf(
        "qwertyuiop".toList(),
        "asdfghjkl".toList(),
        "zxcvbnm".toList(),
    )
    Column(modifier = modifier.fillMaxWidth(), verticalArrangement = Arrangement.SpaceEvenly) {
        for (suggestion in suggestions.take(MAX_CHIPS)) {
            Button(onClick = { onPick(suggestion) }, modifier = Modifier.fillMaxWidth()) {
                Text(text = suggestion, style = MaterialTheme.typography.titleMedium)
            }
        }
        for (row in rows) {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
                for (letter in row) {
                    Button(
                        onClick = { onLetter(letter) },
                        modifier = Modifier.semantics { isSensitiveData = true },
                    ) {
                        Text(text = letter.toString(), style = MaterialTheme.typography.titleLarge)
                    }
                }
            }
        }
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) {
            Button(onClick = onDelete) {
                Text(
                    text = stringResource(R.string.keypad_delete),
                    style = MaterialTheme.typography.titleLarge,
                )
            }
        }
    }
}

/** How many suggestion chips show at most. */
const val MAX_CHIPS: Int = 4
