package org.ghost.ui.feature.restore

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.ghost.ui.R
import org.ghost.ui.gateway.RestoreResult
import org.ghost.ui.protect.GhostTextField

/**
 * Phase 13 design §5.7 (J-R): the restore journey — intro, the 24 words, the outcome. The words
 * travel as the user's own typing, one field, space separated (the word list validates them;
 * nothing is auto-completed from a copy the UI would hold, CR-15).
 */

@Composable
fun RestoreIntroScreen(
    onRead: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text(
            text = stringResource(R.string.restore_intro_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        Text(text = stringResource(R.string.restore_intro_body), style = MaterialTheme.typography.bodyMedium)
        Button(onClick = onRead) {
            Text(text = stringResource(R.string.restore_intro_continue))
        }
    }
}

@Composable
fun RestoreWordsScreen(
    onWords: suspend (List<String>) -> RestoreResult,
    onRestored: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val scope = rememberCoroutineScope()
    val state = remember { TextFieldState() }
    var failed by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    Column(
        modifier = modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = stringResource(R.string.restore_words_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        Text(text = stringResource(R.string.restore_words_body), style = MaterialTheme.typography.bodyMedium)
        GhostTextField(state = state, textStyle = TextStyle(color = MaterialTheme.colorScheme.onSurface))
        if (failed) {
            Text(text = stringResource(R.string.restore_words_failed), style = MaterialTheme.typography.bodyMedium)
        }
        Button(
            enabled = !busy,
            onClick = {
                scope.launch {
                    busy = true
                    val words = state.text.toString().trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
                    when (onWords(words)) {
                        RestoreResult.RESTORED, RestoreResult.ALREADY_ACTIVE -> onRestored()
                        else -> failed = true
                    }
                    busy = false
                }
            },
        ) {
            Text(text = stringResource(R.string.restore_words_confirm))
        }
    }
}

@Composable
fun RestoreNextScreen(
    onRead: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text(
            text = stringResource(R.string.restore_next_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        Text(text = stringResource(R.string.restore_next_body), style = MaterialTheme.typography.bodyMedium)
        Spacer(modifier = Modifier.height(8.dp))
        Button(onClick = onRead) {
            Text(text = stringResource(R.string.restore_next_done))
        }
    }
}
