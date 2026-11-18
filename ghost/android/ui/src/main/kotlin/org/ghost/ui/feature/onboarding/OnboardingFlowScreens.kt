package org.ghost.ui.feature.onboarding

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.ghost.ui.R
import org.ghost.ui.gateway.ActivateResult
import org.ghost.ui.gateway.InvitePreview
import org.ghost.ui.protect.CONFIRM
import org.ghost.ui.protect.DELETE
import org.ghost.ui.protect.GhostTextField
import org.ghost.ui.protect.PinPad

/**
 * The onboarding steps that the slice shipped as a state machine only (§6.2 steps 2, 3, 5–11):
 * the prepare step, the PIN setup, the invite, activation, the words, the backup check and the
 * closing disclosures. Each screen is content-free copy + the step's controls; the
 * [OnboardingModel] owns the order and every illegal jump throws there, not here.
 */

/** §6.2 step 2: the database key is created and the flow moves to the PIN step. */
@Composable
fun PrepareScreen(
    onContinue: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text(
            text = stringResource(R.string.onboarding_prepare_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        Text(text = stringResource(R.string.onboarding_prepare_body), style = MaterialTheme.typography.bodyMedium)
        Spacer(modifier = Modifier.height(8.dp))
        Button(onClick = onContinue) {
            Text(text = stringResource(R.string.onboarding_prepare_continue))
        }
    }
}

/**
 * §6.2 step 3: the PIN typed twice on [PinPad] (no IME, no paste, Q15). The first round arms the
 * confirmation; the second match calls [onPinSet]; a mismatch restarts the first round.
 */
@Composable
fun PinSetupScreen(
    onPinSet: suspend (CharArray) -> Boolean,
    modifier: Modifier = Modifier,
) {
    val scope = rememberCoroutineScope()
    var first by remember { mutableStateOf<CharArray?>(null) }
    var digits by remember { mutableStateOf(CharArray(0)) }
    var mismatch by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    Column(modifier = modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text(
            text = stringResource(
                if (first == null) R.string.onboarding_lock_title else R.string.onboarding_lock_repeat,
            ),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        if (mismatch) {
            Text(text = stringResource(R.string.onboarding_lock_mismatch), style = MaterialTheme.typography.bodyMedium)
        }
        Text(
            text = stringResource(R.string.lock_dot).repeat(digits.size),
            style = MaterialTheme.typography.headlineMedium,
        )
        PinPad(
            onKey = { key ->
                if (busy) return@PinPad
                when (key) {
                    DELETE -> digits = digits.dropLast(1).toCharArray()
                    CONFIRM -> {
                        val current = first
                        if (current == null) {
                            first = digits.copyOf()
                            digits = CharArray(0)
                            mismatch = false
                        } else {
                            if (current.contentEquals(digits)) {
                                busy = true
                                val pin = digits.copyOf()
                                scope.launch {
                                    val ok = onPinSet(pin)
                                    pin.fill('0')
                                    if (!ok) {
                                        first = null
                                        digits = CharArray(0)
                                        mismatch = true
                                        busy = false
                                    }
                                }
                            } else {
                                first = null
                                digits = CharArray(0)
                                mismatch = true
                            }
                        }
                    }
                    else -> if (digits.size < 8) digits = digits + key
                }
            },
            deleteLabel = stringResource(R.string.pinpad_delete),
            confirmLabel = stringResource(R.string.pinpad_confirm),
            modifier = Modifier.weight(1f),
        )
    }
}

/**
 * §6.2 step 5: the invitation. The text is inspected locally on confirm-inspect, the preview is
 * shown, and the activation runs only on the explicit acceptance — never on a link alone (§3.4).
 * [onGenesis] is non-null only in builds whose policy allows the bootstrap activation (Q21).
 */
@Composable
fun InviteScreen(
    onInspect: suspend (String) -> InvitePreview,
    onConfirm: suspend (String) -> ActivateResult,
    onGenesis: (suspend () -> ActivateResult)?,
    busy: Boolean,
    modifier: Modifier = Modifier,
) {
    val scope = rememberCoroutineScope()
    val state = remember { TextFieldState() }
    var preview by remember { mutableStateOf<InvitePreview?>(null) }
    var refused by remember { mutableStateOf<String?>(null) }
    var activating by remember { mutableStateOf(false) }
    Column(
        modifier = modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = stringResource(R.string.onboarding_invite_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        Text(text = stringResource(R.string.onboarding_invite_body), style = MaterialTheme.typography.bodyMedium)
        GhostTextField(state = state, textStyle = TextStyle(color = MaterialTheme.colorScheme.onSurface))
        Button(
            enabled = !busy && !activating && state.text.isNotBlank(),
            onClick = {
                scope.launch {
                    val p = onInspect(state.text.toString())
                    preview = p
                    refused = p.refusedReason
                }
            },
        ) {
            Text(text = stringResource(R.string.onboarding_invite_inspect))
        }
        preview?.let { p ->
            Text(
                text = stringResource(R.string.onboarding_invite_preview, p.version, p.expiryDay ?: 0),
                style = MaterialTheme.typography.bodyMedium,
            )
            if (refused == null) {
                Button(
                    enabled = !busy && !activating,
                    onClick = {
                        scope.launch {
                            activating = true
                            onConfirm(state.text.toString())
                            activating = false
                        }
                    },
                ) {
                    Text(text = stringResource(R.string.onboarding_invite_activate))
                }
            } else {
                Text(text = refused ?: "", style = MaterialTheme.typography.bodyMedium)
            }
        }
        if (onGenesis != null) {
            Spacer(modifier = Modifier.height(16.dp))
            Button(
                enabled = !busy && !activating,
                onClick = {
                    scope.launch {
                        activating = true
                        onGenesis()
                        activating = false
                    }
                },
            ) {
                Text(text = stringResource(R.string.onboarding_genesis))
            }
        }
    }
}

/** Step ACTIVATING: traffic runs; nothing is asked of the user. */
@Composable
fun ActivatingScreen(modifier: Modifier = Modifier) {
    Column(
        modifier = modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        CircularProgressIndicator()
        Spacer(modifier = Modifier.height(16.dp))
        Text(text = stringResource(R.string.onboarding_activating), style = MaterialTheme.typography.bodyMedium)
    }
}

/** §6.2 step 6: the 24 words, shown once. The step exits only through [onShown]. */
@Composable
fun WordsScreen(
    words: List<String>,
    onShown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = stringResource(R.string.onboarding_words_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        Text(text = stringResource(R.string.onboarding_words_body), style = MaterialTheme.typography.bodyMedium)
        words.forEachIndexed { index, word ->
            Text(
                text = stringResource(R.string.onboarding_words_entry, index + 1, word),
                style = MaterialTheme.typography.bodyLarge,
            )
        }
        Button(onClick = onShown) {
            Text(text = stringResource(R.string.onboarding_words_done))
        }
    }
}

/** §6.2 step 7 (§5.6): the backup check — [positions] asked, [words] the full list for labels. */
@Composable
fun BackupScreen(
    positions: List<Int>,
    words: List<String>,
    onVerify: suspend (List<String>) -> Boolean,
    onDone: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val scope = rememberCoroutineScope()
    val answers = remember { positions.map { TextFieldState() }.toTypedArray() }
    var failed by remember { mutableStateOf(false) }
    Column(
        modifier = modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = stringResource(R.string.onboarding_backup_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        Text(text = stringResource(R.string.onboarding_backup_body), style = MaterialTheme.typography.bodyMedium)
        positions.forEachIndexed { i, position ->
            Text(
                text = stringResource(R.string.onboarding_backup_position, position + 1),
                style = MaterialTheme.typography.labelLarge,
            )
            GhostTextField(state = answers[i], textStyle = TextStyle(color = MaterialTheme.colorScheme.onSurface))
        }
        if (failed) {
            Text(text = stringResource(R.string.onboarding_backup_failed), style = MaterialTheme.typography.bodyMedium)
        }
        Button(
            onClick = {
                scope.launch {
                    val given = positions.mapIndexed { i, _ -> answers[i].text.toString() }
                    if (onVerify(given)) onDone() else failed = true
                }
            },
        ) {
            Text(text = stringResource(R.string.onboarding_backup_verify))
        }
    }
}

/** §6.2 step 11: the three mandatory cards, read; the exit ends the onboarding. */
@Composable
fun DisclosuresScreen(
    onRead: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            text = stringResource(R.string.onboarding_disclosures_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        Text(text = stringResource(R.string.onboarding_dc1), style = MaterialTheme.typography.bodyMedium)
        Text(text = stringResource(R.string.onboarding_dc2), style = MaterialTheme.typography.bodyMedium)
        Text(text = stringResource(R.string.onboarding_dc3), style = MaterialTheme.typography.bodyMedium)
        Button(onClick = onRead) {
            Text(text = stringResource(R.string.onboarding_disclosures_done))
        }
    }
}
