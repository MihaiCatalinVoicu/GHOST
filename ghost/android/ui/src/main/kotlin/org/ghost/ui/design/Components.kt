package org.ghost.ui.design

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import org.ghost.ui.R

/**
 * Phase 13 design §9.1, §6.1: the shared components. `StatePanel` renders the seven states every
 * list and detail screen has (empty, loading, ready, offline, degraded, locked, unavailable) —
 * "wiped" is not a screen state but a fresh onboarding. The panel carries content-free copy ids
 * only; the caller renders the ready state itself.
 */
enum class PanelState { EMPTY, LOADING, READY, OFFLINE, DEGRADED, LOCKED, UNAVAILABLE }

@Composable
fun StatePanel(state: PanelState, modifier: Modifier = Modifier, ready: @Composable () -> Unit = {}) {
    when (state) {
        PanelState.READY -> ready()
        PanelState.LOADING -> Column(
            modifier.fillMaxSize(),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) { CircularProgressIndicator() }
        else -> {
            val copyId = when (state) {
                PanelState.EMPTY -> R.string.state_empty
                PanelState.OFFLINE -> R.string.state_offline
                PanelState.DEGRADED -> R.string.state_degraded
                PanelState.LOCKED -> R.string.state_locked
                PanelState.UNAVAILABLE -> R.string.state_unavailable
                else -> R.string.state_empty
            }
            Column(
                modifier.fillMaxSize().padding(24.dp),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text(
                    text = stringResource(copyId),
                    style = MaterialTheme.typography.bodyLarge,
                )
            }
        }
    }
}

/** A priority banner of §6.1 — constant copy by id, an optional bound, no computed content. */
@Composable
fun Banner(copyId: Int, bound: String?, modifier: Modifier = Modifier, onOpen: (() -> Unit)? = null) {
    Surface(
        modifier = modifier.fillMaxWidth(),
        color = MaterialTheme.colorScheme.secondaryContainer,
        tonalElevation = 1.dp,
    ) {
        Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 10.dp)) {
            Text(
                text = stringResource(copyId) + if (bound != null) " · $bound" else "",
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.semantics { heading() },
            )
            if (onOpen != null) {
                TextButton(onClick = onOpen, labelId = R.string.banner_open)
            }
        }
    }
}

/** The one text button of the design system — labels are always resources (G-U12). */
@Composable
fun TextButton(onClick: () -> Unit, labelId: Int, modifier: Modifier = Modifier) {
    Button(
        onClick = onClick,
        modifier = modifier.heightIn(min = 48.dp),
        colors = ButtonDefaults.textButtonColors(),
    ) {
        Text(text = stringResource(labelId))
    }
}
