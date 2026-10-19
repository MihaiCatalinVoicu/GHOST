package org.ghost.ui.feature.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import org.ghost.ui.R

/**
 * Phase 13 design §8.2: the "Cine vede ce" reference screen — the plan §4 matrix with the
 * additions §8.2 lists. Every cell is a constant string (G-U12); the GOAL column carries its
 * status after each goal; the Dovada cell is the em dash while no evidence is green (§8.2: the
 * column shows the register's evidence IDs and their status — empty is the status today). The
 * table's own note says where claims graduate: only through the register (§8.5).
 */
@Composable
fun WhoSeesWhatScreen(model: WhoSeesWhatModel, modifier: Modifier = Modifier) {
    LazyColumn(modifier = modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        item {
            Text(
                text = stringResource(R.string.who_title),
                style = MaterialTheme.typography.headlineSmall,
                modifier = Modifier.semantics { heading() },
            )
            Text(text = stringResource(R.string.who_note), style = MaterialTheme.typography.bodyMedium)
        }
        items(model.rows) { row ->
            Column(modifier = Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(text = stringResource(row.actor), style = MaterialTheme.typography.titleMedium)
                Text(
                    text = stringResource(R.string.who_sees_header) + " " + stringResource(row.sees),
                    style = MaterialTheme.typography.bodyMedium,
                )
                Text(
                    text = stringResource(R.string.who_goal_header) + " " + stringResource(row.goal) +
                        " (" + stringResource(model.goalStatus) + ")",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Text(
                    text = stringResource(R.string.who_proof_header) + " " + stringResource(R.string.who_proof_empty),
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
    }
}
