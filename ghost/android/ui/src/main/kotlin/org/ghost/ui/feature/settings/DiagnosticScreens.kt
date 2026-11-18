package org.ghost.ui.feature.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
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

/** Counts and fixed stages only; the diagnostic screen never renders ids, addresses or activity times. */
@Composable
fun DiagnosticScreen(
    rows: List<Pair<Int, String>>,
    onCrashReports: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = stringResource(R.string.diagnostic_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        Text(text = stringResource(R.string.diagnostic_body), style = MaterialTheme.typography.bodyMedium)
        rows.forEach { row ->
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(text = stringResource(row.first), style = MaterialTheme.typography.bodyMedium)
                Text(text = row.second, style = MaterialTheme.typography.titleSmall)
            }
        }
        OutlinedButton(onClick = onCrashReports) { Text(text = stringResource(R.string.diagnostic_crash_reports)) }
        OutlinedButton(onClick = onBack) { Text(text = stringResource(R.string.payment_back)) }
    }
}

/** Local crash reports can be inspected and deleted; no send action exists in this build. */
@Composable
fun CrashReportsScreen(
    reports: List<String>,
    onDelete: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = stringResource(R.string.crash_reports_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        Text(text = stringResource(R.string.crash_reports_body), style = MaterialTheme.typography.bodyMedium)
        if (reports.isEmpty()) {
            Text(text = stringResource(R.string.crash_reports_empty), style = MaterialTheme.typography.bodyLarge)
        }
        reports.forEach { report -> Text(text = report, style = MaterialTheme.typography.bodySmall) }
        if (reports.isNotEmpty()) OutlinedButton(onClick = onDelete) { Text(text = stringResource(R.string.crash_reports_delete)) }
        OutlinedButton(onClick = onBack) { Text(text = stringResource(R.string.payment_back)) }
    }
}

/** The enabled accessibility services are shown locally, without changing platform settings. */
@Composable
fun AccessibilityScreen(
    services: String,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text(
            text = stringResource(R.string.accessibility_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        Text(text = stringResource(R.string.accessibility_body), style = MaterialTheme.typography.bodyMedium)
        Text(
            text = services.ifEmpty { stringResource(R.string.accessibility_none) },
            style = MaterialTheme.typography.bodyMedium,
        )
        OutlinedButton(onClick = onBack) { Text(text = stringResource(R.string.payment_back)) }
    }
}
