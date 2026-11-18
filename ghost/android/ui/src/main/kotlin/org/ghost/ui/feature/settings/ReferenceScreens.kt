package org.ghost.ui.feature.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
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

/** Static help and limits copy stays local; addresses and external resources are never auto-opened. */
@Composable
fun TextPageScreen(
    titleId: Int,
    bodyIds: List<Int>,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            text = stringResource(titleId),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        bodyIds.forEach { id -> Text(text = stringResource(id), style = MaterialTheme.typography.bodyLarge) }
        OutlinedButton(onClick = onBack) { Text(text = stringResource(R.string.payment_back)) }
    }
}

/** The packaged third-party notices, including the MPL source offer, with no network rendering. */
@Composable
fun LicencesScreen(
    notices: String,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            text = stringResource(R.string.about_licences),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        Text(text = notices, style = MaterialTheme.typography.bodyMedium)
        OutlinedButton(onClick = onBack) { Text(text = stringResource(R.string.payment_back)) }
    }
}
