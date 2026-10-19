package org.ghost.ui.feature.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
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
 * Phase 13 design §6.8 (Despre): the version, the entries into the reference pages, the
 * security contact as plain text, and the `ghost-verify` sentence (§6.7). The ADR-38 residue
 * sentence appears only beside an allowed claim (DC-25) — none is allowed yet, so it is absent.
 * The build-stage sentence (DC-27) states what this stage is and what it lacks. [version] and
 * [securityContact] arrive from :app (BuildConfig and the owner's OA-6 value); an empty contact
 * hides the row rather than showing a placeholder — no invented address.
 */
@Composable
fun AboutScreen(
    version: String,
    securityContact: String,
    onWhoSeesWhat: () -> Unit,
    onLimits: () -> Unit,
    onLicences: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = stringResource(R.string.about_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        Text(
            text = stringResource(R.string.about_version_label) + " " + version,
            style = MaterialTheme.typography.bodyLarge,
        )
        Text(text = stringResource(R.string.about_stage), style = MaterialTheme.typography.bodyMedium)
        SectionRow(R.string.who_title) { onWhoSeesWhat() }
        SectionRow(R.string.about_limits) { onLimits() }
        SectionRow(R.string.about_licences) { onLicences() }
        Text(text = stringResource(R.string.about_verify), style = MaterialTheme.typography.bodyMedium)
        if (securityContact.isNotEmpty()) {
            Text(
                text = stringResource(R.string.about_contact_label) + " " + securityContact,
                style = MaterialTheme.typography.bodyMedium,
            )
        }
    }
}
