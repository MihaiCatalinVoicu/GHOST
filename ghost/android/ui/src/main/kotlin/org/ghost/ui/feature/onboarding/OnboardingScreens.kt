package org.ghost.ui.feature.onboarding

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import org.ghost.ui.R
import org.ghost.ui.gateway.PrivacyMode

/**
 * Phase 13 design §6.2 (J1): the onboarding screens of the D36 order. Each screen is content-free
 * over the model: copy comes from resources (G-U12), the three mandatory disclosure cards of
 * step 11 (DC-1 … DC-3, DC-27's stage label, DC-29's lock wording) are the welcome's and the
 * lock step's own strings.
 */
@Composable
fun WelcomeScreen(
    onInvite: () -> Unit,
    onRestore: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text(
            text = stringResource(R.string.onboarding_welcome_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        Text(text = stringResource(R.string.onboarding_welcome_stage), style = MaterialTheme.typography.labelLarge)
        Spacer(modifier = Modifier.height(8.dp))
        // The three mandatory disclosure cards (§8.1's first layer), each constant copy.
        Text(text = stringResource(R.string.onboarding_dc1), style = MaterialTheme.typography.bodyMedium)
        Text(text = stringResource(R.string.onboarding_dc2), style = MaterialTheme.typography.bodyMedium)
        Text(text = stringResource(R.string.onboarding_dc3), style = MaterialTheme.typography.bodyMedium)
        Spacer(modifier = Modifier.height(16.dp))
        Button(onClick = onInvite, modifier = Modifier.semantics { heading() }) {
            Text(text = stringResource(R.string.onboarding_welcome_invite))
        }
        Button(onClick = onRestore) {
            Text(text = stringResource(R.string.onboarding_welcome_restore))
        }
    }
}

/** The privacy-mode step (§6.2 step 4, D36): the choice precedes the invite and the words. */
@Composable
fun PrivacyChoiceScreen(
    onChoose: (PrivacyMode) -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text(
            text = stringResource(R.string.onboarding_privacy_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        Text(text = stringResource(R.string.onboarding_privacy_body), style = MaterialTheme.typography.bodyMedium)
        Button(onClick = { onChoose(PrivacyMode.STANDARD) }) {
            Text(text = stringResource(R.string.onboarding_privacy_standard))
        }
        Button(onClick = { onChoose(PrivacyMode.HIGH) }) {
            Text(text = stringResource(R.string.onboarding_privacy_high))
        }
    }
}

/**
 * The notification step (§4.6): shown BEFORE the system permission request, saying exactly what
 * the notification will be — one constant message, no text, no count, hidden on the lock screen,
 * and who sees it appear (DC-19). Refusal is respected and lands in Settings.
 */
@Composable
fun NotificationPermissionScreen(
    onAllow: () -> Unit,
    onSkip: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text(
            text = stringResource(R.string.onboarding_notifications_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        Text(text = stringResource(R.string.onboarding_notifications_body), style = MaterialTheme.typography.bodyMedium)
        Button(onClick = onAllow) {
            Text(text = stringResource(R.string.onboarding_notifications_allow))
        }
        Button(onClick = onSkip) {
            Text(text = stringResource(R.string.onboarding_notifications_skip))
        }
    }
}
