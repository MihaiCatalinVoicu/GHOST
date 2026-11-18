package org.ghost.ui.feature.settings

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.ghost.ui.R
import org.ghost.ui.feature.media.DownloadPauseRow
import org.ghost.ui.feature.media.MediaDownloadsModel
import org.ghost.ui.gateway.PrivacyMode

/**
 * Phase 13 design §6.8: the settings screens. The hub lists the sections; the privacy page holds
 * the §7.1 mode choice with DC-22's approved sentence (the only place the modes' behavior is
 * described — no invented promises), the notification and service-visibility switches, and S6's
 * download-pause row; the security page holds the lock timeout (Q5's four values), the biometric
 * convenience and the change-PIN entry. The "who can read the screen", keyboard, recovery words
 * and diagnostic rows land with their own slices — the pages are built so a row is a Row.
 */
@Composable
fun SettingsScreen(
    onPrivacy: () -> Unit,
    onSecurity: () -> Unit,
    onAbout: () -> Unit,
    onHelp: () -> Unit,
    onWipe: () -> Unit,
    modifier: Modifier = Modifier,
    onAccess: (() -> Unit)? = null,
    onUpdate: (() -> Unit)? = null,
) {
    Column(modifier = modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(
            text = stringResource(R.string.settings_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        if (onAccess != null) SectionRow(R.string.access_title) { onAccess() }
        SectionRow(R.string.settings_privacy) { onPrivacy() }
        SectionRow(R.string.settings_security) { onSecurity() }
        SectionRow(R.string.settings_about) { onAbout() }
        if (onUpdate != null) SectionRow(R.string.settings_update) { onUpdate() }
        SectionRow(R.string.settings_help) { onHelp() }
        SectionRow(R.string.settings_wipe) { onWipe() }
    }
}

/** One settings entry: a label row that navigates. */
@Composable
fun SectionRow(labelId: Int, modifier: Modifier = Modifier, onClick: () -> Unit) {
    Row(
        modifier = modifier.fillMaxWidth().clickable(onClick = onClick).padding(vertical = 16.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(text = stringResource(labelId), style = MaterialTheme.typography.titleMedium)
    }
}

/** A label plus a switch that forwards to [onSet]. */
@Composable
fun SwitchRow(labelId: Int, checked: Boolean, modifier: Modifier = Modifier, onSet: (Boolean) -> Unit) {
    Row(
        modifier = modifier.fillMaxWidth().padding(vertical = 12.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(text = stringResource(labelId), style = MaterialTheme.typography.titleMedium)
        Switch(checked = checked, onCheckedChange = onSet)
    }
}

/** The privacy page: the §7.1 mode choice with DC-22's copy, then the three switches. */
@Composable
fun PrivacyScreen(
    model: SettingsModel,
    downloads: MediaDownloadsModel?,
    modifier: Modifier = Modifier,
) {
    val scope = rememberCoroutineScope()
    var mode by remember { mutableStateOf(model.privacyMode) }
    var notifications by remember { mutableStateOf(model.notificationsEnabled) }
    var hidden by remember { mutableStateOf(model.hideFromAllServices) }
    Column(modifier = modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            text = stringResource(R.string.privacy_mode_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        ModeChoice(R.string.privacy_mode_standard, mode == PrivacyMode.STANDARD) {
            mode = PrivacyMode.STANDARD
            scope.launch { model.onSetPrivacyMode(PrivacyMode.STANDARD) }
        }
        ModeChoice(R.string.privacy_mode_high, mode == PrivacyMode.HIGH) {
            mode = PrivacyMode.HIGH
            scope.launch { model.onSetPrivacyMode(PrivacyMode.HIGH) }
        }
        if (mode == PrivacyMode.HIGH) {
            // §7.1's DC-22 sentence: the only behavior description the UI gives.
            Text(text = stringResource(R.string.privacy_mode_high_body), style = MaterialTheme.typography.bodyMedium)
        }
        SwitchRow(R.string.privacy_notifications, notifications) { next ->
            notifications = next
            scope.launch { model.onSetNotificationsEnabled(next) }
        }
        SwitchRow(R.string.privacy_hide_services, hidden) { next ->
            hidden = next
            scope.launch { model.onSetHideFromAllServices(next) }
        }
        if (downloads != null) DownloadPauseRow(model = downloads)
    }
}

/** One mode radio with its label. */
@Composable
fun ModeChoice(labelId: Int, selected: Boolean, modifier: Modifier = Modifier, onClick: () -> Unit) {
    Row(
        modifier = modifier.fillMaxWidth().clickable(onClick = onClick).padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RadioButton(selected = selected, onClick = onClick)
        Text(text = stringResource(labelId), style = MaterialTheme.typography.titleMedium)
    }
}

/** The security page: the lock timeout, the biometric convenience, the change-PIN entry. */
@Composable
fun SecurityScreen(
    model: SecurityModel,
    onChangePin: () -> Unit,
    modifier: Modifier = Modifier,
    onBackup: (() -> Unit)? = null,
    onAccessibility: (() -> Unit)? = null,
    onDiagnostic: (() -> Unit)? = null,
) {
    val scope = rememberCoroutineScope()
    var timeout by remember { mutableStateOf(model.timeoutSeconds) }
    var biometric by remember { mutableStateOf(model.biometricEnabled) }
    Column(modifier = modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            text = stringResource(R.string.security_lock_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        Text(text = stringResource(R.string.security_timeout), style = MaterialTheme.typography.labelLarge)
        TimeoutChoice(R.string.security_timeout_immediate, 0, timeout) { timeout = 0; scope.launch { model.onSetTimeoutSeconds(0) } }
        TimeoutChoice(R.string.security_timeout_1m, 60, timeout) { timeout = 60; scope.launch { model.onSetTimeoutSeconds(60) } }
        TimeoutChoice(R.string.security_timeout_5m, 300, timeout) { timeout = 300; scope.launch { model.onSetTimeoutSeconds(300) } }
        TimeoutChoice(R.string.security_timeout_30m, 1800, timeout) { timeout = 1800; scope.launch { model.onSetTimeoutSeconds(1800) } }
        SwitchRow(R.string.security_biometric, biometric) { next ->
            biometric = next
            scope.launch { model.onSetBiometricEnabled(next) }
        }
        SectionRow(R.string.security_change_pin) { onChangePin() }
        if (onBackup != null) SectionRow(R.string.security_backup) { onBackup() }
        if (onAccessibility != null) SectionRow(R.string.security_accessibility) { onAccessibility() }
        if (onDiagnostic != null) SectionRow(R.string.security_diagnostic) { onDiagnostic() }
    }
}

/** One timeout radio. */
@Composable
fun TimeoutChoice(labelId: Int, seconds: Long, current: Long, modifier: Modifier = Modifier, onClick: () -> Unit) {
    Row(
        modifier = modifier.fillMaxWidth().clickable(onClick = onClick).padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RadioButton(selected = current == seconds, onClick = onClick)
        Text(text = stringResource(labelId), style = MaterialTheme.typography.titleMedium)
    }
}
