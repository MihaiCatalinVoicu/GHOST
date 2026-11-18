package org.ghost.ui.feature.dm

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import org.ghost.ui.R
import org.ghost.ui.design.HoldToConfirm
import org.ghost.ui.protect.GhostTextField

/** Contact management; destructive actions and session reset are explicit user intents. */
@Composable
fun ContactInfoScreen(
    contactId: String,
    name: String?,
    trust: String?,
    resultMessage: String?,
    onRename: (String) -> Unit,
    onBlock: () -> Unit,
    onUnblock: () -> Unit,
    onReset: () -> Unit,
    onDelete: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val alias = remember(contactId, name) { TextFieldState(name ?: "") }
    Column(
        modifier = modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = stringResource(R.string.contact_info_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        Text(text = stringResource(contactTrustLabel(trust)), style = MaterialTheme.typography.titleMedium)
        GhostTextField(state = alias, modifier = Modifier.fillMaxWidth())
        Button(onClick = { onRename(alias.text.toString().trim()) }, enabled = alias.text.isNotBlank()) {
            Text(text = stringResource(R.string.contact_rename))
        }
        if (trust == "BLOCKED") {
            OutlinedButton(onClick = onUnblock) { Text(text = stringResource(R.string.contact_unblock)) }
        } else {
            OutlinedButton(onClick = onBlock) { Text(text = stringResource(R.string.contact_block)) }
        }
        Text(text = stringResource(R.string.contact_block_body), style = MaterialTheme.typography.bodySmall)
        OutlinedButton(onClick = onReset) { Text(text = stringResource(R.string.contact_reset)) }
        Text(text = stringResource(R.string.contact_reset_body), style = MaterialTheme.typography.bodySmall)
        HoldToConfirm(
            onConfirmed = onDelete,
            holdLabelId = R.string.contact_delete_hold,
            alternativeLabelId = R.string.confirm_alternative,
        )
        if (!resultMessage.isNullOrEmpty()) Text(text = resultMessage, style = MaterialTheme.typography.bodyLarge)
        OutlinedButton(onClick = onBack) { Text(text = stringResource(R.string.payment_back)) }
    }
}

private fun contactTrustLabel(trust: String?): Int = when (trust) {
    "VERIFIED" -> R.string.contact_trust_verified
    "UNVERIFIED" -> R.string.contact_trust_unverified
    "CHANGED" -> R.string.contact_trust_changed
    "BLOCKED" -> R.string.contact_trust_blocked
    "REVOKED" -> R.string.contact_trust_revoked
    else -> R.string.contact_trust_request
}
