package org.ghost.ui.feature.access

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
import org.ghost.ui.gateway.InviteView
import org.ghost.ui.protect.GhostTextField
import org.ghost.ui.protect.SensitiveText
import org.ghost.ui.protect.SensitiveTextView
import org.ghost.ui.qr.QrImage

/** Invite creation and revocation; a newly created link is sensitive and shown as QR once. */
@Composable
fun InvitesScreen(
    invites: List<InviteView>,
    created: SensitiveText?,
    resultMessage: String?,
    onCreate: () -> Unit,
    onRevoke: (Int) -> Unit,
    onCopy: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = stringResource(R.string.access_invites_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        Button(onClick = onCreate) { Text(text = stringResource(R.string.access_invite_create)) }
        if (created != null) {
            QrImage(payload = created)
            SensitiveTextView(text = created, style = MaterialTheme.typography.bodyMedium)
            Text(text = stringResource(R.string.access_invite_warning), style = MaterialTheme.typography.bodyMedium)
            OutlinedButton(onClick = onCopy) { Text(text = stringResource(R.string.access_invite_copy)) }
        }
        invites.forEach { invite ->
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(
                    text = stringResource(R.string.access_invite_row, invite.index, invite.expiryDay ?: 0, invite.state),
                    style = MaterialTheme.typography.bodyMedium,
                )
                OutlinedButton(onClick = { onRevoke(invite.index) }) { Text(text = stringResource(R.string.access_invite_revoke)) }
            }
        }
        if (!resultMessage.isNullOrEmpty()) Text(text = resultMessage, style = MaterialTheme.typography.bodyLarge)
        OutlinedButton(onClick = onBack) { Text(text = stringResource(R.string.payment_back)) }
    }
}

/** Referral payout to a fresh wallet subaddress, with the engine's local validation as the gate. */
@Composable
fun PayoutScreen(
    resultMessage: String?,
    onClaim: (String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val address = remember { TextFieldState() }
    Column(
        modifier = modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text(
            text = stringResource(R.string.access_payout_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        Text(text = stringResource(R.string.access_payout_body), style = MaterialTheme.typography.bodyMedium)
        GhostTextField(state = address, modifier = Modifier.fillMaxWidth())
        Button(onClick = { onClaim(address.text.toString().trim()) }, enabled = address.text.isNotBlank()) {
            Text(text = stringResource(R.string.access_payout_claim))
        }
        if (!resultMessage.isNullOrEmpty()) Text(text = resultMessage, style = MaterialTheme.typography.bodyLarge)
        OutlinedButton(onClick = onBack) { Text(text = stringResource(R.string.payment_back)) }
    }
}
