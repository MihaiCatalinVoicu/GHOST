package org.ghost.ui.feature.channel

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import org.ghost.ui.R
import org.ghost.ui.design.HoldToConfirm
import org.ghost.ui.gateway.ChannelFingerprintView
import org.ghost.ui.gateway.ChannelMemberView

/** The local MLS roster: pseudonym fingerprint, role and the two explicit moderation actions. */
@Composable
fun MembersScreen(
    members: List<ChannelMemberView>,
    fingerprint: ChannelFingerprintView?,
    onRemove: (String) -> Unit,
    onReveal: (String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    resultMessage: String? = null,
) {
    Column(
        modifier = modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = stringResource(R.string.ch_members_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        if (fingerprint != null) {
            Text(
                text = stringResource(R.string.ch_fingerprint, fingerprint.epoch, fingerprint.code),
                style = MaterialTheme.typography.bodyMedium,
            )
            Text(text = stringResource(R.string.ch_fingerprint_body), style = MaterialTheme.typography.bodySmall)
        }
        if (members.isEmpty()) Text(text = stringResource(R.string.ch_members_empty), style = MaterialTheme.typography.bodyLarge)
        members.forEach { member ->
            Column(modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
                Text(text = member.id.chunked(16).joinToString(" "), style = MaterialTheme.typography.bodySmall)
                Text(
                    text = stringResource(if (member.committer) R.string.ch_member_committer else R.string.ch_member_member),
                    style = MaterialTheme.typography.labelLarge,
                )
                if (!member.mine) {
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = { onReveal(member.id) }) { Text(text = stringResource(R.string.ch_member_reveal)) }
                        OutlinedButton(onClick = { onRemove(member.id) }) { Text(text = stringResource(R.string.ch_member_remove)) }
                    }
                }
            }
        }
        if (!resultMessage.isNullOrEmpty()) Text(text = resultMessage, style = MaterialTheme.typography.bodyLarge)
        OutlinedButton(onClick = onBack) { Text(text = stringResource(R.string.payment_back)) }
    }
}

/** Reveal starts only after the user confirms an out-of-band, same-epoch fingerprint match. */
@Composable
fun RevealScreen(
    memberId: String,
    fingerprint: ChannelFingerprintView?,
    resultMessage: String?,
    onReveal: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var compared by remember { mutableStateOf(false) }
    Column(
        modifier = modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text(
            text = stringResource(R.string.ch_reveal_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        Text(text = stringResource(R.string.ch_reveal_body), style = MaterialTheme.typography.bodyMedium)
        Text(text = memberId.chunked(16).joinToString(" "), style = MaterialTheme.typography.bodySmall)
        if (fingerprint != null) {
            Text(
                text = stringResource(R.string.ch_fingerprint, fingerprint.epoch, fingerprint.code),
                style = MaterialTheme.typography.bodyMedium,
            )
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = compared, onCheckedChange = { compared = it })
            Text(text = stringResource(R.string.ch_reveal_compared), style = MaterialTheme.typography.bodyMedium)
        }
        if (compared && fingerprint != null) {
            HoldToConfirm(
                onConfirmed = onReveal,
                holdLabelId = R.string.ch_reveal_hold,
                alternativeLabelId = R.string.confirm_alternative,
            )
        }
        if (!resultMessage.isNullOrEmpty()) Text(text = resultMessage, style = MaterialTheme.typography.bodyLarge)
        OutlinedButton(onClick = onBack) { Text(text = stringResource(R.string.payment_back)) }
    }
}
