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
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import org.ghost.ui.R
import org.ghost.ui.design.TextButton
import org.ghost.ui.gateway.RequestView
import org.ghost.ui.gateway.SafetyNumberData
import org.ghost.ui.protect.GhostTextField
import org.ghost.ui.qr.QrImage

/** Contact requests: accept, reject silently, or block; the requester receives no decision signal. */
@Composable
fun RequestsScreen(
    requests: List<RequestView>,
    names: Map<String, String>,
    onAccept: (String) -> Unit,
    onReject: (String) -> Unit,
    onBlock: (String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.fillMaxSize().padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(
            text = stringResource(R.string.dm_requests_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        Text(text = stringResource(R.string.dm_requests_body), style = MaterialTheme.typography.bodyMedium)
        if (requests.isEmpty()) {
            Text(text = stringResource(R.string.dm_requests_empty), style = MaterialTheme.typography.bodyLarge)
        }
        requests.forEach { request ->
            Surface(modifier = Modifier.fillMaxWidth(), tonalElevation = 1.dp, shape = MaterialTheme.shapes.large) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = names[request.contactId] ?: stringResource(R.string.dm_contact_unnamed),
                        style = MaterialTheme.typography.titleMedium,
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(onClick = { onAccept(request.contactId) }) { Text(text = stringResource(R.string.dm_request_accept)) }
                        OutlinedButton(onClick = { onReject(request.contactId) }) { Text(text = stringResource(R.string.dm_request_reject)) }
                    }
                    TextButton(onClick = { onBlock(request.contactId) }, labelId = R.string.dm_request_block)
                }
            }
        }
        OutlinedButton(onClick = onBack) { Text(text = stringResource(R.string.payment_back)) }
    }
}

/** Safety number / pending key change: the same 60 digits and a versioned, locally generated QR. */
@Composable
fun SafetyNumberScreen(
    data: SafetyNumberData?,
    pending: Boolean,
    resultMessage: String?,
    onVerify: (String) -> Unit,
    onVerifyManually: () -> Unit,
    onAcknowledge: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val scanned = remember { TextFieldState() }
    Column(
        modifier = modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text(
            text = stringResource(if (pending) R.string.dm_key_change_title else R.string.dm_safety_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        Text(
            text = stringResource(if (pending) R.string.dm_key_change_body else R.string.dm_safety_body),
            style = MaterialTheme.typography.bodyMedium,
        )
        if (data == null) {
            Text(text = stringResource(R.string.dm_safety_unavailable), style = MaterialTheme.typography.bodyLarge)
        } else {
            QrImage(payload = data.qrPayload)
            val groups = data.digits.chunked(5).chunked(5) { it.joinToString(" ") }.joinToString("\n")
            Text(text = groups, style = MaterialTheme.typography.titleMedium)
            Text(text = stringResource(R.string.dm_safety_scan_hint), style = MaterialTheme.typography.bodySmall)
            GhostTextField(state = scanned, modifier = Modifier.fillMaxWidth())
            Button(onClick = { onVerify(scanned.text.toString()) }, enabled = scanned.text.isNotBlank()) {
                Text(text = stringResource(R.string.dm_safety_verify_scan))
            }
            if (!pending) {
                OutlinedButton(onClick = onVerifyManually) {
                    Text(text = stringResource(R.string.dm_safety_verify_manual))
                }
            }
        }
        if (pending) {
            Text(text = stringResource(R.string.dm_key_change_unverified), style = MaterialTheme.typography.bodyMedium)
            OutlinedButton(onClick = onAcknowledge) { Text(text = stringResource(R.string.dm_key_change_accept)) }
        }
        if (!resultMessage.isNullOrEmpty()) {
            Text(text = resultMessage, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.primary)
        }
        OutlinedButton(onClick = onBack) { Text(text = stringResource(R.string.payment_back)) }
    }
}
