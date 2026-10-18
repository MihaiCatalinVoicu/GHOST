package org.ghost.ui.feature.access

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import org.ghost.ui.R
import org.ghost.ui.gateway.PaymentView
import org.ghost.ui.protect.SensitiveTextView

/**
 * Phase 13 design §6.3 (J2), §3.5 (D35): the payment instructions screen — reachable only for a
 * READY or UNDERPAID purchase (the [PaymentModel] gates it; the route adds nothing). The
 * just-in-time disclosures (§8.1's second layer): DC-6 (an exchange with checks links you; the
 * network sees the moment and the fingerprint; prefer your own wallet over Tor), DC-7…DC-10
 * (no refund, the exact amount, no lock time, the 24 h / 72 h windows, another device or later),
 * DC-23 (sync stops while open and 20–60 min after), DC-32 (compare the first and last six
 * characters after pasting).
 *
 * Q46: there is NO "open in wallet" button — the screen shows the address and the amount for
 * the user's own wallet flow, as QR and sensitive text only.
 */
@Composable
fun PaymentInstructionsScreen(
    payment: PaymentView,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(
            text = stringResource(R.string.payment_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        Text(text = stringResource(R.string.payment_disclosures), style = MaterialTheme.typography.bodyMedium)
        Text(text = stringResource(R.string.payment_no_refund), style = MaterialTheme.typography.bodyMedium)
        Text(text = stringResource(R.string.payment_no_locktime), style = MaterialTheme.typography.bodyMedium)
        Text(text = stringResource(R.string.payment_windows), style = MaterialTheme.typography.bodyMedium)
        Text(text = stringResource(R.string.payment_sync_hold), style = MaterialTheme.typography.bodyMedium)
        Spacer(modifier = Modifier.height(8.dp))
        Text(text = stringResource(R.string.payment_subaddress_label), style = MaterialTheme.typography.labelLarge)
        SensitiveTextView(text = payment.subaddress, style = MaterialTheme.typography.bodyLarge)
        Text(text = stringResource(R.string.payment_amount_label), style = MaterialTheme.typography.labelLarge)
        SensitiveTextView(text = payment.amount, style = MaterialTheme.typography.bodyLarge)
        Text(
            text = stringResource(R.string.payment_deadline_label),
            style = MaterialTheme.typography.labelLarge,
        )
        Text(text = payment.deadlineDay.toString(), style = MaterialTheme.typography.bodyLarge)
        Text(text = stringResource(R.string.payment_compare), style = MaterialTheme.typography.bodyMedium)
    }
}

/** The session's end state (R-U10): sent, and what the user should expect, comprehension only. */
@Composable
fun PaymentSentScreen(modifier: Modifier = Modifier) {
    Column(modifier = modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text(
            text = stringResource(R.string.payment_sent),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        Text(text = stringResource(R.string.payment_sent_body), style = MaterialTheme.typography.bodyMedium)
    }
}
