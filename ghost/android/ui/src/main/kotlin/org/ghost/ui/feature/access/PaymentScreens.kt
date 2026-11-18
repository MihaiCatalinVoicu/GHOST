package org.ghost.ui.feature.access

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
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
import org.ghost.ui.gateway.PaymentDisclosure
import org.ghost.ui.gateway.PaymentView
import org.ghost.ui.protect.SensitiveTextView
import org.ghost.ui.qr.QrImage

/** J2 step 4: every disclosure has its own tick; acknowledgement stays disabled until all are read. */
@Composable
fun PaymentDisclosuresScreen(
    disclosures: Set<PaymentDisclosure>,
    onConfirm: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var checked by remember(disclosures) { mutableStateOf(emptySet<PaymentDisclosure>()) }
    Column(
        modifier = modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = stringResource(R.string.payment_disclosures_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        disclosures.forEach { disclosure ->
            Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Checkbox(
                    checked = disclosure in checked,
                    onCheckedChange = { value ->
                        checked = if (value) checked + disclosure else checked - disclosure
                    },
                )
                Text(text = stringResource(disclosure.copyId()), style = MaterialTheme.typography.bodyMedium)
            }
        }
        Button(enabled = checked.containsAll(disclosures), onClick = onConfirm) {
            Text(text = stringResource(R.string.payment_disclosures_confirm))
        }
    }
}

private fun PaymentDisclosure.copyId(): Int = when (this) {
    PaymentDisclosure.KYC_EXCHANGE -> R.string.payment_disclosures
    PaymentDisclosure.NO_REFUND -> R.string.payment_no_refund
    PaymentDisclosure.EXACT_AMOUNT -> R.string.payment_exact_amount
    PaymentDisclosure.NO_LOCK_TIME -> R.string.payment_no_locktime
    PaymentDisclosure.WINDOWS -> R.string.payment_windows
}

/** A terminal failed read: no indefinite loading state and no hidden route trap. */
@Composable
fun PaymentInstructionsUnavailableScreen(
    onRetry: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text(text = stringResource(R.string.payment_instructions_unavailable), style = MaterialTheme.typography.bodyMedium)
        Button(onClick = onRetry) { Text(text = stringResource(R.string.payment_retry)) }
        Button(onClick = onBack) { Text(text = stringResource(R.string.payment_back)) }
    }
}

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
    onCopyAddress: (() -> Unit)? = null,
    onCopyAmount: (() -> Unit)? = null,
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
        payment.qrUri?.let { uri -> QrImage(payload = uri) }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (onCopyAddress != null) {
                Button(onClick = onCopyAddress) { Text(text = stringResource(R.string.payment_copy_address)) }
            }
            if (onCopyAmount != null) {
                Button(onClick = onCopyAmount) { Text(text = stringResource(R.string.payment_copy_amount)) }
            }
        }
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
