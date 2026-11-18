package org.ghost.ui.feature.access

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
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
import org.ghost.ui.gateway.InviteView
import org.ghost.ui.gateway.PurchaseState
import org.ghost.ui.gateway.PurchaseView

/**
 * Phase 13 design §6.3 (J2), §6.4: the access screen — the purchase list (id, pay-with and state
 * only, never an amount or an address) with the buy action, and the invite list with revoke.
 * The amounts and addresses live exclusively in [PaymentInstructionsScreen] (D35).
 */
@Composable
fun AccessScreen(
    purchases: List<PurchaseView>,
    invites: List<InviteView>,
    onBuyXmr: () -> Unit,
    onOpenPurchase: (String) -> Unit,
    onRevokeInvite: (Int) -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(
            text = stringResource(R.string.access_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        Button(onClick = onBuyXmr) {
            Text(text = stringResource(R.string.access_buy_xmr))
        }
        LazyColumn(modifier = Modifier.weight(1f)) {
            items(purchases, key = { it.id }) { p ->
                Row(
                    modifier = Modifier.fillMaxWidth().clickable { onOpenPurchase(p.id) }.padding(vertical = 12.dp),
                ) {
                    Text(
                        text = stringResource(R.string.access_purchase_row, p.payWith, p.state.name),
                        style = MaterialTheme.typography.bodyLarge,
                    )
                }
            }
        }
        if (invites.isNotEmpty()) {
            Text(
                text = stringResource(R.string.access_invites_title),
                style = MaterialTheme.typography.labelLarge,
            )
            invites.forEach { invite ->
                Row(modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(
                        text = stringResource(R.string.access_invite_row, invite.index, invite.expiryDay ?: 0, invite.state),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    Text(
                        text = stringResource(R.string.access_invite_revoke),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.clickable { onRevokeInvite(invite.index) },
                    )
                }
            }
        }
    }
}

/** The stored timestamp is epoch seconds, rounded down to a minute; convert exactly once. */
internal fun formatSyncTime(epochSeconds: Long, zone: java.time.ZoneId): String =
    java.time.LocalDateTime.ofInstant(java.time.Instant.ofEpochSecond(epochSeconds), zone)
        .format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm"))

/**
 * A single purchase's progress (§6.3): the state read-model polled while the flow advances; the
 * instructions door opens only in READY / UNDERPAID (the [PaymentModel] re-checks, D35).
 */
@Composable
fun PurchaseProgressScreen(
    purchase: PurchaseView?,
    onOpenInstructions: () -> Unit,
    onCheckNow: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text(
            text = stringResource(R.string.purchase_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        Text(
            text = stringResource(R.string.purchase_state, purchase?.state?.name ?: ""),
            style = MaterialTheme.typography.bodyLarge,
        )
        purchase?.let { p ->
            Text(
                text = stringResource(
                    when (p.sync) {
                        org.ghost.ui.gateway.PurchaseSyncState.LIVE -> R.string.purchase_sync_live
                        org.ghost.ui.gateway.PurchaseSyncState.STALE -> R.string.purchase_sync_stale
                        org.ghost.ui.gateway.PurchaseSyncState.ISSUER_UNAVAILABLE -> R.string.purchase_sync_unavailable
                        org.ghost.ui.gateway.PurchaseSyncState.LOCAL_ONLY -> R.string.purchase_sync_local
                    },
                ),
                style = MaterialTheme.typography.bodyMedium,
            )
            p.lastSyncedMinute?.let { minute ->
                val formatted = formatSyncTime(minute, java.time.ZoneId.systemDefault())
                Text(
                    text = stringResource(R.string.purchase_last_sync, formatted),
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
        if (purchase != null && purchase.state in setOf(PurchaseState.READY, PurchaseState.PAYMENT_UNVERIFIED, PurchaseState.UNDERPAID)) {
            Button(onClick = onOpenInstructions) {
                Text(text = stringResource(R.string.purchase_open_payment))
            }
        }
        if (purchase != null && purchase.state in setOf(PurchaseState.READY, PurchaseState.PAYMENT_UNVERIFIED, PurchaseState.UNDERPAID, PurchaseState.CONFIRMING)) {
            Button(onClick = onCheckNow) {
                Text(text = stringResource(R.string.purchase_check_now))
            }
        }
    }
}
