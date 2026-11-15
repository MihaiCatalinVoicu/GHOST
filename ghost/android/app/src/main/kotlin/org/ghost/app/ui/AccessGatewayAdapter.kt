package org.ghost.app.ui

import kotlinx.coroutines.withContext
import org.ghost.entitlement.api.Entitlement
import org.ghost.entitlement.api.PayWith
import org.ghost.entitlement.api.PurchaseId
import org.ghost.ui.gateway.AccessGateway
import org.ghost.ui.gateway.InviteView
import org.ghost.ui.gateway.PaymentView
import org.ghost.ui.gateway.PurchaseState
import org.ghost.ui.gateway.PurchaseView

/**
 * Phase 13 design §3.2, §3.6: the [AccessGateway] over the [Entitlement] facade. The purchase
 * list carries id, pay-with and state only; the payment instructions are the only place an
 * address or an amount exists, wrapped in [org.ghost.ui.protect.SensitiveText] before they
 * cross into `:ui`. Calls run on `ghost-ui-io` (CS-U6).
 */
class AccessGatewayAdapter(
    private val entitlement: () -> Entitlement?,
) : AccessGateway {

    override suspend fun purchases(): List<PurchaseView> = onIo {
        val e = entitlement() ?: return@onIo emptyList()
        e.openPurchases().map { p ->
            PurchaseView(
                id = p.id.toByteArray().joinToString("") { "%02x".format(it) },
                payWith = p.payWith.name,
                state = PurchaseState.valueOf(p.state.name),
            )
        }
    }

    override suspend fun invites(): List<InviteView> = onIo {
        val e = entitlement() ?: return@onIo emptyList()
        e.invites().map { InviteView(index = it.index, expiryDay = it.expiryDay?.toInt(), state = it.state) }
    }

    override suspend fun paymentInstructions(purchaseId: String): PaymentView? = onIo {
        val e = entitlement() ?: return@onIo null
        val id = PurchaseId(hex(purchaseId))
        val p = e.paymentInstructions(id) ?: return@onIo null
        PaymentView(
            subaddress = org.ghost.ui.protect.SensitiveText(p.subaddress),
            amount = org.ghost.ui.protect.SensitiveText(formatAtomic(p.outstandingAtomic)),
            deadlineDay = Math.floorDiv(p.deadlineMinute, 1440).toInt(),
        )
    }

    override suspend fun paymentScreenShown(purchaseId: String): Unit = onIo {
        entitlement()?.paymentScreenShown(PurchaseId(hex(purchaseId)))
    }

    override suspend fun paymentScreenHidden(purchaseId: String): Unit = onIo {
        entitlement()?.paymentScreenHidden(PurchaseId(hex(purchaseId)))
    }

    override suspend fun startPurchase(packId: String): Unit = onIo {
        entitlement()?.startPurchase(PayWith.valueOf(packId))
    }

    override suspend fun requestInvoiceNow(purchaseId: String): Unit = onIo {
        entitlement()?.requestInvoiceNow(PurchaseId(hex(purchaseId)))
    }

    override suspend fun revokeInvite(index: Int): Unit = onIo {
        entitlement()?.revokeInvite(index)
    }

    private fun hex(s: String): ByteArray {
        require(s.length == 32) { "a purchase id is 16 bytes hex" }
        return ByteArray(16) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
    }

    /** XMR atomic units (1e-12) rendered with the trailing zeros the wallet convention keeps. */
    private fun formatAtomic(atomic: Long): String {
        val whole = atomic / 1_000_000_000_000L
        val frac = (atomic % 1_000_000_000_000L).toString().padStart(12, '0').trimEnd('0')
        return if (frac.isEmpty()) whole.toString() else "$whole.$frac"
    }

    private suspend fun <T> onIo(block: () -> T): T = withContext(GhostUiIo.dispatcher) {
        GhostUiIo.assertThread()
        block()
    }
}
