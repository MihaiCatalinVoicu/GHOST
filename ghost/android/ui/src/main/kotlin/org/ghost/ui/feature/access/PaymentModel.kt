package org.ghost.ui.feature.access

import org.ghost.ui.gateway.AccessGateway
import org.ghost.ui.gateway.PurchaseState
import org.ghost.ui.gateway.PurchaseView
import org.ghost.ui.gateway.UserAction

/**
 * Phase 13 design §3.5 (D35), §6.3 (J2): the payment flow's model. [PaymentInstructions] is
 * reachable only for a purchase whose state is READY or UNDERPAID — the instruction read marks
 * the purchase shown and so ends `cancel` and `PAYMENT_READY` (F8 §19.11), which is why the
 * gate G-U5 confines the call to this model and the recording gateways count it (PM-U31, PM-U32,
 * CS-U3). An UNDERPAID purchase goes through [onOpenInstructions] with its hold: shown at open,
 * hidden at leave, hide and lock.
 *
 * Q46: there is no "open in wallet" button — the screen offers the QR, a sensitive copy of the
 * subaddress and one of the amount.
 */
class PaymentModel(private val access: AccessGateway) {
    /** The payment screens' only legal entry: READY or UNDERPAID, never anything else. */
    suspend fun mayOpenInstructions(purchaseId: String): Boolean {
        val purchase = access.purchases().firstOrNull { it.id == purchaseId } ?: return false
        return purchase.state == PurchaseState.READY || purchase.state == PurchaseState.UNDERPAID
    }

    /** CS-U3/PM-U32: shown at the instruction read, hidden at leave/hide/lock. */
    @UserAction
    suspend fun onOpenInstructions(purchaseId: String) {
        check(mayOpenInstructions(purchaseId)) { "instructions open only for READY or UNDERPAID (D35)" }
        access.paymentInstructions(purchaseId)
        access.paymentScreenShown(purchaseId)
    }

    @UserAction
    suspend fun onInstructionsClosed(purchaseId: String) {
        access.paymentScreenHidden(purchaseId)
    }

    suspend fun purchases(): List<PurchaseView> = access.purchases()
}
