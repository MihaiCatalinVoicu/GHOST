package org.ghost.ui.feature.access

import org.ghost.ui.gateway.AccessGateway
import org.ghost.ui.gateway.PurchaseState
import org.ghost.ui.gateway.PaymentView
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
        return purchase.state == PurchaseState.READY ||
            purchase.state == PurchaseState.PAYMENT_UNVERIFIED ||
            purchase.state == PurchaseState.UNDERPAID
    }

    /** CS-U3/PM-U32: shown only after a real instruction read, hidden at leave/hide/lock. */
    @UserAction
    suspend fun onOpenInstructions(purchaseId: String): PaymentView? {
        check(mayOpenInstructions(purchaseId)) { "instructions open only for READY or UNDERPAID (D35)" }
        val payment = access.paymentInstructions(purchaseId) ?: return null
        access.paymentScreenShown(purchaseId)
        return payment
    }

    /** The disclosures still required before the instruction read; no traffic and no sensitive data. */
    suspend fun requiredDisclosures(purchaseId: String): Set<org.ghost.ui.gateway.PaymentDisclosure> =
        access.requiredDisclosures(purchaseId)

    /** J2 step 4: an explicit user acknowledgement, never an implicit side effect of opening a route. */
    @UserAction
    suspend fun onDisclosuresConfirmed(purchaseId: String) {
        val required = access.requiredDisclosures(purchaseId)
        if (required.isNotEmpty()) access.acknowledgeDisclosures(purchaseId, required)
    }

    /** J2 step 6: one declared InvoiceStatus call. BlindSign remains quiet-run work. */
    @UserAction
    suspend fun onCheckNow(purchaseId: String) {
        access.checkNow(purchaseId)
    }

    @UserAction
    suspend fun onInstructionsClosed(purchaseId: String) {
        access.paymentScreenHidden(purchaseId)
    }

    suspend fun purchases(): List<PurchaseView> = access.purchases()

    /** The instruction view for the screen's rendering (D35's read; the shown-mark lives in [onOpenInstructions]). */
    suspend fun view(purchaseId: String): PaymentView? = access.paymentInstructions(purchaseId)
}
