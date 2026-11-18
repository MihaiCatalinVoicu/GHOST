package org.ghost.app.ui

import kotlinx.coroutines.runBlocking
import org.ghost.entitlement.api.Disclosure
import org.ghost.entitlement.api.Entitlement
import org.ghost.entitlement.api.PayWith
import org.ghost.entitlement.api.PaymentInstructions
import org.ghost.entitlement.api.PurchaseId
import org.ghost.ui.feature.access.PaymentModel
import org.ghost.ui.gateway.AccessGateway
import org.ghost.ui.gateway.InviteView
import org.ghost.ui.gateway.PaymentView
import org.ghost.ui.gateway.PurchaseState
import org.ghost.ui.gateway.PurchaseView
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Phase 13 §3.5 (D35), §6.3; PM-U31, PM-U32, CS-U3: the payment flow over recording gateways —
 * instructions open only for READY or UNDERPAID, the shown/hidden hold brackets the read, and
 * the traffic log counts exactly the §2.4 calls.
 */
class PaymentModelTest {
    private class RecordingAccess : AccessGateway {
        val log = ArrayList<String>()
        var disclosures = emptySet<org.ghost.ui.gateway.PaymentDisclosure>()
        var instructionsAvailable = true
        var purchases = listOf(
            PurchaseView(id = "aa".repeat(16), payWith = "XMR", state = PurchaseState.READY),
            PurchaseView(id = "bb".repeat(16), payWith = "XMR", state = PurchaseState.INVOICE_PENDING),
            PurchaseView(id = "cc".repeat(16), payWith = "XMR", state = PurchaseState.PREPARED),
        )
        override suspend fun purchases(): List<PurchaseView> = purchases
        override suspend fun invites(): List<InviteView> = emptyList()
        override suspend fun paymentInstructions(purchaseId: String): PaymentView? {
            log.add("instructions:$purchaseId")
            if (!instructionsAvailable) return null
            return PaymentView(
                subaddress = org.ghost.ui.protect.SensitiveText("8A…"),
                amount = org.ghost.ui.protect.SensitiveText("0.42"),
                deadlineDay = 20_100,
            )
        }

        override suspend fun requiredDisclosures(purchaseId: String) = disclosures
        override suspend fun acknowledgeDisclosures(
            purchaseId: String,
            disclosures: Set<org.ghost.ui.gateway.PaymentDisclosure>,
        ) {
            log.add("acknowledged:$purchaseId")
            this.disclosures = emptySet()
        }
        override suspend fun checkNow(purchaseId: String) = log.add("check:$purchaseId").let { }
        override suspend fun paymentScreenShown(purchaseId: String) = log.add("shown:$purchaseId").let { }
        override suspend fun paymentScreenHidden(purchaseId: String) = log.add("hidden:$purchaseId").let { }
        override suspend fun startPurchase(packId: String) = log.add("start:$packId").let { }
        override suspend fun requestInvoiceNow(purchaseId: String) = log.add("invoice:$purchaseId").let { }
        override suspend fun revokeInvite(index: Int) = log.add("revoke:$index").let { }
    }

    @Test
    fun instructionsOpenOnlyForReadyOrUnderpaid(): Unit = runBlocking {
        val access = RecordingAccess()
        val m = PaymentModel(access)
        assertTrue(m.mayOpenInstructions("aa".repeat(16)))
        assertFalse(m.mayOpenInstructions("bb".repeat(16)))
        assertFalse(m.mayOpenInstructions("cc".repeat(16)))
        access.purchases = access.purchases + PurchaseView(
            id = "dd".repeat(16),
            payWith = "XMR",
            state = PurchaseState.PAYMENT_UNVERIFIED,
        )
        assertTrue("a shown but unverified payment keeps its instructions available", m.mayOpenInstructions("dd".repeat(16)))
        assertThrows(IllegalStateException::class.java) {
            runBlocking { m.onOpenInstructions("bb".repeat(16)) }
        }
        assertEquals("nothing opened for the pending pack", emptyList<String>(), access.log)
    }

    @Test
    fun theHoldBracketsTheInstructionRead(): Unit = runBlocking {
        val access = RecordingAccess()
        val m = PaymentModel(access)
        val id = "aa".repeat(16)
        m.onOpenInstructions(id)
        m.onInstructionsClosed(id)
        assertEquals(listOf("instructions:$id", "shown:$id", "hidden:$id"), access.log)
    }

    @Test
    fun aFailedInstructionReadIsTerminalAndDoesNotStartTheHold(): Unit = runBlocking {
        val access = RecordingAccess().also { it.instructionsAvailable = false }
        val id = "aa".repeat(16)
        assertEquals(null, PaymentModel(access).onOpenInstructions(id))
        assertEquals(listOf("instructions:$id"), access.log)
    }

    @Test
    fun disclosuresAndCheckNowRequireExplicitUserIntents(): Unit = runBlocking {
        val access = RecordingAccess().also {
            it.disclosures = org.ghost.ui.gateway.PaymentDisclosure.entries.toSet()
        }
        val m = PaymentModel(access)
        val id = "aa".repeat(16)
        assertEquals(org.ghost.ui.gateway.PaymentDisclosure.entries.toSet(), m.requiredDisclosures(id))
        m.onDisclosuresConfirmed(id)
        m.onCheckNow(id)
        assertEquals(listOf("acknowledged:$id", "check:$id"), access.log)
    }

    @Test
    fun aPendingInvoiceResendsRequestInsteadOfCheckingANonexistentInvoice(): Unit = runBlocking {
        val access = RecordingAccess().also {
            it.purchases = it.purchases.filter { purchase -> purchase.state == PurchaseState.INVOICE_PENDING }
        }
        val id = "bb".repeat(16)
        startOrResumeXmrPurchase(access)
        assertEquals(listOf("invoice:$id"), access.log)
    }

    @Test
    fun anIssuedInvoiceUsesStatusRatherThanStartingAnotherRequest(): Unit = runBlocking {
        val access = RecordingAccess()
        val id = "aa".repeat(16)
        startOrResumeXmrPurchase(access)
        assertEquals(listOf("check:$id"), access.log)
    }

    @Test
    fun theAdapterMapsPurchasesInstructionsDisclosuresAndCheckNow(): Unit = runBlocking {
        var checked: PurchaseId? = null
        var acknowledged: Set<Disclosure>? = null
        val fake = object : Entitlement {
            override fun openPurchases() = listOf(
                org.ghost.entitlement.api.OpenPurchase(
                    id = PurchaseId(ByteArray(16) { 0xaa.toByte() }),
                    payWith = PayWith.XMR,
                    state = org.ghost.entitlement.api.PurchaseUiState.READY,
                    sync = org.ghost.entitlement.api.PurchaseSyncState.LIVE,
                    lastSyncedMinute = 20_000L,
                ),
            )

            override fun invites() = listOf(
                org.ghost.entitlement.api.InviteIndex(index = 3, expiryDay = 20_021, state = "created"),
            )

            override fun paymentInstructions(id: PurchaseId) = PaymentInstructions(
                subaddress = "8Address",
                amountAtomic = 420_000_000_000L,
                outstandingAtomic = 42_500_000_000L,
                deadlineMinute = 20_100L * 1440 + 700,
                uri = null,
            )

            override fun status() = error("not used")
            override fun startPurchase(payWith: PayWith): PurchaseId? = error("not used")
            override fun requiredDisclosures(id: PurchaseId): Set<Disclosure> = setOf(Disclosure.NO_REFUND)
            override fun acknowledge(id: PurchaseId, disclosures: Set<Disclosure>) { acknowledged = disclosures }
            override fun requestInvoiceNow(id: PurchaseId) = error("not used")
            override fun checkNow(id: PurchaseId) { checked = id }
            override fun cancel(id: PurchaseId): Boolean = error("not used")
            override fun inspectInvite(text: String, nowUnixSeconds: Long) = error("not used")
            override fun activate(inviteText: String) = error("not used")
            override fun activationState() = error("not used")
            override fun restore(mnemonic: List<String>) = error("not used")
            override fun createInvite(expiryDay: Int): String? = error("not used")
            override fun revokeInvite(index: Int): Boolean = error("not used")
            override fun claimPayout(address: String) = error("not used")
            override fun setAutoRenewWithCredits(enabled: Boolean) = error("not used")
            override fun paymentScreenShown(id: PurchaseId) = Unit
            override fun paymentScreenHidden(id: PurchaseId) = Unit
        }
        val adapter = AccessGatewayAdapter({ fake })
        val purchases = adapter.purchases()
        assertEquals(1, purchases.size)
        assertEquals("aa".repeat(16), purchases[0].id)
        assertEquals(PurchaseState.READY, purchases[0].state)
        assertEquals(org.ghost.ui.gateway.PurchaseSyncState.LIVE, purchases[0].sync)
        assertEquals(20_000L, purchases[0].lastSyncedMinute)
        val invites = adapter.invites()
        assertEquals(3, invites[0].index)
        assertEquals(20_021, invites[0].expiryDay)
        val p = adapter.paymentInstructions("aa".repeat(16))!!
        assertEquals("8Address", p.subaddress.value)
        assertEquals("0.0425", p.amount.value)
        assertEquals(20_100, p.deadlineDay)
        val id = "aa".repeat(16)
        assertEquals(setOf(org.ghost.ui.gateway.PaymentDisclosure.NO_REFUND), adapter.requiredDisclosures(id))
        adapter.acknowledgeDisclosures(id, setOf(org.ghost.ui.gateway.PaymentDisclosure.NO_REFUND))
        assertEquals(setOf(Disclosure.NO_REFUND), acknowledged)
        adapter.checkNow(id)
        assertEquals(PurchaseId(ByteArray(16) { 0xaa.toByte() }), checked)
    }
}
