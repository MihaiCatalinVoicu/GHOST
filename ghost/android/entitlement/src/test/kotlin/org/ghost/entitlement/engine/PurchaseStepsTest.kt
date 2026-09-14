package org.ghost.entitlement.engine

import org.ghost.entitlement.T0
import org.ghost.entitlement.TestBytes
import org.ghost.entitlement.TestCrypto
import org.ghost.entitlement.WEEK0
import org.ghost.entitlement.World
import org.ghost.entitlement.api.Disclosure
import org.ghost.entitlement.api.EntitlementFlag
import org.ghost.entitlement.api.PayWith
import org.ghost.entitlement.store.PurchaseStore
import org.ghost.entitlement.store.TokenStore
import org.ghost.network.EntitlementCrypto
import org.ghost.network.TorIssuerTransport
import org.ghost.sync.store.Time
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pack purchases through quiet runs (design §5.3, §11.4, §11.5, §19.11, §19.13): write-ahead, the
 * fixed attempt plan with its cap of 5, identical retries, the terminal wipe, credits paths and the
 * issuer-facing clock.
 */
class PurchaseStepsTest {
    private val label = "ghost/v1/issuer-claim".toByteArray(Charsets.US_ASCII)

    /** Moves the clock to the pack's next due time (if it has one) and runs a quiet run. */
    private fun World.nextAttempt(id: ByteArray) {
        val p = checkNotNull(purchase(id))
        clock.now = maxOf(clock.now, p.nextDueMinute ?: clock.now)
        quiet()
    }

    /** Quiet runs every 2 h for [runs] runs, whatever is due. */
    private fun World.quietRuns(runs: Int) = repeat(runs) {
        quiet()
        clock.now += 2 * Grid.HOUR
    }

    @Test
    fun anXmrPackIsInvoicedSignedAndFinalizedWithEverySecretWiped(): Unit = World().use { w ->
        val id = checkNotNull(w.engine.startPurchase(PayWith.XMR)).toByteArray()
        val prepared = checkNotNull(w.purchase(id))
        assertEquals(PurchaseStore.PREPARED, prepared.state)
        assertFalse("nothing sent at intent", prepared.sent)
        assertEquals(WEEK0, prepared.baseWeek)
        val claimKey = prepared.claimKey()
        assertTrue(w.issuer.calls.isEmpty())

        w.quiet()
        val request = w.issuer.named("requestInvoice").single()
        assertEquals(TestBytes.hex(TestBytes.sha256(label, claimKey)), request.args[0])
        assertEquals("", request.args[1])
        assertEquals(WEEK0.toString(), request.args[2])
        val invoiced = checkNotNull(w.purchase(id))
        assertEquals(PurchaseStore.INVOICED, invoiced.state)
        assertEquals(TestCrypto.PRICE, invoiced.amountAtomic)
        assertEquals(TestCrypto.SUBADDRESS, invoiced.subaddress)
        val receipt = Time.floorMinute(T0)
        assertEquals(receipt, invoiced.receiptMinute)
        assertEquals(RetryPolicy.blindSignDueMinute(invoiced.seed(), receipt, 0), invoiced.nextDueMinute)

        w.quiet()
        assertEquals("not due yet: no call", 1, w.issuer.calls.size)

        w.nextAttempt(id)
        val sign = w.issuer.named("blindSign").single()
        assertEquals("63", sign.args[6])
        val done = checkNotNull(w.purchase(id))
        assertEquals(PurchaseStore.FINALIZED, done.state)
        val wiped = w.count(
            "SELECT count(*) FROM ent_purchase WHERE purchase_id = ?1 AND seed IS NULL AND claim_key IS NULL AND invoice_id IS NULL " +
                "AND subaddress IS NULL AND amount_atomic IS NULL AND created_hour IS NULL AND receipt_minute IS NULL " +
                "AND outstanding_atomic IS NULL AND next_due_minute IS NULL AND terminal_day IS NOT NULL",
            listOf(id),
        )
        assertEquals(1L, wiped)
        val access = w.tokenRows("access")
        assertEquals(60, access.size)
        for (week in WEEK0 until WEEK0 + 5) for (slot in 0..2) assertEquals(4, access.count { it.epoch == week && it.slot == slot })
        assertEquals(listOf(739L, 739L), w.tokenRows("invite").map { it.epoch })
        assertEquals(listOf(227L), w.tokenRows("credit").map { it.epoch })
        // Eligible at the activation slot of the finalization time (§12.3), the same for the whole batch.
        val eligible = access.map { it.eligibleMinute }.toSet().single()
        val finalizedAt = w.issuer.named("blindSign").single().at
        val boundary = -Math.floorDiv(-(finalizedAt + 4 * 3600), 86_400L) * 86_400L
        assertTrue(eligible in boundary until boundary + 6 * 3600)
    }

    @Test
    fun aLyingIssuerGetsExactlyFiveIdenticalAttemptsAtTheirDueTimes(): Unit = World().use { w ->
        w.issuer.signState = TorIssuerTransport.STATE_AWAITING_CONFIRMATIONS
        val id = checkNotNull(w.engine.startPurchase(PayWith.XMR)).toByteArray()
        w.quiet()
        val invoiced = checkNotNull(w.purchase(id))
        val seed = invoiced.seed()
        val receipt = checkNotNull(invoiced.receiptMinute)
        repeat(10) {
            val p = checkNotNull(w.purchase(id))
            if (p.state != PurchaseStore.INVOICED) return@repeat
            w.clock.now = p.nextDueMinute ?: (w.clock.now + 30 * Grid.DAY)
            w.quiet()
        }
        val signs = w.issuer.named("blindSign")
        assertEquals("at most 5 BlindSign whatever the issuer answers (J9, M16)", 5, signs.size)
        assertEquals("every attempt sends identical bytes", 1, signs.map { it.args }.toSet().size)
        signs.forEachIndexed { k, call -> assertEquals(RetryPolicy.blindSignDueMinute(seed, receipt, k), call.at) }
        assertEquals(PurchaseStore.LOST, checkNotNull(w.purchase(id)).state)
        assertTrue(EntitlementFlag.PAYMENT_LOST in w.engine.status().flags)
        // Later quiet runs make no call for it.
        w.clock.now += 60 * Grid.DAY
        w.quiet()
        assertEquals(5, w.issuer.named("blindSign").size)
    }

    @Test
    fun aTransientFailureIsRetriedWithIdenticalBytesAndCounted(): Unit = World().use { w ->
        val id = checkNotNull(w.engine.startPurchase(PayWith.XMR)).toByteArray()
        w.issuer.failOnce = "timeout"
        w.quiet()
        val afterFailure = checkNotNull(w.purchase(id))
        assertEquals(PurchaseStore.PREPARED, afterFailure.state)
        assertTrue(afterFailure.sent)
        assertEquals(1, afterFailure.attempt)
        // The retry's time was drawn when the first attempt left, 20–28 h later; no answer moves it.
        val retry = checkNotNull(afterFailure.nextDueMinute)
        assertTrue(retry >= T0 + 20 * Grid.HOUR && retry <= T0 + 28 * Grid.HOUR + 60)
        w.quiet()
        assertEquals("not due yet", 1, w.issuer.calls.size)
        w.nextAttempt(id)
        val requests = w.issuer.named("requestInvoice")
        assertEquals(2, requests.size)
        assertEquals(requests[0].args, requests[1].args)
        assertEquals(PurchaseStore.INVOICED, checkNotNull(w.purchase(id)).state)
    }

    @Test
    fun theBaseWeekFollowsTheDeviceClockOnlyUntilTheFirstSend(): Unit = World().use { w ->
        val fresh = checkNotNull(w.engine.startPurchase(PayWith.XMR)).toByteArray()
        w.clock.now += Grid.WEEK
        w.quiet()
        assertEquals((WEEK0 + 1).toString(), w.issuer.named("requestInvoice").single().args[2])
        assertEquals(WEEK0 + 1, checkNotNull(w.purchase(fresh)).baseWeek)

        World().use { v ->
            val sent = checkNotNull(v.engine.startPurchase(PayWith.XMR)).toByteArray()
            v.issuer.failOnce = "transport"
            v.quiet()
            v.clock.now += Grid.WEEK
            v.quiet()
            assertEquals(listOf(WEEK0.toString(), WEEK0.toString()), v.issuer.named("requestInvoice").map { it.args[2] })
            assertEquals(WEEK0, checkNotNull(v.purchase(sent)).baseWeek)
        }
    }

    @Test
    fun noIssuerCallWithoutATrustedClockAndAtMostOnePerQuietRun(): Unit = World().use { w ->
        w.engine.startPurchase(PayWith.XMR)
        w.engine.startPurchase(PayWith.XMR)
        w.quiet(trusted = false)
        assertTrue(w.issuer.calls.isEmpty())
        w.quiet()
        assertEquals(1, w.issuer.calls.size)
        w.quiet()
        assertEquals(2, w.issuer.calls.size)
        // A relay session never reaches the issuer.
        w.laneStep()
        assertEquals(2, w.issuer.calls.size)
    }

    @Test
    fun wrongPeriodClosesTheFlowAndItsSuccessorIsTheFlowsOneRetry(): Unit = World().use { w ->
        val id = checkNotNull(w.engine.startPurchase(PayWith.XMR)).toByteArray()
        val first = checkNotNull(w.purchase(id)).claimKey()
        w.issuer.invoiceResult = TorIssuerTransport.INVOICE_WRONG_PERIOD
        w.quiet()
        assertEquals(PurchaseStore.FAILED, checkNotNull(w.purchase(id)).state)
        val fresh = w.purchases().single { it.state == PurchaseStore.PREPARED }
        assertFalse(fresh.sent)
        assertFalse(first.contentEquals(fresh.claimKey()))
        // The successor keeps the attempt count and the retry time drawn with the first send (§19.11,
        // §19.23 point 2): no issuer answer adds an attempt or brings a call forward.
        assertEquals(1, fresh.attempt)
        val retry = checkNotNull(fresh.nextDueMinute)
        assertTrue(retry >= T0 + 20 * Grid.HOUR && retry <= T0 + 28 * Grid.HOUR + 60)
        w.issuer.invoiceResult = TorIssuerTransport.INVOICE_OK
        w.quiet()
        assertEquals("not due before its retry time", 1, w.issuer.named("requestInvoice").size)
        w.nextAttempt(fresh.id())
        val invoiced = checkNotNull(w.purchase(fresh.id()))
        assertEquals(PurchaseStore.INVOICED, invoiced.state)
        assertEquals("the invoice came on the second call: BlindSign starts at its second window (E5)", 1, invoiced.attempt)
    }

    @Test
    fun anIssuerThatAlwaysAnswersWrongPeriodGetsAtMostTwoRequestInvoicesPerPack() {
        for (payWith in listOf(PayWith.CREDITS, PayWith.XMR)) World().use { w ->
            w.addTokens("credit", Grid.creditEpoch(WEEK0), 10)
            w.issuer.invoiceResult = TorIssuerTransport.INVOICE_WRONG_PERIOD
            checkNotNull(w.engine.startPurchase(payWith))
            w.quietRuns(100)
            val requests = w.issuer.named("requestInvoice")
            assertEquals("$payWith: the planned call and one retry whatever the issuer answers (§19.23 point 2)", 2, requests.size)
            assertEquals("$payWith: the same credits both times", requests[0].args[1], requests[1].args[1])
            val gap = requests[1].at - requests[0].at
            assertTrue("$payWith: the retry waits for its time drawn with the first send", gap >= 20 * Grid.HOUR && gap < 30 * Grid.HOUR + 60)
            assertTrue("$payWith: the flow failed", w.purchases().none { it.live })
            assertEquals(10, w.tokenRows("credit").count { it.state == TokenStore.FRESH })
        }
    }

    @Test
    fun aCreditsPackReservesItsCoverAtTheFirstSendAndSpendsItAtFinalization(): Unit = World().use { w ->
        w.addTokens("credit", Grid.creditEpoch(WEEK0), 9)
        assertNull("nine credits do not cover the price", w.engine.startPurchase(PayWith.CREDITS))
        w.addTokens("credit", Grid.creditEpoch(WEEK0), 1)
        val id = checkNotNull(w.engine.startPurchase(PayWith.CREDITS))
        assertEquals(emptySet<Disclosure>(), w.engine.requiredDisclosures(id))
        assertEquals(10, w.tokenRows("credit").count { it.state == TokenStore.FRESH })
        w.quiet()
        val request = w.issuer.named("requestInvoice").single()
        assertEquals(10, request.args[1].split(",").size)
        val credits = w.tokenRows("credit")
        assertTrue(credits.all { it.state == TokenStore.RESERVED && it.reservedFor == TokenStore.FOR_PURCHASE })
        val invoiced = checkNotNull(w.purchase(id.toByteArray()))
        assertEquals(0L, invoiced.amountAtomic)
        assertNull(invoiced.subaddress)
        assertNull(w.engine.paymentInstructions(id))
        w.nextAttempt(id.toByteArray())
        assertEquals("62", w.issuer.named("blindSign").single().args[6])
        assertEquals(PurchaseStore.FINALIZED, checkNotNull(w.purchase(id.toByteArray())).state)
        assertTrue("the spent credits are gone and a credits pack yields none", w.tokenRows("credit").isEmpty())
        assertEquals(60, w.tokenRows("access").size)
    }

    @Test
    fun creditsSpentDeletesTheMaskedCreditsAndReleasesTheOthers(): Unit = World().use { w ->
        w.addTokens("credit", Grid.creditEpoch(WEEK0), 10)
        val id = checkNotNull(w.engine.startPurchase(PayWith.CREDITS)).toByteArray()
        w.issuer.invoiceResult = TorIssuerTransport.INVOICE_CREDITS_SPENT
        w.issuer.invoiceMask = 0b101
        w.quiet()
        assertEquals(PurchaseStore.FAILED, checkNotNull(w.purchase(id)).state)
        val left = w.tokenRows("credit")
        assertEquals(8, left.size)
        assertTrue(left.all { it.state == TokenStore.FRESH && it.reservedFor == null })
    }

    @Test
    fun terminalAnswersEndThePlan(): Unit {
        World().use { w ->
            w.issuer.signState = TorIssuerTransport.STATE_EXPIRED
            val id = checkNotNull(w.engine.startPurchase(PayWith.XMR)).toByteArray()
            w.quiet()
            w.nextAttempt(id)
            assertEquals(PurchaseStore.EXPIRED, checkNotNull(w.purchase(id)).state)
            assertTrue(EntitlementFlag.PAYMENT_EXPIRED in w.engine.status().flags)
        }
        World().use { w ->
            w.issuer.signState = TorIssuerTransport.STATE_OTHER_REQUEST_ISSUED
            val id = checkNotNull(w.engine.startPurchase(PayWith.XMR)).toByteArray()
            w.quiet()
            w.nextAttempt(id)
            assertEquals(PurchaseStore.FAILED, checkNotNull(w.purchase(id)).state)
            assertTrue(EntitlementFlag.ISSUER_MISMATCH in w.engine.status().flags)
        }
    }

    @Test
    fun unauthorizedIsLostUnlessTheLastKnownStateWasExpired(): Unit {
        World().use { w ->
            w.issuer.signState = TorIssuerTransport.STATE_AWAITING_PAYMENT
            val id = checkNotNull(w.engine.startPurchase(PayWith.XMR)).toByteArray()
            w.quiet()
            w.nextAttempt(id)
            w.issuer.fail = "unauthorized"
            w.nextAttempt(id)
            assertEquals(PurchaseStore.LOST, checkNotNull(w.purchase(id)).state)
        }
        World().use { w ->
            val id = checkNotNull(w.engine.startPurchase(PayWith.XMR))
            w.quiet()
            w.issuer.statusState = TorIssuerTransport.STATE_EXPIRED
            w.engine.checkNow(id)
            assertEquals(TorIssuerTransport.STATE_EXPIRED, checkNotNull(w.purchase(id.toByteArray())).prevState)
            w.issuer.fail = "unauthorized"
            w.nextAttempt(id.toByteArray())
            assertEquals(PurchaseStore.EXPIRED, checkNotNull(w.purchase(id.toByteArray())).state)
        }
    }

    @Test
    fun anAmountOtherThanTheSchedulePriceGetsOneIdenticalRetryThenFails(): Unit = World().use { w ->
        w.issuer.amountOverride = TestCrypto.PRICE + 1
        val id = checkNotNull(w.engine.startPurchase(PayWith.XMR)).toByteArray()
        w.quiet()
        assertEquals(PurchaseStore.PREPARED, checkNotNull(w.purchase(id)).state)
        assertFalse(EntitlementFlag.ISSUER_MISMATCH in w.engine.status().flags)
        w.nextAttempt(id)
        assertEquals(PurchaseStore.FAILED, checkNotNull(w.purchase(id)).state)
        assertTrue(EntitlementFlag.ISSUER_MISMATCH in w.engine.status().flags)
        val requests = w.issuer.named("requestInvoice")
        assertEquals(2, requests.size)
        assertEquals(requests[0].args, requests[1].args)
    }

    @Test
    fun aPurchaseStartedWhileEntitlementIsNeededWaitsUpToADay(): Unit = World().use { w ->
        w.ctx().memory.needUnmet(T0)
        w.random.uniformValue = 0.5
        val id = checkNotNull(w.engine.startPurchase(PayWith.XMR)).toByteArray()
        assertEquals(Time.ceilMinute(T0 + 12 * 3600), checkNotNull(w.purchase(id)).nextDueMinute)
        w.quiet()
        assertTrue(w.issuer.calls.isEmpty())
        w.clock.now = T0 + 12 * 3600 + 60
        w.quiet()
        assertEquals(1, w.issuer.calls.size)
    }

    @Test
    fun paymentInstructionsNeedTheInvoiceAndEveryDisclosureAndEndAtTheDeadline(): Unit = World().use { w ->
        val id = checkNotNull(w.engine.startPurchase(PayWith.XMR))
        assertEquals(Disclosure.entries.toSet(), w.engine.requiredDisclosures(id))
        w.engine.acknowledge(id, Disclosure.entries.toSet())
        assertNull("not invoiced yet", w.engine.paymentInstructions(id))
        w.quiet()
        w.engine.acknowledge(id, setOf(Disclosure.NO_REFUND))
        assertTrue(checkNotNull(w.purchase(id.toByteArray())).disclosed)
        World().use { v ->
            val other = checkNotNull(v.engine.startPurchase(PayWith.XMR))
            v.quiet()
            v.engine.acknowledge(other, setOf(Disclosure.NO_REFUND))
            assertNull("a partial acknowledgement shows nothing", v.engine.paymentInstructions(other))
        }
        assertTrue("cancel works while nothing was shown", checkNotNull(w.purchase(id.toByteArray())).shown.not())
        val instructions = checkNotNull(w.engine.paymentInstructions(id))
        assertEquals(TestCrypto.SUBADDRESS, instructions.subaddress)
        assertEquals(TestCrypto.PRICE, instructions.amountAtomic)
        assertEquals(TestCrypto.PRICE, instructions.outstandingAtomic)
        assertEquals(Time.floorMinute(T0) + 24 * 3600, instructions.deadlineMinute)
        assertEquals("monero:${TestCrypto.SUBADDRESS}?tx_amount=${TestCrypto.PRICE}", instructions.uri)
        assertFalse("shown: no more cancel", w.engine.cancel(id))
        w.clock.now = instructions.deadlineMinute
        assertNull(w.engine.paymentInstructions(id))
    }

    @Test
    fun anUnderpaymentLeavesTheOutstandingAmountForTheUri(): Unit = World().use { w ->
        val id = checkNotNull(w.engine.startPurchase(PayWith.XMR))
        w.quiet()
        w.issuer.signState = TorIssuerTransport.STATE_UNDERPAID
        w.issuer.seen = TestCrypto.PRICE / 4
        w.issuer.credited = TestCrypto.PRICE / 4
        w.nextAttempt(id.toByteArray())
        val p = checkNotNull(w.purchase(id.toByteArray()))
        assertEquals(TestCrypto.PRICE / 2, p.outstandingAtomic)
        assertEquals(TorIssuerTransport.STATE_UNDERPAID, p.prevState)
        w.engine.acknowledge(id, Disclosure.entries.toSet())
        w.clock.now = T0 + 60
        assertNotNull(w.engine.paymentInstructions(id)?.uri?.takeIf { it.endsWith("tx_amount=${TestCrypto.PRICE / 2}") })
    }

    @Test
    fun aCreditsPackCanBeCancelledOnlyBeforeItsFirstSend(): Unit {
        World().use { w ->
            w.addTokens("credit", Grid.creditEpoch(WEEK0), 10)
            val id = checkNotNull(w.engine.startPurchase(PayWith.CREDITS))
            assertTrue("nothing left the device", w.engine.cancel(id))
            assertEquals(PurchaseStore.FAILED, checkNotNull(w.purchase(id.toByteArray())).state)
            assertEquals(10, w.tokenRows("credit").count { it.state == TokenStore.FRESH })
            assertFalse(w.engine.cancel(id))
        }
        World().use { w ->
            w.addTokens("credit", Grid.creditEpoch(WEEK0), 10)
            val id = checkNotNull(w.engine.startPurchase(PayWith.CREDITS))
            w.issuer.failOnce = "timeout"
            w.quiet()
            assertFalse("sent: the issuer may already hold an invoice for these credits", w.engine.cancel(id))
            assertEquals(PurchaseStore.PREPARED, checkNotNull(w.purchase(id.toByteArray())).state)
            assertTrue(w.tokenRows("credit").all { it.state == TokenStore.RESERVED })
            w.nextAttempt(id.toByteArray())
            val invoiced = checkNotNull(w.purchase(id.toByteArray()))
            assertEquals(PurchaseStore.INVOICED, invoiced.state)
            assertFalse("never shown, but paid: an invoiced credits pack is never cancelled", invoiced.shown)
            assertFalse(w.engine.cancel(id))
            w.nextAttempt(id.toByteArray())
            assertEquals(PurchaseStore.FINALIZED, checkNotNull(w.purchase(id.toByteArray())).state)
            assertEquals(60, w.tokenRows("access").size)
        }
    }

    @Test
    fun aStallingIssuerGetsAtMostTwoIdenticalRequestInvoicesAtPreDrawnTimes(): Unit = World().use { w ->
        w.issuer.fail = "timeout"
        val id = checkNotNull(w.engine.startPurchase(PayWith.XMR)).toByteArray()
        w.quietRuns(100)
        val requests = w.issuer.named("requestInvoice")
        assertEquals("one planned attempt and one identical retry (J9)", 2, requests.size)
        assertEquals(1, requests.map { it.args }.toSet().size)
        val gap = requests[1].at - requests[0].at
        assertTrue("the retry waits for its pre-drawn time", gap >= 20 * Grid.HOUR && gap < 30 * Grid.HOUR + 60)
        assertEquals(PurchaseStore.FAILED, checkNotNull(w.purchase(id)).state)
    }

    @Test
    fun noPurchaseGetsMoreThanSixIssuerCallsWhateverTheIssuerAnswers(): Unit = World().use { w ->
        w.issuer.failOnce = "timeout"
        w.issuer.signState = TorIssuerTransport.STATE_AWAITING_CONFIRMATIONS
        val id = checkNotNull(w.engine.startPurchase(PayWith.XMR)).toByteArray()
        w.quietRuns(400)
        val requests = w.issuer.named("requestInvoice")
        assertEquals(2, requests.size)
        val signs = w.issuer.named("blindSign")
        assertEquals("the retry took the first BlindSign slot: at most 6 linked calls (E5, J9)", 4, signs.size)
        assertEquals(1, signs.map { it.args }.toSet().size)
        assertTrue("the plan goes on at its second window", signs[0].at - requests[1].at >= 44 * Grid.HOUR)
        assertEquals(PurchaseStore.LOST, checkNotNull(w.purchase(id)).state)
    }

    @Test
    fun aCreditsPackWhoseIssuerStallsGetsItsCreditsBackAfterTheRetry(): Unit = World().use { w ->
        w.addTokens("credit", Grid.creditEpoch(WEEK0), 10)
        val id = checkNotNull(w.engine.startPurchase(PayWith.CREDITS)).toByteArray()
        w.issuer.fail = "timeout"
        w.quietRuns(100)
        assertEquals(2, w.issuer.named("requestInvoice").size)
        assertEquals(PurchaseStore.FAILED, checkNotNull(w.purchase(id)).state)
        assertEquals(10, w.tokenRows("credit").count { it.state == TokenStore.FRESH })
    }

    @Test
    fun autoRenewalWithCreditsIsQuietRunWorkWhenCoverageEnds(): Unit = World().use { w ->
        w.addTokens("credit", Grid.creditEpoch(WEEK0), 10)
        w.addAccess(WEEK0 + 5, 0, 1)
        w.quiet()
        assertTrue("disabled: nothing", w.issuer.calls.isEmpty())
        w.engine.setAutoRenewWithCredits(true)
        w.quiet()
        assertTrue("coverage ends later than 2 weeks ahead", w.issuer.calls.isEmpty())
        w.tx { it.sql.exec("DELETE FROM ent_token WHERE kind = 'access'") }
        w.quiet()
        val request = w.issuer.named("requestInvoice").single()
        assertEquals(10, request.args[1].split(",").size)
        assertEquals(PayWith.CREDITS.name.lowercase(), w.purchases().single().payWith)
        assertNotEquals(0, EntitlementCrypto.PRODUCT_PACK_CREDITS)
    }

    @Test
    fun aFailedAutoRenewalPresentsItsCreditsAgainOnlyAWeekLater(): Unit = World().use { w ->
        w.addTokens("credit", Grid.creditEpoch(WEEK0), 10)
        w.engine.setAutoRenewWithCredits(true)
        w.issuer.invoiceResult = TorIssuerTransport.INVOICE_WRONG_PERIOD
        w.quietRuns(7 * 12)
        val requests = w.issuer.named("requestInvoice")
        assertEquals("one renewal and its retry, then no automatic renewal while its failure is kept", 2, requests.size)
        assertEquals(1, requests.map { it.args[1] }.toSet().size)
        w.quietRuns(3 * 12)
        val later = w.issuer.named("requestInvoice").drop(2)
        assertTrue("the next renewal comes, a week after the failure at the earliest", later.isNotEmpty())
        assertTrue(later.first().at >= (Grid.day(requests[1].at) + PurchaseStore.TERMINAL_RETENTION_DAYS) * Grid.DAY)
        // A stalling issuer is capped the same way.
        World().use { v ->
            v.addTokens("credit", Grid.creditEpoch(WEEK0), 10)
            v.engine.setAutoRenewWithCredits(true)
            v.issuer.fail = "timeout"
            v.quietRuns(7 * 12)
            assertEquals(2, v.issuer.named("requestInvoice").size)
        }
    }
}
