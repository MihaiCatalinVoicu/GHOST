package org.ghost.entitlement.engine

import org.ghost.entitlement.T0
import org.ghost.entitlement.TestBytes
import org.ghost.entitlement.WEEK0
import org.ghost.entitlement.World
import org.ghost.entitlement.android.EntitlementWiring
import org.ghost.entitlement.api.ActivationResult
import org.ghost.entitlement.api.ActivationState
import org.ghost.entitlement.api.ClaimId
import org.ghost.entitlement.api.Disclosure
import org.ghost.entitlement.api.EntitlementFlag
import org.ghost.entitlement.api.EntitlementStatus
import org.ghost.entitlement.api.PayWith
import org.ghost.entitlement.api.PaymentInstructions
import org.ghost.entitlement.api.PurchaseId
import org.ghost.sync.store.Time
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The facade of design §11.2: counts and flags, `PAYMENT_READY` never immediate (§19.11), the horizon
 * rule (`UPDATE_REQUIRED`), the payment-screen moment kept for the next process, and T3: nothing the
 * facade or a store row prints carries a secret (§11.8).
 */
class FacadeTest {

    @Test
    fun paymentReadyAppearsOnlyAfterItsDelayAndNotOnceShown(): Unit = World().use { w ->
        w.random.prfValue = 0.0
        val id = checkNotNull(w.engine.startPurchase(PayWith.XMR))
        w.quiet()
        assertFalse(EntitlementFlag.PAYMENT_READY in w.engine.status().flags)
        w.clock.now = T0 + 3600 - 1
        assertFalse(EntitlementFlag.PAYMENT_READY in w.engine.status().flags)
        w.clock.now = T0 + 3600
        assertTrue(EntitlementFlag.PAYMENT_READY in w.engine.status().flags)
        w.engine.acknowledge(id, Disclosure.entries.toSet())
        checkNotNull(w.engine.paymentInstructions(id))
        assertFalse(EntitlementFlag.PAYMENT_READY in w.engine.status().flags)
        World().use { v ->
            v.random.prfValue = 0.999
            checkNotNull(v.engine.startPurchase(PayWith.XMR))
            v.quiet()
            v.clock.now = T0 + 5 * 3600
            assertFalse(EntitlementFlag.PAYMENT_READY in v.engine.status().flags)
            v.clock.now = T0 + 6 * 3600
            assertTrue(EntitlementFlag.PAYMENT_READY in v.engine.status().flags)
            v.clock.now = T0 + 24 * 3600
            assertFalse("after the deadline", EntitlementFlag.PAYMENT_READY in v.engine.status().flags)
        }
    }

    @Test
    fun aScheduleEndingWithinFiveWeeksRequiresAnUpdate(): Unit = World({ it.lastWeek = WEEK0 + 4 }).use { w ->
        assertTrue(EntitlementFlag.UPDATE_REQUIRED in w.engine.status().flags)
        assertNull(w.engine.startPurchase(PayWith.XMR))
        World({ it.lastWeek = WEEK0 + 5 }).use { v ->
            assertFalse(EntitlementFlag.UPDATE_REQUIRED in v.engine.status().flags)
            assertTrue(v.engine.startPurchase(PayWith.XMR) != null)
        }
    }

    @Test
    fun theStatusCountsTokensPerWeekCreditsAndInvites(): Unit = World().use { w ->
        assertNull(w.engine.status().coverageEndWeek)
        w.addAccess(WEEK0, 0, 3)
        w.addAccess(WEEK0 + 2, 1, 2)
        w.addTokens("credit", Grid.creditEpoch(WEEK0), 4)
        w.addTokens("invite", Grid.inviteEpoch(WEEK0), 1)
        val s = w.engine.status()
        assertEquals(WEEK0 + 2, s.coverageEndWeek)
        assertEquals(mapOf(WEEK0 to 3, WEEK0 + 2 to 2), s.freshTokensPerWeek)
        assertEquals(4, s.credits)
        assertEquals(1, s.invites)
        assertTrue(s.flags.isEmpty())
    }

    @Test
    fun withoutAnOpenDatabaseTheFacadeIsInert(): Unit = World().use { w ->
        val closed = EntitlementEngine(w.deps) { null }
        assertSame(EntitlementStatus.EMPTY, closed.status())
        assertNull(closed.startPurchase(PayWith.XMR))
        assertEquals(ActivationState.NONE, closed.activationState())
        assertEquals(ActivationResult.UNAVAILABLE, closed.activate(w.inviteText()))
        assertNull(closed.createInvite((Grid.day(T0) + 14).toInt()))
        closed.paymentScreenShown(PurchaseId(ByteArray(16)))
        assertEquals("the relay-session hold does not wait for a database", listOf("shown"), w.userCalls.log)
    }

    @Test
    fun thePaymentScreenMomentIsKeptForTheNextProcess(): Unit = World().use { w ->
        val id = checkNotNull(w.engine.startPurchase(PayWith.XMR))
        assertNull(EntitlementWiring.paymentShownEpochSeconds(w.sql))
        w.engine.paymentScreenShown(id)
        assertEquals(Time.ceilMinute(T0), EntitlementWiring.paymentShownEpochSeconds(w.sql))
        w.clock.now = T0 + 90
        w.engine.paymentScreenHidden(id)
        assertEquals(Time.ceilMinute(T0 + 90), EntitlementWiring.paymentShownEpochSeconds(w.sql))
        assertEquals(listOf("shown", "hidden"), w.userCalls.log)
    }

    @Test
    fun hidingTheAppWithThePaymentScreenOpenKeepsTheMomentItWasLastVisible(): Unit = World().use { w ->
        val id = checkNotNull(w.engine.startPurchase(PayWith.XMR))
        w.engine.paymentScreenShown(id)
        // Thirty minutes later the user switches to a wallet app: the screen was visible until then,
        // so a process killed in the background restores the hold from that moment (§19.11, E15).
        w.clock.now = T0 + 30 * 60
        w.engine.onBackground()
        assertEquals(Time.ceilMinute(T0 + 30 * 60), EntitlementWiring.paymentShownEpochSeconds(w.sql))
        // Hiding the app hid the screen too: a later background changes nothing.
        w.clock.now = T0 + 50 * 60
        w.engine.onBackground()
        assertEquals(Time.ceilMinute(T0 + 30 * 60), EntitlementWiring.paymentShownEpochSeconds(w.sql))
        // Nor does one after the screen was hidden in the app.
        w.engine.paymentScreenShown(id)
        w.clock.now = T0 + 60 * 60
        w.engine.paymentScreenHidden(id)
        w.clock.now = T0 + 70 * 60
        w.engine.onBackground()
        assertEquals(Time.ceilMinute(T0 + 60 * 60), EntitlementWiring.paymentShownEpochSeconds(w.sql))
    }

    @Test
    fun nothingPrintedCarriesASecret(): Unit = World().use { w ->
        w.addTokens("credit", Grid.creditEpoch(WEEK0), 10)
        val pack = checkNotNull(w.engine.startPurchase(PayWith.XMR))
        w.quiet()
        w.engine.acknowledge(pack, Disclosure.entries.toSet())
        val instructions = checkNotNull(w.engine.paymentInstructions(pack))
        val claim = checkNotNull(w.engine.claimPayout("5" + "d".repeat(94)))
        val row = checkNotNull(w.purchase(pack.toByteArray()))
        val secrets = listOf(
            TestBytes.hex(pack.toByteArray()), TestBytes.hex(claim.toByteArray()), TestBytes.hex(row.seed()), TestBytes.hex(row.claimKey()),
            TestBytes.hex(row.invoiceId()), "5" + "d".repeat(94), instructions.subaddress, instructions.amountAtomic.toString(),
        ) + w.tokenRows("credit").flatMap { listOf(TestBytes.hex(it.nullifier()), TestBytes.hex(it.token())) }
        val printed = listOf(
            pack, claim, PurchaseId(TestBytes.of(16, 9)), ClaimId(TestBytes.of(16, 9)), instructions, w.engine.status(), row,
            w.tokenRows("credit").first(), w.engine, w.deps, w.ctx(), w.ctx().memory, PaymentInstructions("s".repeat(95), 1, 1, 1, "u"),
        ).joinToString("\n") { it.toString() }
        for (secret in secrets) assertFalse(secret, printed.contains(secret))
        assertFalse(printed.contains("u\n"))
    }
}
