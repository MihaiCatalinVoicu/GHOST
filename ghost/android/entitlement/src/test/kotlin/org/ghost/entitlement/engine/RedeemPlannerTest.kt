package org.ghost.entitlement.engine

import org.ghost.entitlement.T0
import org.ghost.entitlement.TestBytes
import org.ghost.entitlement.TestCrypto
import org.ghost.entitlement.TestOnions
import org.ghost.entitlement.TestRandom
import org.ghost.entitlement.WEEK0
import org.ghost.entitlement.store.SyncTables
import org.ghost.network.EntitlementCrypto
import org.ghost.network.OnionAddress
import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.CapabilityNeed
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.RelayId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/** The redemption timing table of design §12.4 and the slot binding of §19.22 point 3. */
class RedeemPlannerTest {
    private val crypto = TestCrypto()
    private val summary = crypto.scheduleSummary()
    private val random = TestRandom()
    private val planner = RedeemPlanner(random)
    private val relay = SyncTables.Relay(RelayId(1), crypto.onions[1], ByteArray(16), active = true)
    private val ns = NamespaceId(TestBytes.of(32, 1))

    private fun need(kind: CapabilityKind, reason: CapabilityNeed.Reason) = CapabilityNeed(RelayId(1), ns, kind, reason)

    private fun plan(
        need: CapabilityNeed,
        now: Long = T0,
        trusted: Boolean = true,
        firstSeen: Long = now,
        writeExpiry: Long? = null,
        on: SyncTables.Relay? = relay,
    ) = planner.plan(need, on, summary, now, Grid.week(now), trusted, firstSeen, writeExpiry)

    @Test
    fun writeMissingExhaustedAndRejectedRedeemTheCurrentWeekAtOnce() {
        for (reason in listOf(CapabilityNeed.Reason.MISSING, CapabilityNeed.Reason.EXHAUSTED, CapabilityNeed.Reason.REJECTED)) {
            val d = plan(need(CapabilityKind.WRITE, reason)) as RedeemPlanner.Decision.Redeem
            assertEquals(WEEK0, d.week)
            assertEquals(listOf(1), d.slots)
            assertEquals(T0, d.dueSeconds)
        }
    }

    @Test
    fun readMissingWaitsAPrfDelayWithinSixHoursOfFirstSight() {
        random.prfValue = 0.5
        val d = plan(need(CapabilityKind.READ, CapabilityNeed.Reason.MISSING), firstSeen = T0 - 3600) as RedeemPlanner.Decision.Redeem
        assertEquals(T0 - 3600 + 3 * 3600, d.dueSeconds)
        assertEquals(WEEK0, d.week)
    }

    @Test
    fun expiringInTheLastDayRedeemsTheNextWeekInsideItsWindow() {
        val next = Grid.start(WEEK0 + 1)
        for (u in listOf(0.0, 0.5, 0.9999)) {
            random.prfValue = u
            val d = plan(need(CapabilityKind.WRITE, CapabilityNeed.Reason.EXPIRING), now = next - 20 * 3600) as RedeemPlanner.Decision.Redeem
            assertEquals(WEEK0 + 1, d.week)
            assertTrue(d.dueSeconds >= next - 23 * 3600 && d.dueSeconds <= next - 3600)
        }
        // An expiring capability that is not week-aligned (earlier in the week): the current week, at once.
        val early = plan(need(CapabilityKind.READ, CapabilityNeed.Reason.EXPIRING)) as RedeemPlanner.Decision.Redeem
        assertEquals(WEEK0, early.week)
        assertEquals(T0, early.dueSeconds)
    }

    @Test
    fun nothingIsRedeemedWithoutATrustedClockOrNearAWeekBoundary() {
        val write = need(CapabilityKind.WRITE, CapabilityNeed.Reason.MISSING)
        assertSame(RedeemPlanner.Decision.Deferred, plan(write, trusted = false))
        val start = Grid.start(WEEK0)
        assertSame(RedeemPlanner.Decision.Deferred, plan(write, now = start + 3599))
        assertSame(RedeemPlanner.Decision.Deferred, plan(write, now = start - 1))
        assertSame(RedeemPlanner.Decision.Deferred, plan(write, now = Grid.start(WEEK0 + 1) - 3599))
        assertTrue(plan(write, now = start + 3600) is RedeemPlanner.Decision.Redeem)
        assertTrue(RedeemPlanner.nearBoundary(start))
        assertFalse(RedeemPlanner.nearBoundary(T0))
    }

    @Test
    fun aRelayInNoSlotIsNeverRedeemedAndAnInactiveOneIsSkipped() {
        val write = need(CapabilityKind.WRITE, CapabilityNeed.Reason.MISSING)
        val outsider = SyncTables.Relay(RelayId(9), TestOnions.of(9), ByteArray(16), active = true)
        assertSame(RedeemPlanner.Decision.NoSlot, plan(write, on = outsider))
        assertSame(RedeemPlanner.Decision.Skip, plan(write, on = null))
    }

    @Test
    fun aReadNeedCoveredByAWriteCapabilityIsSkipped() {
        val read = need(CapabilityKind.READ, CapabilityNeed.Reason.MISSING)
        random.prfValue = 0.0
        assertSame(RedeemPlanner.Decision.Skip, plan(read, writeExpiry = Grid.start(WEEK0 + 1) + 3600))
        assertTrue(plan(read, writeExpiry = Grid.start(WEEK0 + 1) - 3600) is RedeemPlanner.Decision.Redeem)
    }

    @Test
    fun aRelayIsBoundByItsExactOnionFirstThenByItsSingleServiceKeySlot() {
        val base = TestOnions.of(5)
        val other = OnionAddress.parse(base.host + ":8443")
        val slots = listOf(
            EntitlementCrypto.Slot(4, 0, 0, base),
            EntitlementCrypto.Slot(7, 0, 0, TestOnions.of(6)),
        )
        crypto.slots = slots
        val s = crypto.scheduleSummary()
        assertEquals(listOf(4), RedeemPlanner.slotsFor(s, base, WEEK0))
        assertEquals("the single slot under the service key", listOf(4), RedeemPlanner.slotsFor(s, other, WEEK0))
        crypto.slots = slots + EntitlementCrypto.Slot(8, 0, 0, OnionAddress.parse(base.host + ":9443"))
        val two = crypto.scheduleSummary()
        assertEquals(listOf(4), RedeemPlanner.slotsFor(two, base, WEEK0))
        assertEquals("a key with several slots and an unlisted port serves none", emptyList<Int>(), RedeemPlanner.slotsFor(two, other, WEEK0))
        // Slot validity is per week.
        crypto.slots = listOf(EntitlementCrypto.Slot(4, WEEK0 + 1, 0, base))
        assertEquals(emptyList<Int>(), RedeemPlanner.slotsFor(crypto.scheduleSummary(), base, WEEK0))
        assertEquals(listOf(4), RedeemPlanner.slotsFor(crypto.scheduleSummary(), base, WEEK0 + 1))
    }
}
