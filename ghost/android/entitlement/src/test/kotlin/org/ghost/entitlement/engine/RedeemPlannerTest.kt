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
import org.ghost.sync.api.CapabilitySource
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
    fun anyNeedIsSkippedWhileAUsableWriteCapabilityReachesTheEndOfTheTargetWeek() {
        random.prfValue = 0.0
        val aligned = Grid.start(WEEK0 + 1) + 3600
        // Earlier than the renewal window, a week-aligned write capability cannot be extended by a
        // current-week token (the relay dates it to the token's week): nothing is redeemed.
        for (kind in CapabilityKind.entries) {
            assertSame(RedeemPlanner.Decision.Skip, plan(need(kind, CapabilityNeed.Reason.EXPIRING), writeExpiry = aligned))
        }
        // Inside the window the target is the next week, which the capability does not reach.
        val renewal = plan(need(CapabilityKind.WRITE, CapabilityNeed.Reason.EXPIRING), now = Grid.start(WEEK0 + 1) - 20 * 3600, writeExpiry = aligned)
        assertEquals(WEEK0 + 1, (renewal as RedeemPlanner.Decision.Redeem).week)
        // A capability that ends before the week does is renewed with a current-week token at once.
        val early = plan(need(CapabilityKind.WRITE, CapabilityNeed.Reason.EXPIRING), writeExpiry = T0 + 3600) as RedeemPlanner.Decision.Redeem
        assertEquals(WEEK0, early.week)
    }

    /**
     * A LOCAL namespace installs its own bearer credentials (Phase 9 design §13.3 item 3), so the
     * planner never redeems for it: a contact's inbox or bundle costs no access token (§4.8 token
     * accounting; mutant PM-1b). The decision comes before every other, so no token is reserved and
     * no unmet need of it raises ENTITLEMENT_NEEDED.
     */
    @Test
    fun aLocalNeedIsSkippedWhateverItsKindReasonOrClock() {
        for (kind in listOf(CapabilityKind.WRITE, CapabilityKind.READ)) {
            for (reason in CapabilityNeed.Reason.entries) {
                val local = CapabilityNeed(RelayId(1), ns, kind, reason, CapabilitySource.LOCAL)
                assertSame("$kind $reason", RedeemPlanner.Decision.LocalSkipped, plan(local))
                assertSame("$kind $reason untrusted", RedeemPlanner.Decision.LocalSkipped, plan(local, trusted = false))
                assertSame("$kind $reason without a relay", RedeemPlanner.Decision.LocalSkipped, plan(local, on = null))
                // The same need on a REDEEM namespace is planned as before.
                assertTrue("$kind $reason redeem", plan(CapabilityNeed(RelayId(1), ns, kind, reason)) !is RedeemPlanner.Decision.LocalSkipped)
            }
        }
    }

    /**
     * Phase 10 design §7.5, §7.6: a REGISTER need is planned as a WRITE need of a REDEEM namespace —
     * the sync layer reports it with source REDEEM although the funded channel's own source is LOCAL —
     * so MISSING, EXHAUSTED and REJECTED redeem the current week at once and EXPIRING renews inside the
     * last 23 hours; the clock guard, the slot binding and the missing relay behave as for every need.
     */
    @Test
    fun aRegisterNeedIsPlannedAsAWriteNeedOfARedeemNamespace() {
        for (reason in listOf(CapabilityNeed.Reason.MISSING, CapabilityNeed.Reason.EXHAUSTED, CapabilityNeed.Reason.REJECTED)) {
            val d = plan(need(CapabilityKind.REGISTER, reason)) as RedeemPlanner.Decision.Redeem
            assertEquals(reason.toString(), WEEK0, d.week)
            assertEquals(listOf(1), d.slots)
            assertEquals(T0, d.dueSeconds)
        }
        val next = Grid.start(WEEK0 + 1)
        for (u in listOf(0.0, 0.5, 0.9999)) {
            random.prfValue = u
            val d = plan(need(CapabilityKind.REGISTER, CapabilityNeed.Reason.EXPIRING), now = next - 20 * 3600) as RedeemPlanner.Decision.Redeem
            assertEquals(WEEK0 + 1, d.week)
            assertTrue(d.dueSeconds >= next - 23 * 3600 && d.dueSeconds <= next - 3600)
        }
        // An expiring registration capability earlier in the week is renewed with a current-week token at once.
        val early = plan(need(CapabilityKind.REGISTER, CapabilityNeed.Reason.EXPIRING)) as RedeemPlanner.Decision.Redeem
        assertEquals(WEEK0, early.week)
        assertEquals(T0, early.dueSeconds)
        val register = need(CapabilityKind.REGISTER, CapabilityNeed.Reason.MISSING)
        assertSame(RedeemPlanner.Decision.Deferred, plan(register, trusted = false))
        assertSame(RedeemPlanner.Decision.Deferred, plan(register, now = Grid.start(WEEK0) + 3599))
        assertSame(RedeemPlanner.Decision.Skip, plan(register, on = null))
        val outsider = SyncTables.Relay(RelayId(9), TestOnions.of(9), ByteArray(16), active = true)
        assertSame(RedeemPlanner.Decision.NoSlot, plan(register, on = outsider))
        // The need is the sync layer's to mark: one that came marked LOCAL is skipped like any LOCAL need.
        assertSame(
            RedeemPlanner.Decision.LocalSkipped,
            plan(CapabilityNeed(RelayId(1), ns, CapabilityKind.REGISTER, CapabilityNeed.Reason.MISSING, CapabilitySource.LOCAL)),
        )
    }

    /** The covering capability a caller passes is the pair's own class: a registration capability reaching past the week covers a REGISTER need. */
    @Test
    fun aRegisterNeedIsCoveredByTheExpiryThePlannerIsGiven() {
        random.prfValue = 0.0
        val reaching = Grid.start(WEEK0 + 1) + 3600
        assertSame(RedeemPlanner.Decision.Skip, plan(need(CapabilityKind.REGISTER, CapabilityNeed.Reason.EXPIRING), writeExpiry = reaching))
        assertTrue(plan(need(CapabilityKind.REGISTER, CapabilityNeed.Reason.EXPIRING), writeExpiry = T0 + 3600) is RedeemPlanner.Decision.Redeem)
        // The renewal window targets the next week, which a capability of this week does not reach.
        val renewal = plan(need(CapabilityKind.REGISTER, CapabilityNeed.Reason.EXPIRING), now = Grid.start(WEEK0 + 1) - 20 * 3600, writeExpiry = reaching)
        assertEquals(WEEK0 + 1, (renewal as RedeemPlanner.Decision.Redeem).week)
    }

    /** The PRF input of a REGISTER need carries its own kind byte, so the three kinds of one pair draw their own times. */
    @Test
    fun theThreeKindsOfOnePairDrawTheirOwnRenewalTimes() {
        random.prfValue = null
        val next = Grid.start(WEEK0 + 1)
        val due = CapabilityKind.entries.map { kind ->
            val d = plan(need(kind, CapabilityNeed.Reason.EXPIRING), now = next - 20 * 3600) as RedeemPlanner.Decision.Redeem
            assertTrue(kind.toString(), d.dueSeconds >= next - 23 * 3600 && d.dueSeconds <= next - 3600)
            d.dueSeconds
        }
        assertEquals("READ, WRITE and REGISTER draw three different times", 3, due.toSet().size)
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
