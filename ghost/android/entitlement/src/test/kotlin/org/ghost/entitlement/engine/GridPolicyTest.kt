package org.ghost.entitlement.engine

import org.ghost.entitlement.T0
import org.ghost.entitlement.TestBytes
import org.ghost.entitlement.TestCrypto
import org.ghost.entitlement.TestRandom
import org.ghost.entitlement.WEEK0
import org.ghost.entitlement.store.TokenRow
import org.ghost.network.EntitlementCrypto
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.RelayId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The pure components of the engine: the grid and layout order (design §4.1–§4.3), prices and the
 * covering credit set (§4.6, §19.8), the fixed `BlindSign` attempt plan (§19.11), activation slots
 * (§12.3) and the relay-facing clock estimate (§12.5).
 */
class GridPolicyTest {

    @Test
    fun weeksStartOnMondayAndEpochsFollowTheGrid() {
        assertEquals(0L, Grid.week(345_600L))
        assertEquals(-1L, Grid.week(345_599L))
        assertEquals(WEEK0, Grid.week(T0))
        assertEquals(WEEK0, Grid.week(Grid.start(WEEK0)))
        assertEquals(WEEK0 - 1, Grid.week(Grid.start(WEEK0) - 1))
        // 1970-01-05 (day 4) is a Monday; every week starts on one.
        assertEquals(0L, Math.floorMod(Grid.day(Grid.start(WEEK0)) - 4, 7L))
        assertEquals(739L, Grid.inviteEpoch(WEEK0))
        assertEquals(227L, Grid.creditEpoch(WEEK0))
        assertEquals(Grid.creditEpoch(WEEK0), Grid.priceEpoch(WEEK0))
    }

    @Test
    fun packAndTrialLayoutsFollowTheScheduleOrder() {
        val s = TestCrypto().scheduleSummary()
        val xmr = Layouts.pack(s, WEEK0, xmr = true)
        // N = 16·S·5 + 2 + 1 with access_per_slot = 4 and S = 3 (the harness ES): 63.
        assertEquals(63, xmr.size)
        assertEquals(listOf(0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2), xmr.take(12).map { it.slot })
        assertTrue(xmr.take(12).all { it.kind == EntitlementCrypto.KIND_ACCESS && it.epoch == WEEK0 })
        assertEquals((0 until 5).flatMap { w -> List(12) { WEEK0 + w } }, xmr.take(60).map { it.epoch })
        assertTrue(xmr.subList(60, 62).all { it.kind == EntitlementCrypto.KIND_INVITE && it.epoch == 739L && it.slot == null })
        assertEquals(EntitlementCrypto.KIND_CREDIT, xmr.last().kind)
        assertEquals(227L, xmr.last().epoch)
        val credits = Layouts.pack(s, WEEK0, xmr = false)
        assertEquals(62, credits.size)
        assertEquals(EntitlementCrypto.KIND_INVITE, credits.last().kind)
        val trial = Layouts.trial(s, WEEK0)
        assertEquals(12, trial.size)
        assertEquals(List(6) { WEEK0 } + List(6) { WEEK0 + 1 }, trial.map { it.epoch })
    }

    private fun credit(epoch: Long, n: Int) =
        TokenRow(TestBytes.of(32, n), "credit", epoch, null, TestBytes.token(n), "fresh", 0, null, null, null, null, null)

    @Test
    fun theCoveringCreditSetIsTheSmallestOfAtLeastTen() {
        val crypto = TestCrypto()
        val s = crypto.scheduleSummary()
        val c = Grid.creditEpoch(WEEK0)
        assertEquals(10, Pricing.coveringSet(s, List(12) { credit(c, it) }, WEEK0, WEEK0)?.size)
        assertNull(Pricing.coveringSet(s, List(9) { credit(c, it) }, WEEK0, WEEK0))
        // Credits of the epoch c − 5 are no longer accepted (52–65 weeks of validity, §19.8).
        assertNull(Pricing.coveringSet(s, List(9) { credit(c, it) } + credit(c - 5, 99), WEEK0, WEEK0))
        assertEquals(10, Pricing.coveringSet(s, List(9) { credit(c, it) } + credit(c - 4, 99), WEEK0, WEEK0)?.size)
        // A price increase: credits keep the value of their own epoch, so 11 cover the new price.
        crypto.priceOverrides[c] = TestCrypto.PRICE * 11 / 10
        val raised = crypto.scheduleSummary()
        assertEquals(11, Pricing.coveringSet(raised, List(12) { credit(c - 1, it) }, WEEK0, WEEK0)?.size)
        // More than 20 needed: none.
        crypto.priceOverrides[c] = TestCrypto.PRICE * 21 / 10
        assertNull(Pricing.coveringSet(crypto.scheduleSummary(), List(30) { credit(c - 1, it) }, WEEK0, WEEK0))
    }

    @Test
    fun blindSignAttemptsFallInTheirWindowsAndDependOnTheSeedOnly() {
        val windows = listOf(3L to 5L, 44L to 52L, 100L to 112L, 168L to 192L, 480L to 528L)
        val receipt = T0 - T0 % 60
        for (i in 0 until 200) {
            val seed = TestBytes.of(32, i)
            var previous = receipt
            for (k in 0 until RetryPolicy.BLIND_SIGN_ATTEMPTS) {
                val due = RetryPolicy.blindSignDueMinute(seed, receipt, k)
                val (lo, hi) = windows[k]
                assertEquals(0L, due % 60)
                assertTrue("attempt $k early", due >= receipt + lo * 3600)
                assertTrue("attempt $k late", due <= receipt + hi * 3600 + 60)
                assertTrue(due > previous)
                previous = due
                assertEquals(due, RetryPolicy.blindSignDueMinute(seed, receipt, k))
            }
        }
        assertNotEquals(
            RetryPolicy.blindSignDueMinute(TestBytes.of(32, 1), receipt, 0),
            RetryPolicy.blindSignDueMinute(TestBytes.of(32, 2), receipt, 0),
        )
    }

    @Test
    fun failureCategoriesMapOntoFlowActions() {
        assertEquals(Failure.UNAUTHORIZED, RetryPolicy.classify("unauthorized"))
        for (c in listOf("rejected", "invalid_argument", "not_onion")) assertEquals(Failure.REJECTED, RetryPolicy.classify(c))
        assertEquals(Failure.MALFORMED, RetryPolicy.classify("malformed_response"))
        for (c in listOf("transport", "timeout", "relay_unavailable", "closed", "quota", "tor_bootstrap", "not_bootstrapped", "internal", "x")) {
            assertEquals(Failure.TRANSIENT, RetryPolicy.classify(c))
        }
    }

    @Test
    fun packTokensBecomeEligibleAtAnActivationSlot() {
        val r = TestRandom()
        // Wednesday 12:00: the first day boundary at or after 16:00 is Thursday 00:00.
        val thursday = Grid.start(WEEK0) + 3 * Grid.DAY
        r.uniformValue = 0.0
        assertEquals(thursday, Slots.packEligibleMinute(T0, r, PrivacyMode.STANDARD))
        r.uniformValue = 0.9999999
        val late = Slots.packEligibleMinute(T0, r, PrivacyMode.STANDARD)
        assertTrue(late in thursday until thursday + 6 * Grid.HOUR)
        assertEquals(0L, late % 60)
        // 21:00 + 4 h crosses midnight: Friday 00:00.
        r.uniformValue = 0.0
        assertEquals(thursday + Grid.DAY, Slots.packEligibleMinute(T0 + 9 * Grid.HOUR, r, PrivacyMode.STANDARD))
        // HIGH: Geometric(1/2) whole days first (two successes, then a stop), then the offset.
        r.uniforms.addAll(listOf(0.1, 0.2, 0.7, 0.5))
        assertEquals(thursday + 2 * Grid.DAY + 3 * Grid.HOUR, Slots.packEligibleMinute(T0, r, PrivacyMode.HIGH))
        // Trial tokens: at once in STANDARD, by the pack rule in HIGH.
        assertEquals(T0 - T0 % 60, Slots.trialEligibleMinute(T0 + 59, r, PrivacyMode.STANDARD))
        // HIGH: the geometric draw stops at once (0.9), then an offset of 0.
        r.uniforms.addAll(listOf(0.9, 0.0))
        assertEquals(thursday, Slots.trialEligibleMinute(T0, r, PrivacyMode.HIGH))
        // The extra days are capped, so a run of successes cannot push eligibility out of the pack's weeks.
        r.uniformValue = 0.0
        assertEquals(thursday + 16 * Grid.DAY, Slots.packEligibleMinute(T0, r, PrivacyMode.HIGH))
    }

    @Test
    fun theRelayClockNeedsTwoRelaysAndAdoptsAWrongPeriodWithinADay() {
        val clock = ClockEstimate()
        val a = RelayId(1)
        val b = RelayId(2)
        val c = RelayId(3)
        clock.record(a, T0 / 60 + 10, WEEK0, T0, wrongPeriod = false)
        assertEquals("one relay does not move the estimate", T0, clock.now(T0))
        clock.record(b, T0 / 60 + 20, WEEK0, T0, wrongPeriod = false)
        assertEquals(T0 + 15 * 60, clock.now(T0))
        clock.record(c, T0 / 60 - 100, WEEK0, T0, wrongPeriod = false)
        assertEquals(T0 + 10 * 60, clock.now(T0))
        // Twelve hours before the next week a relay answers WRONG_PERIOD in it: adopted for that relay.
        val late = Grid.start(WEEK0 + 1) - 12 * Grid.HOUR
        clock.record(a, late / 60 + 10, WEEK0 + 1, late, wrongPeriod = true)
        assertEquals(WEEK0 + 1, clock.week(a, late))
        assertEquals(WEEK0, clock.week(b, late))
        assertEquals("three and a half days before it starts, no honest relay is in it", WEEK0, clock.week(a, T0))
        clock.record(a, late / 60 + 10, WEEK0, late, wrongPeriod = false)
        assertEquals(WEEK0, clock.week(a, late))
    }

    @Test
    fun theRelayClockStaysWithinADayOfTheDeviceClock() {
        val clock = ClockEstimate()
        val fourWeeksMinutes = 4 * Grid.WEEK / 60
        clock.record(RelayId(1), T0 / 60 + fourWeeksMinutes, WEEK0 + 4, T0, wrongPeriod = false)
        clock.record(RelayId(2), T0 / 60 + fourWeeksMinutes, WEEK0 + 4, T0, wrongPeriod = false)
        assertEquals("relays four weeks ahead move the estimate by a day at most", T0 + Grid.DAY, clock.now(T0))
        clock.record(RelayId(1), Long.MIN_VALUE, WEEK0, T0, wrongPeriod = false)
        clock.record(RelayId(2), -1, WEEK0, T0, wrongPeriod = false)
        assertEquals(T0 - Grid.DAY, clock.now(T0))
        clock.record(RelayId(3), Long.MAX_VALUE, WEEK0 + 4, T0, wrongPeriod = true)
        assertEquals("a period four weeks ahead is not adopted", WEEK0, clock.week(RelayId(3), T0))
    }
}
