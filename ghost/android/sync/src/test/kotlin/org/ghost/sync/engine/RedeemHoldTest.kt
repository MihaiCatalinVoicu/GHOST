package org.ghost.sync.engine

import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.CapabilityNeed
import org.ghost.sync.api.CapabilitySource
import org.ghost.sync.api.Consumer
import org.ghost.sync.port.SyncClock
import org.ghost.sync.store.Time
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.ghost.sync.api.SessionKind as ParticipantKind

/**
 * The redeem hold of a background relay session (Phase 8 design §17 Q29, §19.23 point 5): armed by the
 * count of pending write needs at the session's start alone, ended by the lane's first step or the
 * deadline; the participant's step reaches it through the session's redeem access. The runtime's use
 * of it is `SessionParticipantTest`.
 */
class RedeemHoldTest {

    @Test
    fun aHoldIsArmedByAPendingWriteNeedAndEndsAtTheFirstStepOrTheDeadline() {
        assertFalse(RedeemHold.background(0, 1_000).armed)
        assertFalse(RedeemHold.background(0, 1_000).holds(0))
        assertFalse(RedeemHold.none().holds(0))
        val h = RedeemHold.background(2, 1_000)
        assertTrue(h.armed)
        assertTrue(h.holds(999))
        assertFalse("never past the deadline", h.holds(1_000))
        assertTrue(h.stepDone())
        assertFalse(h.holds(0))
        assertFalse("only the first step counts", h.stepDone())
        assertThrows(IllegalArgumentException::class.java) { RedeemHold.background(-1, 1_000) }
    }

    /**
     * Phase 10 design §7.6: a registration capability is a write need of a REDEEM namespace for the redeem
     * hold, so a funder whose registration capabilities lapsed recovers in a background session, as an
     * owner whose write capabilities did. A read need alone arms nothing (Phase 8 Q34).
     */
    @Test
    fun aRegisterNeedArmsTheHoldAndAReadNeedAloneDoesNot() = EngineWorld().use { w ->
        val relays = w.relays(1, 2)
        val ns = w.namespace(1, relays, listen = true, consumer = Consumer.CHANNEL, capabilitySource = CapabilitySource.LOCAL)
        // A listened namespace with no credential: READ MISSING (LOCAL), which is no write need.
        assertEquals(listOf(CapabilityKind.READ), w.stores.capabilities.needed().map { it.kind }.distinct())
        assertEquals(0, RedeemHold.pendingWriteNeeds(w.stores))
        assertFalse(RedeemHold.background(RedeemHold.pendingWriteNeeds(w.stores), 1_000).armed)
        w.fund(ns)
        w.registration(relays[0], ns, Time.week(w.clock.epochSeconds()))
        val kinds = w.stores.capabilities.needed().map { it.kind }.toSet()
        assertEquals(setOf(CapabilityKind.READ, CapabilityKind.REGISTER), kinds)
        assertEquals("the REGISTER need and no other is counted", 1, RedeemHold.pendingWriteNeeds(w.stores))
        assertTrue(RedeemHold.background(RedeemHold.pendingWriteNeeds(w.stores), 1_000).armed)
    }

    /**
     * "A funder whose registration capabilities lapsed" (Phase 10 design §7.6; the review of S1a found the
     * note's claim covered only the capability that was never there): a held registration capability that is
     * rejected, exhausted or about to expire is a write need of a REDEEM namespace like one that is missing, so
     * a background session holds for the redemption in all four cases.
     */
    @Test
    fun aLapsedRegistrationCapabilityArmsTheHoldInEveryReason() = EngineWorld().use { w ->
        val relays = w.relays(1, 2, 3)
        val ns = w.namespace(1, relays, listen = false, consumer = Consumer.CHANNEL, capabilitySource = CapabilitySource.LOCAL)
        w.fund(ns)
        val week = Time.week(w.clock.epochSeconds())
        val healthy = Time.WEEK_ORIGIN + Time.WEEK * (week + 1) + Time.HOUR
        relays.forEach { w.capability(it, ns, CapabilityKind.REGISTER, seed = 1, expiresAt = healthy) }
        assertEquals("healthy registration capabilities are no need", 0, RedeemHold.pendingWriteNeeds(w.stores))
        fun armedBy(reason: CapabilityNeed.Reason) {
            val needs = w.stores.capabilities.needed()
            assertEquals(listOf(CapabilityKind.REGISTER to reason), needs.map { it.kind to it.reason })
            assertEquals("$reason is counted", 1, RedeemHold.pendingWriteNeeds(w.stores))
            assertTrue("$reason arms the hold", RedeemHold.background(RedeemHold.pendingWriteNeeds(w.stores), 1_000).armed)
        }
        // Expiring: inside the last 24 hours of its validity.
        w.capability(relays[0], ns, CapabilityKind.REGISTER, seed = 2, expiresAt = w.clock.epochSeconds() + 20 * 3_600)
        armedBy(CapabilityNeed.Reason.EXPIRING)
        // Rejected, then a new generation, then exhausted: the relay refused the token it was presented.
        w.capability(relays[0], ns, CapabilityKind.REGISTER, seed = 3, expiresAt = healthy)
        assertEquals(0, RedeemHold.pendingWriteNeeds(w.stores))
        w.tx { w.stores.capabilityStore.refuse(it, relays[0], ns, CapabilityKind.REGISTER, w.stores.capabilityStore.generation(it, relays[0], ns, CapabilityKind.REGISTER)!!, exhausted = false) }
        armedBy(CapabilityNeed.Reason.REJECTED)
        w.capability(relays[0], ns, CapabilityKind.REGISTER, seed = 4, expiresAt = healthy)
        w.tx { w.stores.capabilityStore.refuse(it, relays[0], ns, CapabilityKind.REGISTER, w.stores.capabilityStore.generation(it, relays[0], ns, CapabilityKind.REGISTER)!!, exhausted = true) }
        armedBy(CapabilityNeed.Reason.EXHAUSTED)
        // Renewed: nothing is pending, nothing is held.
        w.capability(relays[0], ns, CapabilityKind.REGISTER, seed = 5, expiresAt = healthy)
        assertEquals(0, RedeemHold.pendingWriteNeeds(w.stores))
        assertFalse(RedeemHold.background(RedeemHold.pendingWriteNeeds(w.stores), 1_000).armed)
    }

    @Test
    fun aRelaySessionHandsEveryReportedStepToTheHold() {
        val clock = object : SyncClock {
            override fun epochSeconds(): Long = 0

            override fun monotonicMillis(): Long = 0
        }
        val scheduler = QuietRunScheduler(KeyedRandomSources(ByteArray(32) { 3 }), clock)
        var steps = 0
        val background = scheduler.session(ParticipantKind.BACKGROUND, RecordingLease(), Long.MAX_VALUE, { true }, { false }) { steps++ }
        checkNotNull(background.relayRedeem).stepDone()
        checkNotNull(background.relayRedeem).stepDone()
        assertEquals(2, steps)
        // A quiet run has no redeem access, so nothing it does can end a hold.
        assertNull(scheduler.session(ParticipantKind.QUIET, RecordingLease(), Long.MAX_VALUE, { true }, { false }) { steps++ }.relayRedeem)
        // Without a hold (the default), a reported step does nothing.
        checkNotNull(scheduler.session(ParticipantKind.FOREGROUND, RecordingLease(), Long.MAX_VALUE, { true }, { false }).relayRedeem).stepDone()
        assertEquals(2, steps)
    }
}
