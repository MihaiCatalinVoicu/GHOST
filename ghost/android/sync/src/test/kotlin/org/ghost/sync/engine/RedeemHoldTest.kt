package org.ghost.sync.engine

import org.ghost.sync.port.SyncClock
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
