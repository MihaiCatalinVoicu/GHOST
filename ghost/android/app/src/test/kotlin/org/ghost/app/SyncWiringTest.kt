package org.ghost.app

import org.ghost.sync.android.DatabaseOpener
import org.ghost.sync.api.ParticipantSession
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.SessionParticipant
import org.ghost.sync.api.SyncController
import org.ghost.sync.api.SyncCounts
import org.ghost.sync.api.SyncStatus
import org.ghost.sync.api.TransportStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The app's sync decisions (design §5.4, §5.6, §11.1 Q6, §11.2 #17, #18; Phase 8 design §11.6,
 * §19.11): the entitlement participant is installed at every process start before anything else;
 * the payment-screen hold is restored before the periodic job is ensured, and only with a key; the
 * periodic job is ensured at process start only when the key envelope exists and right after the key
 * is created, never because of visibility; a background session never opens an auth-bound database.
 */
class SyncWiringTest {

    private class Events {
        val log = ArrayList<String>()
        var installed: SessionParticipant? = null
    }

    private class RecordingController(private val events: Events) : SyncController {
        override fun onAppForeground() {
            events.log += "foreground"
        }

        override fun onAppBackground() {
            events.log += "background"
        }

        override fun requestExpedite() {
            events.log += "expedite"
        }

        override fun setPrivacyMode(mode: PrivacyMode) {
            events.log += "mode"
        }

        override fun status(): SyncStatus = SyncStatus(TransportStatus.OFF, PrivacyMode.STANDARD, emptySet(), SyncCounts.EMPTY)

        override fun onWipe() {
            events.log += "wipe"
        }

        override fun setParticipant(p: SessionParticipant?) {
            events.installed = p
            events.log += "participant"
        }

        override fun runUserIssuerCall(block: (ParticipantSession) -> Unit) {
            events.log += "user-issuer-call"
        }

        override fun onPaymentScreenShown() {
            events.log += "payment-shown"
        }

        override fun onPaymentScreenHidden() {
            events.log += "payment-hidden"
        }

        override fun restorePaymentHold(lastShownEpochSeconds: Long) {
            events.log += "payment-hold:$lastShownEpochSeconds"
        }
    }

    private val participant = object : SessionParticipant {
        override fun onRelaySession(session: ParticipantSession) = Unit

        override fun onQuietRun(session: ParticipantSession) = Unit
    }

    /** [posted] receives the moment readers handed to the runtime thread (the runtime runs them in order). */
    private fun wiring(events: Events, key: Boolean, moment: Long? = null, posted: MutableList<() -> Long?> = ArrayList()) = SyncWiring(
        keyExists = { key },
        controller = RecordingController(events),
        ensurePeriodic = { events.log += "ensurePeriodic" },
        databaseAvailable = { events.log += "available" },
        participant = participant,
        paymentShownAt = {
            events.log += "moment"
            moment
        },
        restorePaymentHold = { read ->
            events.log += "hold-posted"
            posted += read
        },
        visible = { events.log += "entitlement-visible" },
        hidden = { events.log += "entitlement-hidden" },
    )

    @Test
    fun aProcessStartWithAKeyInstallsTheParticipantPostsTheHoldRestoreThenEnsuresTheJob() {
        val events = Events()
        val posted = ArrayList<() -> Long?>()
        wiring(events, key = true, moment = 1_789_560_060L, posted = posted).onProcessStart()
        // Reading the moment opens the database (Keystore, key derivation, migration): never on the
        // calling (main) thread. The runtime thread reads it, before any job or foreground command.
        assertEquals(listOf("participant", "hold-posted", "ensurePeriodic"), events.log)
        assertSame(participant, events.installed)
        assertEquals(1_789_560_060L, posted.single().invoke())
        assertEquals("moment", events.log.last())
    }

    @Test
    fun aProcessStartWithoutARememberedMomentRestoresNothing() {
        val events = Events()
        val posted = ArrayList<() -> Long?>()
        wiring(events, key = true, posted = posted).onProcessStart()
        assertEquals(listOf("participant", "hold-posted", "ensurePeriodic"), events.log)
        assertEquals(null, posted.single().invoke())
    }

    @Test
    fun aProcessStartWithoutAKeyOnlyInstallsTheParticipant() {
        val events = Events()
        val posted = ArrayList<() -> Long?>()
        wiring(events, key = false, moment = 60L, posted = posted).onProcessStart()
        assertEquals("no database is opened and nothing is scheduled", listOf("participant"), events.log)
        assertTrue(posted.isEmpty())
    }

    @Test
    fun theFirstKeyEnsuresTheJobThenAnnouncesTheDatabase() {
        val events = Events()
        wiring(events, key = false).onKeyCreated()
        assertEquals(listOf("ensurePeriodic", "available"), events.log)
    }

    @Test
    fun visibilityDrivesTheForegroundSessionAndThePendingTrialAndNeverSchedules() {
        val events = Events()
        val w = wiring(events, key = true)
        w.onVisible()
        w.onHidden()
        w.onVisible()
        // Hiding the app also tells the engine, which keeps the moment an open payment screen was last visible (§19.11).
        assertEquals(
            listOf("foreground", "entitlement-visible", "background", "entitlement-hidden", "foreground", "entitlement-visible"),
            events.log,
        )
    }

    @Test
    fun onlyAKeyThatExistsOpensAndAnAuthBoundKeyNeverOpensInTheBackground() {
        val fg = DatabaseOpener.Purpose.FOREGROUND
        val bg = DatabaseOpener.Purpose.BACKGROUND
        assertTrue(DatabaseAccess.mayOpen(fg, keyExists = true, authBound = false))
        assertTrue(DatabaseAccess.mayOpen(bg, keyExists = true, authBound = false))
        assertTrue(DatabaseAccess.mayOpen(fg, keyExists = true, authBound = true))
        assertFalse(DatabaseAccess.mayOpen(bg, keyExists = true, authBound = true))
        for (purpose in DatabaseOpener.Purpose.entries) {
            for (authBound in listOf(false, true)) assertFalse(DatabaseAccess.mayOpen(purpose, keyExists = false, authBound = authBound))
        }
        assertFalse("Phase 7 keeps the key unbound (Phase 4 default)", DatabaseAccess.AUTH_BOUND)
    }
}
