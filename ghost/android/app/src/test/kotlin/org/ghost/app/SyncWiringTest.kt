package org.ghost.app

import org.ghost.sync.android.DatabaseOpener
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.SyncController
import org.ghost.sync.api.SyncCounts
import org.ghost.sync.api.SyncStatus
import org.ghost.sync.api.TransportStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The app's sync decisions (design §5.4, §5.6, §11.1 Q6, §11.2 #17, #18): the periodic job is ensured
 * at process start only when the key envelope exists and right after the key is created, never
 * because of visibility; a background session never opens an auth-bound database.
 */
class SyncWiringTest {

    private class Events {
        val log = ArrayList<String>()
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
    }

    private fun wiring(events: Events, key: Boolean) = SyncWiring(
        keyExists = { key },
        controller = RecordingController(events),
        ensurePeriodic = { events.log += "ensurePeriodic" },
        databaseAvailable = { events.log += "available" },
    )

    @Test
    fun aProcessStartWithAKeyEnsuresThePeriodicJobOnce() {
        val events = Events()
        wiring(events, key = true).onProcessStart()
        assertEquals(listOf("ensurePeriodic"), events.log)
    }

    @Test
    fun aProcessStartWithoutAKeySchedulesNothing() {
        val events = Events()
        wiring(events, key = false).onProcessStart()
        assertEquals(emptyList<String>(), events.log)
    }

    @Test
    fun theFirstKeyEnsuresTheJobThenAnnouncesTheDatabase() {
        val events = Events()
        wiring(events, key = false).onKeyCreated()
        assertEquals(listOf("ensurePeriodic", "available"), events.log)
    }

    @Test
    fun visibilityDrivesTheForegroundSessionAndNeverSchedules() {
        val events = Events()
        val w = wiring(events, key = true)
        w.onVisible()
        w.onHidden()
        w.onVisible()
        assertEquals(listOf("foreground", "background", "foreground"), events.log)
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
