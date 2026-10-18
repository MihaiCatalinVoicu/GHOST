package org.ghost.app.ui

import java.util.concurrent.CopyOnWriteArrayList
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Phase 13 design §3.5 (D33, PM-U29): sessions follow INTERACTIVE — the foreground session
 * starts only when a GHOST window shows, the activity is resumed AND the app is unlocked; an
 * open that shows only the lock screen causes no session.
 */
class AppPresenceTest {
    private class RecordingListener : AppPresence.Listener {
        val interactiveStarts = CopyOnWriteArrayList<String>()
        val interactiveEnds = CopyOnWriteArrayList<String>()
        override fun onInteractive() { interactiveStarts.add("x") }
        override fun onNotInteractive() { interactiveEnds.add("x") }
    }

    @Test
    fun hiddenToVisibleToInteractive() {
        val l = RecordingListener()
        val p = AppPresence(l)
        assertEquals(AppPresence.Presence.HIDDEN, p.presence)
        p.onWindowShown()
        assertEquals(AppPresence.Presence.VISIBLE, p.presence)
        assertEquals(0, l.interactiveStarts.size)
        p.onResumed()
        // Onboarding before a lock exists counts as unlocked.
        assertEquals(AppPresence.Presence.INTERACTIVE, p.presence)
        assertEquals(1, l.interactiveStarts.size)
        p.onPaused()
        assertEquals(AppPresence.Presence.VISIBLE, p.presence)
        assertEquals(1, l.interactiveEnds.size)
        p.onWindowHidden()
        assertEquals(AppPresence.Presence.HIDDEN, p.presence)
    }

    @Test
    fun theLockScreenShowsNoSession() {
        val l = RecordingListener()
        val p = AppPresence(l)
        p.onLocked()
        p.onWindowShown()
        p.onResumed()
        // Only the lock screen: VISIBLE, never INTERACTIVE (PM-U29: an open by the launcher or
        // a ghost:// link causes no onAppForeground while the lock screen shows).
        assertEquals(AppPresence.Presence.VISIBLE, p.presence)
        assertEquals(0, l.interactiveStarts.size)
        // The unlock starts the session.
        p.onUnlocked()
        assertEquals(AppPresence.Presence.INTERACTIVE, p.presence)
        assertEquals(1, l.interactiveStarts.size)
        // A lock while visible ends the session at once.
        p.onLocked()
        assertEquals(AppPresence.Presence.VISIBLE, p.presence)
        assertEquals(1, l.interactiveEnds.size)
    }

    @Test
    fun repeatedEventsAreIdempotent() {
        val l = RecordingListener()
        val p = AppPresence(l)
        p.onWindowShown()
        p.onWindowShown()
        p.onResumed()
        p.onResumed()
        assertEquals(1, l.interactiveStarts.size)
        p.onWindowHidden()
        p.onWindowHidden()
        assertEquals(1, l.interactiveEnds.size)
    }
}
