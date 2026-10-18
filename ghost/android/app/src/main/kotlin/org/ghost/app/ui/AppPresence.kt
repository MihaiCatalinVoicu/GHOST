package org.ghost.app.ui

/**
 * Phase 13 design §3.5 (D33, X-U14): the app's presence. HIDDEN — no GHOST window; VISIBLE — a
 * GHOST window shows (possibly the lock screen); INTERACTIVE — VISIBLE, the activity resumed and
 * unlocked (onboarding before a lock exists counts as unlocked). **Sessions follow
 * INTERACTIVE**: the foreground session's start and end are reported on the transitions into and
 * out of INTERACTIVE, never at VISIBLE — nothing syncs while only the lock screen shows.
 */
class AppPresence(private val listener: Listener) {
    enum class Presence { HIDDEN, VISIBLE, INTERACTIVE }

    interface Listener {
        /** Entered INTERACTIVE: the foreground session may start (after the link-open delay). */
        fun onInteractive()

        /** Left INTERACTIVE (hide or lock while visible): the foreground session ends. */
        fun onNotInteractive()
    }

    private var windowShown = false
    private var resumed = false
    private var unlocked = true

    var presence: Presence = Presence.HIDDEN
        private set

    private fun recompute() {
        val next = when {
            !windowShown -> Presence.HIDDEN
            resumed && unlocked -> Presence.INTERACTIVE
            else -> Presence.VISIBLE
        }
        val was = presence
        presence = next
        if (next == Presence.INTERACTIVE && was != Presence.INTERACTIVE) listener.onInteractive()
        if (next != Presence.INTERACTIVE && was == Presence.INTERACTIVE) listener.onNotInteractive()
    }

    /** ON_START of the activity (a configuration change re-triggers it; presence is idempotent). */
    fun onWindowShown() {
        windowShown = true
        recompute()
    }

    /** ON_STOP that is not a configuration change. */
    fun onWindowHidden() {
        windowShown = false
        resumed = false
        recompute()
    }

    /** The activity's onResume/onPause pair. */
    fun onResumed() {
        resumed = true
        recompute()
    }

    fun onPaused() {
        resumed = false
        recompute()
    }

    /** The lock state: only the PIN screen shows (or onboarding before a lock exists). */
    fun onLocked() {
        unlocked = false
        recompute()
    }

    fun onUnlocked() {
        unlocked = true
        recompute()
    }
}
