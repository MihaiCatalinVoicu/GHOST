package org.ghost.app.ui

/**
 * Phase 13 design §3.3 (X-U15): the hide duties — run at every hide (`onStop` that is not a
 * configuration change), whether or not the timeout will lock at the return. Screen models drop
 * their `UiState` and re-query on return; `GhostApp.onContentLock()` closes every open media
 * handle (a view-once handle closes as viewed), releases players, clears the preview cache and
 * sets the on-screen signal to null; the payment screen is hidden. The DM context, the database
 * and sync are untouched (X-U1). The composition shows the neutral curtain until the return.
 */
object ContentLock {
    private val listeners = mutableListOf<Listener>()

    interface Listener {
        /** Drop all content state; re-query on the next show. */
        fun onContentLock()
    }

    @Synchronized
    fun register(listener: Listener) {
        listeners.add(listener)
    }

    @Synchronized
    fun unregister(listener: Listener) {
        listeners.remove(listener)
    }

    /** Runs every registered listener's hide duties; called only from MainActivity.onStop. */
    @Synchronized
    fun lockContent() {
        for (l in listeners.toList()) l.onContentLock()
    }
}
