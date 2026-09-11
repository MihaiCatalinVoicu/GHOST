package org.ghost.sync.android

/**
 * The in-process driver while the app is visible (design §5.2, §5.4): the app's process lifecycle
 * (`ProcessLifecycleOwner` ON_START / ON_STOP, wired in the app) starts and stops the FOREGROUND
 * session through [SyncRuntime]. On ON_STOP the session stops taking items and the transport is
 * closed as soon as its calls in flight have finished (design §11.3). Expedite reaches only a
 * visible session, and only in STANDARD mode (the session checks the mode). Nothing is persisted.
 */
internal class ForegroundDriver(private val runtime: SyncRuntime) {
    @Volatile
    var visible: Boolean = false
        private set

    fun onAppForeground() {
        visible = true
        runtime.setForeground(true)
    }

    fun onAppBackground() {
        visible = false
        runtime.setForeground(false)
    }

    fun requestExpedite() {
        if (visible) runtime.expedite()
    }

    override fun toString(): String = "ForegroundDriver"
}
