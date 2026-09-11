package org.ghost.sync.api

/** Process-level control of sync; the Android implementation is wired by the app (design §5.4). */
interface SyncController {
    fun onAppForeground()

    fun onAppBackground()

    /** STANDARD mode only: wakes the work lane for due stores; never creates read events. */
    fun requestExpedite()

    fun setPrivacyMode(mode: PrivacyMode)

    /** Counts and enums only. */
    fun status(): SyncStatus

    /** The local data was wiped: cancel the periodic job and stop every session (design §11.2 #17). */
    fun onWipe()
}
