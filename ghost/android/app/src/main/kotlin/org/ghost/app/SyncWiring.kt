package org.ghost.app

import org.ghost.sync.api.SyncController

/**
 * The app's sync decisions (design §5.4, §5.6, §11.2 #17, #18), free of Android types:
 *  - at every process start (after a reboot, an update or a force-stop too) the periodic job is
 *    ensured, but only when the database key envelope exists; ensuring reschedules only when the
 *    pending job is missing or differs, so the period timer is not reset;
 *  - right after the key is first created, the job is ensured and the database announced;
 *  - visibility starts and stops the foreground session and never schedules anything: no request
 *    and no wake-up is caused by user activity.
 */
internal class SyncWiring(
    private val keyExists: () -> Boolean,
    private val controller: SyncController,
    private val ensurePeriodic: () -> Unit,
    private val databaseAvailable: () -> Unit,
) {
    fun onProcessStart() {
        if (keyExists()) ensurePeriodic()
    }

    fun onKeyCreated() {
        ensurePeriodic()
        databaseAvailable()
    }

    fun onVisible() = controller.onAppForeground()

    fun onHidden() = controller.onAppBackground()

    override fun toString(): String = "SyncWiring"
}
