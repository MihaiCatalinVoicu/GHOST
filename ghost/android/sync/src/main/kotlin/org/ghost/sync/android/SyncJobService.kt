package org.ghost.sync.android

import android.app.job.JobParameters
import android.app.job.JobService

/**
 * The background wake-up (design §5.4, ADR-20): the one periodic job scheduled by
 * [JobSchedulerWake]. Declared in the app manifest, not exported and protected by
 * `BIND_JOB_SERVICE` (design §5.5).
 *
 *  - [onStartJob]: without a database key envelope the job cancels itself and returns (design
 *    §11.2 #17). Otherwise it posts a BACKGROUND session to the runtime thread and returns true.
 *    The runtime reports the end with `jobFinished(params, false)` in every case, so JobScheduler's
 *    backoff never ties timing to failures: after the session, at once while the app is visible,
 *    and at once when the database cannot be opened in the background (Q6: no network I/O).
 *  - [onStopJob]: aborts the transport (calls in flight end with `closed`, an ambiguous result the
 *    next session resolves) and stops the session. The periodic job keeps its schedule.
 */
class SyncJobService : JobService() {
    @Volatile
    private var ticket: JobTicket? = null

    override fun onStartJob(params: JobParameters): Boolean {
        val controller = (application as? SyncHost)?.syncController
        if (controller == null) {
            // No sync runtime in this app process: nothing could ever run.
            JobSchedulerWake(this).cancel()
            return false
        }
        if (!controller.databaseKeyExists()) {
            controller.cancelPeriodic()
            return false
        }
        ticket = controller.startBackgroundJob { jobFinished(params, false) }
        return true
    }

    override fun onStopJob(params: JobParameters): Boolean {
        val current = ticket
        ticket = null
        if (current != null) (application as? SyncHost)?.syncController?.stopBackgroundJob(current)
        return false
    }
}
