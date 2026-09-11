package org.ghost.sync.port

/** The one periodic background wake-up (JobScheduler in production, design §5.4). */
interface WakeScheduler {
    fun ensurePeriodic()

    fun cancel()
}
