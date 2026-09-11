package org.ghost.sync.port

/** Wall clock (unix seconds, persisted only at minute/hour/day granularity) and monotonic time. */
interface SyncClock {
    fun epochSeconds(): Long

    fun monotonicMillis(): Long
}
