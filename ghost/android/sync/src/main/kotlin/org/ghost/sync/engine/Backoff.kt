package org.ghost.sync.engine

import org.ghost.sync.store.Time

/** Retry delays (design §3.7). Pure functions; the jitter is passed in by the caller. */
internal object Backoff {
    /** First retry delay, seconds. */
    const val BASE_SECONDS: Long = 60

    /** Longest delivery or fetch retry delay, seconds (the stores accept at most one hour). */
    const val MAX_SECONDS: Long = 3_600

    /** First transport recreation delay. */
    const val TRANSPORT_BASE_MILLIS: Long = 60_000

    /** Longest transport recreation delay. */
    const val TRANSPORT_MAX_MILLIS: Long = 15 * 60_000

    /**
     * Delivery and fetch backoff for the [attempt]-th attempt (1 = first):
     * `b(n) = min(60 s × 2^(n−1), 1 h) × U[0.5, 1]`, rounded up to the minute and never above one
     * hour. [u] is uniform in [0, 1) from the selection stream (never the read lane's).
     */
    fun retrySeconds(attempt: Int, u: Double): Long {
        require(attempt >= 1) { "attempt out of range" }
        require(u >= 0.0 && u < 1.0) { "jitter out of range" }
        val doublings = minOf(attempt - 1, 6)
        val base = minOf(BASE_SECONDS shl doublings, MAX_SECONDS)
        val jittered = Math.ceil(base * (0.5 + 0.5 * u)).toLong()
        return minOf(Time.ceilMinute(jittered), MAX_SECONDS)
    }

    /** Transport recreation after a failed bootstrap ([failures] ≥ 1 in a row): 1, 2, 4, 8, then 15 min. In memory only. */
    fun transportMillis(failures: Int): Long {
        require(failures >= 1) { "failures out of range" }
        val doublings = minOf(failures - 1, 4)
        return minOf(TRANSPORT_BASE_MILLIS shl doublings, TRANSPORT_MAX_MILLIS)
    }
}
