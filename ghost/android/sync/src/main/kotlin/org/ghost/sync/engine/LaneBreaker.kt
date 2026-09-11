package org.ghost.sync.engine

import org.ghost.sync.api.RelayId

/**
 * Circuit breaker of one lane, per relay, in memory only (design §3.7, §11.2 #13). It opens when a
 * relay's failure count reaches [THRESHOLD], for `min(60 s × 2^(failures−3), 30 min) × U[0.75, 1.25]`;
 * any success resets it. After an opening a call is allowed again; its failure reopens the breaker
 * for longer. The read lane's breaker counts first-page list outcomes only, so nothing the work
 * lane does can open it (T19); its jitter comes from the keyed read-breaker stream.
 *
 * Thread-safe: read-lane workers of different pairs of one relay share it.
 */
internal class LaneBreaker(private val jitter: (RelayId, Long) -> Double) {
    private class State {
        var failures = 0
        var openUntil = Long.MIN_VALUE
        var openings = 0L
    }

    private val states = HashMap<Long, State>()

    /** True if a call to [relay] may be made at monotonic time [now]. */
    @Synchronized
    fun allows(relay: RelayId, now: Long): Boolean {
        val state = states[relay.value] ?: return true
        return now >= state.openUntil
    }

    /** Monotonic time until which calls to [relay] are held, or null when the breaker is closed. */
    @Synchronized
    fun openUntil(relay: RelayId, now: Long): Long? {
        val until = states[relay.value]?.openUntil ?: return null
        return if (until > now) until else null
    }

    @Synchronized
    fun success(relay: RelayId) {
        states.remove(relay.value)
    }

    /** Adds [weight] failures (1 or 2, design §3.6) at monotonic time [now]. */
    @Synchronized
    fun failure(relay: RelayId, weight: Int, now: Long) {
        require(weight >= 1) { "failure weight out of range" }
        val state = states.getOrPut(relay.value) { State() }
        state.failures += weight
        if (state.failures >= THRESHOLD) {
            state.openUntil = now + openMillis(state.failures, jitter(relay, state.openings))
            state.openings++
        }
    }

    /** Failures currently counted for [relay] (tests and status). */
    @Synchronized
    fun failures(relay: RelayId): Int = states[relay.value]?.failures ?: 0

    override fun toString(): String = "LaneBreaker"

    companion object {
        const val THRESHOLD: Int = 3
        const val BASE_MILLIS: Long = 60_000
        const val MAX_MILLIS: Long = 30 * 60_000

        /** Opening for a failure count ≥ [THRESHOLD] and a jitter [u] in [0, 1). */
        fun openMillis(failures: Int, u: Double): Long {
            require(failures >= THRESHOLD) { "breaker is not open" }
            require(u >= 0.0 && u < 1.0) { "jitter out of range" }
            val doublings = minOf(failures - THRESHOLD, 5)
            val base = minOf(BASE_MILLIS shl doublings, MAX_MILLIS)
            return (base * (0.75 + 0.5 * u)).toLong()
        }
    }
}
