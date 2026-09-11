package org.ghost.sync.port

enum class TransportState { READY, UNAVAILABLE, BRIDGE_CONFIG, FAILED }

interface TransportPort {
    /**
     * Creates/bootstraps if needed; never blocks past the deadline (bootstrap is bounded at 180 s
     * natively). After [abort] it creates a fresh transport (new circuits).
     */
    fun ensureReady(deadlineMonotonicMillis: Long): TransportState

    val relays: RelayPort

    /**
     * Any thread (onStopJob, a failed bootstrap, the end of a session): closes the current
     * transport; in-flight calls end with `closed`, and the next [ensureReady] creates a new one.
     */
    fun abort()
}
