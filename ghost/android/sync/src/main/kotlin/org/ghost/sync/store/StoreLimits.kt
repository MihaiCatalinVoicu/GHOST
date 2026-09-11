package org.ghost.sync.store

/** Bounds the stores enforce themselves (design §3, §4, §11.2 #1–#3). */
object StoreLimits {
    /** ADR-11 quorum: distinct operators with verified copies for `sent`, and needed at enqueue. */
    const val QUORUM: Int = 2

    /** HIGH-mode send delay upper bound, U[0, 10 min] (ADR-15). */
    const val SEND_DELAY_MAX_SECONDS: Long = 600

    /**
     * Fetched rows per namespace that throttle further fetches; only rows that are due for an offer
     * and not suspect count (offers < 3, §11.2 #1).
     */
    const val FETCHED_CAP: Int = 256

    /** Listed + unavailable rows per (relay, namespace) with that relay as a candidate (§11.2 #2). */
    const val BACKLOG_CAP: Int = 4096

    /** Largest `check` batch. */
    const val CHECK_BATCH: Int = 64

    /** A fetched row offered this many times is suspect and is claimed alone (§11.2 #3). */
    const val SUSPECT_OFFERS: Int = 2

    /** From this many offers on, a claim also backs the row off (1 h, 2 h, ... 24 h). */
    const val BACKOFF_OFFERS: Int = 3

    /** Longest claim backoff. */
    const val MAX_OFFER_BACKOFF_SECONDS: Long = 24 * 3600

    /** Longest `defer`. */
    const val MAX_DEFER_SECONDS: Int = 7 * 86_400

    /** A `not_found` source is retried once, at least this long after the first answer (§11.3). */
    const val NOT_FOUND_RETRY_SECONDS: Long = 3600

    /** Relay cursors are empty ("caught up", never stored) or exactly this long. */
    const val CURSOR_SIZE: Int = 8
}
