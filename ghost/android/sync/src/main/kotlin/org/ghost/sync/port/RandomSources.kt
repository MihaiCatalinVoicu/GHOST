package org.ghost.sync.port

import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.RelayId

/**
 * Keyed PRF streams. Production (`org.ghost.sync.engine.KeyedRandomSources`): a 32-byte key from
 * SecureRandom, fresh per process and never persisted; HmacSHA256 (platform JCA).
 *
 * The read lane uses only [schedule] and [readBreaker], which are pure functions of the key and
 * their arguments; it never draws from the shared [sendDelay] or [selection] streams, so nothing
 * the work lane or a consumer does can change a read-lane value (T19).
 */
interface RandomSources {
    /** Uniform in [0,1) for (pair, purpose, index); independent of everything else (T19). */
    fun schedule(pair: PairKey, purpose: SchedulePurpose, index: Long): Double

    /** Uniform in [0,1) for the read-lane breaker of [relay], its [index]-th opening (T19). */
    fun readBreaker(relay: RelayId, index: Long): Double

    /** HIGH-mode send delay, sampled once per op at enqueue. */
    fun sendDelay(): Double

    /** Backoff jitter, candidate choice. Never used by the read lane. */
    fun selection(): Double

    /**
     * Uniform in [0,1) for the [index]-th periodic job run of the process: the quiet-run draw (Phase 8
     * design §12.2, §19.14). A pure function of the key and [index], so the pattern of quiet runs
     * depends on nothing else (no entitlement state, no issuer answer, no sync activity).
     */
    fun quietRun(index: Long): Double

    /** Uniform in [0,1) for the [index]-th payment-screen hold of relay sessions (Phase 8 design §19.11). */
    fun paymentHold(index: Long): Double
}

enum class SchedulePurpose {
    /** Phase of a pair's first foreground event (index 0). */
    FOREGROUND_START,

    /** Step k → k + 1 of a pair's foreground schedule. */
    FOREGROUND_STEP,

    /** Offset of a pair's event within a background job's window (index = job). */
    BACKGROUND_OFFSET,

    /** Rank of a pair for the round-robin groups beyond the read-pair cap (design §11.2 #12). */
    ROUND_ROBIN,
}

/** A (relay, namespace) pair; content equality, redacted toString (T3). */
class PairKey(val relayId: RelayId, val namespace: NamespaceId) {
    override fun equals(other: Any?): Boolean = other is PairKey && other.relayId == relayId && other.namespace == namespace

    override fun hashCode(): Int = relayId.hashCode() * 31 + namespace.hashCode()

    override fun toString(): String = "PairKey(redacted)"
}
