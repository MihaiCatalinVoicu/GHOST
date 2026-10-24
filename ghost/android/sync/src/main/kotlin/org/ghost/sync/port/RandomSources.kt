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

    /**
     * Uniform in [0,1) for the [index]-th periodic job run's update draw (Phase 14 design §7.3):
     * a run is an update run when the draw is `< 1/24` among the jobs that are not quiet. A pure
     * function of the key and [index] — nothing else is an input (no update state, no pending
     * work), so which jobs are update runs is independent of the client's activity (P-D1).
     */
    fun updateRun(index: Long): Double

    /**
     * 32 bytes for the [index]-th update run's mirror draw (Phase 14 design §7.8): the two
     * mirrors of the run are chosen from this, never from client state other than the root and
     * the manifest. Its own keyed domain, drawn once per run.
     */
    fun updateDrawBytes(index: Long): ByteArray

    /**
     * 16 bytes for the request id of one key registration (Phase 9 design §4.2): a fresh id per
     * registration, stored in its row so every retry of that registration sends the same one. Its
     * own stream, drawn on the work lane only (T19).
     */
    fun requestId(): ByteArray
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
