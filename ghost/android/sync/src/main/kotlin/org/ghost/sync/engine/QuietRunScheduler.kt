package org.ghost.sync.engine

import org.ghost.sync.api.ParticipantSession
import org.ghost.sync.port.RandomSources
import org.ghost.sync.port.SyncClock
import org.ghost.sync.port.TransportLease
import org.ghost.sync.api.SessionKind as ParticipantKind

/**
 * The participant's schedule, from client randomness only (Phase 8 design §11.6, §12.2, §19.11,
 * §19.14). Pure JVM; the Android runtime uses it, and the `:entitlement` worlds (NI-K, J9) drive
 * this same component.
 *
 *  - [quiet]: whether a periodic job run is quiet. One run in 8, a PRF of the process's random key
 *    and the run's index only ([RandomSources.quietRun]). Nothing else is an input: not entitlement
 *    state, not pending work, not an issuer answer, so the pattern of quiet runs is independent of
 *    all of them (NI-K, J9, mutant M20). Foreground sessions are never quiet (the runtime asks only
 *    at a job's start).
 *  - [session]: what a participant may reach in each kind of session. Issuer access only in QUIET
 *    and USER_ISSUER_CALL sessions, at most one call each, on a fresh flow; redemption only in
 *    FOREGROUND and BACKGROUND relay sessions (P-7).
 *  - [paymentHoldMillis]: how long relay sessions stay held after the payment screen was last
 *    shown, U[20 min, 60 min] (§19.11).
 */
class QuietRunScheduler(private val random: RandomSources, private val clock: SyncClock) {

    /** Whether the [index]-th periodic job run of this process is quiet (probability [QUIET_PROBABILITY]). */
    fun quiet(index: Long): Boolean {
        require(index >= 0) { "run index out of range" }
        return random.quietRun(index) < QUIET_PROBABILITY
    }

    /** Hold of relay sessions after the [index]-th hiding of the payment screen, in ms. */
    fun paymentHoldMillis(index: Long): Long {
        require(index >= 0) { "hold index out of range" }
        val span = PAYMENT_HOLD_MAX_MILLIS - PAYMENT_HOLD_MIN_MILLIS
        return PAYMENT_HOLD_MIN_MILLIS + minOf(span - 1, (random.paymentHold(index) * span).toLong())
    }

    /**
     * The participant's view of one activity over [lease]: accesses granted by [kind], calls cut to
     * [deadlineMonotonicMillis]. [clockTrusted] is the engine's clock trust; [inTransaction] tells
     * whether the calling thread is inside a sync transaction (such a call is refused).
     */
    fun session(
        kind: ParticipantKind,
        lease: TransportLease,
        deadlineMonotonicMillis: Long,
        clockTrusted: () -> Boolean,
        inTransaction: () -> Boolean,
    ): ParticipantSession = LeasedSession(kind, lease, deadlineMonotonicMillis, clock, clockTrusted, inTransaction)

    override fun toString(): String = "QuietRunScheduler"

    companion object {
        /** q = 1/8 (exact: a draw is a multiple of 2^-53). */
        const val QUIET_PROBABILITY: Double = 0.125

        const val PAYMENT_HOLD_MIN_MILLIS: Long = 20 * 60_000L
        const val PAYMENT_HOLD_MAX_MILLIS: Long = 60 * 60_000L

        /** A participant call needs at least this much of its session's time left. */
        const val MIN_CALL_MILLIS: Long = 1_000
    }
}
