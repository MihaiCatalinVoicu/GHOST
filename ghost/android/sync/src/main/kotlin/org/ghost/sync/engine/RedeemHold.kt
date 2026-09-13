package org.ghost.sync.engine

import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.store.SyncStores
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The redeem hold of a background relay session (Phase 8 design §11.6, §17 Q29, §19.23 point 5): a
 * background session that starts with a pending write need, while a participant is installed, stays
 * open after its sync work has ended (its transport READY, the participant's lease open) until the
 * participant's redeem lane has run one step ([org.ghost.sync.api.RelayRedeemAccess.stepDone]), and
 * never past the job's deadline. Without it such a session ends right after its first pass when no
 * read or write pair has a usable capability, before the lane's first step (READY + U[0, 30 s]), so a
 * client whose capabilities all lapsed could redeem only in the foreground.
 *
 *  - Whether a session is held is a function of the number of pending write needs read at the
 *    session's start only ([background]'s one input besides the deadline): not entitlement state,
 *    not token counts, not an issuer answer, and not a need that appears or is met later.
 *  - The hold starts only once the session's lanes have finished and changes nothing they did: the
 *    read lane's events, calls and end are those of the session without it (T19).
 *  - It ends at the lane's first step, at [deadlineMonotonicMillis], or when the session is stopped
 *    (a foreground wanted, the payment screen, onStopJob, a wipe), whichever comes first. A session
 *    whose transport failed is not held (no redemption could run on it). The runtime
 *    (`SyncRuntime`) and the `:entitlement` harness both decide with this one component.
 */
class RedeemHold private constructor(
    /** The session started with a pending write need, while a participant was installed. */
    val armed: Boolean,
    /** Monotonic time (the sync clock) at which the hold ends in any case: the job's deadline. */
    val deadlineMonotonicMillis: Long,
) {
    private val stepped = AtomicBoolean()

    /** The participant's redeem lane has run a step; true for the first call only. */
    fun stepDone(): Boolean = stepped.compareAndSet(false, true)

    /** The session is held at [nowMonotonicMillis]: armed, no step yet, before the deadline. */
    fun holds(nowMonotonicMillis: Long): Boolean = armed && !stepped.get() && nowMonotonicMillis < deadlineMonotonicMillis

    override fun toString(): String = "RedeemHold(armed=$armed)"

    companion object {
        /** A session that is never held (the foreground, or no participant installed). */
        fun none(): RedeemHold = RedeemHold(false, Long.MIN_VALUE)

        /** The hold of a background session that started with [pendingWriteNeeds] pending write needs. */
        fun background(pendingWriteNeeds: Int, deadlineMonotonicMillis: Long): RedeemHold {
            require(pendingWriteNeeds >= 0) { "need count out of range" }
            return RedeemHold(pendingWriteNeeds > 0, deadlineMonotonicMillis)
        }

        /** The pending write needs of [stores] (any reason), read at a session's start in its own transaction. */
        fun pendingWriteNeeds(stores: SyncStores): Int = stores.capabilities.needed().count { it.kind == CapabilityKind.WRITE }
    }
}
