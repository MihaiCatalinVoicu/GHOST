package org.ghost.sync.engine

import org.ghost.sync.port.PairKey
import org.ghost.sync.port.RegisterResult
import org.ghost.sync.store.DueRegistration
import org.ghost.sync.store.RegistrationLease

/** What one `RegisterKey` attempt did (Phase 9 design §13.3 item 5). */
internal enum class RegistrationResult {
    /** No lease was taken (the guard did not match, or no budget or deadline was left). */
    SKIPPED,

    /** The relay recorded the registration; the row is done until the validity it answered. */
    RECORDED,

    /** The relay judged the period against the capability and refused it; the row stays pending. */
    WRONG_PERIOD,

    /** The capability was refused: its generation is marked and the row waits for the next one. */
    PARKED,

    /** A transient failure: the row keeps the lease's backoff. */
    NOT_APPLIED,

    /** The transport stopped; the session's calls stop. */
    STOPPED,
}

/**
 * The key-registration step of the work lane (Phase 9 design §4.8, §13.3 item 5). It follows the
 * store pattern: a lease transaction, one `RegisterKey` on the namespace's circuit, a result
 * transaction. It never touches the read lane, so a pair's listing schedule is the same with and
 * without registrations (T19).
 *
 * Results: OK marks the row done with the relay's validity; WRONG_PERIOD and `unauthorized` leave it
 * pending, and the next write-capability generation re-arms it (the M2 idea; a `RegisterKey` is
 * idempotent at the relay, so a repeated attempt costs one call and records nothing new); every
 * other failure takes the Phase 7 backoff, breaker and transport handling of §3.6 through the same
 * error table as a store, so no new error category exists.
 *
 * Open so the exit-gate harness can substitute mutants (design §8.8).
 */
internal open class RegistrationStep {

    /**
     * Attempts due registrations: of one pair at its event (HIGH mode) or of every pair in a
     * maintenance pass ([pair] null, STANDARD), at most [limit] per call. Returns the attempts made.
     */
    open fun round(ctx: WorkContext, pair: PairKey?, limit: Int): Int {
        if (!ctx.active) return 0
        val due = ctx.db.transaction { tx ->
            ctx.stores.registrationStore.due(tx, ctx.now(), limit, pair?.relayId, pair?.namespace)
        }
        var attempts = 0
        for (d in due) {
            if (attempts >= limit || !ctx.active) break
            if (!ctx.allows(PairKey(d.key.relayId, d.key.namespace))) continue
            if (attempt(ctx, d) != RegistrationResult.SKIPPED) attempts++
        }
        return attempts
    }

    /** One attempt for one due row. */
    open fun attempt(ctx: WorkContext, due: DueRegistration): RegistrationResult {
        val relay = due.key.relayId
        val deadline = ctx.deadline(relay) ?: return RegistrationResult.SKIPPED
        val backoff = Backoff.retrySeconds(due.attempts + 1, ctx.selection())
        val lease = ctx.db.transaction { tx -> ctx.stores.registrationStore.lease(tx, due.key, ctx.now(), backoff) }
            ?: return RegistrationResult.SKIPPED
        val answered = ctx.timed(relay) {
            relayCall {
                ctx.port.registerKey(
                    lease.relay, due.key.namespace, lease.capability.token, due.key.periodId, due.key.kind,
                    lease.verifier(), lease.requestId(), deadline,
                )
            }
        }
        return when (answered) {
            is CallResult.Ok -> {
                ctx.success(relay)
                when (answered.value.result) {
                    RegisterResult.OK -> {
                        ctx.db.transaction { tx ->
                            ctx.stores.registrationStore.recordDone(tx, due.key, answered.value.validUntilUnixSeconds)
                        }
                        RegistrationResult.RECORDED
                    }
                    RegisterResult.WRONG_PERIOD -> {
                        ctx.db.transaction { tx -> ctx.stores.registrationStore.endLease(tx, due.key) }
                        RegistrationResult.WRONG_PERIOD
                    }
                }
            }
            is CallResult.Failed -> failed(ctx, lease, answered)
        }
    }

    /**
     * A failed call, through the store column of the §3.6 table: nothing was recorded either way (a
     * registration that did reach the relay is repeated idempotently), so only the breaker, the
     * flag, the capability and the transport differ.
     */
    protected open fun failed(ctx: WorkContext, lease: RegistrationLease, failure: CallResult.Failed): RegistrationResult {
        val disposition = ErrorPolicy.store(failure.errorClass)
        disposition.flag?.let { ctx.flag(it) }
        ctx.failure(lease.key.relayId, disposition.breakerWeight)
        ctx.db.transaction { tx ->
            ctx.stores.registrationStore.endLease(tx, lease.key)
            if (disposition.action == StoreAction.PARK_UNAUTHORIZED || disposition.action == StoreAction.QUOTA_CHECK) {
                // A quota answer cannot reach RegisterKey (no bytes are stored); both refusals mean
                // the capability that was presented is spent for this purpose, so its generation is
                // marked and the row waits for the next one. The capability is the lease's own: the
                // write capability of an unfunded namespace, the registration capability of a funded
                // one (Phase 10 design §7.5 item 2), and never the other of the two.
                ctx.stores.capabilityStore.refuse(
                    tx, lease.key.relayId, lease.key.namespace, lease.capability.kind, lease.capability.generation,
                    exhausted = disposition.action == StoreAction.QUOTA_CHECK,
                )
            }
        }
        return when (disposition.action) {
            StoreAction.STOP -> {
                ctx.fault(failure)
                RegistrationResult.STOPPED
            }
            StoreAction.PARK_UNAUTHORIZED, StoreAction.QUOTA_CHECK -> RegistrationResult.PARKED
            StoreAction.NOT_APPLIED, StoreAction.AMBIGUOUS, StoreAction.FAIL -> {
                if (failure.category == ErrorPolicy.NOT_ONION) {
                    ctx.engine.pauseRelayWork(lease.key.relayId, ctx.monotonic() + SyncEngine.PAUSE_MILLIS)
                }
                RegistrationResult.NOT_APPLIED
            }
        }
    }

    override fun toString(): String = "RegistrationStep"
}
