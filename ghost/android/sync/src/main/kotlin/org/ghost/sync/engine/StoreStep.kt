package org.ghost.sync.engine

import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.port.PairKey
import org.ghost.sync.port.StoreReceipt
import org.ghost.sync.store.DueStore
import org.ghost.sync.store.ReceiptResult
import org.ghost.sync.store.StoreLease

/** What one store attempt did (design §3.3). */
internal enum class StoreResult {
    /** No lease was taken (guard did not match, or no budget/deadline left). */
    SKIPPED,

    /** A receipt acknowledged the store. */
    ACKED,

    /** A receipt arrived for a delivery already failed or closed: the possible copy was recorded. */
    LATE,

    /** A receipt arrived after the lease was normalized elsewhere. */
    NO_LEASE,

    /** `check` found the hash (check-before-restore or the quota path): verified without a store. */
    VERIFIED,

    /** The outcome is ambiguous: a copy may exist. */
    AMBIGUOUS,

    /** Nothing was persisted; the lease backoff applies. */
    NOT_APPLIED,

    /** The token was refused or exhausted: the delivery waits for a new capability (or is due now on a newer one). */
    PARKED,

    /** The delivery failed (rejected, local bug). */
    FAILED,

    /** The transport stopped; the session's calls stop. */
    STOPPED,
}

/**
 * Store step of the work lane (design §3.3, §3.6): plan, write-ahead lease, check before restore,
 * store, and one result transaction. The work lane is the only store issuer. Every result is
 * recorded by the guarded store methods, which also run D1, D2 and W for the op.
 *
 * Open so the exit-gate harness can substitute mutants (design §8.8 M3, M5, M9, M11).
 */
internal open class StoreStep {

    /**
     * Attempts due stores: of one pair at its event (HIGH mode, at most [limit]), or of every pair in
     * a maintenance pass ([pair] null, STANDARD). Deliveries whose relay is held (breaker, pause,
     * budget) are skipped and stay due. Returns the number of attempts made.
     */
    open fun round(ctx: WorkContext, pair: PairKey?, limit: Int): Int {
        if (!ctx.active) return 0
        val due = ctx.db.transaction { tx ->
            if (pair == null) {
                ctx.stores.outboxStore.dueStores(tx, ctx.now(), limit * PLAN_OVERSAMPLE)
            } else {
                ctx.stores.outboxStore.dueStores(tx, ctx.now(), limit, pair.relayId, pair.namespace)
            }
        }
        var attempts = 0
        for (d in due) {
            if (attempts >= limit || !ctx.active) break
            if (!ctx.allows(PairKey(d.relayId, d.namespace))) continue
            if (attempt(ctx, d) != StoreResult.SKIPPED) attempts++
        }
        return attempts
    }

    /** One attempt for one due delivery. */
    open fun attempt(ctx: WorkContext, due: DueStore): StoreResult {
        val relay = due.relayId
        val deadline = ctx.deadline(relay) ?: return StoreResult.SKIPPED
        val backoff = Backoff.retrySeconds(due.attempts + 1, ctx.selection())
        val lease = ctx.db.transaction { tx -> ctx.stores.outboxStore.lease(tx, due.operationId, relay, ctx.now(), backoff) }
            ?: return StoreResult.SKIPPED
        val pair = PairKey(relay, lease.namespace)

        // 1. Check before restore: a previous attempt may have left a copy.
        if (lease.checkFirst) {
            val checked = ctx.timed(relay) { relayCall { ctx.port.check(lease.relay, lease.namespace, lease.capability.token, listOf(lease.hash), deadline) } }
            when (checked) {
                is CallResult.Ok -> {
                    ctx.success(relay)
                    if (lease.hash in checked.value) {
                        ctx.db.transaction { tx -> ctx.stores.outboxStore.recordFoundByCheck(tx, lease.operationId, relay, ctx.now()) }
                        return StoreResult.VERIFIED
                    }
                    // Absent while a copy made at the earliest hour would still be live: it never existed.
                    if (lease.clearableIfAbsent) {
                        ctx.db.transaction { tx -> ctx.stores.outboxStore.clearUnackedCopy(tx, lease.operationId, relay, ctx.now()) }
                    }
                }
                is CallResult.Failed -> return checkFailed(ctx, lease, pair, checked)
            }
        }

        // 2. Store the frozen bytes.
        val storeDeadline = ctx.deadline(relay) ?: run {
            ctx.db.transaction { tx -> ctx.stores.outboxStore.recordNotApplied(tx, lease.operationId, relay, ctx.now()) }
            return StoreResult.SKIPPED
        }
        val stored = ctx.timed(relay) {
            relayCall { ctx.port.store(lease.relay, lease.namespace, lease.capability.token, lease.ciphertext, lease.ttlSeconds, storeDeadline) }
        }
        return when (stored) {
            is CallResult.Ok -> receipt(ctx, lease, stored.value)
            is CallResult.Failed -> storeFailed(ctx, lease, pair, stored)
        }
    }

    /** A receipt: Kotlin re-checks that it names the op's hash; a mismatch is hostile and ambiguous. */
    protected open fun receipt(ctx: WorkContext, lease: StoreLease, receipt: StoreReceipt): StoreResult {
        if (receipt.blobHash != lease.hash) {
            ctx.db.transaction { tx -> ctx.stores.outboxStore.recordAmbiguous(tx, lease.operationId, lease.relayId, ctx.now()) }
            ctx.failure(lease.relayId, HOSTILE_WEIGHT)
            return StoreResult.AMBIGUOUS
        }
        val result = ctx.db.transaction { tx ->
            ctx.stores.outboxStore.recordReceipt(tx, lease.operationId, lease.relayId, receipt.expiryUnixSeconds, ctx.now())
        }
        ctx.success(lease.relayId)
        return when (result) {
            ReceiptResult.ACKED -> StoreResult.ACKED
            ReceiptResult.LATE -> StoreResult.LATE
            ReceiptResult.NO_LEASE -> StoreResult.NO_LEASE
        }
    }

    /** A failed store, per the store column of the §3.6 table. */
    protected open fun storeFailed(ctx: WorkContext, lease: StoreLease, pair: PairKey, failed: CallResult.Failed): StoreResult {
        val disposition = ErrorPolicy.store(failed.errorClass)
        disposition.flag?.let { ctx.flag(it) }
        ctx.failure(lease.relayId, disposition.breakerWeight)
        val outbox = ctx.stores.outboxStore
        return when (disposition.action) {
            StoreAction.STOP -> {
                ctx.db.transaction { tx ->
                    if (disposition.copyEffect == CopyEffect.POSSIBLE) {
                        outbox.recordAmbiguous(tx, lease.operationId, lease.relayId, ctx.now())
                    } else {
                        outbox.recordNotApplied(tx, lease.operationId, lease.relayId, ctx.now())
                    }
                }
                ctx.fault(failed)
                StoreResult.STOPPED
            }
            StoreAction.NOT_APPLIED -> {
                ctx.db.transaction { tx -> outbox.recordNotApplied(tx, lease.operationId, lease.relayId, ctx.now()) }
                StoreResult.NOT_APPLIED
            }
            StoreAction.AMBIGUOUS -> {
                ctx.db.transaction { tx -> outbox.recordAmbiguous(tx, lease.operationId, lease.relayId, ctx.now()) }
                StoreResult.AMBIGUOUS
            }
            StoreAction.PARK_UNAUTHORIZED -> {
                park(ctx, lease, exhausted = false)
                StoreResult.PARKED
            }
            StoreAction.QUOTA_CHECK -> quota(ctx, lease, pair)
            StoreAction.FAIL -> {
                ctx.db.transaction { tx -> outbox.failDelivery(tx, lease.operationId, lease.relayId, ctx.now()) }
                if (failed.category == ErrorPolicy.NOT_ONION) ctx.engine.pauseRelayWork(lease.relayId, ctx.monotonic() + SyncEngine.PAUSE_MILLIS)
                StoreResult.FAILED
            }
        }
    }

    /**
     * `quota`: nothing was persisted. `check([h])` with the same token tells whether an earlier
     * attempt's copy is there (verified) or the token is spent (exhausted, parked).
     */
    protected open fun quota(ctx: WorkContext, lease: StoreLease, pair: PairKey): StoreResult {
        val deadline = ctx.deadline(lease.relayId)
        val checked = if (deadline == null) {
            null
        } else {
            ctx.timed(lease.relayId) { relayCall { ctx.port.check(lease.relay, lease.namespace, lease.capability.token, listOf(lease.hash), deadline) } }
        }
        if (checked is CallResult.Ok && lease.hash in checked.value) {
            ctx.success(lease.relayId)
            ctx.db.transaction { tx -> ctx.stores.outboxStore.recordFoundByCheck(tx, lease.operationId, lease.relayId, ctx.now()) }
            return StoreResult.VERIFIED
        }
        park(ctx, lease, exhausted = true)
        if (checked is CallResult.Failed) {
            // The relay's quota answer stands; the failed check only feeds the breaker or stops the transport.
            val disposition = ErrorPolicy.read(checked.errorClass, isGet = false)
            ctx.failure(lease.relayId, disposition.breakerWeight)
            if (disposition.action == ReadAction.STOP) {
                ctx.fault(checked)
                return StoreResult.STOPPED
            }
        }
        return StoreResult.PARKED
    }

    /** A failed check before restore: the lease ends (the earlier possible copy is kept). */
    protected open fun checkFailed(ctx: WorkContext, lease: StoreLease, pair: PairKey, failed: CallResult.Failed): StoreResult {
        val disposition = ErrorPolicy.read(failed.errorClass, isGet = false)
        disposition.flag?.let { ctx.flag(it) }
        ctx.failure(lease.relayId, disposition.breakerWeight)
        if (disposition.action == ReadAction.SUSPEND) {
            park(ctx, lease, exhausted = false)
            return StoreResult.PARKED
        }
        ctx.db.transaction { tx -> ctx.stores.outboxStore.recordNotApplied(tx, lease.operationId, lease.relayId, ctx.now()) }
        return when (disposition.action) {
            ReadAction.STOP -> {
                ctx.fault(failed)
                StoreResult.STOPPED
            }
            ReadAction.PAUSE -> {
                ctx.engine.pauseWork(pair, ctx.monotonic() + SyncEngine.PAUSE_MILLIS)
                StoreResult.NOT_APPLIED
            }
            ReadAction.SKIP, ReadAction.HOSTILE, ReadAction.NOT_FOUND, ReadAction.SUSPEND -> StoreResult.NOT_APPLIED
        }
    }

    /** Refuses the lease's token generation (`unauthorized` → rejected, quota → exhausted) and parks the delivery. */
    private fun park(ctx: WorkContext, lease: StoreLease, exhausted: Boolean) {
        check(lease.capability.kind == CapabilityKind.WRITE) { "stores use write tokens" }
        ctx.db.transaction { tx ->
            ctx.stores.outboxStore.parkForCapability(
                tx, lease.operationId, lease.relayId, lease.namespace, lease.capability.generation, exhausted, ctx.now(),
            )
        }
    }

    override fun toString(): String = "StoreStep"

    companion object {
        /** Breaker weight of a hostile answer (design §3.6). */
        const val HOSTILE_WEIGHT: Int = 2

        /** A pass plans this many times its cap, so deliveries to held relays do not starve the others. */
        const val PLAN_OVERSAMPLE: Int = 4
    }
}
