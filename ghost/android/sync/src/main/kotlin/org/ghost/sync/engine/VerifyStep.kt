package org.ghost.sync.engine

import org.ghost.network.OnionAddress
import org.ghost.sync.api.BlobHash
import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.StatusFlag
import org.ghost.sync.api.SyncTransaction
import org.ghost.sync.port.PairKey
import org.ghost.sync.store.CapabilityToken
import org.ghost.sync.store.OwnCheck

/**
 * Verification of acknowledged stores by `check` (design §3.4, "compară inventarul"): for write-only
 * pairs, pairs without a usable read token, and deliveries listing has not verified within the
 * fallback. Present → verified; absent → a strike (a repair store, or failed at the second), and the
 * relay gets +2 on its work-lane breaker and the RELAY_SUSPECT flag. The check itself is shared
 * with resolution (one request per pair event, see [CheckRound]).
 */
internal open class VerifyStep {

    open fun select(ctx: WorkContext, tx: SyncTransaction, pair: PairKey, now: Long, minAgeSeconds: Long, limit: Int): List<OwnCheck> =
        if (limit <= 0) {
            emptyList()
        } else {
            ctx.stores.outboxStore.ackedAwaitingVerification(tx, pair.relayId, pair.namespace, now, minAgeSeconds, limit)
        }

    /** Records the answer; returns how many acknowledged deliveries the relay did not show. */
    open fun apply(ctx: WorkContext, tx: SyncTransaction, checks: List<OwnCheck>, present: Set<BlobHash>, now: Long): Int {
        var absent = 0
        for (c in checks) {
            if (c.hash in present) {
                ctx.stores.outboxStore.recordVerifiedAfterAck(tx, c.operationId, c.relayId, now)
            } else if (ctx.stores.outboxStore.recordAbsentAfterAck(tx, c.operationId, c.relayId, now)) {
                absent++
            }
        }
        return absent
    }

    override fun toString(): String = "VerifyStep"
}

/**
 * Resolution of possible copies (design §3.5): a delivery whose attempt may have stored, never
 * acknowledged, on an active relay, still live if made at its earliest hour. Present → verified;
 * absent → the copy never existed (`copy_hour` is cleared), which can reopen the store window or let
 * D2 decide. Pending deliveries are resolved by their own store attempt (check before restore)
 * while their op's window is open.
 */
internal open class ResolveStep {

    open fun select(ctx: WorkContext, tx: SyncTransaction, pair: PairKey, now: Long, limit: Int): List<OwnCheck> =
        if (limit <= 0) emptyList() else ctx.stores.outboxStore.resolvable(tx, pair.relayId, pair.namespace, now, limit)

    open fun apply(ctx: WorkContext, tx: SyncTransaction, checks: List<OwnCheck>, present: Set<BlobHash>, now: Long) {
        for (c in checks) {
            if (c.hash in present) {
                ctx.stores.outboxStore.recordFoundByCheck(tx, c.operationId, c.relayId, now)
            } else {
                ctx.stores.outboxStore.clearUnackedCopy(tx, c.operationId, c.relayId, now)
            }
        }
    }

    override fun toString(): String = "ResolveStep"
}

/**
 * One `check` per pair event for verification and resolution together (at most
 * [TrafficPolicy.checkBatch] hashes), with the write token (write grants read on the relay) or the
 * read token when there is no write token that reads.
 */
internal object CheckRound {

    /** Returns true if a check request was made. */
    fun run(ctx: WorkContext, pair: PairKey): Boolean {
        if (!ctx.allows(pair)) return false
        val batch = ctx.policy.checkBatch
        val plan = ctx.db.transaction { tx ->
            val now = ctx.now()
            val token = ctx.stores.capabilityStore.forChecking(tx, pair.relayId, pair.namespace, now)
            val relay = ctx.stores.directoryStore.address(tx, pair.relayId)
            val namespace = ctx.stores.directoryStore.namespace(tx, pair.namespace)
            if (token == null || relay == null || namespace == null) {
                null
            } else {
                val readToken = ctx.stores.capabilityStore.usable(tx, pair.relayId, pair.namespace, CapabilityKind.READ, now)
                // Listing verifies for free; only write-only pairs and pairs without a read token check after 60 s.
                val minAge = if (!namespace.listening || readToken == null) ctx.policy.verifyAckAgeSeconds else ctx.policy.verifyFallbackSeconds
                val verify = ctx.steps.verify.select(ctx, tx, pair, now, minAge, batch)
                val resolve = ctx.steps.resolve.select(ctx, tx, pair, now, batch - verify.size)
                Plan(relay, token, verify, resolve)
            }
        } ?: return false
        if (plan.verify.isEmpty() && plan.resolve.isEmpty()) return false
        val deadline = ctx.deadline(pair.relayId) ?: return false
        val hashes = LinkedHashSet<BlobHash>().apply {
            plan.verify.forEach { add(it.hash) }
            plan.resolve.forEach { add(it.hash) }
        }.toList()
        val result = ctx.timed(pair.relayId) {
            relayCall { ctx.port.check(plan.relay, pair.namespace, plan.token.token, hashes, deadline) }
        }
        when (result) {
            is CallResult.Ok -> {
                val present = result.value.filterTo(HashSet()) { it in hashes }
                val absent = ctx.db.transaction { tx ->
                    val now = ctx.now()
                    val absentAfterAck = ctx.steps.verify.apply(ctx, tx, plan.verify, present, now)
                    ctx.steps.resolve.apply(ctx, tx, plan.resolve, present, now)
                    absentAfterAck
                }
                if (absent > 0) {
                    ctx.failure(pair.relayId, ABSENT_AFTER_ACK_WEIGHT)
                    ctx.flag(StatusFlag.RELAY_SUSPECT)
                } else {
                    ctx.success(pair.relayId)
                }
            }
            is CallResult.Failed -> ctx.readFailure(pair, plan.token, result, isGet = false)
        }
        return true
    }

    private class Plan(
        val relay: OnionAddress,
        val token: CapabilityToken,
        val verify: List<OwnCheck>,
        val resolve: List<OwnCheck>,
    )

    /** Breaker weight of an acknowledged store the relay no longer shows (design §3.4). */
    const val ABSENT_AFTER_ACK_WEIGHT: Int = 2
}
