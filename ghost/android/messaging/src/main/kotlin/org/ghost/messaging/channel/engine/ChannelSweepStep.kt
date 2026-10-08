package org.ghost.messaging.channel.engine

import org.ghost.messaging.channel.store.ChannelState
import org.ghost.messaging.engine.DmTime
import org.ghost.sync.api.NamespaceId

/**
 * **`CH-SWEEP`** (Phase 10 design §10.4), each item in **one transaction**: the join half and the drain
 * half of slice S6.
 *
 * **The join half** (§6.2.2 step 4, §6.11 `joining → join_expired`): a join whose `expiry_day` has passed
 * without a Welcome expires. The channel becomes `join_expired`, the KeyPackage's private keys
 * (`mls_global_kv`) and its box key go, and the client **stops listening**: the namespace is removed
 * (`Namespaces.remove`), or — while it still has an operation or a fetched row, which `remove` refuses
 * (the join request's op until its deadline) — its listening is turned off and the removal is tried again
 * at the next sweep, the join row (expired, so no read sees it) keeping the namespace's name until then.
 *
 * **The drain half** (§6.5 "Drain", §19.23): a generation whose `drain_until_day` has passed is removed —
 * of every member, a removed or leaving one on its own schedule included (no reflexes: the fetch itself
 * stays, dropping rows; §19.8 (b)). `Namespaces.remove` returns false while the namespace has operations
 * or fetched, unconsumed rows (`Namespaces.kt`), so the sweep first marks consumed every fetched row of
 * the namespace that is still deferred (by then unopenable: its epoch keys are past retention) — `held`
 * enumerates them, in rounds outside the transaction (it runs its own short one) — and retries the
 * removal at the next sweep while an op is still open: the row stays, `drained` keeps naming it, and the
 * listening is off so no new blob is fetched. With the removal the generation's row goes — `G_g`, `JK_g`
 * and the generation's credentials with it (`remove` drops the namespace's capabilities).
 *
 * Also the expired `ch_request` rows (a leaver never removed, its request past its day).
 *
 * The rest of `CH-SWEEP` — expired posts and their rows, epochs past retention (`sweepPast`), expired
 * invites, tags, fork signals, the own INDETERMINATE commit of CO-4 (c) — is slice S8's.
 *
 * Gate G-M5 lists this file for `Namespaces.remove` and `Namespaces.setListening`.
 */
internal class ChannelSweepStep(
    private val env: ChannelEnv,
    private val sync: ChannelSyncPorts,
) {
    private val stores = env.stores

    /** Expires the joins past their day; returns how many joins it finished. */
    fun sweepJoins(): Int {
        val day = DmTime.day(env.now())
        val expired = env.database.transaction { tx -> stores.joins.expiredJoins(tx.sql, day, BATCH) }
        var done = 0
        for (join in expired) {
            env.database.transaction { tx ->
                val c = join.channelId
                val channel = stores.channels.channel(tx.sql, c)
                if (channel?.state == ChannelState.JOINING) {
                    stores.channels.transition(tx, c, ChannelState.JOINING, ChannelState.JOIN_EXPIRED)
                    stores.mls.deleteGlobalRows(tx, c)
                    stores.members.deleteBoxKeys(tx, c)
                }
                val ns = join.ns
                // Only an expired join's namespace is the join's own: a member's (any other state) is its generation's.
                val expiring = channel?.state == ChannelState.JOINING || channel?.state == ChannelState.JOIN_EXPIRED
                if (ns == null || !expiring) {
                    stores.joins.deleteJoin(tx, c, join.kpRef)
                    done++
                } else if (sync.namespaces.remove(tx, NamespaceId(ns))) {
                    stores.joins.deleteJoin(tx, c, join.kpRef)
                    done++
                } else {
                    sync.namespaces.setListening(tx, NamespaceId(ns), false)
                }
            }
        }
        return done
    }

    /**
     * Removes the generations whose drain has ended (§6.5); returns how many it removed. The deferred
     * rows are consumed in rounds before the removal transaction (`held` runs its own short one); the
     * removal retries at the next sweep while an op of the namespace is still open.
     */
    fun sweepDrains(): Int {
        val now = env.now()
        val day = DmTime.day(now)
        val drained = env.database.transaction { tx -> stores.generations.drained(tx.sql, day, BATCH) }
        var done = 0
        for (row in drained) {
            val ns = NamespaceId(row.namespaceId)
            while (true) {
                val held = sync.inbox.held(ns, now, HELD_BATCH)
                if (held.isEmpty()) break
                env.database.transaction { tx ->
                    for (h in held) sync.inbox.markConsumed(tx, h.namespace, h.hash)
                }
            }
            val removed = env.database.transaction { tx ->
                if (sync.namespaces.remove(tx, ns)) {
                    stores.generations.delete(tx, row.channelId, row.generation)
                    // The settle's corner (§6.5, recorded in §19.41): a member removed while an older
                    // generation still drained ended the older drain at once and deferred this demotion —
                    // at most one draining generation per channel. The current generation drains from
                    // today (the commit's switch day is no longer reachable here; the corner needs an op
                    // of the old namespace still open at the settle, which production GC makes rare).
                    val channel = stores.channels.channel(tx.sql, row.channelId)
                    if (channel != null && (channel.state == ChannelState.REMOVED || channel.state == ChannelState.REPLACED)) {
                        stores.generations.current(tx.sql, row.channelId, day)?.let {
                            stores.generations.demote(tx, row.channelId, it.generation, day + ChannelSettleStep.DRAIN_DAYS)
                        }
                    }
                    true
                } else {
                    // An op of the namespace is still open: the drain has ended (the row is past its day,
                    // so no read listens to the generation any more); stop listening and retry next sweep.
                    sync.namespaces.setListening(tx, ns, false)
                    false
                }
            }
            if (removed) done++
        }
        return done
    }

    /** Drops the `ch_request` rows past their day; returns how many went. */
    fun sweepRequests(): Int {
        val day = DmTime.day(env.now())
        val expired = env.database.transaction { tx -> stores.members.expiredRequests(tx.sql, day, BATCH) }
        var done = 0
        for (request in expired) {
            env.database.transaction { tx ->
                if (stores.members.deleteRequest(tx, request.channelId, request.kind, request.subject)) done++
            }
        }
        return done
    }

    override fun toString() = "ChannelSweepStep"

    companion object {
        const val BATCH: Int = 16

        /** The deferred rows consumed per round before a drain's removal (a namespace's fetched cap is 256). */
        const val HELD_BATCH: Int = 256
    }
}
