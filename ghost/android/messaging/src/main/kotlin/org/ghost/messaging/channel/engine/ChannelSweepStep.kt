package org.ghost.messaging.channel.engine

import org.ghost.messaging.channel.store.ChannelState
import org.ghost.messaging.engine.DmTime
import org.ghost.sync.api.NamespaceId

/**
 * **The join half of `CH-SWEEP`** (Phase 10 design §6.2.2 step 4, §6.11 `joining → join_expired`, §10.4): a join whose
 * `expiry_day` has passed without a Welcome expires, **one transaction per join**. The channel becomes `join_expired`,
 * the KeyPackage's private keys (`mls_global_kv`) and its box key go, and the client **stops listening**: the namespace
 * is removed (`Namespaces.remove`), or — while it still has an operation or a fetched row, which `remove` refuses (the
 * join request's op until its deadline) — its listening is turned off and the removal is tried again at the next sweep,
 * the join row (expired, so no read sees it) keeping the namespace's name until then.
 *
 * The rest of `CH-SWEEP` — expired posts and their rows, epochs past retention (`sweepPast`), drained generations,
 * invites, requests, tags, fork signals, the own INDETERMINATE commit of CO-4 (c) — is slice S8's.
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

    override fun toString(): String = "ChannelSweepStep"

    companion object {
        const val BATCH: Int = 16
    }
}
