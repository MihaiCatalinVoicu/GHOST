package org.ghost.messaging.channel.engine

import org.ghost.crypto.bridge.MlsOutcome
import org.ghost.messaging.channel.store.ChannelState
import org.ghost.messaging.channel.store.PostState
import org.ghost.messaging.engine.DmTime
import org.ghost.messaging.port.DmCheckpoint
import org.ghost.sync.api.NamespaceId

/**
 * **`CH-SWEEP`** (Phase 10 design §10.4), each item in **one transaction** (a sweep is several
 * transactions, §10.6 bounds the transaction and not the sweep).
 *
 * **The join half** (§6.2.2 step 4, §6.11 `joining → join_expired`): a join whose `expiry_day` has passed
 * without a Welcome expires. The channel becomes `join_expired`, the KeyPackage's private keys
 * (`mls_global_kv`) and its box key go, and the client **stops listening**: the namespace is removed
 * (`Namespaces.remove`), or — while it still has an operation or a fetched row, which `remove` refuses
 * (the join request's op until its deadline) — its listening is turned off and the removal is tried again
 * at the next sweep, the join row (expired, so no read sees it) keeping the namespace's name until then.
 * The rejoin half (a re-send at day + 7, `reinvite_needed` at day + 14) is [ChannelRejoinStep.sweepRejoins]'s.
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
 * **The ephemeral half** (slice S8, §8.2, §8.3, §8.5, §6.3.5, §19.21; the exit's SCN-CF and EP-C suites):
 *
 *  - [sweepPosts] fires the post timers: a post past `delete_at_minute` or — while unread — past its
 *    relay expiry E goes in the cascade of §8.2 (one transaction): the post row (its reactions follow by
 *    the foreign key's `ON DELETE CASCADE`), its `ch_pending_post` row (a failed post's waiting retry)
 *    and, past a batch, `wal_checkpoint(TRUNCATE)` with `busy = 0` checked — without the checkpoint the
 *    bodies stay in the `-wal` (T25's physical scan; mutant ME-C3).
 *  - [sweepPending] is the expired-pending edge recorded for S8 (§19.37 row 11, §6.3.1's last sentence):
 *    a pending post whose op deadline (`fail_after_hour`) has passed becomes FAILED — its `queued` post
 *    row, the user may retry (§6.11) — and leaves the pending set, which is how the 256 bound of §6.3.5
 *    counts live rows; an administrative post (no post row) just leaves the queue.
 *  - [sweepReveals] deletes the `ch_reveal` rows past the REVEAL post's timer (§8.5; the row's only time
 *    is that deadline, §19.17). The REVEAL post itself is a post like any other and goes with [sweepPosts].
 *  - [sweepSeen] and [sweepKpTags] drop the dedup tags past their retention (§6.3.4 layer 4, §6.3.5).
 *  - [sweepEpochs] keeps the epochs: the rows past `keep_until_day` go with their epoch's fork signals
 *    (§6.3.5), then — the count of §8.3 — `sweepPast(keepCount = n)`, n the final epochs still within
 *    retention, drains the native past epochs beyond n (retention is by count, never by OpenMLS's stamps,
 *    §19.4; mutant MM-28), and the box keys whose `last_epoch` left retention go (§19.17).
 *    **A pending own commit is never touched here**: its custody is CO-4's, at the settle
 *    ([ChannelSettleStep]'s custody clear) and the outcome step's resends — the sweep leaves a pending
 *    commit pending, which EP-C asserts (§19.37 row 47).
 *  - [sweepInvites] deletes the `INVITE_ISSUED` records and the sponsor's own links past their
 *    `expiry_day` — both live through `expiry_day` and are swept from `expiry_day + 1` (§8.5: committers
 *    admit up to the invite's expiry; §6.2.1; the records hold ids, keys and a signature, no user text).
 *  - [sweepJoinRequests] and [sweepRequests] drop the requests past their day: a join request until its
 *    invite's expiry or 7 days after its day (§6.3.5), a `ch_request` (a leaver never removed) after 7 days
 *    (§6.6, `LEAVE_REQUEST_DAYS`).
 *  - [sweepGlobalRows] deletes the `mls_global_kv` rows past their `delete_after_day` (§9: KeyPackage and
 *    key-pair rows go by day).
 *
 * Gate G-M5 lists this file for `Namespaces.remove` and `Namespaces.setListening`.
 */
internal class ChannelSweepStep(
    private val env: ChannelEnv,
    private val sync: ChannelSyncPorts,
    /** The checkpoint after a cascade (§8.2): the pragma needs an executor outside a transaction, which
     *  `:messaging` reaches only through this port (the DM's `DmCheckpoint`, same contract). */
    private val checkpoint: DmCheckpoint,
) {
    private val stores = env.stores

    /** Expires the joins past their day; returns how many joins it finished. Rejoin rows are slice S7's
     * ([ChannelRejoinStep.sweepRejoins]: a re-send at day + 7, `reinvite_needed` at day + 14) and are
     * not touched here. */
    fun sweepJoins(): Int {
        val day = DmTime.day(env.now())
        val expired = env.database.transaction { tx ->
            stores.joins.expiredJoins(tx.sql, day, BATCH).filter { it.type != org.ghost.messaging.channel.store.JoinType.REJOIN }
        }
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

    // ---------------------------------------------------------------------------------- the ephemeral half (slice S8)

    /**
     * Fires the post timers (§8.2, §8.5): every post past `delete_at_minute` or — while unread — past its
     * relay expiry E, in the cascade of §8.2, one transaction per batch of [BATCH]: the post row (its
     * reactions follow by the foreign key's `ON DELETE CASCADE`, ADR-32) and its `ch_pending_post` row (a
     * failed post's retry still waiting). Rounds run until a short batch or [MAX_BATCHES] rounds (the DM
     * sweeper's cap, §19.46 FIX 4: keeps one sweep from becoming unbounded work on the actor thread; what
     * the cap does not drain, the next pass does); the sweep ends with `wal_checkpoint(TRUNCATE)`, after
     * the commits, its result checked — without it the bodies stay in the `-wal` (T25's physical scan;
     * mutant ME-C3). A busy pragma or a full disk at the checkpoint keeps the debt like the DM sweeper
     * (§10.7, the ME-10 shape): retried at the next sweep that deleted rows, never lost with the counts.
     */
    fun sweepPosts(): Int {
        val nowMinute = DmTime.floorMinute(env.now())
        var done = 0
        var batches = 0
        while (batches < MAX_BATCHES) {
            val batch = env.database.transaction { tx -> stores.posts.expiredPosts(tx.sql, nowMinute, BATCH) }
            if (batch.isEmpty()) break
            env.database.transaction { tx ->
                for (opId in batch) {
                    if (stores.posts.deletePost(tx, opId)) done++
                    stores.posts.deletePending(tx, opId)
                }
            }
            batches++
            if (batch.size < BATCH) break
        }
        if (done > 0 || checkpointDue) {
            checkpointDue = !truncateCheckpoint()
        }
        return done
    }

    /** The pragma, outside any transaction; a failure (busy reader, full disk) keeps the debt. */
    private fun truncateCheckpoint(): Boolean = try {
        checkpoint.truncate()
    } catch (e: org.ghost.storage.StorageFullException) {
        false
    }

    /** The checkpoint debt of §10.7: set when the pragma stayed busy or the disk was full, retried at the next sweep. */
    private var checkpointDue: Boolean = false

    /**
     * The expired-pending edge recorded for this slice (§19.37 row 11, §6.3.1's last sentence): a pending
     * post whose op deadline (`fail_after_hour`) has passed becomes FAILED and leaves the pending set —
     * its `queued` post row turns (`failed`, the user may retry it, §6.11's `failed → queued`), which is
     * the only state the sweep adds to a post's machine. A pending administrative post (an `INVITE_ISSUED`
     * or a `LEAVE`, no post row) just leaves the queue. The deletions are what keeps the 256 bound of
     * §6.3.5 counting live rows.
     */
    fun sweepPending(): Int {
        val nowHour = DmTime.floorHour(env.now())
        val expired = env.database.transaction { tx -> stores.posts.expiredPending(tx.sql, nowHour, BATCH) }
        var done = 0
        for (row in expired) {
            env.database.transaction { tx ->
                if (row.kind == ChannelPostStep.KIND_POST) {
                    stores.posts.setState(tx, row.opId, PostState.QUEUED, PostState.FAILED)
                }
                if (stores.posts.deletePending(tx, row.opId)) done++
            }
        }
        return done
    }

    /** The `ch_reveal` rows past the REVEAL post's timer (§8.5): the row's only time is that deadline. */
    fun sweepReveals(): Int {
        val nowMinute = DmTime.floorMinute(env.now())
        return env.database.transaction { tx -> stores.posts.deleteExpiredReveals(tx, nowMinute) }
    }

    /** The seen tags past their retention (§6.3.5); a tag is a week, `until_day` on the week grid. */
    fun sweepSeen(): Int {
        val day = DmTime.day(env.now())
        return env.database.transaction { tx -> stores.posts.deleteSeenTags(tx, day) }
    }

    /** The committer's KeyPackage tags past their last admissible day (§6.3.5). */
    fun sweepKpTags(): Int {
        val day = DmTime.day(env.now())
        return env.database.transaction { tx -> stores.joins.deleteKpTags(tx, day) }
    }

    /**
     * The epochs past retention and the count of §8.3: the rows past `keep_until_day` go, with their
     * epoch's fork signals (§6.3.5); then, for a channel a row of which went (its oldest retained epoch
     * moved), `sweepPast(keepCount = n)` — n the final epochs still within retention — drains the native
     * past epochs beyond n (retention is by count, computed from `ch_epoch.final_day`, never from
     * OpenMLS's stamps, §19.4; mutant MM-28), and the box keys whose `last_epoch` left retention go
     * (§19.17). The native call parses the channel's whole state, so it runs only where the sweep changed
     * something, never per pass per channel.
     *
     * **An own pending commit is never touched**: custody of it is CO-4's — the resends of
     * [ChannelOutcomeStep] and the settle's clear ([ChannelSettleStep], CO-4 (a)–(c)). The sweep deleting
     * an epoch row never names an open epoch, and a pending commit's epoch is open.
     */
    fun sweepEpochs(): Int {
        val day = DmTime.day(env.now())
        var done = 0
        val touched = HashSet<List<Byte>>()
        var batches = 0
        while (batches < MAX_BATCHES) {
            val batch = env.database.transaction { tx -> stores.epochs.expired(tx.sql, day, BATCH) }
            if (batch.isEmpty()) break
            env.database.transaction { tx ->
                for (key in batch) {
                    stores.epochs.deleteForkSignals(tx, key.channelId, key.epoch)
                    if (stores.epochs.delete(tx, key.channelId, key.epoch)) {
                        done++
                        touched += key.channelId.toList()
                    }
                }
            }
            batches++
            if (batch.size < BATCH) break
        }
        for (id in touched) {
            val channelId = ByteArray(id.size) { id[it] }
            // The native call loads the channel's group state; a removed, replaced or left channel has
            // none (the merge deleted it) — only its rows are swept, and the box keys still expire by
            // retention below, which is pure SQL.
            val opened = env.contexts.open(channelId)
            val hasState = env.database.transaction { tx -> stores.mls.groupRowCount(tx.sql, channelId) > 0 }
            if (opened != null && hasState) {
                env.database.transaction { tx ->
                    val rows = MlsRows.of(stores.mls.rows(tx.sql, channelId, day))
                    val keep = stores.epochs.pastCount(tx.sql, channelId, day)
                    when (val r = opened.crypto.sweepPast(channelId, rows, keep, day.toInt())) {
                        is MlsOutcome.Ok -> stores.mls.apply(tx, channelId, MlsRows.changes(r.value))
                        is MlsOutcome.Refused -> throw IllegalStateException("channel sweepPast refused: ${r.refusal.code}")
                    }
                }
            }
            val oldest = env.database.transaction { tx ->
                stores.epochs.retained(tx.sql, channelId, day).minByOrNull { it.epoch }?.epoch
            }
            if (oldest != null) {
                env.database.transaction { tx -> stores.members.deleteRetiredBefore(tx, channelId, oldest) }
            }
        }
        return done
    }

    /**
     * The administrative posts' records (§8.5, §5.8, §19.21): an `INVITE_ISSUED` is declared membership
     * metadata — ids, keys, a signature, no user text — kept **through** `expiry_day` on every member (a
     * committer admits up to the invite's expiry) and swept from `expiry_day + 1`; the sponsor's own link
     * (`ch_invite_own`) lives by the same rule (§6.2.1; at day granularity the old "+1 vs until" divergence
     * collapses, §19.46 FIX 7).
     */
    fun sweepInvites(): Int {
        val day = DmTime.day(env.now())
        val expired = env.database.transaction { tx -> stores.invites.expiredIssued(tx.sql, day, BATCH) }
        var done = 0
        for (row in expired) {
            env.database.transaction { tx ->
                if (stores.invites.deleteIssued(tx, row.channelId, row.inviteId)) done++
            }
        }
        done += env.database.transaction { tx -> stores.invites.deleteExpiredOwn(tx, day) }
        return done
    }

    /** The pending join, restore and rejoin requests past their day (§6.3.5), which keeps the 64 bound live-rowed. */
    fun sweepJoinRequests(): Int {
        val day = DmTime.day(env.now())
        val expired = env.database.transaction { tx -> stores.joins.expiredRequests(tx.sql, day, BATCH) }
        var done = 0
        for (request in expired) {
            env.database.transaction { tx ->
                if (stores.joins.deleteRequest(tx, request.channelId, request.hash)) done++
            }
        }
        return done
    }

    /** The `mls_global_kv` rows past their `delete_after_day` (§9: KeyPackage and key-pair rows go by day). */
    fun sweepGlobalRows(): Int {
        val day = DmTime.day(env.now())
        val expired = env.database.transaction { tx -> stores.mls.expiredGlobal(tx.sql, day, BATCH) }
        var done = 0
        for (key in expired) {
            env.database.transaction { tx ->
                if (stores.mls.deleteGlobal(tx, key)) done++
            }
        }
        return done
    }

    override fun toString() = "ChannelSweepStep"

    companion object {
        const val BATCH: Int = 16

        /**
         * The rounds cap of the two round-robin sweeps ([sweepPosts], [sweepEpochs]), the DM sweeper's
         * `MAX_BATCHES` value and rule (§19.46 FIX 4): keeps one sweep from becoming unbounded work on
         * the actor thread; what it does not drain, the next pass does.
         */
        const val MAX_BATCHES: Int = 20

        /** The deferred rows consumed per round before a drain's removal (a namespace's fetched cap is 256). */
        const val HELD_BATCH: Int = 256
    }
}
