package org.ghost.messaging.channel.engine

import org.ghost.crypto.bridge.MlsOutcome
import org.ghost.messaging.channel.store.OpPurpose
import org.ghost.messaging.channel.store.PostState
import org.ghost.messaging.engine.DmTime
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.OutboundOutcome
import org.ghost.sync.api.Outcome
import org.ghost.sync.api.SyncTransaction

/**
 * **`CH-OUTCOME`** (Phase 10 design §10.4, CO-4; the DM's OUTCOME of Phase 9 §7.5): the decided outcomes of the channel's
 * Phase 7 operations, each in **one transaction** with its `Outbox.release` — release first, effect second, so an outcome
 * is applied exactly once across a crash.
 *
 * | Purpose | SENT, DEGRADED | FAILED | INDETERMINATE |
 * |---|---|---|---|
 * | post | the post's state | `failed` (the user may retry: the same op id, §6.3.4) | `indeterminate` |
 * | commit | the own candidate is **verified** (CO-4: it may win) | the own pending commit is **cleared** (`clearOwn`): no copy can exist, F7's contract | kept pending (CO-4 (a)); cleared by the sweep at its deadline plus the handshake TTL (CO-4 (c), slice S8) |
 * | Welcome, join, request | nothing to record | nothing (a joiner whose request failed waits for its expiry) | nothing |
 *
 * **No resend in this slice.** Phase 7 lets an INDETERMINATE op be enqueued again with the identical bytes until its
 * resend bound; the DM layer does so twice. The channel engine does not yet (recorded in §19.37): the INDETERMINATE
 * post stays `indeterminate`, and an INDETERMINATE commit stays pending under CO-4's rule.
 *
 * **No relay-visible call** (T40, gate G-M5): `release` writes a local row; nothing is enqueued here.
 */
internal class ChannelOutcomeStep(
    private val env: ChannelEnv,
    private val sync: ChannelSyncPorts,
) {
    private val stores = env.stores

    /** How many outcomes this pass released. */
    fun run(): Int {
        var released = 0
        for (outcome in sync.outbox.outcomes(Consumer.CHANNEL, OUTCOMES)) {
            if (apply(outcome)) released++
        }
        return released
    }

    private fun apply(outcome: OutboundOutcome): Boolean {
        val day = DmTime.day(env.now())
        return env.database.transaction { tx ->
            if (!sync.outbox.release(tx, outcome.operationId)) return@transaction false
            val operationId = outcome.operationId.toByteArray()
            val op = stores.posts.op(tx.sql, operationId) ?: return@transaction true
            val c = op.channelId
            when (op.purpose) {
                OpPurpose.POST -> {
                    val ref = op.ref
                    if (ref != null) {
                        val to = when (outcome.outcome) {
                            Outcome.SENT -> PostState.SENT
                            Outcome.DEGRADED -> PostState.DEGRADED
                            Outcome.FAILED -> PostState.FAILED
                            Outcome.INDETERMINATE -> PostState.INDETERMINATE
                        }
                        // A reaction has no post row; a post already swept has none either.
                        stores.posts.setState(tx, ref, PostState.QUEUED, to)
                    }
                }
                OpPurpose.COMMIT -> {
                    val own = op.ref?.let { hash -> stores.candidates.ownCommits(tx.sql, c).firstOrNull { it.hash.contentEquals(hash) } }
                    if (own != null) {
                        when (outcome.outcome) {
                            Outcome.SENT, Outcome.DEGRADED -> {
                                // CO-4 (D-4): the op outcome evidences the stored copy at this minute; it is the
                                // sighting the own commit anchors at (the creation pass does not anchor it, S5).
                                val seen = DmTime.floorMinute(env.now())
                                stores.candidates.markVerified(tx, c, own.epoch, own.hash, seen)
                                lowerAnchor(tx, c, own.epoch, seen, null)
                            }
                            Outcome.FAILED -> {
                                // CO-4: no copy can exist, so the pending commit is cleared and its requests stay pending.
                                val opened = env.contexts.open(c) ?: throw IllegalStateException("channel context closed under an outcome")
                                val rows = MlsRows.of(stores.mls.rows(tx.sql, c, day))
                                when (val r = opened.crypto.clearOwn(c, rows, day.toInt())) {
                                    is MlsOutcome.Ok -> stores.mls.apply(tx, c, MlsRows.changes(r.value))
                                    is MlsOutcome.Refused -> throw IllegalStateException("channel clearOwn refused: ${r.code}")
                                }
                                stores.candidates.delete(tx, c, own.epoch, own.hash)
                                if (stores.candidates.candidates(tx.sql, c, own.epoch).isEmpty()) {
                                    stores.epochs.setAnchor(tx, c, own.epoch, null)
                                }
                                env.counters.count(ChannelCounters.Reason.OWN_COMMIT_CLEARED)
                            }
                            Outcome.INDETERMINATE -> Unit
                        }
                    }
                }
                OpPurpose.WELCOME, OpPurpose.JOIN, OpPurpose.REJOIN, OpPurpose.REQUEST -> Unit
            }
            stores.posts.deleteOp(tx, operationId)
            true
        }
    }

    /** The epoch's anchor is the earliest sighting or store hour + 60 min over its candidates (CO-4 (i)). */
    private fun lowerAnchor(tx: SyncTransaction, channelId: ByteArray, epoch: Long, firstSeen: Long, storeHour: Long?) {
        val day = DmTime.day(env.now())
        val row = stores.epochs.epoch(tx.sql, channelId, epoch, day) ?: return
        val sighting = minOf(firstSeen, storeHour?.let { it + DmTime.HOUR } ?: Long.MAX_VALUE)
        val anchor = DmTime.floorMinute(row.anchorMinute?.let { minOf(it, sighting) } ?: sighting)
        if (anchor != row.anchorMinute) stores.epochs.setAnchor(tx, channelId, epoch, anchor)
    }

    override fun toString(): String = "ChannelOutcomeStep"

    companion object {
        /** Outcomes released per pass. */
        const val OUTCOMES: Int = 64
    }
}
