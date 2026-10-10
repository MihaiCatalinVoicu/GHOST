package org.ghost.messaging.channel.engine

import org.ghost.crypto.bridge.MlsOutcome
import org.ghost.messaging.channel.store.OpPurpose
import org.ghost.messaging.channel.store.PostState
import org.ghost.messaging.channel.store.PostStore
import org.ghost.messaging.engine.DmTime
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.InsufficientReplicasException
import org.ghost.sync.api.OutboundBlob
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
 * | commit | the own candidate is **verified** (CO-4: it may win) | the own pending commit is **cleared** (`clearOwn`): no copy can exist, F7's contract | kept pending (CO-4 (a)); cleared by the settle's custody at its deadline plus the handshake TTL (CO-4 (c), [ChannelSettleStep]) |
 * | Welcome, join, request | nothing to record | nothing (a joiner whose request failed waits for its expiry) | nothing |
 *
 * **The INDETERMINATE resend** (slice S8, §19.37 row 47; the mirror of the DM's §7.5/G-7): an op that closed
 * INDETERMINATE is enqueued again with **the identical bytes** — [org.ghost.sync.api.OutboundBlob] repeats the
 * retained [org.ghost.messaging.channel.store.PostStore.OpRow.blob], never a re-seal (the seal's salt is a fresh
 * draw, so a re-seal would not be the identical bytes Phase 7's resend contract names) — at most
 * [org.ghost.messaging.channel.store.PostStore.MAX_RESENDS] times, only while `now < resendNotAfterEpochSeconds`
 * and before the op's own deadline (`OpRow.deadlineHour`), and in the outcome's transaction, so the release and
 * the new op commit together or not at all (the DM's §7.8 reasoning). The count travels to the new op's row, so
 * the bound is per logical op, as the DM's `resendCount`. A post stays `indeterminate` through the resends; a
 * commit stays pending under CO-4 — the resend is exactly what may yet produce the verified copy CO-4 (a) needs;
 * past the bound, the op is released with nothing resent and the committer's custody is the settle's.
 * Fewer than two operators this week: the resend is skipped (the release stands, the post stays `indeterminate`);
 * a full disk rolls the release back and the outcome is offered again, as the DM's.
 *
 * **No relay-visible call beyond the resend** (T40, gate G-M5): `release` writes a local row; the resend is caused
 * by the user's own earlier send, never by inbound traffic — the same exemption the DM's `SendStep.resend` has.
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
                                // CO-4: no copy can exist, so the pending commit is cleared and
                                // its requests stay pending — but F7's no-copy-can-exist contract
                                // is the original send's alone: a resend op's FAILED leaves
                                // copy-existence open (§19.13: an own commit that may have reached
                                // a relay is never cleared on its own), so only the original op
                                // (resends = 0) clears here. A resend op's FAILED is
                                // terminal-INDETERMINATE of a kind: release, keep the commit
                                // pending, and the custody at the settle is its bound (§19.46).
                                if (op.resends == 0) {
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
                            }
                            Outcome.INDETERMINATE -> Unit
                        }
                    }
                }
                OpPurpose.WELCOME, OpPurpose.JOIN, OpPurpose.REJOIN, OpPurpose.REQUEST -> Unit
            }
            // The INDETERMINATE resend (the class note): identical bytes, at most twice, inside the resend
            // bound and the op's deadline, in this transaction with the release. A commit resends only while
            // its candidate is still pending — the custody check is the candidate's existence, §19.45 row 3's
            // own text: a commit whose candidate was cleared meanwhile (CO-4 (b) at a settle) is not resent;
            // a post whose row is gone (swept meanwhile) resends like the DM's — the op row is what exists.
            if (outcome.outcome == Outcome.INDETERMINATE) {
                val ref = op.ref
                val candidatePending = op.purpose != OpPurpose.COMMIT ||
                    ref != null && stores.candidates.ownCommits(tx.sql, c).any { it.hash.contentEquals(ref) }
                if (candidatePending) resendOp(tx, op, outcome)
            }
            stores.posts.deleteOp(tx, operationId)
            true
        }
    }

    /**
     * The identical-bytes resend of an INDETERMINATE op (the class note): a new operation carries the retained
     * bytes under a fresh id; the count travels to its row. False when the resend window is closed, the count is
     * spent, the deadline has passed, or this week's slot table cannot give a quorum — the release stands either
     * way and the caller deletes the old row.
     *
     * Named `resendOp`, not `resend`: G-DM2 (`dm-enqueue-callers.sh`) matches the DM step objects' entry
     * points by name under the premise they are unique to them, and this file is a channel engine file the
     * gate's step rule still reads (review of S9, §19.48 — the rename restores the premise; the gate's rule
     * and strength are untouched).
     *
     * §11.2 #6 bounds the resend twice: by `resendNotAfter` (checked above) and by the recipients' tombstones
     * (`Outbox.enqueue`'s own-tombstone check, which the channel side cannot read ahead). The tombstone bound
     * closes in two documented states: the `done` row's retention passed, and the row still `listed` from a
     * relay before the `done` tombstone existed — an op can close INDETERMINATE while its bytes' own tombstone
     * is in that state. Either bound closing is the resend's terminal state: the op ends `indeterminate` and
     * the commit stays pending under CO-4 — so both refusal predicates are caught here, exactly, and every
     * other enqueue defect still throws (§19.46 FIX 1).
     */
    private fun resendOp(tx: SyncTransaction, op: PostStore.OpRow, outcome: OutboundOutcome): Boolean {
        val now = env.now()
        val notAfter = outcome.resendNotAfterEpochSeconds
        if (op.resends >= PostStore.MAX_RESENDS || notAfter == null || now >= notAfter || now >= op.deadlineHour) {
            return false
        }
        val newOperationId = env.random.bytes(org.ghost.sync.api.OperationId.SIZE)
        return try {
            sync.outbox.enqueue(
                tx,
                OutboundBlob(
                    org.ghost.sync.api.OperationId(newOperationId), outcome.namespace, op.blob, outcome.ttl,
                    deadlineEpochSeconds = op.deadlineHour,
                ),
            )
            stores.posts.insertOp(tx, newOperationId, op.channelId, op.purpose, op.ref, op.blob, op.deadlineHour, op.resends + 1)
            true
        } catch (e: InsufficientReplicasException) {
            false
        } catch (e: IllegalStateException) {
            // Both §11.2 #6 refusal predicates are the resend's terminal state (§19.46 FIX 1):
            // the retention bound and the own tombstone still 'listed' — the refusal a raised
            // tombstone raises for bytes it received. Anything else is an enqueue defect and throws.
            if (e.message in RESEND_TERMINAL_REFUSALS) false else throw e
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

        /**
         * The exact refusal predicates of `Outbox.enqueue`'s own-tombstone check (§11.2 #6): either
         * one closing is the resend's terminal state — the release stands, nothing is resent. Kept
         * verbatim beside the enqueue check they mirror; any other enqueue defect still throws.
         */
        private val RESEND_TERMINAL_REFUSALS = setOf(
            "identical bytes can no longer be resent",
            "these bytes were received from a relay",
        )
    }
}
