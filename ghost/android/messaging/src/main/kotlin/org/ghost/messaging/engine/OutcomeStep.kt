package org.ghost.messaging.engine

import org.ghost.messaging.port.DmClock
import org.ghost.messaging.store.MessageStore
import org.ghost.messaging.store.OwnerStore
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.Outcome
import org.ghost.sync.api.OutboundOutcome
import org.ghost.sync.api.SyncDatabase

/**
 * **OUTCOME** and the decision behind **RESEND** (Phase 9 design §7.5, §21.8 point 5).
 *
 * | Outcome | Rule | Why |
 * |---|---|---|
 * | SENT | `sent`; blob dropped | a quorum of operators verified it |
 * | DEGRADED | `degraded`; blob dropped; **never resent** | a copy exists; another would only be a duplicate |
 * | INDETERMINATE | the identical blob as a new op, at most twice, only while `now < resendNotAfter` and before the deadline; then `indeterminate` | the Phase 7 contract, and caused by the user's own send, not by inbound traffic (T28) |
 * | FAILED | `failed`; the user may retry, which re-encrypts the same L0 | no copy ever existed, so re-encrypting is safe, and D3 makes a wrongly decided FAILED harmless |
 *
 * **The enqueue is not here.** `Outbox.enqueue` is [SendStep]'s, which is the file gate G-DM2
 * allows it in; this step decides and calls [SendStep.resend] **with its own transaction**. The
 * distinction matters because the gate reads call sites, and the reason the call is allowed at all
 * is that the resend is caused by the **user's own earlier send** and never by something that
 * arrived.
 *
 * **`Outbox.release` first, effect second, one transaction for both** (§7.5, §7.8). The release
 * answers true exactly once per operation, so an outcome cannot be applied twice across a crash;
 * and because the resend commits with it, it cannot be **lost** across one either — a resend in a
 * second transaction would leave, after a process death between the two, a released op and an
 * item still `enqueued` that nothing ever looks at again.
 */
internal class OutcomeStep(
    private val database: SyncDatabase,
    private val sync: DmSyncPorts,
    private val sendStep: SendStep,
    private val clock: DmClock,
    private val contexts: SelfContexts,
    private val mediaOrphans: MediaOrphanSteps,
    /**
     * §11.1's checkpoint, run after a transaction that erased a view-once sender's `key_env`
     * (§6.4's cleanup, §13.5's "checkpoint … after the cleanup"). Defaulted, not omitted, at the
     * one harness (`DmWorld`) that runs no media: its tests drive no view-once sends, and the
     * media worlds wire real ones, exactly as `DmCheckpoint`'s KDoc demands.
     */
    private val checkpoint: org.ghost.messaging.port.DmCheckpoint = org.ghost.messaging.port.DmCheckpoint { true },
    /** The reconcile half of §13.5's "after the cleanup", run after [checkpoint]. */
    private val onSenderCopyErased: () -> Unit = {},
    /**
     * §11.1's debt for the cleanup's checkpoint (the S8 review's R1): a busy or failed pragma
     * is recorded here and SWEEP re-asks it. Defaulted; `MessagingRuntime` wires the shared
     * instance the sweep reads (a default there would leave the debt unread).
     */
    private val mediaCheckpoint: MediaCheckpointState = MediaCheckpointState(),
) {
    private val messages = MessageStore()
    private val owner = OwnerStore()
    private val mediaObjects = org.ghost.media.store.MediaObjects(org.ghost.media.store.MediaFragments())

    /** How many outcomes this pass released. */
    fun run(): Int {
        // Resolved before any outcome transaction, like every caller of SelfContexts since the
        // S8 review: get() opens its own transaction when the cache is cold, and SyncDatabase
        // refuses a nested one outright.
        val self = contexts.get()
        var released = 0
        var viewOnceCleaned = false
        for (outcome in sync.outbox.outcomes(Consumer.DM, DM_OUTCOMES)) {
            if (applyOne(outcome, self) { viewOnceCleaned = true }) released += 1
        }
        for (outcome in sync.outbox.outcomes(Consumer.PREKEYS, PREKEY_OUTCOMES)) {
            if (applyBundle(outcome)) released += 1
        }
        // §13.5's "checkpoint and reconcile after the cleanup": the erasure stood inside an
        // outcome transaction above; both run here, after the commits, outside any transaction.
        if (viewOnceCleaned) {
            // A busy answer keeps the debt: SWEEP re-asks the pragma at its next pass
            // (§10.7's shape, the S8 review's R1).
            mediaCheckpoint.record(checkpoint.truncate())
            onSenderCopyErased()
        }
        return released
    }

    @Suppress("ReturnCount")
    private fun applyOne(outcome: OutboundOutcome, self: SelfContext?, onViewOnceCleaned: () -> Unit): Boolean {
        val now = clock.nowEpochSeconds()
        return database.transaction { tx ->
            if (!sync.outbox.release(tx, outcome.operationId)) return@transaction false
            val op = messages.op(tx.sql, outcome.operationId.toByteArray())
                // The message expired and was swept meanwhile (§7.5): the release stands and
                // there is nothing left to record.
                ?: return@transaction true
            val itemId = op.itemId ?: return@transaction true
            val item = messages.item(tx.sql, itemId) ?: return@transaction true
            when (outcome.outcome) {
                Outcome.SENT -> terminal(tx, op.operationId, itemId, item, STATE_SENT, self, onViewOnceCleaned)
                Outcome.DEGRADED -> terminal(tx, op.operationId, itemId, item, STATE_DEGRADED, self, onViewOnceCleaned)
                Outcome.FAILED -> {
                    // §7.5: the user may retry, which re-encrypts the same L0 — so `l0_env` stays
                    // until the deadline, unlike at the three terminal outcomes.
                    messages.setItemState(tx, itemId, item.state, STATE_FAILED)
                    messages.setMessageState(tx, itemId, MessageStore.STATE_QUEUED, STATE_FAILED)
                    messages.clearOpBlob(tx, op.operationId)
                }
                Outcome.INDETERMINATE -> {
                    val blob = op.blob
                    val resendNotAfter = outcome.resendNotAfterEpochSeconds
                    val mayResend = blob != null &&
                        op.resendCount < MAX_RESENDS &&
                        resendNotAfter != null &&
                        now < resendNotAfter &&
                        now < op.deadlineHour
                    val resent = mayResend && sendStep.resend(
                        tx = tx,
                        contactId = item.contactId,
                        previousOperationId = op.operationId,
                        namespace = outcome.namespace.toByteArray(),
                        blob = requireNotNull(blob),
                        // §10.2 row 6: "the Phase 7 identical-bytes resend repeats the op's own
                        // TTL". It used to take the conversation's **current** bucket, so a 7-day
                        // TEXT resent after the timer was turned off sat at relays for 30 days
                        // (past §10.1's bound), and a TIMER_SET that shortened the timer lost
                        // R-T3's larger bucket on its resend (phase review ENG-5).
                        ttl = outcome.ttl,
                        deadlineHour = op.deadlineHour,
                        itemId = itemId,
                        resendCount = op.resendCount,
                    )
                    // The contact is no longer sendable, or this week's slot table cannot give a
                    // quorum: the release stands and the item ends `indeterminate` — "may not have
                    // been delivered", which is exactly what is true.
                    if (!resent) terminal(tx, op.operationId, itemId, item, STATE_INDETERMINATE, self, onViewOnceCleaned)
                }
            }
            true
        }
    }

    /**
     * §21.8 point 5: a bundle op. SENT or DEGRADED records the week in
     * `dm_self.bundle_published_week`; a FAILED or INDETERMINATE one leaves the column behind.
     *
     * **Nothing reads it yet, and that is a declared gap rather than an oversight** (§22.12). The
     * rule's remedy is that the next time-triggered OWNER-WEEK pass "re-seals the current bundle
     * (new salt, same generation and `bundle_rank`)" while the week's validity lasts, and neither
     * half of that is reachable from `:messaging`: the closed surface of §2.6 has only
     * `bundleCreate`, which draws a **fresh** generation, and re-depositing the identical retained
     * bytes is refused by Phase 7's `outbox_op UNIQUE (namespace_id, blob_hash)`. So the column is
     * written here, where the rule says to write it, and the step that will read it waits for the
     * slice that adds the re-seal to the JNI surface. The consequence, recorded in the design: a
     * publication that ends FAILED costs the owner that week's bundle.
     */
    private fun applyBundle(outcome: OutboundOutcome): Boolean = database.transaction { tx ->
        if (!sync.outbox.release(tx, outcome.operationId)) return@transaction false
        val op = messages.op(tx.sql, outcome.operationId.toByteArray()) ?: return@transaction true
        val week = op.bundleWeek ?: return@transaction true
        if (outcome.outcome == Outcome.SENT || outcome.outcome == Outcome.DEGRADED) {
            owner.markBundlePublished(tx, week)
        }
        messages.clearOpBlob(tx, op.operationId)
        true
    }

    private fun terminal(
        tx: org.ghost.sync.api.SyncTransaction,
        operationId: ByteArray,
        itemId: ByteArray,
        item: MessageStore.ItemRow,
        state: String,
        self: SelfContext?,
        onViewOnceCleaned: () -> Unit,
    ) {
        messages.setItemState(tx, itemId, item.state, state)
        messages.setMessageState(tx, itemId, MessageStore.STATE_QUEUED, state)
        // §7.5 "Retained blob": messaging's copy exists only so an identical resend can repeat the
        // bytes, and it goes at the terminal outcome. It is E2E ciphertext no key on this device
        // opens, and T25 counts its lifetime from here (L7-D7).
        messages.clearOpBlob(tx, operationId)
        messages.clearItemL0(tx, itemId)
        // Phase 11 design §5.1/§13.4: a kind-5 (descriptor) item's final outcome may complete the
        // `M_c` orphan condition — the upload half of the object ended before the descriptor was
        // even deposited, so the descriptor's outcome is usually the clause that closes. FAILED is
        // not terminal (the user may retry until the deadline), so it never reaches this call.
        if (item.kind == KIND_DESCRIPTOR) {
            mediaOrphans.recordIfOrphaned(tx, self, item.contactId)
            // §6.4/§11.2's view-once sender cleanup: a descriptor's final outcome other than
            // FAILED (this call is never reached for FAILED) erases the sender's copy — key,
            // fragment rows, unshared blobs — in the same transaction; the checkpoint and the
            // reconcile follow the commit (§13.5, §11.1; MC-M20 is this erasure skipped on a
            // final INDETERMINATE).
            val objectId = mediaObjects.keyedViewOnceOfMessage(tx.sql, itemId)
            if (objectId != null) {
                mediaObjects.eraseSenderCopy(tx, objectId)
                onViewOnceCleaned()
            }
        }
    }

    companion object {
        /** §7.5: `Outbox.outcomes(DM, 64) + Outbox.outcomes(PREKEYS, 16)`. */
        const val DM_OUTCOMES: Int = 64

        /** The bundle half of the same loop. */
        const val PREKEY_OUTCOMES: Int = 16

        /** G-7, C-15: at most two identical-bytes resends per op. */
        const val MAX_RESENDS: Int = 2

        /**
         * The descriptor item's kind (Phase 11 design §4.1's kind-5 L0). The SEND path that
         * creates kind-5 items is slice S5; until then no such row exists and this guard is inert.
         */
        const val KIND_DESCRIPTOR: Int = 5

        /** `dm_message.state` and `dm_outbound_item.state` (§13.5). */
        const val STATE_SENT: String = "sent"
        const val STATE_DEGRADED: String = "degraded"
        const val STATE_FAILED: String = "failed"
        const val STATE_INDETERMINATE: String = "indeterminate"
    }
}
