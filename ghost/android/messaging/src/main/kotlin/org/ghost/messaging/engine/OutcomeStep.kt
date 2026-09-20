package org.ghost.messaging.engine

import org.ghost.messaging.port.DmClock
import org.ghost.messaging.store.ContactStore
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
 * allows it in; this step decides and calls `SendStep.resend`. The distinction matters because
 * the gate reads call sites, and the reason the call is allowed at all is that the resend is
 * caused by the **user's own earlier send** and never by something that arrived.
 *
 * **`Outbox.release` first, effect second, in one transaction.** It answers true exactly once per
 * operation, so an outcome cannot be applied twice across a crash (§7.5's `if (!release) continue`).
 */
internal class OutcomeStep(
    private val database: SyncDatabase,
    private val sync: DmSyncPorts,
    private val sendStep: SendStep,
    private val clock: DmClock,
) {
    private val contacts = ContactStore()
    private val messages = MessageStore()
    private val owner = OwnerStore()

    /** How many outcomes this pass released. */
    fun run(): Int {
        var released = 0
        for (outcome in sync.outbox.outcomes(Consumer.DM, DM_OUTCOMES)) {
            if (applyOne(outcome)) released += 1
        }
        for (outcome in sync.outbox.outcomes(Consumer.PREKEYS, PREKEY_OUTCOMES)) {
            if (applyBundle(outcome)) released += 1
        }
        return released
    }

    @Suppress("ReturnCount")
    private fun applyOne(outcome: OutboundOutcome): Boolean {
        val now = clock.nowEpochSeconds()
        val plan = database.transaction { tx ->
            if (!sync.outbox.release(tx, outcome.operationId)) return@transaction null
            val op = messages.op(tx.sql, outcome.operationId.toByteArray())
                // The message expired and was swept meanwhile (§7.5): the release stands and
                // there is nothing left to record.
                ?: return@transaction null
            val itemId = op.itemId ?: return@transaction null
            val item = messages.item(tx.sql, itemId) ?: return@transaction null
            when (outcome.outcome) {
                Outcome.SENT -> {
                    terminal(tx, op.operationId, itemId, item, STATE_SENT)
                    null
                }
                Outcome.DEGRADED -> {
                    terminal(tx, op.operationId, itemId, item, STATE_DEGRADED)
                    null
                }
                Outcome.FAILED -> {
                    // §7.5: the user may retry, which re-encrypts the same L0 — so `l0_env` stays
                    // until the deadline, unlike at the three terminal outcomes.
                    messages.setItemState(tx, itemId, item.state, STATE_FAILED)
                    messages.setMessageState(tx, itemId, MessageStore.STATE_QUEUED, STATE_FAILED)
                    messages.clearOpBlob(tx, op.operationId)
                    null
                }
                Outcome.INDETERMINATE -> {
                    val blob = op.blob
                    val resendNotAfter = outcome.resendNotAfterEpochSeconds
                    val mayResend = blob != null &&
                        op.resendCount < MAX_RESENDS &&
                        resendNotAfter != null &&
                        now < resendNotAfter &&
                        now < op.deadlineHour
                    if (!mayResend) {
                        terminal(tx, op.operationId, itemId, item, STATE_INDETERMINATE)
                        null
                    } else {
                        val conversation = contacts.conversation(tx.sql, item.contactId)
                        Resend(
                            contactId = item.contactId,
                            itemId = itemId,
                            blob = requireNotNull(blob),
                            timerCode = conversation?.timerCode ?: DmTimers.TIMER_DEFAULT,
                            deadlineHour = op.deadlineHour,
                            resendCount = op.resendCount,
                        )
                    }
                }
            }
        } ?: return true

        // The resend is its own transaction, in the file that may enqueue (§7.5, gate G-DM2).
        val sent = sendStep.resend(
            contactId = plan.contactId,
            previousOperationId = outcome.operationId.toByteArray(),
            namespace = outcome.namespace.toByteArray(),
            blob = plan.blob,
            ttl = DmTimers.bucketOf(plan.timerCode),
            deadlineHour = plan.deadlineHour,
            itemId = plan.itemId,
            resendCount = plan.resendCount,
        )
        if (!sent) {
            // The contact stopped being sendable between the two transactions, or the relay set
            // shrank: the op is already released, so the item ends `indeterminate` — "may not
            // have been delivered", which is exactly what is true.
            database.transaction { tx ->
                val item = messages.item(tx.sql, plan.itemId) ?: return@transaction
                terminal(tx, outcome.operationId.toByteArray(), plan.itemId, item, STATE_INDETERMINATE)
            }
        }
        return true
    }

    /**
     * §21.8 point 5: a bundle op. SENT or DEGRADED records the week in
     * `dm_self.bundle_published_week`, and a FAILED or INDETERMINATE one leaves it behind so the
     * next time-triggered `OWNER-WEEK` pass re-seals while the week's validity lasts.
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
    ) {
        messages.setItemState(tx, itemId, item.state, state)
        messages.setMessageState(tx, itemId, MessageStore.STATE_QUEUED, state)
        // §7.5 "Retained blob": messaging's copy exists only so an identical resend can repeat the
        // bytes, and it goes at the terminal outcome. It is E2E ciphertext no key on this device
        // opens, and T25 counts its lifetime from here (L7-D7).
        messages.clearOpBlob(tx, operationId)
        messages.clearItemL0(tx, itemId)
    }

    private class Resend(
        val contactId: ByteArray,
        val itemId: ByteArray,
        val blob: ByteArray,
        val timerCode: Int,
        val deadlineHour: Long,
        val resendCount: Int,
    )

    companion object {
        /** §7.5: `Outbox.outcomes(DM, 64) + Outbox.outcomes(PREKEYS, 16)`. */
        const val DM_OUTCOMES: Int = 64

        /** The bundle half of the same loop. */
        const val PREKEY_OUTCOMES: Int = 16

        /** G-7, C-15: at most two identical-bytes resends per op. */
        const val MAX_RESENDS: Int = 2

        /** `dm_message.state` and `dm_outbound_item.state` (§13.5). */
        const val STATE_SENT: String = "sent"
        const val STATE_DEGRADED: String = "degraded"
        const val STATE_FAILED: String = "failed"
        const val STATE_INDETERMINATE: String = "indeterminate"
    }
}
