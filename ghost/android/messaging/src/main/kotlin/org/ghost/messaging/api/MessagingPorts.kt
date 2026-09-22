package org.ghost.messaging.api

import org.ghost.sync.api.SyncTransaction

/**
 * The two ports the ephemeral slice ships (Phase 9 design §13.1 `org.ghost.messaging.api`, §10.6,
 * §10.7, §21.10 point 9).
 *
 * Both are **ports and no-ops in Phase 9**: the implementations belong to Phase 13 (the
 * notification) and Phase 11 (media). What Phase 9 owns is their *shape*, because the shape is the
 * guarantee — a notification that could carry a sender or a body would be one that Android's
 * notification history keeps for 24 hours (§10.7), and a media deletion outside the deletion
 * transaction would be one a crash could lose.
 */

/**
 * §10.7 (Q19), T33: **the whole of what the DM layer tells a notifier is a number.**
 *
 * > `NotificationPort` exposes only `onUnreadChanged(count: Int)`; the Phase 13 implementation
 * > posts one constant text with no sender, conversation id or content, **locked or not**
 * > (Android's notification history keeps what was posted for 24 h).
 *
 * The interface is deliberately impossible to widen quietly: `NotificationPortContractTest`
 * reflects over it and refuses any member that takes or returns anything but an `Int`, which is
 * the Phase 9 half of the ADR-27 notification rules (§21.10 point 9 moves the
 * `getActiveNotifications()` and notification-history checks to Phase 13 with its permission ADR).
 * Mutant **ME-13** ("a notification with content") cannot be written against this signature at
 * all; it can only be written by changing it, and then the contract test fails.
 *
 * **Count semantics.** [count] is the number of **live** unread incoming messages — the expiry
 * filter of §10.7 point 4 applies, so a message whose timer passed is not counted even before
 * SWEEP has deleted it. It is published after the commit of `RECV`, `HELD`, `DISPLAY` and `SWEEP`
 * (§7.2), and `0` means "cancel": there is nothing left to tell the user about.
 */
fun interface NotificationPort {
    /** The live unread count after the transaction that changed it committed. Never content. */
    fun onUnreadChanged(count: Int)
}

/**
 * §10.6's media row of the deletion cascade: "`MediaPort.onMessagesDeleted(tx, ids)` (Phase 11; a
 * no-op port in Phase 9)".
 *
 * **Why it takes the transaction.** The attachments of an expired message must go with the row, in
 * the same commit: a port called after the commit would leave, after a process death in between,
 * a thumbnail of a message the user was told had disappeared and that nothing would ever look at
 * again. Phase 11 wires the media store behind it; Phase 9 wires [NONE].
 *
 * The ids are the messages SWEEP is deleting in that transaction, and nothing else — no body, no
 * conversation and no contact (T33).
 */
interface MediaPort {
    fun onMessagesDeleted(tx: SyncTransaction, ids: List<MessageId>)

    companion object {
        /** The Phase 9 implementation: there is no media layer yet, so there is nothing to delete. */
        val NONE: MediaPort = object : MediaPort {
            override fun onMessagesDeleted(tx: SyncTransaction, ids: List<MessageId>) = Unit

            override fun toString(): String = "MediaPort.NONE"
        }
    }
}
