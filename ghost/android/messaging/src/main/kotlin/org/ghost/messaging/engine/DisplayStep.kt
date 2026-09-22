package org.ghost.messaging.engine

import org.ghost.messaging.port.DmClock
import org.ghost.messaging.store.MessageStore
import org.ghost.sync.api.SyncDatabase

/**
 * **DISPLAY** (Phase 9 design §7.2, §10.3, §21.10 point 6): the recipient's countdown starts when
 * the message is **first shown**, not when it arrived.
 *
 * > | Recipient, displayed | `markDisplayed(ids)` (Phase 13 UI; the DISPLAY transaction) |
 * > `expire_at_minute = ceil_minute(now + timer)` | only if earlier than an existing value |
 *
 * **Why display and not receipt.** ADR-27 point 9: a 5-minute message the recipient never opened
 * must not be gone before it is read, and one that *was* read must go 5 minutes later. The unread
 * cap (`unread_deadline_minute`, §10.3, C-11) is the other half and is written at consume; this
 * step may push `delete_at_minute` **past** it, which is the one direction in which a deletion time
 * legitimately moves later — the CHECK on `delete_at_minute` says so
 * (`COALESCE(expire_at_minute, unread_deadline_minute)`) and the `dm_message_expiry` trigger
 * deliberately names only the other two columns (§21.10 point 6). Mutant **ME-7** ("recipient
 * countdown at receive") is this step not existing.
 *
 * **Three guards, each of which is a rule rather than defensive code.**
 *  1. **An expired id is ignored** (§21.10 point 6: "DISPLAY ignores ids whose `delete_at_minute ≤
 *     now_e`"). A stale `markDisplayed` — the UI held a list across the unread cap, or the user
 *     unlocked a phone that had been frozen for a day — must not resurrect a message by giving it
 *     a fresh `expire_at_minute` later than the cap it already passed. The read that finds the row
 *     is `MessageStore.message`, which carries the §10.7 point 4 filter, so this guard is the
 *     filter and needs no second condition.
 *  2. **Only earlier** (R-T6). `expire_at_minute` is written with a guard, not with a plain
 *     `UPDATE`: the `dm_message_expiry` trigger aborts an increase, and a second display of the
 *     same message a minute later would otherwise abort the whole transaction — so a repeated
 *     `markDisplayed` writes nothing instead of failing. A row the guard leaves alone already
 *     carries an earlier minute, which is what the state change below needs
 *     (`CHECK (state <> 'read' OR timer_code = 0 OR expire_at_minute IS NOT NULL)`), so the
 *     changed-row count is deliberately not inspected.
 *  3. **Incoming and unread only.** An outgoing row's countdown started at its own SEND commit and
 *     the state machine has no `sent → read` edge (§13.5); a row already `read` keeps the minute
 *     its first display fixed, which is what "the recipient countdown starts at the first display"
 *     means.
 *
 * **The timer is the message's own** (§10.5: "a message is always deleted by **its own**
 * `timer_code`, whatever the conversation timer is now"), which is why nothing here reads
 * `dm_conversation`.
 *
 * With the timer off there is no countdown at all: `expire_at_minute` stays NULL, the row still
 * moves to `read`, and the `timer_code = 0` CHECK admits it.
 */
internal class DisplayStep(
    private val database: SyncDatabase,
    private val clock: DmClock,
) {
    private val messages = MessageStore()

    /**
     * Marks [messageIds] displayed. Returns how many rows changed — a count, never a time or an id
     * (T3).
     *
     * One transaction for the batch: the UI marks a screenful at once, and a partial commit would
     * leave half a screen counted as unread by the notification that follows.
     */
    fun markDisplayed(messageIds: List<ByteArray>): Int {
        if (messageIds.isEmpty()) return 0
        val now = clock.nowEpochSeconds()
        val nowMinute = DmTime.floorMinute(now)
        return database.transaction { tx ->
            var displayed = 0
            for (messageId in messageIds) {
                val row = messages.message(tx.sql, messageId, nowMinute) ?: continue
                if (row.outgoing) continue
                if (row.state != MessageStore.STATE_UNREAD) continue
                // §10.3: `ceil_minute(now + timer)`, from the display and not from the author
                // minute — a sender whose clock runs ahead cannot lengthen this either (C-11).
                val expireAt = DmTimers.senderExpireMinute(now, row.timerCode)
                if (expireAt != null) messages.lowerExpireAt(tx, messageId, expireAt)
                if (messages.setMessageState(
                        tx,
                        messageId,
                        MessageStore.STATE_UNREAD,
                        MessageStore.STATE_READ,
                    )
                ) {
                    displayed += 1
                }
            }
            displayed
        }
    }
}
