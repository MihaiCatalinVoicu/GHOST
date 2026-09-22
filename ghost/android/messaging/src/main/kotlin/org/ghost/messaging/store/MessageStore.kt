package org.ghost.messaging.store

import org.ghost.messaging.engine.DmTime
import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.SyncTransaction

/**
 * The message-side rows of schema v5 (Phase 9 design §13.6 step 5): `dm_message`, `dm_reaction`,
 * `dm_seen`, `dm_outbound_item`, `dm_outbound_op` and `dm_pending_send`.
 *
 * **Every read of `dm_message` carries the expiry filter of §10.7 point 4** —
 * `delete_at_minute IS NULL OR delete_at_minute > :now_e` — and is registered in `:storage`'s
 * `DmDaoQueries`, which runs it against a world that still holds expired rows and one that does
 * not and requires the two to be indistinguishable (mutant ME-16, §22.10 item 3). Physical
 * deletion lags — a frozen process, a deferred alarm, a reboot with no network — so the filter is
 * the only thing between an expired message and the screen.
 *
 * **Every write goes through the caller's [SyncTransaction]**, and there is no `REPLACE` anywhere
 * (gate G-DM4).
 */
internal class MessageStore {

    /** A `dm_message` row, as the facade renders it. */
    class MessageRow(
        val messageId: ByteArray,
        val conversationId: ByteArray,
        val outgoing: Boolean,
        val kind: Int,
        val authorMinute: Long,
        val sortMinute: Long,
        val minuteIndex: Int,
        val timerCode: Int,
        val bodyEnv: ByteArray?,
        val state: String,
    ) {
        /** Never shows the body (T3). */
        override fun toString(): String = "MessageRow(state=$state)"
    }

    /** A `dm_outbound_item` row: every outgoing L0, whatever its kind (§21.8 point 1). */
    class ItemRow(
        val itemId: ByteArray,
        val contactId: ByteArray,
        val messageRef: ByteArray?,
        val kind: Int,
        val control: String?,
        val l0Env: ByteArray?,
        val deadlineHour: Long,
        val state: String,
    ) {
        override fun toString(): String = "ItemRow(kind=$kind, state=$state)"
    }

    /** A `dm_outbound_op` row of purpose `item` (§21.8 point 1). */
    class OpRow(
        val operationId: ByteArray,
        val purpose: String,
        val itemId: ByteArray?,
        val bundleWeek: Long?,
        val blob: ByteArray?,
        val resendCount: Int,
        val deadlineHour: Long,
    ) {
        override fun toString(): String = "OpRow(purpose=$purpose, resends=$resendCount)"
    }

    /** A `dm_pending_send` row: an item waiting for establishment (§5.5, §21.7). */
    class PendingRow(
        val itemId: ByteArray,
        val contactId: ByteArray,
        val failAfterHour: Long,
    ) {
        override fun toString(): String = "PendingRow(failAfterHour=$failAfterHour)"
    }

    // ---------------------------------------------------------------- dm_message

    /**
     * The newest page of a conversation (§13.2 `conversation`), ordered by R-O1
     * `(sort_minute, minute_index, message_id)` descending so the caller can page backwards.
     */
    fun conversationPage(
        sql: SqlExecutor,
        conversationId: ByteArray,
        nowMinute: Long,
        limit: Int,
    ): List<MessageRow> = page(
        sql,
        CONVERSATION_PAGE,
        listOf(conversationId, nowMinute, limit.toLong()),
    )

    /** The page before a cursor, for the same order (§13.2 `before`). */
    @Suppress("LongParameterList")
    fun conversationPageBefore(
        sql: SqlExecutor,
        conversationId: ByteArray,
        nowMinute: Long,
        limit: Int,
        beforeSortMinute: Long,
        beforeMinuteIndex: Int,
        beforeMessageId: ByteArray,
    ): List<MessageRow> = page(
        sql,
        CONVERSATION_PAGE_BEFORE,
        listOf(
            conversationId,
            nowMinute,
            beforeSortMinute,
            beforeSortMinute,
            beforeMinuteIndex.toLong(),
            beforeSortMinute,
            beforeMinuteIndex.toLong(),
            beforeMessageId,
            limit.toLong(),
        ),
    )

    private fun page(sql: SqlExecutor, query: String, args: List<Any?>): List<MessageRow> {
        val out = ArrayList<MessageRow>()
        sql.query(query, args) { r -> out += readMessage(r) }
        return out
    }

    /** One message, if it exists and has not expired: the reaction target rule of §7.4.1. */
    fun message(sql: SqlExecutor, messageId: ByteArray, nowMinute: Long): MessageRow? {
        var row: MessageRow? = null
        sql.query(MESSAGE_BY_ID, listOf(messageId, nowMinute)) { r -> row = readMessage(r) }
        return row
    }

    /** The unread count the notification port is given; counts only, never content (§10.7). */
    fun unreadCount(sql: SqlExecutor, nowMinute: Long): Int {
        var count = 0
        sql.query(UNREAD_COUNT, listOf(nowMinute)) { r -> count = r.long(0).toInt() }
        return count
    }

    /**
     * `minute_index` = `1 + max(minute_index)` over the sender's own **live** outgoing rows of the
     * conversation with the same `author_minute`, 0 if none (§7.7).
     *
     * No counter is persisted (T33), so an expired row can make an index repeat and `message_id`
     * breaks the tie — which is why the read carries the expiry filter like every other.
     */
    fun nextMinuteIndex(
        sql: SqlExecutor,
        conversationId: ByteArray,
        authorMinute: Long,
        nowMinute: Long,
    ): Int {
        var next = 0
        sql.query(NEXT_MINUTE_INDEX, listOf(conversationId, authorMinute, nowMinute)) { r ->
            if (!r.isNull(0)) next = r.long(0).toInt() + 1
        }
        return next
    }

    @Suppress("LongParameterList")
    fun insertMessage(
        tx: SyncTransaction,
        messageId: ByteArray,
        conversationId: ByteArray,
        outgoing: Boolean,
        kind: Int,
        authorMinute: Long,
        sortMinute: Long,
        minuteIndex: Int,
        timerCode: Int,
        bodyEnv: ByteArray?,
        state: String,
        expireAtMinute: Long?,
        unreadDeadlineMinute: Long?,
    ) {
        tx.sql.exec(
            "INSERT INTO dm_message(message_id, conversation_id, direction, kind, author_minute, " +
                "sort_minute, minute_index, timer_code, body_env, state, expire_at_minute, " +
                "unread_deadline_minute, delete_at_minute) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            listOf(
                messageId,
                conversationId,
                if (outgoing) "out" else "in",
                kind.toLong(),
                authorMinute,
                sortMinute,
                minuteIndex.toLong(),
                timerCode.toLong(),
                bodyEnv,
                state,
                expireAtMinute,
                unreadDeadlineMinute,
                expireAtMinute ?: unreadDeadlineMinute,
            ),
        )
    }

    /**
     * The minute the **next live** row becomes deletable, or null when none will (§10.7 trigger 1,
     * §21.9 rule 1: the actor timer includes "the next `delete_at_minute`").
     *
     * It is a read path like any other and carries the §10.7 point 4 bound in its own shape: rows
     * already past [nowMinute] are excluded, because a wake for a row SWEEP should already have
     * deleted would be a wake in the past — an alarm loop — rather than the next deadline. A row
     * with the timer off has `delete_at_minute IS NULL` and never becomes one.
     */
    fun nextDeleteAtMinute(sql: SqlExecutor, nowMinute: Long): Long? {
        var next: Long? = null
        sql.query(NEXT_DELETE_AT, listOf(nowMinute)) { r -> if (!r.isNull(0)) next = r.long(0) }
        return next
    }

    /**
     * §10.6: one batch of the rows SWEEP deletes, at most [batch] of them, oldest deadline first.
     *
     * This is **not** a read path and is registered in `:storage`'s `DmSweepQueries` rather than in
     * `DmDaoQueries`: it is the expiry enforcement itself, and it is judged by the opposite
     * contract — it must return exactly the rows the sweep removes and nothing at all once they are
     * gone. The ids are needed twice, for the delete and for `MediaPort.onMessagesDeleted(tx, ids)`
     * inside the same transaction (§10.6), and SQLite's `DELETE` carries no `LIMIT` on Android's
     * build, so the batch bound of §10.6 has to be expressed here.
     */
    fun expiredMessages(sql: SqlExecutor, nowMinute: Long, batch: Int): List<ByteArray> {
        val out = ArrayList<ByteArray>()
        sql.query(EXPIRED_BATCH, listOf(nowMinute, batch.toLong())) { r -> out += r.blob(0) }
        return out
    }

    /** §10.6: the message row goes; reactions, items, ops and pending sends cascade. */
    fun deleteMessage(tx: SyncTransaction, messageId: ByteArray): Int =
        tx.sql.execUpdate("DELETE FROM dm_message WHERE message_id = ?", listOf(messageId))

    /**
     * R-T6 and §10.3: `expire_at_minute` moves **only earlier**, so DISPLAY writes it under a
     * guard rather than plainly.
     *
     * The `dm_message_expiry` trigger aborts an increase, which would take the whole DISPLAY
     * transaction down; the guard turns a second display of the same message into "nothing
     * changed". `delete_at_minute` follows its CHECK and is written in the same statement — it is
     * the one column of the three that may move **later**, because a displayed message's countdown
     * legitimately outlives the unread cap (ADR-27 point 9, §21.10 point 6).
     *
     * Returns how many rows changed. **Zero is not a failure** and the caller does not check it:
     * the guard matches a NULL `expire_at_minute`, so a row it leaves alone is one that already
     * carries an earlier minute — which is exactly what the state change that follows needs
     * (`CHECK (state <> 'read' OR timer_code = 0 OR expire_at_minute IS NOT NULL)`). A second read
     * here to confirm it would be a read of `dm_message` without the expiry filter, which is what
     * the DAO lint refuses and rightly: the caller has already read the row **with** the filter, in
     * this same transaction.
     */
    fun lowerExpireAt(tx: SyncTransaction, messageId: ByteArray, expireAtMinute: Long): Int =
        tx.sql.execUpdate(
            "UPDATE dm_message SET expire_at_minute = ?, delete_at_minute = ? " +
                "WHERE message_id = ? AND (expire_at_minute IS NULL OR expire_at_minute > ?)",
            listOf(expireAtMinute, expireAtMinute, messageId, expireAtMinute),
        )

    /** §10.6: `dm_seen` tags past their `until_day` (D3's window, §21.10 point 3). */
    fun deleteSeenTags(tx: SyncTransaction, today: Long): Int =
        tx.sql.execUpdate("DELETE FROM dm_seen WHERE until_day <= ?", listOf(today))

    /**
     * §10.6 and R-T5: `dm_pending_send` rows whose item can no longer be stored anywhere.
     *
     * The rows of an **expired** message cascade with it; this covers the other shape — an item
     * whose `fail_after_hour` passed while its message is still live (the timer is off, or longer
     * than the store window). `DmActor.failExpiredPending` moves those items to `failed` on a
     * time-triggered pass; SWEEP is the trigger of last resort for a device that only ever sweeps.
     */
    fun expiredPendingSends(sql: SqlExecutor, nowSeconds: Long, batch: Int): List<PendingRow> {
        val out = ArrayList<PendingRow>()
        sql.query(
            "SELECT item_id, contact_id, fail_after_hour FROM dm_pending_send " +
                "WHERE fail_after_hour <= ? ORDER BY fail_after_hour, item_id LIMIT ?",
            listOf(nowSeconds, batch.toLong()),
        ) { r -> out += PendingRow(r.blob(0), r.blob(1), r.long(2)) }
        return out
    }

    /**
     * §22.8.5 rule 1: the weeks for which an out pair key must be kept because a **live retryable
     * item** of this contact could still be re-encrypted under it.
     *
     * > Besides `K_{week(now)}` of the newest generation, the sender keeps the out key (generation,
     * > week) of every earlier week w for which an item of c authored in w is `pending`, `enqueued`
     * > or `failed` with `deadline_hour > now` (at most 7 days); SWEEP erases it at that deadline.
     *
     * The author minute is not a column of `dm_outbound_item` (a CONTROL and a REACTION have no
     * `dm_message` row of their own to read it from), so the week is derived from the one column
     * that is: `deadline_hour = ceil_hour(author_minute + min(bucket, 7 d))`, hence
     * `author_minute ∈ [deadline_hour − 7 d − 1 h, deadline_hour]` and the author week is one of
     * the (at most three) weeks that interval spans. Keeping that whole interval is a superset of
     * the rule and costs nothing against P-7: the item itself is gone at its deadline, so the extra
     * weeks are erased at the same instant the exactly-derived one would have been.
     */
    fun retryableItemWeeks(
        sql: SqlExecutor,
        contactId: ByteArray,
        nowSeconds: Long,
    ): Set<Long> {
        val weeks = HashSet<Long>()
        sql.query(
            "SELECT deadline_hour FROM dm_outbound_item WHERE contact_id = ? " +
                "AND state IN ('pending', 'enqueued', 'failed') AND deadline_hour > ?",
            listOf(contactId, nowSeconds),
        ) { r ->
            val deadline = r.long(0)
            val earliest = deadline - RETRY_AUTHOR_SPAN_SECONDS
            var week = DmTime.week(earliest)
            val last = DmTime.week(deadline)
            while (week <= last) {
                weeks += week
                week += 1
            }
        }
        return weeks
    }

    /** The `dm_message_state` transitions of §13.5, guarded by the state the caller expects. */
    fun setMessageState(
        tx: SyncTransaction,
        messageId: ByteArray,
        from: String,
        to: String,
    ): Boolean = tx.sql.execUpdate(
        "UPDATE dm_message SET state = ? WHERE message_id = ? AND state = ?",
        listOf(to, messageId, from),
    ) == 1

    private fun readMessage(r: SqlExecutor.Row) = MessageRow(
        messageId = r.blob(0),
        conversationId = r.blob(1),
        outgoing = r.string(2) == "out",
        kind = r.long(3).toInt(),
        authorMinute = r.long(4),
        sortMinute = r.long(5),
        minuteIndex = r.long(6).toInt(),
        timerCode = r.long(7).toInt(),
        bodyEnv = if (r.isNull(8)) null else r.blob(8),
        state = r.string(9),
    )

    // --------------------------------------------------------------- dm_reaction

    /** Inserts or replaces one side's reaction to a message (§7.4.1); an empty grapheme removes it. */
    fun putReaction(
        tx: SyncTransaction,
        targetId: ByteArray,
        fromSelf: Boolean,
        graphemeEnv: ByteArray,
    ) {
        val self = if (fromSelf) 1L else 0L
        val changed = tx.sql.execUpdate(
            "UPDATE dm_reaction SET grapheme_env = ? WHERE target_id = ? AND from_self = ?",
            listOf(graphemeEnv, targetId, self),
        )
        if (changed == 0) {
            tx.sql.exec(
                "INSERT INTO dm_reaction(target_id, from_self, grapheme_env) VALUES (?, ?, ?)",
                listOf(targetId, self, graphemeEnv),
            )
        }
    }

    fun deleteReaction(tx: SyncTransaction, targetId: ByteArray, fromSelf: Boolean) {
        tx.sql.exec(
            "DELETE FROM dm_reaction WHERE target_id = ? AND from_self = ?",
            listOf(targetId, if (fromSelf) 1L else 0L),
        )
    }

    // ------------------------------------------------------------------ dm_seen

    /**
     * D3 (§7.6): `INSERT OR IGNORE` of the keyed tag, which deletes nothing and so needs no
     * REPLACE guard. True when the tag was new — a false is `drop(duplicate)`.
     */
    fun markSeen(tx: SyncTransaction, tag: ByteArray, untilDay: Long): Boolean =
        tx.sql.execUpdate(
            "INSERT OR IGNORE INTO dm_seen(tag, until_day) VALUES (?, ?)",
            listOf(tag, untilDay),
        ) == 1

    // --------------------------------------------------------- dm_outbound_item

    fun item(sql: SqlExecutor, itemId: ByteArray): ItemRow? {
        var row: ItemRow? = null
        sql.query(
            "SELECT item_id, contact_id, message_ref, kind, control, l0_env, deadline_hour, state " +
                "FROM dm_outbound_item WHERE item_id = ?",
            listOf(itemId),
        ) { r -> row = readItem(r) }
        return row
    }

    @Suppress("LongParameterList")
    fun insertItem(
        tx: SyncTransaction,
        itemId: ByteArray,
        contactId: ByteArray,
        messageRef: ByteArray?,
        kind: Int,
        control: String?,
        l0Env: ByteArray?,
        deadlineHour: Long,
        state: String,
    ) {
        tx.sql.exec(
            "INSERT INTO dm_outbound_item(item_id, contact_id, message_ref, kind, control, l0_env, " +
                "deadline_hour, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            listOf(itemId, contactId, messageRef, kind.toLong(), control, l0Env, deadlineHour, state),
        )
    }

    fun setItemState(tx: SyncTransaction, itemId: ByteArray, from: String, to: String): Boolean =
        tx.sql.execUpdate(
            "UPDATE dm_outbound_item SET state = ? WHERE item_id = ? AND state = ?",
            listOf(to, itemId, from),
        ) == 1

    /**
     * A pending item that will never be sent: the `dm_pending_send` row goes and the item and its
     * message move `pending → failed` and `queued → failed` (§21.7 point 5, §13.5).
     *
     * The three writes live together because every caller owes all three. An item left `pending`
     * with no pending send breaks §21.8 point 7's structural invariant ("every `pending` or
     * `enqueued` item has a pending send or an unreleased op"), and a `dm_message` left `queued` is
     * a message the UI shows as still on its way with nothing left that could ever resolve it —
     * which is what `block` did to the messages queued before it.
     */
    fun failPending(tx: SyncTransaction, itemId: ByteArray) {
        deletePendingSend(tx, itemId)
        setItemState(tx, itemId, ITEM_PENDING, STATE_FAILED)
        setMessageState(tx, itemId, STATE_QUEUED, STATE_FAILED)
    }

    /**
     * Drops the stored L0 at a terminal outcome (§21.8 point 1: `l0_env` becomes NULL at SENT,
     * DEGRADED or INDETERMINATE; a FAILED item keeps it until its deadline, for the user retry).
     */
    fun clearItemL0(tx: SyncTransaction, itemId: ByteArray) {
        tx.sql.exec("UPDATE dm_outbound_item SET l0_env = NULL WHERE item_id = ?", listOf(itemId))
    }

    private fun readItem(r: SqlExecutor.Row) = ItemRow(
        itemId = r.blob(0),
        contactId = r.blob(1),
        messageRef = if (r.isNull(2)) null else r.blob(2),
        kind = r.long(3).toInt(),
        control = if (r.isNull(4)) null else r.string(4),
        l0Env = if (r.isNull(5)) null else r.blob(5),
        deadlineHour = r.long(6),
        state = r.string(7),
    )

    // ----------------------------------------------------------- dm_outbound_op

    fun op(sql: SqlExecutor, operationId: ByteArray): OpRow? {
        var row: OpRow? = null
        sql.query(
            "SELECT operation_id, purpose, item_id, bundle_week, blob, resend_count, deadline_hour " +
                "FROM dm_outbound_op WHERE operation_id = ?",
            listOf(operationId),
        ) { r -> row = readOp(r) }
        return row
    }

    @Suppress("LongParameterList")
    fun insertItemOp(
        tx: SyncTransaction,
        operationId: ByteArray,
        itemId: ByteArray,
        blob: ByteArray,
        resendCount: Int,
        deadlineHour: Long,
    ) {
        tx.sql.exec(
            "INSERT INTO dm_outbound_op(operation_id, purpose, item_id, bundle_week, blob, " +
                "resend_count, deadline_hour) VALUES (?, 'item', ?, NULL, ?, ?, ?)",
            listOf(operationId, itemId, blob, resendCount.toLong(), deadlineHour),
        )
    }

    /**
     * Drops the retained blob at a terminal outcome (§7.5 "Retained blob"): Phase 7 wipes the op's
     * own payload, and messaging's copy exists only so an INDETERMINATE resend can repeat the
     * identical bytes. It is E2E ciphertext no key on this device opens, and it goes as soon as
     * there is nothing left to resend.
     */
    fun clearOpBlob(tx: SyncTransaction, operationId: ByteArray) {
        tx.sql.exec(
            "UPDATE dm_outbound_op SET blob = NULL WHERE operation_id = ?",
            listOf(operationId),
        )
    }

    private fun readOp(r: SqlExecutor.Row) = OpRow(
        operationId = r.blob(0),
        purpose = r.string(1),
        itemId = if (r.isNull(2)) null else r.blob(2),
        bundleWeek = if (r.isNull(3)) null else r.long(3),
        blob = if (r.isNull(4)) null else r.blob(4),
        resendCount = r.long(5).toInt(),
        deadlineHour = r.long(6),
    )

    // --------------------------------------------------------- dm_pending_send

    /**
     * A contact's pending sends, **oldest first**.
     *
     * The order matters because a flush turns these rows into ratchet steps: `item_id` is 16
     * random bytes, so ordering by it gives the Olm chain an arbitrary permutation of the order
     * the user wrote the messages in — the display order survives (R-O1 sorts by
     * `sort_minute, minute_index`), but the chain order the gap hold reconstructs no longer
     * matches the author order it is built around (§7.7).
     *
     * `dm_pending_send` stores no author minute and is `WITHOUT ROWID` with a random primary key,
     * so the key is the item's `deadline_hour`: `ceil_hour(author_minute + min(bucket, 7 d))`, which
     * is monotone in the author minute for every item of the same TTL bucket — that is, for every
     * item of one conversation between two timer changes. `item_id` breaks the remaining ties
     * deterministically.
     */
    fun pendingSends(sql: SqlExecutor, contactId: ByteArray): List<PendingRow> {
        val out = ArrayList<PendingRow>()
        sql.query(
            "SELECT p.item_id, p.contact_id, p.fail_after_hour FROM dm_pending_send p " +
                "JOIN dm_outbound_item i ON i.item_id = p.item_id " +
                "WHERE p.contact_id = ? ORDER BY i.deadline_hour, p.item_id",
            listOf(contactId),
        ) { r -> out += PendingRow(r.blob(0), r.blob(1), r.long(2)) }
        return out
    }

    fun insertPendingSend(
        tx: SyncTransaction,
        itemId: ByteArray,
        contactId: ByteArray,
        failAfterHour: Long,
    ) {
        tx.sql.exec(
            "INSERT INTO dm_pending_send(item_id, contact_id, fail_after_hour) VALUES (?, ?, ?)",
            listOf(itemId, contactId, failAfterHour),
        )
    }

    fun deletePendingSend(tx: SyncTransaction, itemId: ByteArray) {
        tx.sql.exec("DELETE FROM dm_pending_send WHERE item_id = ?", listOf(itemId))
    }

    companion object {
        /**
         * The **seven** reads of `dm_message`, spelled out as constants so the expired-row lint's
         * static half sees the table name (an interpolated one it cannot see, §22.10 item 3) and
         * so `DmDaoQueries` can register the **same** string the DAO runs.
         *
         * Six are registered in `DmDaoQueries` and judged by the read contract; [EXPIRED_BATCH] is
         * SWEEP's own and is registered in `DmSweepQueries`, under the mirror of it. The count is
         * written out because it is the thing that goes stale: S9 added the last two and left this
         * sentence saying "four".
         */
        /** §13.2 `conversation`, newest first; R-O1's order, reversed for paging. */
        const val CONVERSATION_PAGE: String =
            "SELECT message_id, conversation_id, direction, kind, author_minute, sort_minute, " +
                "minute_index, timer_code, body_env, state FROM dm_message " +
                "WHERE conversation_id = ? AND (delete_at_minute IS NULL OR delete_at_minute > ?) " +
                "ORDER BY sort_minute DESC, minute_index DESC, message_id DESC LIMIT ?"

        /** The same page before a cursor, with the tuple comparison written out (§13.2). */
        const val CONVERSATION_PAGE_BEFORE: String =
            "SELECT message_id, conversation_id, direction, kind, author_minute, sort_minute, " +
                "minute_index, timer_code, body_env, state FROM dm_message " +
                "WHERE conversation_id = ? AND (delete_at_minute IS NULL OR delete_at_minute > ?) " +
                "AND (sort_minute < ? OR (sort_minute = ? AND minute_index < ?) " +
                "OR (sort_minute = ? AND minute_index = ? AND message_id < ?)) " +
                "ORDER BY sort_minute DESC, minute_index DESC, message_id DESC LIMIT ?"

        /** One message, for the reaction target rule and the display transition. */
        const val MESSAGE_BY_ID: String =
            "SELECT message_id, conversation_id, direction, kind, author_minute, sort_minute, " +
                "minute_index, timer_code, body_env, state FROM dm_message " +
                "WHERE message_id = ? AND (delete_at_minute IS NULL OR delete_at_minute > ?)"

        /** The unread badge (§10.7): a count, which is mutant ME-16's own shape. */
        const val UNREAD_COUNT: String =
            "SELECT count(*) FROM dm_message WHERE direction = 'in' AND state = 'unread' " +
                "AND (delete_at_minute IS NULL OR delete_at_minute > ?)"

        /** `minute_index` (§7.7): over live outgoing rows of the same author minute. */
        const val NEXT_MINUTE_INDEX: String =
            "SELECT max(minute_index) FROM dm_message WHERE conversation_id = ? " +
                "AND direction = 'out' AND author_minute = ? " +
                "AND (delete_at_minute IS NULL OR delete_at_minute > ?)"

        /**
         * The actor timer's and the alarm's next wake (§10.7 trigger 1). A read like any other: it
         * is over live rows only, so it cannot differ between a swept and an unswept world.
         */
        const val NEXT_DELETE_AT: String =
            "SELECT min(delete_at_minute) FROM dm_message " +
                "WHERE delete_at_minute IS NOT NULL AND delete_at_minute > ?"

        /**
         * SWEEP's own batch (§10.6). Registered in `DmSweepQueries`, not in `DmDaoQueries`: it
         * names the expired rows on purpose, and the lint judges it by the opposite contract.
         */
        const val EXPIRED_BATCH: String =
            "SELECT message_id FROM dm_message WHERE delete_at_minute <= ? " +
                "ORDER BY delete_at_minute, message_id LIMIT ?"

        /** `dm_message.state` for an outgoing row that has not been enqueued yet (§13.5). */
        const val STATE_QUEUED: String = "queued"

        /** An incoming row the user has not displayed (§13.5). */
        const val STATE_UNREAD: String = "unread"

        /** An incoming row the user has seen; its countdown started at that display (§10.3). */
        const val STATE_READ: String = "read"

        /**
         * How far before its `deadline_hour` an item may have been authored: the 7-day store cap of
         * R-T4 plus the hour `ceil_hour` may add. Used by [retryableItemWeeks] to bound the author
         * week without a column for the author minute.
         */
        const val RETRY_AUTHOR_SPAN_SECONDS: Long =
            7 * DmTime.DAY + DmTime.HOUR

        /** `dm_outbound_item.state`: waiting for establishment (§21.8 point 1). */
        const val ITEM_PENDING: String = "pending"

        /** Handed to the outbox. */
        const val ITEM_ENQUEUED: String = "enqueued"

        /**
         * `dm_message.state` and `dm_outbound_item.state` for an item that will not be stored
         * (§13.5). Shared by every caller of [failPending].
         */
        const val STATE_FAILED: String = "failed"
    }
}
