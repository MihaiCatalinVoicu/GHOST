package org.ghost.messaging.store

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

    fun pendingSends(sql: SqlExecutor, contactId: ByteArray): List<PendingRow> {
        val out = ArrayList<PendingRow>()
        sql.query(
            "SELECT item_id, contact_id, fail_after_hour FROM dm_pending_send WHERE contact_id = ? " +
                "ORDER BY item_id",
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
         * The four reads of `dm_message`, spelled out as constants so the expired-row lint's
         * static half sees the table name (an interpolated one it cannot see, §22.10 item 3) and
         * so `DmDaoQueries` can register the **same** string the DAO runs.
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

        /** `dm_message.state` for an outgoing row that has not been enqueued yet (§13.5). */
        const val STATE_QUEUED: String = "queued"

        /** An incoming row the user has not displayed (§13.5). */
        const val STATE_UNREAD: String = "unread"

        /** `dm_outbound_item.state`: waiting for establishment (§21.8 point 1). */
        const val ITEM_PENDING: String = "pending"

        /** Handed to the outbox. */
        const val ITEM_ENQUEUED: String = "enqueued"
    }
}
