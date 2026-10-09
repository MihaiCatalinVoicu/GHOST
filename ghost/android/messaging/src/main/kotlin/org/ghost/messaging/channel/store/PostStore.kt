package org.ghost.messaging.channel.store

import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.SyncTransaction

/**
 * The post-side rows of schema v7 (Phase 10 design §6.3, §8.2, §8.5, §9): `ch_post`, `ch_reaction`,
 * `ch_pending_post`, `ch_seen`, `ch_reveal` and `ch_outbound_op`.
 *
 * **Every read of an expiring table carries its filter**, as §8.2 and §10.1 require ("every read query
 * filters expired rows", mutant ME-16 over `ch_*`): `ch_post` by **both** of its deadlines — `delete_at_minute IS
 * NULL OR delete_at_minute > :now_e` (a NULL deadline is a channel whose timer is off) **and** `relay_expiry_hour
 * IS NULL OR relay_expiry_hour > :now_e` (the relay expiry E of an unread post, §8.2: "an unread post is deleted at
 * min(E, consume + bucket + 1 h)"; a display forgets it, so a read post has none and a timer-off post that is
 * read lives on) —, `ch_reveal` by `delete_at_minute`, `ch_pending_post` by `fail_after_hour > :now`, `ch_seen`
 * by `until_day >= :today`. The first version applied `delete_at_minute` alone, so an unread post whose E had
 * passed was shown, counted and kept by the alarm query, and an unread post of a timer-off channel (no
 * `delete_at_minute` at all) was never swept (the review of S3). Physical deletion lags — a frozen process, a
 * deferred alarm, a reboot — and the filter is the only thing between an expired post and the screen. Every
 * query is spelled out in full, so the lint's static half sees the table, and is registered with `:storage`'s
 * `ChannelExpiredRowLint`, which runs it against a world that still holds expired rows and one that does not
 * and requires the two to be indistinguishable. The sweep's own reads (`expiredPosts`, `expiredPending`,
 * `expiredReveals`) name the opposite set and are judged by the mirror contract.
 *
 * **The order of the posts of a channel** is `(author_minute, author, op_id)`, newest first: every member
 * holds the same three values for a post, so every member shows the same order ("one order everywhere",
 * §12.5) and neither a local counter nor the rowid enters it. §9 lists no `sort_minute` or `minute_index` for
 * channels, which is the one place this differs from `dm_message` (recorded in §19.35, F-2).
 *
 * **Every write goes through the caller's [SyncTransaction]**; no `REPLACE`, no upsert (G-DM4).
 */
internal class PostStore {

    /** A `ch_post` row. Never shows the body or the author (T3). */
    class PostRow(
        val opId: ByteArray,
        val channelId: ByteArray,
        val direction: Direction,
        val author: ByteArray,
        val kind: Int,
        val replyTo: ByteArray?,
        val timerCode: Int,
        val epoch: Long,
        val bodyEnv: ByteArray,
        val state: PostState,
        val authorMinute: Long,
        val displayedMinute: Long?,
        val deleteAtMinute: Long?,
        val relayExpiryHour: Long?,
    ) {
        override fun toString(): String = "PostRow(state=${state.sql})"
    }

    /** The place after which [PostStore.pageBefore] continues: the three values the order is made of. */
    class PostCursor(val authorMinute: Long, val author: ByteArray, val opId: ByteArray) {
        override fun toString(): String = "PostCursor(redacted)"
    }

    class ReactionRow(val target: ByteArray, val author: ByteArray, val graphemeEnv: ByteArray) {
        override fun toString(): String = "ReactionRow(redacted)"
    }

    /** A post waiting for the channel to be current (§6.3.1): its content under the content key, until its op deadline. */
    class PendingRow(val opId: ByteArray, val channelId: ByteArray, val kind: Int, val contentEnv: ByteArray, val failAfterHour: Long) {
        override fun toString(): String = "PendingRow(kind=$kind)"
    }

    class RevealRow(val channelId: ByteArray, val direction: Direction, val peer: ByteArray, val deleteAtMinute: Long?) {
        override fun toString(): String = "RevealRow(direction=${direction.sql})"
    }

    class OpRow(
        val operationId: ByteArray,
        val channelId: ByteArray,
        val purpose: OpPurpose,
        val ref: ByteArray?,
        /** The retained ciphertext of the op's own enqueue (slice S8, §19.45): an INDETERMINATE resend repeats
         *  these identical bytes, never a re-seal. E2E ciphertext; the row takes it to its outcome. */
        val blob: ByteArray,
        /** The op's own deadline of §5.8, hour-grain: the resend bound is checked against it. */
        val deadlineHour: Long,
        /** How many identical-bytes resends this op itself is (Phase 7's "at most twice"). */
        val resends: Int,
    ) {
        override fun toString(): String = "OpRow(purpose=${purpose.sql}, resends=$resends)"
    }

    // ------------------------------------------------------------------------------------ ch_post

    /** The newest page of a channel, in the order above. */
    fun page(sql: SqlExecutor, channelId: ByteArray, nowMinute: Long, limit: Int): List<PostRow> =
        posts(sql, PAGE, listOf(channelId, nowMinute, nowMinute, limit.toLong()))

    /** The page before a cursor, with the tuple comparison written out. */
    fun pageBefore(sql: SqlExecutor, channelId: ByteArray, nowMinute: Long, limit: Int, cursor: PostCursor): List<PostRow> =
        posts(
            sql,
            PAGE_BEFORE,
            listOf(
                channelId, nowMinute, nowMinute,
                cursor.authorMinute, cursor.authorMinute, cursor.author, cursor.authorMinute, cursor.author, cursor.opId,
                limit.toLong(),
            ),
        )

    /** One post, if it exists and has not expired: the reaction target and the quote rule (a reply to an expired post renders as expired). */
    fun post(sql: SqlExecutor, opId: ByteArray, nowMinute: Long): PostRow? {
        var row: PostRow? = null
        sql.query(POST_BY_ID, listOf(opId, nowMinute, nowMinute)) { r -> row = readPost(r) }
        return row
    }

    /** The unread badge of one channel: a count, which is ME-16's own shape. */
    fun unreadCount(sql: SqlExecutor, channelId: ByteArray, nowMinute: Long): Int {
        var n = 0
        sql.query(UNREAD_COUNT, listOf(channelId, nowMinute, nowMinute)) { r -> n = r.long(0).toInt() }
        return n
    }

    /**
     * The next deletion time of a live post, for the actor's timer and the alarm (§8.2): over live rows only, and
     * the earlier of the two deadlines a row has (an unread post dies at its relay expiry E when that comes first).
     */
    fun nextDeleteAt(sql: SqlExecutor, nowMinute: Long): Long? {
        var next: Long? = null
        sql.query(NEXT_DELETE_AT, listOf(nowMinute, nowMinute, nowMinute, nowMinute)) { r -> if (!r.isNull(0)) next = r.long(0) }
        return next
    }

    /** Inserts an outgoing post in `queued` (`CH-POST`): its countdown starts at this commit (§8.2). */
    fun insertOutgoing(
        tx: SyncTransaction,
        opId: ByteArray,
        channelId: ByteArray,
        author: ByteArray,
        kind: Int,
        replyTo: ByteArray?,
        timerCode: Int,
        epoch: Long,
        bodyEnv: ByteArray,
        authorMinute: Long,
        deleteAtMinute: Long?,
    ) {
        checkPost(opId, channelId, author, kind, replyTo, timerCode, epoch, bodyEnv, authorMinute, deleteAtMinute, null)
        insertPost(
            tx, opId, channelId, Direction.OUT, author, kind, replyTo, timerCode, epoch, bodyEnv, PostState.QUEUED,
            authorMinute, deleteAtMinute, null,
        )
    }

    /**
     * An **incoming** post (`CH-RECV`), inserted only when no row — live or expired and not yet swept — already
     * holds [opId]; false when one does. The id is the author's to choose: a member that reuses an id (a replay
     * under another epoch, a collision with an own post) must not make the insert hit the `ch_post_no_replace`
     * guard inside `CH-RECV`, which would roll the batch back until its blob is consumed as poison. The
     * existence test is part of the **write**, so it reads no row into a view (the same reasoning as the DM
     * store's `insertIncomingIfAbsent`).
     */
    fun insertIncomingIfAbsent(
        tx: SyncTransaction,
        opId: ByteArray,
        channelId: ByteArray,
        author: ByteArray,
        kind: Int,
        replyTo: ByteArray?,
        timerCode: Int,
        epoch: Long,
        bodyEnv: ByteArray,
        authorMinute: Long,
        deleteAtMinute: Long?,
        relayExpiryHour: Long?,
    ): Boolean {
        checkPost(opId, channelId, author, kind, replyTo, timerCode, epoch, bodyEnv, authorMinute, deleteAtMinute, relayExpiryHour)
        return tx.sql.execUpdate(
            "INSERT INTO ch_post(op_id, channel_id, direction, author, kind, reply_to, timer_code, epoch, body_env, state, " +
                "author_minute, delete_at_minute, relay_expiry_hour) SELECT ?, ?, 'in', ?, ?, ?, ?, ?, ?, 'unread', ?, ?, ? " +
                "WHERE NOT EXISTS (SELECT 1 FROM ch_post WHERE op_id = ?)",
            listOf(
                opId, channelId, author, kind.toLong(), replyTo, timerCode.toLong(), epoch, bodyEnv, authorMinute,
                deleteAtMinute, relayExpiryHour, opId,
            ),
        ) == 1
    }

    private fun checkPost(
        opId: ByteArray, channelId: ByteArray, author: ByteArray, kind: Int, replyTo: ByteArray?, timerCode: Int,
        epoch: Long, bodyEnv: ByteArray, authorMinute: Long, deleteAtMinute: Long?, relayExpiryHour: Long?,
    ) {
        Fields.bytes("ch_post.op_id", opId, 16)
        Fields.bytes("ch_post.channel_id", channelId, 32)
        Fields.bytes("ch_post.author", author, 32)
        Fields.rangeInt("ch_post.kind", kind, 1, 2)
        Fields.bytesOrNull("ch_post.reply_to", replyTo, 16)
        Fields.rangeInt("ch_post.timer_code", timerCode, 0, 5)
        Fields.nonNegative("ch_post.epoch", epoch)
        Fields.bytesBetween("ch_post.body_env", bodyEnv, 29, MAX_BODY)
        Fields.minute("ch_post.author_minute", authorMinute)
        Fields.minuteOrNull("ch_post.delete_at_minute", deleteAtMinute)
        Fields.hourOrNull("ch_post.relay_expiry_hour", relayExpiryHour)
    }

    private fun insertPost(
        tx: SyncTransaction, opId: ByteArray, channelId: ByteArray, direction: Direction, author: ByteArray, kind: Int,
        replyTo: ByteArray?, timerCode: Int, epoch: Long, bodyEnv: ByteArray, state: PostState, authorMinute: Long,
        deleteAtMinute: Long?, relayExpiryHour: Long?,
    ) {
        val changed = tx.sql.execUpdate(
            "INSERT INTO ch_post(op_id, channel_id, direction, author, kind, reply_to, timer_code, epoch, body_env, state, " +
                "author_minute, delete_at_minute, relay_expiry_hour) SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? " +
                "WHERE NOT EXISTS (SELECT 1 FROM ch_post WHERE op_id = ?)",
            listOf(
                opId, channelId, direction.sql, author, kind.toLong(), replyTo, timerCode.toLong(), epoch, bodyEnv,
                state.sql, authorMinute, deleteAtMinute, relayExpiryHour, opId,
            ),
        )
        if (changed != 1) throw ChannelStoreException(ChannelStoreError.ROW_EXISTS, "ch_post")
    }

    /** A guarded state change: false when the post is not in [from]; an edge the machine lacks is [ChannelStoreError.ILLEGAL_TRANSITION]. */
    fun setState(tx: SyncTransaction, opId: ByteArray, from: PostState, to: PostState): Boolean {
        if (!from.allows(to) || to == PostState.READ) {
            throw ChannelStoreException(ChannelStoreError.ILLEGAL_TRANSITION, "ch_post.state")
        }
        return tx.sql.execUpdate(
            "UPDATE ch_post SET state = ? WHERE op_id = ? AND state = ?",
            listOf(to.sql, opId, from.sql),
        ) == 1
    }

    /**
     * `markDisplayed` (§8.2): an unread post becomes read, its countdown starts at [displayedMinute] and ends at
     * [deleteAtMinute] (the minimum of that and the deadline it already has, which the schema holds to "only
     * earlier"), and the relay expiry it was kept for is forgotten.
     *
     * **The minute is kept only where a countdown needs it**: `displayed_minute` is written for a post whose timer
     * is on and stays NULL for a timer-off post, whose read post has no deadline and no reason to remember when it
     * was opened (F9's `dm_message` stores no time at all with the timer off, T33; the schema refuses the pair).
     *
     * **A post past a deadline is not displayed**: the statement matches only a post that is still live at
     * [displayedMinute] by both of its deadlines. Forgetting E on a post whose E has passed would give it back the
     * life the relay copy no longer has (a UI that held a list across the expiry, a phone unfrozen after a day:
     * the DM `DisplayStep` ignores an expired id for the same reason). False when the post is not unread or is
     * past a deadline.
     */
    fun markDisplayed(tx: SyncTransaction, opId: ByteArray, displayedMinute: Long, deleteAtMinute: Long?): Boolean {
        Fields.minute("ch_post.displayed_minute", displayedMinute)
        Fields.minuteOrNull("ch_post.delete_at_minute", deleteAtMinute)
        return tx.sql.execUpdate(
            "UPDATE ch_post SET state = 'read', displayed_minute = CASE WHEN timer_code = 0 THEN NULL ELSE ? END, " +
                "relay_expiry_hour = NULL, " +
                "delete_at_minute = CASE WHEN ? IS NULL THEN delete_at_minute " +
                "WHEN delete_at_minute IS NULL OR delete_at_minute > ? THEN ? ELSE delete_at_minute END " +
                "WHERE op_id = ? AND state = 'unread' " +
                "AND (delete_at_minute IS NULL OR delete_at_minute > ?) AND (relay_expiry_hour IS NULL OR relay_expiry_hour > ?)",
            listOf(
                displayedMinute, deleteAtMinute, deleteAtMinute, deleteAtMinute, opId, displayedMinute, displayedMinute,
            ),
        ) == 1
    }

    /** A deadline only moves earlier (§8.2): lowers [deleteAtMinute] to the minimum of itself and the stored one. */
    fun lowerDeleteAt(tx: SyncTransaction, opId: ByteArray, deleteAtMinute: Long): Boolean {
        Fields.minute("ch_post.delete_at_minute", deleteAtMinute)
        return tx.sql.execUpdate(
            "UPDATE ch_post SET delete_at_minute = ? WHERE op_id = ? AND (delete_at_minute IS NULL OR delete_at_minute > ?)",
            listOf(deleteAtMinute, opId, deleteAtMinute),
        ) == 1
    }

    /** The user's retry of a failed post: it is queued again, re-encrypted under the epoch, timer and minute then current. */
    fun retry(tx: SyncTransaction, opId: ByteArray, epoch: Long, timerCode: Int, authorMinute: Long, deleteAtMinute: Long?): Boolean {
        Fields.nonNegative("ch_post.epoch", epoch)
        Fields.rangeInt("ch_post.timer_code", timerCode, 0, 5)
        Fields.minute("ch_post.author_minute", authorMinute)
        Fields.minuteOrNull("ch_post.delete_at_minute", deleteAtMinute)
        return tx.sql.execUpdate(
            "UPDATE ch_post SET state = 'queued', epoch = ?, timer_code = ?, author_minute = ?, " +
                "delete_at_minute = CASE WHEN delete_at_minute IS NULL THEN ? ELSE min(delete_at_minute, COALESCE(?, delete_at_minute)) END " +
                "WHERE op_id = ? AND state = 'failed' AND direction = 'out'",
            listOf(epoch, timerCode.toLong(), authorMinute, deleteAtMinute, deleteAtMinute, opId),
        ) == 1
    }

    /**
     * SWEEP's read: a batch of expired posts, by the earlier of their two deadlines (at most the transaction bound
     * the caller gives): a post past its `delete_at_minute`, and an unread one past its relay expiry.
     */
    fun expiredPosts(sql: SqlExecutor, nowMinute: Long, batch: Int): List<ByteArray> {
        val out = ArrayList<ByteArray>()
        sql.query(EXPIRED_POSTS, listOf(nowMinute, nowMinute, batch.toLong())) { r -> out += r.blob(0) }
        return out
    }

    /** Deletes a post; its reactions go with it by cascade (ADR-32). */
    fun deletePost(tx: SyncTransaction, opId: ByteArray): Boolean =
        tx.sql.execUpdate("DELETE FROM ch_post WHERE op_id = ?", listOf(opId)) == 1

    private fun posts(sql: SqlExecutor, query: String, args: List<Any?>): List<PostRow> {
        val out = ArrayList<PostRow>()
        sql.query(query, args) { r -> out += readPost(r) }
        return out
    }

    private fun readPost(r: SqlExecutor.Row) = PostRow(
        opId = r.blob(0),
        channelId = r.blob(1),
        direction = Direction.of(r.string(2)),
        author = r.blob(3),
        kind = r.long(4).toInt(),
        replyTo = if (r.isNull(5)) null else r.blob(5),
        timerCode = r.long(6).toInt(),
        epoch = r.long(7),
        bodyEnv = r.blob(8),
        state = PostState.of(r.string(9)),
        authorMinute = r.long(10),
        displayedMinute = if (r.isNull(11)) null else r.long(11),
        deleteAtMinute = if (r.isNull(12)) null else r.long(12),
        relayExpiryHour = if (r.isNull(13)) null else r.long(13),
    )

    // ------------------------------------------------------------------------------- ch_reaction

    /**
     * The reactions of a post, if the post is live: the join makes the filter a property of the query, so a
     * reaction cannot outlive the post it hangs on in a view (ADR-32).
     */
    fun reactions(sql: SqlExecutor, target: ByteArray, nowMinute: Long): List<ReactionRow> {
        val out = ArrayList<ReactionRow>()
        sql.query(REACTIONS, listOf(target, nowMinute, nowMinute)) { r -> out += ReactionRow(r.blob(0), r.blob(1), r.blob(2)) }
        return out
    }

    /**
     * One reaction per (author, target): an UPDATE of the row that exists, else an INSERT. **False, with nothing
     * written, when no post of [channelId] holds [target]**: a reaction can reach a device before the post it
     * hangs on (blobs are fetched in blob-hash order and decrypted in `(epoch, sender_leaf, seq)` order, which
     * puts no member's reaction after another's post), and the foreign key would otherwise turn that ordinary
     * case into a constraint failure inside the batch of `CH-RECV`. What the engine does with such a reaction is
     * S4's (recorded in §19.35). A target that has expired and is not yet swept still takes the row; the view
     * joins on the live post (ADR-32).
     */
    fun putReaction(tx: SyncTransaction, target: ByteArray, author: ByteArray, channelId: ByteArray, graphemeEnv: ByteArray): Boolean {
        Fields.bytes("ch_reaction.target", target, 16)
        Fields.bytes("ch_reaction.author", author, 32)
        Fields.bytesBetween("ch_reaction.grapheme_env", graphemeEnv, 29, 60)
        val updated = tx.sql.execUpdate(
            "UPDATE ch_reaction SET grapheme_env = ? WHERE target = ? AND author = ?",
            listOf(graphemeEnv, target, author),
        )
        if (updated == 1) return true
        return tx.sql.execUpdate(
            "INSERT INTO ch_reaction(target, author, channel_id, grapheme_env) SELECT ?, ?, ?, ? " +
                "WHERE EXISTS (SELECT 1 FROM ch_post WHERE op_id = ? AND channel_id = ?)",
            listOf(target, author, channelId, graphemeEnv, target, channelId),
        ) == 1
    }

    /** An empty grapheme withdraws the reaction (§5.5). */
    fun deleteReaction(tx: SyncTransaction, target: ByteArray, author: ByteArray): Boolean =
        tx.sql.execUpdate("DELETE FROM ch_reaction WHERE target = ? AND author = ?", listOf(target, author)) == 1

    // ---------------------------------------------------------------------------- ch_pending_post

    /** The posts waiting to be encrypted that have not reached their deadline; at most 256 per channel (§6.3.5). */
    fun pending(sql: SqlExecutor, channelId: ByteArray, nowHour: Long): List<PendingRow> {
        val out = ArrayList<PendingRow>()
        sql.query(PENDING, listOf(channelId, nowHour)) { r -> out += readPending(r) }
        return out
    }

    fun insertPending(tx: SyncTransaction, opId: ByteArray, channelId: ByteArray, kind: Int, contentEnv: ByteArray, failAfterHour: Long) {
        Fields.bytes("ch_pending_post.op_id", opId, 16)
        Fields.rangeInt("ch_pending_post.kind", kind, 1, 7)
        Fields.bytesBetween("ch_pending_post.content_env", contentEnv, 29, MAX_BODY)
        Fields.hour("ch_pending_post.fail_after_hour", failAfterHour)
        var n = 0
        tx.sql.query(PENDING_COUNT, listOf(channelId)) { r -> n = r.long(0).toInt() }
        if (n >= MAX_PENDING) throw ChannelStoreException(ChannelStoreError.LIMIT, "ch_pending_post")
        val changed = tx.sql.execUpdate(
            "INSERT INTO ch_pending_post(op_id, channel_id, kind, content_env, fail_after_hour) SELECT ?, ?, ?, ?, ? " +
                "WHERE NOT EXISTS (SELECT 1 FROM ch_pending_post WHERE op_id = ?)",
            listOf(opId, channelId, kind.toLong(), contentEnv, failAfterHour, opId),
        )
        if (changed != 1) throw ChannelStoreException(ChannelStoreError.ROW_EXISTS, "ch_pending_post")
    }

    /** The encrypted post leaves the queue in the transaction that writes its row; a failed one leaves it at its deadline. */
    fun deletePending(tx: SyncTransaction, opId: ByteArray): Boolean =
        tx.sql.execUpdate("DELETE FROM ch_pending_post WHERE op_id = ?", listOf(opId)) == 1

    /** SWEEP's read: the pending posts whose deadline has been reached, which fail (`FAILED`, the user may retry). */
    fun expiredPending(sql: SqlExecutor, nowHour: Long, batch: Int): List<PendingRow> {
        val out = ArrayList<PendingRow>()
        sql.query(EXPIRED_PENDING, listOf(nowHour, batch.toLong())) { r -> out += readPending(r) }
        return out
    }

    private fun readPending(r: SqlExecutor.Row) = PendingRow(r.blob(0), r.blob(1), r.long(2).toInt(), r.blob(3), r.long(4))

    // ------------------------------------------------------------------------------------ ch_seen

    /** Whether an `op_id` (as its keyed tag) was already displayed and its tag is within retention (§6.3.4, layer 4). */
    fun isSeen(sql: SqlExecutor, channelId: ByteArray, tag: ByteArray, today: Long): Boolean {
        var seen = false
        sql.query(SEEN, listOf(channelId, tag, today)) { seen = true }
        return seen
    }

    /**
     * `INSERT OR IGNORE`, which deletes nothing (the table has no guard for that reason); true for a tag that is
     * new. [untilDay] is a **week**, `ceil7(day(author_minute) + ceil_days(FRESH(bucket)) + 1)` as `dm_seen`'s
     * (F9 §7.6 D3): a day that is not a multiple of 7 is [ChannelStoreError.BAD_VALUE], as the schema's CHECK
     * would refuse it, so that a seized device shows the week a post was displayed in and not the day.
     */
    fun markSeen(tx: SyncTransaction, channelId: ByteArray, tag: ByteArray, untilDay: Long): Boolean {
        Fields.bytes("ch_seen.tag", tag, 16)
        Fields.week("ch_seen.until_day", untilDay)
        return tx.sql.execUpdate(
            "INSERT OR IGNORE INTO ch_seen(channel_id, tag, until_day) VALUES (?, ?, ?)",
            listOf(channelId, tag, untilDay),
        ) == 1
    }

    /** SWEEP: tags past their retention. */
    fun deleteSeenTags(tx: SyncTransaction, today: Long): Int =
        tx.sql.execUpdate("DELETE FROM ch_seen WHERE until_day < ?", listOf(today))

    // ---------------------------------------------------------------------------------- ch_reveal

    /** The reveals of a channel whose post has not expired (§19.17: no time but the deletion deadline). */
    fun reveals(sql: SqlExecutor, channelId: ByteArray, nowMinute: Long): List<RevealRow> {
        val out = ArrayList<RevealRow>()
        sql.query(REVEALS, listOf(channelId, nowMinute)) { r ->
            out += RevealRow(r.blob(0), Direction.of(r.string(1)), r.blob(2), if (r.isNull(3)) null else r.long(3))
        }
        return out
    }

    /** One row per (direction, peer): the deadline of the REVEAL post's timer, `null` in a channel whose timer is off. */
    fun putReveal(tx: SyncTransaction, channelId: ByteArray, direction: Direction, peer: ByteArray, deleteAtMinute: Long?) {
        Fields.bytes("ch_reveal.peer", peer, 32)
        Fields.minuteOrNull("ch_reveal.delete_at_minute", deleteAtMinute)
        val updated = tx.sql.execUpdate(
            "UPDATE ch_reveal SET delete_at_minute = ? WHERE channel_id = ? AND direction = ? AND peer = ?",
            listOf(deleteAtMinute, channelId, direction.sql, peer),
        )
        if (updated == 0) {
            tx.sql.exec(
                "INSERT INTO ch_reveal(channel_id, direction, peer, delete_at_minute) VALUES (?, ?, ?, ?)",
                listOf(channelId, direction.sql, peer, deleteAtMinute),
            )
        }
    }

    /** SWEEP: the reveal rows whose post's timer has run out, with the post (§8.5). */
    fun deleteExpiredReveals(tx: SyncTransaction, nowMinute: Long): Int =
        tx.sql.execUpdate("DELETE FROM ch_reveal WHERE delete_at_minute <= ?", listOf(nowMinute))

    /** SWEEP's read of the same set, for the lint's mirror contract. */
    fun expiredReveals(sql: SqlExecutor, nowMinute: Long, batch: Int): List<RevealRow> {
        val out = ArrayList<RevealRow>()
        sql.query(EXPIRED_REVEALS, listOf(nowMinute, batch.toLong())) { r ->
            out += RevealRow(r.blob(0), Direction.of(r.string(1)), r.blob(2), if (r.isNull(3)) null else r.long(3))
        }
        return out
    }

    // ----------------------------------------------------------------------------- ch_outbound_op

    /**
     * The op of one enqueue, retained until its outcome (`CH-OUTCOME`): the ciphertext the resend repeats
     * ([OpRow.blob]), the op's deadline and the resend count. Slice S8 (§19.45).
     */
    fun insertOp(
        tx: SyncTransaction,
        operationId: ByteArray,
        channelId: ByteArray,
        purpose: OpPurpose,
        ref: ByteArray?,
        blob: ByteArray,
        deadlineHour: Long,
        resends: Int = 0,
    ) {
        Fields.bytes("ch_outbound_op.operation_id", operationId, 16)
        Fields.bytesBetweenOrNull("ch_outbound_op.ref", ref, 1, 64)
        Fields.bytesBetween("ch_outbound_op.blob", blob, 4096, 65_536)
        Fields.hour("ch_outbound_op.deadline_hour", deadlineHour)
        Fields.rangeInt("ch_outbound_op.resends", resends, 0, MAX_RESENDS)
        val changed = tx.sql.execUpdate(
            "INSERT INTO ch_outbound_op(operation_id, channel_id, purpose, ref, blob, deadline_hour, resends) " +
                "SELECT ?, ?, ?, ?, ?, ?, ? WHERE NOT EXISTS " +
                "(SELECT 1 FROM ch_outbound_op WHERE operation_id = ?)",
            listOf(operationId, channelId, purpose.sql, ref, blob, deadlineHour, resends.toLong(), operationId),
        )
        if (changed != 1) throw ChannelStoreException(ChannelStoreError.ROW_EXISTS, "ch_outbound_op")
    }

    fun op(sql: SqlExecutor, operationId: ByteArray): OpRow? {
        var row: OpRow? = null
        sql.query(OP, listOf(operationId)) { r -> row = readOp(r) }
        return row
    }

    /** The ops of a channel for an object: the commit whose hash is [ref], the post whose id is [ref]. */
    fun opsFor(sql: SqlExecutor, channelId: ByteArray, purpose: OpPurpose, ref: ByteArray): List<OpRow> {
        val out = ArrayList<OpRow>()
        sql.query(OPS_FOR, listOf(channelId, purpose.sql, ref)) { r -> out += readOp(r) }
        return out
    }

    fun opsOf(sql: SqlExecutor, channelId: ByteArray, purpose: OpPurpose): List<OpRow> {
        val out = ArrayList<OpRow>()
        sql.query(OPS_OF, listOf(channelId, purpose.sql)) { r -> out += readOp(r) }
        return out
    }

    fun deleteOp(tx: SyncTransaction, operationId: ByteArray): Boolean =
        tx.sql.execUpdate("DELETE FROM ch_outbound_op WHERE operation_id = ?", listOf(operationId)) == 1

    private fun readOp(r: SqlExecutor.Row) = OpRow(
        r.blob(0), r.blob(1), OpPurpose.of(r.string(2)), if (r.isNull(3)) null else r.blob(3),
        r.blob(4), r.long(5), r.long(6).toInt(),
    )

    companion object {
        const val MAX_BODY: Int = 65_564
        const val MAX_PENDING: Int = 256

        /** Phase 7's bound on the identical-bytes resends of an op (the DM's G-7, C-15). */
        const val MAX_RESENDS: Int = 2

        /**
         * `ORDER BY author_minute DESC, author DESC, op_id DESC`: the same three values on every device. A post is
         * live when **both** of its deadlines are ahead (a NULL is no deadline): `delete_at_minute`, and the relay
         * expiry `relay_expiry_hour` of an unread post (§8.2).
         */
        const val PAGE: String =
            "SELECT op_id, channel_id, direction, author, kind, reply_to, timer_code, epoch, body_env, state, " +
                "author_minute, displayed_minute, delete_at_minute, relay_expiry_hour FROM ch_post " +
                "WHERE channel_id = ? AND (delete_at_minute IS NULL OR delete_at_minute > ?) " +
                "AND (relay_expiry_hour IS NULL OR relay_expiry_hour > ?) " +
                "ORDER BY author_minute DESC, author DESC, op_id DESC LIMIT ?"

        const val PAGE_BEFORE: String =
            "SELECT op_id, channel_id, direction, author, kind, reply_to, timer_code, epoch, body_env, state, " +
                "author_minute, displayed_minute, delete_at_minute, relay_expiry_hour FROM ch_post " +
                "WHERE channel_id = ? AND (delete_at_minute IS NULL OR delete_at_minute > ?) " +
                "AND (relay_expiry_hour IS NULL OR relay_expiry_hour > ?) " +
                "AND (author_minute < ? OR (author_minute = ? AND author < ?) " +
                "OR (author_minute = ? AND author = ? AND op_id < ?)) " +
                "ORDER BY author_minute DESC, author DESC, op_id DESC LIMIT ?"

        const val POST_BY_ID: String =
            "SELECT op_id, channel_id, direction, author, kind, reply_to, timer_code, epoch, body_env, state, " +
                "author_minute, displayed_minute, delete_at_minute, relay_expiry_hour FROM ch_post " +
                "WHERE op_id = ? AND (delete_at_minute IS NULL OR delete_at_minute > ?) " +
                "AND (relay_expiry_hour IS NULL OR relay_expiry_hour > ?)"

        const val UNREAD_COUNT: String =
            "SELECT count(*) FROM ch_post WHERE channel_id = ? AND direction = 'in' AND state = 'unread' " +
                "AND (delete_at_minute IS NULL OR delete_at_minute > ?) AND (relay_expiry_hour IS NULL OR relay_expiry_hour > ?)"

        /**
         * The earliest deadline of a live post: the smaller of the earliest `delete_at_minute` and the earliest
         * `relay_expiry_hour` among the live posts (a post is live when both its deadlines are ahead). Two selects,
         * one per partial index (`idx_ch_post_delete`, `idx_ch_post_expiry`), so that a channel whose timer is off
         * and holds many posts without a deadline is not scanned by the alarm.
         */
        const val NEXT_DELETE_AT: String =
            "SELECT min(t) FROM (" +
                "SELECT min(delete_at_minute) AS t FROM ch_post WHERE delete_at_minute > ? " +
                "AND (relay_expiry_hour IS NULL OR relay_expiry_hour > ?) " +
                "UNION ALL " +
                "SELECT min(relay_expiry_hour) FROM ch_post WHERE relay_expiry_hour > ? " +
                "AND (delete_at_minute IS NULL OR delete_at_minute > ?))"

        /** SWEEP's own batch: registered in `ChannelSweepQueries`. A post is expired when either deadline has passed. */
        const val EXPIRED_POSTS: String =
            "SELECT op_id FROM ch_post WHERE delete_at_minute <= ? OR relay_expiry_hour <= ? " +
                "ORDER BY CASE WHEN relay_expiry_hour IS NOT NULL AND (delete_at_minute IS NULL OR relay_expiry_hour <= delete_at_minute) " +
                "THEN relay_expiry_hour ELSE delete_at_minute END, op_id LIMIT ?"

        const val REACTIONS: String =
            "SELECT r.target, r.author, r.grapheme_env FROM ch_reaction r JOIN ch_post p ON p.op_id = r.target " +
                "WHERE r.target = ? AND (p.delete_at_minute IS NULL OR p.delete_at_minute > ?) " +
                "AND (p.relay_expiry_hour IS NULL OR p.relay_expiry_hour > ?) ORDER BY r.author"

        const val PENDING: String =
            "SELECT op_id, channel_id, kind, content_env, fail_after_hour FROM ch_pending_post " +
                "WHERE channel_id = ? AND fail_after_hour > ? ORDER BY fail_after_hour, op_id"

        /** The bound query: counts every row, expired or not, as the `ch_pending_post_limit` trigger does. */
        const val PENDING_COUNT: String = "SELECT count(*) FROM ch_pending_post WHERE channel_id = ?"

        const val EXPIRED_PENDING: String =
            "SELECT op_id, channel_id, kind, content_env, fail_after_hour FROM ch_pending_post " +
                "WHERE fail_after_hour <= ? ORDER BY fail_after_hour, op_id LIMIT ?"

        const val SEEN: String = "SELECT 1 FROM ch_seen WHERE channel_id = ? AND tag = ? AND until_day >= ?"

        const val REVEALS: String =
            "SELECT channel_id, direction, peer, delete_at_minute FROM ch_reveal " +
                "WHERE channel_id = ? AND (delete_at_minute IS NULL OR delete_at_minute > ?) ORDER BY direction, peer"

        const val EXPIRED_REVEALS: String =
            "SELECT channel_id, direction, peer, delete_at_minute FROM ch_reveal WHERE delete_at_minute <= ? " +
                "ORDER BY delete_at_minute, channel_id, direction, peer LIMIT ?"

        const val OP: String =
            "SELECT operation_id, channel_id, purpose, ref, blob, deadline_hour, resends FROM ch_outbound_op WHERE operation_id = ?"
        const val OPS_FOR: String =
            "SELECT operation_id, channel_id, purpose, ref, blob, deadline_hour, resends FROM ch_outbound_op WHERE channel_id = ? AND purpose = ? AND ref = ? " +
                "ORDER BY operation_id"
        const val OPS_OF: String =
            "SELECT operation_id, channel_id, purpose, ref, blob, deadline_hour, resends FROM ch_outbound_op WHERE channel_id = ? AND purpose = ? ORDER BY operation_id"
    }
}
