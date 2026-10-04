package org.ghost.messaging.channel.store

import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.SyncTransaction

/**
 * The member-side rows of schema v7 (Phase 10 design §6.6, §6.7, §8.3, §9, §19.17): `ch_member_seen` and
 * `ch_member_refresh` (a committer's records of who is alive: the last epoch with an authenticated message
 * from a member's current leaf, and the day of its last leaf refresh), `ch_request` (a committer's pending
 * leave, remove, policy and class work, each until its day) and `ch_box_key` (the member's own box secret keys,
 * one per leaf it has had that is still within retention, at most 18).
 *
 * **`ch_request` is read with the expiry filter** `until_day >= :today`: a request past its day is dropped,
 * whether or not `CH-SWEEP` has deleted it, and the lint registers the query. The other three tables carry no
 * deadline of their own: a member record lives while the member is in the channel, a box key until the epoch
 * that replaced it leaves retention ([deleteRetiredBefore], which SWEEP calls with the oldest epoch it keeps).
 *
 * **Every write goes through the caller's [SyncTransaction]**; no `REPLACE`, no upsert (G-DM4).
 */
internal class MemberStore {

    class RequestRow(val channelId: ByteArray, val kind: RequestKind, val subject: ByteArray, val payloadEnv: ByteArray?, val untilDay: Long) {
        override fun toString(): String = "RequestRow(kind=${kind.sql})"
    }

    /** A `ch_box_key` row: `b_pk` as published in a leaf, `b_sk` wrapped (class 4, 60 bytes), and the epoch that replaced the leaf. */
    class BoxKeyRow(val channelId: ByteArray, val boxPk: ByteArray, val skEnv: ByteArray, val lastEpoch: Long?) {
        override fun toString(): String = "BoxKeyRow(current=${lastEpoch == null})"
    }

    // ------------------------------------------------------------------------------ ch_member_seen

    fun lastEpoch(sql: SqlExecutor, channelId: ByteArray, member: ByteArray): Long? {
        var epoch: Long? = null
        sql.query(MEMBER_SEEN, listOf(channelId, member)) { r -> epoch = r.long(0) }
        return epoch
    }

    /** The last epoch with an authenticated message from the member's current leaf: it only grows (UPDATE-then-INSERT). */
    fun noteMemberSeen(tx: SyncTransaction, channelId: ByteArray, member: ByteArray, epoch: Long) {
        Fields.bytes("ch_member_seen.member", member, 32)
        Fields.nonNegative("ch_member_seen.last_epoch", epoch)
        val updated = tx.sql.execUpdate(
            "UPDATE ch_member_seen SET last_epoch = ? WHERE channel_id = ? AND member = ? AND last_epoch < ?",
            listOf(epoch, channelId, member, epoch),
        )
        if (updated == 0) {
            tx.sql.execUpdate(
                "INSERT INTO ch_member_seen(channel_id, member, last_epoch) SELECT ?, ?, ? " +
                    "WHERE NOT EXISTS (SELECT 1 FROM ch_member_seen WHERE channel_id = ? AND member = ?)",
                listOf(channelId, member, epoch, channelId, member),
            )
        }
    }

    /** The leaf was replaced (a swap, a rejoin) or the member left: the record starts over. */
    fun deleteMemberSeen(tx: SyncTransaction, channelId: ByteArray, member: ByteArray): Boolean =
        tx.sql.execUpdate("DELETE FROM ch_member_seen WHERE channel_id = ? AND member = ?", listOf(channelId, member)) == 1

    // --------------------------------------------------------------------------- ch_member_refresh

    fun refreshDay(sql: SqlExecutor, channelId: ByteArray, member: ByteArray): Long? {
        var day: Long? = null
        sql.query(REFRESH, listOf(channelId, member)) { r -> day = r.long(0) }
        return day
    }

    /** The members whose last refresh is before [beforeDay]: the idle-eviction candidates of §6.6, oldest first. */
    fun idleBefore(sql: SqlExecutor, channelId: ByteArray, beforeDay: Long, limit: Int): List<ByteArray> {
        val out = ArrayList<ByteArray>()
        sql.query(IDLE, listOf(channelId, beforeDay, limit.toLong())) { r -> out += r.blob(0) }
        return out
    }

    /** The day of the member's last leaf refresh (join, rejoin, own self-update or own commit). */
    fun putRefresh(tx: SyncTransaction, channelId: ByteArray, member: ByteArray, day: Long) {
        Fields.bytes("ch_member_refresh.member", member, 32)
        Fields.nonNegative("ch_member_refresh.refresh_day", day)
        val updated = tx.sql.execUpdate(
            "UPDATE ch_member_refresh SET refresh_day = ? WHERE channel_id = ? AND member = ?",
            listOf(day, channelId, member),
        )
        if (updated == 0) {
            tx.sql.exec(
                "INSERT INTO ch_member_refresh(channel_id, member, refresh_day) VALUES (?, ?, ?)",
                listOf(channelId, member, day),
            )
        }
    }

    fun deleteRefresh(tx: SyncTransaction, channelId: ByteArray, member: ByteArray): Boolean =
        tx.sql.execUpdate("DELETE FROM ch_member_refresh WHERE channel_id = ? AND member = ?", listOf(channelId, member)) == 1

    // ----------------------------------------------------------------------------------- ch_request

    fun requests(sql: SqlExecutor, channelId: ByteArray, today: Long): List<RequestRow> {
        val out = ArrayList<RequestRow>()
        sql.query(REQUESTS, listOf(channelId, today)) { r -> out += readRequest(r) }
        return out
    }

    fun request(sql: SqlExecutor, channelId: ByteArray, kind: RequestKind, subject: ByteArray, today: Long): RequestRow? {
        var row: RequestRow? = null
        sql.query(REQUEST, listOf(channelId, kind.sql, subject, today)) { r -> row = readRequest(r) }
        return row
    }

    /**
     * Records a committer's pending work. The work is **recorded once**: its day is what CO-8's work-age rule
     * measures, so a second record of the same (kind, subject) keeps the first one and returns false. A `policy`
     * or `class` request names no pseudonym; its subject is the one byte `0x00`.
     */
    fun record(tx: SyncTransaction, channelId: ByteArray, kind: RequestKind, subject: ByteArray, payloadEnv: ByteArray?, untilDay: Long): Boolean {
        Fields.bytesBetween("ch_request.subject", subject, 1, 32)
        Fields.bytesBetweenOrNull("ch_request.payload_env", payloadEnv, 29, 4096)
        Fields.nonNegative("ch_request.until_day", untilDay)
        return tx.sql.execUpdate(
            "INSERT INTO ch_request(channel_id, kind, subject, payload_env, until_day) SELECT ?, ?, ?, ?, ? " +
                "WHERE NOT EXISTS (SELECT 1 FROM ch_request WHERE channel_id = ? AND kind = ? AND subject = ?)",
            listOf(channelId, kind.sql, subject, payloadEnv, untilDay, channelId, kind.sql, subject),
        ) == 1
    }

    fun deleteRequest(tx: SyncTransaction, channelId: ByteArray, kind: RequestKind, subject: ByteArray): Boolean =
        tx.sql.execUpdate(
            "DELETE FROM ch_request WHERE channel_id = ? AND kind = ? AND subject = ?",
            listOf(channelId, kind.sql, subject),
        ) == 1

    /** SWEEP's read: the requests past their day. */
    fun expiredRequests(sql: SqlExecutor, today: Long, batch: Int): List<RequestRow> {
        val out = ArrayList<RequestRow>()
        sql.query(EXPIRED_REQUESTS, listOf(today, batch.toLong())) { r -> out += readRequest(r) }
        return out
    }

    private fun readRequest(r: SqlExecutor.Row) =
        RequestRow(r.blob(0), RequestKind.of(r.string(1)), r.blob(2), if (r.isNull(3)) null else r.blob(3), r.long(4))

    // ----------------------------------------------------------------------------------- ch_box_key

    /** The box key of the member's current leaf (`last_epoch` NULL), if it has one. */
    fun currentBoxKey(sql: SqlExecutor, channelId: ByteArray): BoxKeyRow? {
        var row: BoxKeyRow? = null
        sql.query(CURRENT_BOX_KEY, listOf(channelId)) { r -> row = readBox(r) }
        return row
    }

    /** Every box key of the channel, current first: `revealOpen` tries the one of the post's epoch (§6.9). */
    fun boxKeys(sql: SqlExecutor, channelId: ByteArray): List<BoxKeyRow> {
        val out = ArrayList<BoxKeyRow>()
        sql.query(BOX_KEYS, listOf(channelId)) { r -> out += readBox(r) }
        return out
    }

    fun boxKey(sql: SqlExecutor, channelId: ByteArray, boxPk: ByteArray): BoxKeyRow? {
        var row: BoxKeyRow? = null
        sql.query(BOX_KEY, listOf(channelId, boxPk)) { r -> row = readBox(r) }
        return row
    }

    /** A new leaf's box key (`CH-CREATE`, `CH-ACCEPT`'s KeyPackage, `CH-SETTLE` of the own winning commit); at most 18 per channel. */
    fun insertBoxKey(tx: SyncTransaction, channelId: ByteArray, boxPk: ByteArray, skEnv: ByteArray) {
        Fields.bytes("ch_box_key.box_pk", boxPk, 32)
        Fields.bytes("ch_box_key.sk_env", skEnv, 60)
        var n = 0
        tx.sql.query("SELECT count(*) FROM ch_box_key WHERE channel_id = ?", listOf(channelId)) { r -> n = r.long(0).toInt() }
        if (n >= MAX_BOX_KEYS) throw ChannelStoreException(ChannelStoreError.LIMIT, "ch_box_key")
        val changed = tx.sql.execUpdate(
            "INSERT INTO ch_box_key(channel_id, box_pk, sk_env) SELECT ?, ?, ? " +
                "WHERE NOT EXISTS (SELECT 1 FROM ch_box_key WHERE channel_id = ? AND box_pk = ?)",
            listOf(channelId, boxPk, skEnv, channelId, boxPk),
        )
        if (changed != 1) throw ChannelStoreException(ChannelStoreError.ROW_EXISTS, "ch_box_key")
    }

    /** A new leaf replaced the key's: it is kept until [lastEpoch] leaves retention. False if it was already retired. */
    fun retireBoxKey(tx: SyncTransaction, channelId: ByteArray, boxPk: ByteArray, lastEpoch: Long): Boolean {
        Fields.nonNegative("ch_box_key.last_epoch", lastEpoch)
        return tx.sql.execUpdate(
            "UPDATE ch_box_key SET last_epoch = ? WHERE channel_id = ? AND box_pk = ? AND last_epoch IS NULL",
            listOf(lastEpoch, channelId, boxPk),
        ) == 1
    }

    /**
     * SWEEP (§8.3, §19.17): the keys whose last epoch is before [oldestRetainedEpoch] are deleted, which is when
     * no epoch of the retained ones can hold the leaf that carried them; the current leaf's key never is.
     */
    fun deleteRetiredBefore(tx: SyncTransaction, channelId: ByteArray, oldestRetainedEpoch: Long): Int {
        Fields.nonNegative("ch_box_key.last_epoch", oldestRetainedEpoch)
        return tx.sql.execUpdate(
            "DELETE FROM ch_box_key WHERE channel_id = ? AND last_epoch IS NOT NULL AND last_epoch < ?",
            listOf(channelId, oldestRetainedEpoch),
        )
    }

    private fun readBox(r: SqlExecutor.Row) = BoxKeyRow(r.blob(0), r.blob(1), r.blob(2), if (r.isNull(3)) null else r.long(3))

    companion object {
        /** The current leaf's, the pending commit's and one per retained epoch (§6.3.5, §19.17). */
        const val MAX_BOX_KEYS: Int = 18

        const val MEMBER_SEEN: String = "SELECT last_epoch FROM ch_member_seen WHERE channel_id = ? AND member = ?"
        const val REFRESH: String = "SELECT refresh_day FROM ch_member_refresh WHERE channel_id = ? AND member = ?"
        const val IDLE: String =
            "SELECT member FROM ch_member_refresh WHERE channel_id = ? AND refresh_day < ? ORDER BY refresh_day, member LIMIT ?"

        const val REQUESTS: String =
            "SELECT channel_id, kind, subject, payload_env, until_day FROM ch_request WHERE channel_id = ? AND until_day >= ? " +
                "ORDER BY until_day, kind, subject"

        const val REQUEST: String =
            "SELECT channel_id, kind, subject, payload_env, until_day FROM ch_request " +
                "WHERE channel_id = ? AND kind = ? AND subject = ? AND until_day >= ?"

        const val EXPIRED_REQUESTS: String =
            "SELECT channel_id, kind, subject, payload_env, until_day FROM ch_request WHERE until_day < ? " +
                "ORDER BY until_day, channel_id, kind, subject LIMIT ?"

        const val CURRENT_BOX_KEY: String =
            "SELECT channel_id, box_pk, sk_env, last_epoch FROM ch_box_key WHERE channel_id = ? AND last_epoch IS NULL"

        const val BOX_KEYS: String =
            "SELECT channel_id, box_pk, sk_env, last_epoch FROM ch_box_key WHERE channel_id = ? " +
                "ORDER BY last_epoch IS NOT NULL, last_epoch DESC, box_pk"

        const val BOX_KEY: String =
            "SELECT channel_id, box_pk, sk_env, last_epoch FROM ch_box_key WHERE channel_id = ? AND box_pk = ?"
    }
}
