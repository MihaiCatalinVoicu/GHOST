package org.ghost.messaging.channel.store

import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.SyncTransaction

/**
 * The join-side rows of schema v7 (Phase 10 design §6.2, §6.7, §9): `ch_join` (the invitee's, rejoiner's or
 * restorer's own pending join: the KeyPackage it published, until `expiry_day`), `ch_join_request` (the
 * committer's pending requests, at most 64 per channel, each until its invite's expiry or 7 days after its
 * day) and `ch_kp_seen` (a committer's keyed tags of the KeyPackages it has admitted or refused, until
 * `GhostKpBind.day + 11`, at most 1 024 per channel).
 *
 * **Every read applies the expiry filter** of its table (`expiry_day >= :today`, `until_day >= :today`;
 * §8.5 "kept until"): a join or a request past its day is not offered even if `CH-SWEEP` has not deleted it
 * (the committer must not admit an expired request, the invitee must not accept a Welcome for an expired
 * join). Every query is spelled out and registered with `:storage`'s `ChannelExpiredRowLint`; the sweep's
 * reads name the opposite set.
 *
 * **The order of the requests is their arrival order, `ORDER BY rowid`**: §6.2.3 processes a pass's requests "in
 * arrival order", §9 gives `ch_join_request` no arrival column, and the table is an ordinary rowid table (§9 marks
 * only the two tag tables WITHOUT ROWID), so the hidden rowid is the arrival order: a new row is always numbered
 * after the rows that are still there, whatever was deleted. It is the one place where the design asks for an
 * insertion order; what the other rowid tables record by it is §19.35's F-7 (T33).
 *
 * **Every write goes through the caller's [SyncTransaction]**; no `REPLACE`, no upsert (G-DM4); the two
 * tag tables are written with `INSERT OR IGNORE`, which deletes nothing.
 */
internal class JoinStore {

    /** A `ch_join` row: the KeyPackage this client published for a join, a rejoin or a restore. Shows nothing (T3). */
    class JoinRow(
        val channelId: ByteArray,
        val kpRef: ByteArray,
        val type: JoinType,
        val inviteId: ByteArray?,
        val generation: Long,
        val expiryDay: Long,
    ) {
        override fun toString(): String = "JoinRow(type=${type.sql})"
    }

    /** A `ch_join_request` row: a request sealed in mode 0x12 that a committer has opened and not yet answered. */
    class RequestRow(
        val channelId: ByteArray,
        val hash: ByteArray,
        val generation: Long,
        val type: JoinType,
        val inviteId: ByteArray?,
        val bodyEnv: ByteArray,
        val untilDay: Long,
    ) {
        override fun toString(): String = "RequestRow(type=${type.sql})"
    }

    // ------------------------------------------------------------------------------------ ch_join

    fun joins(sql: SqlExecutor, channelId: ByteArray, today: Long): List<JoinRow> {
        val out = ArrayList<JoinRow>()
        sql.query(JOINS, listOf(channelId, today)) { r -> out += readJoin(r) }
        return out
    }

    /** The join whose KeyPackage a Welcome names (`kp_ref`), if it has not expired. */
    fun join(sql: SqlExecutor, channelId: ByteArray, kpRef: ByteArray, today: Long): JoinRow? {
        var row: JoinRow? = null
        sql.query(JOIN, listOf(channelId, kpRef, today)) { r -> row = readJoin(r) }
        return row
    }

    fun insertJoin(
        tx: SyncTransaction,
        channelId: ByteArray,
        kpRef: ByteArray,
        type: JoinType,
        inviteId: ByteArray?,
        generation: Long,
        expiryDay: Long,
    ) {
        Fields.bytes("ch_join.kp_ref", kpRef, 32)
        Fields.bytesOrNull("ch_join.invite_id", inviteId, 16)
        Fields.u32("ch_join.generation", generation)
        Fields.nonNegative("ch_join.expiry_day", expiryDay)
        if (type.hasInvite != (inviteId != null)) throw ChannelStoreException(ChannelStoreError.BAD_VALUE, "ch_join.invite_id")
        val changed = tx.sql.execUpdate(
            "INSERT INTO ch_join(channel_id, kp_ref, type, invite_id, generation, expiry_day) SELECT ?, ?, ?, ?, ?, ? " +
                "WHERE NOT EXISTS (SELECT 1 FROM ch_join WHERE channel_id = ? AND kp_ref = ?)",
            listOf(channelId, kpRef, type.sql, inviteId, generation, expiryDay, channelId, kpRef),
        )
        if (changed != 1) throw ChannelStoreException(ChannelStoreError.ROW_EXISTS, "ch_join")
    }

    /** The join state goes when the Welcome is processed or the join expires (`CH-JOIN`, `CH-SWEEP`). */
    fun deleteJoin(tx: SyncTransaction, channelId: ByteArray, kpRef: ByteArray): Boolean =
        tx.sql.execUpdate("DELETE FROM ch_join WHERE channel_id = ? AND kp_ref = ?", listOf(channelId, kpRef)) == 1

    fun deleteJoins(tx: SyncTransaction, channelId: ByteArray): Int =
        tx.sql.execUpdate("DELETE FROM ch_join WHERE channel_id = ?", listOf(channelId))

    /** SWEEP's read (§6.2.2: "at `expiry_day + 1` without a Welcome it deletes the join state"). */
    fun expiredJoins(sql: SqlExecutor, today: Long, batch: Int): List<JoinRow> {
        val out = ArrayList<JoinRow>()
        sql.query(EXPIRED_JOINS, listOf(today, batch.toLong())) { r -> out += readJoin(r) }
        return out
    }

    private fun readJoin(r: SqlExecutor.Row) = JoinRow(
        channelId = r.blob(0),
        kpRef = r.blob(1),
        type = JoinType.of(r.string(2)),
        inviteId = if (r.isNull(3)) null else r.blob(3),
        generation = r.long(4),
        expiryDay = r.long(5),
    )

    // ------------------------------------------------------------------------------ ch_join_request

    /** The pending requests of a channel in the order of the pass, not yet expired. */
    fun requests(sql: SqlExecutor, channelId: ByteArray, today: Long): List<RequestRow> {
        val out = ArrayList<RequestRow>()
        sql.query(REQUESTS, listOf(channelId, today)) { r -> out += readRequest(r) }
        return out
    }

    fun request(sql: SqlExecutor, channelId: ByteArray, hash: ByteArray, today: Long): RequestRow? {
        var row: RequestRow? = null
        sql.query(REQUEST, listOf(channelId, hash, today)) { r -> row = readRequest(r) }
        return row
    }

    /** Records a request (`CH-RECV`, mode 0x12). A repeat of the same blob is [ChannelStoreError.ROW_EXISTS]; a 65th is [ChannelStoreError.LIMIT]. */
    fun insertRequest(
        tx: SyncTransaction,
        channelId: ByteArray,
        hash: ByteArray,
        generation: Long,
        type: JoinType,
        inviteId: ByteArray?,
        bodyEnv: ByteArray,
        untilDay: Long,
    ) {
        Fields.bytes("ch_join_request.hash", hash, 32)
        Fields.u32("ch_join_request.generation", generation)
        Fields.bytesOrNull("ch_join_request.invite_id", inviteId, 16)
        Fields.bytesBetween("ch_join_request.body_env", bodyEnv, 29, 4096)
        Fields.nonNegative("ch_join_request.until_day", untilDay)
        if (type.hasInvite != (inviteId != null)) throw ChannelStoreException(ChannelStoreError.BAD_VALUE, "ch_join_request.invite_id")
        var n = 0
        tx.sql.query(REQUEST_COUNT, listOf(channelId)) { r -> n = r.long(0).toInt() }
        if (n >= MAX_REQUESTS) throw ChannelStoreException(ChannelStoreError.LIMIT, "ch_join_request")
        val changed = tx.sql.execUpdate(
            "INSERT INTO ch_join_request(channel_id, hash, generation, type, invite_id, body_env, until_day) " +
                "SELECT ?, ?, ?, ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM ch_join_request WHERE channel_id = ? AND hash = ?)",
            listOf(channelId, hash, generation, type.sql, inviteId, bodyEnv, untilDay, channelId, hash),
        )
        if (changed != 1) throw ChannelStoreException(ChannelStoreError.ROW_EXISTS, "ch_join_request")
    }

    fun deleteRequest(tx: SyncTransaction, channelId: ByteArray, hash: ByteArray): Boolean =
        tx.sql.execUpdate("DELETE FROM ch_join_request WHERE channel_id = ? AND hash = ?", listOf(channelId, hash)) == 1

    /** An invite is consumed (single use): every other request that names it is ignored from then on (§6.2.4). */
    fun deleteRequestsOfInvite(tx: SyncTransaction, channelId: ByteArray, inviteId: ByteArray): Int =
        tx.sql.execUpdate("DELETE FROM ch_join_request WHERE channel_id = ? AND invite_id = ?", listOf(channelId, inviteId))

    /** SWEEP's read: requests past their day. */
    fun expiredRequests(sql: SqlExecutor, today: Long, batch: Int): List<RequestRow> {
        val out = ArrayList<RequestRow>()
        sql.query(EXPIRED_REQUESTS, listOf(today, batch.toLong())) { r -> out += readRequest(r) }
        return out
    }

    private fun readRequest(r: SqlExecutor.Row) = RequestRow(
        channelId = r.blob(0),
        hash = r.blob(1),
        generation = r.long(2),
        type = JoinType.of(r.string(3)),
        inviteId = if (r.isNull(4)) null else r.blob(4),
        bodyEnv = r.blob(5),
        untilDay = r.long(6),
    )

    // ------------------------------------------------------------------------------------ ch_kp_seen

    /** Whether the keyed tag of a KeyPackage (`HMAC(local key, kp_ref ‖ init_key)[0..16]`) is within retention. */
    fun isKpSeen(sql: SqlExecutor, channelId: ByteArray, tag: ByteArray, today: Long): Boolean {
        var seen = false
        sql.query(KP_SEEN, listOf(channelId, tag, today)) { seen = true }
        return seen
    }

    /**
     * Records the tag with `INSERT OR IGNORE`, which deletes nothing; true when it is new. A new tag in a channel
     * that holds 1 024 is [ChannelStoreError.LIMIT]; the committer deletes the expired ones first (`CH-SWEEP`).
     */
    fun markKpSeen(tx: SyncTransaction, channelId: ByteArray, tag: ByteArray, untilDay: Long): Boolean {
        Fields.bytes("ch_kp_seen.tag", tag, 16)
        Fields.nonNegative("ch_kp_seen.until_day", untilDay)
        var n = 0
        tx.sql.query(KP_COUNT, listOf(channelId)) { r -> n = r.long(0).toInt() }
        if (n >= MAX_KP_TAGS) {
            var present = false
            tx.sql.query(KP_PRESENT, listOf(channelId, tag)) { present = true }
            if (!present) throw ChannelStoreException(ChannelStoreError.LIMIT, "ch_kp_seen")
        }
        return tx.sql.execUpdate(
            "INSERT OR IGNORE INTO ch_kp_seen(channel_id, tag, until_day) VALUES (?, ?, ?)",
            listOf(channelId, tag, untilDay),
        ) == 1
    }

    /** SWEEP: tags past their last admissible day. */
    fun deleteKpTags(tx: SyncTransaction, today: Long): Int =
        tx.sql.execUpdate("DELETE FROM ch_kp_seen WHERE until_day < ?", listOf(today))

    companion object {
        const val MAX_REQUESTS: Int = 64
        const val MAX_KP_TAGS: Int = 1024

        const val JOINS: String =
            "SELECT channel_id, kp_ref, type, invite_id, generation, expiry_day FROM ch_join " +
                "WHERE channel_id = ? AND expiry_day >= ? ORDER BY expiry_day, kp_ref"

        const val JOIN: String =
            "SELECT channel_id, kp_ref, type, invite_id, generation, expiry_day FROM ch_join " +
                "WHERE channel_id = ? AND kp_ref = ? AND expiry_day >= ?"

        /** SWEEP's own batch. */
        const val EXPIRED_JOINS: String =
            "SELECT channel_id, kp_ref, type, invite_id, generation, expiry_day FROM ch_join WHERE expiry_day < ? " +
                "ORDER BY expiry_day, channel_id, kp_ref LIMIT ?"

        const val REQUESTS: String =
            "SELECT channel_id, hash, generation, type, invite_id, body_env, until_day FROM ch_join_request " +
                "WHERE channel_id = ? AND until_day >= ? ORDER BY rowid"

        const val REQUEST: String =
            "SELECT channel_id, hash, generation, type, invite_id, body_env, until_day FROM ch_join_request " +
                "WHERE channel_id = ? AND hash = ? AND until_day >= ?"

        const val EXPIRED_REQUESTS: String =
            "SELECT channel_id, hash, generation, type, invite_id, body_env, until_day FROM ch_join_request " +
                "WHERE until_day < ? ORDER BY until_day, channel_id, hash LIMIT ?"

        const val KP_SEEN: String = "SELECT 1 FROM ch_kp_seen WHERE channel_id = ? AND tag = ? AND until_day >= ?"

        /**
         * The three bound queries: they **count every row, expired or not**, because the schema's triggers do
         * (`ch_join_request_limit`, `ch_kp_seen_limit`): a store that counted only the live rows would think
         * a table has room that the trigger will refuse. Registered in the lint's bound registry, which
         * requires the opposite of the read contract: the expired rows must be seen.
         */
        const val REQUEST_COUNT: String = "SELECT count(*) FROM ch_join_request WHERE channel_id = ?"
        const val KP_COUNT: String = "SELECT count(*) FROM ch_kp_seen WHERE channel_id = ?"
        const val KP_PRESENT: String = "SELECT 1 FROM ch_kp_seen WHERE channel_id = ? AND tag = ?"
    }
}
