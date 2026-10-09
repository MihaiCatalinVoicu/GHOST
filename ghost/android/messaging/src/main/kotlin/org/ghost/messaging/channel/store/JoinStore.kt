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
 * arrival order", §9 gives `ch_join_request` no arrival column, and the table is one of the two that keep their
 * hidden rowid (the other is `mls_kv`; every other channel table is WITHOUT ROWID, T33), so the rowid is the
 * arrival order: a new row is always numbered after the rows that are still there, whatever was deleted. It is the
 * one place where the design asks for an insertion order, and a declared exception to T33 (§19.35, F-7): the
 * gaps between the rowids that survive count the requests deleted in between, of every channel.
 *
 * **Every write goes through the caller's [SyncTransaction]**; no `REPLACE`, no upsert (G-DM4); the two
 * tag tables are written with `INSERT OR IGNORE`, which deletes nothing.
 */
internal class JoinStore {

    /**
     * A `ch_join` row: the KeyPackage this client published for a join, a rejoin or a restore, and — for a join or a
     * restore — what its invite carried that nothing else keeps (amended by slice S4, §19.37, §19.35 F-8): the invite's
     * namespace, its `JK_g` (an invite's class-6 envelope, which seals the request and opens the Welcome only), the
     * recognition key `R_join(g)` and the committers digest the Welcome must be anchored to (§6.2.5). Shows nothing (T3).
     */
    class JoinRow(
        val channelId: ByteArray,
        val kpRef: ByteArray,
        val type: JoinType,
        val inviteId: ByteArray?,
        val generation: Long,
        val expiryDay: Long,
        val ns: ByteArray? = null,
        val jkEnv: ByteArray? = null,
        val rJoin: ByteArray? = null,
        val committersDigest: ByteArray? = null,
        /**
         * A rejoin's absolute give-up day (first attempt day + 14, §6.7): `expiryDay` is the next
         * re-send (attempt day + 7), this the `reinvite_needed` deadline. Null for a join or a
         * restore (the schema ties it to `type = 'rejoin'`).
         */
        val rejoinDeadlineDay: Long? = null,
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
        /** The requester's pseudonym, recorded with the row (slice S7): a rejoin names no invite. */
        val member: ByteArray?,
        val untilDay: Long,
        /** The day the request was first recorded (§19.35 F-11 (a)): CO-8's work-age rule measures the work's age from it. */
        val recordedDay: Long,
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

    /**
     * The join or restore whose invite named [ns] (the namespace `CH-RECV` fetched a blob from), if it has not expired:
     * how a blob of a `joining` channel is routed, since such a channel has no `ch_generation` row yet (§19.35 F-8).
     */
    fun joinByNamespace(sql: SqlExecutor, ns: ByteArray, today: Long): JoinRow? {
        var row: JoinRow? = null
        sql.query(JOIN_BY_NS, listOf(ns, today)) { r -> row = readJoin(r) }
        return row
    }

    /**
     * Records the client's own join (`CH-ACCEPT`), rejoin or restore. A join or a restore carries its invite's state
     * ([ns], [jkEnv], [rJoin], [committersDigest], all four or none); a rejoin carries none of it and instead
     * [rejoinDeadlineDay], its give-up day (§6.7).
     */
    fun insertJoin(
        tx: SyncTransaction,
        channelId: ByteArray,
        kpRef: ByteArray,
        type: JoinType,
        inviteId: ByteArray?,
        generation: Long,
        expiryDay: Long,
        ns: ByteArray? = null,
        jkEnv: ByteArray? = null,
        rJoin: ByteArray? = null,
        committersDigest: ByteArray? = null,
        rejoinDeadlineDay: Long? = null,
    ) {
        Fields.bytes("ch_join.kp_ref", kpRef, 32)
        Fields.bytesOrNull("ch_join.invite_id", inviteId, 16)
        Fields.u32("ch_join.generation", generation)
        Fields.nonNegative("ch_join.expiry_day", expiryDay)
        Fields.bytesOrNull("ch_join.ns", ns, 32)
        Fields.bytesOrNull("ch_join.jk_env", jkEnv, 60)
        Fields.bytesOrNull("ch_join.r_join", rJoin, 32)
        Fields.bytesOrNull("ch_join.committers_digest", committersDigest, 32)
        Fields.nonNegativeOrNull("ch_join.rejoin_deadline_day", rejoinDeadlineDay)
        if (type.hasInvite != (inviteId != null)) throw ChannelStoreException(ChannelStoreError.BAD_VALUE, "ch_join.invite_id")
        if ((rejoinDeadlineDay != null) != (type == JoinType.REJOIN)) {
            throw ChannelStoreException(ChannelStoreError.BAD_VALUE, "ch_join.rejoin_deadline_day")
        }
        val state = listOf(ns, jkEnv, rJoin, committersDigest)
        if (state.any { (it != null) != type.hasInvite }) throw ChannelStoreException(ChannelStoreError.BAD_VALUE, "ch_join.ns")
        val changed = tx.sql.execUpdate(
            "INSERT INTO ch_join(channel_id, kp_ref, type, invite_id, generation, expiry_day, ns, jk_env, r_join, " +
                "committers_digest, rejoin_deadline_day) SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? " +
                "WHERE NOT EXISTS (SELECT 1 FROM ch_join WHERE (channel_id = ? AND kp_ref = ?) OR ns = ?)",
            listOf(
                channelId, kpRef, type.sql, inviteId, generation, expiryDay, ns, jkEnv, rJoin, committersDigest,
                rejoinDeadlineDay, channelId, kpRef, ns,
            ),
        )
        if (changed != 1) throw ChannelStoreException(ChannelStoreError.ROW_EXISTS, "ch_join")
    }

    /** The join state goes when the Welcome is processed or the join expires (`CH-JOIN`, `CH-SWEEP`). */
    fun deleteJoin(tx: SyncTransaction, channelId: ByteArray, kpRef: ByteArray): Boolean =
        tx.sql.execUpdate("DELETE FROM ch_join WHERE channel_id = ? AND kp_ref = ?", listOf(channelId, kpRef)) == 1

    fun deleteJoins(tx: SyncTransaction, channelId: ByteArray): Int =
        tx.sql.execUpdate("DELETE FROM ch_join WHERE channel_id = ?", listOf(channelId))

    /** `CH-REJOIN`'s fresh attempt replaces the pending one: the old row (and its give-up day) goes. */
    fun deleteJoinsOfType(tx: SyncTransaction, channelId: ByteArray, type: JoinType): Int =
        tx.sql.execUpdate("DELETE FROM ch_join WHERE channel_id = ? AND type = ?", listOf(channelId, type.sql))

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
        ns = if (r.isNull(6)) null else r.blob(6),
        jkEnv = if (r.isNull(7)) null else r.blob(7),
        rJoin = if (r.isNull(8)) null else r.blob(8),
        committersDigest = if (r.isNull(9)) null else r.blob(9),
        rejoinDeadlineDay = if (r.isNull(10)) null else r.long(10),
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

    /** The first pending request that names [inviteId], if any: a second request for one invite is ignored (§6.2.4). */
    fun requestOfInvite(sql: SqlExecutor, channelId: ByteArray, inviteId: ByteArray, today: Long): RequestRow? {
        var row: RequestRow? = null
        sql.query(REQUEST_OF_INVITE, listOf(channelId, inviteId, today)) { r -> row = readRequest(r) }
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
        recordedDay: Long,
        /** The requester's pseudonym (slice S7): set for every request; a rejoin names no invite. */
        member: ByteArray? = null,
    ) {
        Fields.bytes("ch_join_request.hash", hash, 32)
        Fields.u32("ch_join_request.generation", generation)
        Fields.bytesOrNull("ch_join_request.invite_id", inviteId, 16)
        Fields.bytesBetween("ch_join_request.body_env", bodyEnv, 29, 4096)
        Fields.bytesOrNull("ch_join_request.member", member, 32)
        Fields.nonNegative("ch_join_request.until_day", untilDay)
        Fields.nonNegative("ch_join_request.recorded_day", recordedDay)
        if (type.hasInvite != (inviteId != null)) throw ChannelStoreException(ChannelStoreError.BAD_VALUE, "ch_join_request.invite_id")
        var n = 0
        tx.sql.query(REQUEST_COUNT, listOf(channelId)) { r -> n = r.long(0).toInt() }
        if (n >= MAX_REQUESTS) throw ChannelStoreException(ChannelStoreError.LIMIT, "ch_join_request")
        val changed = tx.sql.execUpdate(
            "INSERT INTO ch_join_request(channel_id, hash, generation, type, invite_id, body_env, member, until_day, recorded_day) " +
                "SELECT ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM ch_join_request WHERE channel_id = ? AND hash = ?)",
            listOf(channelId, hash, generation, type.sql, inviteId, bodyEnv, member, untilDay, recordedDay, channelId, hash),
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
        member = if (r.isNull(6)) null else r.blob(6),
        untilDay = r.long(7),
        recordedDay = r.long(8),
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
            "SELECT channel_id, kp_ref, type, invite_id, generation, expiry_day, ns, jk_env, r_join, " +
                "committers_digest, rejoin_deadline_day FROM ch_join " +
                "WHERE channel_id = ? AND expiry_day >= ? ORDER BY expiry_day, kp_ref"

        const val JOIN: String =
            "SELECT channel_id, kp_ref, type, invite_id, generation, expiry_day, ns, jk_env, r_join, " +
                "committers_digest, rejoin_deadline_day FROM ch_join " +
                "WHERE channel_id = ? AND kp_ref = ? AND expiry_day >= ?"

        const val JOIN_BY_NS: String =
            "SELECT channel_id, kp_ref, type, invite_id, generation, expiry_day, ns, jk_env, r_join, " +
                "committers_digest, rejoin_deadline_day FROM ch_join WHERE ns = ? AND expiry_day >= ?"

        /** SWEEP's own batch. */
        const val EXPIRED_JOINS: String =
            "SELECT channel_id, kp_ref, type, invite_id, generation, expiry_day, ns, jk_env, r_join, " +
                "committers_digest, rejoin_deadline_day FROM ch_join " +
                "WHERE expiry_day < ? ORDER BY expiry_day, channel_id, kp_ref LIMIT ?"

        const val REQUEST_OF_INVITE: String =
            "SELECT channel_id, hash, generation, type, invite_id, body_env, member, until_day, recorded_day " +
                "FROM ch_join_request WHERE channel_id = ? AND invite_id = ? AND until_day >= ? ORDER BY rowid LIMIT 1"

        const val REQUESTS: String =
            "SELECT channel_id, hash, generation, type, invite_id, body_env, member, until_day, recorded_day " +
                "FROM ch_join_request WHERE channel_id = ? AND until_day >= ? ORDER BY rowid"

        const val REQUEST: String =
            "SELECT channel_id, hash, generation, type, invite_id, body_env, member, until_day, recorded_day " +
                "FROM ch_join_request WHERE channel_id = ? AND hash = ? AND until_day >= ?"

        const val EXPIRED_REQUESTS: String =
            "SELECT channel_id, hash, generation, type, invite_id, body_env, member, until_day, recorded_day " +
                "FROM ch_join_request WHERE until_day < ? ORDER BY until_day, channel_id, hash LIMIT ?"

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
