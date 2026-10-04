package org.ghost.messaging.channel.store

import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.SyncTransaction

/**
 * The commit candidates of an epoch (Phase 10 design §6.4 CO-1 to CO-6, §6.3.5 CS-C8, §9 `ch_candidate`): the
 * commits a member holds for its current epoch until it settles, plus its own pending commit with the
 * Welcomes it sealed and the box key of its new leaf (kept wrapped, enqueued or moved only if the commit wins).
 *
 * **The bounds are the schema's, and this store only makes them cheap to keep**: at most 8 foreign candidates
 * and one own commit per epoch, at most one per sender (the lowest hash of that sender is the one kept, CO-3).
 * Which candidate to keep when the table is full is the engine's decision (CO-3); this store deletes the one
 * it is told to and inserts the one it is told to, and refuses with [ChannelStoreError.LIMIT] the insert the
 * trigger would abort.
 *
 * `ch_candidate` has no deletion time (a candidate lives until its epoch settles), so its reads carry no
 * expiry filter and are not registered with the expired-row lint. **Every write goes through the caller's
 * [SyncTransaction]**; no `REPLACE`.
 */
internal class CandidateStore {

    /** A `ch_candidate` row. Never shows a hash, a sender or a body (T3). */
    class CandidateRow(
        val channelId: ByteArray,
        val epoch: Long,
        val hash: ByteArray,
        val sender: ByteArray,
        val rank: Int,
        val own: Boolean,
        /** For the own commit: a copy was verified at a relay (CO-4); always false for a foreign candidate. */
        val verified: Boolean,
        val bodyEnv: ByteArray,
        /** The own commit's sealed WELCOME blobs, wrapped; enqueued at the settle if the commit wins. */
        val welcomeEnv: ByteArray?,
        /** The own commit's new box key, wrapped (class 4); moved to `ch_box_key` if the commit wins. */
        val boxEnv: ByteArray?,
        val firstSeenMinute: Long,
        val storeHour: Long?,
    ) {
        override fun toString(): String = "CandidateRow(epoch=$epoch, rank=$rank, own=$own)"
    }

    /** The candidates of one epoch in the order CO-3 ranks them when no trial settle is needed: `(rank, hash)`. */
    fun candidates(sql: SqlExecutor, channelId: ByteArray, epoch: Long): List<CandidateRow> {
        val out = ArrayList<CandidateRow>()
        sql.query(OF_EPOCH, listOf(channelId, epoch)) { r -> out += read(r) }
        return out
    }

    fun candidate(sql: SqlExecutor, channelId: ByteArray, epoch: Long, hash: ByteArray): CandidateRow? {
        var row: CandidateRow? = null
        sql.query(BY_HASH, listOf(channelId, epoch, hash)) { r -> row = read(r) }
        return row
    }

    /** The candidate a sender has for the epoch, if any: one per sender (CO-3 keeps the lowest hash of a sender). */
    fun candidateOf(sql: SqlExecutor, channelId: ByteArray, epoch: Long, sender: ByteArray): CandidateRow? {
        var row: CandidateRow? = null
        sql.query(BY_SENDER, listOf(channelId, epoch, sender)) { r -> row = read(r) }
        return row
    }

    /** The own commit of the epoch, if one is pending. */
    fun own(sql: SqlExecutor, channelId: ByteArray, epoch: Long): CandidateRow? {
        var row: CandidateRow? = null
        sql.query(OWN, listOf(channelId, epoch)) { r -> row = read(r) }
        return row
    }

    /** Every own pending commit of a channel: CO-4 (c) clears the ones no copy can remain for. */
    fun ownCommits(sql: SqlExecutor, channelId: ByteArray): List<CandidateRow> {
        val out = ArrayList<CandidateRow>()
        sql.query(OWN_OF_CHANNEL, listOf(channelId)) { r -> out += read(r) }
        return out
    }

    /** How many candidates the epoch holds, own and foreign: the engine decides what to drop when this reaches 8 + 1. */
    fun count(sql: SqlExecutor, channelId: ByteArray, epoch: Long): Int {
        var n = 0
        sql.query("SELECT count(*) FROM ch_candidate WHERE channel_id = ? AND epoch = ?", listOf(channelId, epoch)) { r ->
            n = r.long(0).toInt()
        }
        return n
    }

    /**
     * Records a candidate. A foreign one has no Welcomes, no box key and no verified copy; an own one may.
     * Bounds and uniqueness are checked first and refused as typed errors: a second candidate of a sender or a
     * repeated hash is [ChannelStoreError.ROW_EXISTS], a ninth foreign one or a second own one is
     * [ChannelStoreError.LIMIT].
     */
    fun insert(
        tx: SyncTransaction,
        channelId: ByteArray,
        epoch: Long,
        hash: ByteArray,
        sender: ByteArray,
        rank: Int,
        own: Boolean,
        bodyEnv: ByteArray,
        firstSeenMinute: Long,
        storeHour: Long? = null,
        welcomeEnv: ByteArray? = null,
        boxEnv: ByteArray? = null,
        verified: Boolean = false,
    ) {
        Fields.nonNegative("ch_candidate.epoch", epoch)
        Fields.bytes("ch_candidate.hash", hash, 32)
        Fields.bytes("ch_candidate.sender", sender, 32)
        Fields.rangeInt("ch_candidate.rank", rank, 0, 255)
        Fields.bytesBetween("ch_candidate.body_env", bodyEnv, 29, MAX_BODY)
        Fields.minute("ch_candidate.first_seen_minute", firstSeenMinute)
        Fields.hourOrNull("ch_candidate.store_hour", storeHour)
        Fields.bytesBetweenOrNull("ch_candidate.welcome_env", welcomeEnv, 29, MAX_WELCOMES)
        Fields.bytesOrNull("ch_candidate.box_env", boxEnv, 60)
        if (!own && (welcomeEnv != null || boxEnv != null || verified)) {
            throw ChannelStoreException(ChannelStoreError.BAD_VALUE, "ch_candidate.own")
        }
        // The bounds are the schema's (the trigger refuses a ninth foreign candidate and a second own commit); the
        // store says so as a typed error first, so the caller learns which bound it met.
        var foreign = 0
        var ownRows = 0
        tx.sql.query(
            "SELECT own, count(*) FROM ch_candidate WHERE channel_id = ? AND epoch = ? GROUP BY own",
            listOf(channelId, epoch),
        ) { r -> if (r.long(0) == 1L) ownRows = r.long(1).toInt() else foreign = r.long(1).toInt() }
        if ((!own && foreign >= MAX_FOREIGN) || (own && ownRows >= 1)) throw ChannelStoreException(ChannelStoreError.LIMIT, "ch_candidate")
        val changed = tx.sql.execUpdate(
            "INSERT INTO ch_candidate(channel_id, epoch, hash, sender, rank, own, verified, body_env, welcome_env, box_env, " +
                "first_seen_minute, store_hour) SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE NOT EXISTS " +
                "(SELECT 1 FROM ch_candidate WHERE channel_id = ? AND epoch = ? AND (hash = ? OR sender = ?))",
            listOf(
                channelId, epoch, hash, sender, rank.toLong(), Fields.flag(own), Fields.flag(verified), bodyEnv,
                welcomeEnv, boxEnv, firstSeenMinute, storeHour, channelId, epoch, hash, sender,
            ),
        )
        if (changed != 1) throw ChannelStoreException(ChannelStoreError.ROW_EXISTS, "ch_candidate")
    }

    /** The own commit's copy was verified at a relay (CO-4): once true it stays true. */
    fun markVerified(tx: SyncTransaction, channelId: ByteArray, epoch: Long, hash: ByteArray): Boolean =
        tx.sql.execUpdate(
            "UPDATE ch_candidate SET verified = 1 WHERE channel_id = ? AND epoch = ? AND hash = ? AND own = 1",
            listOf(channelId, epoch, hash),
        ) == 1

    /** Another relay's copy was stored earlier: the anchor only moves earlier (the schema refuses a later hour). */
    fun lowerStoreHour(tx: SyncTransaction, channelId: ByteArray, epoch: Long, hash: ByteArray, storeHour: Long): Boolean {
        Fields.hour("ch_candidate.store_hour", storeHour)
        return tx.sql.execUpdate(
            "UPDATE ch_candidate SET store_hour = ? WHERE channel_id = ? AND epoch = ? AND hash = ? " +
                "AND (store_hour IS NULL OR store_hour > ?)",
            listOf(storeHour, channelId, epoch, hash, storeHour),
        ) == 1
    }

    /** The Welcomes and the box key of a lost or cleared own commit are erased (CO-4); the row goes on with its epoch. */
    fun eraseOwnSecrets(tx: SyncTransaction, channelId: ByteArray, epoch: Long, hash: ByteArray): Boolean =
        tx.sql.execUpdate(
            "UPDATE ch_candidate SET welcome_env = NULL, box_env = NULL WHERE channel_id = ? AND epoch = ? AND hash = ? AND own = 1",
            listOf(channelId, epoch, hash),
        ) == 1

    fun delete(tx: SyncTransaction, channelId: ByteArray, epoch: Long, hash: ByteArray): Boolean =
        tx.sql.execUpdate(
            "DELETE FROM ch_candidate WHERE channel_id = ? AND epoch = ? AND hash = ?",
            listOf(channelId, epoch, hash),
        ) == 1

    /** The settle deletes the other candidates of the epoch (CO-5); the own commit's secrets go with it. */
    fun deleteEpoch(tx: SyncTransaction, channelId: ByteArray, epoch: Long): Int =
        tx.sql.execUpdate("DELETE FROM ch_candidate WHERE channel_id = ? AND epoch = ?", listOf(channelId, epoch))

    private fun read(r: SqlExecutor.Row) = CandidateRow(
        channelId = r.blob(0),
        epoch = r.long(1),
        hash = r.blob(2),
        sender = r.blob(3),
        rank = r.long(4).toInt(),
        own = r.long(5) == 1L,
        verified = r.long(6) == 1L,
        bodyEnv = r.blob(7),
        welcomeEnv = if (r.isNull(8)) null else r.blob(8),
        boxEnv = if (r.isNull(9)) null else r.blob(9),
        firstSeenMinute = r.long(10),
        storeHour = if (r.isNull(11)) null else r.long(11),
    )

    companion object {
        const val MAX_FOREIGN: Int = 8
        const val MAX_BODY: Int = 16_777_216
        const val MAX_WELCOMES: Int = 67_108_864

        private const val COLUMNS =
            "channel_id, epoch, hash, sender, rank, own, verified, body_env, welcome_env, box_env, first_seen_minute, store_hour"

        const val OF_EPOCH: String = "SELECT $COLUMNS FROM ch_candidate WHERE channel_id = ? AND epoch = ? ORDER BY rank, hash"
        const val BY_HASH: String = "SELECT $COLUMNS FROM ch_candidate WHERE channel_id = ? AND epoch = ? AND hash = ?"
        const val BY_SENDER: String = "SELECT $COLUMNS FROM ch_candidate WHERE channel_id = ? AND epoch = ? AND sender = ?"
        const val OWN: String = "SELECT $COLUMNS FROM ch_candidate WHERE channel_id = ? AND epoch = ? AND own = 1"
        const val OWN_OF_CHANNEL: String = "SELECT $COLUMNS FROM ch_candidate WHERE channel_id = ? AND own = 1 ORDER BY epoch"
    }
}
