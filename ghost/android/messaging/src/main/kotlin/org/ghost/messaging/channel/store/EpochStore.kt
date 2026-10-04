package org.ghost.messaging.channel.store

import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.SyncTransaction

/**
 * The epochs of a channel (Phase 10 design §6.4, §8.3, §9): `ch_epoch` (the epoch keys `K_ep` and their recognition
 * keys `R_ep`, state `open -> final`, the anchor of the settle and the retention bound), `ch_epoch_log` (the
 * winner of each settled epoch, for the rejoin's fork check, §6.7) and `ch_fork_signal` (the late commits of a
 * settled epoch, CO-6).
 *
 * **Every read of `ch_epoch` applies the retention filter** `keep_until_day IS NULL OR keep_until_day >=
 * :today` (§8.3: "Past epoch secrets and epoch keys `K_ep(e)` are kept until `final_day(e) + R`"): an epoch past
 * its bound is not offered to the recognition step even if `CH-SWEEP` has not deleted its row, which is the
 * only thing between a seized device and a post of an epoch the user was promised was gone (T25). The sweep's
 * own reads, [expired], name the opposite set. Both are registered with `:storage`'s `ChannelExpiredRowLint`.
 * **The fork signals** have no deadline column; they "go with their epoch's key" (§6.3.5), so [forkSignals]
 * applies the retention of the epoch they name by a join on `ch_epoch` (the review of S3: the first version
 * read them with no term at all, and the lint's list of expiring tables did not name `ch_fork_signal`).
 *
 * **Every write goes through the caller's [SyncTransaction]**, with no `REPLACE` and no upsert (G-DM4).
 */
internal class EpochStore {

    /** A `ch_epoch` row. The keys are envelopes; `R_ep` is the one key Kotlin holds in the clear (CS-S6). Shows nothing (T3). */
    class EpochRow(
        val channelId: ByteArray,
        val epoch: Long,
        val state: EpochState,
        /** `K_ep(e)` and `e`, wrapped under the state key (class 1, 68 bytes). */
        val kEnv: ByteArray,
        /** `R_ep(e)`, the recognition key that matches the hints of the epoch's blobs. */
        val rEp: ByteArray,
        /** The hash of the commit that produced this epoch's successor, once final. */
        val winnerHash: ByteArray?,
        /** The `seq` of the next own post (`ChannelOrder`, §5.5). */
        val ownSeq: Long,
        /** The settle anchor (CO-4) while the epoch is open; `null` once final (§19.21). */
        val anchorMinute: Long?,
        val finalDay: Long?,
        val keepUntilDay: Long?,
    ) {
        override fun toString(): String = "EpochRow(epoch=$epoch, state=${state.sql})"
    }

    class LogRow(val channelId: ByteArray, val epoch: Long, val winnerHash: ByteArray, val finalDay: Long) {
        override fun toString(): String = "LogRow(epoch=$epoch)"
    }

    class ForkSignalRow(val channelId: ByteArray, val epoch: Long, val hash: ByteArray, val firstSeenDay: Long) {
        override fun toString(): String = "ForkSignalRow(epoch=$epoch)"
    }

    /** A `(channel, epoch)` pair: what SWEEP names for deletion. */
    class EpochKey(val channelId: ByteArray, val epoch: Long) {
        override fun toString(): String = "EpochKey(epoch=$epoch)"
    }

    // ---------------------------------------------------------------------------------- ch_epoch

    /** One epoch, if it is within its retention. */
    fun epoch(sql: SqlExecutor, channelId: ByteArray, epoch: Long, today: Long): EpochRow? {
        var row: EpochRow? = null
        sql.query(EPOCH, listOf(channelId, epoch, today)) { r -> row = read(r) }
        return row
    }

    /** The open (current) epoch of a channel, if it has one. */
    fun open(sql: SqlExecutor, channelId: ByteArray, today: Long): EpochRow? {
        var row: EpochRow? = null
        sql.query(OPEN, listOf(channelId, today)) { r -> row = read(r) }
        return row
    }

    /** Every epoch within its retention, newest first: the keys the recognition step tries (§6.3.2). */
    fun retained(sql: SqlExecutor, channelId: ByteArray, today: Long): List<EpochRow> {
        val out = ArrayList<EpochRow>()
        sql.query(RETAINED, listOf(channelId, today)) { r -> out += read(r) }
        return out
    }

    /** `n` of §8.3: how many past epochs are still within retention, which `sweepPast` keeps. */
    fun pastCount(sql: SqlExecutor, channelId: ByteArray, today: Long): Int {
        var n = 0
        sql.query(PAST_COUNT, listOf(channelId, today)) { r -> n = r.long(0).toInt() }
        return n
    }

    /** Inserts an epoch row: `open` at creation, at a join and at a settle (`CH-CREATE`, `CH-JOIN`, `CH-SETTLE`). */
    fun insert(
        tx: SyncTransaction,
        channelId: ByteArray,
        epoch: Long,
        kEnv: ByteArray,
        rEp: ByteArray,
        winnerHash: ByteArray? = null,
        anchorMinute: Long? = null,
    ) {
        Fields.nonNegative("ch_epoch.epoch", epoch)
        Fields.bytes("ch_epoch.k_env", kEnv, 68)
        Fields.bytes("ch_epoch.r_ep", rEp, 32)
        Fields.bytesOrNull("ch_epoch.winner_hash", winnerHash, 32)
        Fields.minuteOrNull("ch_epoch.anchor_minute", anchorMinute)
        // The bound is the schema's (the trigger refuses an 18th row); the store says so as a typed error first.
        // The engine deletes the epochs past retention before it inserts the next (§8.3, CH-SWEEP), so a full
        // table here is a defect of the caller.
        if (count(tx.sql, EPOCH_COUNT, channelId) >= MAX_EPOCHS) {
            throw ChannelStoreException(ChannelStoreError.LIMIT, "ch_epoch")
        }
        val changed = tx.sql.execUpdate(
            "INSERT INTO ch_epoch(channel_id, epoch, state, k_env, r_ep, winner_hash, anchor_minute) " +
                "SELECT ?, ?, 'open', ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM ch_epoch WHERE channel_id = ? AND epoch = ?)",
            listOf(channelId, epoch, kEnv, rEp, winnerHash, anchorMinute, channelId, epoch),
        )
        if (changed != 1) throw ChannelStoreException(ChannelStoreError.ROW_EXISTS, "ch_epoch")
    }

    /** The settle anchor of an open epoch (CO-4): the earliest of the candidates' sightings and store hours; `null` clears it. */
    fun setAnchor(tx: SyncTransaction, channelId: ByteArray, epoch: Long, anchorMinute: Long?): Boolean {
        Fields.minuteOrNull("ch_epoch.anchor_minute", anchorMinute)
        return tx.sql.execUpdate(
            "UPDATE ch_epoch SET anchor_minute = ? WHERE channel_id = ? AND epoch = ? AND state = 'open'",
            listOf(anchorMinute, channelId, epoch),
        ) == 1
    }

    /**
     * The epoch becomes final (`CH-SETTLE`, CO-5): sticky, its anchor cleared (§19.21), its winner and the day it
     * became past recorded, and the day its keys stop being kept (§8.3). False when the epoch is not open.
     *
     * **Its sequence number is reset to 0**: `own_seq` is the `seq` of the next own post of the *open* epoch and
     * nothing reads it afterwards, but left in place it would show, until `keep_until_day` (up to 16 epochs), how
     * many posts the member wrote in each past epoch — an activity counter T33 does not allow beyond the sweep of
     * the posts themselves (the review of S3: 25 own posts in a 5-minute channel left `own_seq = 25` for days).
     * The schema allows the reset at the one transition and nowhere else (`ch_epoch_identity`, and the CHECK
     * `state = 'open' OR own_seq = 0`).
     */
    fun finalize(
        tx: SyncTransaction,
        channelId: ByteArray,
        epoch: Long,
        winnerHash: ByteArray?,
        finalDay: Long,
        keepUntilDay: Long,
    ): Boolean {
        Fields.bytesOrNull("ch_epoch.winner_hash", winnerHash, 32)
        Fields.nonNegative("ch_epoch.final_day", finalDay)
        Fields.nonNegative("ch_epoch.keep_until_day", keepUntilDay)
        return tx.sql.execUpdate(
            "UPDATE ch_epoch SET state = 'final', anchor_minute = NULL, own_seq = 0, winner_hash = ?, final_day = ?, " +
                "keep_until_day = ? WHERE channel_id = ? AND epoch = ? AND state = 'open'",
            listOf(winnerHash, finalDay, keepUntilDay, channelId, epoch),
        ) == 1
    }

    /**
     * The `seq` for the next own post of an open epoch, and the increment, in the caller's transaction
     * (`MlsNative.encrypt`'s `seq`, §10.2 fn 10: "incremented in the same transaction"): returns the number
     * to put in `ChannelOrder`, and the row holds the one after it. A missing or final epoch is
     * [ChannelStoreError.MISSING_ROW]; an epoch whose `u32` is spent is [ChannelStoreError.LIMIT].
     */
    fun nextOwnSeq(tx: SyncTransaction, channelId: ByteArray, epoch: Long, today: Long): Long {
        var seq: Long? = null
        tx.sql.query(OWN_SEQ, listOf(channelId, epoch, today)) { r -> seq = r.long(0) }
        val current = seq ?: throw ChannelStoreException(ChannelStoreError.MISSING_ROW, "ch_epoch")
        if (current >= Fields.U32_MAX) throw ChannelStoreException(ChannelStoreError.LIMIT, "ch_epoch.own_seq")
        val changed = tx.sql.execUpdate(
            "UPDATE ch_epoch SET own_seq = ? WHERE channel_id = ? AND epoch = ? AND state = 'open' AND own_seq = ?",
            listOf(current + 1, channelId, epoch, current),
        )
        if (changed != 1) throw ChannelStoreException(ChannelStoreError.MISSING_ROW, "ch_epoch")
        return current
    }

    /** SWEEP's read (§8.3): the epochs past their retention bound, oldest first. */
    fun expired(sql: SqlExecutor, today: Long, batch: Int): List<EpochKey> {
        val out = ArrayList<EpochKey>()
        sql.query(EXPIRED, listOf(today, batch.toLong())) { r -> out += EpochKey(r.blob(0), r.long(1)) }
        return out
    }

    fun delete(tx: SyncTransaction, channelId: ByteArray, epoch: Long): Boolean =
        tx.sql.execUpdate("DELETE FROM ch_epoch WHERE channel_id = ? AND epoch = ?", listOf(channelId, epoch)) == 1

    private fun read(r: SqlExecutor.Row) = EpochRow(
        channelId = r.blob(0),
        epoch = r.long(1),
        state = EpochState.of(r.string(2)),
        kEnv = r.blob(3),
        rEp = r.blob(4),
        winnerHash = if (r.isNull(5)) null else r.blob(5),
        ownSeq = r.long(6),
        anchorMinute = if (r.isNull(7)) null else r.long(7),
        finalDay = if (r.isNull(8)) null else r.long(8),
        keepUntilDay = if (r.isNull(9)) null else r.long(9),
    )

    private fun count(sql: SqlExecutor, query: String, vararg args: Any?): Int {
        var n = 0
        sql.query(query, args.toList()) { r -> n = r.long(0).toInt() }
        return n
    }

    // ------------------------------------------------------------------------------- ch_epoch_log

    /** Appends the winner of a settled epoch (CO-5); the log is append-only and bounded at [MAX_LOG] rows per channel. */
    fun appendLog(tx: SyncTransaction, channelId: ByteArray, epoch: Long, winnerHash: ByteArray, finalDay: Long) {
        Fields.nonNegative("ch_epoch_log.epoch", epoch)
        Fields.bytes("ch_epoch_log.winner_hash", winnerHash, 32)
        Fields.nonNegative("ch_epoch_log.final_day", finalDay)
        val changed = tx.sql.execUpdate(
            "INSERT INTO ch_epoch_log(channel_id, epoch, winner_hash, final_day) SELECT ?, ?, ?, ? " +
                "WHERE NOT EXISTS (SELECT 1 FROM ch_epoch_log WHERE channel_id = ? AND epoch = ?)",
            listOf(channelId, epoch, winnerHash, finalDay, channelId, epoch),
        )
        if (changed != 1) throw ChannelStoreException(ChannelStoreError.ROW_EXISTS, "ch_epoch_log")
    }

    /** The winner recorded for [epoch], if the log still holds it (the rejoin's fork check, §6.7). */
    fun logged(sql: SqlExecutor, channelId: ByteArray, epoch: Long): LogRow? {
        var row: LogRow? = null
        sql.query(LOGGED, listOf(channelId, epoch)) { r -> row = LogRow(r.blob(0), r.long(1), r.blob(2), r.long(3)) }
        return row
    }

    fun logCount(sql: SqlExecutor, channelId: ByteArray): Int = count(sql, "SELECT count(*) FROM ch_epoch_log WHERE channel_id = ?", channelId)

    /** Drops the oldest rows beyond [keep], which makes room for the next (the trigger refuses the 1025th); returns how many went. */
    fun trimLog(tx: SyncTransaction, channelId: ByteArray, keep: Int): Int {
        Fields.rangeInt("ch_epoch_log.keep", keep, 0, MAX_LOG)
        return tx.sql.execUpdate(
            "DELETE FROM ch_epoch_log WHERE channel_id = ? AND epoch NOT IN " +
                "(SELECT epoch FROM ch_epoch_log WHERE channel_id = ? ORDER BY epoch DESC LIMIT ?)",
            listOf(channelId, channelId, keep.toLong()),
        )
    }

    // ----------------------------------------------------------------------------- ch_fork_signal

    /**
     * Records a late candidate for a settled epoch (CO-6): `(epoch, hash)` once, with the day it was first seen.
     * At [MAX_FORK_SIGNALS] rows the oldest goes first (§6.3.5: "the oldest dropped"). False for a repeat.
     */
    fun addForkSignal(tx: SyncTransaction, channelId: ByteArray, epoch: Long, hash: ByteArray, day: Long): Boolean {
        Fields.nonNegative("ch_fork_signal.epoch", epoch)
        Fields.bytes("ch_fork_signal.hash", hash, 32)
        Fields.nonNegative("ch_fork_signal.first_seen_day", day)
        if (count(tx.sql, FORK_SIGNAL_PRESENT, channelId, epoch, hash) == 1) {
            return false
        }
        if (count(tx.sql, FORK_SIGNAL_COUNT, channelId) >= MAX_FORK_SIGNALS) {
            tx.sql.exec(
                "DELETE FROM ch_fork_signal WHERE channel_id = ? AND (epoch, hash) = " +
                    "(SELECT epoch, hash FROM ch_fork_signal WHERE channel_id = ? ORDER BY first_seen_day, epoch, hash LIMIT 1)",
                listOf(channelId, channelId),
            )
        }
        tx.sql.exec(
            "INSERT INTO ch_fork_signal(channel_id, epoch, hash, first_seen_day) VALUES (?, ?, ?, ?)",
            listOf(channelId, epoch, hash, day),
        )
        return true
    }

    /**
     * The fork signals of the epochs still within their retention: a signal goes with its epoch's key (§6.3.5), so
     * one whose epoch is past `keep_until_day` (or whose row is gone) is not offered even if `CH-SWEEP` has not
     * deleted it yet.
     */
    fun forkSignals(sql: SqlExecutor, channelId: ByteArray, today: Long): List<ForkSignalRow> {
        val out = ArrayList<ForkSignalRow>()
        sql.query(FORK_SIGNALS, listOf(channelId, today)) { r -> out += ForkSignalRow(r.blob(0), r.long(1), r.blob(2), r.long(3)) }
        return out
    }

    /** The signals of an epoch go with its key (§6.3.5). */
    fun deleteForkSignals(tx: SyncTransaction, channelId: ByteArray, epoch: Long): Int =
        tx.sql.execUpdate("DELETE FROM ch_fork_signal WHERE channel_id = ? AND epoch = ?", listOf(channelId, epoch))

    companion object {
        /** The current epoch and 16 past ones (`max_past_epochs(16)`, S0-6). */
        const val MAX_EPOCHS: Int = 17
        const val MAX_LOG: Int = 1024
        const val MAX_FORK_SIGNALS: Int = 16

        const val EPOCH: String =
            "SELECT channel_id, epoch, state, k_env, r_ep, winner_hash, own_seq, anchor_minute, final_day, keep_until_day " +
                "FROM ch_epoch WHERE channel_id = ? AND epoch = ? AND (keep_until_day IS NULL OR keep_until_day >= ?)"

        const val OPEN: String =
            "SELECT channel_id, epoch, state, k_env, r_ep, winner_hash, own_seq, anchor_minute, final_day, keep_until_day " +
                "FROM ch_epoch WHERE channel_id = ? AND state = 'open' AND (keep_until_day IS NULL OR keep_until_day >= ?)"

        const val RETAINED: String =
            "SELECT channel_id, epoch, state, k_env, r_ep, winner_hash, own_seq, anchor_minute, final_day, keep_until_day " +
                "FROM ch_epoch WHERE channel_id = ? AND (keep_until_day IS NULL OR keep_until_day >= ?) ORDER BY epoch DESC"

        const val PAST_COUNT: String =
            "SELECT count(*) FROM ch_epoch WHERE channel_id = ? AND state = 'final' " +
                "AND (keep_until_day IS NULL OR keep_until_day >= ?)"

        /** The bound query: counts every row, expired or not, as the `ch_epoch_limit` trigger does (see `JoinStore.REQUEST_COUNT`). */
        const val EPOCH_COUNT: String = "SELECT count(*) FROM ch_epoch WHERE channel_id = ?"

        const val OWN_SEQ: String =
            "SELECT own_seq FROM ch_epoch WHERE channel_id = ? AND epoch = ? AND state = 'open' " +
                "AND (keep_until_day IS NULL OR keep_until_day >= ?)"

        /** SWEEP's own batch: registered in `ChannelSweepQueries`, judged by the opposite contract. */
        const val EXPIRED: String =
            "SELECT channel_id, epoch FROM ch_epoch WHERE keep_until_day < ? ORDER BY keep_until_day, channel_id, epoch LIMIT ?"

        const val LOGGED: String = "SELECT channel_id, epoch, winner_hash, final_day FROM ch_epoch_log WHERE channel_id = ? AND epoch = ?"

        const val FORK_SIGNALS: String =
            "SELECT s.channel_id, s.epoch, s.hash, s.first_seen_day FROM ch_fork_signal s WHERE s.channel_id = ? " +
                "AND EXISTS (SELECT 1 FROM ch_epoch e WHERE e.channel_id = s.channel_id AND e.epoch = s.epoch " +
                "AND (e.keep_until_day IS NULL OR e.keep_until_day >= ?)) ORDER BY s.epoch, s.hash"

        /**
         * The bound queries: they count every row, expired or not, as the `ch_fork_signal_limit` trigger does (see
         * `JoinStore.REQUEST_COUNT`).
         */
        const val FORK_SIGNAL_COUNT: String = "SELECT count(*) FROM ch_fork_signal WHERE channel_id = ?"
        const val FORK_SIGNAL_PRESENT: String =
            "SELECT count(*) FROM ch_fork_signal WHERE channel_id = ? AND epoch = ? AND hash = ?"
    }
}
