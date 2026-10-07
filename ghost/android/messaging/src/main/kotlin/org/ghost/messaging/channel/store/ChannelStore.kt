package org.ghost.messaging.channel.store

import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.SyncTransaction

/**
 * The channel-level rows of schema v7 (Phase 10 design §9, "Migration 7"): `ch_channel`, `ch_liveness` and
 * `ch_schedule`.
 *
 * **Every write goes through the caller's [SyncTransaction]**; a store opens no transaction of its own (the
 * transactions of §10.4 are each exactly one `SyncDatabase.transaction`, and a DAO that opened one would
 * break the atomicity `CH-SETTLE` and `CH-RECV` rely on). **No `REPLACE`, no upsert** (gate G-DM4, the
 * `*_no_replace` guards): a row that may or may not exist is a guarded `UPDATE` whose changed-row count
 * decides whether an `INSERT` follows.
 *
 * **Reads of these three tables carry no expiry filter**: none of them has a deletion time (T33). The one
 * time column that governs when something happens is `ch_schedule.next_pass_minute`, a wake and not an
 * expiry; [duePasses] is bounded by the time it is given like the DM actor's wakes are.
 */
internal class ChannelStore {

    /** A `ch_channel` row. Never shows the pseudonym or the name (T3). */
    class ChannelRow(
        val channelId: ByteArray,
        val state: ChannelState,
        val splitSuspected: Boolean,
        val partitionSuspected: Boolean,
        val staleSuspected: Boolean,
        /** Flag bit 2 of the context mirrored for the UI (§19.28.5); `pw_version` is read from the native state. */
        val pwRequired: Boolean,
        val generation: Long,
        val epoch: Long,
        val joinedEpoch: Long,
        val sizeClass: Int,
        val timerCode: Int,
        val myPseudonym: ByteArray,
        val nameEnv: ByteArray?,
        val lastCommitterCommitDay: Long?,
        /**
         * The digest of the committers of the member's current context, as the last native call that returned it gave it
         * (amended by slice S4, §19.37, F-S4-2): `inviteBuild` at the member's own invite, the invite's anchor at its
         * join. `null` while the member has not learnt it; a committer admits nothing then (§6.2.4 (B), fail closed).
         */
        val committersDigest: ByteArray? = null,
    ) {
        override fun toString(): String = "ChannelRow(state=${state.sql})"
    }

    /** What `CH-CREATE` and `CH-ACCEPT` write: the flags start clear and `suite` is 3. */
    class NewChannel(
        val channelId: ByteArray,
        val state: ChannelState,
        val generation: Long,
        val epoch: Long,
        val joinedEpoch: Long,
        val sizeClass: Int,
        val timerCode: Int,
        val myPseudonym: ByteArray,
        val nameEnv: ByteArray?,
        val pwRequired: Boolean = false,
    ) {
        override fun toString(): String = "NewChannel(state=${state.sql})"
    }

    /** A `ch_liveness` row (CO-11, CO-12): the window of unopenable foreign blobs and the progress seen. */
    class LivenessRow(
        val channelId: ByteArray,
        val unopenableCount: Int,
        val unopenableOperators: Int,
        val sessions: Int,
        val progressEnv: ByteArray,
        val unopenableFirstMinute: Long?,
    ) {
        override fun toString(): String = "LivenessRow(unopenable=$unopenableCount, sessions=$sessions)"
    }

    /** A `ch_schedule` row (CO-8, CO-9). */
    class ScheduleRow(
        val channelId: ByteArray,
        val nextSelfupdateDay: Long,
        val lastOwnCommitDay: Long?,
        val nextPassMinute: Long?,
    ) {
        override fun toString(): String = "ScheduleRow(redacted)"
    }

    // ------------------------------------------------------------------------------- ch_channel

    fun channel(sql: SqlExecutor, channelId: ByteArray): ChannelRow? {
        var row: ChannelRow? = null
        sql.query(CHANNEL_BY_ID, listOf(channelId)) { r -> row = readChannel(r) }
        return row
    }

    /** Every channel, by id: `Channels.channels()` (§10.3) lists them with no time. */
    fun channels(sql: SqlExecutor): List<ChannelRow> {
        val out = ArrayList<ChannelRow>()
        sql.query(ALL_CHANNELS) { r -> out += readChannel(r) }
        return out
    }

    /** The channels in [state]: the sweep's and the session start's view of who is joining, leaving or stuck. */
    fun channelsIn(sql: SqlExecutor, state: ChannelState): List<ChannelRow> {
        val out = ArrayList<ChannelRow>()
        sql.query(CHANNELS_IN_STATE, listOf(state.sql)) { r -> out += readChannel(r) }
        return out
    }

    /**
     * Inserts the row of a created (`active`) or accepted (`joining`) channel. A channel that exists is
     * [ChannelStoreError.ROW_EXISTS]: a new invitation for a channel the client left re-enters `joining`
     * through [transition], not through an insert (§6.2.2).
     */
    fun insert(tx: SyncTransaction, channel: NewChannel) {
        val c = channel
        require(c.state == ChannelState.ACTIVE || c.state == ChannelState.JOINING) { "a channel starts active or joining" }
        Fields.bytes("ch_channel.channel_id", c.channelId, 32)
        Fields.bytes("ch_channel.my_pseudonym", c.myPseudonym, 32)
        Fields.bytesBetweenOrNull("ch_channel.name_env", c.nameEnv, 29, 76)
        Fields.u32("ch_channel.generation", c.generation)
        Fields.nonNegative("ch_channel.epoch", c.epoch)
        Fields.nonNegative("ch_channel.joined_epoch", c.joinedEpoch)
        Fields.rangeInt("ch_channel.size_class", c.sizeClass, 0, 1)
        Fields.rangeInt("ch_channel.timer_code", c.timerCode, 0, 5)
        val changed = tx.sql.execUpdate(
            "INSERT INTO ch_channel(channel_id, state, pw_required, generation, epoch, joined_epoch, size_class, " +
                "timer_code, my_pseudonym, name_env) SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ? " +
                "WHERE NOT EXISTS (SELECT 1 FROM ch_channel WHERE channel_id = ?)",
            listOf(
                c.channelId, c.state.sql, Fields.flag(c.pwRequired), c.generation, c.epoch, c.joinedEpoch,
                c.sizeClass.toLong(), c.timerCode.toLong(), c.myPseudonym, c.nameEnv, c.channelId,
            ),
        )
        if (changed != 1) throw ChannelStoreException(ChannelStoreError.ROW_EXISTS, "ch_channel")
    }

    /**
     * Moves a channel from [from] to [to] if it is in [from]; false when it is in another state (the guard did
     * not match, like the DM stores' guarded updates). An edge the machine does not have is
     * [ChannelStoreError.ILLEGAL_TRANSITION], raised before the statement, where the trigger would abort it.
     */
    fun transition(tx: SyncTransaction, channelId: ByteArray, from: ChannelState, to: ChannelState): Boolean {
        if (!from.allows(to)) throw ChannelStoreException(ChannelStoreError.ILLEGAL_TRANSITION, "ch_channel.state")
        return tx.sql.execUpdate(
            "UPDATE ch_channel SET state = ? WHERE channel_id = ? AND state = ?",
            listOf(to.sql, channelId, from.sql),
        ) == 1
    }

    /** The three flags of CO-11 and CO-12, which the UI shows; all three are written together. */
    fun setFlags(tx: SyncTransaction, channelId: ByteArray, split: Boolean, partition: Boolean, stale: Boolean): Boolean =
        tx.sql.execUpdate(
            "UPDATE ch_channel SET split_suspected = ?, partition_suspected = ?, stale_suspected = ? WHERE channel_id = ?",
            listOf(Fields.flag(split), Fields.flag(partition), Fields.flag(stale), channelId),
        ) == 1

    /** The policy a settled commit changed: the timer, the size class, the password flag and the name. */
    fun setPolicy(
        tx: SyncTransaction,
        channelId: ByteArray,
        timerCode: Int,
        sizeClass: Int,
        pwRequired: Boolean,
        nameEnv: ByteArray?,
    ): Boolean {
        Fields.rangeInt("ch_channel.timer_code", timerCode, 0, 5)
        Fields.rangeInt("ch_channel.size_class", sizeClass, 0, 1)
        Fields.bytesBetweenOrNull("ch_channel.name_env", nameEnv, 29, 76)
        return tx.sql.execUpdate(
            "UPDATE ch_channel SET timer_code = ?, size_class = ?, pw_required = ?, name_env = ? WHERE channel_id = ?",
            listOf(timerCode.toLong(), sizeClass.toLong(), Fields.flag(pwRequired), nameEnv, channelId),
        ) == 1
    }

    /** The position a settle or a switch reaches: the generation number and the current epoch. */
    fun setPosition(tx: SyncTransaction, channelId: ByteArray, generation: Long, epoch: Long): Boolean {
        Fields.u32("ch_channel.generation", generation)
        Fields.nonNegative("ch_channel.epoch", epoch)
        return tx.sql.execUpdate(
            "UPDATE ch_channel SET generation = ?, epoch = ? WHERE channel_id = ?",
            listOf(generation, epoch, channelId),
        ) == 1
    }

    /** `CH-JOIN`: the epoch the member joined at, which is also its current epoch, and its generation. */
    fun setJoined(tx: SyncTransaction, channelId: ByteArray, joinedEpoch: Long, generation: Long): Boolean {
        Fields.nonNegative("ch_channel.joined_epoch", joinedEpoch)
        Fields.u32("ch_channel.generation", generation)
        return tx.sql.execUpdate(
            "UPDATE ch_channel SET joined_epoch = ?, epoch = ?, generation = ? WHERE channel_id = ?",
            listOf(joinedEpoch, joinedEpoch, generation, channelId),
        ) == 1
    }

    /** The day of the last committer commit merged (CO-12's partition and stale flags read it). */
    fun setLastCommitterCommitDay(tx: SyncTransaction, channelId: ByteArray, day: Long?): Boolean {
        Fields.nonNegativeOrNull("ch_channel.last_committer_commit_day", day)
        return tx.sql.execUpdate(
            "UPDATE ch_channel SET last_committer_commit_day = ? WHERE channel_id = ?",
            listOf(day, channelId),
        ) == 1
    }

    /**
     * The committers digest of the current context (slice S4, §19.37): written by `CH-INVITE` from `inviteBuild` and by
     * `CH-JOIN` from the anchor the Welcome passed; `null` forgets it (a settle that changes the committers, S5).
     */
    fun setCommittersDigest(tx: SyncTransaction, channelId: ByteArray, digest: ByteArray?): Boolean {
        Fields.bytesOrNull("ch_channel.committers_digest", digest, 32)
        return tx.sql.execUpdate(
            "UPDATE ch_channel SET committers_digest = ? WHERE channel_id = ?",
            listOf(digest, channelId),
        ) == 1
    }

    /** Deletes the channel and, by cascade, every row of every channel table that belongs to it (the wipe). */
    fun delete(tx: SyncTransaction, channelId: ByteArray): Boolean =
        tx.sql.execUpdate("DELETE FROM ch_channel WHERE channel_id = ?", listOf(channelId)) == 1

    private fun readChannel(r: SqlExecutor.Row) = ChannelRow(
        channelId = r.blob(0),
        state = ChannelState.of(r.string(1)),
        splitSuspected = r.long(2) == 1L,
        partitionSuspected = r.long(3) == 1L,
        staleSuspected = r.long(4) == 1L,
        pwRequired = r.long(5) == 1L,
        generation = r.long(6),
        epoch = r.long(7),
        joinedEpoch = r.long(8),
        sizeClass = r.long(9).toInt(),
        timerCode = r.long(10).toInt(),
        myPseudonym = r.blob(11),
        nameEnv = if (r.isNull(12)) null else r.blob(12),
        lastCommitterCommitDay = if (r.isNull(13)) null else r.long(13),
        committersDigest = if (r.isNull(14)) null else r.blob(14),
    )

    // ------------------------------------------------------------------------------- ch_liveness

    fun liveness(sql: SqlExecutor, channelId: ByteArray): LivenessRow? {
        var row: LivenessRow? = null
        sql.query(LIVENESS_BY_ID, listOf(channelId)) { r ->
            row = LivenessRow(
                channelId = r.blob(0),
                unopenableCount = r.long(1).toInt(),
                unopenableOperators = r.long(2).toInt(),
                sessions = r.long(3).toInt(),
                progressEnv = r.blob(4),
                unopenableFirstMinute = if (r.isNull(5)) null else r.long(5),
            )
        }
        return row
    }

    /**
     * Writes the whole window (CO-11): the counters, the operators' bitmask, the wrapped progress senders and
     * the minute the window opened — which is `null` exactly while nothing is counted (the schema ties them).
     * An UPDATE of the row that exists, else an INSERT.
     */
    fun putLiveness(
        tx: SyncTransaction,
        channelId: ByteArray,
        unopenableCount: Int,
        unopenableOperators: Int,
        sessions: Int,
        progressEnv: ByteArray,
        unopenableFirstMinute: Long?,
    ) {
        Fields.rangeInt("ch_liveness.unopenable_count", unopenableCount, 0, 255)
        Fields.rangeInt("ch_liveness.unopenable_operators", unopenableOperators, 0, 255)
        Fields.rangeInt("ch_liveness.sessions", sessions, 0, 255)
        Fields.bytesBetween("ch_liveness.progress_env", progressEnv, 28, 256)
        Fields.minuteOrNull("ch_liveness.unopenable_first_minute", unopenableFirstMinute)
        // The window's start exists exactly while something is counted (the schema's CHECK).
        if ((unopenableCount == 0) != (unopenableFirstMinute == null)) {
            throw ChannelStoreException(ChannelStoreError.BAD_VALUE, "ch_liveness.unopenable_first_minute")
        }
        val args = listOf(
            unopenableCount.toLong(), unopenableOperators.toLong(), sessions.toLong(), progressEnv,
            unopenableFirstMinute, channelId,
        )
        val updated = tx.sql.execUpdate(
            "UPDATE ch_liveness SET unopenable_count = ?, unopenable_operators = ?, sessions = ?, progress_env = ?, " +
                "unopenable_first_minute = ? WHERE channel_id = ?",
            args,
        )
        if (updated == 0) {
            tx.sql.exec(
                "INSERT INTO ch_liveness(unopenable_count, unopenable_operators, sessions, progress_env, " +
                    "unopenable_first_minute, channel_id) VALUES (?, ?, ?, ?, ?, ?)",
                args,
            )
        }
    }

    /** Progress was made (CO-11 (b)): the window closes and nothing stays of it but an empty progress record. */
    fun resetLiveness(tx: SyncTransaction, channelId: ByteArray, emptyProgressEnv: ByteArray) =
        putLiveness(tx, channelId, 0, 0, 0, emptyProgressEnv, null)

    fun deleteLiveness(tx: SyncTransaction, channelId: ByteArray): Boolean =
        tx.sql.execUpdate("DELETE FROM ch_liveness WHERE channel_id = ?", listOf(channelId)) == 1

    // ------------------------------------------------------------------------------- ch_schedule

    fun schedule(sql: SqlExecutor, channelId: ByteArray): ScheduleRow? {
        var row: ScheduleRow? = null
        sql.query(SCHEDULE_BY_ID, listOf(channelId)) { r ->
            row = ScheduleRow(
                channelId = r.blob(0),
                nextSelfupdateDay = r.long(1),
                lastOwnCommitDay = if (r.isNull(2)) null else r.long(2),
                nextPassMinute = if (r.isNull(3)) null else r.long(3),
            )
        }
        return row
    }

    /** UPDATE-then-INSERT of the schedule of §6.8 and CO-8, CO-9. */
    fun putSchedule(
        tx: SyncTransaction,
        channelId: ByteArray,
        nextSelfupdateDay: Long,
        lastOwnCommitDay: Long?,
        nextPassMinute: Long?,
    ) {
        Fields.nonNegative("ch_schedule.next_selfupdate_day", nextSelfupdateDay)
        Fields.nonNegativeOrNull("ch_schedule.last_own_commit_day", lastOwnCommitDay)
        Fields.minuteOrNull("ch_schedule.next_pass_minute", nextPassMinute)
        val updated = tx.sql.execUpdate(
            "UPDATE ch_schedule SET next_selfupdate_day = ?, last_own_commit_day = ?, next_pass_minute = ? WHERE channel_id = ?",
            listOf(nextSelfupdateDay, lastOwnCommitDay, nextPassMinute, channelId),
        )
        if (updated == 0) {
            tx.sql.exec(
                "INSERT INTO ch_schedule(next_selfupdate_day, last_own_commit_day, next_pass_minute, channel_id) VALUES (?, ?, ?, ?)",
                listOf(nextSelfupdateDay, lastOwnCommitDay, nextPassMinute, channelId),
            )
        }
    }

    /** The channels whose scheduled pass is due at [nowMinute]: a wake, not an expiry, bounded by the time it is given. */
    fun duePasses(sql: SqlExecutor, nowMinute: Long, limit: Int): List<ByteArray> {
        val out = ArrayList<ByteArray>()
        sql.query(DUE_PASSES, listOf(nowMinute, limit.toLong())) { r -> out += r.blob(0) }
        return out
    }

    companion object {
        private const val CHANNEL_COLUMNS =
            "channel_id, state, split_suspected, partition_suspected, stale_suspected, pw_required, generation, " +
                "epoch, joined_epoch, size_class, timer_code, my_pseudonym, name_env, last_committer_commit_day, committers_digest"

        const val CHANNEL_BY_ID: String = "SELECT $CHANNEL_COLUMNS FROM ch_channel WHERE channel_id = ?"
        const val ALL_CHANNELS: String = "SELECT $CHANNEL_COLUMNS FROM ch_channel ORDER BY channel_id"
        const val CHANNELS_IN_STATE: String = "SELECT $CHANNEL_COLUMNS FROM ch_channel WHERE state = ? ORDER BY channel_id"

        const val LIVENESS_BY_ID: String =
            "SELECT channel_id, unopenable_count, unopenable_operators, sessions, progress_env, " +
                "unopenable_first_minute FROM ch_liveness WHERE channel_id = ?"

        const val SCHEDULE_BY_ID: String =
            "SELECT channel_id, next_selfupdate_day, last_own_commit_day, next_pass_minute FROM ch_schedule WHERE channel_id = ?"

        const val DUE_PASSES: String =
            "SELECT channel_id FROM ch_schedule WHERE next_pass_minute IS NOT NULL AND next_pass_minute <= ? " +
                "ORDER BY next_pass_minute, channel_id LIMIT ?"
    }
}
