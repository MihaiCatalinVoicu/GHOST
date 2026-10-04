package org.ghost.messaging.channel.store

import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.SyncTransaction

/**
 * The generations of a channel (Phase 10 design §6.5, §9 `ch_generation`): each is a namespace, a secret `G_g`
 * and a join key `JK_g` (wrapped under the channel state key), in one of three states — `pending_switch`
 * (derived at a settle, listened to from `switch_hour` or the next session start), `current` and `draining`
 * (listened to until `drain_until_day`) — with at most one `current` and one `draining` per channel (the
 * schema's triggers, which `CH-SWITCH` honours by ending an older drain first).
 *
 * **Every read of a generation applies the drain filter** `drain_until_day IS NULL OR drain_until_day >=
 * :today` (§6.5, "Members list `ns_g` until `drain_until_day`"): a drained generation is not listened to,
 * whether or not `CH-SWEEP` has deleted its row yet. The sweep's own read, [drained], names the opposite set.
 * Every read is registered with `:storage`'s `ChannelExpiredRowLint` (mutant ME-16 over `ch_*`).
 */
internal class GenerationStore {

    /** A `ch_generation` row. The secrets are envelopes; nothing here shows them (T3). */
    class GenerationRow(
        val channelId: ByteArray,
        val generation: Long,
        val namespaceId: ByteArray,
        val state: GenerationState,
        /** `G_g` wrapped under the state key (class 2, 60 bytes). */
        val gEnv: ByteArray,
        /** `JK_g` wrapped under the state key (class 3, 60 bytes). */
        val jkEnv: ByteArray,
        /** The recognition key `R_join(g)` Kotlin matches the join traffic's hints with (CS-S6). */
        val rJoin: ByteArray,
        /** Set on a pending row only; `null` there means "at the next session start" (§19.8, a joiner's). */
        val switchHour: Long?,
        /** Set on a draining row only. */
        val drainUntilDay: Long?,
    ) {
        override fun toString(): String = "GenerationRow(generation=$generation, state=${state.sql})"
    }

    /** The channel and generation a namespace belongs to: what `CH-RECV` needs to route a fetched blob. */
    class Route(val channelId: ByteArray, val generation: Long, val state: GenerationState) {
        override fun toString(): String = "Route(generation=$generation, state=${state.sql})"
    }

    /** One generation of a channel, if it is not drained. */
    fun generation(sql: SqlExecutor, channelId: ByteArray, generation: Long, today: Long): GenerationRow? {
        var row: GenerationRow? = null
        sql.query(GENERATION, listOf(channelId, generation, today)) { r -> row = read(r) }
        return row
    }

    /** Every generation of a channel that is still listened to or about to be: at most a draining, a current and a pending or two. */
    fun live(sql: SqlExecutor, channelId: ByteArray, today: Long): List<GenerationRow> {
        val out = ArrayList<GenerationRow>()
        sql.query(LIVE, listOf(channelId, today)) { r -> out += read(r) }
        return out
    }

    /** The current generation: no deadline, so no filter can differ between a swept and an unswept world. */
    fun current(sql: SqlExecutor, channelId: ByteArray, today: Long): GenerationRow? {
        var row: GenerationRow? = null
        sql.query(CURRENT, listOf(channelId, today)) { r -> row = read(r) }
        return row
    }

    /** The pending generations whose switch is due at [nowHour] (or has no hour: the next session start). */
    fun duePending(sql: SqlExecutor, channelId: ByteArray, nowHour: Long, today: Long): List<GenerationRow> {
        val out = ArrayList<GenerationRow>()
        sql.query(DUE_PENDING, listOf(channelId, nowHour, today)) { r -> out += read(r) }
        return out
    }

    /** The route of a namespace: which channel and generation a blob fetched from it belongs to, if it is still listened to. */
    fun route(sql: SqlExecutor, namespaceId: ByteArray, today: Long): Route? {
        var route: Route? = null
        sql.query(ROUTE, listOf(namespaceId, today)) { r ->
            route = Route(r.blob(0), r.long(1), GenerationState.of(r.string(2)))
        }
        return route
    }

    /**
     * Inserts a generation: `current` at creation (`CH-CREATE`) and at a join, `pending_switch` at a settle that
     * rotates or a Welcome that names a newer generation, `draining` for a removed member's old one. The
     * namespace is unique across channels, the key is `(channel, generation)`; a repeat of either is
     * [ChannelStoreError.ROW_EXISTS].
     */
    fun insert(
        tx: SyncTransaction,
        channelId: ByteArray,
        generation: Long,
        namespaceId: ByteArray,
        state: GenerationState,
        gEnv: ByteArray,
        jkEnv: ByteArray,
        rJoin: ByteArray,
        switchHour: Long? = null,
        drainUntilDay: Long? = null,
    ) {
        Fields.u32("ch_generation.generation", generation)
        Fields.bytes("ch_generation.namespace_id", namespaceId, 32)
        Fields.bytes("ch_generation.g_env", gEnv, 60)
        Fields.bytes("ch_generation.jk_env", jkEnv, 60)
        Fields.bytes("ch_generation.r_join", rJoin, 32)
        Fields.hourOrNull("ch_generation.switch_hour", switchHour)
        Fields.nonNegativeOrNull("ch_generation.drain_until_day", drainUntilDay)
        if (switchHour != null && state != GenerationState.PENDING_SWITCH) {
            throw ChannelStoreException(ChannelStoreError.BAD_VALUE, "ch_generation.switch_hour")
        }
        if ((state == GenerationState.DRAINING) != (drainUntilDay != null)) {
            throw ChannelStoreException(ChannelStoreError.BAD_VALUE, "ch_generation.drain_until_day")
        }
        val changed = tx.sql.execUpdate(
            "INSERT INTO ch_generation(channel_id, generation, namespace_id, state, g_env, jk_env, r_join, switch_hour, " +
                "drain_until_day) SELECT ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE NOT EXISTS " +
                "(SELECT 1 FROM ch_generation WHERE (channel_id = ? AND generation = ?) OR namespace_id = ?)",
            listOf(
                channelId, generation, namespaceId, state.sql, gEnv, jkEnv, rJoin, switchHour, drainUntilDay,
                channelId, generation, namespaceId,
            ),
        )
        if (changed != 1) throw ChannelStoreException(ChannelStoreError.ROW_EXISTS, "ch_generation")
    }

    /** `CH-SWITCH`: the pending generation becomes current and loses its switch hour (the schema ties it to `pending_switch`). */
    fun promote(tx: SyncTransaction, channelId: ByteArray, generation: Long): Boolean =
        tx.sql.execUpdate(
            "UPDATE ch_generation SET state = 'current', switch_hour = NULL WHERE channel_id = ? AND generation = ? " +
                "AND state = 'pending_switch'",
            listOf(channelId, generation),
        ) == 1

    /** `CH-SWITCH`: the current generation drains until [drainUntilDay] (the day of the commit's switch hour plus 14, §6.5). */
    fun demote(tx: SyncTransaction, channelId: ByteArray, generation: Long, drainUntilDay: Long): Boolean {
        Fields.nonNegative("ch_generation.drain_until_day", drainUntilDay)
        return tx.sql.execUpdate(
            "UPDATE ch_generation SET state = 'draining', drain_until_day = ? WHERE channel_id = ? AND generation = ? " +
                "AND state = 'current'",
            listOf(drainUntilDay, channelId, generation),
        ) == 1
    }

    /** Ends a generation: an older drain ended by a newer switch (§6.5), a drain that ran out, or a pending one that was skipped. */
    fun delete(tx: SyncTransaction, channelId: ByteArray, generation: Long): Boolean =
        tx.sql.execUpdate(
            "DELETE FROM ch_generation WHERE channel_id = ? AND generation = ?",
            listOf(channelId, generation),
        ) == 1

    /** SWEEP's read (§6.5 "Drain"): the draining generations whose drain ended before [today], oldest first. */
    fun drained(sql: SqlExecutor, today: Long, batch: Int): List<Route> {
        val out = ArrayList<Route>()
        sql.query(DRAINED, listOf(today, batch.toLong())) { r ->
            out += Route(r.blob(0), r.long(1), GenerationState.of(r.string(2)))
        }
        return out
    }

    private fun read(r: SqlExecutor.Row) = GenerationRow(
        channelId = r.blob(0),
        generation = r.long(1),
        namespaceId = r.blob(2),
        state = GenerationState.of(r.string(3)),
        gEnv = r.blob(4),
        jkEnv = r.blob(5),
        rJoin = r.blob(6),
        switchHour = if (r.isNull(7)) null else r.long(7),
        drainUntilDay = if (r.isNull(8)) null else r.long(8),
    )

    companion object {
        const val GENERATION: String =
            "SELECT channel_id, generation, namespace_id, state, g_env, jk_env, r_join, switch_hour, drain_until_day " +
                "FROM ch_generation WHERE channel_id = ? AND generation = ? " +
                "AND (drain_until_day IS NULL OR drain_until_day >= ?)"

        const val LIVE: String =
            "SELECT channel_id, generation, namespace_id, state, g_env, jk_env, r_join, switch_hour, drain_until_day " +
                "FROM ch_generation WHERE channel_id = ? AND (drain_until_day IS NULL OR drain_until_day >= ?) " +
                "ORDER BY generation"

        const val CURRENT: String =
            "SELECT channel_id, generation, namespace_id, state, g_env, jk_env, r_join, switch_hour, drain_until_day " +
                "FROM ch_generation WHERE channel_id = ? AND state = 'current' " +
                "AND (drain_until_day IS NULL OR drain_until_day >= ?)"

        const val DUE_PENDING: String =
            "SELECT channel_id, generation, namespace_id, state, g_env, jk_env, r_join, switch_hour, drain_until_day " +
                "FROM ch_generation WHERE channel_id = ? AND state = 'pending_switch' " +
                "AND (switch_hour IS NULL OR switch_hour <= ?) AND (drain_until_day IS NULL OR drain_until_day >= ?) " +
                "ORDER BY generation"

        const val ROUTE: String =
            "SELECT channel_id, generation, state FROM ch_generation WHERE namespace_id = ? " +
                "AND (drain_until_day IS NULL OR drain_until_day >= ?)"

        /** SWEEP's own batch: registered in `ChannelSweepQueries`, judged by the opposite contract. */
        const val DRAINED: String =
            "SELECT channel_id, generation, state FROM ch_generation WHERE drain_until_day < ? " +
                "ORDER BY drain_until_day, channel_id, generation LIMIT ?"
    }
}
