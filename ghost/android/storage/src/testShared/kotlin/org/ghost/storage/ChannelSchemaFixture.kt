package org.ghost.storage

/**
 * The names and the row builders of the channel schema (Phase 10 design §9, "Migration 7"; slice S3),
 * shared by the test source sets of every module that opens a migrated database (`src/testShared`).
 *
 * **The lists are a second source of truth on purpose.** [Schema.expectedTables] and
 * [Schema.expectedTriggers] are what the production code asserts; the sets below are written out again
 * from the design, so a table, a trigger or a time column that migration 7 gains or loses without the
 * design saying so fails a test instead of passing because both sides moved together.
 */
internal object ChannelSchema {

    /** The four v1 channel tables migration 7 drops behind its guard (§9 step 0). */
    val v1Tables: Set<String> = setOf("channels", "channel_pseudonyms", "mls_state", "posts")

    /** The 26 tables of §9. */
    val tables: Set<String> = setOf(
        "ch_channel", "ch_liveness", "ch_schedule", "ch_generation", "ch_epoch", "ch_epoch_log", "ch_candidate",
        "ch_fork_signal", "mls_kv", "mls_global_kv", "ch_post", "ch_reaction", "ch_pending_post", "ch_outbound_op",
        "ch_seen", "ch_reveal", "ch_join", "ch_join_request", "ch_invite_issued", "ch_kp_seen", "ch_member_seen",
        "ch_invite_own", "ch_sponsor", "ch_member_refresh", "ch_request", "ch_box_key",
    )

    /** The two tables written with `INSERT OR IGNORE`, whose rows carry no rule: no REPLACE guard. */
    val unguarded: Set<String> = setOf("ch_seen", "ch_kp_seen")

    /** The 29 state-machine, write-once and bound triggers. */
    val rules: Set<String> = setOf(
        "ch_channel_identity", "ch_channel_state",
        "ch_generation_identity", "ch_generation_state", "ch_generation_one_current_insert",
        "ch_generation_one_current_update", "ch_generation_one_draining_insert", "ch_generation_one_draining_update",
        "ch_epoch_limit", "ch_epoch_anchor_insert", "ch_epoch_anchor_update", "ch_epoch_identity", "ch_epoch_final",
        "ch_epoch_log_limit", "ch_epoch_log_append_only",
        "ch_candidate_limit", "ch_candidate_identity", "ch_fork_signal_limit", "ch_fork_signal_append_only",
        "ch_post_identity", "ch_post_state", "ch_post_expiry", "ch_pending_post_limit",
        "ch_join_request_limit", "ch_invite_issued_identity", "ch_invite_issued_flags", "ch_kp_seen_limit",
        "ch_box_key_limit", "ch_box_key_replaced",
    )

    /** The 24 REPLACE guards: every table but [unguarded]. */
    val guards: Set<String> = setOf(
        "ch_channel_no_replace", "ch_liveness_no_replace", "ch_schedule_no_replace", "ch_generation_no_replace",
        "ch_epoch_no_replace", "ch_epoch_log_no_replace", "ch_candidate_no_replace", "ch_fork_signal_no_replace",
        "mls_kv_no_replace", "mls_global_kv_no_replace", "ch_post_no_replace", "ch_reaction_no_replace",
        "ch_pending_post_no_replace", "ch_outbound_op_no_replace", "ch_reveal_no_replace", "ch_join_no_replace",
        "ch_join_request_no_replace", "ch_invite_issued_no_replace", "ch_member_seen_no_replace",
        "ch_invite_own_no_replace", "ch_sponsor_no_replace", "ch_member_refresh_no_replace", "ch_request_no_replace",
        "ch_box_key_no_replace",
    )

    /**
     * The tables that are `WITHOUT ROWID`: the two tag tables, and only the two, because §9 marks only them
     * (it says outright that `mls_kv` is not one, and says nothing of the others).
     */
    val withoutRowidTables: Set<String> = setOf("ch_seen", "ch_kp_seen")

    /**
     * The tables that keep a hidden rowid, which records the order their rows arrived in (T33; §19.35): the
     * other 24. A REPLACE guard of such a table also refuses an insert that names an existing rowid.
     */
    val rowidTables: Set<String> = tables - withoutRowidTables

    /**
     * Every time column of §9, as `table.column`: 30 of them. The introspection tests require the
     * database to hold exactly these (a column that matches the time-like rule and is not here fails,
     * and so does one here that no table has), each with the granularity its suffix names.
     */
    val timeColumns: Set<String> = setOf(
        "ch_channel.last_committer_commit_day",
        "ch_liveness.unopenable_first_minute",
        "ch_schedule.next_selfupdate_day", "ch_schedule.last_own_commit_day", "ch_schedule.next_pass_minute",
        "ch_generation.switch_hour", "ch_generation.drain_until_day",
        "ch_epoch.anchor_minute", "ch_epoch.final_day", "ch_epoch.keep_until_day",
        "ch_epoch_log.final_day",
        "ch_candidate.first_seen_minute", "ch_candidate.store_hour",
        "ch_fork_signal.first_seen_day",
        "mls_global_kv.delete_after_day",
        "ch_post.author_minute", "ch_post.displayed_minute", "ch_post.delete_at_minute", "ch_post.relay_expiry_hour",
        "ch_pending_post.fail_after_hour",
        "ch_seen.until_day",
        "ch_reveal.delete_at_minute",
        "ch_join.expiry_day", "ch_join_request.until_day",
        "ch_invite_issued.expiry_day", "ch_kp_seen.until_day", "ch_invite_own.expiry_day",
        "ch_sponsor.admitted_day", "ch_member_refresh.refresh_day",
        "ch_request.until_day",
    )

    /**
     * The epoch counters, which match the time-like rule by name and are no time: MLS epoch numbers, `u64`,
     * each with a `typeof` CHECK.
     */
    val epochColumns: Set<String> = setOf(
        "ch_channel.epoch", "ch_channel.joined_epoch", "ch_epoch.epoch", "ch_epoch_log.epoch",
        "ch_candidate.epoch", "ch_fork_signal.epoch", "ch_post.epoch",
        "ch_member_seen.last_epoch", "ch_box_key.last_epoch",
    )

    /** Names that contain a word of the time-like rule while the value is no time. */
    val notTimes: Map<String, String> = mapOf(
        "ch_channel.timer_code" to "the channel's disappearing-timer bucket code, 0..5",
        "ch_post.timer_code" to "the bucket code the post was written under, 0..5",
    )

    /**
     * Integer columns that are neither a time nor an epoch and carry `typeof` beside a range: the
     * generation counters (`u32`), the commit rank, the own sequence number, the liveness counters, the
     * password version, the content kind of a pending post and the two timer codes.
     */
    val counterColumns: Set<String> = setOf(
        "ch_channel.generation", "ch_generation.generation", "ch_join.generation", "ch_join_request.generation",
        "ch_candidate.rank", "ch_epoch.own_seq",
        "ch_liveness.unopenable_count", "ch_liveness.unopenable_operators", "ch_liveness.sessions",
        "ch_invite_issued.pw_version", "ch_pending_post.kind",
        "ch_channel.timer_code", "ch_post.timer_code",
    )

    /** The 0/1 flags: `CHECK (x IN (0, 1))`, which admits no fraction either. */
    val flagColumns: Set<String> = setOf(
        "ch_channel.split_suspected", "ch_channel.partition_suspected", "ch_channel.stale_suspected",
        "ch_channel.pw_required", "ch_channel.size_class",
        "ch_candidate.own", "ch_candidate.verified", "ch_invite_issued.consumed", "ch_invite_issued.void",
    )

    /** The integer columns that are a closed list of values: `suite = 3` and the post's content kind (1, 2). */
    val enumColumns: Set<String> = setOf("ch_channel.suite", "ch_post.kind")

    /**
     * What each table's columns are, in order, as `name` (NOT NULL) or `name?` (nullable): §9's table, and
     * nothing else. A column added to a channel table — a `created_at`, a counter — fails the introspection
     * test until it is written here beside the rule that allows it.
     */
    val columns: Map<String, String> = mapOf(
        "ch_channel" to "channel_id state split_suspected partition_suspected stale_suspected pw_required suite " +
            "generation epoch joined_epoch size_class timer_code my_pseudonym name_env? last_committer_commit_day?",
        "ch_liveness" to "channel_id unopenable_count unopenable_operators sessions progress_env unopenable_first_minute?",
        "ch_schedule" to "channel_id next_selfupdate_day last_own_commit_day? next_pass_minute?",
        "ch_generation" to "channel_id generation namespace_id state g_env jk_env r_join switch_hour? drain_until_day?",
        "ch_epoch" to "channel_id epoch state k_env r_ep winner_hash? own_seq anchor_minute? final_day? keep_until_day?",
        "ch_epoch_log" to "channel_id epoch winner_hash final_day",
        "ch_candidate" to "channel_id epoch hash sender rank own verified body_env welcome_env? box_env? " +
            "first_seen_minute store_hour?",
        "ch_fork_signal" to "channel_id epoch hash first_seen_day",
        "mls_kv" to "channel_id k v_env",
        "mls_global_kv" to "k v_env channel_id delete_after_day?",
        "ch_post" to "op_id channel_id direction author kind reply_to? timer_code epoch body_env state author_minute " +
            "displayed_minute? delete_at_minute? relay_expiry_hour?",
        "ch_reaction" to "target author channel_id grapheme_env",
        "ch_pending_post" to "op_id channel_id kind content_env fail_after_hour",
        "ch_outbound_op" to "operation_id channel_id purpose ref?",
        "ch_seen" to "channel_id tag until_day",
        "ch_reveal" to "channel_id direction peer delete_at_minute?",
        "ch_join" to "channel_id kp_ref type invite_id? generation expiry_day",
        "ch_join_request" to "channel_id hash generation type invite_id? body_env until_day",
        "ch_invite_issued" to "channel_id invite_id invite_pk sponsor sponsor_sig committers_digest pw_version? " +
            "consumed void expiry_day",
        "ch_kp_seen" to "channel_id tag until_day",
        "ch_member_seen" to "channel_id member last_epoch",
        "ch_invite_own" to "invite_id channel_id invite_env? expiry_day",
        "ch_sponsor" to "channel_id member sponsor invite_id admitted_day",
        "ch_member_refresh" to "channel_id member refresh_day",
        "ch_request" to "channel_id kind subject payload_env? until_day",
        "ch_box_key" to "channel_id box_pk sk_env last_epoch?",
    )
}

internal fun chBytes(size: Int, fill: Int) = ByteArray(size) { fill.toByte() }

/**
 * A migrated database with row builders for the 26 tables: [put] inserts a valid row built from the
 * table's defaults and the overrides, after the parent rows it needs. [sql] returns the statement, so a
 * test can embed a literal (`3.5`) in place of a bound value.
 */
internal class ChannelFixture(
    val db: JdbcSqlExecutor = JdbcSqlExecutor().also { MigrationRunner(it).migrate() },
) : AutoCloseable {

    companion object {
        /** The channel every default row belongs to. */
        val CH: ByteArray = chBytes(32, 0xC1)
        val POST: ByteArray = chBytes(16, 0x16)

        /** The columns of each table, in order, with a valid value for each column a row must set. */
        private val defaults: Map<String, Map<String, Any?>> = mapOf(
            "ch_channel" to linkedMapOf(
                "channel_id" to CH, "state" to "active", "generation" to 0L, "epoch" to 0L, "joined_epoch" to 0L,
                "size_class" to 0L, "timer_code" to 4L, "my_pseudonym" to chBytes(32, 0x50),
            ),
            "ch_liveness" to linkedMapOf("channel_id" to CH, "progress_env" to chBytes(28, 1)),
            "ch_schedule" to linkedMapOf("channel_id" to CH, "next_selfupdate_day" to 20_000L),
            "ch_generation" to linkedMapOf(
                "channel_id" to CH, "generation" to 0L, "namespace_id" to chBytes(32, 0x61), "state" to "current",
                "g_env" to chBytes(60, 2), "jk_env" to chBytes(60, 3), "r_join" to chBytes(32, 4),
            ),
            "ch_epoch" to linkedMapOf(
                "channel_id" to CH, "epoch" to 0L, "state" to "open", "k_env" to chBytes(68, 5), "r_ep" to chBytes(32, 6),
            ),
            "ch_epoch_log" to linkedMapOf(
                "channel_id" to CH, "epoch" to 0L, "winner_hash" to chBytes(32, 7), "final_day" to 20_000L,
            ),
            "ch_candidate" to linkedMapOf(
                "channel_id" to CH, "epoch" to 0L, "hash" to chBytes(32, 8), "sender" to chBytes(32, 9),
                "rank" to 0L, "own" to 0L, "body_env" to chBytes(300, 10), "first_seen_minute" to 60L,
            ),
            "ch_fork_signal" to linkedMapOf(
                "channel_id" to CH, "epoch" to 0L, "hash" to chBytes(32, 11), "first_seen_day" to 20_000L,
            ),
            "mls_kv" to linkedMapOf("channel_id" to CH, "k" to chBytes(20, 12), "v_env" to chBytes(100, 13)),
            "mls_global_kv" to linkedMapOf("k" to chBytes(20, 14), "v_env" to chBytes(100, 15), "channel_id" to CH),
            "ch_post" to linkedMapOf(
                "op_id" to POST, "channel_id" to CH, "direction" to "in", "author" to chBytes(32, 17), "kind" to 1L,
                "timer_code" to 4L, "epoch" to 0L, "body_env" to chBytes(50, 18), "state" to "unread",
                "author_minute" to 600L,
            ),
            "ch_reaction" to linkedMapOf(
                "target" to POST, "author" to chBytes(32, 19), "channel_id" to CH, "grapheme_env" to chBytes(30, 20),
            ),
            "ch_pending_post" to linkedMapOf(
                "op_id" to chBytes(16, 21), "channel_id" to CH, "kind" to 1L, "content_env" to chBytes(50, 22),
                "fail_after_hour" to 3_600L,
            ),
            "ch_outbound_op" to linkedMapOf(
                "operation_id" to chBytes(16, 23), "channel_id" to CH, "purpose" to "post",
            ),
            "ch_seen" to linkedMapOf("channel_id" to CH, "tag" to chBytes(16, 24), "until_day" to 20_000L),
            "ch_reveal" to linkedMapOf("channel_id" to CH, "direction" to "out", "peer" to chBytes(32, 25)),
            "ch_join" to linkedMapOf(
                "channel_id" to CH, "kp_ref" to chBytes(32, 26), "type" to "join", "invite_id" to chBytes(16, 27),
                "generation" to 0L, "expiry_day" to 20_007L,
            ),
            "ch_join_request" to linkedMapOf(
                "channel_id" to CH, "hash" to chBytes(32, 28), "generation" to 0L, "type" to "join",
                "invite_id" to chBytes(16, 27), "body_env" to chBytes(500, 29), "until_day" to 20_007L,
            ),
            "ch_invite_issued" to linkedMapOf(
                "channel_id" to CH, "invite_id" to chBytes(16, 27), "invite_pk" to chBytes(32, 30),
                "sponsor" to chBytes(32, 31), "sponsor_sig" to chBytes(64, 32), "committers_digest" to chBytes(32, 33),
                "expiry_day" to 20_007L,
            ),
            "ch_kp_seen" to linkedMapOf("channel_id" to CH, "tag" to chBytes(16, 34), "until_day" to 20_011L),
            "ch_member_seen" to linkedMapOf("channel_id" to CH, "member" to chBytes(32, 35), "last_epoch" to 0L),
            "ch_invite_own" to linkedMapOf(
                "invite_id" to chBytes(16, 36), "channel_id" to CH, "invite_env" to chBytes(363, 37),
                "expiry_day" to 20_007L,
            ),
            "ch_sponsor" to linkedMapOf(
                "channel_id" to CH, "member" to chBytes(32, 38), "sponsor" to chBytes(32, 39),
                "invite_id" to chBytes(16, 27), "admitted_day" to 20_000L,
            ),
            "ch_member_refresh" to linkedMapOf(
                "channel_id" to CH, "member" to chBytes(32, 40), "refresh_day" to 20_000L,
            ),
            "ch_request" to linkedMapOf(
                "channel_id" to CH, "kind" to "leave", "subject" to chBytes(32, 41), "until_day" to 20_007L,
            ),
            "ch_box_key" to linkedMapOf(
                "channel_id" to CH, "box_pk" to chBytes(32, 42), "sk_env" to chBytes(60, 43),
            ),
        )

        init {
            check(defaults.keys == ChannelSchema.tables) { "a table without defaults: ${ChannelSchema.tables - defaults.keys}" }
        }

        /** The default row of [table] (a copy), with its columns in the order of the insert. */
        fun defaultsOf(table: String): LinkedHashMap<String, Any?> = LinkedHashMap(defaults.getValue(table))
    }

    /**
     * The statement and the arguments that insert the default row of [table] with [overrides] applied.
     * A column in [literals] is written as that SQL text instead of a bound value (`3.5`, `NULL`), which is
     * how a REAL reaches an INTEGER column, since the executor binds no REAL.
     */
    fun sql(
        table: String,
        overrides: Map<String, Any?> = emptyMap(),
        literals: Map<String, String> = emptyMap(),
        verb: String = "INSERT",
    ): Pair<String, List<Any?>> {
        val row = defaultsOf(table)
        for ((k, v) in overrides) row[k] = v
        for (k in literals.keys) row.putIfAbsent(k, null)
        val columns = row.keys.toList()
        val args = ArrayList<Any?>()
        val marks = columns.map { c ->
            val literal = literals[c]
            if (literal != null) literal else { args += row[c]; "?" }
        }
        return "$verb INTO $table(${columns.joinToString(", ")}) VALUES (${marks.joinToString(", ")})" to args
    }

    /** Inserts a valid row of [table], after the parents it needs; returns the arguments for a re-insert. */
    fun put(table: String, vararg overrides: Pair<String, Any?>) {
        parents(table)
        val (sql, args) = sql(table, mapOf(*overrides))
        db.exec(sql, args)
    }

    /** The parent rows of [table]: the channel for every channel-scoped table, and the post for a reaction. */
    fun parents(table: String) {
        if (table != "ch_channel" && !channelExists()) put("ch_channel")
        if (table == "ch_reaction" && db.queryLong("SELECT count(*) FROM ch_post WHERE op_id = ?", listOf(POST)) == 0L) put("ch_post")
    }

    private fun channelExists(): Boolean =
        db.queryLong("SELECT count(*) FROM ch_channel WHERE channel_id = ?", listOf(CH)) != 0L

    fun count(table: String): Long = db.queryLong("SELECT count(*) FROM $table")!!

    override fun close() = db.close()
}
