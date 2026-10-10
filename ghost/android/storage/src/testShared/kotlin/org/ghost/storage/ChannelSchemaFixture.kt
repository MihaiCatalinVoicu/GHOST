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

    /**
     * The 26 tables of §9 and `mls_self`, the one-row table of the wrapped channel state key that slice S4 amended into
     * migration 7 (§10.4 "State key"; §19.35 F-9, §19.37).
     */
    val tables: Set<String> = setOf(
        "ch_channel", "ch_liveness", "ch_schedule", "ch_generation", "ch_epoch", "ch_epoch_log", "ch_candidate",
        "ch_fork_signal", "mls_kv", "mls_global_kv", "ch_post", "ch_reaction", "ch_pending_post", "ch_outbound_op",
        "ch_seen", "ch_reveal", "ch_join", "ch_join_request", "ch_invite_issued", "ch_kp_seen", "ch_member_seen",
        "ch_invite_own", "ch_sponsor", "ch_member_refresh", "ch_request", "ch_box_key", "mls_self",
    )

    /** The two tables written with `INSERT OR IGNORE`, whose rows carry no rule: no REPLACE guard. */
    val unguarded: Set<String> = setOf("ch_seen", "ch_kp_seen")

    /**
     * The 37 state-machine, write-once and bound triggers: the 29 of the first version of migration 7, the seven the
     * review of S3 added (the end of a drain, a global row's day, a join, an own invite, and the three that keep a
     * pending post, a join request and a KeyPackage tag in the channel that bounds it) and `mls_self_fixed` (slice S4:
     * the state key is written once and never changed).
     */
    val rules: Set<String> = setOf(
        "ch_channel_identity", "ch_channel_state",
        "ch_generation_identity", "ch_generation_state", "ch_generation_drain", "ch_generation_one_current_insert",
        "ch_generation_one_current_update", "ch_generation_one_draining_insert", "ch_generation_one_draining_update",
        "ch_epoch_limit", "ch_epoch_anchor_insert", "ch_epoch_anchor_update", "ch_epoch_identity", "ch_epoch_final",
        "ch_epoch_log_limit", "ch_epoch_log_append_only",
        "ch_candidate_limit", "ch_candidate_identity", "ch_fork_signal_limit", "ch_fork_signal_append_only",
        "ch_post_identity", "ch_post_state", "ch_post_expiry", "ch_pending_post_limit", "ch_pending_post_channel",
        "ch_join_request_limit", "ch_join_request_channel", "ch_join_fixed", "ch_invite_own_fixed",
        "ch_invite_issued_identity", "ch_invite_issued_flags", "ch_kp_seen_limit", "ch_kp_seen_channel",
        "mls_global_kv_fixed", "ch_box_key_limit", "ch_box_key_replaced", "mls_self_fixed",
    )

    /** The rowid invariant of the two rowid tables: no row of theirs is stored with a rowid below 1, or changes its rowid. */
    val rowidChecks: Set<String> = setOf(
        "mls_kv_rowid_positive", "mls_kv_rowid_fixed", "ch_join_request_rowid_positive", "ch_join_request_rowid_fixed",
    )

    /** The 25 REPLACE guards: every table but [unguarded]. */
    val guards: Set<String> = setOf(
        "ch_channel_no_replace", "ch_liveness_no_replace", "ch_schedule_no_replace", "ch_generation_no_replace",
        "ch_epoch_no_replace", "ch_epoch_log_no_replace", "ch_candidate_no_replace", "ch_fork_signal_no_replace",
        "mls_kv_no_replace", "mls_global_kv_no_replace", "ch_post_no_replace", "ch_reaction_no_replace",
        "ch_pending_post_no_replace", "ch_outbound_op_no_replace", "ch_reveal_no_replace", "ch_join_no_replace",
        "ch_join_request_no_replace", "ch_invite_issued_no_replace", "ch_member_seen_no_replace",
        "ch_invite_own_no_replace", "ch_sponsor_no_replace", "ch_member_refresh_no_replace", "ch_request_no_replace",
        "ch_box_key_no_replace", "mls_self_no_replace",
    )

    /**
     * The tables that keep a hidden rowid, which records the order their rows arrived in (T33: "random WITHOUT
     * ROWID keys", F9 §13.6 step 5; §19.35, F-7): **two**, because the design needs it for them and for nothing
     * else — `mls_kv`, whose values are 0.1 to 125 KB (S0-6: §9 says it is not WITHOUT ROWID), and
     * `ch_join_request`, whose rows the committer serves "in arrival order" (§6.2.3). A REPLACE guard of such a
     * table also refuses an insert that names an existing rowid, and the table never holds a rowid below 1.
     */
    val rowidTables: Set<String> = setOf("mls_kv", "ch_join_request")

    /** The tables that are `WITHOUT ROWID`: the other 25, so that no table records the order its rows arrived in. */
    val withoutRowidTables: Set<String> = tables - rowidTables

    /**
     * Every time column of §9, as `table.column`: 34 of them (33 before slice S8 amended `ch_outbound_op` with the
     * op's deadline, §5.8, §19.45). The introspection tests require the database to hold exactly these (a column
     * that matches the time-like rule and is not here fails, and so does one here that no table has), each with
     * the granularity its suffix names.
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
        "ch_join.expiry_day",
        // Slice S7 (§6.7): `CH-REJOIN`'s absolute give-up day, first attempt day + 14.
        "ch_join.rejoin_deadline_day",
        "ch_join_request.until_day", "ch_join_request.recorded_day",
        "ch_invite_issued.expiry_day", "ch_kp_seen.until_day", "ch_invite_own.expiry_day",
        "ch_sponsor.admitted_day", "ch_member_refresh.refresh_day",
        "ch_request.until_day", "ch_request.recorded_day",
        // Slice S8 (§19.45): the outbound op's own deadline (§5.8), what the INDETERMINATE resend is bounded by.
        "ch_outbound_op.deadline_hour",
    )

    /**
     * The `*_day` columns that are a **week** (`% 7 = 0`), the `ceil7` of F9 §7.6 D3: a seizer learns the week a
     * post was displayed in and not the day. Only the dedup tag of a post, `dm_seen`'s twin; `ch_kp_seen.until_day`
     * is `GhostKpBind.day + 11` (§6.2.4 (B)) and is not.
     */
    val weekColumns: Set<String> = setOf("ch_seen.until_day")

    /**
     * The epoch counters, which match the time-like rule by name and are no time: MLS epoch numbers, `u64`,
     * each with a `typeof` CHECK.
     */
    val epochColumns: Set<String> = setOf(
        "ch_channel.epoch", "ch_channel.joined_epoch", "ch_epoch.epoch", "ch_epoch_log.epoch",
        "ch_candidate.epoch", "ch_fork_signal.epoch", "ch_post.epoch",
        "ch_member_seen.last_epoch", "ch_box_key.last_epoch",
        // Slice S4 (§19.37 F-S4-7): the epoch that opened a generation, `E_g` of the bootstrap (§5.4).
        "ch_generation.open_epoch",
    )

    /** Names that contain a word of the time-like rule while the value is no time. */
    val notTimes: Map<String, String> = mapOf(
        "ch_channel.timer_code" to "the channel's disappearing-timer bucket code, 0..5",
        "ch_post.timer_code" to "the bucket code the post was written under, 0..5",
    )

    /**
     * Integer columns that are neither a time nor an epoch and carry `typeof` beside a range: the
     * generation counters (`u32`), the commit rank, the own sequence number, the liveness counters, the
     * password version, the content kind of a pending post, the op's resend count (slice S8, §19.45:
     * Phase 7's "at most twice") and the two timer codes.
     */
    val counterColumns: Set<String> = setOf(
        "ch_channel.generation", "ch_generation.generation", "ch_join.generation", "ch_join_request.generation",
        "ch_candidate.rank", "ch_epoch.own_seq",
        "ch_liveness.unopenable_count", "ch_liveness.unopenable_operators", "ch_liveness.sessions",
        "ch_invite_issued.pw_version", "ch_pending_post.kind", "ch_outbound_op.resends",
        "ch_channel.timer_code", "ch_post.timer_code",
    )

    /** The 0/1 flags: `CHECK (x IN (0, 1))`, which admits no fraction either. */
    val flagColumns: Set<String> = setOf(
        "ch_channel.split_suspected", "ch_channel.partition_suspected", "ch_channel.stale_suspected",
        "ch_channel.pw_required", "ch_channel.size_class",
        "ch_candidate.own", "ch_candidate.verified", "ch_invite_issued.consumed", "ch_invite_issued.void",
        // Slice S4 (§19.35 F-1, §19.37): the candidate removes a pseudonym, the removal hold of CO-13.
        "ch_candidate.removes",
        // Slice S6 (§19.41): the member's own commit opened the generation (its funding is the rotating
        // committer's at the switch, §6.5).
        "ch_generation.own_rotation",
    )

    /**
     * The integer columns that are a closed list of values: `suite = 3`, the post's content kind (1, 2) and the one
     * row of `mls_self` (`id = 1`, slice S4).
     */
    val enumColumns: Set<String> = setOf("ch_channel.suite", "ch_post.kind", "mls_self.id")

    /**
     * What each table's columns are, in order, as `name` (NOT NULL) or `name?` (nullable): §9's table, and
     * nothing else. A column added to a channel table — a `created_at`, a counter — fails the introspection
     * test until it is written here beside the rule that allows it. **Slice S4's amendments** (§19.37):
     * `ch_channel.committers_digest` (F-S4-2), `ch_generation.open_epoch` (F-S4-7), `ch_candidate.removes` (§19.35
     * F-1), the invite state of `ch_join` (`ns`, `jk_env`, `r_join`, `committers_digest`; §19.35 F-8) and
     * `mls_self` (F-9).
     */
    val columns: Map<String, String> = mapOf(
        "ch_channel" to "channel_id state split_suspected partition_suspected stale_suspected pw_required suite " +
            "generation epoch joined_epoch size_class timer_code my_pseudonym name_env? last_committer_commit_day? " +
            "committers_digest?",
        "ch_liveness" to "channel_id unopenable_count unopenable_operators sessions progress_env unopenable_first_minute?",
        "ch_schedule" to "channel_id next_selfupdate_day last_own_commit_day? next_pass_minute?",
        "ch_generation" to "channel_id generation namespace_id state g_env jk_env r_join open_epoch own_rotation " +
            "switch_hour? drain_until_day?",
        "ch_epoch" to "channel_id epoch state k_env r_ep winner_hash? own_seq anchor_minute? final_day? keep_until_day?",
        "ch_epoch_log" to "channel_id epoch winner_hash final_day",
        "ch_candidate" to "channel_id epoch hash sender rank own verified body_env welcome_env? box_env? " +
            "first_seen_minute store_hour? removes",
        "ch_fork_signal" to "channel_id epoch hash first_seen_day",
        "mls_kv" to "channel_id k v_env",
        "mls_global_kv" to "k v_env channel_id delete_after_day?",
        "ch_post" to "op_id channel_id direction author kind reply_to? timer_code epoch body_env state author_minute " +
            "displayed_minute? delete_at_minute? relay_expiry_hour?",
        "ch_reaction" to "target author channel_id grapheme_env",
        "ch_pending_post" to "op_id channel_id kind content_env fail_after_hour",
        "ch_outbound_op" to "operation_id channel_id purpose ref? blob deadline_hour resends",
        "ch_seen" to "channel_id tag until_day",
        "ch_reveal" to "channel_id direction peer delete_at_minute?",
        "ch_join" to "channel_id kp_ref type invite_id? generation expiry_day ns? jk_env? r_join? committers_digest? " +
            "rejoin_deadline_day?",
        "ch_join_request" to "channel_id hash generation type invite_id? body_env member? until_day recorded_day",
        "ch_invite_issued" to "channel_id invite_id invite_pk sponsor sponsor_sig committers_digest pw_version? " +
            "consumed void expiry_day",
        "ch_kp_seen" to "channel_id tag until_day",
        "ch_member_seen" to "channel_id member last_epoch",
        "ch_invite_own" to "invite_id channel_id invite_env? expiry_day",
        "ch_sponsor" to "channel_id member sponsor invite_id admitted_day",
        "ch_member_refresh" to "channel_id member refresh_day",
        "ch_request" to "channel_id kind subject payload_env? until_day recorded_day",
        "ch_box_key" to "channel_id box_pk sk_env last_epoch?",
        "mls_self" to "id state_key_wrapped",
    )
}

internal fun chBytes(size: Int, fill: Int) = ByteArray(size) { fill.toByte() }

/**
 * A migrated database with row builders for the 27 tables: [put] inserts a valid row built from the
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
                "g_env" to chBytes(60, 2), "jk_env" to chBytes(60, 3), "r_join" to chBytes(32, 4), "open_epoch" to 0L,
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
                "blob" to chBytes(4096, 0x17), "deadline_hour" to 7_200L,
            ),
            "ch_seen" to linkedMapOf("channel_id" to CH, "tag" to chBytes(16, 24), "until_day" to 19_999L),
            "ch_reveal" to linkedMapOf("channel_id" to CH, "direction" to "out", "peer" to chBytes(32, 25)),
            "ch_join" to linkedMapOf(
                "channel_id" to CH, "kp_ref" to chBytes(32, 26), "type" to "join", "invite_id" to chBytes(16, 27),
                "generation" to 0L, "expiry_day" to 20_007L, "ns" to chBytes(32, 0x62), "jk_env" to chBytes(60, 0x63),
                "r_join" to chBytes(32, 0x64), "committers_digest" to chBytes(32, 0x65),
            ),
            "ch_join_request" to linkedMapOf(
                "channel_id" to CH, "hash" to chBytes(32, 28), "generation" to 0L, "type" to "join",
                "invite_id" to chBytes(16, 27), "body_env" to chBytes(500, 29), "until_day" to 20_007L,
                "recorded_day" to 20_000L,
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
                "recorded_day" to 20_000L,
            ),
            "ch_box_key" to linkedMapOf(
                "channel_id" to CH, "box_pk" to chBytes(32, 42), "sk_env" to chBytes(60, 43),
            ),
            "mls_self" to linkedMapOf("id" to 1L, "state_key_wrapped" to chBytes(48, 0x66)),
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
        if (table != "ch_channel" && table != "mls_self" && !channelExists()) put("ch_channel")
        if (table == "ch_reaction" && db.queryLong("SELECT count(*) FROM ch_post WHERE op_id = ?", listOf(POST)) == 0L) put("ch_post")
    }

    private fun channelExists(): Boolean =
        db.queryLong("SELECT count(*) FROM ch_channel WHERE channel_id = ?", listOf(CH)) != 0L

    fun count(table: String): Long = db.queryLong("SELECT count(*) FROM $table")!!

    override fun close() = db.close()
}
