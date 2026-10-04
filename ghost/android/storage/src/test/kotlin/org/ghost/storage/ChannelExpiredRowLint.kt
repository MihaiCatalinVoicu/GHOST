package org.ghost.storage

import java.io.File

/**
 * The **expired-row lint over the channel tables** (Phase 10 design §8.2, §10.1: "every read query filters
 * expired rows (the F9 `DmExpiredRowLint` extended to `ch_*`)"; mutant **ME-16**, "a read path ignores
 * expiry"), built in slice S3 with the DAOs of `org.ghost.messaging.channel.store`.
 *
 * The mechanism is [DmExpiredRowLint]'s and is not reimplemented: its scanner takes the set of tables to look
 * for ([DmExpiredRowLint.readQueriesOverExpiringRows]), and its two-world idea is applied here — every
 * registered query runs against a database that still holds the expired rows and against the same database
 * after they were swept, and the two answers must be **identical**, so a compliant read cannot tell whether
 * SWEEP has run yet. What differs from the DM lint is the number of tables (14, each with its own deadline
 * column and unit) and that three kinds of query exist, because three contracts do:
 *
 *  - [ChannelDaoQueries] **reads** — a user, the engine or a call sees their result: identical in the two
 *    worlds, non-empty in the swept one, and exactly the rows the live fixture holds (so a filter that hides
 *    a live row, `>` for `>=` on the last day of a row, is caught here and not only by the store's own tests).
 *    A point lookup by key is registered twice: once with a live key (judged as a read) and once with an
 *    **expired** key ([Mode.HIDES]), which must answer nothing in a world that still holds the row — the one
 *    thing a lookup can leak.
 *  - [ChannelBoundQueries] **bounds** — a count or an existence probe that mirrors a schema trigger (at most
 *    17 epochs, 64 requests, 256 pending posts, 1 024 tags). The trigger counts every row, expired or not, so
 *    the query must too: the opposite of a read, judged by seeing the expired rows.
 *  - [ChannelSweepQueries] **sweeps** — SWEEP's own selects, which name exactly the expired rows: something
 *    in the world that holds them, nothing after the sweep, and every expired row of the fixture.
 *
 * **The static half** is [DmExpiredRowLint]'s scan with [expiringTables]: every literal in the Android
 * production sources that reads one of the 14 tables must be registered (verbatim, so the string the DAO runs is
 * the string the lint runs) and every registered query must still exist. A DAO added by S4 to S9 cannot read
 * an expiring channel table without the lint hearing of it. **What it cannot see** is the same as the DM lint's:
 * a table name that arrives through a template or a constant; the channel DAOs spell the table out.
 */
object ChannelExpiredRowLint {

    /**
     * Table -> the column whose value makes a row expired (§8.2, §8.3, §8.5, §6.5, §6.2.2). `ch_reaction` has no
     * deadline of its own — it dies with its post, by cascade — so a read of it must go through the post's
     * deadline, which is what the entry says and what the scan therefore also looks for.
     */
    val expiringTables: Map<String, String> = mapOf(
        "ch_post" to "delete_at_minute",
        "ch_reaction" to "ch_post.delete_at_minute (through the target)",
        "ch_reveal" to "delete_at_minute",
        "ch_pending_post" to "fail_after_hour",
        "ch_seen" to "until_day",
        "ch_generation" to "drain_until_day",
        "ch_epoch" to "keep_until_day",
        "ch_join" to "expiry_day",
        "ch_join_request" to "until_day",
        "ch_kp_seen" to "until_day",
        "ch_invite_issued" to "expiry_day",
        "ch_invite_own" to "expiry_day",
        "ch_request" to "until_day",
        "mls_global_kv" to "delete_after_day",
    )

    /** The `now_e` of the fixture world, in seconds: on a minute and on an hour boundary. */
    const val NOW: Long = 1_800_000_000L

    /** The day of [NOW]'s world: what a `*_day` filter is given. */
    const val TODAY: Long = 20_833L

    val CH: ByteArray = ChannelFixture.CH
    val CH_B: ByteArray = chBytes(32, 0xC2)

    fun id(n: Int): ByteArray = chBytes(16, n)
    fun key(n: Int): ByteArray = chBytes(32, n)

    /** What a query is judged by. */
    enum class Mode { READ, HIDES, BOUND, SWEEP }

    class Query(
        val name: String,
        val sql: String,
        val args: List<Any?>,
        val mode: Mode = Mode.READ,
        /** READ and SWEEP: the rows the query answers in the swept world (READ) or names in the unswept one (SWEEP). */
        val rows: Int? = null,
        /** HIDES: a statement that counts the expired row the key names, to prove the unswept world holds it. */
        val proof: Pair<String, List<Any?>>? = null,
    ) {
        override fun toString(): String = name
    }

    data class Outcome(val beforeTheSweep: List<String>, val afterTheSweep: List<String>) {
        /** The two worlds are distinguishable: an expired row changed what the query answers (ME-16). */
        val showsAnExpiredRow: Boolean get() = beforeTheSweep != afterTheSweep
        val returnsNothing: Boolean get() = afterTheSweep.isEmpty()
    }

    fun outcomeOf(sql: String, args: List<Any?>): Outcome =
        Outcome(rowsOf(sql, args, withExpired = true), rowsOf(sql, args, withExpired = false))

    fun showsAnExpiredRow(sql: String, args: List<Any?>): Boolean = outcomeOf(sql, args).showsAnExpiredRow

    private fun rowsOf(sql: String, args: List<Any?>, withExpired: Boolean): List<String> =
        JdbcSqlExecutor().use { db ->
            MigrationRunner(db).migrate()
            seed(db, withExpired)
            val out = ArrayList<String>()
            db.query(sql, args) { out += render(it) }
            out.sorted()
        }

    /** The value of a statement that counts, in the unswept world: the proof that an expired row is there. */
    fun countIn(sql: String, args: List<Any?>, withExpired: Boolean): Long =
        JdbcSqlExecutor().use { db ->
            MigrationRunner(db).migrate()
            seed(db, withExpired)
            db.queryLong(sql, args) ?: 0L
        }

    private const val MAX_COLUMNS = 64

    private fun render(row: SqlExecutor.Row): String {
        val cells = ArrayList<String>()
        for (index in 0 until MAX_COLUMNS) {
            val cell: String
            try {
                cell = if (row.isNull(index)) "null" else row.blob(index).joinToString("") { "%02x".format(it) }
            } catch (e: Exception) {
                break
            }
            cells += cell
        }
        return cells.joinToString("|")
    }

    /**
     * The fixture world. Per expiring table, rows that are expired (`E…`: the boundary one, which a `>=` for `>`
     * admits, and older ones), live (`L…`: the last day of a row, which a `>` for `>=` hides, a far one and, where
     * the column is nullable, one with no deadline). With [withExpired] false the expired rows are never inserted,
     * which is the state the database reaches once SWEEP has run.
     *
     * | table | expired | live |
     * |---|---|---|
     * | `ch_post` | `NOW` (E1), `NOW − 60` (E2), `NOW − 7 200` (E3) | `NOW + 60`, `NOW + 3 600`, none |
     * | `ch_reveal` | `NOW`, `NOW − 60` | `NOW + 60`, none |
     * | `ch_pending_post` | `NOW`, `NOW − 3 600` | `NOW + 3 600`, `NOW + 7 200` |
     * | `ch_seen`, `ch_join`, `ch_join_request`, `ch_kp_seen`, `ch_invite_issued`, `ch_invite_own`, `ch_request` | `TODAY − 1` | `TODAY`, `TODAY + 7` |
     * | `ch_generation` (CH) | a draining one until `TODAY − 1` | a current one, a pending one; (CH_B) a draining one until `TODAY` |
     * | `ch_epoch` | final, kept until `TODAY − 1` | final until `TODAY`, until `TODAY + 1`, and the open one |
     * | `mls_global_kv` | until `TODAY − 1` | until `TODAY`, none; and one of another channel |
     */
    fun seed(db: JdbcSqlExecutor, withExpired: Boolean) {
        val f = ChannelFixture(db)
        f.put("ch_channel")
        f.put("ch_channel", "channel_id" to CH_B)
        fun row(expired: Boolean, table: String, vararg set: Pair<String, Any?>) {
            if (expired && !withExpired) return
            val (sql, args) = f.sql(table, mapOf(*set))
            db.exec(sql, args)
        }
        // ---- ch_post, with reactions on an expired and on a live post
        fun post(n: Int, expired: Boolean, dir: String, state: String, deleteAt: Long?) =
            row(
                expired, "ch_post", "op_id" to id(n), "author" to key(n), "direction" to dir, "state" to state,
                "delete_at_minute" to deleteAt, "author_minute" to NOW - 3_600L - n * 60L,
            )
        post(0xE1, true, "in", "unread", NOW)
        post(0xE2, true, "out", "sent", NOW - 60)
        post(0xE3, true, "in", "unread", NOW - 7_200)
        post(0x11, false, "in", "unread", NOW + 60)
        post(0x12, false, "out", "sent", NOW + 3_600)
        post(0x13, false, "in", "unread", null)
        fun reaction(target: Int, author: Int, expired: Boolean) {
            if (expired && !withExpired) return
            db.exec(
                "INSERT INTO ch_reaction(target, author, channel_id, grapheme_env) VALUES (?, ?, ?, ?)",
                listOf(id(target), key(author), CH, chBytes(30, author)),
            )
        }
        reaction(0xE1, 0xA1, true)
        reaction(0x11, 0xA1, false)
        reaction(0x11, 0xA2, false)
        // ---- ch_reveal
        row(true, "ch_reveal", "direction" to "out", "peer" to key(0xE1), "delete_at_minute" to NOW)
        row(true, "ch_reveal", "direction" to "in", "peer" to key(0xE2), "delete_at_minute" to NOW - 60)
        row(false, "ch_reveal", "direction" to "out", "peer" to key(0x11), "delete_at_minute" to NOW + 60)
        row(false, "ch_reveal", "direction" to "in", "peer" to key(0x12), "delete_at_minute" to null)
        // ---- ch_pending_post
        row(true, "ch_pending_post", "op_id" to id(0xE1), "fail_after_hour" to NOW)
        row(true, "ch_pending_post", "op_id" to id(0xE2), "fail_after_hour" to NOW - 3_600)
        row(false, "ch_pending_post", "op_id" to id(0x11), "fail_after_hour" to NOW + 3_600)
        row(false, "ch_pending_post", "op_id" to id(0x12), "fail_after_hour" to NOW + 7_200)
        // ---- the day-keyed tables: expired at TODAY − 1, live on TODAY itself and a week on
        fun tag(n: Int) = chBytes(16, n)
        for ((n, day, expired) in listOf(Triple(0xE1, TODAY - 1, true), Triple(0x11, TODAY, false), Triple(0x12, TODAY + 7, false))) {
            row(expired, "ch_seen", "tag" to tag(n), "until_day" to day)
            row(expired, "ch_join", "kp_ref" to key(n), "expiry_day" to day)
            row(expired, "ch_join_request", "hash" to key(n), "until_day" to day)
            row(expired, "ch_invite_issued", "invite_id" to id(n), "expiry_day" to day)
            row(expired, "ch_invite_own", "invite_id" to id(n), "expiry_day" to day, "invite_env" to if (n == 0x12) null else chBytes(363, n))
            row(expired, "ch_request", "kind" to if (n == 0x12) "remove" else "leave", "subject" to key(n), "until_day" to day)
        }
        row(true, "ch_kp_seen", "tag" to tag(0xE1), "until_day" to TODAY - 1)
        row(false, "ch_kp_seen", "tag" to tag(0x11), "until_day" to TODAY)
        // ---- ch_generation: channel CH has an expired drain; channel CH_B a drain on its last day
        row(true, "ch_generation", "generation" to 0L, "namespace_id" to key(0xA0), "state" to "draining", "drain_until_day" to TODAY - 1)
        row(false, "ch_generation", "generation" to 1L, "namespace_id" to key(0xA1), "state" to "current")
        row(false, "ch_generation", "generation" to 2L, "namespace_id" to key(0xA2), "state" to "pending_switch", "switch_hour" to NOW + 3_600)
        row(false, "ch_generation", "channel_id" to CH_B, "generation" to 0L, "namespace_id" to key(0xB0), "state" to "draining", "drain_until_day" to TODAY)
        row(false, "ch_generation", "channel_id" to CH_B, "generation" to 1L, "namespace_id" to key(0xB1), "state" to "current")
        // ---- ch_epoch
        row(true, "ch_epoch", "epoch" to 0L, "state" to "final", "final_day" to TODAY - 10, "keep_until_day" to TODAY - 1)
        row(false, "ch_epoch", "epoch" to 1L, "state" to "final", "final_day" to TODAY - 5, "keep_until_day" to TODAY)
        row(false, "ch_epoch", "epoch" to 2L, "state" to "final", "final_day" to TODAY - 1, "keep_until_day" to TODAY + 1)
        row(false, "ch_epoch", "epoch" to 3L)
        // ---- mls_global_kv: rows of CH (one expired, one on its last day, one with no day) and one of CH_B
        row(true, "mls_global_kv", "k" to key(0xE1), "delete_after_day" to TODAY - 1)
        row(false, "mls_global_kv", "k" to key(0x11), "delete_after_day" to TODAY)
        row(false, "mls_global_kv", "k" to key(0x12), "delete_after_day" to null)
        row(false, "mls_global_kv", "k" to key(0x13), "channel_id" to CH_B, "delete_after_day" to TODAY + 7)
    }

    // ------------------------------------------------------------------ the static half

    data class Found(val file: File, val line: Int, val sql: String) {
        override fun toString(): String {
            val path = file.invariantSeparatorsPath
            val marker = path.indexOf("/src/main/")
            val shown = if (marker < 0) path else path.substring(path.lastIndexOf('/', marker - 1) + 1)
            return "$shown:$line: ${sql.take(160)}"
        }
    }

    /** Every read of one of the 14 tables in [sources]: [DmExpiredRowLint]'s scan with the channel set. */
    fun readQueriesOverExpiringRows(sources: List<File>): List<Found> =
        DmExpiredRowLint.readQueriesOverExpiringRows(sources, expiringTables.keys).map { Found(it.file, it.line, it.sql) }
}

/**
 * Every read of an expiring channel table by a DAO, with the arguments the lint binds. Each entry is the query
 * **verbatim** (the string the DAO runs, as `+`-joined literals build it); the arguments are chosen so that the
 * query answers the live rows of the fixture world and, wherever the fixture allows it, so that the unswept
 * world differs if the filter were missing.
 */
object ChannelDaoQueries {
    private val L = ChannelExpiredRowLint
    private val CH = L.CH
    private const val NOW = ChannelExpiredRowLint.NOW
    private const val TODAY = ChannelExpiredRowLint.TODAY

    private fun read(name: String, sql: String, args: List<Any?>, rows: Int) = ChannelExpiredRowLint.Query(name, sql, args, rows = rows)

    private fun hides(name: String, sql: String, args: List<Any?>, table: String, where: String, proofArgs: List<Any?>) =
        ChannelExpiredRowLint.Query(
            name, sql, args, ChannelExpiredRowLint.Mode.HIDES,
            proof = "SELECT count(*) FROM $table WHERE $where" to proofArgs,
        )

    private const val POST_COLUMNS =
        "SELECT op_id, channel_id, direction, author, kind, reply_to, timer_code, epoch, body_env, state, " +
            "author_minute, displayed_minute, delete_at_minute, relay_expiry_hour FROM ch_post "

    private const val POST_PAGE = POST_COLUMNS +
        "WHERE channel_id = ? AND (delete_at_minute IS NULL OR delete_at_minute > ?) " +
        "ORDER BY author_minute DESC, author DESC, op_id DESC LIMIT ?"

    private const val GEN_COLUMNS =
        "SELECT channel_id, generation, namespace_id, state, g_env, jk_env, r_join, switch_hour, drain_until_day FROM ch_generation "

    private const val EPOCH_COLUMNS =
        "SELECT channel_id, epoch, state, k_env, r_ep, winner_hash, own_seq, anchor_minute, final_day, keep_until_day FROM ch_epoch "

    val registered: List<ChannelExpiredRowLint.Query> = listOf(
        // ---- PostStore
        read("thePostPage", POST_PAGE, listOf(CH, NOW, 50L), rows = 3),
        read(
            "thePostPageBeforeACursor",
            POST_COLUMNS + "WHERE channel_id = ? AND (delete_at_minute IS NULL OR delete_at_minute > ?) " +
                "AND (author_minute < ? OR (author_minute = ? AND author < ?) " +
                "OR (author_minute = ? AND author = ? AND op_id < ?)) " +
                "ORDER BY author_minute DESC, author DESC, op_id DESC LIMIT ?",
            listOf(CH, NOW, NOW, NOW, L.key(0xFF), NOW, L.key(0xFF), L.id(0xFF), 50L), rows = 3,
        ),
        read(
            "onePostById",
            POST_COLUMNS + "WHERE op_id = ? AND (delete_at_minute IS NULL OR delete_at_minute > ?)",
            listOf(L.id(0x11), NOW), rows = 1,
        ),
        hides(
            "anExpiredPostById",
            POST_COLUMNS + "WHERE op_id = ? AND (delete_at_minute IS NULL OR delete_at_minute > ?)",
            listOf(L.id(0xE1), NOW), "ch_post", "op_id = ?", listOf(L.id(0xE1)),
        ),
        read(
            "theUnreadCount",
            "SELECT count(*) FROM ch_post WHERE channel_id = ? AND direction = 'in' AND state = 'unread' " +
                "AND (delete_at_minute IS NULL OR delete_at_minute > ?)",
            listOf(CH, NOW), rows = 1,
        ),
        read(
            "theNextDeletionTime",
            "SELECT min(delete_at_minute) FROM ch_post WHERE delete_at_minute IS NOT NULL AND delete_at_minute > ?",
            listOf(NOW), rows = 1,
        ),
        read(
            "theReactionsOfALivePost",
            "SELECT r.target, r.author, r.grapheme_env FROM ch_reaction r JOIN ch_post p ON p.op_id = r.target " +
                "WHERE r.target = ? AND (p.delete_at_minute IS NULL OR p.delete_at_minute > ?) ORDER BY r.author",
            listOf(L.id(0x11), NOW), rows = 2,
        ),
        hides(
            "theReactionsOfAnExpiredPost",
            "SELECT r.target, r.author, r.grapheme_env FROM ch_reaction r JOIN ch_post p ON p.op_id = r.target " +
                "WHERE r.target = ? AND (p.delete_at_minute IS NULL OR p.delete_at_minute > ?) ORDER BY r.author",
            listOf(L.id(0xE1), NOW), "ch_reaction", "target = ?", listOf(L.id(0xE1)),
        ),
        read(
            "thePendingPosts",
            "SELECT op_id, channel_id, kind, content_env, fail_after_hour FROM ch_pending_post " +
                "WHERE channel_id = ? AND fail_after_hour > ? ORDER BY fail_after_hour, op_id",
            listOf(CH, NOW), rows = 2,
        ),
        read("aSeenTagWithinItsDay", "SELECT 1 FROM ch_seen WHERE channel_id = ? AND tag = ? AND until_day >= ?", listOf(CH, chBytes(16, 0x11), TODAY), rows = 1),
        hides(
            "anExpiredSeenTag", "SELECT 1 FROM ch_seen WHERE channel_id = ? AND tag = ? AND until_day >= ?",
            listOf(CH, chBytes(16, 0xE1), TODAY), "ch_seen", "tag = ?", listOf(chBytes(16, 0xE1)),
        ),
        read(
            "theReveals",
            "SELECT channel_id, direction, peer, delete_at_minute FROM ch_reveal " +
                "WHERE channel_id = ? AND (delete_at_minute IS NULL OR delete_at_minute > ?) ORDER BY direction, peer",
            listOf(CH, NOW), rows = 2,
        ),
        // ---- GenerationStore
        read(
            "oneGenerationWithinItsDrain",
            GEN_COLUMNS + "WHERE channel_id = ? AND generation = ? AND (drain_until_day IS NULL OR drain_until_day >= ?)",
            listOf(CH, 1L, TODAY), rows = 1,
        ),
        hides(
            "aDrainedGeneration",
            GEN_COLUMNS + "WHERE channel_id = ? AND generation = ? AND (drain_until_day IS NULL OR drain_until_day >= ?)",
            listOf(CH, 0L, TODAY), "ch_generation", "channel_id = ? AND generation = 0", listOf(CH),
        ),
        read(
            "theLiveGenerations",
            GEN_COLUMNS + "WHERE channel_id = ? AND (drain_until_day IS NULL OR drain_until_day >= ?) ORDER BY generation",
            listOf(CH, TODAY), rows = 2,
        ),
        read(
            "theLiveGenerationsOfTheOtherChannelOnTheLastDayOfItsDrain",
            GEN_COLUMNS + "WHERE channel_id = ? AND (drain_until_day IS NULL OR drain_until_day >= ?) ORDER BY generation",
            listOf(L.CH_B, TODAY), rows = 2,
        ),
        read(
            "theCurrentGeneration",
            GEN_COLUMNS + "WHERE channel_id = ? AND state = 'current' AND (drain_until_day IS NULL OR drain_until_day >= ?)",
            listOf(CH, TODAY), rows = 1,
        ),
        read(
            "thePendingGenerationsDueNow",
            GEN_COLUMNS + "WHERE channel_id = ? AND state = 'pending_switch' " +
                "AND (switch_hour IS NULL OR switch_hour <= ?) AND (drain_until_day IS NULL OR drain_until_day >= ?) " +
                "ORDER BY generation",
            listOf(CH, NOW + 3_600, TODAY), rows = 1,
        ),
        read(
            "theRouteOfAListenedNamespace",
            "SELECT channel_id, generation, state FROM ch_generation WHERE namespace_id = ? " +
                "AND (drain_until_day IS NULL OR drain_until_day >= ?)",
            listOf(L.key(0xB0), TODAY), rows = 1,
        ),
        hides(
            "theRouteOfADrainedNamespace",
            "SELECT channel_id, generation, state FROM ch_generation WHERE namespace_id = ? " +
                "AND (drain_until_day IS NULL OR drain_until_day >= ?)",
            listOf(L.key(0xA0), TODAY), "ch_generation", "namespace_id = ?", listOf(L.key(0xA0)),
        ),
        // ---- EpochStore
        read(
            "oneEpochWithinItsRetention",
            EPOCH_COLUMNS + "WHERE channel_id = ? AND epoch = ? AND (keep_until_day IS NULL OR keep_until_day >= ?)",
            listOf(CH, 1L, TODAY), rows = 1,
        ),
        hides(
            "anEpochPastItsRetention",
            EPOCH_COLUMNS + "WHERE channel_id = ? AND epoch = ? AND (keep_until_day IS NULL OR keep_until_day >= ?)",
            listOf(CH, 0L, TODAY), "ch_epoch", "channel_id = ? AND epoch = 0", listOf(CH),
        ),
        read(
            "theOpenEpoch",
            EPOCH_COLUMNS + "WHERE channel_id = ? AND state = 'open' AND (keep_until_day IS NULL OR keep_until_day >= ?)",
            listOf(CH, TODAY), rows = 1,
        ),
        read(
            "theRetainedEpochs",
            EPOCH_COLUMNS + "WHERE channel_id = ? AND (keep_until_day IS NULL OR keep_until_day >= ?) ORDER BY epoch DESC",
            listOf(CH, TODAY), rows = 3,
        ),
        read(
            "thePastEpochsStillKept",
            "SELECT count(*) FROM ch_epoch WHERE channel_id = ? AND state = 'final' " +
                "AND (keep_until_day IS NULL OR keep_until_day >= ?)",
            listOf(CH, TODAY), rows = 1,
        ),
        read(
            "theOwnSequenceOfTheOpenEpoch",
            "SELECT own_seq FROM ch_epoch WHERE channel_id = ? AND epoch = ? AND state = 'open' " +
                "AND (keep_until_day IS NULL OR keep_until_day >= ?)",
            listOf(CH, 3L, TODAY), rows = 1,
        ),
        // ---- JoinStore
        read(
            "theJoinsOfAChannel",
            "SELECT channel_id, kp_ref, type, invite_id, generation, expiry_day FROM ch_join " +
                "WHERE channel_id = ? AND expiry_day >= ? ORDER BY expiry_day, kp_ref",
            listOf(CH, TODAY), rows = 2,
        ),
        read(
            "oneJoin",
            "SELECT channel_id, kp_ref, type, invite_id, generation, expiry_day FROM ch_join " +
                "WHERE channel_id = ? AND kp_ref = ? AND expiry_day >= ?",
            listOf(CH, L.key(0x11), TODAY), rows = 1,
        ),
        hides(
            "anExpiredJoin",
            "SELECT channel_id, kp_ref, type, invite_id, generation, expiry_day FROM ch_join " +
                "WHERE channel_id = ? AND kp_ref = ? AND expiry_day >= ?",
            listOf(CH, L.key(0xE1), TODAY), "ch_join", "kp_ref = ?", listOf(L.key(0xE1)),
        ),
        read(
            "theJoinRequests",
            "SELECT channel_id, hash, generation, type, invite_id, body_env, until_day FROM ch_join_request " +
                "WHERE channel_id = ? AND until_day >= ? ORDER BY rowid",
            listOf(CH, TODAY), rows = 2,
        ),
        read(
            "oneJoinRequest",
            "SELECT channel_id, hash, generation, type, invite_id, body_env, until_day FROM ch_join_request " +
                "WHERE channel_id = ? AND hash = ? AND until_day >= ?",
            listOf(CH, L.key(0x12), TODAY), rows = 1,
        ),
        hides(
            "anExpiredJoinRequest",
            "SELECT channel_id, hash, generation, type, invite_id, body_env, until_day FROM ch_join_request " +
                "WHERE channel_id = ? AND hash = ? AND until_day >= ?",
            listOf(CH, L.key(0xE1), TODAY), "ch_join_request", "hash = ?", listOf(L.key(0xE1)),
        ),
        read("aKeyPackageTagWithinItsDay", "SELECT 1 FROM ch_kp_seen WHERE channel_id = ? AND tag = ? AND until_day >= ?", listOf(CH, chBytes(16, 0x11), TODAY), rows = 1),
        hides(
            "anExpiredKeyPackageTag", "SELECT 1 FROM ch_kp_seen WHERE channel_id = ? AND tag = ? AND until_day >= ?",
            listOf(CH, chBytes(16, 0xE1), TODAY), "ch_kp_seen", "tag = ?", listOf(chBytes(16, 0xE1)),
        ),
        // ---- InviteStore
        read(
            "oneIssuedInvite",
            "SELECT channel_id, invite_id, invite_pk, sponsor, sponsor_sig, committers_digest, pw_version, consumed, void, " +
                "expiry_day FROM ch_invite_issued WHERE channel_id = ? AND invite_id = ? AND expiry_day >= ?",
            listOf(CH, L.id(0x11), TODAY), rows = 1,
        ),
        hides(
            "anExpiredIssuedInvite",
            "SELECT channel_id, invite_id, invite_pk, sponsor, sponsor_sig, committers_digest, pw_version, consumed, void, " +
                "expiry_day FROM ch_invite_issued WHERE channel_id = ? AND invite_id = ? AND expiry_day >= ?",
            listOf(CH, L.id(0xE1), TODAY), "ch_invite_issued", "invite_id = ?", listOf(L.id(0xE1)),
        ),
        read(
            "theIssuedInvitesOfAChannel",
            "SELECT channel_id, invite_id, invite_pk, sponsor, sponsor_sig, committers_digest, pw_version, consumed, void, " +
                "expiry_day FROM ch_invite_issued WHERE channel_id = ? AND expiry_day >= ? ORDER BY invite_id",
            listOf(CH, TODAY), rows = 2,
        ),
        read(
            "theOwnInvitesOfAChannel",
            "SELECT invite_id, channel_id, invite_env, expiry_day FROM ch_invite_own WHERE channel_id = ? AND expiry_day >= ? " +
                "ORDER BY expiry_day, invite_id",
            listOf(CH, TODAY), rows = 2,
        ),
        read(
            "oneOwnInvite",
            "SELECT invite_id, channel_id, invite_env, expiry_day FROM ch_invite_own WHERE invite_id = ? AND expiry_day >= ?",
            listOf(L.id(0x11), TODAY), rows = 1,
        ),
        hides(
            "anExpiredOwnInvite",
            "SELECT invite_id, channel_id, invite_env, expiry_day FROM ch_invite_own WHERE invite_id = ? AND expiry_day >= ?",
            listOf(L.id(0xE1), TODAY), "ch_invite_own", "invite_id = ?", listOf(L.id(0xE1)),
        ),
        // ---- MemberStore
        read(
            "theRequestsOfAChannel",
            "SELECT channel_id, kind, subject, payload_env, until_day FROM ch_request WHERE channel_id = ? AND until_day >= ? " +
                "ORDER BY until_day, kind, subject",
            listOf(CH, TODAY), rows = 2,
        ),
        read(
            "oneRequest",
            "SELECT channel_id, kind, subject, payload_env, until_day FROM ch_request " +
                "WHERE channel_id = ? AND kind = ? AND subject = ? AND until_day >= ?",
            listOf(CH, "leave", L.key(0x11), TODAY), rows = 1,
        ),
        hides(
            "anExpiredRequest",
            "SELECT channel_id, kind, subject, payload_env, until_day FROM ch_request " +
                "WHERE channel_id = ? AND kind = ? AND subject = ? AND until_day >= ?",
            listOf(CH, "leave", L.key(0xE1), TODAY), "ch_request", "subject = ?", listOf(L.key(0xE1)),
        ),
        // ---- MlsKvStore
        read(
            "theGlobalRowsOfAChannelWithinTheirDay",
            "SELECT k, v_env FROM mls_global_kv WHERE channel_id = ? AND (delete_after_day IS NULL OR delete_after_day >= ?) ORDER BY k",
            listOf(CH, TODAY), rows = 2,
        ),
    )
}

/**
 * The counts and probes that mirror a schema trigger: they **see the expired rows**, because the trigger counts
 * every row, so a store that counted only the live ones would think a table has room the trigger will refuse.
 */
object ChannelBoundQueries {
    private val L = ChannelExpiredRowLint
    private val CH = L.CH

    private fun bound(name: String, sql: String, args: List<Any?>) =
        ChannelExpiredRowLint.Query(name, sql, args, ChannelExpiredRowLint.Mode.BOUND)

    val registered: List<ChannelExpiredRowLint.Query> = listOf(
        bound("theEpochRowsOfAChannel", "SELECT count(*) FROM ch_epoch WHERE channel_id = ?", listOf(CH)),
        bound("thePendingPostsOfAChannel", "SELECT count(*) FROM ch_pending_post WHERE channel_id = ?", listOf(CH)),
        bound("theJoinRequestsOfAChannel", "SELECT count(*) FROM ch_join_request WHERE channel_id = ?", listOf(CH)),
        bound("theKeyPackageTagsOfAChannel", "SELECT count(*) FROM ch_kp_seen WHERE channel_id = ?", listOf(CH)),
        bound(
            "aKeyPackageTagThatIsThere", "SELECT 1 FROM ch_kp_seen WHERE channel_id = ? AND tag = ?",
            listOf(CH, chBytes(16, 0xE1)),
        ),
    )
}

/**
 * The selects SWEEP runs to find what it deletes: they name **exactly the expired rows**. Judged by the mirror of
 * the read contract: something in the world that still holds them, nothing after the sweep, and — by [Query.rows]
 * — every expired row of the fixture.
 */
object ChannelSweepQueries {
    private val L = ChannelExpiredRowLint
    private const val NOW = ChannelExpiredRowLint.NOW
    private const val TODAY = ChannelExpiredRowLint.TODAY

    private fun sweep(name: String, sql: String, args: List<Any?>, rows: Int) =
        ChannelExpiredRowLint.Query(name, sql, args, ChannelExpiredRowLint.Mode.SWEEP, rows = rows)

    val registered: List<ChannelExpiredRowLint.Query> = listOf(
        sweep(
            "oneBatchOfExpiredPosts",
            "SELECT op_id FROM ch_post WHERE delete_at_minute <= ? ORDER BY delete_at_minute, op_id LIMIT ?",
            listOf(NOW, 500L), rows = 3,
        ),
        sweep(
            "oneBatchOfExpiredPendingPosts",
            "SELECT op_id, channel_id, kind, content_env, fail_after_hour FROM ch_pending_post " +
                "WHERE fail_after_hour <= ? ORDER BY fail_after_hour, op_id LIMIT ?",
            listOf(NOW, 500L), rows = 2,
        ),
        sweep(
            "oneBatchOfExpiredReveals",
            "SELECT channel_id, direction, peer, delete_at_minute FROM ch_reveal WHERE delete_at_minute <= ? " +
                "ORDER BY delete_at_minute, channel_id, direction, peer LIMIT ?",
            listOf(NOW, 500L), rows = 2,
        ),
        sweep(
            "oneBatchOfDrainedGenerations",
            "SELECT channel_id, generation, state FROM ch_generation WHERE drain_until_day < ? " +
                "ORDER BY drain_until_day, channel_id, generation LIMIT ?",
            listOf(TODAY, 500L), rows = 1,
        ),
        sweep(
            "oneBatchOfExpiredEpochs",
            "SELECT channel_id, epoch FROM ch_epoch WHERE keep_until_day < ? ORDER BY keep_until_day, channel_id, epoch LIMIT ?",
            listOf(TODAY, 500L), rows = 1,
        ),
        sweep(
            "oneBatchOfExpiredJoins",
            "SELECT channel_id, kp_ref, type, invite_id, generation, expiry_day FROM ch_join WHERE expiry_day < ? " +
                "ORDER BY expiry_day, channel_id, kp_ref LIMIT ?",
            listOf(TODAY, 500L), rows = 1,
        ),
        sweep(
            "oneBatchOfExpiredJoinRequests",
            "SELECT channel_id, hash, generation, type, invite_id, body_env, until_day FROM ch_join_request " +
                "WHERE until_day < ? ORDER BY until_day, channel_id, hash LIMIT ?",
            listOf(TODAY, 500L), rows = 1,
        ),
        sweep(
            "oneBatchOfExpiredIssuedInvites",
            "SELECT channel_id, invite_id, invite_pk, sponsor, sponsor_sig, committers_digest, pw_version, consumed, void, " +
                "expiry_day FROM ch_invite_issued WHERE expiry_day < ? ORDER BY expiry_day, channel_id, invite_id LIMIT ?",
            listOf(TODAY, 500L), rows = 1,
        ),
        sweep(
            "oneBatchOfExpiredOwnInvites",
            "SELECT invite_id, channel_id, invite_env, expiry_day FROM ch_invite_own WHERE expiry_day < ? " +
                "ORDER BY expiry_day, invite_id LIMIT ?",
            listOf(TODAY, 500L), rows = 1,
        ),
        sweep(
            "oneBatchOfExpiredRequests",
            "SELECT channel_id, kind, subject, payload_env, until_day FROM ch_request WHERE until_day < ? " +
                "ORDER BY until_day, channel_id, kind, subject LIMIT ?",
            listOf(TODAY, 500L), rows = 1,
        ),
        sweep(
            "oneBatchOfExpiredGlobalRows",
            "SELECT k FROM mls_global_kv WHERE delete_after_day < ? ORDER BY delete_after_day, k LIMIT ?",
            listOf(TODAY, 500L), rows = 1,
        ),
    )
}
