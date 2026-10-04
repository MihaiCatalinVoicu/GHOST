package org.ghost.storage

import java.io.File

/**
 * The **expired-row lint** of Phase 9 design §10.7 point 4 and §21.14 (mutant **ME-16**, "a read
 * path ignores expiry"), built in slice S5.
 *
 * > "every read query filters `delete_at_minute IS NULL OR delete_at_minute > :now_e` (an expired
 * > row is never shown before physical deletion; a lint test runs every DAO query against an
 * > expired row)"
 *
 * Physical deletion of an expired message is SWEEP's job and it lags: the process may be frozen,
 * the alarm deferred by Doze, the device rebooted with no boot receiver (§21.10 point 8). Between
 * the expiry minute and the sweep the row is still in the database, and **the only thing standing
 * between it and the screen is the filter on every read query**. A read path that forgets the
 * filter is not a cosmetic bug: it shows a message the user was promised had disappeared.
 *
 * The lint has two halves, and needs both:
 *
 *  1. **Static** ([readQueriesOverExpiringRows]): the production sources are scanned for SQL that
 *     reads an expiring table. Every query found must be registered in [DmDaoQueries] — or, since
 *     slice S9, in [DmSweepQueries], which judges it by the opposite contract. This is what makes
 *     the lint automatic — a DAO added in S6 or S7 cannot be written without the lint noticing,
 *     wherever in the Android modules it lands.
 *  2. **Behavioural** ([outcomeOf]): each registered query is run twice, against a database that
 *     still holds the expired rows and against the same database after they were swept, and the
 *     two results must be **identical** — a compliant read path cannot tell whether SWEEP has run
 *     yet. This is §10.7's own words — "runs every DAO query against an expired row" — and it
 *     catches what a text scan cannot: a filter that is present but wrong (`>=` for `>`, `now` for
 *     `now_e`, a filter on the wrong column, a filter in a subquery that the outer join undoes).
 *
 * **Why the two-world comparison and not "did the expired id come back".** A lint that looks for
 * the expired `message_id` in the first column of the result sees nothing in an aggregate
 * (`SELECT count(*) …`, an unread badge — which is ME-16 exactly, §10.3), nothing in a projection
 * that puts the id anywhere but first, and nothing in a query that returns another table's columns
 * joined to `dm_message`. Comparing the whole result set of the two worlds needs no assumption
 * about what a query projects. Beside it, [Outcome.returnsNothing] refuses a query that matches no
 * row even in the swept world: such a query is broken, not compliant, and would otherwise pass for
 * free.
 *
 * **Scope (design §22.10 item 3).** The expiring table is `dm_message` and the column is
 * `delete_at_minute`, which is what §10.7 point 4 names. The other rows SWEEP deletes by time —
 * held envelopes, seen tags, pair keys, generations, retired sessions — are not read into a view,
 * so their bound is the sweep itself and not a read filter; if S7 gives one of them a read path
 * that a user sees, it joins [expiringTables] then.
 *
 * **What the static half still cannot see**, recorded so it is not mistaken for coverage: a query
 * whose *table name* arrives through a Kotlin template or a constant (`"SELECT … FROM $DM_MESSAGE"`)
 * names no expiring table in its text. Adjacent literals joined by `+` are concatenated before
 * matching ([literalRuns]), so the repo's own house style of splitting a long statement across
 * lines is covered; an interpolated table name is not, and a DM DAO must spell the table out.
 *
 * **The registry filled in S7** (`:messaging`'s `MessageStore`) and **split in S9**. Both halves
 * are still proved on fixtures as well as on production code, so the mechanism is known to work
 * independently of what it happens to find today.
 */
object DmExpiredRowLint {

    /** Table -> the column whose value makes a row expired, per §10.6 and §10.7 point 4. */
    val expiringTables: Map<String, String> = mapOf("dm_message" to "delete_at_minute")

    /**
     * One SQL string literal (or one run of `+`-joined literals) found in a production source. It
     * renders as `path:line: sql` from the Android root down, so a failure can be opened without
     * searching for the file first.
     */
    data class Found(val file: File, val line: Int, val sql: String) {
        override fun toString(): String {
            val path = file.invariantSeparatorsPath
            val marker = path.indexOf("/src/main/")
            val shown = if (marker < 0) path else path.substring(path.lastIndexOf('/', marker - 1) + 1)
            return "$shown:$line: ${sql.take(160)}"
        }
    }

    /** Directories that hold no production source and are never descended into. */
    private val prunedDirectories = setOf("build", "target", ".git", ".gradle", ".idea", "node_modules")

    /**
     * The Android modules' production Kotlin and Java sources. Resolved from the module directory
     * upwards, so the test does not depend on which module Gradle runs it from; returns null when
     * the Android root cannot be found, which callers must treat as a failure and not as "clean".
     *
     * Every `src/main` under the root is scanned, **at any depth**: `settings.gradle.kts` is flat
     * today, but a nested module (`features/dm/src/main`) must not be silently unscanned — the
     * other modules would still satisfy the vacuity floor and the gap would be invisible. This is
     * the same rule `dm-no-fts.sh` applies with its recursive `find`.
     */
    fun androidProductionSources(start: File = File(".").absoluteFile): List<File>? {
        var dir: File? = start
        while (dir != null && !File(dir, "settings.gradle.kts").isFile) dir = dir.parentFile
        val root = dir ?: return null
        val mains = ArrayList<File>()
        collectMainDirectories(root, mains)
        return mains
            .flatMap { main ->
                main.walkTopDown()
                    .filter { it.isFile && (it.extension == "kt" || it.extension == "java") }
                    .toList()
            }
            .sortedBy { it.path }
    }

    private fun collectMainDirectories(dir: File, out: MutableList<File>) {
        if (dir.name in prunedDirectories) return
        // `src/test`, `src/androidTest`, `src/testShared`, …: not production, and nothing
        // production sits below them.
        if (dir.parentFile?.name == "src" && dir.name != "main") return
        if (dir.name == "main" && dir.parentFile?.name == "src") {
            out += dir
            return
        }
        for (child in dir.listFiles().orEmpty()) if (child.isDirectory) collectMainDirectories(child, out)
    }

    private val selectLike = Regex("\\b(SELECT|FROM|JOIN)\\b", RegexOption.IGNORE_CASE)

    /**
     * Schema statements are not read paths. `Schema.kt`'s REPLACE guard for `dm_message` is a
     * `CREATE TRIGGER` whose body is `SELECT 1 FROM dm_message WHERE message_id = NEW.message_id`:
     * it reads the table to refuse a conflicting insert, it never shows anything, and an expiry
     * filter there would break the guard. The migration and index statements are excluded for the
     * same reason. [DmExpiredRowLintTest.theScannerIgnoresSchemaStatements] pins this.
     *
     * `CREATE VIEW` is **not** on this list although it is a schema statement: a view over
     * `dm_message` *is* a read path, and a DAO that selects from it never names `dm_message` at
     * all, so skipping the view would bypass both halves of the lint end to end. A view over an
     * expiring table is therefore reported like any other read, and must be registered or removed.
     */
    private val schemaStatement = Regex("\\bCREATE\\s+(TRIGGER|TABLE|INDEX|UNIQUE\\s+INDEX)\\b", RegexOption.IGNORE_CASE)

    /**
     * A statement whose **top-level verb** is a write is not a read path, whatever it contains
     * further in.
     *
     * The KDoc above has always said "writes (`DELETE`, `UPDATE`, `INSERT`) are not read paths and
     * are left alone", and until slice S9 the code only kept that promise for writes with no
     * subquery: the test was "does the literal contain `SELECT`", so a plain
     * `DELETE FROM dm_message WHERE delete_at_minute <= ?` was skipped while
     * `DELETE FROM dm_message WHERE message_id IN (SELECT message_id FROM dm_message …)` — the
     * batched form SWEEP has to use, because SQLite's `DELETE` takes no `LIMIT` unless it was
     * compiled with `SQLITE_ENABLE_UPDATE_DELETE_LIMIT` and Android's is not — was reported as a
     * read of `dm_message`. Anchoring on the first keyword is what the sentence already meant.
     *
     * It is deliberately **anchored**: a literal that merely mentions `DELETE` later (a `SELECT …
     * WHERE delete_at_minute …` does, as a column name) is still a read.
     */
    private val writeStatement = Regex("^\\s*(DELETE|UPDATE|INSERT|REPLACE)\\b", RegexOption.IGNORE_CASE)

    /**
     * Every SQL string literal of [sources] that reads one of [expiringTables]. A literal is a
     * `"..."` or `"""..."""` run that names `SELECT` and the table; writes (`DELETE`, `UPDATE`,
     * `INSERT`) are not read paths and are left alone — SWEEP's own `DELETE ... WHERE
     * delete_at_minute <= ?` is the one statement that is *supposed* to name expired rows.
     *
     * Adjacent literals joined by `+` are matched as one string, because that is how this repo
     * writes long SQL (`OutboxStore`, `DirectoryStore`, `StateStore`): the `SELECT` list and the
     * `FROM` clause sit in different literals, and a per-literal test would see neither half.
     *
     * [tables] is the set of expiring tables the scan looks for: the DM one by default, and
     * [ChannelExpiredRowLint] passes the channel tables (Phase 10 design §10.1, slice S3), so the scanner is
     * one implementation for both families.
     */
    fun readQueriesOverExpiringRows(sources: List<File>, tables: Set<String> = expiringTables.keys): List<Found> {
        val out = ArrayList<Found>()
        for (file in sources) {
            val text = runCatching { file.readText() }.getOrNull() ?: continue
            if (tables.none { text.contains(it) }) continue
            for (literal in literalRuns(text, stringLiterals(text))) {
                val sql = literal.text
                if (!selectLike.containsMatchIn(sql)) continue
                if (!sql.contains("SELECT", ignoreCase = true)) continue
                if (schemaStatement.containsMatchIn(sql)) continue
                if (writeStatement.containsMatchIn(sql)) continue
                if (tables.none { Regex("\\b$it\\b").containsMatchIn(sql) }) continue
                out += Found(file, literal.line, sql.replace(Regex("\\s+"), " ").trim())
            }
        }
        return out
    }

    private data class Literal(val line: Int, val text: String, val start: Int, val end: Int)

    /** Only whitespace and a single `+` between two literals: they are one string at runtime. */
    private val concatenation = Regex("^\\s*\\+\\s*$")

    /**
     * The literals of a source with every `+`-joined run collapsed into the string the runtime
     * actually builds. The run keeps the **first** literal's line, which is where a reader looks
     * for the statement, and its text is exactly what a DAO would register verbatim.
     */
    private fun literalRuns(text: String, literals: List<Literal>): List<Literal> {
        val out = ArrayList<Literal>()
        var i = 0
        while (i < literals.size) {
            var last = i
            val body = StringBuilder(literals[i].text)
            while (last + 1 < literals.size &&
                concatenation.matches(text.substring(literals[last].end, literals[last + 1].start))
            ) {
                last += 1
                body.append(literals[last].text)
            }
            out += Literal(literals[i].line, body.toString(), literals[i].start, literals[last].end)
            i = last + 1
        }
        return out
    }

    /**
     * String literals of a Kotlin or Java source, `"""raw"""` ones joined across their lines. This
     * is a scanner, not a parser: it takes the text between quotes, which is all the lint needs,
     * and it errs towards finding more literals rather than fewer.
     */
    private fun stringLiterals(text: String): List<Literal> {
        val out = ArrayList<Literal>()
        var i = 0
        var line = 1
        while (i < text.length) {
            val c = text[i]
            if (c == '\n') { line += 1; i += 1; continue }
            if (c != '"') { i += 1; continue }
            if (text.startsWith("\"\"\"", i)) {
                val end = text.indexOf("\"\"\"", i + 3)
                if (end < 0) break
                val body = text.substring(i + 3, end)
                out += Literal(line, body, i, end + 3)
                line += body.count { it == '\n' }
                i = end + 3
            } else {
                var j = i + 1
                val body = StringBuilder()
                while (j < text.length && text[j] != '"' && text[j] != '\n') {
                    if (text[j] == '\\') j += 1
                    if (j < text.length) body.append(text[j])
                    j += 1
                }
                out += Literal(line, body.toString(), i, minOf(j + 1, text.length))
                i = j + 1
            }
        }
        return out
    }

    /**
     * What a query returns in the world that still holds the expired rows, and in the same world
     * after SWEEP removed them.
     */
    data class Outcome(val beforeTheSweep: List<String>, val afterTheSweep: List<String>) {
        /**
         * The two worlds are distinguishable, so something the query returned depended on a row
         * the user was told had gone: a body, an id, or only a count. That is ME-16.
         */
        val showsAnExpiredRow: Boolean get() = beforeTheSweep != afterTheSweep

        /** A query that matches nothing even in the swept world is broken, not compliant. */
        val returnsNothing: Boolean get() = afterTheSweep.isEmpty()

        /**
         * The mirror property, for a **sweep** query ([DmSweepQueries]): every row it names is one
         * the sweep removes, so the swept world — which differs from the other only in those rows —
         * answers it with nothing at all.
         *
         * It is one half of the sweep contract. The other half is **completeness** (it names
         * *every* expired row), which the registry's test checks by count, because a query that
         * names two of the three fixture rows still satisfies this one.
         */
        val namesOnlyExpiredRows: Boolean get() = afterTheSweep.isEmpty()
    }

    /**
     * Runs [sql] against two databases that differ only in the expired `dm_message` rows — the
     * fixture world of [seedMessages] with and without them — and reports both result sets.
     *
     * The query is given `now` for every bind placeholder it carries, which is the shape §10.7
     * point 4 prescribes (`:now_e`); a query that needs other arguments registers them.
     */
    fun outcomeOf(sql: String, args: List<Any?>): Outcome =
        Outcome(rowsOf(sql, args, withExpired = true), rowsOf(sql, args, withExpired = false))

    /** Shorthand for [Outcome.showsAnExpiredRow]. */
    fun showsAnExpiredRow(sql: String, args: List<Any?>): Boolean = outcomeOf(sql, args).showsAnExpiredRow

    private fun rowsOf(sql: String, args: List<Any?>, withExpired: Boolean): List<String> =
        JdbcSqlExecutor().use { db ->
            MigrationRunner(db).migrate()
            seedMessages(db, withExpired)
            val out = ArrayList<String>()
            db.query(sql, args) { out += renderRow(it) }
            out.sorted()
        }

    /** No query of a DM DAO projects more columns than this; the reader stops at the first gap. */
    private const val MAX_COLUMNS = 64

    /**
     * A row rendered as the hex of every column it has, so two result sets can be compared without
     * knowing what the query projects. `getBytes` renders an INTEGER or TEXT value as its bytes
     * rather than failing, which is all the comparison needs.
     */
    private fun renderRow(row: SqlExecutor.Row): String {
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
     * The five fixture rows. Three are expired and two are not, and the shapes are chosen so that
     * a filter on the **wrong column** is caught by a value rather than by a NULL:
     *
     * | id | direction | state | `minute_index` | `expire_at` | `unread_deadline` | `delete_at` |
     * |---|---|---|---|---|---|---|
     * | [EXPIRED_OUT] | out | sent | 1 | `NOW` | NULL | `NOW` — the boundary: `>=` admits it, `>` does not |
     * | [EXPIRED_READ_IN] | in | read | 0 | `NOW - 60` | `NOW + 3600` | `NOW - 60` — an unread-deadline filter admits it |
     * | [EXPIRED_UNREAD_IN] | in | unread | 0 | NULL | `NOW - 60` | `NOW - 60` — an `expire_at` filter admits it |
     * | [LIVE_OUT] | out | sent | 0 | `NOW + 3600` | NULL | `NOW + 3600` |
     * | [LIVE_IN] | in | unread | 0 | NULL | `NOW + 3600` | `NOW + 3600` |
     *
     * Both directions carry a live row, so an inbound-only or unread-only read path still matches
     * something and cannot pass [Outcome.returnsNothing] for free.
     *
     * **Why [EXPIRED_OUT] is the one row with a `minute_index` above zero.** `NEXT_MINUTE_INDEX`
     * is `SELECT max(minute_index) … direction = 'out' AND author_minute = ?`, and every fixture
     * row used to carry index 0 — so the aggregate answered 0 in both worlds whether or not the
     * expiry filter was there, and an aggregate always returns a row, so
     * [Outcome.returnsNothing] did not catch it either. The registry entry was vacuous: deleting
     * the filter from the production query left the lint green. With the expired outgoing row one
     * index above the live one, the unswept world answers 1 and the swept world 0, which is the
     * repeat `MessageStore.nextMinuteIndex` exists to prevent. `dm_message` has no UNIQUE over
     * `(conversation_id, author_minute, minute_index)`, only
     * `CHECK (minute_index BETWEEN 0 AND 65535)`, so the fixture is legal.
     */
    val EXPIRED_OUT: ByteArray = ByteArray(16) { 0xE0.toByte() }
    val EXPIRED_READ_IN: ByteArray = ByteArray(16) { 0xE1.toByte() }
    val EXPIRED_UNREAD_IN: ByteArray = ByteArray(16) { 0xE2.toByte() }
    val LIVE_OUT: ByteArray = ByteArray(16) { 0x11 }
    val LIVE_IN: ByteArray = ByteArray(16) { 0x12 }

    /** The rows SWEEP takes, and the rows it leaves. */
    val expiredIds: List<ByteArray> = listOf(EXPIRED_OUT, EXPIRED_READ_IN, EXPIRED_UNREAD_IN)
    val liveIds: List<ByteArray> = listOf(LIVE_OUT, LIVE_IN)

    /** The `now_e` the fixture world is built around. */
    const val NOW: Long = 1_800_000_000L - 1_800_000_000L % 60
    /** The conversation every row belongs to. */
    val CONVERSATION: ByteArray = ByteArray(16) { 0x01 }

    private const val AUTHOR: Long = NOW - 86_400

    /** A row of the fixture world: what [seedMessages] inserts, and whether SWEEP takes it. */
    private data class Fixture(
        val id: ByteArray,
        val direction: String,
        val state: String,
        val expireAt: Long?,
        val unreadDeadline: Long?,
        val minuteIndex: Long = 0,
    ) {
        /** `delete_at_minute` follows its CHECK: the expiry minute when there is one, else the deadline. */
        val deleteAt: Long? get() = expireAt ?: unreadDeadline
    }

    private val fixtures = listOf(
        Fixture(EXPIRED_OUT, "out", "sent", NOW, null, minuteIndex = 1),
        Fixture(EXPIRED_READ_IN, "in", "read", NOW - 60, NOW + 3600),
        Fixture(EXPIRED_UNREAD_IN, "in", "unread", null, NOW - 60),
        Fixture(LIVE_OUT, "out", "sent", NOW + 3600, null),
        Fixture(LIVE_IN, "in", "unread", null, NOW + 3600),
    )

    /**
     * The fixture world: one contact, one conversation and the messages of [fixtures]. With
     * [withExpired] false the rows whose `delete_at_minute` has passed are simply never inserted,
     * which is the state the database reaches once SWEEP has run.
     */
    fun seedMessages(db: SqlExecutor, withExpired: Boolean = true) {
        db.exec(
            "INSERT INTO dm_contact(contact_id, identity_pk, card_env, card_index, trust_state, source, establishment) " +
                "VALUES (?, ?, ?, 0, 'unverified', 'link', 'card_only')",
            listOf(CONVERSATION, ByteArray(32) { 0x01 }, ByteArray(159) { 0x01 }),
        )
        db.exec(
            "INSERT INTO dm_conversation(conversation_id, contact_id) VALUES (?, ?)",
            listOf(CONVERSATION, CONVERSATION),
        )
        for (row in fixtures) {
            val expired = row.deleteAt!! <= NOW
            if (expired && !withExpired) continue
            db.exec(
                "INSERT INTO dm_message(message_id, conversation_id, direction, kind, author_minute, sort_minute, " +
                    "minute_index, timer_code, body_env, state, expire_at_minute, unread_deadline_minute, " +
                    "delete_at_minute) VALUES (?, ?, ?, 1, ?, ?, ?, 4, ?, ?, ?, ?, ?)",
                listOf(
                    row.id, CONVERSATION, row.direction, AUTHOR, AUTHOR, row.minuteIndex,
                    ByteArray(100) { row.id[0] }, row.state, row.expireAt, row.unreadDeadline, row.deleteAt,
                ),
            )
        }
    }
}

/**
 * Every read query of a DM DAO, with the arguments the lint should bind.
 *
 * The registry is filled by **slice S7**, which wrote the first DAO that reads `dm_message`
 * (`:messaging`'s `MessageStore`). Each entry is the query **verbatim**, because the point of the
 * registry is that the string the DAO runs is the string the lint runs; a query built from
 * `+`-joined literals registers as the string those literals build, which is what the scanner
 * reports and what `normalize` compares.
 *
 * **What the arguments are chosen for.** Each set makes the query match something in the swept
 * world — [DmExpiredRowLint.Outcome.returnsNothing] refuses a query that matches nothing even
 * there, because such a query is broken rather than compliant — and, where the fixture allows it,
 * makes the **unswept** world differ if the filter were missing. `theUnreadCount`,
 * `theConversationPageBeforeACursor` and `theNextMinuteIndex` all do both: without the filter the
 * first counts `EXPIRED_UNREAD_IN`, the second returns all three expired rows, and the third
 * answers the expired row's index instead of the live one's.
 *
 * `oneMessageById` is the one entry that cannot: a query keyed by a **live** id returns the same
 * row in both worlds whatever the filter does, and an **expired** id returns nothing in either,
 * which `returnsNothing` refuses as broken. Its filter is covered by the text scan alone, and
 * that is stated here rather than left to be discovered.
 */
object DmDaoQueries {
    data class Query(val name: String, val sql: String, val args: List<Any?>)

    /** The conversation of the fixture world; `seedMessages` keys the contact by it too. */
    private val conversation = DmExpiredRowLint.CONVERSATION

    /** The `now_e` every read is given, as §10.7 point 4 writes it (`:now_e`). */
    private const val NOW = DmExpiredRowLint.NOW

    /** The fixture's author minute: `NOW - 86 400`, which every row shares. */
    private const val AUTHOR = NOW - 86_400

    val registered: List<Query> = listOf(
        Query(
            name = "theConversationPage",
            sql = "SELECT message_id, conversation_id, direction, kind, author_minute, sort_minute, " +
                "minute_index, timer_code, body_env, state FROM dm_message " +
                "WHERE conversation_id = ? AND (delete_at_minute IS NULL OR delete_at_minute > ?) " +
                "ORDER BY sort_minute DESC, minute_index DESC, message_id DESC LIMIT ?",
            args = listOf(conversation, NOW, 50L),
        ),
        Query(
            name = "theConversationPageBeforeACursor",
            sql = "SELECT message_id, conversation_id, direction, kind, author_minute, sort_minute, " +
                "minute_index, timer_code, body_env, state FROM dm_message " +
                "WHERE conversation_id = ? AND (delete_at_minute IS NULL OR delete_at_minute > ?) " +
                "AND (sort_minute < ? OR (sort_minute = ? AND minute_index < ?) " +
                "OR (sort_minute = ? AND minute_index = ? AND message_id < ?)) " +
                "ORDER BY sort_minute DESC, minute_index DESC, message_id DESC LIMIT ?",
            // A cursor a minute after every fixture row, so the first disjunct admits all five and
            // the expiry filter is the only thing that can remove the three expired ones.
            args = listOf(
                conversation, NOW, AUTHOR + 60, AUTHOR + 60, 0L, AUTHOR + 60, 0L,
                ByteArray(16) { 0xFF.toByte() }, 50L,
            ),
        ),
        Query(
            name = "oneMessageById",
            sql = "SELECT message_id, conversation_id, direction, kind, author_minute, sort_minute, " +
                "minute_index, timer_code, body_env, state FROM dm_message " +
                "WHERE message_id = ? AND (delete_at_minute IS NULL OR delete_at_minute > ?)",
            // A **live** id: an expired one would return nothing in either world, which the lint
            // refuses as broken rather than accepting as compliant.
            args = listOf(DmExpiredRowLint.LIVE_IN, NOW),
        ),
        Query(
            name = "theUnreadCount",
            sql = "SELECT count(*) FROM dm_message WHERE direction = 'in' AND state = 'unread' " +
                "AND (delete_at_minute IS NULL OR delete_at_minute > ?)",
            args = listOf(NOW),
        ),
        Query(
            name = "theNextWakeDeadline",
            sql = "SELECT min(delete_at_minute) FROM dm_message " +
                "WHERE delete_at_minute IS NOT NULL AND delete_at_minute > ?",
            // A wake computed over expired rows is a wake in the past — an alarm that fires and
            // finds nothing left to do, once per expired row (§10.7 trigger 1). Without the filter
            // the fixture answers `NOW - 60` instead of `NOW + 3600`, and with `>=` it answers
            // `NOW`, so both near misses are caught by a value.
            args = listOf(NOW),
        ),
        Query(
            name = "theNextMinuteIndex",
            sql = "SELECT max(minute_index) FROM dm_message WHERE conversation_id = ? " +
                "AND direction = 'out' AND author_minute = ? " +
                "AND (delete_at_minute IS NULL OR delete_at_minute > ?)",
            args = listOf(conversation, AUTHOR, NOW),
        ),
    )
}

/**
 * The other side of the same scan: the queries **SWEEP** runs to find the rows it deletes.
 *
 * Added by slice S9, which wrote the first one. SWEEP's own statements are the expiry enforcement
 * and not a read path — they are *supposed* to name expired rows — but the static half of the lint
 * cannot tell them apart from a DAO read by looking, and it must not be allowed to: a registry
 * that simply exempted a file would exempt whatever that file later grew.
 *
 * So a sweep query is registered here and judged by the **mirror** of the read contract
 * ([DmExpiredRowLint.Outcome.namesOnlyExpiredRows]): run against the world that still holds
 * the expired rows it must return something, and against the same world after the sweep it must
 * return **nothing**. A UI read smuggled in here would return the live rows in the swept world and
 * fail; a sweep query with the boundary the wrong way round (`<` for `<=`, or the filter on
 * `expire_at_minute`) would miss `EXPIRED_UNREAD_IN` or `EXPIRED_OUT` and fail the same test, for
 * the same reason the read registry's near misses fail theirs.
 *
 * **Why SWEEP needs a `SELECT` at all**, rather than deleting by the condition alone: §10.6 bounds
 * one transaction at 500 rows, SQLite's `DELETE` takes no `LIMIT` on a build without
 * `SQLITE_ENABLE_UPDATE_DELETE_LIMIT` (Android's has none), and §10.6 also hands the ids to
 * `MediaPort.onMessagesDeleted(tx, ids)` inside the same transaction. Both need the ids.
 */
object DmSweepQueries {
    /** The `now_e` of the fixture world (§10.3 R-T7), which every sweep query is given. */
    private const val NOW = DmExpiredRowLint.NOW

    /** One batch of expired messages, as `Sweeper` reads them (§10.6, at most 500). */
    val registered: List<DmDaoQueries.Query> = listOf(
        DmDaoQueries.Query(
            name = "oneBatchOfExpiredMessages",
            sql = "SELECT message_id FROM dm_message WHERE delete_at_minute <= ? " +
                "ORDER BY delete_at_minute, message_id LIMIT ?",
            args = listOf(NOW, 500L),
        ),
    )
}
