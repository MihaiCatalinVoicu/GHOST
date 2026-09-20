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
 *     reads an expiring table. Every query found must be registered in [DmDaoQueries]. This is
 *     what makes the lint automatic — a DAO added in S6 or S7 cannot be written without the lint
 *     noticing, wherever in the Android modules it lands.
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
 * **Today the registry is empty**, and that is a fact the lint asserts rather than assumes: no DM
 * DAO exists (`:messaging` is a manifest and nothing else; `:storage` has no DM repository), the
 * static half finds nothing, and both halves are proved on fixtures instead of on production code
 * so the mechanism is known to work before it has work to do.
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
     * Every SQL string literal of [sources] that reads one of [expiringTables]. A literal is a
     * `"..."` or `"""..."""` run that names `SELECT` and the table; writes (`DELETE`, `UPDATE`,
     * `INSERT`) are not read paths and are left alone — SWEEP's own `DELETE ... WHERE
     * delete_at_minute <= ?` is the one statement that is *supposed* to name expired rows.
     *
     * Adjacent literals joined by `+` are matched as one string, because that is how this repo
     * writes long SQL (`OutboxStore`, `DirectoryStore`, `StateStore`): the `SELECT` list and the
     * `FROM` clause sit in different literals, and a per-literal test would see neither half.
     */
    fun readQueriesOverExpiringRows(sources: List<File>): List<Found> {
        val out = ArrayList<Found>()
        for (file in sources) {
            val text = runCatching { file.readText() }.getOrNull() ?: continue
            if (expiringTables.keys.none { text.contains(it) }) continue
            for (literal in literalRuns(text, stringLiterals(text))) {
                val sql = literal.text
                if (!selectLike.containsMatchIn(sql)) continue
                if (!sql.contains("SELECT", ignoreCase = true)) continue
                if (schemaStatement.containsMatchIn(sql)) continue
                if (expiringTables.keys.none { Regex("\\b$it\\b").containsMatchIn(sql) }) continue
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
     * | id | direction | state | `expire_at` | `unread_deadline` | `delete_at` |
     * |---|---|---|---|---|---|
     * | [EXPIRED_OUT] | out | sent | `NOW` | NULL | `NOW` — the boundary: `>=` admits it, `>` does not |
     * | [EXPIRED_READ_IN] | in | read | `NOW - 60` | `NOW + 3600` | `NOW - 60` — an unread-deadline filter admits it |
     * | [EXPIRED_UNREAD_IN] | in | unread | NULL | `NOW - 60` | `NOW - 60` — an `expire_at` filter admits it |
     * | [LIVE_OUT] | out | sent | `NOW + 3600` | NULL | `NOW + 3600` |
     * | [LIVE_IN] | in | unread | NULL | `NOW + 3600` | `NOW + 3600` |
     *
     * Both directions carry a live row, so an inbound-only or unread-only read path still matches
     * something and cannot pass [Outcome.returnsNothing] for free.
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
    ) {
        /** `delete_at_minute` follows its CHECK: the expiry minute when there is one, else the deadline. */
        val deleteAt: Long? get() = expireAt ?: unreadDeadline
    }

    private val fixtures = listOf(
        Fixture(EXPIRED_OUT, "out", "sent", NOW, null),
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
                    "delete_at_minute) VALUES (?, ?, ?, 1, ?, ?, 0, 4, ?, ?, ?, ?, ?)",
                listOf(
                    row.id, CONVERSATION, row.direction, AUTHOR, AUTHOR,
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
 * makes the **unswept** world differ if the filter were missing. `theUnreadCount` and
 * `theConversationPageBeforeACursor` are the two that do both: without the filter the first
 * counts `EXPIRED_UNREAD_IN` and the second returns all three expired rows.
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
            name = "theNextMinuteIndex",
            sql = "SELECT max(minute_index) FROM dm_message WHERE conversation_id = ? " +
                "AND direction = 'out' AND author_minute = ? " +
                "AND (delete_at_minute IS NULL OR delete_at_minute > ?)",
            args = listOf(conversation, AUTHOR, NOW),
        ),
    )
}
