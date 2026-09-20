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
 *  2. **Behavioural** ([showsAnExpiredRow]): each registered query is run against a database
 *     holding one expired row and one live row. A query that returns the expired row fails. This
 *     is §10.7's own words — "runs every DAO query against an expired row" — and it catches what
 *     a text scan cannot: a filter that is present but wrong (`>=` for `>`, `now` for `now_e`, a
 *     filter on the wrong column, a filter in a subquery that the outer join undoes).
 *
 * **Scope (design §22.10 item 3).** The expiring table is `dm_message` and the column is
 * `delete_at_minute`, which is what §10.7 point 4 names. The other rows SWEEP deletes by time —
 * held envelopes, seen tags, pair keys, generations, retired sessions — are not read into a view,
 * so their bound is the sweep itself and not a read filter; if S7 gives one of them a read path
 * that a user sees, it joins [expiringTables] then.
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
     * One SQL string literal found in a production source. It renders as `path:line: sql` from the
     * Android root down, so a failure can be opened without searching for the file first.
     */
    data class Found(val file: File, val line: Int, val sql: String) {
        override fun toString(): String {
            val path = file.invariantSeparatorsPath
            val marker = path.indexOf("/src/main/")
            val shown = if (marker < 0) path else path.substring(path.lastIndexOf('/', marker - 1) + 1)
            return "$shown:$line: ${sql.take(160)}"
        }
    }

    /**
     * The Android modules' production Kotlin and Java sources. Resolved from the module directory
     * upwards, so the test does not depend on which module Gradle runs it from; returns null when
     * the Android root cannot be found, which callers must treat as a failure and not as "clean".
     */
    fun androidProductionSources(start: File = File(".").absoluteFile): List<File>? {
        var dir: File? = start
        while (dir != null && !File(dir, "settings.gradle.kts").isFile) dir = dir.parentFile
        val root = dir ?: return null
        return root.listFiles()
            .orEmpty()
            .filter { it.isDirectory && File(it, "src/main").isDirectory }
            .flatMap { module ->
                File(module, "src/main").walkTopDown()
                    .filter { it.isFile && (it.extension == "kt" || it.extension == "java") }
                    .toList()
            }
            .sortedBy { it.path }
    }

    private val selectLike = Regex("\\b(SELECT|FROM|JOIN)\\b", RegexOption.IGNORE_CASE)

    /**
     * Schema statements are not read paths. `Schema.kt`'s REPLACE guard for `dm_message` is a
     * `CREATE TRIGGER` whose body is `SELECT 1 FROM dm_message WHERE message_id = NEW.message_id`:
     * it reads the table to refuse a conflicting insert, it never shows anything, and an expiry
     * filter there would break the guard. The migration and index statements are excluded for the
     * same reason. [DmExpiredRowLintTest.theScannerIgnoresSchemaStatements] pins this.
     */
    private val schemaStatement = Regex("\\bCREATE\\s+(TRIGGER|TABLE|INDEX|UNIQUE\\s+INDEX|VIEW)\\b", RegexOption.IGNORE_CASE)

    /**
     * Every SQL string literal of [sources] that reads one of [expiringTables]. A literal is a
     * `"..."` or `"""..."""` run that names `SELECT` and the table; writes (`DELETE`, `UPDATE`,
     * `INSERT`) are not read paths and are left alone — SWEEP's own `DELETE ... WHERE
     * delete_at_minute <= ?` is the one statement that is *supposed* to name expired rows.
     */
    fun readQueriesOverExpiringRows(sources: List<File>): List<Found> {
        val out = ArrayList<Found>()
        for (file in sources) {
            val text = runCatching { file.readText() }.getOrNull() ?: continue
            if (expiringTables.keys.none { text.contains(it) }) continue
            for (literal in stringLiterals(text)) {
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

    private data class Literal(val line: Int, val text: String)

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
                out += Literal(line, body)
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
                out += Literal(line, body.toString())
                i = j + 1
            }
        }
        return out
    }

    /**
     * Runs [sql] against a database that holds exactly two `dm_message` rows of one conversation,
     * one expired at [now] and one that is not, and reports whether the expired one came back.
     *
     * The query is given `now` for every bind placeholder it carries, which is the shape §10.7
     * point 4 prescribes (`:now_e`); a query that needs other arguments registers them.
     */
    fun showsAnExpiredRow(sql: String, args: List<Any?>): Boolean {
        JdbcSqlExecutor().use { db ->
            MigrationRunner(db).migrate()
            seedOneExpiredAndOneLiveMessage(db)
            var sawExpired = false
            db.query(sql, args) { row ->
                // Every registered query selects the message id first; the lint reads that column
                // and nothing else, so a query may project whatever it needs beside it.
                if (!row.isNull(0) && row.blob(0).contentEquals(EXPIRED_ID)) sawExpired = true
            }
            return sawExpired
        }
    }

    /** The expired row's id, so a lint failure names which row leaked. */
    val EXPIRED_ID: ByteArray = ByteArray(16) { 0xE0.toByte() }
    /** The live row's id: a query that returns nothing at all is not passing, it is broken. */
    val LIVE_ID: ByteArray = ByteArray(16) { 0x11 }
    /** The `now_e` the fixture world is built around. */
    const val NOW: Long = 1_800_000_000L - 1_800_000_000L % 60
    /** The conversation both rows belong to. */
    val CONVERSATION: ByteArray = ByteArray(16) { 0x01 }

    fun seedOneExpiredAndOneLiveMessage(db: SqlExecutor) {
        db.exec(
            "INSERT INTO dm_contact(contact_id, identity_pk, card_env, card_index, trust_state, source, establishment) " +
                "VALUES (?, ?, ?, 0, 'unverified', 'link', 'card_only')",
            listOf(CONVERSATION, ByteArray(32) { 0x01 }, ByteArray(159) { 0x01 }),
        )
        db.exec(
            "INSERT INTO dm_conversation(conversation_id, contact_id) VALUES (?, ?)",
            listOf(CONVERSATION, CONVERSATION),
        )
        // The expired one went one minute ago; the live one goes in an hour.
        for ((id, deleteAt) in listOf(EXPIRED_ID to NOW - 60, LIVE_ID to NOW + 3600)) {
            db.exec(
                "INSERT INTO dm_message(message_id, conversation_id, direction, kind, author_minute, sort_minute, " +
                    "minute_index, timer_code, body_env, state, expire_at_minute, delete_at_minute) " +
                    "VALUES (?, ?, 'out', 1, ?, ?, 0, 4, ?, 'sent', ?, ?)",
                listOf(id, CONVERSATION, NOW - 86_400, NOW - 86_400, ByteArray(100) { id[0] }, deleteAt, deleteAt),
            )
        }
    }
}

/**
 * Every read query of a DM DAO, with the arguments the lint should bind. **Empty until S6/S7**:
 * the DAOs that read `dm_message` land with the owner side and the send/receive slice, and
 * [DmExpiredRowLintTest.everyProductionReadOfAnExpiringTableIsRegistered] fails the day one is
 * written without being registered here. Add the query verbatim — the point of the registry is
 * that the string the DAO runs is the string the lint runs.
 */
object DmDaoQueries {
    data class Query(val name: String, val sql: String, val args: List<Any?>)

    val registered: List<Query> = emptyList()
}
