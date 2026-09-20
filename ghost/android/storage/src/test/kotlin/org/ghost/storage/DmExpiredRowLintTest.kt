package org.ghost.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * The expired-row lint of §10.7 point 4 and §21.14, mutant **ME-16** (slice S5; see
 * [DmExpiredRowLint] for what the two halves are and why both are needed).
 *
 * No DM DAO exists yet — `:messaging` is a manifest and nothing else, `:storage` has no DM
 * repository — so the lint has nothing of its own to check and [DmDaoQueries.registered] is empty.
 * What this class therefore does is **prove the mechanism on fixtures** and **arm it**: the static
 * half is shown to find a query in a source tree shaped like the real one, to ignore the schema
 * statements that read the same table for another purpose, and to report the production tree as
 * empty only because it really is; the behavioural half is shown to fail a query without the
 * filter and pass one with it. The day S6 or S7 writes a DM DAO,
 * [everyProductionReadOfAnExpiringTableIsRegistered] fails until the query is registered, and
 * [everyRegisteredQueryHidesAnExpiredRow] then runs it against an expired row.
 */
class DmExpiredRowLintTest {

    @get:Rule
    val temp = TemporaryFolder()

    private val now = DmExpiredRowLint.NOW

    /** The filter §10.7 point 4 prescribes, and the same query without it. */
    private val filtered =
        "SELECT message_id, body_env FROM dm_message WHERE conversation_id = ? " +
            "AND (delete_at_minute IS NULL OR delete_at_minute > ?) ORDER BY sort_minute"
    private val unfiltered =
        "SELECT message_id, body_env FROM dm_message WHERE conversation_id = ? ORDER BY sort_minute"

    // ------------------------------------------------------------------ the behavioural half

    @Test
    fun theLintFailsAQueryThatIgnoresExpiryAndPassesOneThatDoesNot() {
        assertTrue(
            "a query without the expiry filter must be caught",
            DmExpiredRowLint.showsAnExpiredRow(unfiltered, listOf(DmExpiredRowLint.CONVERSATION)),
        )
        assertFalse(
            "the filter of §10.7 point 4 must hide the expired row",
            DmExpiredRowLint.showsAnExpiredRow(filtered, listOf(DmExpiredRowLint.CONVERSATION, now)),
        )
    }

    /**
     * The near misses, which are the whole reason the behavioural half exists beside the text
     * scan: each of these queries *mentions* `delete_at_minute` and would satisfy any reading of
     * the source, and each still returns the expired row.
     */
    @Test
    fun theLintCatchesAFilterThatIsPresentButWrong() {
        val nearMisses = mapOf(
            "the boundary is exclusive, not inclusive (>= admits the row that expires now)" to
                ("SELECT message_id FROM dm_message WHERE conversation_id = ? " +
                    "AND (delete_at_minute IS NULL OR delete_at_minute >= ?)" to listOf<Any?>(DmExpiredRowLint.CONVERSATION, now - 60)),
            "the filter is on the wrong column (unread_deadline_minute is one of the two sources of the deletion time, not the deletion time)" to
                ("SELECT message_id FROM dm_message WHERE conversation_id = ? " +
                    "AND (unread_deadline_minute IS NULL OR unread_deadline_minute > ?)" to listOf<Any?>(DmExpiredRowLint.CONVERSATION, now)),
            "the filter is ORed with another term instead of ANDed" to
                ("SELECT message_id FROM dm_message WHERE (delete_at_minute IS NULL OR delete_at_minute > ?) " +
                    "OR conversation_id = ?" to listOf<Any?>(now, DmExpiredRowLint.CONVERSATION)),
        )
        for ((why, query) in nearMisses) {
            assertTrue(why, DmExpiredRowLint.showsAnExpiredRow(query.first, query.second))
        }
    }

    /** A query that returns nothing at all is broken, not compliant: the live row must come back. */
    @Test
    fun theFixtureWorldHoldsOneExpiredAndOneLiveRow() = JdbcSqlExecutor().use { db ->
        MigrationRunner(db).migrate()
        DmExpiredRowLint.seedOneExpiredAndOneLiveMessage(db)
        assertEquals(2L, db.queryLong("SELECT count(*) FROM dm_message"))
        val seen = ArrayList<String>()
        db.query(filtered, listOf(DmExpiredRowLint.CONVERSATION, now)) { seen += it.blob(0).joinToString("") { b -> "%02x".format(b) } }
        assertEquals(listOf(DmExpiredRowLint.LIVE_ID.joinToString("") { "%02x".format(it) }), seen)
    }

    @Test
    fun everyRegisteredQueryHidesAnExpiredRow() {
        for (query in DmDaoQueries.registered) {
            assertFalse(
                "${query.name} shows a message whose delete_at_minute has passed (ME-16)",
                DmExpiredRowLint.showsAnExpiredRow(query.sql, query.args),
            )
        }
    }

    // ------------------------------------------------------------------ the static half

    private fun normalize(sql: String) = sql.replace(Regex("\\s+"), " ").trim()

    /**
     * A source tree shaped like the Android one — a `settings.gradle.kts` at the root, a module
     * with `src/main/kotlin` — holding one compliant query and one that is not. Both must be
     * found: the scanner's job is to notice that a read path exists, not to judge it; judging it
     * is the behavioural half's job, and a query it never hears about is never judged.
     */
    private fun fixtureTree(): File {
        val root = temp.newFolder("android")
        File(root, "settings.gradle.kts").writeText("include(\":messaging\")\n")
        val packageDir = File(root, "messaging/src/main/kotlin/org/ghost/messaging")
        packageDir.mkdirs()
        val source = File(packageDir, "DmMessageDao.kt")
        source.writeText(
            """
            package org.ghost.messaging

            class DmMessageDao(private val db: Any) {
                fun visible(conversation: ByteArray, nowE: Long) = query(
                    ""${'"'}SELECT message_id, body_env FROM dm_message
                       WHERE conversation_id = ?
                         AND (delete_at_minute IS NULL OR delete_at_minute > ?)
                       ORDER BY sort_minute""${'"'},
                )

                fun everything(conversation: ByteArray) =
                    query("SELECT message_id FROM dm_message WHERE conversation_id = ?")

                fun sweep(nowE: Long) = exec("DELETE FROM dm_message WHERE delete_at_minute <= ?")

                fun unrelated() = query("SELECT tag FROM dm_seen WHERE until_day > ?")
            }
            """.trimIndent(),
        )
        return root
    }

    @Test
    fun theScannerFindsEveryReadOfAnExpiringTableAndNothingElse() {
        val root = fixtureTree()
        val sources = DmExpiredRowLint.androidProductionSources(File(root, "messaging"))
        assertNotNull("the Android root must be found from inside a module", sources)
        assertEquals(1, sources!!.size)
        val found = DmExpiredRowLint.readQueriesOverExpiringRows(sources).map { normalize(it.sql) }
        assertEquals(
            listOf(
                normalize(
                    "SELECT message_id, body_env FROM dm_message WHERE conversation_id = ? " +
                        "AND (delete_at_minute IS NULL OR delete_at_minute > ?) ORDER BY sort_minute",
                ),
                normalize("SELECT message_id FROM dm_message WHERE conversation_id = ?"),
            ),
            found,
        )
        // The DELETE is SWEEP's own statement and the `dm_seen` read is over a table with no read
        // filter rule: neither is a read path over an expiring table.
        assertTrue(found.none { it.contains("DELETE") || it.contains("dm_seen") })
    }

    /**
     * `Schema.kt`'s REPLACE guard reads `dm_message` inside a `CREATE TRIGGER`. It is not a read
     * path — nothing it returns reaches a screen, and an expiry filter there would let a REPLACE
     * delete an expired row's identity. The scanner must skip it, and this test proves the skip is
     * exercised by the real schema rather than being dead code.
     */
    @Test
    fun theScannerIgnoresSchemaStatements() {
        val guard = Schema.migrations.single { it.version == 5 }.statements
            .single { it.contains("dm_message_no_replace") }
        assertTrue("the guard really does read dm_message", guard.contains("SELECT 1 FROM dm_message"))
        val file = temp.newFile("Schema.kt")
        file.writeText("val statements = listOf(\n    \"\"\"$guard\"\"\",\n)\n")
        assertEquals(emptyList<DmExpiredRowLint.Found>(), DmExpiredRowLint.readQueriesOverExpiringRows(listOf(file)))
    }

    /**
     * The arming assertion. Every read of an expiring table anywhere in the Android production
     * sources must be registered in [DmDaoQueries], and every registered query must still exist in
     * the sources. Today both sides are empty; the day S6 or S7 adds a DM DAO this fails with the
     * file and line of the query, and the fix is to register it — at which point
     * [everyRegisteredQueryHidesAnExpiredRow] runs it against an expired row.
     */
    @Test
    fun everyProductionReadOfAnExpiringTableIsRegistered() {
        val sources = DmExpiredRowLint.androidProductionSources()
        assertNotNull("the Android root was not found; the lint would pass vacuously", sources)
        assertTrue("no production sources were scanned; the lint would pass vacuously", sources!!.size >= 20)
        assertTrue(
            "the scanned tree is not the GHOST one: Schema.kt was not among the sources",
            sources.any { it.name == "Schema.kt" },
        )
        val found = DmExpiredRowLint.readQueriesOverExpiringRows(sources)
        val registered = DmDaoQueries.registered.map { normalize(it.sql) }.toSet()
        val unregistered = found.filter { normalize(it.sql) !in registered }
        assertEquals(
            "a DM read path over an expiring table is not registered with the expired-row lint " +
                "(design §10.7 point 4, §22.10 item 3)",
            emptyList<String>(),
            unregistered.map { it.toString() },
        )
        val stale = registered - found.map { normalize(it.sql) }.toSet()
        assertEquals("a registered query no longer exists in the sources", emptySet<String>(), stale)
    }
}
