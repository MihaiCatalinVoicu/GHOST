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
 * half is shown to find a query in a source tree shaped like the real one — including one written
 * in this repo's own concatenated style and one hidden behind a view — to ignore the schema
 * statements that read the same table for another purpose, and to report the production tree as
 * empty only because it really is; the behavioural half is shown to fail a query without the
 * filter, several with a filter that is present but wrong, one that only counts, and one that
 * matches nothing at all. The day S6 or S7 writes a DM DAO,
 * [everyProductionReadOfAnExpiringTableIsRegistered] fails until the query is registered, and
 * [everyRegisteredQueryHidesAnExpiredRow] then runs it against the expired rows.
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
        val compliant = DmExpiredRowLint.outcomeOf(filtered, listOf(DmExpiredRowLint.CONVERSATION, now))
        assertFalse("the filter of §10.7 point 4 must hide the expired rows", compliant.showsAnExpiredRow)
        assertFalse("and it must still return the live ones", compliant.returnsNothing)
    }

    /**
     * The near misses, which are the whole reason the behavioural half exists beside the text
     * scan: each of these queries *mentions* an expiry column, or returns no message column at
     * all, and would satisfy any reading of the source — and each still lets an expired row change
     * what the user sees.
     */
    @Test
    fun theLintCatchesAFilterThatIsPresentButWrong() {
        val conversation = DmExpiredRowLint.CONVERSATION
        val nearMisses = mapOf(
            "the boundary is exclusive, not inclusive (>= admits the row that expires now)" to
                ("SELECT message_id FROM dm_message WHERE conversation_id = ? " +
                    "AND (delete_at_minute IS NULL OR delete_at_minute >= ?)" to listOf<Any?>(conversation, now)),
            "the filter is on the wrong column (unread_deadline_minute is one of the two sources of the deletion time, not the deletion time)" to
                ("SELECT message_id FROM dm_message WHERE conversation_id = ? " +
                    "AND (unread_deadline_minute IS NULL OR unread_deadline_minute > ?)" to listOf<Any?>(conversation, now)),
            "the filter is on expire_at_minute, which is NULL on an incoming message that was never read" to
                ("SELECT message_id FROM dm_message WHERE conversation_id = ? " +
                    "AND (expire_at_minute IS NULL OR expire_at_minute > ?)" to listOf<Any?>(conversation, now)),
            "the filter is ORed with another term instead of ANDed" to
                ("SELECT message_id FROM dm_message WHERE (delete_at_minute IS NULL OR delete_at_minute > ?) " +
                    "OR conversation_id = ?" to listOf<Any?>(now, conversation)),
            "an unread badge counts expired rows (§10.3: the count is a read path like any other)" to
                ("SELECT count(*) FROM dm_message WHERE conversation_id = ? AND state = 'unread'"
                    to listOf<Any?>(conversation)),
            "the message id is not the first column, so no id-shaped check would see it" to
                ("SELECT body_env, message_id FROM dm_message WHERE conversation_id = ?" to listOf<Any?>(conversation)),
        )
        for ((why, query) in nearMisses) {
            assertTrue(why, DmExpiredRowLint.showsAnExpiredRow(query.first, query.second))
        }
    }

    /**
     * A query that returns nothing at all is broken, not compliant — and it is the shape that
     * would otherwise pass for free, because two empty result sets are equal. The inbound read
     * paths §10.3 and C-11 care about are exactly the ones a fixture world of outgoing rows would
     * miss, so the world carries a live row in each direction.
     */
    @Test
    fun aQueryThatMatchesNothingIsNotCompliant() {
        val matchesNothing = DmExpiredRowLint.outcomeOf(
            "SELECT message_id FROM dm_message WHERE conversation_id = ? AND direction = 'in' AND state = 'displayed'",
            listOf(DmExpiredRowLint.CONVERSATION),
        )
        assertFalse("the query cannot tell the two worlds apart", matchesNothing.showsAnExpiredRow)
        assertTrue("and that is only because it matches nothing", matchesNothing.returnsNothing)
        // An inbound read path that does match is accepted, so the guard is not a blanket refusal.
        val inbound = DmExpiredRowLint.outcomeOf(
            "SELECT message_id FROM dm_message WHERE conversation_id = ? AND direction = 'in' " +
                "AND (delete_at_minute IS NULL OR delete_at_minute > ?)",
            listOf(DmExpiredRowLint.CONVERSATION, now),
        )
        assertFalse(inbound.showsAnExpiredRow)
        assertFalse(inbound.returnsNothing)
    }

    /** The fixture world really holds what the table in [DmExpiredRowLint] describes. */
    @Test
    fun theFixtureWorldHoldsThreeExpiredAndTwoLiveRows() = JdbcSqlExecutor().use { db ->
        MigrationRunner(db).migrate()
        DmExpiredRowLint.seedMessages(db, withExpired = true)
        assertEquals(5L, db.queryLong("SELECT count(*) FROM dm_message"))
        assertEquals(3L, db.queryLong("SELECT count(*) FROM dm_message WHERE delete_at_minute <= ?", listOf(now)))
        // Both directions are represented on both sides of the sweep, so no read path is excused.
        assertEquals(
            listOf("in", "in", "out"),
            column(db, "SELECT direction FROM dm_message WHERE delete_at_minute <= ? ORDER BY direction", now),
        )
        assertEquals(
            listOf("in", "out"),
            column(db, "SELECT direction FROM dm_message WHERE delete_at_minute > ? ORDER BY direction", now),
        )
        val seen = ArrayList<String>()
        db.query(filtered, listOf(DmExpiredRowLint.CONVERSATION, now)) { seen += hexOf(it.blob(0)) }
        assertEquals(DmExpiredRowLint.liveIds.map { hexOf(it) }.sorted(), seen.sorted())
    }

    private fun hexOf(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it) }

    private fun column(db: JdbcSqlExecutor, sql: String, arg: Long): List<String> {
        val out = ArrayList<String>()
        db.query(sql, listOf(arg)) { out += it.string(0) }
        return out
    }

    @Test
    fun everyRegisteredQueryHidesAnExpiredRow() {
        for (query in DmDaoQueries.registered) {
            val outcome = DmExpiredRowLint.outcomeOf(query.sql, query.args)
            assertFalse(
                "${query.name} shows a message whose delete_at_minute has passed (ME-16)",
                outcome.showsAnExpiredRow,
            )
            assertFalse(
                "${query.name} matches no row of the lint's fixture world, so it was never judged; " +
                    "widen the world in DmExpiredRowLint.fixtures or register arguments that match one",
                outcome.returnsNothing,
            )
        }
    }

    // ------------------------------------------------------------------ the static half

    private fun normalize(sql: String) = sql.replace(Regex("\\s+"), " ").trim()

    /**
     * A source tree shaped like the Android one — a `settings.gradle.kts` at the root, a module
     * with `src/main/kotlin` — holding four read paths: one compliant raw-string query, one that
     * is not, one written in this repo's concatenated style (the `SELECT` list and the `FROM`
     * clause in different literals, as `OutboxStore` and `DirectoryStore` write them), and a view.
     * All must be found: the scanner's job is to notice that a read path exists, not to judge it;
     * judging it is the behavioural half's job, and a query it never hears about is never judged.
     *
     * The module sits two directories below the root, so a nested Gradle module is covered too.
     */
    private fun fixtureTree(): File {
        val root = temp.newFolder("android")
        File(root, "settings.gradle.kts").writeText("include(\":features:messaging\")\n")
        val packageDir = File(root, "features/messaging/src/main/kotlin/org/ghost/messaging")
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

                fun unread(conversation: ByteArray) = query(
                    "SELECT m.message_id, m.body_env " +
                        "FROM dm_message m JOIN dm_conversation c ON c.conversation_id = m.conversation_id " +
                        "WHERE m.state = 'unread'",
                )

                fun view() = exec("CREATE VIEW dm_visible AS SELECT message_id FROM dm_message")

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
        val sources = DmExpiredRowLint.androidProductionSources(File(root, "features/messaging"))
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
                // The concatenated one is reported as the string the literals build, which is the
                // string a DAO registers verbatim and the lint then runs.
                normalize(
                    "SELECT m.message_id, m.body_env FROM dm_message m " +
                        "JOIN dm_conversation c ON c.conversation_id = m.conversation_id WHERE m.state = 'unread'",
                ),
                // A view over an expiring table is a read path: a DAO selecting from `dm_visible`
                // would name no expiring table at all, so the view is where the lint must catch it.
                normalize("CREATE VIEW dm_visible AS SELECT message_id FROM dm_message"),
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
     * [everyRegisteredQueryHidesAnExpiredRow] runs it against the expired rows.
     */
    @Test
    fun everyProductionReadOfAnExpiringTableIsRegistered() {
        val sources = DmExpiredRowLint.androidProductionSources()
        assertNotNull("the Android root was not found; the lint would pass vacuously", sources)
        // The floor is a real count, not a token one: the Android production tree holds well over
        // a hundred sources today, so a scan that collapsed to one module would fail here.
        assertTrue(
            "only ${sources!!.size} production sources were scanned; the lint would pass vacuously",
            sources.size >= 100,
        )
        assertTrue(
            "the scanned tree is not the GHOST one: Schema.kt was not among the sources",
            sources.any { it.name == "Schema.kt" },
        )
        val found = DmExpiredRowLint.readQueriesOverExpiringRows(sources)
        val registered = (DmDaoQueries.registered + DmSweepQueries.registered)
            .map { normalize(it.sql) }.toSet()
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

    // ------------------------------------------------------------------ the sweep half (S9)

    /**
     * The mirror contract of [everyRegisteredQueryHidesAnExpiredRow], for the queries SWEEP runs
     * to find what it deletes (§10.6, [DmSweepQueries]).
     *
     * A sweep query must name **exactly** the expired rows: something in the world that still holds
     * them, nothing at all in the world after they are gone. A UI read moved into this registry to
     * escape the read contract would return the live rows in the swept world and fail here, and a
     * sweep query whose boundary is wrong — `<` for `<=`, or a filter on `expire_at_minute`, which
     * is NULL on an incoming message that was never read — would miss a fixture row and fail the
     * first half.
     */
    @Test
    fun everyRegisteredSweepQueryNamesExactlyTheExpiredRows() {
        assertTrue("the sweep registry is empty; SWEEP would not be judged", DmSweepQueries.registered.isNotEmpty())
        for (query in DmSweepQueries.registered) {
            val outcome = DmExpiredRowLint.outcomeOf(query.sql, query.args)
            assertTrue(
                "${query.name} still returns rows after the sweep, so it names live messages too",
                outcome.namesOnlyExpiredRows,
            )
            assertEquals(
                "${query.name} does not name every expired row of the fixture world",
                DmExpiredRowLint.expiredIds.size,
                outcome.beforeTheSweep.size,
            )
        }
    }

    /**
     * The near misses of a sweep query, which the mirror contract must catch for the same reason
     * the read contract catches its own: each of these *mentions* the right idea and still leaves a
     * message on the device after the minute the user was promised it would go — or takes one that
     * is still alive.
     */
    @Test
    fun theSweepContractCatchesABoundaryThatIsWrong() {
        val incomplete = mapOf(
            "the boundary is exclusive, so the row that expires exactly now is never deleted" to
                ("SELECT message_id FROM dm_message WHERE delete_at_minute < ?" to listOf<Any?>(now)),
            "the filter is on expire_at_minute, which is NULL on an unread incoming message" to
                ("SELECT message_id FROM dm_message WHERE expire_at_minute <= ?" to listOf<Any?>(now)),
            "the filter is on unread_deadline_minute, which a displayed message may outlive" to
                ("SELECT message_id FROM dm_message WHERE unread_deadline_minute <= ?" to listOf<Any?>(now)),
        )
        for ((why, query) in incomplete) {
            val outcome = DmExpiredRowLint.outcomeOf(query.first, query.second)
            assertTrue(why, outcome.beforeTheSweep.size < DmExpiredRowLint.expiredIds.size)
        }
        // And the other half: a read smuggled into the sweep registry to escape the read contract
        // names live rows, which the swept world shows at once.
        val tooWide = DmExpiredRowLint.outcomeOf("SELECT message_id FROM dm_message", emptyList())
        assertFalse(
            "a query with no expiry condition at all names every live message",
            tooWide.namesOnlyExpiredRows,
        )
    }

    /**
     * A write is not a read path, whatever it contains further in — which is what the scanner's own
     * KDoc has always said and what it only did for writes with no subquery until S9.
     *
     * SWEEP's batched delete needs the subquery form, because SQLite's `DELETE` takes no `LIMIT`
     * unless it was built with `SQLITE_ENABLE_UPDATE_DELETE_LIMIT` and Android's is not. The
     * anchoring matters in the other direction too: a `SELECT` that merely names the
     * `delete_at_minute` column is still a read.
     */
    @Test
    fun theScannerSkipsAWriteWithASubqueryAndNothingElse() {
        val file = temp.newFile("Sweeper.kt")
        file.writeText(
            """
            val batched = "DELETE FROM dm_message WHERE message_id IN " +
                "(SELECT message_id FROM dm_message WHERE delete_at_minute <= ? LIMIT 500)"
            val plain = "DELETE FROM dm_message WHERE delete_at_minute <= ?"
            val update = "UPDATE dm_message SET state = 'read' WHERE message_id = ?"
            val stillARead = "SELECT message_id FROM dm_message WHERE delete_at_minute > ?"
            """.trimIndent(),
        )
        assertEquals(
            listOf("SELECT message_id FROM dm_message WHERE delete_at_minute > ?"),
            DmExpiredRowLint.readQueriesOverExpiringRows(listOf(file)).map { normalize(it.sql) },
        )
    }
}
