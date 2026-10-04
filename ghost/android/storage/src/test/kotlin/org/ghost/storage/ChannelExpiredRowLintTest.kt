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
 * The expired-row lint over the channel tables (Phase 10 design §8.2, §10.1; mutant **ME-16**; slice S3), the
 * twin of [DmExpiredRowLintTest]: the mechanism proved on fixtures — a read without the filter, with it wrong, a
 * count that leaks, a filter that hides too much, a lookup of an expired key — and then **armed** over the
 * production sources, where the channel DAOs of `:messaging` are registered query by query.
 *
 * It lives in `:storage`, which cannot depend on `:messaging`: the registry copies each query verbatim, and
 * [everyProductionReadOfAnExpiringChannelTableIsRegistered] proves the copy against the source in both
 * directions, so a DAO query that is edited, added or removed without its entry fails here with the file and
 * line.
 */
class ChannelExpiredRowLintTest {

    @get:Rule
    val temp = TemporaryFolder()

    private val L = ChannelExpiredRowLint
    private val CH = L.CH
    private val now = L.NOW
    private val today = L.TODAY

    private fun normalize(sql: String) = sql.replace(Regex("\\s+"), " ").trim()

    // ------------------------------------------------------------------ the fixture world

    @Test
    fun theFixtureWorldHoldsTheExpiredAndTheLiveRowsItDescribes() {
        // table -> (rows with the expired ones, rows after the sweep)
        val expected = mapOf(
            "ch_post" to (6L to 3L), "ch_reaction" to (3L to 2L), "ch_reveal" to (4L to 2L),
            "ch_pending_post" to (4L to 2L), "ch_seen" to (3L to 2L), "ch_generation" to (5L to 4L),
            "ch_epoch" to (4L to 3L), "ch_join" to (3L to 2L), "ch_join_request" to (3L to 2L),
            "ch_kp_seen" to (2L to 1L), "ch_invite_issued" to (3L to 2L), "ch_invite_own" to (3L to 2L),
            "ch_request" to (3L to 2L), "mls_global_kv" to (4L to 3L),
        )
        assertEquals(L.expiringTables.keys, expected.keys)
        for ((table, counts) in expected) {
            assertEquals("$table before the sweep", counts.first, L.countIn("SELECT count(*) FROM $table", emptyList(), true))
            assertEquals("$table after the sweep", counts.second, L.countIn("SELECT count(*) FROM $table", emptyList(), false))
        }
        // The boundary row of every minute and hour table is exactly on the deadline, and the day tables' live
        // rows include the last day: the two places a filter's comparison can be one off.
        assertEquals(1L, L.countIn("SELECT count(*) FROM ch_post WHERE delete_at_minute = ?", listOf(now), true))
        assertEquals(1L, L.countIn("SELECT count(*) FROM ch_pending_post WHERE fail_after_hour = ?", listOf(now), true))
        assertEquals(1L, L.countIn("SELECT count(*) FROM ch_join WHERE expiry_day = ?", listOf(today), false))
        assertEquals(1L, L.countIn("SELECT count(*) FROM ch_generation WHERE drain_until_day = ?", listOf(today), false))
    }

    // ------------------------------------------------------------------ the behavioural half, proved on fixtures

    @Test
    fun theLintFailsAReadThatIgnoresExpiryAndPassesOneThatDoesNot() {
        val unfiltered = "SELECT op_id, delete_at_minute FROM ch_post WHERE channel_id = ?"
        assertTrue(L.showsAnExpiredRow(unfiltered, listOf(CH)))
        val filtered = "SELECT op_id, delete_at_minute FROM ch_post WHERE channel_id = ? AND (delete_at_minute IS NULL OR delete_at_minute > ?)"
        val compliant = L.outcomeOf(filtered, listOf(CH, now))
        assertFalse("the filter of §8.2 must hide the expired posts", compliant.showsAnExpiredRow)
        assertFalse("and it must still return the live ones", compliant.returnsNothing)
        assertEquals(3, compliant.afterTheSweep.size)
    }

    /**
     * The near misses: each of these *mentions* an expiry column or returns no post column at all, and still lets
     * an expired row change what the user sees — or hides a live one, which the row count catches.
     */
    @Test
    fun theLintCatchesAFilterThatIsPresentButWrong() {
        val leaks = mapOf(
            "the boundary is inclusive: >= admits the post that expires now (§8.2)" to
                ("SELECT op_id FROM ch_post WHERE channel_id = ? AND (delete_at_minute IS NULL OR delete_at_minute >= ?)" to listOf<Any?>(CH, now)),
            "the filter is on the wrong column (the display time, not the deletion time)" to
                ("SELECT op_id FROM ch_post WHERE channel_id = ? AND (displayed_minute IS NULL OR displayed_minute > ?)" to listOf<Any?>(CH, now)),
            "the filter is ORed with another term instead of ANDed" to
                ("SELECT op_id FROM ch_post WHERE (delete_at_minute IS NULL OR delete_at_minute > ?) OR channel_id = ?" to listOf<Any?>(now, CH)),
            "an unread badge counts expired rows (§10.3: the count is a read like any other)" to
                ("SELECT count(*) FROM ch_post WHERE channel_id = ? AND direction = 'in' AND state = 'unread'" to listOf<Any?>(CH)),
            "the post id is not the first column, so no id-shaped check would see it" to
                ("SELECT body_env, op_id FROM ch_post WHERE channel_id = ?" to listOf<Any?>(CH)),
            "the reactions are read without the post's deadline" to
                ("SELECT target, author FROM ch_reaction WHERE target = ?" to listOf<Any?>(L.id(0xE1))),
            "a pending post is offered at the very hour its deadline is reached" to
                ("SELECT op_id FROM ch_pending_post WHERE channel_id = ? AND fail_after_hour >= ?" to listOf<Any?>(CH, now)),
            "a drained generation is still routed" to
                ("SELECT channel_id, generation FROM ch_generation WHERE namespace_id = ?" to listOf<Any?>(L.key(0xA0))),
            "a day-keyed row is offered the day after its day: > for >= is the wrong way round" to
                ("SELECT kp_ref FROM ch_join WHERE channel_id = ? AND expiry_day >= ?" to listOf<Any?>(CH, today - 1)),
            "a retention bound is not applied to the open-epoch lookup" to
                ("SELECT epoch FROM ch_epoch WHERE channel_id = ?" to listOf<Any?>(CH)),
            "a global row is loaded past its day" to
                ("SELECT k, v_env FROM mls_global_kv WHERE channel_id = ?" to listOf<Any?>(CH)),
        )
        for ((why, query) in leaks) assertTrue(why, L.showsAnExpiredRow(query.first, query.second))
    }

    @Test
    fun theLintCatchesAFilterThatHidesALiveRowByItsRowCount() {
        // No leak: both worlds agree, because the row that expires on its last day is hidden in both. Only the
        // registered row count (the live fixture holds two joins) tells this from the compliant query.
        val tooStrict = L.outcomeOf("SELECT kp_ref FROM ch_join WHERE channel_id = ? AND expiry_day > ?", listOf(CH, today))
        assertFalse(tooStrict.showsAnExpiredRow)
        assertEquals("the last day of a join is a live day", 1, tooStrict.afterTheSweep.size)
        val compliant = L.outcomeOf("SELECT kp_ref FROM ch_join WHERE channel_id = ? AND expiry_day >= ?", listOf(CH, today))
        assertFalse(compliant.showsAnExpiredRow)
        assertEquals(2, compliant.afterTheSweep.size)
    }

    @Test
    fun aQueryThatMatchesNothingIsNotCompliantAndALookupOfAnExpiredKeyIsJudgedByAbsence() {
        val matchesNothing = L.outcomeOf("SELECT op_id FROM ch_post WHERE channel_id = ? AND state = 'degraded'", listOf(CH))
        assertFalse(matchesNothing.showsAnExpiredRow)
        assertTrue("that is only because it matches nothing", matchesNothing.returnsNothing)
        // A lookup by a key that is expired answers nothing in the unswept world when the filter works ...
        val lookup = "SELECT op_id FROM ch_post WHERE op_id = ? AND (delete_at_minute IS NULL OR delete_at_minute > ?)"
        assertTrue(L.outcomeOf(lookup, listOf(L.id(0xE1), now)).beforeTheSweep.isEmpty())
        // ... and answers the expired row when it does not: the one thing a point lookup can leak.
        assertEquals(1, L.outcomeOf("SELECT op_id FROM ch_post WHERE op_id = ?", listOf(L.id(0xE1))).beforeTheSweep.size)
    }

    // ------------------------------------------------------------------ the registries

    @Test
    fun everyRegisteredReadHidesTheExpiredRowsAndShowsExactlyTheLiveOnes() {
        assertTrue(ChannelDaoQueries.registered.size >= 40)
        for (query in ChannelDaoQueries.registered) {
            val outcome = L.outcomeOf(query.sql, query.args)
            when (query.mode) {
                ChannelExpiredRowLint.Mode.READ -> {
                    assertFalse("${query.name} shows a row whose deadline has passed (ME-16)", outcome.showsAnExpiredRow)
                    assertFalse(
                        "${query.name} matches no row of the lint's fixture world, so it was never judged",
                        outcome.returnsNothing,
                    )
                    assertEquals("${query.name} shows the live rows of the fixture, no more and no fewer", query.rows, outcome.afterTheSweep.size)
                }
                ChannelExpiredRowLint.Mode.HIDES -> {
                    assertTrue("${query.name} answers an expired key (ME-16)", outcome.beforeTheSweep.isEmpty())
                    assertTrue("${query.name} answers nothing after the sweep either", outcome.afterTheSweep.isEmpty())
                    val (proof, args) = query.proof!!
                    assertTrue("${query.name}: the unswept world must hold the expired row it hides", L.countIn(proof, args, true) >= 1)
                    assertEquals("${query.name}: and the swept world must not", 0L, L.countIn(proof, args, false))
                }
                else -> error("${query.name} is registered as a read with mode ${query.mode}")
            }
        }
    }

    @Test
    fun everyBoundQuerySeesTheExpiredRowsBecauseTheTriggerCountsThem() {
        assertEquals(5, ChannelBoundQueries.registered.size)
        for (query in ChannelBoundQueries.registered) {
            val outcome = L.outcomeOf(query.sql, query.args)
            assertTrue("${query.name} must count the expired rows too, as the trigger does", outcome.showsAnExpiredRow)
        }
    }

    @Test
    fun everySweepQueryNamesExactlyTheExpiredRows() {
        assertTrue("the sweep registry is empty; SWEEP would not be judged", ChannelSweepQueries.registered.isNotEmpty())
        for (query in ChannelSweepQueries.registered) {
            val outcome = L.outcomeOf(query.sql, query.args)
            assertTrue("${query.name} still returns rows after the sweep, so it names live rows too", outcome.afterTheSweep.isEmpty())
            assertEquals("${query.name} does not name every expired row of the fixture", query.rows, outcome.beforeTheSweep.size)
        }
    }

    @Test
    fun theSweepContractCatchesABoundaryThatIsWrongAndAReadSmuggledIn() {
        // an exclusive boundary misses the post that expires exactly now
        val exclusive = L.outcomeOf("SELECT op_id FROM ch_post WHERE delete_at_minute < ?", listOf(now))
        assertTrue(exclusive.beforeTheSweep.size < 3)
        // a day table swept with <= would take the row on its last day
        val tooWide = L.outcomeOf("SELECT kp_ref FROM ch_join WHERE expiry_day <= ?", listOf(today))
        assertFalse("a sweep that names live rows still finds them after the sweep", tooWide.afterTheSweep.isEmpty())
        // a UI read moved into the sweep registry to escape the read contract names the live rows
        assertFalse(L.outcomeOf("SELECT op_id FROM ch_post", emptyList()).afterTheSweep.isEmpty())
    }

    // ------------------------------------------------------------------ the static half

    /**
     * A source tree shaped like the Android one, holding the channel reads the scanner must find (a read of an
     * expiring table, a join, a read hidden behind a concatenation) and the statements it must leave alone: writes
     * with a subquery, a trigger or an index, a table with no deadline.
     */
    private fun fixtureTree(): File {
        val root = temp.newFolder("android")
        File(root, "settings.gradle.kts").writeText("include(\":features:channels\")\n")
        val packageDir = File(root, "features/channels/src/main/kotlin/org/ghost/channels")
        packageDir.mkdirs()
        File(packageDir, "PostDao.kt").writeText(
            """
            package org.ghost.channels

            class PostDao(private val db: Any) {
                fun visible(channel: ByteArray, nowE: Long) = query(
                    ""${'"'}SELECT op_id, body_env FROM ch_post
                       WHERE channel_id = ? AND (delete_at_minute IS NULL OR delete_at_minute > ?)""${'"'},
                )

                fun everything(channel: ByteArray) = query("SELECT op_id FROM ch_post WHERE channel_id = ?")

                fun reactions(post: ByteArray) =
                    query("SELECT author FROM ch_reaction WHERE target = ?")

                fun joins(channel: ByteArray) = query(
                    "SELECT kp_ref " +
                        "FROM ch_join WHERE channel_id = ?",
                )

                fun insertIfAbsent() = exec("INSERT INTO ch_post(op_id) SELECT ? WHERE NOT EXISTS (SELECT 1 FROM ch_post WHERE op_id = ?)")

                fun sweep(nowE: Long) = exec("DELETE FROM ch_post WHERE op_id IN (SELECT op_id FROM ch_post WHERE delete_at_minute <= ?)")

                fun update() = exec("UPDATE ch_post SET state = 'read' WHERE op_id = ?")

                fun trigger() = exec("CREATE TRIGGER ch_epoch_limit BEFORE INSERT ON ch_epoch WHEN (SELECT count(*) FROM ch_epoch) >= 17 BEGIN SELECT 1; END")

                fun unrelated() = query("SELECT hash FROM ch_candidate WHERE channel_id = ?")

                fun lookalikes() = query("SELECT x FROM ch_post_extra WHERE a = ? UNION SELECT y FROM ch_pending_posts_old")
            }
            """.trimIndent(),
        )
        return root
    }

    @Test
    fun theScannerFindsEveryReadOfAnExpiringChannelTableAndNothingElse() {
        val root = fixtureTree()
        val sources = DmExpiredRowLint.androidProductionSources(File(root, "features/channels"))
        assertNotNull(sources)
        val found = L.readQueriesOverExpiringRows(sources!!).map { normalize(it.sql) }
        assertEquals(
            listOf(
                "SELECT op_id, body_env FROM ch_post WHERE channel_id = ? AND (delete_at_minute IS NULL OR delete_at_minute > ?)",
                "SELECT op_id FROM ch_post WHERE channel_id = ?",
                "SELECT author FROM ch_reaction WHERE target = ?",
                "SELECT kp_ref FROM ch_join WHERE channel_id = ?",
            ),
            found,
        )
    }

    /**
     * The arming assertion. Every read of an expiring channel table anywhere in the Android production sources
     * must be registered in [ChannelDaoQueries], [ChannelBoundQueries] or [ChannelSweepQueries], and every
     * registered query must still exist in the sources.
     */
    @Test
    fun everyProductionReadOfAnExpiringChannelTableIsRegistered() {
        val sources = DmExpiredRowLint.androidProductionSources()
        assertNotNull("the Android root was not found; the lint would pass vacuously", sources)
        assertTrue("only ${sources!!.size} production sources were scanned; the lint would pass vacuously", sources.size >= 100)
        assertTrue(
            "the channel DAOs are not among the scanned sources",
            sources.any { it.name == "PostStore.kt" && it.invariantSeparatorsPath.contains("/channel/store/") },
        )
        val found = L.readQueriesOverExpiringRows(sources)
        assertTrue("the scan found only ${found.size} channel reads; it is not looking at the DAOs", found.size >= 45)
        val registered = (ChannelDaoQueries.registered + ChannelBoundQueries.registered + ChannelSweepQueries.registered)
        val registeredSql = registered.map { normalize(it.sql) }.toSet()
        val unregistered = found.filter { normalize(it.sql) !in registeredSql }
        assertEquals(
            "a read path over an expiring channel table is not registered with the expired-row lint " +
                "(design §8.2, §10.1; register it in ChannelDaoQueries, ChannelBoundQueries or ChannelSweepQueries)",
            emptyList<String>(),
            unregistered.map { it.toString() },
        )
        val stale = registeredSql - found.map { normalize(it.sql) }.toSet()
        assertEquals("a registered query no longer exists in the sources", emptySet<String>(), stale)
        // No two entries share a name; each name tells a reader which query it judges.
        assertEquals(registered.map { it.name }.toSet().size, registered.size)
    }

    /** `Schema.kt` reads these tables inside triggers (the bounds, the guards): a trigger is no read path. */
    @Test
    fun theScannerIgnoresTheSchemasTriggersAndIndexes() {
        val bound = Schema.migrations.single { it.version == 7 }.statements.single { it.contains("CREATE TRIGGER ch_epoch_limit") }
        assertTrue(bound.contains("SELECT count(*) FROM ch_epoch"))
        val guard = Schema.migrations.single { it.version == 7 }.statements.single { it.contains("CREATE TRIGGER ch_post_no_replace") }
        assertTrue(guard.contains("SELECT 1 FROM ch_post"))
        val file = temp.newFile("Schema.kt")
        file.writeText("val statements = listOf(\n    \"\"\"$bound\"\"\",\n    \"\"\"$guard\"\"\",\n)\n")
        assertEquals(emptyList<ChannelExpiredRowLint.Found>(), L.readQueriesOverExpiringRows(listOf(file)))
    }
}
