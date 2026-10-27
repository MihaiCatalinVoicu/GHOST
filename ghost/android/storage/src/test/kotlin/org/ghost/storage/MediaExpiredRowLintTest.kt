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
 * The expired-row lint over the media tables (Phase 11 design §13.6, §10.7 point 4; mutant **ME-16**; slice S3), the twin of
 * [DmExpiredRowLintTest] and [ChannelExpiredRowLintTest]: the mechanism proved on fixtures — a read without the filter, with it
 * wrong, a deadline the maintenance has not applied yet, a count that leaks, a collector that takes a live blob — and then
 * **armed** over the production sources, where the DAOs of `:media` are registered query by query.
 *
 * It lives in `:storage`, which cannot depend on `:media`: the registry copies each query verbatim ([MediaQueryTexts]), and
 * [everyProductionReadOfAnExpiringMediaTableIsRegistered] proves the copy against the source in both directions, so a DAO query
 * that is edited, added or removed without its entry fails here with the file and line.
 */
class MediaExpiredRowLintTest {

    @get:Rule
    val temp = TemporaryFolder()

    private val L = MediaExpiredRowLint
    private val now = L.NOW
    private val today = L.TODAY

    private fun normalize(sql: String) = sql.replace(Regex("\\s+"), " ").trim()

    // ------------------------------------------------------------------ the fixture world

    @Test
    fun theFixtureWorldHoldsTheExpiredAndTheLiveRowsItDescribes() {
        // table -> (rows with the expired ones, rows after the sweep)
        val expected = mapOf(
            "media_object" to (14L to 10L), "media_upload" to (7L to 4L), "media_blob" to (21L to 15L),
            "media_fragment" to (21L to 13L), "media_outbound_op" to (3L to 2L), "dm_message" to (13L to 9L),
        )
        for ((table, counts) in expected) {
            assertEquals("$table before the sweep", counts.first, L.countIn("SELECT count(*) FROM $table", emptyList(), true))
            assertEquals("$table after the sweep", counts.second, L.countIn("SELECT count(*) FROM $table", emptyList(), false))
        }
        assertEquals(L.expiringTables.keys, MediaSchema.tables)
        // the boundaries: a message that expires exactly now, a download whose hour is exactly now, an upload whose deadline is
        // exactly now, a pooled blob on its last day — the four places a filter's comparison can be one off
        assertEquals(1L, L.countIn("SELECT count(*) FROM dm_message WHERE delete_at_minute = ?", listOf(now), true))
        assertEquals(1L, L.countIn("SELECT count(*) FROM media_object WHERE incomplete_after_hour = ? AND role = 'in'", listOf(now), true))
        assertEquals(1L, L.countIn("SELECT count(*) FROM media_upload WHERE deadline_hour = ?", listOf(now), true))
        assertEquals(1L, L.countIn("SELECT count(*) FROM media_blob WHERE retain_until_day = ?", listOf(today), false))
        // the maintenance changes three objects in place, and the swept world is what it leaves
        assertEquals(2L, L.countIn("SELECT count(*) FROM media_object WHERE state = 'uploading' AND object_id IN (?, ?)", listOf(L.O2, L.O6), true))
        assertEquals(0L, L.countIn("SELECT count(*) FROM media_object WHERE state = 'uploading' AND object_id IN (?, ?)", listOf(L.O2, L.O6), false))
        assertEquals(2L, L.countIn("SELECT count(*) FROM media_object WHERE state = 'incomplete'", emptyList(), false))
        assertEquals(0L, L.countIn("SELECT count(*) FROM media_object WHERE state = 'incomplete'", emptyList(), true))
        // a blob past its day that a live object names is in both worlds, and is not pooled in either
        assertEquals(1L, L.countIn("SELECT count(*) FROM media_blob WHERE blob_hash = ? AND retain_until_day < ?", listOf(L.hash(0x41), today), false))
        // the blob a dead and a live object share survives the sweep
        assertEquals(1L, L.countIn("SELECT count(*) FROM media_blob WHERE blob_hash = ?", listOf(L.hash(0x21)), false))
    }

    // ------------------------------------------------------------------ the behavioural half, proved on fixtures

    private val liveFilter = "(m.message_id IS NULL OR m.delete_at_minute IS NULL OR m.delete_at_minute > ?)"
    private val joinMessage = "FROM media_object o LEFT JOIN dm_message m ON m.message_id = o.message_id"

    @Test
    fun theLintFailsAReadThatIgnoresExpiryAndPassesOneThatDoesNot() {
        val unfiltered = "SELECT o.object_id FROM media_object o WHERE o.object_id = ?"
        assertTrue(L.showsAnExpiredRow(unfiltered, listOf(L.O4)))
        val filtered = "SELECT o.object_id $joinMessage WHERE o.object_id = ? AND $liveFilter"
        // the live object answers the same in both worlds ...
        val compliant = L.outcomeOf(filtered, listOf(L.O1, now))
        assertFalse(compliant.showsAnExpiredRow)
        assertFalse(compliant.returnsNothing)
        // ... and the expired one answers nothing in the unswept world too
        assertTrue(L.outcomeOf(filtered, listOf(L.O4, now)).beforeTheSweep.isEmpty())
    }

    /**
     * The near misses: each of these *mentions* an expiry column or returns no id at all, and still lets an expired row, or a
     * deadline the maintenance has not applied yet, change what the reader sees.
     */
    @Test
    fun theLintCatchesAFilterThatIsPresentButWrongOrAMissingDeadline() {
        val leaks = mapOf(
            "the boundary is inclusive: >= admits the object whose message expires now" to
                ("SELECT o.object_id $joinMessage WHERE o.object_id = ? AND (m.message_id IS NULL OR m.delete_at_minute IS NULL OR m.delete_at_minute >= ?)" to listOf<Any?>(L.O4, now)),
            "the filter is on the wrong column (the unread deadline, NULL on an outgoing message)" to
                ("SELECT o.object_id $joinMessage WHERE o.object_id = ? AND (m.message_id IS NULL OR m.unread_deadline_minute IS NULL OR m.unread_deadline_minute > ?)" to listOf<Any?>(L.O4, now)),
            "the filter is ORed with another term instead of ANDed" to
                ("SELECT o.object_id $joinMessage WHERE ((m.message_id IS NULL OR m.delete_at_minute IS NULL OR m.delete_at_minute > ?)) OR o.object_id = ?" to listOf<Any?>(now, L.O4)),
            "the message is not looked at at all (the reader of the display path)" to
                ("SELECT o.state FROM media_object o WHERE o.message_id = ?" to listOf<Any?>(L.M_E1)),
            "the state is read as stored: a download past its deadline still says fetching (§7.5: declared loss)" to
                ("SELECT o.state $joinMessage WHERE o.object_id = ? AND $liveFilter" to listOf<Any?>(L.I3, now)),
            "the key is read as stored: a download past its deadline still hands out its key" to
                ("SELECT o.key_env $joinMessage WHERE o.object_id = ? AND $liveFilter" to listOf<Any?>(L.I3, now)),
            "the state is read as stored: an upload past its deadline still says uploading (§6.4)" to
                ("SELECT o.state $joinMessage WHERE o.object_id = ? AND $liveFilter" to listOf<Any?>(L.O2, now)),
            "the fragments of a download past its deadline are listed" to
                ("SELECT f.ordinal FROM media_fragment f JOIN media_object o ON o.object_id = f.object_id WHERE f.object_id = ?" to listOf<Any?>(L.I3)),
            "the fragments of an object of an expired message are listed" to
                ("SELECT f.ordinal FROM media_fragment f WHERE f.object_id = ?" to listOf<Any?>(L.O4)),
            "the operation of an expired upload is found" to
                ("SELECT p.ordinal FROM media_outbound_op p WHERE p.operation_id = ?" to listOf<Any?>(L.id(0x31))),
            "an upload row of an expired object is read" to
                ("SELECT u.ttl_seconds FROM media_upload u WHERE u.object_id = ?" to listOf<Any?>(L.O4)),
            "the active uploads include the one whose deadline is exactly now (>= for >)" to
                ("SELECT o.object_id FROM media_object o JOIN media_upload u ON u.object_id = o.object_id WHERE o.state = 'uploading' AND u.deadline_hour >= ?" to listOf<Any?>(now)),
            "the active uploads do not look at the message" to
                ("SELECT o.object_id FROM media_object o JOIN media_upload u ON u.object_id = o.object_id WHERE o.state = 'uploading' AND u.deadline_hour > ?" to listOf<Any?>(now)),
            "the pending downloads include the one whose hour is exactly now (>= for >)" to
                ("SELECT o.object_id FROM media_object o WHERE o.state IN ('awaiting', 'fetching') AND o.incomplete_after_hour >= ?" to listOf<Any?>(now)),
            "the pending downloads do not look at the hour at all" to
                ("SELECT o.object_id $joinMessage WHERE o.state IN ('awaiting', 'fetching') AND $liveFilter" to listOf<Any?>(now)),
            "a count of the fragments of a dead object leaks it (a count is a read like any other)" to
                ("SELECT count(*) FROM media_fragment WHERE object_id = ?" to listOf<Any?>(L.O4)),
            "the files of a download are listed with no deadline" to
                ("SELECT f.ordinal, b.file_name FROM media_fragment f JOIN media_blob b ON b.blob_hash = f.blob_hash WHERE f.object_id = ? AND f.state = 'bound'" to listOf<Any?>(L.I3)),
        )
        for ((why, query) in leaks) assertTrue(why, L.showsAnExpiredRow(query.first, query.second))
    }

    @Test
    fun theLintCatchesAFilterThatHidesALiveRowByItsRowCount() {
        // No leak: both worlds agree, because the pending download whose hour is exactly now is hidden in both. Only the
        // registered row count (the live fixture holds one pending download, and the one on the hour is declared incomplete)
        // tells this from a query that hides the live one too.
        val tooStrict = L.outcomeOf("SELECT o.object_id FROM media_object o WHERE o.state IN ('awaiting', 'fetching') AND o.incomplete_after_hour > ?", listOf(now + 7_200L))
        assertFalse("it leaks nothing, so the leak check alone would pass it", tooStrict.showsAnExpiredRow)
        assertTrue("... because it also hides the live download, which only the registered row count can see", tooStrict.returnsNothing)
        val compliant = L.outcomeOf(MediaQueryTexts.OBJECTS_PENDING_DOWNLOADS, listOf(now, now, 50L))
        assertFalse(compliant.showsAnExpiredRow)
        assertEquals(1, compliant.afterTheSweep.size)
    }

    @Test
    fun aQueryThatMatchesNothingIsNotCompliantAndALookupOfAnExpiredKeyIsJudgedByAbsence() {
        val matchesNothing = L.outcomeOf("SELECT o.object_id FROM media_object o WHERE o.state = 'undecodable'", emptyList())
        assertFalse(matchesNothing.showsAnExpiredRow)
        assertTrue("that is only because it matches nothing", matchesNothing.returnsNothing)
        // a lookup by a key that is expired answers nothing in the unswept world when the filter works ...
        assertTrue(L.outcomeOf(MediaQueryTexts.OBJECTS_BY_ID, listOf(now, now, now, L.O4, now)).beforeTheSweep.isEmpty())
        // ... and answers the expired row when it does not: the one thing a point lookup can leak
        assertEquals(1, L.outcomeOf("SELECT o.object_id FROM media_object o WHERE o.object_id = ?", listOf(L.O4)).beforeTheSweep.size)
    }

    // ------------------------------------------------------------------ the registries

    @Test
    fun everyRegisteredReadHidesTheExpiredRowsAndShowsExactlyTheLiveOnes() {
        assertTrue(MediaDaoQueries.registered.size >= 40)
        for (query in MediaDaoQueries.registered) {
            val outcome = L.outcomeOf(query.sql, query.args)
            when (query.mode) {
                MediaExpiredRowLint.Mode.READ -> {
                    assertFalse("${query.name} shows a row whose deadline has passed (ME-16)", outcome.showsAnExpiredRow)
                    assertFalse("${query.name} matches no row of the lint's fixture world, so it was never judged", outcome.returnsNothing)
                    assertEquals("${query.name} shows the live rows of the fixture, no more and no fewer", query.rows, outcome.afterTheSweep.size)
                }
                MediaExpiredRowLint.Mode.HIDES -> {
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
    fun everyBoundQuerySeesTheExpiredRowsBecauseTheTriggerAndTheReconcileCountThem() {
        assertEquals(27, MediaBoundQueries.registered.size)
        for (query in MediaBoundQueries.registered) {
            val outcome = L.outcomeOf(query.sql, query.args)
            assertTrue("${query.name} must see the expired rows too, as the trigger and the reconcile do", outcome.showsAnExpiredRow)
        }
    }

    @Test
    fun everySweepQueryNamesExactlyTheExpiredRows() {
        assertEquals(4, MediaSweepQueries.registered.size)
        for (query in MediaSweepQueries.registered) {
            val outcome = L.outcomeOf(query.sql, query.args)
            assertTrue("${query.name} still returns rows after the sweep, so it names live rows too", outcome.afterTheSweep.isEmpty())
            assertEquals("${query.name} does not name every expired row of the fixture", query.rows, outcome.beforeTheSweep.size)
        }
    }

    @Test
    fun theSweepContractCatchesABoundaryThatIsWrongAndASelectThatTakesALiveBlob() {
        // an exclusive boundary misses the download whose hour is exactly now
        val exclusive = L.outcomeOf("SELECT o.object_id FROM media_object o WHERE o.state IN ('awaiting', 'fetching') AND o.incomplete_after_hour < ?", listOf(now))
        assertEquals("only the one an hour ago", 1, exclusive.beforeTheSweep.size)
        // a collector with <= takes the pooled blob on its last day
        val tooWide = L.outcomeOf("SELECT b.blob_hash FROM media_blob b WHERE b.origin = 'ingested' AND b.retain_until_day <= ? AND NOT EXISTS (SELECT 1 FROM media_fragment f WHERE f.blob_hash = b.blob_hash)", listOf(today))
        assertFalse("a sweep that names live rows still finds them after the sweep", tooWide.afterTheSweep.isEmpty())
        // a collector that forgets that a live object names the blob takes I4's blobs, which are past their day
        val forgetsNames = L.outcomeOf("SELECT b.blob_hash FROM media_blob b WHERE b.origin = 'ingested' AND b.retain_until_day < ?", listOf(today))
        assertFalse(forgetsNames.afterTheSweep.isEmpty())
        // a read smuggled into the sweep registry to escape the read contract names the live rows
        assertFalse(L.outcomeOf("SELECT o.object_id FROM media_object o", emptyList()).afterTheSweep.isEmpty())
    }

    // ------------------------------------------------------------------ the static half

    /**
     * A source tree shaped like the Android one, holding the media reads the scanner must find (a read of an expiring table, a
     * join, a read hidden behind a concatenation) and the statements it must leave alone: writes with a subquery, a trigger or an
     * index, a table with no deadline.
     */
    private fun fixtureTree(): File {
        val root = temp.newFolder("android")
        File(root, "settings.gradle.kts").writeText("include(\":features:media\")\n")
        val packageDir = File(root, "features/media/src/main/kotlin/org/ghost/features")
        packageDir.mkdirs()
        File(packageDir, "ObjectDao.kt").writeText(
            """
            package org.ghost.features

            class ObjectDao(private val db: Any) {
                fun visible(id: ByteArray, nowE: Long) = query(
                    ""${'"'}SELECT o.state FROM media_object o LEFT JOIN dm_message m ON m.message_id = o.message_id
                       WHERE o.object_id = ? AND (m.delete_at_minute IS NULL OR m.delete_at_minute > ?)""${'"'},
                )

                fun everything(id: ByteArray) = query("SELECT state FROM media_object WHERE object_id = ?")

                fun fragments(id: ByteArray) =
                    query("SELECT ordinal FROM media_fragment WHERE object_id = ?")

                fun joined() = query(
                    "SELECT f.ordinal " +
                        "FROM media_fragment f JOIN media_blob b ON b.blob_hash = f.blob_hash",
                )

                fun shouting() = query("SELECT state FROM MEDIA_OBJECT WHERE object_id = ?")

                fun commented() = query(
                    "SELECT file_name " + // the column
                        /* and the table */ "FROM media_blob WHERE blob_hash = ?",
                )

                fun insertIfAbsent() = exec("INSERT INTO media_blob(blob_hash) SELECT ? WHERE NOT EXISTS (SELECT 1 FROM media_blob WHERE blob_hash = ?)")

                fun sweep() = exec("DELETE FROM media_object WHERE object_id IN (SELECT object_id FROM media_object WHERE state = 'viewed')")

                fun update() = exec("UPDATE media_object SET state = 'verified' WHERE object_id = ?")

                fun trigger() = exec("CREATE TRIGGER media_blob_referenced BEFORE DELETE ON media_blob WHEN EXISTS (SELECT 1 FROM media_fragment WHERE blob_hash = OLD.blob_hash) BEGIN SELECT 1; END")

                fun unrelated() = query("SELECT tag FROM dm_seen WHERE until_day > ?")

                fun lookalikes() = query("SELECT x FROM media_object_extra WHERE a = ? UNION SELECT y FROM media_blobs")
            }
            """.trimIndent(),
        )
        // The shapes the first version of the scan let through (review of slice S3): the table name from a template, from a
        // constant joined with `+` (in the middle, at the end, at the start), and a write that returns rows with RETURNING;
        // then the decoys that must stay unreported and the table positions nobody can resolve, which must be reported.
        File(packageDir, "Templated.kt").writeText(
            """
            package org.ghost.features

            class Templated(private val db: Any) {
                private companion object {
                    const val OBJECTS = "media_object"
                    const val BLOBS = "media_blob"
                    const val LEAD = "SELECT file_name FROM "
                    const val SERVING = "(SELECT x FROM relay_capability UNION ALL SELECT y FROM relay_register_capability)"
                }

                fun fromATemplate() = query("SELECT state FROM ${'$'}OBJECTS WHERE object_id = ?")

                fun fromABracedTemplate() = query("SELECT state FROM ${'$'}{OBJECTS} WHERE object_id = ?")

                fun fromAConstantJoinedWithPlus() = query("SELECT state FROM " + OBJECTS + " WHERE object_id = ?")

                fun fromATrailingConstant() = query("SELECT file_name FROM " + BLOBS)

                fun fromALeadingConstant() = query(LEAD + "media_blob WHERE blob_hash = ?")

                fun updateReturning() = query("UPDATE media_object SET state = 'viewing' WHERE object_id = ? RETURNING key_env")

                fun deleteReturning() = query("DELETE FROM media_blob WHERE blob_hash = ? RETURNING file_name")

                fun aTableNobodyCanResolve(table: String) = query("SELECT x FROM " + table + " WHERE y = ?")

                fun aTemplateNobodyCanResolve(table: String) = query("SELECT x FROM ${'$'}table WHERE y = ?")

                fun aDerivedTableOfOtherTables() = query("SELECT a FROM ${'$'}SERVING c WHERE c.id = ?")

                fun aWriteThatReturnsNothing() = exec("UPDATE media_object SET state = 'viewing' WHERE object_id = ?")

                fun theTemplateIsInTheListNotTheTable(n: Int) = query("SELECT state FROM media_object WHERE object_id IN (${'$'}{marks(n)})")
            }
            """.trimIndent(),
        )
        return root
    }

    private val objectDaoReads = listOf(
        "SELECT o.state FROM media_object o LEFT JOIN dm_message m ON m.message_id = o.message_id WHERE o.object_id = ? AND (m.delete_at_minute IS NULL OR m.delete_at_minute > ?)",
        "SELECT state FROM media_object WHERE object_id = ?",
        "SELECT ordinal FROM media_fragment WHERE object_id = ?",
        "SELECT f.ordinal FROM media_fragment f JOIN media_blob b ON b.blob_hash = f.blob_hash",
        "SELECT state FROM MEDIA_OBJECT WHERE object_id = ?",
        "SELECT file_name FROM media_blob WHERE blob_hash = ?",
    )

    @Test
    fun theScannerFindsEveryReadOfAnExpiringMediaTableAndNothingElse() {
        val root = fixtureTree()
        val sources = DmExpiredRowLint.androidProductionSources(File(root, "features/media"))
        assertNotNull(sources)
        val found = L.readQueriesOverExpiringRows(sources!!).map { normalize(it.sql) }
        assertEquals(
            objectDaoReads + listOf(
                // the table from a template, braced, joined with `+` in the middle, at the end and at the start
                "SELECT state FROM media_object WHERE object_id = ?",
                "SELECT state FROM media_object WHERE object_id = ?",
                "SELECT state FROM media_object WHERE object_id = ?",
                "SELECT file_name FROM media_blob",
                "SELECT file_name FROM media_blob WHERE blob_hash = ?",
                // a write that answers rows is a read
                "UPDATE media_object SET state = 'viewing' WHERE object_id = ? RETURNING key_env",
                "DELETE FROM media_blob WHERE blob_hash = ? RETURNING file_name",
                // a table position nobody can resolve is reported: the DAO must spell the table out
                "SELECT x FROM",
                "SELECT x FROM ${'$'}table WHERE y = ?",
                // (a derived table of other tables, `$SERVING`, and a write that returns nothing are not reads of a media table)
                "SELECT state FROM media_object WHERE object_id IN (${'$'}{marks(n)})",
            ),
            found,
        )
    }

    /** The strict mode only adds: the DM and channel lints call the default mode, and see exactly what they saw before. */
    @Test
    fun theDefaultScanIsTheOldOneAndTheStrictScanFindsEverythingItFindsAndMore() {
        val root = fixtureTree()
        val sources = DmExpiredRowLint.androidProductionSources(File(root, "features/media"))!!
        val lenient = DmExpiredRowLint.readQueriesOverExpiringRows(sources, L.expiringTables.keys).map { normalize(it.sql) }
        val strict = L.readQueriesOverExpiringRows(sources).map { normalize(it.sql) }
        // the hole of the old scan: of the nine new shapes it sees only the one that spells the table out
        assertEquals(objectDaoReads + "SELECT state FROM media_object WHERE object_id IN (${'$'}{marks(n)})", lenient)
        assertTrue(strict.containsAll(lenient))
        assertEquals(strict.size, lenient.size + 9)
    }

    /**
     * The arming assertion. Every read of an expiring media table anywhere in the Android production sources must be
     * registered in [MediaDaoQueries], [MediaBoundQueries] or [MediaSweepQueries], and every registered query must still exist
     * in the sources.
     */
    @Test
    fun everyProductionReadOfAnExpiringMediaTableIsRegistered() {
        val sources = DmExpiredRowLint.androidProductionSources()
        assertNotNull("the Android root was not found; the lint would pass vacuously", sources)
        assertTrue("only ${sources!!.size} production sources were scanned; the lint would pass vacuously", sources.size >= 100)
        assertTrue(
            "the media DAOs are not among the scanned sources",
            listOf("MediaObjects.kt", "MediaFragments.kt", "MediaBlobs.kt").all { name ->
                sources.any { it.name == name && it.invariantSeparatorsPath.contains("/media/store/") }
            },
        )
        val found = L.readQueriesOverExpiringRows(sources)
        assertTrue("the scan found only ${found.size} media reads; it is not looking at the DAOs", found.size >= 38)
        val registered = L.allRegistered()
        val registeredSql = registered.map { normalize(it.sql) }.toSet()
        val unregistered = found.filter { normalize(it.sql) !in registeredSql }
        assertEquals(
            "a read path over an expiring media table is not registered with the expired-row lint " +
                "(design §13.6, §10.7 point 4; register it in MediaDaoQueries, MediaBoundQueries or MediaSweepQueries)",
            emptyList<String>(),
            unregistered.map { it.toString() },
        )
        val foundSql = found.map { normalize(it.sql) }.toSet()
        assertEquals("a registered query no longer exists in the sources", emptySet<String>(), registeredSql - foundSql)
        // every constant copied into MediaQueryTexts is used by exactly one registry entry at least, and the names are unique
        assertEquals(registered.map { it.name }.toSet().size, registered.size)
        assertEquals(
            "a copied query that no entry registers",
            foundSql,
            registeredSql,
        )
    }

    /** `Schema.kt` reads these tables inside triggers (the bounds, the guards): a trigger is no read path. */
    @Test
    fun theScannerIgnoresTheSchemasTriggersAndIndexes() {
        val statements = Schema.migrations.single { it.version == 8 }.statements
        val rule = statements.single { it.contains("CREATE TRIGGER media_fragment_state") }
        assertTrue(rule.contains("SELECT 1 FROM media_upload"))
        val guard = statements.single { it.contains("CREATE TRIGGER media_blob_no_replace") }
        assertTrue(guard.contains("SELECT 1 FROM media_blob"))
        val file = temp.newFile("Schema.kt")
        file.writeText("val statements = listOf(\n    \"\"\"$rule\"\"\",\n    \"\"\"$guard\"\"\",\n)\n")
        assertEquals(emptyList<MediaExpiredRowLint.Found>(), L.readQueriesOverExpiringRows(listOf(file)))
        // ... and neither is the guard of the migration, which counts the v1 tables with a write
        val countsV1 = statements.single { it.startsWith("INSERT INTO v8_migration_guard(row_count) SELECT count(*) FROM media_blobs") }
        val f2 = temp.newFile("Migration.kt")
        f2.writeText("val x = \"$countsV1\"\n")
        assertEquals(emptyList<MediaExpiredRowLint.Found>(), L.readQueriesOverExpiringRows(listOf(f2)))
    }

    /** The twin of the channel lint's: the scanner's first look at a file reads a table name without regard to case. */
    @Test
    fun aFileThatNamesAMediaTableOnlyInCapitalsIsStillScanned() {
        val file = temp.newFile("Shouting.kt")
        file.writeText("class Shouting { fun all() = query(\"SELECT STATE FROM MEDIA_OBJECT WHERE OBJECT_ID = ?\") }\n")
        assertFalse("the fixture must hold no lower-case table name", file.readText().contains("media_object"))
        assertEquals(listOf("SELECT STATE FROM MEDIA_OBJECT WHERE OBJECT_ID = ?"), L.readQueriesOverExpiringRows(listOf(file)).map { normalize(it.sql) })
    }

    /** The registered media queries that join `dm_message` are the ones the DM lint would otherwise report as unregistered reads of it. */
    @Test
    fun theMediaQueriesThatReadDmMessageAreTheOnesTheDmLintLeavesToThisOne() {
        val joined = L.allRegistered().filter { it.sql.contains("dm_message", ignoreCase = true) }
        assertTrue(joined.size >= 14)
        for (query in joined) assertTrue("${query.name} applies the message's filter", query.sql.contains("delete_at_minute"))
    }
}
