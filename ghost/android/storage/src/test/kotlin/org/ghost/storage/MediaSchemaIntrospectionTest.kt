package org.ghost.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * **R-M1, R-M3 and R-M4 over the media tables** (Phase 11 design §13.6: "`DmSchemaIntrospectionTest` (T33) gains
 * `incomplete_after_hour`, `deadline_hour` and `retain_until_day`"; T33, §12.4), slice S3.
 *
 * [DmSchemaIntrospectionTest] already scans every table of the database, so a media column that looks like a time and
 * is not declared fails there too; this class is the media-specific half and says more:
 *
 *  - the tables are exactly the five of §13.6, and the columns of each are exactly §13.6's ([MediaSchema.columns]), so a
 *    `created_at`, a counter or an activity column added to one fails until it is written down beside the rule that
 *    allows it (R-M1's "the dump shows only what the design declares");
 *  - every time column is one of the three of [MediaSchema.timeColumns] — an hour, an hour and a day, **no other** —,
 *    each with the granularity its suffix names and `typeof(x) = 'integer'` (R-M3), and every such CHECK is
 *    **executed**: a REAL whose whole part is aligned is refused, a value one unit off the grid is refused, a whole
 *    number written as `x.0` is stored as an integer;
 *  - every other integer column is classified: a bounded counter, a flag or a closed list, and nothing else;
 *  - no object is or names a virtual table (R-M4; the source half is `dm-no-fts.sh`);
 *  - the shape: **every table WITHOUT ROWID with no exception** (T33: no table records the order its rows arrived in;
 *    Phase 10 needed two exceptions, Phase 11 needs none), the foreign keys and cascades, the objects that hang on each
 *    table.
 */
class MediaSchemaIntrospectionTest {

    private val timeLike = Regex("(minute|hour|day|week|_at$|time|date|epoch|_ms$|_seconds$|expir|_ts$|stamp|last_|since|until)")

    private fun migrated(): JdbcSqlExecutor = JdbcSqlExecutor().also { MigrationRunner(it).migrate() }

    private fun mediaTables(db: SqlExecutor): List<String> {
        val out = ArrayList<String>()
        db.query("SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'media\\_%' ESCAPE '\\' ORDER BY name") { out += it.string(0) }
        return out
    }

    private class Column(val name: String, val type: String, val notNull: Boolean, val pk: Int)

    private fun columns(db: SqlExecutor, table: String): List<Column> {
        val out = ArrayList<Column>()
        db.query("PRAGMA table_info($table)") { out += Column(it.string(1), it.string(2), it.long(3) == 1L, it.long(5).toInt()) }
        return out
    }

    private fun createSql(db: SqlExecutor, table: String): String =
        db.queryString("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", listOf(table))!!.replace(Regex("\\s+"), " ")

    // ------------------------------------------------------------------ R-M1: what the tables hold

    @Test
    fun theTablesAreExactlyTheFiveOfSectionThirteenSixAndTheOldOnesAreGone() = migrated().use { db ->
        assertEquals(MediaSchema.tables, mediaTables(db).toSet())
        assertEquals(5, MediaSchema.tables.size)
        val all = HashSet<String>()
        db.query("SELECT name FROM sqlite_master WHERE type = 'table'") { all += it.string(0) }
        for (gone in MediaSchema.v1Tables) assertFalse("$gone is dropped by migration 8", gone in all)
    }

    @Test
    fun theColumnsOfEveryTableAreExactlyTheDesignedOnesInOrderWithTheirNullability() = migrated().use { db ->
        assertEquals(MediaSchema.tables, MediaSchema.columns.keys)
        for ((table, expected) in MediaSchema.columns) {
            val found = columns(db, table).joinToString(" ") { it.name + if (it.notNull) "" else "?" }
            assertEquals(table, expected, found)
        }
        // Every key column is declared NOT NULL (a PRIMARY KEY column of a rowid table could hold NULL otherwise).
        for ((table, _) in MediaSchema.columns) {
            for (column in columns(db, table)) if (column.pk > 0) assertTrue("$table.${column.name} is a NOT NULL key", column.notNull)
        }
    }

    /** The dump of §12.4: a column that records a creation, an update, an access or a count of activity is not here. */
    @Test
    fun noColumnRecordsCreationActivityOrACountOfWhatHappened() = migrated().use { db ->
        val activity = Regex("(created|updated|modified|touched|accessed|activity|counter|total|seq_no|rowid|last_|seen)")
        val named = ArrayList<String>()
        for (table in mediaTables(db)) for (column in columns(db, table)) if (activity.containsMatchIn(column.name)) named += "$table.${column.name}"
        assertEquals(emptyList<String>(), named)
    }

    // ------------------------------------------------------------------ R-M3: time columns

    /**
     * The corpus is `sqlite_master`, not a list of table names: every column of every `media_*` table whose name looks
     * like a time is declared, in both directions.
     */
    @Test
    fun everyTimeLikeColumnOfTheMediaTablesIsOneTheDesignDeclares() = migrated().use { db ->
        val foundTimes = HashSet<String>()
        val usedExemptions = HashSet<String>()
        val undeclared = ArrayList<String>()
        for (table in mediaTables(db)) {
            for (column in columns(db, table)) {
                val qualified = "$table.${column.name}"
                if (!timeLike.containsMatchIn(column.name.lowercase())) continue
                when (qualified) {
                    in MediaSchema.timeColumns -> foundTimes += qualified
                    in MediaSchema.notTimes -> usedExemptions += qualified
                    else -> undeclared += qualified
                }
            }
        }
        assertEquals("undeclared time-like columns (R-M3)", emptyList<String>(), undeclared.sorted())
        assertEquals("declared time columns that no table has", MediaSchema.timeColumns, foundTimes)
        assertEquals("exemptions that match nothing", MediaSchema.notTimes.keys, usedExemptions)
        assertEquals("T33: an hour, an hour and a day, and no other time (§12.4)", 3, MediaSchema.timeColumns.size)
    }

    /** The suffix names the grid, and the grid and the type are in the column's own CHECK (T20, §21.14). */
    @Test
    fun everyTimeColumnCarriesItsGranularityAndItsTypeCheck() = migrated().use { db ->
        for (qualified in MediaSchema.timeColumns) {
            val (table, column) = qualified.split(".")
            val sql = createSql(db, table)
            assertTrue("$qualified needs typeof($column) = 'integer'", sql.contains("typeof($column) = 'integer'"))
            when {
                column.endsWith("_minute") -> assertTrue("$qualified needs % 60 = 0", sql.contains("$column % 60 = 0"))
                column.endsWith("_hour") -> assertTrue("$qualified needs % 3600 = 0", sql.contains("$column % 3600 = 0"))
                column.endsWith("_day") -> assertTrue("$qualified needs >= 0", sql.contains("$column >= 0"))
                else -> error("$qualified has no granularity suffix")
            }
        }
        for (qualified in MediaSchema.counterColumns) {
            val (table, column) = qualified.split(".")
            assertTrue("$qualified needs typeof($column) = 'integer'", createSql(db, table).contains("typeof($column) = 'integer'"))
        }
        // No other integer carries a granularity: a `% 60` anywhere else would be a time nobody declared.
        val withGrid = ArrayList<String>()
        for (table in mediaTables(db)) {
            for (column in columns(db, table)) {
                if (Regex("\\b${column.name} % \\d+ = 0").containsMatchIn(createSql(db, table))) withGrid += "$table.${column.name}"
            }
        }
        assertEquals(MediaSchema.timeColumns.filter { !it.endsWith("_day") }.sorted(), withGrid.sorted())
    }

    /** One typeof-guarded column with the statement that writes it (the DM test's `TypedColumn`, over the fixture). */
    private class Typed(
        val qualified: String,
        /** A value inside the column's range and on its grid. */
        val whole: Long,
        /** The other columns the row needs for this one to be legal. */
        val with: Map<String, Any?> = emptyMap(),
        /** Values just outside the range. */
        val outside: List<Long> = emptyList(),
        /** `-1` is a legal value (the manifest's ordinal), so the "a negative value" case does not apply. */
        val minusOneIsLegal: Boolean = false,
    )

    private val typed: List<Typed> = listOf(
        // ---- time columns
        Typed("media_object.incomplete_after_hour", 3_600, mapOf("role" to "in", "state" to "awaiting")),
        Typed("media_upload.deadline_hour", 7_200),
        Typed("media_blob.retain_until_day", 20_000, mapOf("origin" to "ingested")),
        // ---- the bounded counters and codes
        Typed("media_object.class_code", 3, mapOf("kind" to 2L), outside = listOf(11L)),
        Typed("media_object.decode_failures", 1, mapOf("role" to "in", "state" to "verified", "incomplete_after_hour" to 3_600L), outside = listOf(3L)),
        Typed("media_upload.retry_gen", 2, outside = listOf(4L)),
        Typed("media_fragment.ordinal", 5, outside = listOf(804L, -2L), minusOneIsLegal = true),
        Typed("media_outbound_op.retry_gen", 1, outside = listOf(4L)),
        Typed("media_outbound_op.resend_count", 1, outside = listOf(3L)),
    )

    /**
     * R-M3 and §21.14, **executed**: every integer column the design declares refuses a REAL whose whole part is aligned
     * (SQLite's `%` and `BETWEEN` cast and compare numerically, so `x.5` passes every granularity and range CHECK and
     * only `typeof` refuses it), refuses a value one unit off its grid, a negative value and the values just outside its
     * range, and stores the same number written `x.0` as an integer.
     */
    @Test
    fun everyIntegerColumnRefusesAFractionalValueAndOneOffItsGrid() {
        assertEquals(
            "a declared integer column that no case of this test writes",
            (MediaSchema.timeColumns + MediaSchema.counterColumns).sorted(),
            typed.map { it.qualified }.distinct().sorted(),
        )
        var offGrid = 0
        for (case in typed) MediaFixture().use { f ->
            val (table, column) = case.qualified.split(".")
            f.parents(table, case.with)
            val before = f.count(table)
            fun rejected(literal: String, why: String) {
                val (sql, args) = f.sql(table, case.with, mapOf(column to literal))
                f.db.rejects(CHECK_FAILED, sql, *args.toTypedArray())
                assertEquals("$why: ${case.qualified}", before, f.count(table))
            }
            rejected("${case.whole}.5", "a fractional value")
            if (!case.minusOneIsLegal) rejected("-1", "a negative value")
            for (value in case.outside) rejected("$value", "a value outside the range")
            if (column.endsWith("_hour") || column.endsWith("_minute")) {
                offGrid++
                rejected("${case.whole + 1}", "a value off the grid")
            }
            // Written with no fractional part, INTEGER affinity coerces it and the row is stored as an integer.
            val (sql, args) = f.sql(table, case.with, mapOf(column to "${case.whole}.0"))
            f.db.exec(sql, args)
            assertEquals(case.qualified, "integer", f.db.queryString("SELECT typeof($column) FROM $table WHERE $column IS NOT NULL ORDER BY $column DESC LIMIT 1"))
        }
        assertEquals("every hour column was written one unit off its grid", 2, offGrid)
    }

    // ------------------------------------------------------------------ no counters beyond the declared ones

    /**
     * §12.4: "no time column other than `*_day` and `*_hour`", T33: no activity history. Every INTEGER column of every
     * media table is a time (declared), a bounded counter or code (declared), a 0/1 flag, a closed list or the half of a
     * composite key; an INTEGER column that is none of them fails here until the design says what it is.
     */
    @Test
    fun everyIntegerColumnIsClassifiedAndNothingCountsActivity() = migrated().use { db ->
        val classified = MediaSchema.timeColumns + MediaSchema.counterColumns + MediaSchema.flagColumns +
            MediaSchema.enumColumns + MediaSchema.referenceColumns
        val found = HashSet<String>()
        for (table in mediaTables(db)) {
            for (column in columns(db, table)) if (column.type == "INTEGER") found += "$table.${column.name}"
        }
        assertEquals("integer columns nobody classified", emptySet<String>(), found - classified)
        assertEquals("classified integer columns no table has", emptySet<String>(), classified - found)
        for (qualified in MediaSchema.flagColumns) {
            val (table, column) = qualified.split(".")
            assertTrue("$qualified is a 0/1 flag", Regex("CHECK \\($column IN \\(0, 1\\)\\)").containsMatchIn(createSql(db, table)))
        }
        for (qualified in MediaSchema.enumColumns) {
            val (table, column) = qualified.split(".")
            assertTrue("$qualified is a closed list", Regex("CHECK \\($column (IN \\([0-9, ]+\\)|= \\d+)\\)").containsMatchIn(createSql(db, table)))
        }
        // The only counters are bounded by a CHECK of three values or fewer, except the ordinal, which names a fragment.
        for (qualified in MediaSchema.counterColumns - "media_fragment.ordinal" - "media_object.class_code") {
            val (table, column) = qualified.split(".")
            assertTrue(qualified, Regex("$column BETWEEN 0 AND [0-3]\\b").containsMatchIn(createSql(db, table)))
        }
    }

    // ------------------------------------------------------------------ R-M4 and the shape

    /** R-M4 over every object of the media schema; the whole-database twin is [DmSchemaIntrospectionTest]'s. */
    @Test
    fun noMediaObjectIsOrNamesAVirtualTable() = migrated().use { db ->
        val offenders = ArrayList<String>()
        db.query("SELECT type, name, ifnull(sql, '') FROM sqlite_master WHERE tbl_name LIKE 'media\\_%' ESCAPE '\\'") { row ->
            val sql = row.string(2).lowercase()
            if (sql.contains("virtual") || Regex("(^|[^a-z0-9])fts").containsMatchIn(sql)) offenders += "${row.string(0)} ${row.string(1)}"
        }
        assertEquals(emptyList<String>(), offenders)
    }

    /**
     * T33 and F9 §13.6 step 5: "random WITHOUT ROWID keys". The hidden rowid of a table is the order its rows arrived
     * in, and the gaps between the rowids that survive count the rows that were swept. No table of this migration needs an
     * order (Phase 10 had two that did), so **all five are WITHOUT ROWID with no exception**: `SELECT rowid` is the test,
     * a table that has none refuses the word.
     */
    @Test
    fun everyTableIsWithoutRowidAndRecordsNoOrder() = migrated().use { db ->
        for (table in MediaSchema.tables) {
            assertTrue(table, createSql(db, table).trimEnd().endsWith("WITHOUT ROWID"))
            val answers = try {
                db.queryLong("SELECT count(rowid) FROM $table")
                true
            } catch (e: java.sql.SQLException) {
                false
            }
            assertFalse("$table answers rowid", answers)
        }
        assertEquals(emptySet<String>(), MediaSchema.rowidTables)
        assertEquals(5, MediaSchema.withoutRowidTables.size)
        // The five rebuilt DM tables are as WITHOUT ROWID as they were.
        for (table in MediaSchema.rebuilt) assertTrue(table, createSql(db, table).trimEnd().endsWith("WITHOUT ROWID"))
    }

    @Test
    fun theForeignKeysAndCascadesAreTheSpecifiedOnes() = migrated().use { db ->
        fun foreignKeys(table: String): List<String> {
            val out = ArrayList<String>()
            db.query("PRAGMA foreign_key_list($table)") { out += "${it.string(3)} -> ${it.string(2)}.${it.string(4)} on delete ${it.string(6)}" }
            return out.sorted()
        }
        assertEquals(listOf("message_id -> dm_message.message_id on delete CASCADE"), foreignKeys("media_object"))
        assertEquals(
            listOf(
                "namespace_id -> sync_namespace.namespace_id on delete NO ACTION",
                "object_id -> media_object.object_id on delete CASCADE",
            ),
            foreignKeys("media_upload"),
        )
        assertEquals(emptyList<String>(), foreignKeys("media_blob"))
        assertEquals(listOf("object_id -> media_object.object_id on delete CASCADE"), foreignKeys("media_fragment"))
        assertEquals(
            listOf("object_id -> media_fragment.object_id on delete CASCADE", "ordinal -> media_fragment.ordinal on delete CASCADE"),
            foreignKeys("media_outbound_op"),
        )
        // A fragment names its blob by hash and by no foreign key: its blob may arrive after it (`expected`, D25).
        assertTrue(foreignKeys("media_fragment").none { it.contains("media_blob") })
        // The rebuilt tables keep the references v7 had, to the final names.
        assertEquals(
            listOf("contact_id -> dm_contact.contact_id on delete CASCADE", "message_ref -> dm_message.message_id on delete CASCADE"),
            foreignKeys("dm_outbound_item"),
        )
        assertEquals(listOf("item_id -> dm_outbound_item.item_id on delete CASCADE"), foreignKeys("dm_outbound_op"))
        assertEquals(
            listOf("contact_id -> dm_contact.contact_id on delete CASCADE", "item_id -> dm_outbound_item.item_id on delete CASCADE"),
            foreignKeys("dm_pending_send"),
        )
        assertEquals(listOf("target_id -> dm_message.message_id on delete CASCADE"), foreignKeys("dm_reaction"))
        assertEquals(listOf("conversation_id -> dm_conversation.conversation_id on delete CASCADE"), foreignKeys("dm_message"))
    }

    /** What hangs on each media table: only its rules and its guard, beside the five named indexes (and one automatic one). */
    @Test
    fun theObjectsOnTheMediaTablesAreTheirRulesGuardsAndFiveIndexes() = migrated().use { db ->
        val triggers = HashSet<String>()
        val indexes = HashSet<String>()
        db.query(
            "SELECT type, name FROM sqlite_master WHERE tbl_name LIKE 'media\\_%' ESCAPE '\\' AND type IN ('trigger', 'index')",
        ) { if (it.string(0) == "trigger") triggers += it.string(1) else indexes += it.string(1) }
        assertEquals(MediaSchema.rules + MediaSchema.guards, triggers)
        assertEquals(MediaSchema.indexes + "sqlite_autoindex_media_outbound_op_2", indexes)
        // The partial and unique indexes carry their predicates.
        fun indexSql(name: String) = db.queryString("SELECT sql FROM sqlite_master WHERE name = ?", listOf(name))!!.replace(Regex("\\s+"), " ")
        assertTrue(indexSql("idx_media_object_message").startsWith("CREATE UNIQUE INDEX") && indexSql("idx_media_object_message").endsWith("WHERE message_id IS NOT NULL"))
        assertTrue(indexSql("idx_media_blob_file").startsWith("CREATE UNIQUE INDEX"))
        assertTrue(indexSql("idx_media_blob_retention").endsWith("WHERE retain_until_day IS NOT NULL"))
        assertTrue(indexSql("idx_media_fragment_open").endsWith("WHERE upload_state = 'open'"))
        assertFalse(indexSql("idx_media_fragment_hash").contains(" UNIQUE "))
        // Every guard is a BEFORE INSERT trigger on its own table, named after it.
        for (guard in MediaSchema.guards) {
            val table = guard.removeSuffix("_no_replace")
            val sql = db.queryString("SELECT sql FROM sqlite_master WHERE name = ?", listOf(guard))!!.replace(Regex("\\s+"), " ")
            assertTrue(guard, sql.contains("BEFORE INSERT ON $table WHEN EXISTS (SELECT 1 FROM $table WHERE "))
        }
        assertEquals(MediaSchema.tables, MediaSchema.guards.map { it.removeSuffix("_no_replace") }.toSet())
        // Every other rule is a BEFORE trigger on a table of this migration, and none is an AFTER trigger or an INSTEAD OF.
        for (rule in MediaSchema.rules) {
            val sql = db.queryString("SELECT sql FROM sqlite_master WHERE name = ?", listOf(rule))!!.replace(Regex("\\s+"), " ")
            assertTrue(rule, Regex("^CREATE TRIGGER $rule BEFORE (INSERT|UPDATE|DELETE)\\b").containsMatchIn(sql))
        }
    }

    /** Nothing else of the whole database changed shape: the integrity checks the runner and SQLite make still pass. */
    @Test
    fun theWholeDatabaseStillPassesItsOwnIntegrityChecks() = migrated().use { db ->
        assertEquals("ok", db.queryString("PRAGMA integrity_check"))
        assertEquals(null, db.queryLong("PRAGMA foreign_key_check"))
        MigrationRunner(db).verifyIntegrity()
    }
}
