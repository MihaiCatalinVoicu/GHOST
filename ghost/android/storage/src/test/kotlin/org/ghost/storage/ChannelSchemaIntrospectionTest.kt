package org.ghost.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * **R-M1, R-M3 and R-M4 over the channel tables** (Phase 10 design §9 last paragraph: "`DmSchemaIntrospectionTest`'s
 * rule (every time column checked, no virtual table) extends to `ch_*` and `mls_*`"; T20, T33, §19.21), slice S3.
 *
 * [DmSchemaIntrospectionTest] already scans every table of the database, so a channel column that looks
 * like a time and is not declared fails there too; this class is the channel-specific half and says more:
 *
 *  - the tables are exactly the 26 of §9, and the columns of each are exactly §9's ([ChannelSchema.columns]),
 *    so a `created_at`, a counter or an activity column added to one fails until it is written down
 *    beside the rule that allows it (R-M1's "the dump shows only what the design declares");
 *  - every time column is one of the 30 of [ChannelSchema.timeColumns], each with the granularity its
 *    suffix names and `typeof(x) = 'integer'` (R-M3), and every such CHECK is **executed**: a REAL
 *    whose whole part is aligned is refused, a value one unit off the grid is refused, a whole number
 *    written as `x.0` is stored as an integer;
 *  - every other integer column is classified: an epoch, a bounded counter, a flag or a closed list,
 *    and nothing else ("no counters per channel except the bounded liveness counters of CO-11");
 *  - no object is or names a virtual table (R-M4; the gate `dm-no-fts.sh` is the source half);
 *  - the shape: WITHOUT ROWID only for the two tag tables §9 marks (the other 24 keep a hidden rowid, an
 *    insertion order), the foreign keys and cascades, the objects that hang on each table.
 */
class ChannelSchemaIntrospectionTest {

    private val timeLike = Regex("(minute|hour|day|week|_at$|time|date|epoch|_ms$|_seconds$|expir|_ts$|stamp|last_|since|until)")

    private fun migrated(): JdbcSqlExecutor = JdbcSqlExecutor().also { MigrationRunner(it).migrate() }

    private fun channelTables(db: SqlExecutor): List<String> {
        val out = ArrayList<String>()
        db.query("SELECT name FROM sqlite_master WHERE type = 'table' AND (name LIKE 'ch\\_%' ESCAPE '\\' OR name LIKE 'mls\\_%' ESCAPE '\\') ORDER BY name") {
            out += it.string(0)
        }
        return out
    }

    private class Column(val name: String, val type: String, val notNull: Boolean)

    private fun columns(db: SqlExecutor, table: String): List<Column> {
        val out = ArrayList<Column>()
        db.query("PRAGMA table_info($table)") { out += Column(it.string(1), it.string(2), it.long(3) == 1L) }
        return out
    }

    private fun createSql(db: SqlExecutor, table: String): String =
        db.queryString("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", listOf(table))!!.replace(Regex("\\s+"), " ")

    // ------------------------------------------------------------------ R-M1: what the tables hold

    @Test
    fun theTablesAreExactlyTheTwentySixOfSectionNineAndTheOldOnesAreGone() = migrated().use { db ->
        assertEquals(ChannelSchema.tables, channelTables(db).toSet())
        assertEquals(26, ChannelSchema.tables.size)
        val all = HashSet<String>()
        db.query("SELECT name FROM sqlite_master WHERE type = 'table'") { all += it.string(0) }
        for (gone in ChannelSchema.v1Tables) assertFalse("$gone is dropped by migration 7", gone in all)
        assertTrue("media and media_blobs stay for Phase 11", "media" in all && "media_blobs" in all)
    }

    @Test
    fun theColumnsOfEveryTableAreExactlyTheDesignedOnesInOrderWithTheirNullability() = migrated().use { db ->
        assertEquals(ChannelSchema.tables, ChannelSchema.columns.keys)
        for ((table, expected) in ChannelSchema.columns) {
            val found = columns(db, table).joinToString(" ") { it.name + if (it.notNull) "" else "?" }
            // A PRIMARY KEY column of a rowid table may hold NULL unless declared NOT NULL, so every key column is.
            assertEquals(table, expected, found)
        }
    }

    // ------------------------------------------------------------------ R-M3: time columns

    /**
     * The corpus is `sqlite_master`, not a list of table names: every column of every `ch_*` and `mls_*`
     * table whose name looks like a time is declared, in both directions.
     */
    @Test
    fun everyTimeLikeColumnOfTheChannelTablesIsOneTheDesignDeclares() = migrated().use { db ->
        val foundTimes = HashSet<String>()
        val foundEpochs = HashSet<String>()
        val usedExemptions = HashSet<String>()
        val undeclared = ArrayList<String>()
        for (table in channelTables(db)) {
            for (column in columns(db, table)) {
                val qualified = "$table.${column.name}"
                if (!timeLike.containsMatchIn(column.name.lowercase())) continue
                when (qualified) {
                    in ChannelSchema.timeColumns -> foundTimes += qualified
                    in ChannelSchema.epochColumns -> foundEpochs += qualified
                    in ChannelSchema.notTimes -> usedExemptions += qualified
                    else -> undeclared += qualified
                }
            }
        }
        assertEquals("undeclared time-like columns (R-M3)", emptyList<String>(), undeclared.sorted())
        assertEquals("declared time columns that no table has", ChannelSchema.timeColumns, foundTimes)
        assertEquals("declared epoch counters that no table has", ChannelSchema.epochColumns, foundEpochs)
        assertEquals("exemptions that match nothing", ChannelSchema.notTimes.keys, usedExemptions)
        assertEquals(30, ChannelSchema.timeColumns.size)
    }

    /** The suffix names the grid, and the grid and the type are in the column's own CHECK (T20, §21.14). */
    @Test
    fun everyTimeColumnCarriesItsGranularityAndItsTypeCheck() = migrated().use { db ->
        for (qualified in ChannelSchema.timeColumns) {
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
        for (qualified in ChannelSchema.epochColumns + ChannelSchema.counterColumns) {
            val (table, column) = qualified.split(".")
            assertTrue("$qualified needs typeof($column) = 'integer'", createSql(db, table).contains("typeof($column) = 'integer'"))
        }
        // No other integer carries a granularity: a `% 60` anywhere else would be a time nobody declared.
        val withGrid = ArrayList<String>()
        for (table in channelTables(db)) {
            for (column in columns(db, table)) {
                if (Regex("\\b${column.name} % \\d+ = 0").containsMatchIn(createSql(db, table))) withGrid += "$table.${column.name}"
            }
        }
        assertEquals(ChannelSchema.timeColumns.filter { !it.endsWith("_day") }.sorted(), withGrid.sorted())
    }

    /** One typeof-guarded column with the statement that writes it (the DM test's `TypedColumn`, over the fixture). */
    private class Typed(
        val qualified: String,
        /** A value inside the column's range and on its grid. */
        val whole: Long,
        /** The other columns the row needs for this one to be legal (a state that carries the column, a coupled partner). */
        val with: Map<String, Any?> = emptyMap(),
        /** A value just outside the range, if the column has an upper or lower bound beyond `>= 0`. */
        val outside: List<Long> = emptyList(),
    )

    private val typed: List<Typed> = listOf(
        // ---- time columns
        Typed("ch_channel.last_committer_commit_day", 20_000),
        Typed("ch_liveness.unopenable_first_minute", 600, mapOf("unopenable_count" to 1L)),
        Typed("ch_schedule.next_selfupdate_day", 20_000),
        Typed("ch_schedule.last_own_commit_day", 20_000),
        Typed("ch_schedule.next_pass_minute", 600),
        Typed("ch_generation.switch_hour", 3_600, mapOf("state" to "pending_switch")),
        Typed("ch_generation.drain_until_day", 20_014, mapOf("state" to "draining")),
        Typed("ch_epoch.anchor_minute", 600),
        Typed("ch_epoch.final_day", 20_000, mapOf("state" to "final")),
        Typed("ch_epoch.keep_until_day", 20_002, mapOf("state" to "final", "final_day" to 20_000L)),
        Typed("ch_epoch_log.final_day", 20_000),
        Typed("ch_candidate.first_seen_minute", 600),
        Typed("ch_candidate.store_hour", 3_600),
        Typed("ch_fork_signal.first_seen_day", 20_000),
        Typed("mls_global_kv.delete_after_day", 20_007),
        Typed("ch_post.author_minute", 600),
        Typed("ch_post.displayed_minute", 660, mapOf("state" to "read")),
        Typed("ch_post.delete_at_minute", 604_800),
        Typed("ch_post.relay_expiry_hour", 3_600),
        Typed("ch_pending_post.fail_after_hour", 3_600),
        Typed("ch_seen.until_day", 20_000),
        Typed("ch_reveal.delete_at_minute", 600),
        Typed("ch_join.expiry_day", 20_007),
        Typed("ch_join_request.until_day", 20_007),
        Typed("ch_invite_issued.expiry_day", 20_007),
        Typed("ch_kp_seen.until_day", 20_011),
        Typed("ch_invite_own.expiry_day", 20_007),
        Typed("ch_sponsor.admitted_day", 20_000),
        Typed("ch_member_refresh.refresh_day", 20_000),
        Typed("ch_request.until_day", 20_007),
        // ---- the epoch counters
        Typed("ch_channel.epoch", 5), Typed("ch_channel.joined_epoch", 5), Typed("ch_epoch.epoch", 5),
        Typed("ch_epoch_log.epoch", 5), Typed("ch_candidate.epoch", 5), Typed("ch_fork_signal.epoch", 5),
        Typed("ch_post.epoch", 5), Typed("ch_member_seen.last_epoch", 5), Typed("ch_box_key.last_epoch", 5),
        // ---- the bounded counters and codes
        Typed("ch_channel.generation", 5, outside = listOf(4_294_967_296L)),
        Typed("ch_generation.generation", 5, outside = listOf(4_294_967_296L)),
        Typed("ch_join.generation", 5, outside = listOf(4_294_967_296L)),
        Typed("ch_join_request.generation", 5, outside = listOf(4_294_967_296L)),
        Typed("ch_candidate.rank", 7, outside = listOf(256L)),
        Typed("ch_epoch.own_seq", 7, outside = listOf(4_294_967_296L)),
        Typed("ch_liveness.unopenable_count", 7, mapOf("unopenable_first_minute" to 600L), outside = listOf(256L)),
        Typed("ch_liveness.unopenable_operators", 7, outside = listOf(256L)),
        Typed("ch_liveness.sessions", 7, outside = listOf(256L)),
        Typed("ch_invite_issued.pw_version", 3, outside = listOf(0L, 65_536L)),
        Typed("ch_pending_post.kind", 3, outside = listOf(0L, 8L)),
        Typed("ch_channel.timer_code", 4, outside = listOf(6L)),
        Typed("ch_post.timer_code", 4, outside = listOf(6L)),
    )

    /**
     * R-M3 and §21.14, **executed**: every integer column the design declares refuses a REAL whose whole part
     * is aligned (SQLite's `%` and `BETWEEN` cast and compare numerically, so `x.5` passes every granularity
     * and range CHECK and only `typeof` refuses it), refuses a value one unit off its grid, a negative value
     * and the values just outside its range, and stores the same number written `x.0` as an integer.
     */
    @Test
    fun everyIntegerColumnRefusesAFractionalValueAndOneOffItsGrid() {
        assertEquals(
            "a declared integer column that no case of this test writes",
            (ChannelSchema.timeColumns + ChannelSchema.epochColumns + ChannelSchema.counterColumns).sorted(),
            typed.map { it.qualified }.distinct().sorted(),
        )
        var offGrid = 0
        for (case in typed) ChannelFixture().use { f ->
            val (table, column) = case.qualified.split(".")
            f.parents(table)
            fun rejected(literal: String, why: String) {
                val (sql, args) = f.sql(table, case.with, mapOf(column to literal))
                f.db.rejects(CHECK_FAILED, sql, *args.toTypedArray())
                assertEquals("$why: ${case.qualified}", 0L, f.count(table))
            }
            rejected("${case.whole}.5", "a fractional value")
            rejected("-1", "a negative value")
            for (value in case.outside) rejected("$value", "a value outside the range")
            if (column.endsWith("_minute") || column.endsWith("_hour")) {
                offGrid++
                rejected("${case.whole + 1}", "a value off the grid")
            }
            // Written with no fractional part, INTEGER affinity coerces it and the row is stored as an integer.
            val (sql, args) = f.sql(table, case.with, mapOf(column to "${case.whole}.0"))
            f.db.exec(sql, args)
            assertEquals(case.qualified, "integer", f.db.queryString("SELECT typeof($column) FROM $table WHERE $column IS NOT NULL LIMIT 1"))
        }
        assertEquals("every minute and hour column was written one unit off its grid", 12, offGrid)
    }

    // ------------------------------------------------------------------ no counters beyond the declared ones

    /**
     * §9: "no counters per channel except the bounded liveness counters of CO-11, no activity records except
     * those declared". Every INTEGER column of every channel table is a time (declared), an epoch counter, a
     * bounded counter or code (declared), a 0/1 flag or a closed list; an INTEGER column that is none of them
     * fails here until the design says what it is.
     */
    @Test
    fun everyIntegerColumnIsClassifiedAndNothingCountsActivity() = migrated().use { db ->
        val classified = ChannelSchema.timeColumns + ChannelSchema.epochColumns + ChannelSchema.counterColumns +
            ChannelSchema.flagColumns + ChannelSchema.enumColumns
        val found = HashSet<String>()
        for (table in channelTables(db)) {
            for (column in columns(db, table)) if (column.type == "INTEGER") found += "$table.${column.name}"
        }
        assertEquals("integer columns nobody classified", emptySet<String>(), found - classified)
        assertEquals("classified integer columns no table has", emptySet<String>(), classified - found)
        for (qualified in ChannelSchema.flagColumns) {
            val (table, column) = qualified.split(".")
            assertTrue("$qualified is a 0/1 flag", Regex("CHECK \\($column IN \\(0, 1\\)\\)").containsMatchIn(createSql(db, table)))
        }
        for (qualified in ChannelSchema.enumColumns) {
            val (table, column) = qualified.split(".")
            assertTrue("$qualified is a closed list", Regex("CHECK \\($column (IN \\([0-9, ]+\\)|= \\d+)\\)").containsMatchIn(createSql(db, table)))
        }
        // The counters of CO-11 are the three of ch_liveness, each capped at 255, and the own sequence is one per epoch.
        val counters = ChannelSchema.counterColumns.filter { it.startsWith("ch_liveness.") || it.endsWith("own_seq") }
        assertEquals(setOf("ch_liveness.unopenable_count", "ch_liveness.unopenable_operators", "ch_liveness.sessions", "ch_epoch.own_seq"), counters.toSet())
        // No column is named like a record of activity or creation.
        val activity = Regex("(created|updated|modified|touched|accessed|activity|counter|total|seq_no|rowid)")
        val named = ArrayList<String>()
        for (table in channelTables(db)) for (column in columns(db, table)) if (activity.containsMatchIn(column.name)) named += "$table.${column.name}"
        assertEquals(emptyList<String>(), named)
    }

    // ------------------------------------------------------------------ R-M4 and the shape

    /** R-M4 over every object of the channel schema; the whole-database twin is [DmSchemaIntrospectionTest]'s. */
    @Test
    fun noChannelObjectIsOrNamesAVirtualTable() = migrated().use { db ->
        val offenders = ArrayList<String>()
        db.query("SELECT type, name, ifnull(sql, '') FROM sqlite_master WHERE tbl_name LIKE 'ch\\_%' ESCAPE '\\' OR tbl_name LIKE 'mls\\_%' ESCAPE '\\'") { row ->
            val sql = row.string(2).lowercase()
            if (sql.contains("virtual") || Regex("(^|[^a-z0-9])fts").containsMatchIn(sql)) offenders += "${row.string(0)} ${row.string(1)}"
        }
        assertEquals(emptyList<String>(), offenders)
    }

    @Test
    fun onlyTheTwoTagTablesSectionNineMarksAreWithoutRowid() = migrated().use { db ->
        for (table in ChannelSchema.tables) {
            val withoutRowid = createSql(db, table).trimEnd().endsWith("WITHOUT ROWID")
            assertEquals("$table", table in ChannelSchema.withoutRowidTables, withoutRowid)
        }
        assertEquals(setOf("ch_seen", "ch_kp_seen"), ChannelSchema.withoutRowidTables)
        assertEquals(24, ChannelSchema.rowidTables.size)
        // The hidden rowid of the other 24 is an insertion order: a table that has one answers `rowid`, and
        // the two that have none refuse the word (T33; the cost is recorded in §19.35, F-7).
        for (table in ChannelSchema.tables) {
            val answers = try {
                db.queryLong("SELECT count(rowid) FROM $table")
                true
            } catch (e: java.sql.SQLException) {
                false
            }
            assertEquals("$table", table in ChannelSchema.rowidTables, answers)
        }
    }

    @Test
    fun theForeignKeysAndCascadesAreTheSpecifiedOnes() = migrated().use { db ->
        fun foreignKeys(table: String): List<String> {
            val out = ArrayList<String>()
            db.query("PRAGMA foreign_key_list($table)") { out += "${it.string(3)} -> ${it.string(2)}.${it.string(4)} on delete ${it.string(6)}" }
            return out.sorted()
        }
        for (table in ChannelSchema.tables) {
            val expected = when (table) {
                "ch_channel" -> emptyList()
                "ch_reaction" -> listOf(
                    "channel_id -> ch_channel.channel_id on delete CASCADE",
                    "target -> ch_post.op_id on delete CASCADE",
                )
                else -> listOf("channel_id -> ch_channel.channel_id on delete CASCADE")
            }
            assertEquals(table, expected, foreignKeys(table))
        }
        // Nothing the sync engine owns is referenced: a generation's namespace row is registered later (CH-SWITCH).
        for (table in ChannelSchema.tables) {
            assertTrue(table, foreignKeys(table).none { it.contains("sync_") || it.contains("relay_") || it.contains("outbox_") })
        }
    }

    /** What hangs on each channel table: only its rules and its guard, beside three indexes. */
    @Test
    fun theObjectsOnTheChannelTablesAreTheirRulesGuardsAndThreeIndexes() = migrated().use { db ->
        val triggers = HashSet<String>()
        val indexes = HashSet<String>()
        db.query(
            "SELECT type, name FROM sqlite_master WHERE (tbl_name LIKE 'ch\\_%' ESCAPE '\\' OR tbl_name LIKE 'mls\\_%' ESCAPE '\\') " +
                "AND type IN ('trigger', 'index') AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\'",
        ) { if (it.string(0) == "trigger") triggers += it.string(1) else indexes += it.string(1) }
        assertEquals(ChannelSchema.rules + ChannelSchema.guards, triggers)
        assertEquals(setOf("idx_mls_global_kv_channel", "idx_ch_post_order", "idx_ch_post_delete"), indexes)
        // The partial index on the deletion time carries its predicate, so an undated post is not indexed.
        assertTrue(
            db.queryString("SELECT sql FROM sqlite_master WHERE name = 'idx_ch_post_delete'")!!.contains("WHERE delete_at_minute IS NOT NULL"),
        )
        // Every guard is a BEFORE INSERT trigger on its own table, named after it.
        for (guard in ChannelSchema.guards) {
            val table = guard.removeSuffix("_no_replace")
            val sql = db.queryString("SELECT sql FROM sqlite_master WHERE name = ?", listOf(guard))!!.replace(Regex("\\s+"), " ")
            assertTrue(guard, sql.contains("BEFORE INSERT ON $table WHEN EXISTS (SELECT 1 FROM $table WHERE "))
        }
        assertEquals(ChannelSchema.tables - ChannelSchema.unguarded, ChannelSchema.guards.map { it.removeSuffix("_no_replace") }.toSet())
    }

    @Test
    fun theWholeDatabaseStillPassesItsOwnIntegrityChecks() = migrated().use { db ->
        assertEquals("ok", db.queryString("PRAGMA integrity_check"))
        assertEquals(null, db.queryLong("PRAGMA foreign_key_check"))
        MigrationRunner(db).verifyIntegrity()
    }
}
