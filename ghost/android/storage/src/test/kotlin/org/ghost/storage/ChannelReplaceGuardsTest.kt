package org.ghost.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The REPLACE guards of migration 7 (Phase 8 design §19.21 point 4, Phase 10 design §9; slice S3), executed.
 *
 * With `recursive_triggers` off, a row that REPLACE deletes to resolve a key conflict runs no DELETE
 * trigger, and the foreign-key cascades of `ch_channel` and `ch_post` would run: a REPLACE of a channel
 * row would delete its posts, keys and generations without one trigger firing. A `BEFORE INSERT` trigger
 * runs before the conflict is resolved, so [ChannelSchema.guards] refuse **every** form of insert for a key
 * that exists, on all 24 tables; `ch_seen` and `ch_kp_seen` have none because they are written with
 * `INSERT OR IGNORE`, which deletes nothing. Only two tables keep a hidden rowid (`mls_kv` and
 * `ch_join_request`, T33 and §19.35), and only their guards compare it; their rowids are positive and never change.
 *
 * That every guard names every key of its table is [ReplaceGuardsTest.everyGuardCoversEveryKeyOfItsTableAndOnlyTwoV2TablesGoWithout]'s,
 * read from the schema; this class **provokes** each of them.
 */
class ChannelReplaceGuardsTest {

    private val forms = listOf("INSERT", "INSERT OR REPLACE", "REPLACE", "INSERT OR IGNORE", "INSERT OR ABORT")

    /** The table's rows as text, to prove that a refused insert left them as they were. */
    private fun SqlExecutor.rows(table: String): List<String> {
        val columns = ArrayList<String>()
        query("PRAGMA table_info($table)") { columns += it.string(1) }
        val out = ArrayList<String>()
        query("SELECT ${columns.joinToString(" || '|' || ") { "quote($it)" }} FROM $table") { out += it.string(0) }
        return out.sorted()
    }

    @Test
    fun everyFormOfInsertIsRefusedForAKeyThatExistsOnEveryGuardedTable() {
        for (table in ChannelSchema.tables - ChannelSchema.unguarded) ChannelFixture().use { f ->
            f.put(table)
            val before = f.db.rows(table)
            for (form in forms) {
                val (sql, args) = f.sql(table, verb = form)
                f.db.rejects("$table rows are never replaced", sql, *args.toTypedArray())
            }
            assertEquals(table, before, f.db.rows(table))
            assertEquals(table, 1L, f.count(table))
        }
    }

    @Test
    fun theTwoTablesWrittenWithInsertOrIgnoreIgnoreARepeatAndDeleteNothing() {
        for (table in ChannelSchema.unguarded) ChannelFixture().use { f ->
            f.put(table)
            val before = f.db.rows(table)
            val (sql, args) = f.sql(table, verb = "INSERT OR IGNORE")
            assertEquals(table, 0, f.db.execUpdate(sql, args))
            assertEquals(table, before, f.db.rows(table))
            // A plain INSERT of the same key is the primary-key error of any table: a bug, not a replace.
            val (plain, plainArgs) = f.sql(table)
            f.db.rejects("UNIQUE constraint failed", plain, *plainArgs.toTypedArray())
        }
    }

    @Test
    fun aReplaceOfAChannelWouldHaveCascadedAwayEverythingItOwnsAndTheGuardStopsItFirst() = ChannelFixture().use { f ->
        for (table in ChannelSchema.tables) f.put(table)
        val before = ChannelSchema.tables.associateWith { f.db.rows(it) }
        val (sql, args) = f.sql("ch_channel", verb = "INSERT OR REPLACE")
        f.db.rejects("ch_channel rows are never replaced", sql, *args.toTypedArray())
        assertEquals(before, ChannelSchema.tables.associateWith { f.db.rows(it) })
        // The same replace without the guard does what the guard exists to stop: it deletes the channel's children.
        f.db.exec("DROP TRIGGER ch_channel_no_replace")
        f.db.exec(sql, args)
        assertEquals("the cascade ran", 0L, f.count("ch_post"))
        assertEquals("the cascade ran", 0L, f.count("mls_kv"))
        assertEquals("the cascade ran", 0L, f.count("ch_generation"))
    }

    @Test
    fun aReplaceOfAPostWouldHaveCascadedAwayItsReactions() = ChannelFixture().use { f ->
        f.put("ch_reaction")
        val (sql, args) = f.sql("ch_post", verb = "INSERT OR REPLACE")
        f.db.rejects("ch_post rows are never replaced", sql, *args.toTypedArray())
        assertEquals(1L, f.count("ch_reaction"))
        f.db.exec("DROP TRIGGER ch_post_no_replace")
        f.db.exec(sql, args)
        assertEquals("the cascade ran", 0L, f.count("ch_reaction"))
    }

    /** The unique constraints beside the primary keys: a generation's namespace, one candidate per sender and epoch. */
    @Test
    fun aGuardAlsoStopsAConflictOnAUniqueConstraintThatIsNotTheKey() = ChannelFixture().use { f ->
        f.put("ch_generation")
        for (form in forms) {
            val (sql, args) = f.sql("ch_generation", mapOf("generation" to 7L), verb = form)
            f.db.rejects("ch_generation rows are never replaced", sql, *args.toTypedArray())
        }
        assertEquals(1L, f.count("ch_generation"))
        f.put("ch_candidate")
        for (form in forms) {
            // another commit by the same sender for the same epoch: one candidate per sender
            val (sql, args) = f.sql("ch_candidate", mapOf("hash" to chBytes(32, 77)), verb = form)
            f.db.rejects("ch_candidate rows are never replaced", sql, *args.toTypedArray())
            // the same commit claimed by another sender: the key
            val (sql2, args2) = f.sql("ch_candidate", mapOf("sender" to chBytes(32, 78)), verb = form)
            f.db.rejects("ch_candidate rows are never replaced", sql2, *args2.toTypedArray())
        }
        assertEquals(1L, f.count("ch_candidate"))
        // another epoch's candidate by the same sender is another key
        f.put("ch_candidate", "epoch" to 1L)
        assertEquals(2L, f.count("ch_candidate"))
    }

    /**
     * A key that differs from the default row's in every key column, so that the only thing a second row can
     * conflict on is the hidden rowid. Only the two tables that have one.
     */
    private val other = chBytes(32, 0xC2)
    private val otherKeys: Map<String, Map<String, Any?>> = mapOf(
        "mls_kv" to mapOf("k" to chBytes(20, 99)),
        "ch_join_request" to mapOf("hash" to chBytes(32, 0x99)),
    )

    /**
     * The two tables that have a hidden rowid (`mls_kv` and `ch_join_request`; every other channel table is
     * WITHOUT ROWID, T33) conflict on it too, as the `outbox_op` guard of migration 3 does: an insert that names the
     * rowid of a row with another key would make REPLACE delete that row, with no trigger to see it. Each table is
     * judged alone, on a fresh database: the refusal must carry the guard's own message, and the same row with no
     * rowid named must go in, which shows that the refusal was the rowid and nothing else.
     */
    @Test
    fun everyRowidTableRefusesAnInsertThatNamesAnExistingRowid() {
        assertEquals(ChannelSchema.rowidTables, otherKeys.keys)
        assertTrue(ChannelSchema.rowidTables.all { it in ChannelSchema.tables - ChannelSchema.unguarded })
        for (table in ChannelSchema.rowidTables) ChannelFixture().use { f ->
            f.put("ch_channel", "channel_id" to other)
            f.put(table)
            val rowid = f.db.queryLong("SELECT rowid FROM $table ORDER BY rowid LIMIT 1")
            val before = f.count(table)
            val key = otherKeys.getValue(table)
            val (sql, args) = f.sql(table, key + ("rowid" to rowid), verb = "INSERT OR REPLACE")
            f.db.rejects("$table rows are never replaced", sql, *args.toTypedArray())
            assertEquals(table, before, f.count(table))
            // the same row, no rowid named: a plain insert
            val (plain, plainArgs) = f.sql(table, key)
            f.db.exec(plain, plainArgs)
            assertEquals(table, before + 1, f.count(table))
        }
    }

    /**
     * An insert that names no rowid has none for the guard to compare: in a BEFORE trigger `NEW.rowid` is -1, which
     * the first version took for "matches no row" - true until a row with rowid -1 exists, and then every later plain
     * insert into the table aborted with "never replaced" (the review of S3 made one with an explicit rowid of -1).
     * An AFTER INSERT check now refuses any row stored with a rowid below 1, so no such row can exist.
     */
    @Test
    fun aRowidTableNeverHoldsARowidBelowOneSoAnInsertThatNamesNoneNeverCollidesWithOne() {
        for (table in ChannelSchema.rowidTables) ChannelFixture().use { f ->
            f.put("ch_channel", "channel_id" to other)
            f.parents(table)
            for (rowid in listOf(-1L, 0L, -7L)) {
                val (sql, args) = f.sql(table, mapOf("rowid" to rowid))
                f.db.rejects("$table rows have a rowid of 1 or more", sql, *args.toTypedArray())
                val (replace, replaceArgs) = f.sql(table, mapOf("rowid" to rowid), verb = "INSERT OR REPLACE")
                f.db.rejects("$table rows have a rowid of 1 or more", replace, *replaceArgs.toTypedArray())
                assertEquals("$table: the refused row was not stored", 0L, f.count(table))
            }
            // the table still takes a plain insert, and a free positive rowid named
            f.put(table)
            val key = otherKeys.getValue(table)
            val (named, namedArgs) = f.sql(table, key + ("rowid" to 1_000L))
            f.db.exec(named, namedArgs)
            assertEquals(table, 1_000L, f.db.queryLong("SELECT max(rowid) FROM $table"))
            assertEquals(table, 2L, f.count(table))
        }
    }

    /**
     * A row keeps the rowid it was numbered with: an UPDATE that moved it - to -1, which would make every later plain
     * insert "conflict" with it, or onto another row's, which would delete that row (`UPDATE OR REPLACE`), or past
     * it, which would reorder an arrival order - is refused.
     */
    @Test
    fun aRowKeepsItsRowidAndAnUpdateThatWouldMoveItIsRefused() {
        for (table in ChannelSchema.rowidTables) ChannelFixture().use { f ->
            f.put("ch_channel", "channel_id" to other)
            f.put(table)
            val key = otherKeys.getValue(table)
            val (plain, plainArgs) = f.sql(table, key)
            f.db.exec(plain, plainArgs)
            val rowids = ArrayList<Long>()
            f.db.query("SELECT rowid FROM $table ORDER BY rowid") { rowids += it.long(0) }
            assertEquals(table, 2, rowids.size)
            for (target in listOf(-1L, 0L, 1_000L, rowids[1])) {
                f.db.rejects("$table rows keep their rowid", "UPDATE $table SET rowid = $target WHERE rowid = ${rowids[0]}")
                f.db.rejects("$table rows keep their rowid", "UPDATE OR REPLACE $table SET rowid = $target WHERE rowid = ${rowids[0]}")
            }
            val after = ArrayList<Long>()
            f.db.query("SELECT rowid FROM $table ORDER BY rowid") { after += it.long(0) }
            assertEquals("$table: no row moved, none was deleted", rowids, after)
            // an UPDATE that leaves the rowid where it is is no move
            assertEquals(table, 2, f.db.execUpdate("UPDATE $table SET rowid = rowid"))
        }
    }

    /** The other 24 tables have no rowid to name: T33's "random WITHOUT ROWID keys". */
    @Test
    fun theOtherTablesHaveNoRowidToName() {
        for (table in ChannelSchema.withoutRowidTables) ChannelFixture().use { f ->
            f.parents(table)
            val (sql, args) = f.sql(table, mapOf("rowid" to 5L))
            f.db.rejects("has no column named rowid", sql, *args.toTypedArray())
        }
    }

    /** The two OpenMLS tables' keys: `mls_kv` by (channel, key), `mls_global_kv` by key alone. */
    @Test
    fun theOpenMlsTablesKeepTheirKeysApart() = ChannelFixture().use { f ->
        f.put("mls_kv")
        f.put("mls_global_kv")
        // A key that does not exist, with no rowid named, is a plain insert.
        f.put("mls_kv", "k" to chBytes(20, 98))
        f.put("mls_global_kv", "k" to chBytes(20, 98))
        assertEquals(2L, f.count("mls_kv"))
        // The same k under another channel is another row of mls_kv; mls_global_kv is keyed by k alone.
        f.put("ch_channel", "channel_id" to chBytes(32, 0xC2))
        f.put("mls_kv", "channel_id" to chBytes(32, 0xC2))
        val (sql, args) = f.sql("mls_global_kv", mapOf("channel_id" to chBytes(32, 0xC2)), verb = "INSERT OR REPLACE")
        f.db.rejects("mls_global_kv rows are never replaced", sql, *args.toTypedArray())
        assertTrue(f.count("mls_kv") == 3L)
    }

    /** Writers are UPDATE-then-INSERT pairs: the update of a row that exists is not an insert, so no guard stands in its way. */
    @Test
    fun anUpdateOfARowThatExistsPassesTheGuardAndAnInsertOfANewKeyToo() = ChannelFixture().use { f ->
        f.put("mls_kv")
        assertEquals(1, f.db.execUpdate("UPDATE mls_kv SET v_env = ? WHERE channel_id = ? AND k = ?", listOf(chBytes(120, 5), ChannelFixture.CH, chBytes(20, 12))))
        assertEquals(0, f.db.execUpdate("UPDATE mls_kv SET v_env = ? WHERE channel_id = ? AND k = ?", listOf(chBytes(120, 5), ChannelFixture.CH, chBytes(20, 55))))
        f.put("mls_kv", "k" to chBytes(20, 55), "v_env" to chBytes(120, 5))
        assertEquals(2L, f.count("mls_kv"))
    }
}
