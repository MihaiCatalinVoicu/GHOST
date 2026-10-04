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
 * `INSERT OR IGNORE`, which deletes nothing.
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
     * conflict on is the hidden rowid. A table keyed by the channel alone gets another channel (the test creates
     * [other]); `ch_channel` itself gets a third.
     */
    private val other = chBytes(32, 0xC2)
    private val otherKeys: Map<String, Map<String, Any?>> = mapOf(
        "ch_channel" to mapOf("channel_id" to chBytes(32, 0xC3)),
        "ch_liveness" to mapOf("channel_id" to other),
        "ch_schedule" to mapOf("channel_id" to other),
        "ch_generation" to mapOf("generation" to 1L, "namespace_id" to chBytes(32, 0x99), "state" to "pending_switch"),
        "ch_epoch" to mapOf("epoch" to 1L),
        "ch_epoch_log" to mapOf("epoch" to 1L),
        "ch_candidate" to mapOf("hash" to chBytes(32, 0x99), "sender" to chBytes(32, 0x98)),
        "ch_fork_signal" to mapOf("hash" to chBytes(32, 0x99)),
        "mls_kv" to mapOf("k" to chBytes(20, 99)),
        "mls_global_kv" to mapOf("k" to chBytes(20, 99)),
        "ch_post" to mapOf("op_id" to chBytes(16, 0x99)),
        "ch_reaction" to mapOf("author" to chBytes(32, 0x99)),
        "ch_pending_post" to mapOf("op_id" to chBytes(16, 0x99)),
        "ch_outbound_op" to mapOf("operation_id" to chBytes(16, 0x99)),
        "ch_reveal" to mapOf("peer" to chBytes(32, 0x99)),
        "ch_join" to mapOf("kp_ref" to chBytes(32, 0x99)),
        "ch_join_request" to mapOf("hash" to chBytes(32, 0x99)),
        "ch_invite_issued" to mapOf("invite_id" to chBytes(16, 0x99)),
        "ch_member_seen" to mapOf("member" to chBytes(32, 0x99)),
        "ch_invite_own" to mapOf("invite_id" to chBytes(16, 0x99)),
        "ch_sponsor" to mapOf("member" to chBytes(32, 0x99)),
        "ch_member_refresh" to mapOf("member" to chBytes(32, 0x99)),
        "ch_request" to mapOf("subject" to chBytes(32, 0x99)),
        "ch_box_key" to mapOf("box_pk" to chBytes(32, 0x99)),
    )

    /**
     * Every table that has a hidden rowid (the 24 that §9 does not mark WITHOUT ROWID) conflicts on it too, as
     * the `outbox_op` guard of migration 3 does: an insert that names the rowid of a row with another key would
     * make REPLACE delete that row, with no trigger to see it. Each table is judged alone, on a fresh database:
     * the refusal must carry the guard's own message, and the same row with no rowid named must go in, which
     * shows that the refusal was the rowid and nothing else.
     */
    @Test
    fun everyRowidTableRefusesAnInsertThatNamesAnExistingRowid() {
        assertEquals(ChannelSchema.rowidTables, otherKeys.keys)
        assertEquals(ChannelSchema.tables - ChannelSchema.unguarded, ChannelSchema.rowidTables)
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
