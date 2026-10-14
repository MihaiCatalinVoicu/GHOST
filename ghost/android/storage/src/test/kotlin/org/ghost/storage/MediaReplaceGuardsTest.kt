package org.ghost.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The five REPLACE guards of migration 8 (Phase 11 design §13.6 step 5: "REPLACE guards for the five tables (the F9
 * `replaceGuard` helper)"; Phase 8 design §19.21 point 4; G-DM4 is the source half), slice S3.
 *
 * With `recursive_triggers` off, a row that REPLACE deletes to resolve a PRIMARY KEY or UNIQUE conflict fires no DELETE
 * trigger, and the row written in its place passes no UPDATE trigger. A BEFORE INSERT trigger runs before the conflict
 * is resolved, so each media table refuses an insert that conflicts on **any** of its keys — the primary key, and the
 * second unique key of the two tables that have one (`media_object.message_id`, the partial unique index; `media_blob.file_name`)
 * and the unique tuple of `media_outbound_op` — in every form of insert. The row that exists is untouched by every refused
 * form, and a row with another key goes in. An UPDATE that moves a row onto another row's key is refused too, by the
 * write-once trigger of the table (they fire before the conflict is resolved), so `UPDATE OR REPLACE` deletes nothing.
 *
 * All five tables are WITHOUT ROWID, so there is no rowid to name and no rowid guard (v7's two rowid tables needed them).
 */
class MediaReplaceGuardsTest {

    /** Every form of insert; each is refused for a key that exists. */
    private val insertForms = listOf("INSERT OR REPLACE", "REPLACE", "INSERT OR IGNORE", "INSERT OR ABORT", "INSERT OR ROLLBACK", "INSERT")

    private class Key(val label: String, val table: String, val conflict: Map<String, Any?>)

    /** One conflicting key per entry: the override that makes a new row collide with the default row on that key only. */
    private val keys: List<Key> = listOf(
        Key("media_object.object_id", "media_object", mapOf("message_id" to null)),
        Key("media_object.message_id", "media_object", mapOf("object_id" to mBytes(16, 0xA9))),
        Key("media_upload.object_id", "media_upload", emptyMap()),
        Key("media_blob.blob_hash", "media_blob", mapOf("file_name" to mBytes(16, 0xF9))),
        Key("media_blob.file_name", "media_blob", mapOf("blob_hash" to mBytes(32, 0xC9))),
        Key("media_fragment.(object_id, ordinal)", "media_fragment", emptyMap()),
        Key("media_outbound_op.operation_id", "media_outbound_op", mapOf("ordinal" to 1L)),
        Key("media_outbound_op.(object_id, ordinal, retry_gen, resend_count)", "media_outbound_op", mapOf("operation_id" to mBytes(16, 0xE9))),
    )

    private fun rows(f: MediaFixture, table: String): List<String> {
        val columns = ArrayList<String>()
        f.db.query("PRAGMA table_info($table)") { columns += it.string(1) }
        val out = ArrayList<String>()
        f.db.query("SELECT ${columns.joinToString(" || '|' || ") { "quote($it)" }} FROM $table") { out += it.string(0) }
        return out.sorted()
    }

    @Test
    fun everyFormOfInsertIsRefusedForEveryKeyThatExistsAndLeavesTheRowAsItWas() {
        for (key in keys) MediaFixture().use { f ->
            // The default row, its message where the key is the message, and a second fragment for the op that names ordinal 1.
            f.dmMessage(mBytes(16, 0x91))
            f.put("media_object", "message_id" to mBytes(16, 0x91))
            if (key.table == "media_outbound_op") f.put("media_fragment", "ordinal" to 1L)
            if (key.table != "media_object") f.put(key.table)
            val before = rows(f, key.table)
            val guard = "${key.table} rows are never replaced"
            // The colliding row: the default row with the one override that frees every other key.
            val overrides = if (key.table == "media_object" && key.label.endsWith("message_id")) {
                key.conflict + ("message_id" to mBytes(16, 0x91))
            } else if (key.table == "media_object") {
                key.conflict + ("object_id" to MediaFixture.OUT)
            } else {
                key.conflict
            }
            for (form in insertForms) {
                val (sql, args) = f.sql(key.table, overrides, verb = form)
                f.db.rejects(guard, sql, *args.toTypedArray())
                assertEquals("${key.label} after $form", before, rows(f, key.table))
            }
            // The upsert forms are refused alike (the guard runs before the conflict clause is looked at).
            val (insert, args) = f.sql(key.table, overrides)
            f.db.rejects(guard, "$insert ON CONFLICT DO NOTHING", *args.toTypedArray())
            val conflictTarget = when (key.table) {
                "media_object" -> "object_id"
                "media_upload" -> "object_id"
                "media_blob" -> "blob_hash"
                "media_fragment" -> "object_id, ordinal"
                else -> "operation_id"
            }
            val setColumn = when (key.table) { "media_object" -> "state"; "media_upload" -> "retry_gen"; "media_blob" -> "origin"; "media_fragment" -> "state"; else -> "resend_count" }
            f.db.rejects(guard, "$insert ON CONFLICT($conflictTarget) DO UPDATE SET $setColumn = excluded.$setColumn", *args.toTypedArray())
            assertEquals("${key.label} after the upserts", before, rows(f, key.table))
        }
    }

    /** A row with another key goes in, in every form: the guard refuses the conflict and nothing else. */
    @Test
    fun aRowWithAnotherKeyIsNotTheGuardsBusiness() = MediaFixture().use { f ->
        f.put("media_object")
        f.put("media_upload")
        f.put("media_fragment")
        f.put("media_outbound_op")
        f.put("media_object", "object_id" to mBytes(16, 0xA2))
        f.put("media_upload", "object_id" to mBytes(16, 0xA2))
        f.put("media_blob", "blob_hash" to mBytes(32, 0xC2), "file_name" to mBytes(16, 0xF2))
        f.put("media_fragment", "ordinal" to 1L)
        f.put("media_outbound_op", "operation_id" to mBytes(16, 0xE2), "ordinal" to 1L)
        // Even the verbs that replace, written for a key that is not taken, insert a row (and replace none).
        val (sql, args) = f.sql("media_object", mapOf("object_id" to mBytes(16, 0xA3)), verb = "INSERT OR REPLACE")
        f.db.exec(sql, args)
        assertEquals(mapOf("media_object" to 3L, "media_upload" to 2L, "media_blob" to 2L, "media_fragment" to 2L, "media_outbound_op" to 2L), MediaSchema.tables.associateWith { f.count(it) })
    }

    /**
     * `UPDATE OR REPLACE ... SET <key> = another row's key` would delete the other row with no trigger; the write-once
     * trigger of each table runs first and refuses the change, so no key of a media table can be moved onto another's.
     */
    @Test
    fun anUpdateOntoAnotherRowsKeyIsRefusedBeforeItCanDeleteIt() = MediaFixture().use { f ->
        f.dmMessage(mBytes(16, 0x91))
        f.dmMessage(mBytes(16, 0x92))
        f.put("media_object", "message_id" to mBytes(16, 0x91))
        f.put("media_object", "object_id" to mBytes(16, 0xA2), "message_id" to mBytes(16, 0x92))
        f.put("media_upload")
        f.put("media_upload", "object_id" to mBytes(16, 0xA2))
        f.put("media_blob")
        f.put("media_blob", "blob_hash" to mBytes(32, 0xC2), "file_name" to mBytes(16, 0xF2))
        f.put("media_fragment")
        f.put("media_fragment", "ordinal" to 1L)
        f.put("media_outbound_op")
        f.put("media_outbound_op", "operation_id" to mBytes(16, 0xE2), "ordinal" to 1L)
        val statements = listOf(
            "UPDATE OR REPLACE media_object SET object_id = ? WHERE object_id = ?" to listOf(mBytes(16, 0xA2), MediaFixture.OUT),
            "UPDATE OR REPLACE media_object SET message_id = ? WHERE object_id = ?" to listOf(mBytes(16, 0x92), MediaFixture.OUT),
            "UPDATE OR REPLACE media_upload SET object_id = ? WHERE object_id = ?" to listOf(mBytes(16, 0xA2), MediaFixture.OUT),
            "UPDATE OR REPLACE media_blob SET blob_hash = ? WHERE blob_hash = ?" to listOf(mBytes(32, 0xC2), MediaFixture.BLOB),
            "UPDATE OR REPLACE media_blob SET file_name = ? WHERE blob_hash = ?" to listOf(mBytes(16, 0xF2), MediaFixture.BLOB),
            "UPDATE OR REPLACE media_fragment SET ordinal = 1 WHERE ordinal = 0" to emptyList(),
            "UPDATE OR REPLACE media_outbound_op SET operation_id = ? WHERE operation_id = ?" to listOf(mBytes(16, 0xE2), mBytes(16, 0xE1)),
        )
        val before = MediaSchema.tables.associateWith { rows(f, it) }
        for ((sql, args) in statements) {
            val e = org.junit.Assert.assertThrows(sql, java.sql.SQLException::class.java) { f.db.exec(sql, args) }
            assertTrue("$sql: ${e.message}", e.message.orEmpty().contains("keeps its") || e.message.orEmpty().contains("never changed"))
        }
        assertEquals(before, MediaSchema.tables.associateWith { rows(f, it) })
    }

    /** The guard texts are the shared one: a BEFORE INSERT trigger whose WHEN names every key of its table, in the form `replaceGuard` writes. */
    @Test
    fun theGuardsNameEveryKeyOfTheirTable() = MediaFixture().use { f ->
        val expected = mapOf(
            "media_object" to listOf("NEW.object_id", "NEW.message_id"),
            "media_upload" to listOf("NEW.object_id"),
            "media_blob" to listOf("NEW.blob_hash", "NEW.file_name"),
            "media_fragment" to listOf("NEW.object_id", "NEW.ordinal"),
            "media_outbound_op" to listOf("NEW.operation_id", "NEW.object_id", "NEW.ordinal", "NEW.retry_gen", "NEW.resend_count"),
        )
        for ((table, parts) in expected) {
            val sql = f.db.queryString("SELECT sql FROM sqlite_master WHERE name = ?", listOf("${table}_no_replace"))!!.replace(Regex("\\s+"), " ")
            assertTrue(sql, sql.contains("BEFORE INSERT ON $table WHEN EXISTS (SELECT 1 FROM $table WHERE "))
            for (part in parts) assertTrue("$table misses $part", sql.contains(part))
        }
        // No table of this migration has a rowid, so no guard names one.
        for (table in expected.keys) {
            val sql = f.db.queryString("SELECT sql FROM sqlite_master WHERE name = ?", listOf("${table}_no_replace"))!!
            assertTrue(!sql.contains("rowid"))
        }
    }
}
