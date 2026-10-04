package org.ghost.sync.store

import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * T20 by schema introspection (design §7.2, §11.2 #8): every persisted time column of the sync
 * tables is a `*_minute`, `*_hour` or `*_day` column with a matching CHECK, no other time-like
 * column exists, and a `done` inbox row can carry nothing but (namespace, hash, retain_until_day).
 */
class SchemaIntrospectionTest {
    private val syncTables = listOf(
        "relay_directory", "sync_namespace", "namespace_relay", "relay_capability", "relay_cursor",
        "outbox_op", "outbox_delivery", "inbox_blob", "inbox_source",
        // v4 (Phase 9 design §13.6 step 4)
        "relay_key_registration",
        // v6 (Phase 10 design §9, slice S1a)
        "sync_namespace_fund", "relay_register_capability",
    )

    /** Durations, counters and grid indices that look numeric but are not points in time. */
    private val notTimes = setOf(
        "ttl_seconds", "attempts", "fetch_attempts", "offers", "strikes", "generation", "fetch_seq", "required_operators",
        // A registration's period is an ISO-week index of the grid, not a time (§21.14 schema delta).
        "period_id",
    )

    private fun columns(db: JdbcSqlExecutor, table: String): List<String> {
        val out = ArrayList<String>()
        db.query("PRAGMA table_info($table)") { out += it.string(1) }
        return out
    }

    private fun createSql(db: JdbcSqlExecutor, table: String): String {
        var sql = ""
        db.query("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", listOf(table)) { sql = it.string(0) }
        return sql.replace(Regex("\\s+"), " ")
    }

    @Test
    fun everyTimeColumnHasItsGranularityCheck(): Unit = JdbcSqlExecutor().use { db ->
        MigrationRunner(db).migrate()
        val timeColumns = ArrayList<String>()
        for (table in syncTables) {
            val sql = createSql(db, table)
            assertTrue("missing table $table", sql.isNotEmpty())
            for (column in columns(db, table)) {
                val lower = column.lowercase()
                when {
                    lower.endsWith("_minute") -> {
                        assertTrue("$table.$column needs % 60 = 0", sql.contains("$column % 60 = 0"))
                        timeColumns += "$table.$column"
                    }
                    lower.endsWith("_hour") -> {
                        assertTrue("$table.$column needs % 3600 = 0", sql.contains("$column % 3600 = 0"))
                        timeColumns += "$table.$column"
                    }
                    lower.endsWith("_day") -> {
                        assertTrue("$table.$column needs a CHECK", Regex("CHECK \\([^)]*\\b$column\\b").containsMatchIn(sql))
                        timeColumns += "$table.$column"
                    }
                    else -> {
                        val timeLike = Regex("(_at$|time|date|epoch|_ms$|_seconds$|expir|_ts$|stamp|last_|since|until)").containsMatchIn(lower)
                        assertFalse("$table.$column looks like an unchecked time column", timeLike && lower !in notTimes)
                    }
                }
            }
        }
        // The retention day is also a 7-day boundary (§11.2 #8).
        assertTrue(createSql(db, "inbox_blob").contains("retain_until_day % 7 = 0"))
        // R-M3 (Phase 9 design §13.6): migration 4 grows the sync set from 11 to 15 columns with
        // `inbox_blob.relay_expiry_hour` and the three time columns of `relay_key_registration`.
        assertEquals(
            setOf(
                "relay_directory.retired_day", "relay_capability.expires_hour", "outbox_op.not_before_minute", "outbox_op.deadline_hour",
                "outbox_delivery.next_attempt_minute", "outbox_delivery.lease_hour", "outbox_delivery.copy_hour", "outbox_delivery.ack_minute",
                "inbox_blob.next_fetch_minute", "inbox_blob.offer_after_minute", "inbox_blob.retain_until_day",
                "inbox_blob.relay_expiry_hour",
                "relay_key_registration.lease_hour", "relay_key_registration.next_attempt_minute", "relay_key_registration.valid_until_hour",
                // Phase 10 design §9 (migration 6): the registration capability's floored expiry, 15 -> 16.
                "relay_register_capability.expires_hour",
            ),
            timeColumns.toSet(),
        )
        assertEquals(16, timeColumns.size)
    }

    @Test
    fun aDoneRowCarriesOnlyNamespaceHashAndRetentionDay(): Unit = SyncWorld().use { w ->
        val (ns, _) = w.standardSet()
        w.enqueue(1, ns)
        val h = w.hashOf(1)
        val keep = setOf("namespace_id", "blob_hash", "state", "retain_until_day")
        val others = columns(w.sql, "inbox_blob").filter { it !in keep }
        assertEquals(
            setOf("ciphertext", "fetch_seq", "fetch_attempts", "next_fetch_minute", "offers", "offer_after_minute", "relay_expiry_hour"),
            others.toSet(),
        )
        for (column in others) {
            val value: Any = when (column) {
                "ciphertext" -> ByteArray(1024)
                "next_fetch_minute", "offer_after_minute" -> 60L
                "relay_expiry_hour" -> 3600L
                else -> 1L
            }
            val e = assertThrows("$column must stay empty on a done row", java.sql.SQLException::class.java) {
                w.raw("UPDATE inbox_blob SET $column = ? WHERE namespace_id = ? AND blob_hash = ?", value, ns, h)
            }
            // The relay expiry is refused by its trigger (Phase 9 §13.6 step 2), the rest by CHECKs.
            val expected = if (column == "relay_expiry_hour") "relay expiry is kept only while fetched" else "CHECK constraint failed"
            assertTrue(e.message.orEmpty(), e.message.orEmpty().contains(expected))
        }
        assertEquals(
            1L,
            w.long(
                "SELECT ciphertext IS NULL AND fetch_seq IS NULL AND fetch_attempts = 0 AND next_fetch_minute = 0 " +
                    "AND offers = 0 AND offer_after_minute = 0 AND relay_expiry_hour IS NULL FROM inbox_blob WHERE state = 'done'",
            ),
        )
        // WITHOUT ROWID: no insertion order is kept.
        assertTrue(createSql(w.sql, "inbox_blob").trimEnd().endsWith("WITHOUT ROWID"))
    }
}
