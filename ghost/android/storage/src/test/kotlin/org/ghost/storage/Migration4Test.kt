package org.ghost.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Migration 4 (Phase 9 design §13.6 steps 0–4) with the G-9 test of §21.13 point 9: the rebuilt
 * `outbox_op` and `outbox_delivery` differ from the released v2 tables in the `ttl_seconds` CHECK
 * and in nothing else, every trigger and index naming them is recreated identically, and every row
 * and `outbox_op` rowid survives on a fixture holding ops and deliveries in every state, in-flight
 * leases and every outcome.
 */
class Migration4Test {
    private val upToV3 = Schema.migrations.filter { it.version <= 3 }

    private fun atV3(): JdbcSqlExecutor = JdbcSqlExecutor().also { MigrationRunner(it, upToV3).migrate() }

    /** Identifier quoting (`ALTER TABLE ... RENAME` adds it) and whitespace are not schema differences. */
    private fun normalize(sql: String): String = sql.replace("\"", "").replace(Regex("\\s+"), " ").trim()

    private fun JdbcSqlExecutor.objectsNaming(vararg tables: String): List<String> {
        val out = ArrayList<String>()
        query("SELECT type, name, COALESCE(sql, '') FROM sqlite_master ORDER BY type, name") { row ->
            val sql = row.string(2)
            if (tables.any { sql.contains(it) }) out += "${row.string(0)}|${row.string(1)}|${normalize(sql)}"
        }
        return out
    }

    private fun JdbcSqlExecutor.pragmaRows(pragma: String): List<String> {
        val out = ArrayList<String>()
        query("PRAGMA $pragma") { row ->
            val cells = ArrayList<String>()
            var i = 0
            while (true) {
                val cell = try {
                    if (row.isNull(i)) "null" else row.string(i)
                } catch (e: java.sql.SQLException) {
                    break
                }
                cells += cell
                i++
            }
            out += cells.joinToString(",")
        }
        return out
    }

    private fun JdbcSqlExecutor.shape(table: String): List<String> =
        pragmaRows("table_info($table)") + pragmaRows("foreign_key_list($table)") + pragmaRows("index_list($table)")

    /**
     * Ops and deliveries in every state at v3: three ops with explicit, non-contiguous rowids, every
     * outcome, a released op, a wiped payload, an in-flight lease and a possible copy.
     */
    private fun seedOutbox(db: JdbcSqlExecutor) {
        db.exec(
            "INSERT INTO relay_directory(relay_id, onion_address, operator_id, state, source) VALUES (1, ?, ?, 'active', 'config')",
            listOf(onion(1), bytes(16, 1)),
        )
        db.exec(
            "INSERT INTO relay_directory(relay_id, onion_address, operator_id, state, source) VALUES (2, ?, ?, 'active', 'config')",
            listOf(onion(2), bytes(16, 2)),
        )
        db.exec("INSERT INTO sync_namespace(namespace_id, consumer, listening) VALUES (?, 'dm', 1)", listOf(bytes(32, 1)))
        for ((rowid, i) in listOf(5 to 1, 9 to 2, 14 to 3)) {
            db.exec(
                "INSERT INTO outbox_op(rowid, operation_id, namespace_id, blob_hash, ciphertext, ttl_seconds, not_before_minute, " +
                    "deadline_hour, required_operators, outcome, released) VALUES (?, ?, ?, ?, ?, 604800, 60, 7200, 2, 'pending', 0)",
                listOf(rowid, opId(i), bytes(32, 1), hash(i), bytes(1024, i)),
            )
            for (relay in 1..2) {
                db.exec(
                    "INSERT INTO outbox_delivery(operation_id, relay_id, state, next_attempt_minute) VALUES (?, ?, 'pending', 60)",
                    listOf(opId(i), relay),
                )
            }
        }
        // op1: one delivery waiting for a capability, one acked with a possible copy.
        db.exec("UPDATE outbox_delivery SET state = 'wait_capability' WHERE operation_id = ? AND relay_id = 1", listOf(opId(1)))
        db.exec(
            "UPDATE outbox_delivery SET state = 'acked', ack_minute = 120, copy_hour = 3600, attempts = 2 WHERE operation_id = ? AND relay_id = 2",
            listOf(opId(1)),
        )
        // op2: verified and failed, decided sent and released, payload wiped.
        db.exec("UPDATE outbox_delivery SET state = 'verified', copy_hour = 3600 WHERE operation_id = ? AND relay_id = 1", listOf(opId(2)))
        db.exec("UPDATE outbox_delivery SET state = 'failed', strikes = 2 WHERE operation_id = ? AND relay_id = 2", listOf(opId(2)))
        db.exec("UPDATE outbox_op SET outcome = 'sent' WHERE operation_id = ?", listOf(opId(2)))
        db.exec("UPDATE outbox_op SET ciphertext = NULL WHERE operation_id = ?", listOf(opId(2)))
        db.exec("UPDATE outbox_op SET released = 1 WHERE operation_id = ?", listOf(opId(2)))
        // op3: one lease in flight, one closed; the op is indeterminate.
        db.exec(
            "UPDATE outbox_delivery SET inflight = 1, lease_hour = 7200, attempts = 1 WHERE operation_id = ? AND relay_id = 1",
            listOf(opId(3)),
        )
        db.exec("UPDATE outbox_delivery SET state = 'closed' WHERE operation_id = ? AND relay_id = 2", listOf(opId(3)))
        db.exec("UPDATE outbox_op SET outcome = 'indeterminate' WHERE operation_id = ?", listOf(opId(3)))
    }

    private fun JdbcSqlExecutor.dump(sql: String): List<String> {
        val out = ArrayList<String>()
        query(sql) { row ->
            val cells = ArrayList<String>()
            var i = 0
            while (true) {
                val cell = try {
                    if (row.isNull(i)) "null" else row.string(i)
                } catch (e: java.sql.SQLException) {
                    break
                }
                cells += cell
                i++
            }
            out += cells.joinToString("|")
        }
        return out
    }

    private val opDump =
        "SELECT rowid, hex(operation_id), hex(namespace_id), hex(blob_hash), hex(COALESCE(ciphertext, x'')), ttl_seconds, " +
            "not_before_minute, deadline_hour, required_operators, outcome, released FROM outbox_op ORDER BY rowid"
    private val deliveryDump =
        "SELECT hex(operation_id), relay_id, state, attempts, next_attempt_minute, inflight, lease_hour, copy_hour, ack_minute, " +
            "strikes FROM outbox_delivery ORDER BY operation_id, relay_id"

    @Test
    fun theRebuiltOutboxTablesDifferOnlyInTheTtlCheckAndKeepEveryRowAndRowid() = atV3().use { db ->
        seedOutbox(db)
        val beforeObjects = db.objectsNaming("outbox_op", "outbox_delivery")
        val beforeOpShape = db.shape("outbox_op")
        val beforeDeliveryShape = db.shape("outbox_delivery")
        val beforeOps = db.dump(opDump)
        val beforeDeliveries = db.dump(deliveryDump)
        assertEquals(3, beforeOps.size)
        assertEquals(6, beforeDeliveries.size)

        assertEquals(listOf(4, 5, 6, 7, 8, 9), MigrationRunner(db).migrate())
        MigrationRunner(db).verifyIntegrity()

        // Trigger and index rows are identical by (type, name, sql); the two table rows differ in
        // the ttl_seconds CHECK alone.
        val afterObjects = db.objectsNaming("outbox_op", "outbox_delivery")
        val ttlPatched = afterObjects.map { it.replace("ttl_seconds IN (3600, 86400", "ttl_seconds IN (86400") }
        assertEquals(beforeObjects, ttlPatched)
        assertTrue("the new table really admits 3600", afterObjects.any { it.contains("ttl_seconds IN (3600, 86400") })
        assertEquals(beforeOpShape, db.shape("outbox_op"))
        assertEquals(beforeDeliveryShape, db.shape("outbox_delivery"))
        assertEquals(beforeOps, db.dump(opDump))
        assertEquals(beforeDeliveries, db.dump(deliveryDump))
        assertEquals(listOf("5", "9", "14"), db.dump("SELECT rowid FROM outbox_op ORDER BY rowid"))
        assertNull(db.queryLong("PRAGMA foreign_key_check"))
        assertEquals("ok", db.queryString("PRAGMA integrity_check"))

        // The rebuilt tables keep their rules: the v2 triggers and the v3 guards still fire.
        db.rejects("outbox_op identity is immutable", "UPDATE outbox_op SET ttl_seconds = 86400 WHERE operation_id = ?", opId(1))
        db.rejects(
            "outbox_op rows are never replaced",
            "INSERT OR REPLACE INTO outbox_op(operation_id, namespace_id, blob_hash, ciphertext, ttl_seconds, not_before_minute, " +
                "required_operators, outcome) VALUES (?, ?, ?, ?, 604800, 0, 2, 'pending')",
            opId(1), bytes(32, 1), hash(90), bytes(1024, 9),
        )
        db.rejects("illegal delivery transition", "UPDATE outbox_delivery SET state = 'pending' WHERE operation_id = ? AND relay_id = 1", opId(2))
        // And the one-hour bucket the rebuild was for.
        assertEquals(
            1,
            db.changes(
                "INSERT INTO outbox_op(operation_id, namespace_id, blob_hash, ciphertext, ttl_seconds, not_before_minute, " +
                    "required_operators, outcome) VALUES (?, ?, ?, ?, 3600, 0, 2, 'pending')",
                opId(50), bytes(32, 1), hash(50), bytes(1024, 5),
            ),
        )
    }

    /**
     * Step 2 on a database that already holds fetched rows: the new column is filled from the
     * row's retention, which is `ceil7(day(E) + 24)`, so `(retain_until_day − 23) days` is above
     * every relay expiry the row can have had. A consumer therefore never reads an unknown expiry
     * as an expiry of 0 (deletion on arrival); listed rows and tombstones keep none.
     */
    @Test
    fun aRowFetchedBeforeTheUpgradeGetsAnExpiryBoundedByItsRetention() = atV3().use { db ->
        db.exec(
            "INSERT INTO relay_directory(relay_id, onion_address, operator_id, state, source) VALUES (1, ?, ?, 'active', 'config')",
            listOf(onion(1), bytes(16, 1)),
        )
        db.exec("INSERT INTO sync_namespace(namespace_id, consumer, listening) VALUES (?, 'dm', 1)", listOf(bytes(32, 1)))
        for (i in 1..3) {
            db.exec(
                "INSERT INTO inbox_blob(namespace_id, blob_hash, state, retain_until_day) VALUES (?, ?, 'listed', ?)",
                listOf(bytes(32, 1), hash(i), 112L + 7 * i),
            )
        }
        db.exec(
            "UPDATE inbox_blob SET state = 'fetched', ciphertext = ?, fetch_seq = 1 WHERE namespace_id = ? AND blob_hash = ?",
            listOf(bytes(1024, 1), bytes(32, 1), hash(1)),
        )
        db.exec(
            "UPDATE inbox_blob SET state = 'fetched', ciphertext = ?, fetch_seq = 2 WHERE namespace_id = ? AND blob_hash = ?",
            listOf(bytes(1024, 3), bytes(32, 1), hash(3)),
        )
        db.exec(
            "UPDATE inbox_blob SET state = 'done', ciphertext = NULL, fetch_seq = NULL WHERE namespace_id = ? AND blob_hash = ?",
            listOf(bytes(32, 1), hash(3)),
        )

        assertEquals(listOf(4, 5, 6, 7, 8, 9), MigrationRunner(db).migrate())
        MigrationRunner(db).verifyIntegrity()

        val fetched = db.queryLong("SELECT relay_expiry_hour FROM inbox_blob WHERE blob_hash = ?", listOf(hash(1)))
        assertEquals((112L + 7 - 23) * 86_400, fetched)
        assertEquals("an expiry hour is a whole hour", 0L, checkNotNull(fetched) % 3600)
        assertNull("a listed row has no relay expiry", db.queryLong("SELECT relay_expiry_hour FROM inbox_blob WHERE blob_hash = ?", listOf(hash(2))))
        assertNull("a tombstone carries no relay time", db.queryLong("SELECT relay_expiry_hour FROM inbox_blob WHERE blob_hash = ?", listOf(hash(3))))
        // The filled row still consumes: the expiry goes with the ciphertext (§13.3 item 2).
        assertEquals(
            1,
            db.changes(
                "UPDATE inbox_blob SET state = 'done', ciphertext = NULL, fetch_seq = NULL, relay_expiry_hour = NULL " +
                    "WHERE namespace_id = ? AND blob_hash = ?",
                bytes(32, 1), hash(1),
            ),
        )
    }

    /** Step 2: the relay expiry of a fetched blob, and only of a fetched blob. */
    @Test
    fun theRelayExpiryIsKeptOnlyWhileFetched() = SyncFixture().use { f ->
        val db = f.db
        f.listed(1)
        db.rejects(
            "relay expiry is kept only while fetched",
            "INSERT INTO inbox_blob(namespace_id, blob_hash, state, retain_until_day, relay_expiry_hour) VALUES (?, ?, 'listed', 112, 3600)",
            f.ns, hash(2),
        )
        assertEquals(
            1,
            db.changes(
                "UPDATE inbox_blob SET state = 'fetched', ciphertext = ?, fetch_seq = 1, relay_expiry_hour = 7200 " +
                    "WHERE namespace_id = ? AND blob_hash = ?",
                bytes(1024, 1), f.ns, hash(1),
            ),
        )
        assertEquals(7200L, db.queryLong("SELECT relay_expiry_hour FROM inbox_blob WHERE namespace_id = ? AND blob_hash = ?", listOf(f.ns, hash(1))))
        db.rejects(
            CHECK_FAILED,
            "UPDATE inbox_blob SET relay_expiry_hour = 3601 WHERE namespace_id = ? AND blob_hash = ?",
            f.ns, hash(1),
        )
        // Consuming the row must drop the expiry in the same statement.
        db.rejects(
            "relay expiry is kept only while fetched",
            "UPDATE inbox_blob SET state = 'done', ciphertext = NULL, fetch_seq = NULL WHERE namespace_id = ? AND blob_hash = ?",
            f.ns, hash(1),
        )
        assertEquals(
            1,
            db.changes(
                "UPDATE inbox_blob SET state = 'done', ciphertext = NULL, fetch_seq = NULL, relay_expiry_hour = NULL " +
                    "WHERE namespace_id = ? AND blob_hash = ?",
                f.ns, hash(1),
            ),
        )
    }

    /** Step 4: the registration table's CHECKs, its state trigger and its REPLACE guard. */
    @Test
    fun keyRegistrationsKeepTheirKeyAndMoveOnlyBetweenPendingAndDone() = SyncFixture().use { f ->
        val db = f.db
        val insert = "INSERT INTO relay_key_registration(relay_id, namespace_id, period_id, kind, verifier, request_id, state, " +
            "inflight, lease_hour, attempts, next_attempt_minute, valid_until_hour) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 60, ?)"
        fun add(period: Long, kind: String, state: String = "pending", inflight: Int = 0, lease: Long? = null, validUntil: Long? = null) =
            db.changes(insert, 1, f.ns, period, kind, bytes(32, 7), bytes(16, 8), state, inflight, lease, validUntil)

        for (kind in listOf("read", "deposit", "fetch")) assertEquals(1, add(2960, kind))
        db.rejects(CHECK_FAILED, insert, 1, f.ns, 2960L, "write", bytes(32, 7), bytes(16, 8), "pending", 0, null, null)
        db.rejects(CHECK_FAILED, insert, 1, f.ns, -1L, "read", bytes(32, 7), bytes(16, 8), "pending", 0, null, null)
        db.rejects(CHECK_FAILED, insert, 1, f.ns, 2961L, "read", bytes(31, 7), bytes(16, 8), "pending", 0, null, null)
        db.rejects(CHECK_FAILED, insert, 1, f.ns, 2961L, "read", bytes(32, 7), bytes(15, 8), "pending", 0, null, null)
        // done needs a validity, pending must not carry one, a lease needs its hour, done is idle.
        db.rejects(CHECK_FAILED, insert, 1, f.ns, 2961L, "read", bytes(32, 7), bytes(16, 8), "done", 0, null, null)
        db.rejects(CHECK_FAILED, insert, 1, f.ns, 2961L, "read", bytes(32, 7), bytes(16, 8), "pending", 0, null, 7200L)
        db.rejects(CHECK_FAILED, insert, 1, f.ns, 2961L, "read", bytes(32, 7), bytes(16, 8), "pending", 1, null, null)
        db.rejects(CHECK_FAILED, insert, 1, f.ns, 2961L, "read", bytes(32, 7), bytes(16, 8), "done", 1, 3600L, 7200L)
        assertEquals(1, add(2961, "read", state = "pending", inflight = 1, lease = 3600))

        val row = "WHERE relay_id = 1 AND namespace_id = ? AND period_id = 2960 AND kind = 'read'"
        db.rejects("a registration keeps its key and verifier", "UPDATE relay_key_registration SET verifier = ? $row", bytes(32, 9), f.ns)
        db.rejects("a registration keeps its key and verifier", "UPDATE relay_key_registration SET kind = 'deposit' $row", f.ns)
        db.rejects("a registration keeps its key and verifier", "UPDATE relay_key_registration SET period_id = 2962 $row", f.ns)
        assertEquals(1, db.changes("UPDATE relay_key_registration SET state = 'done', valid_until_hour = 7200 $row", f.ns))
        // Healing takes a done row back to pending; nothing else moves.
        assertEquals(1, db.changes("UPDATE relay_key_registration SET state = 'pending', valid_until_hour = NULL $row", f.ns))
        db.rejects(
            "relay_key_registration rows are never replaced",
            "INSERT OR REPLACE INTO relay_key_registration(relay_id, namespace_id, period_id, kind, verifier, request_id, state, " +
                "next_attempt_minute) VALUES (1, ?, 2960, 'read', ?, ?, 'pending', 60)",
            f.ns, bytes(32, 9), bytes(16, 9),
        )
        // Removing the namespace or the relay takes its registrations with it.
        assertEquals(4L, f.count("relay_key_registration"))
        db.exec("DELETE FROM relay_directory WHERE relay_id = 1")
        assertEquals(0L, f.count("relay_key_registration"))
    }
}
