package org.ghost.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Every CHECK, UNIQUE and foreign key of migration v2 (docs/design/faza7-sync-engine.md §2.2 and
 * §11), each with an accepted and a rejected case.
 */
class SyncSchemaConstraintsTest {
    private val insertRelay =
        "INSERT INTO relay_directory(onion_address, operator_id, state, source, retired_day) VALUES (?, ?, ?, ?, ?)"

    @Test
    fun relayDirectory() = SyncFixture().use { f ->
        val db = f.db
        // onion_address: 56-character host + ".onion:" + a 1..5 digit port, i.e. 64..68 characters.
        assertEquals(1, db.changes(insertRelay, onion(10, "1"), bytes(16, 10), "active", "config", null))
        assertEquals(1, db.changes(insertRelay, onion(11, "65535"), bytes(16, 11), "active", "manifest", null))
        db.rejects(CHECK_FAILED, insertRelay, onion(12, ""), bytes(16, 12), "active", "config", null)
        db.rejects(CHECK_FAILED, insertRelay, onion(12, "655350"), bytes(16, 12), "active", "config", null)
        db.rejects(CHECK_FAILED, insertRelay, "c".repeat(56) + ".onion/443", bytes(16, 12), "active", "config", null)
        db.rejects(CHECK_FAILED, insertRelay, "c".repeat(55) + ".onion:4430", bytes(16, 12), "active", "config", null)
        db.rejects(UNIQUE_FAILED, insertRelay, onion(10, "1"), bytes(16, 12), "active", "config", null)
        // operator_id is 16 bytes.
        db.rejects(CHECK_FAILED, insertRelay, onion(12), bytes(15, 12), "active", "config", null)
        db.rejects(CHECK_FAILED, insertRelay, onion(12), bytes(17, 12), "active", "config", null)
        // state, source, and retired_day <-> retired.
        db.rejects(CHECK_FAILED, insertRelay, onion(12), bytes(16, 12), "gone", "config", null)
        db.rejects(CHECK_FAILED, insertRelay, onion(12), bytes(16, 12), "active", "dns", null)
        db.rejects(CHECK_FAILED, insertRelay, onion(12), bytes(16, 12), "retired", "config", null)
        db.rejects(CHECK_FAILED, insertRelay, onion(12), bytes(16, 12), "active", "config", 5)
        db.rejects(CHECK_FAILED, insertRelay, onion(12), bytes(16, 12), "retired", "config", -1)
        assertEquals(1, db.changes(insertRelay, onion(12), bytes(16, 12), "retired", "config", 0))
        // Retire and reactivate the same row.
        assertEquals(1, db.changes("UPDATE relay_directory SET state = 'retired', retired_day = 20000 WHERE relay_id = 1"))
        db.rejects(CHECK_FAILED, "UPDATE relay_directory SET state = 'active' WHERE relay_id = 1")
        assertEquals(1, db.changes("UPDATE relay_directory SET state = 'active', retired_day = NULL WHERE relay_id = 1"))
    }

    @Test
    fun syncNamespace() = SyncFixture().use { f ->
        val db = f.db
        val insert = "INSERT INTO sync_namespace(namespace_id, consumer, listening) VALUES (?, ?, ?)"
        for ((i, consumer) in listOf("dm", "prekeys", "channel", "media", "identity").withIndex()) {
            assertEquals(1, db.changes(insert, bytes(32, 10 + i), consumer, i % 2))
        }
        // send_delay defaults to 'default' and accepts only the three override values (§11.2 #15).
        assertEquals("default", db.queryString("SELECT send_delay FROM sync_namespace WHERE namespace_id = ?", listOf(f.ns)))
        for (value in listOf("on", "off", "default")) {
            assertEquals(1, db.changes("UPDATE sync_namespace SET send_delay = ? WHERE namespace_id = ?", value, f.ns))
        }
        db.rejects(CHECK_FAILED, "UPDATE sync_namespace SET send_delay = 'high' WHERE namespace_id = ?", f.ns)
        db.rejects("NOT NULL constraint failed", "UPDATE sync_namespace SET send_delay = NULL WHERE namespace_id = ?", f.ns)
        db.rejects(CHECK_FAILED, insert, bytes(31, 20), "dm", 1)
        db.rejects(CHECK_FAILED, insert, bytes(33, 20), "dm", 1)
        db.rejects(CHECK_FAILED, insert, bytes(32, 20), "forum", 1)
        db.rejects(CHECK_FAILED, insert, bytes(32, 20), "dm", 2)
        db.rejects(UNIQUE_FAILED, insert, f.ns, "dm", 1)
    }

    @Test
    fun namespaceRelay() = SyncFixture().use { f ->
        val db = f.db
        val insert = "INSERT INTO namespace_relay(namespace_id, relay_id) VALUES (?, ?)"
        assertEquals(1, db.changes(insert, f.ns, 1))
        assertEquals(1, db.changes(insert, f.ns, 2))
        db.rejects(UNIQUE_FAILED, insert, f.ns, 1)
        db.rejects(FOREIGN_KEY_FAILED, insert, bytes(32, 9), 1)
        db.rejects(FOREIGN_KEY_FAILED, insert, f.ns, 99)
    }

    @Test
    fun relayCapability() = SyncFixture().use { f ->
        val db = f.db
        val insert =
            "INSERT INTO relay_capability(relay_id, namespace_id, kind, token, expires_hour, state, generation) VALUES (?, ?, ?, ?, ?, ?, ?)"
        assertEquals(1, db.changes(insert, 1, f.ns, "write", bytes(82, 1), 3600L * 500_000, "usable", 1))
        assertEquals(1, db.changes(insert, 1, f.ns, "read", bytes(1, 1), null, "rejected", 7))
        assertEquals(1, db.changes(insert, 2, f.ns, "read", bytes(512, 1), 0, "exhausted", 1))
        db.rejects(UNIQUE_FAILED, insert, 1, f.ns, "write", bytes(82, 2), null, "usable", 2)
        db.rejects(CHECK_FAILED, insert, 2, f.ns, "admin", bytes(82, 1), null, "usable", 1)
        db.rejects(CHECK_FAILED, insert, 2, f.ns, "write", ByteArray(0), null, "usable", 1)
        db.rejects(CHECK_FAILED, insert, 2, f.ns, "write", bytes(513, 1), null, "usable", 1)
        db.rejects(CHECK_FAILED, insert, 2, f.ns, "write", bytes(82, 1), 3601, "usable", 1)
        db.rejects(CHECK_FAILED, insert, 2, f.ns, "write", bytes(82, 1), null, "revoked", 1)
        db.rejects(CHECK_FAILED, insert, 2, f.ns, "write", bytes(82, 1), null, "usable", 0)
        db.rejects(FOREIGN_KEY_FAILED, insert, 99, f.ns, "write", bytes(82, 1), null, "usable", 1)
        db.rejects(FOREIGN_KEY_FAILED, insert, 2, bytes(32, 9), "write", bytes(82, 1), null, "usable", 1)
    }

    @Test
    fun relayCursor() = SyncFixture().use { f ->
        val db = f.db
        val insert = "INSERT INTO relay_cursor(relay_id, namespace_id, cursor) VALUES (?, ?, ?)"
        assertEquals(1, db.changes(insert, 1, f.ns, bytes(8, 1)))
        for (size in listOf(0, 7, 9)) db.rejects(CHECK_FAILED, insert, 2, f.ns, bytes(size, 1))
        db.rejects(UNIQUE_FAILED, insert, 1, f.ns, bytes(8, 2))
        db.rejects(FOREIGN_KEY_FAILED, insert, 99, f.ns, bytes(8, 1))
        db.rejects(FOREIGN_KEY_FAILED, insert, 2, bytes(32, 9), bytes(8, 1))
        // The cursor is replaced by UPSERT (§4.1).
        assertEquals(
            1,
            db.changes(
                "INSERT INTO relay_cursor(relay_id, namespace_id, cursor) VALUES (?, ?, ?) " +
                    "ON CONFLICT(relay_id, namespace_id) DO UPDATE SET cursor = excluded.cursor",
                1, f.ns, bytes(8, 3),
            ),
        )
        assertEquals(bytes(8, 3).toList(), db.queryBlob("SELECT cursor FROM relay_cursor WHERE relay_id = 1")!!.toList())
    }

    private val insertOp =
        "INSERT INTO outbox_op(operation_id, namespace_id, blob_hash, ciphertext, ttl_seconds, not_before_minute, deadline_hour, " +
            "required_operators, outcome, released) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"

    @Test
    fun outboxOp() = SyncFixture().use { f ->
        val db = f.db
        fun ok(i: Int, ciphertext: ByteArray?, ttl: Int = 604800, notBefore: Long = 0, deadline: Long? = null, required: Int = 2, outcome: String = "pending", released: Int = 0) =
            assertEquals(1, db.changes(insertOp, opId(i), f.ns, hash(i), ciphertext, ttl, notBefore, deadline, required, outcome, released))
        fun bad(fragment: String, ciphertext: ByteArray? = bytes(1024, 0), id: ByteArray = opId(90), blobHash: ByteArray = hash(90), ns: ByteArray = f.ns, ttl: Int = 604800, notBefore: Long = 0, deadline: Long? = null, required: Int = 2, outcome: String = "pending", released: Int = 0) =
            db.rejects(fragment, insertOp, id, ns, blobHash, ciphertext, ttl, notBefore, deadline, required, outcome, released)

        // Every bucket size, every TTL bucket, a wiped payload.
        for ((i, size) in listOf(1024, 4096, 16384, 65536).withIndex()) ok(1 + i, bytes(size, i))
        for ((i, ttl) in listOf(86400, 604800, 2592000, 7776000).withIndex()) ok(10 + i, bytes(1024, i), ttl = ttl)
        ok(20, null)
        ok(21, bytes(1024, 1), notBefore = 60, deadline = 3600, required = 3)
        ok(22, null, outcome = "sent", released = 1)
        for ((i, outcome) in listOf("degraded", "failed", "indeterminate").withIndex()) ok(30 + i, null, outcome = outcome)

        bad(CHECK_FAILED, id = bytes(15, 90))
        bad(CHECK_FAILED, blobHash = bytes(31, 90))
        bad(CHECK_FAILED, ciphertext = bytes(1000, 1))
        bad(CHECK_FAILED, ciphertext = bytes(65537, 1))
        bad(CHECK_FAILED, ciphertext = ByteArray(0))
        bad(CHECK_FAILED, ttl = 3600)
        bad(CHECK_FAILED, notBefore = 61)
        bad(CHECK_FAILED, deadline = 3601)
        bad(CHECK_FAILED, notBefore = 3600, deadline = 3600)
        bad(CHECK_FAILED, notBefore = 7200, deadline = 3600)
        bad(CHECK_FAILED, required = 1)
        bad(CHECK_FAILED, outcome = "lost")
        bad(CHECK_FAILED, released = 2)
        bad(CHECK_FAILED, released = 1)
        bad(FOREIGN_KEY_FAILED, ns = bytes(32, 9))
        // (namespace, hash) is unique across ops (§11.2 #5); the same hash in another namespace is fine.
        // The REPLACE guard of migration 3 (Phase 8 design §19.21 point 4) answers before the UNIQUE and
        // PRIMARY KEY constraints do.
        bad("outbox_op rows are never replaced", blobHash = hash(1))
        bad("outbox_op rows are never replaced", id = opId(1), blobHash = hash(91))
        f.namespace(bytes(32, 2))
        assertEquals(1, db.changes(insertOp, opId(91), bytes(32, 2), hash(1), bytes(1024, 1), 604800, 0, null, 2, "pending", 0))
    }

    @Test
    fun outboxDelivery() = SyncFixture().use { f ->
        val db = f.db
        f.op(1)
        f.delivery(1, 1)
        assertEquals(0L, db.queryLong("SELECT attempts + inflight + strikes FROM outbox_delivery"))
        val insert = "INSERT INTO outbox_delivery(operation_id, relay_id, state, next_attempt_minute) VALUES (?, ?, 'pending', ?)"
        db.rejects(CHECK_FAILED, insert, opId(1), 2, 61)
        db.rejects(FOREIGN_KEY_FAILED, insert, opId(1), 99, 0)
        db.rejects(UNIQUE_FAILED, insert, opId(1), 1, 0)
        // Column checks, through updates (inserts are further restricted by outbox_delivery_insert).
        f.rejectsDeliveryUpdate(CHECK_FAILED, 1, 1, "attempts = -1")
        f.rejectsDeliveryUpdate(CHECK_FAILED, 1, 1, "next_attempt_minute = 61")
        f.rejectsDeliveryUpdate(CHECK_FAILED, 1, 1, "inflight = 2, lease_hour = 3600")
        f.rejectsDeliveryUpdate(CHECK_FAILED, 1, 1, "lease_hour = 3601")
        f.rejectsDeliveryUpdate(CHECK_FAILED, 1, 1, "copy_hour = 3601")
        f.rejectsDeliveryUpdate(CHECK_FAILED, 1, 1, "ack_minute = 61")
        f.rejectsDeliveryUpdate(CHECK_FAILED, 1, 1, "strikes = 3")
        f.rejectsDeliveryUpdate(CHECK_FAILED, 1, 1, "strikes = -1")
        // A lease needs its hour.
        f.rejectsDeliveryUpdate(CHECK_FAILED, 1, 1, "inflight = 1")
        assertEquals(1, f.updateDelivery(1, 1, "attempts = 1, inflight = 1, lease_hour = 7200, next_attempt_minute = 120"))
        assertEquals(1, f.updateDelivery(1, 1, "inflight = 0, copy_hour = COALESCE(copy_hour, lease_hour)"))
        assertEquals(1, f.updateDelivery(1, 1, "strikes = 2"))
        // acked needs both its receipt minute and a possible-copy hour.
        f.delivery(1, 2)
        f.rejectsDeliveryUpdate(CHECK_FAILED, 1, 2, "state = 'acked'")
        f.rejectsDeliveryUpdate(CHECK_FAILED, 1, 2, "state = 'acked', ack_minute = 60")
        f.rejectsDeliveryUpdate(CHECK_FAILED, 1, 2, "state = 'acked', copy_hour = 3600")
        assertEquals(1, f.updateDelivery(1, 2, "state = 'acked', ack_minute = 60, copy_hour = 3600"))
        // An unknown state is refused (by the state trigger, before the CHECK is evaluated).
        f.rejectsDeliveryUpdate("illegal delivery transition", 1, 2, "state = 'lost'")
    }

    private val insertBlob =
        "INSERT INTO inbox_blob(namespace_id, blob_hash, state, ciphertext, fetch_seq, fetch_attempts, next_fetch_minute, offers, " +
            "offer_after_minute, retain_until_day) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"

    @Test
    fun inboxBlob() = SyncFixture().use { f ->
        val db = f.db
        fun row(i: Int, state: String = "listed", ciphertext: ByteArray? = null, seq: Long? = null, attempts: Int = 0, nextFetch: Long = 0, offers: Int = 0, offerAfter: Long = 0, retain: Long = 7, blobHash: ByteArray = hash(i), ns: ByteArray = f.ns) =
            arrayOf<Any?>(ns, blobHash, state, ciphertext, seq, attempts, nextFetch, offers, offerAfter, retain)

        assertEquals(1, db.changes(insertBlob, *row(1, attempts = 3, nextFetch = 120, offers = 1, offerAfter = 60, retain = 0)))
        assertEquals(1, db.changes(insertBlob, *row(2, state = "done", retain = 20_006)))
        db.rejects(UNIQUE_FAILED, insertBlob, *row(1))
        db.rejects(FOREIGN_KEY_FAILED, insertBlob, *row(3, ns = bytes(32, 9)))
        db.rejects(CHECK_FAILED, insertBlob, *row(3, blobHash = bytes(31, 3)))
        // Only fetched rows carry ciphertext and a hand-off sequence.
        db.rejects(CHECK_FAILED, insertBlob, *row(3, ciphertext = bytes(1024, 3)))
        db.rejects(CHECK_FAILED, insertBlob, *row(3, seq = 1))
        db.rejects(CHECK_FAILED, insertBlob, *row(3, attempts = -1))
        db.rejects(CHECK_FAILED, insertBlob, *row(3, nextFetch = 61))
        db.rejects(CHECK_FAILED, insertBlob, *row(3, offers = -1))
        db.rejects(CHECK_FAILED, insertBlob, *row(3, offerAfter = 61))
        // retain_until_day: a non-negative day, rounded up to a 7-day boundary (§11.2 #8).
        db.rejects(CHECK_FAILED, insertBlob, *row(3, retain = -7))
        for (retain in listOf(1L, 8L, 20_000L)) db.rejects(CHECK_FAILED, insertBlob, *row(3, retain = retain))
        // A done tombstone carries nothing but (namespace, hash, retain_until_day).
        db.rejects(CHECK_FAILED, insertBlob, *row(3, state = "done", attempts = 1))
        db.rejects(CHECK_FAILED, insertBlob, *row(3, state = "done", nextFetch = 60))
        db.rejects(CHECK_FAILED, insertBlob, *row(3, state = "done", offers = 1))
        db.rejects(CHECK_FAILED, insertBlob, *row(3, state = "done", offerAfter = 60))
        // fetched: exactly one bucket of ciphertext plus a unique fetch_seq.
        val fetch = "UPDATE inbox_blob SET state = 'fetched', ciphertext = ?, fetch_seq = ? WHERE namespace_id = ? AND blob_hash = ?"
        f.listed(4)
        f.listed(5)
        db.rejects(CHECK_FAILED, fetch, null, 1, f.ns, hash(4))
        db.rejects(CHECK_FAILED, fetch, bytes(1024, 4), null, f.ns, hash(4))
        db.rejects(CHECK_FAILED, fetch, bytes(1000, 4), 1, f.ns, hash(4))
        assertEquals(1, db.changes(fetch, bytes(1024, 4), 1, f.ns, hash(4)))
        db.rejects(UNIQUE_FAILED, fetch, bytes(1024, 5), 1, f.ns, hash(5))
        assertEquals(1, db.changes(fetch, bytes(65536, 5), 2, f.ns, hash(5)))
        // A fetched row keeps its ciphertext until it is consumed.
        db.rejects(CHECK_FAILED, "UPDATE inbox_blob SET ciphertext = NULL WHERE blob_hash = ?", hash(4))
    }

    @Test
    fun inboxSource() = SyncFixture().use { f ->
        val db = f.db
        f.listed(1)
        val insert = "INSERT INTO inbox_source(namespace_id, blob_hash, relay_id, state) VALUES (?, ?, ?, ?)"
        assertEquals(1, db.changes(insert, f.ns, hash(1), 1, "candidate"))
        assertEquals(1, db.changes(insert, f.ns, hash(1), 2, "not_found"))
        assertEquals(1, db.changes("UPDATE inbox_source SET state = 'bad' WHERE relay_id = 2"))
        db.rejects(CHECK_FAILED, "UPDATE inbox_source SET state = 'maybe' WHERE relay_id = 2")
        db.rejects(UNIQUE_FAILED, insert, f.ns, hash(1), 1, "candidate")
        db.rejects(FOREIGN_KEY_FAILED, insert, f.ns, hash(2), 1, "candidate")
        db.rejects(FOREIGN_KEY_FAILED, insert, f.ns, hash(1), 99, "candidate")
        // Existing not_found/bad sources are kept by the listing insert (§4.1).
        assertEquals(
            0,
            db.changes(
                "INSERT INTO inbox_source(namespace_id, blob_hash, relay_id, state) SELECT namespace_id, blob_hash, ?, 'candidate' " +
                    "FROM inbox_blob WHERE namespace_id = ? AND blob_hash = ? AND state IN ('listed', 'unavailable') " +
                    "ON CONFLICT(namespace_id, blob_hash, relay_id) DO NOTHING",
                2, f.ns, hash(1),
            ),
        )
        assertEquals("bad", db.queryString("SELECT state FROM inbox_source WHERE relay_id = 2"))
    }

    @Test
    fun namespaceDeletionIsBlockedByOpsAndCascadesEverythingElse() = SyncFixture().use { f ->
        val db = f.db
        db.exec("INSERT INTO namespace_relay(namespace_id, relay_id) VALUES (?, 1), (?, 2)", listOf(f.ns, f.ns))
        db.exec(
            "INSERT INTO relay_capability(relay_id, namespace_id, kind, token, state, generation) VALUES (1, ?, 'write', ?, 'usable', 1)",
            listOf(f.ns, bytes(82, 1)),
        )
        db.exec("INSERT INTO relay_cursor(relay_id, namespace_id, cursor) VALUES (1, ?, ?)", listOf(f.ns, bytes(8, 1)))
        f.listed(1)
        db.exec("INSERT INTO inbox_source(namespace_id, blob_hash, relay_id, state) VALUES (?, ?, 1, 'candidate')", listOf(f.ns, hash(1)))
        db.exec("INSERT INTO inbox_blob(namespace_id, blob_hash, state, retain_until_day) VALUES (?, ?, 'done', 14)", listOf(f.ns, hash(2)))
        // An op pins its namespace (no cascade): Namespaces.remove() must wait for it (§11.2 #19).
        f.op(3)
        f.delivery(3, 1)
        db.rejects(FOREIGN_KEY_FAILED, "DELETE FROM sync_namespace WHERE namespace_id = ?", f.ns)
        assertEquals(1L, f.count("sync_namespace"))
        // Remove-before-GC: the relay set, cursors and capabilities go, tombstones stay.
        assertEquals(1, db.changes("UPDATE sync_namespace SET listening = 0 WHERE namespace_id = ?", f.ns))
        assertEquals(2, db.changes("DELETE FROM namespace_relay WHERE namespace_id = ?", f.ns))
        assertEquals(1, db.changes("DELETE FROM relay_cursor WHERE namespace_id = ?", f.ns))
        assertEquals(1, db.changes("DELETE FROM relay_capability WHERE namespace_id = ?", f.ns))
        assertEquals(2L, f.count("inbox_blob"))
        // Once the op is gone, deleting the namespace cascades its inbox rows and their sources.
        assertEquals(1, f.updateDelivery(3, 1, "state = 'failed'"))
        assertEquals(1, f.updateOp(3, "outcome = 'failed'"))
        assertEquals(1, f.updateOp(3, "ciphertext = NULL"))
        assertEquals(1, f.updateOp(3, "released = 1"))
        assertEquals(1, db.changes("DELETE FROM outbox_op WHERE operation_id = ?", opId(3)))
        assertEquals(0L, f.count("outbox_delivery"))
        assertEquals(1, db.changes("DELETE FROM sync_namespace WHERE namespace_id = ?", f.ns))
        for (table in listOf("inbox_blob", "inbox_source", "namespace_relay", "relay_cursor", "relay_capability")) {
            assertEquals(table, 0L, f.count(table))
        }
        assertEquals(2L, f.count("relay_directory"))
    }

    @Test
    fun relayDeletionIsBlockedWhileReferencedAndCascadesCursorsCapabilitiesSources() = SyncFixture().use { f ->
        val db = f.db
        db.exec("INSERT INTO namespace_relay(namespace_id, relay_id) VALUES (?, 1)", listOf(f.ns))
        db.rejects(FOREIGN_KEY_FAILED, "DELETE FROM relay_directory WHERE relay_id = 1")
        f.op(1)
        f.delivery(1, 2)
        db.rejects(FOREIGN_KEY_FAILED, "DELETE FROM relay_directory WHERE relay_id = 2")
        f.relay(3)
        db.exec(
            "INSERT INTO relay_capability(relay_id, namespace_id, kind, token, state, generation) VALUES (3, ?, 'read', ?, 'usable', 1)",
            listOf(f.ns, bytes(82, 1)),
        )
        db.exec("INSERT INTO relay_cursor(relay_id, namespace_id, cursor) VALUES (3, ?, ?)", listOf(f.ns, bytes(8, 1)))
        f.listed(5)
        db.exec("INSERT INTO inbox_source(namespace_id, blob_hash, relay_id, state) VALUES (?, ?, 3, 'candidate')", listOf(f.ns, hash(5)))
        assertEquals(1, db.changes("DELETE FROM relay_directory WHERE relay_id = 3"))
        assertEquals(0L, f.count("relay_capability"))
        assertEquals(0L, f.count("relay_cursor"))
        assertEquals(0L, f.count("inbox_source"))
        assertEquals("listed", f.inboxState(5))
        assertNull(db.queryLong("SELECT 1 FROM relay_directory WHERE relay_id = 3"))
    }
}
