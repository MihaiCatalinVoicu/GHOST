package org.ghost.storage

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The outbox and inbox statements of docs/design/faza7-sync-engine.md §3 and §4 (with the §11.2
 * #5 verification statement) run against the v2 schema: each guarded statement changes exactly the
 * rows the design expects, and none of them is refused by a trigger.
 */
class SyncSchemaDesignStatementsTest {
    private val hour = 3600L
    private val day = 86_400L
    private val storeWindow = 7 * day
    private val skew = 3 * day
    private val t0 = 1_800_000_000L / hour * hour

    private fun ceil7(d: Long) = (d + 6) / 7 * 7

    private val insertOp =
        "INSERT INTO outbox_op(operation_id, namespace_id, blob_hash, ciphertext, ttl_seconds, not_before_minute, deadline_hour, " +
            "required_operators, outcome) VALUES (?, ?, ?, ?, 604800, ?, NULL, 2, 'pending')"
    private val insertDeliveries =
        "INSERT INTO outbox_delivery(operation_id, relay_id, state, attempts, next_attempt_minute) " +
            "SELECT ?, nr.relay_id, 'pending', 0, ? FROM namespace_relay nr JOIN relay_directory rd ON rd.relay_id = nr.relay_id " +
            "WHERE nr.namespace_id = ? AND rd.state = 'active'"
    private val ownDone =
        "INSERT INTO inbox_blob(namespace_id, blob_hash, state, retain_until_day) VALUES (?, ?, 'done', ?) " +
            "ON CONFLICT(namespace_id, blob_hash) DO UPDATE SET retain_until_day = max(inbox_blob.retain_until_day, excluded.retain_until_day) " +
            "WHERE inbox_blob.state = 'done'"
    private val lease =
        "UPDATE outbox_delivery SET attempts = attempts + 1, inflight = 1, lease_hour = ?, next_attempt_minute = ? " +
            "WHERE operation_id = ? AND relay_id = ? AND state = 'pending' AND inflight = 0 AND next_attempt_minute <= ?"
    private val receipt =
        "UPDATE outbox_delivery SET state = 'acked', inflight = 0, ack_minute = ?, copy_hour = COALESCE(copy_hour, lease_hour) " +
            "WHERE operation_id = ? AND relay_id = ? AND inflight = 1 AND state IN ('pending', 'wait_capability')"
    private val ambiguous =
        "UPDATE outbox_delivery SET inflight = 0, copy_hour = COALESCE(copy_hour, lease_hour) WHERE operation_id = ? AND relay_id = ? AND inflight = 1"
    private val m1 = "UPDATE outbox_delivery SET inflight = 0, copy_hour = COALESCE(copy_hour, lease_hour) WHERE inflight = 1"
    private val foundByCheck =
        "UPDATE outbox_delivery SET state = 'verified', inflight = 0, copy_hour = COALESCE(copy_hour, lease_hour) " +
            "WHERE operation_id = ? AND relay_id = ? AND state <> 'verified'"
    private val checkAbsent =
        "UPDATE outbox_delivery SET strikes = strikes + 1, state = CASE WHEN strikes + 1 >= 2 THEN 'failed' ELSE 'pending' END, " +
            "next_attempt_minute = ? WHERE operation_id = ? AND relay_id = ? AND state = 'acked'"
    private val verifyFromListing =
        "UPDATE outbox_delivery SET state = 'verified' WHERE relay_id = ? AND inflight = 0 " +
            "AND state IN ('pending', 'wait_capability', 'acked', 'failed', 'closed') " +
            "AND operation_id IN (SELECT operation_id FROM outbox_op WHERE namespace_id = ? AND blob_hash = ? AND outcome = 'pending')"
    private val d1 =
        "UPDATE outbox_op SET outcome = 'sent' WHERE operation_id = ? AND outcome = 'pending' " +
            "AND (SELECT COUNT(DISTINCT rd.operator_id) FROM outbox_delivery d JOIN relay_directory rd ON rd.relay_id = d.relay_id " +
            "WHERE d.operation_id = ? AND d.state = 'verified') >= required_operators"
    private val d2 =
        "UPDATE outbox_op SET outcome = CASE " +
            "WHEN EXISTS (SELECT 1 FROM outbox_delivery d WHERE d.operation_id = ? AND d.state = 'verified') THEN 'degraded' " +
            "WHEN EXISTS (SELECT 1 FROM outbox_delivery d WHERE d.operation_id = ? AND d.copy_hour IS NOT NULL) THEN 'indeterminate' " +
            "ELSE 'failed' END " +
            "WHERE operation_id = ? AND outcome = 'pending' " +
            "AND NOT EXISTS (SELECT 1 FROM outbox_delivery d WHERE d.operation_id = ? " +
            "AND (d.state IN ('pending', 'wait_capability', 'acked') OR d.inflight = 1)) " +
            "AND NOT EXISTS (SELECT 1 FROM outbox_delivery d JOIN relay_directory rd ON rd.relay_id = d.relay_id " +
            "WHERE d.operation_id = ? AND d.copy_hour IS NOT NULL AND d.ack_minute IS NULL AND d.state IN ('failed', 'closed') " +
            "AND rd.state = 'active' AND ? < d.copy_hour + outbox_op.ttl_seconds - ?)"
    private val wipe =
        "UPDATE outbox_op SET ciphertext = NULL WHERE operation_id = ? AND ciphertext IS NOT NULL " +
            "AND NOT EXISTS (SELECT 1 FROM outbox_delivery d WHERE d.operation_id = ? " +
            "AND (d.state IN ('pending', 'wait_capability', 'acked') OR d.inflight = 1))"
    private val m2 =
        "UPDATE outbox_delivery SET state = 'wait_capability' WHERE state = 'pending' AND inflight = 0 " +
            "AND NOT EXISTS (SELECT 1 FROM outbox_op o JOIN relay_capability c " +
            "ON c.relay_id = outbox_delivery.relay_id AND c.namespace_id = o.namespace_id " +
            "WHERE o.operation_id = outbox_delivery.operation_id AND c.kind = 'write' AND c.state = 'usable' " +
            "AND (c.expires_hour IS NULL OR c.expires_hour > ?))"
    private val m3 =
        "UPDATE outbox_delivery SET state = 'closed' WHERE state IN ('pending', 'wait_capability') AND inflight = 0 " +
            "AND operation_id IN (SELECT o.operation_id FROM outbox_op o " +
            "WHERE (o.deadline_hour IS NOT NULL AND o.deadline_hour <= ?) " +
            "OR (EXISTS (SELECT 1 FROM outbox_delivery x WHERE x.operation_id = o.operation_id " +
            "AND x.copy_hour IS NOT NULL AND x.copy_hour + ? <= ?) " +
            "AND NOT EXISTS (SELECT 1 FROM outbox_delivery y JOIN relay_directory ry ON ry.relay_id = y.relay_id " +
            "WHERE y.operation_id = o.operation_id AND y.copy_hour IS NOT NULL AND y.ack_minute IS NULL " +
            "AND y.state IN ('pending', 'wait_capability', 'failed', 'closed') AND ry.state = 'active' " +
            "AND ? < y.copy_hour + o.ttl_seconds - ?)))"
    private val rearm =
        "UPDATE outbox_delivery SET state = 'pending', next_attempt_minute = ? WHERE relay_id = ? AND state = 'wait_capability' " +
            "AND operation_id IN (SELECT operation_id FROM outbox_op WHERE namespace_id = ?)"
    private val release = "UPDATE outbox_op SET released = 1 WHERE operation_id = ? AND released = 0 AND outcome <> 'pending'"

    private val listUpsert =
        "INSERT INTO inbox_blob(namespace_id, blob_hash, state, retain_until_day) VALUES (?, ?, 'listed', ?) " +
            "ON CONFLICT(namespace_id, blob_hash) DO UPDATE SET retain_until_day = max(inbox_blob.retain_until_day, excluded.retain_until_day) " +
            "WHERE inbox_blob.state IN ('listed', 'unavailable')"
    private val listSource =
        "INSERT INTO inbox_source(namespace_id, blob_hash, relay_id, state) SELECT namespace_id, blob_hash, ?, 'candidate' " +
            "FROM inbox_blob WHERE namespace_id = ? AND blob_hash = ? AND state IN ('listed', 'unavailable') " +
            "ON CONFLICT(namespace_id, blob_hash, relay_id) DO NOTHING"
    private val relist =
        "UPDATE inbox_blob SET state = 'listed' WHERE namespace_id = ? AND blob_hash = ? AND state = 'unavailable' " +
            "AND EXISTS (SELECT 1 FROM inbox_source s WHERE s.namespace_id = ? AND s.blob_hash = ? AND s.state = 'candidate')"
    private val cursor =
        "INSERT INTO relay_cursor(relay_id, namespace_id, cursor) VALUES (?, ?, ?) " +
            "ON CONFLICT(relay_id, namespace_id) DO UPDATE SET cursor = excluded.cursor"
    private val fetchLease =
        "UPDATE inbox_blob SET fetch_attempts = fetch_attempts + 1, next_fetch_minute = ? " +
            "WHERE namespace_id = ? AND blob_hash = ? AND state = 'listed' AND next_fetch_minute <= ?"
    private val fetchSuccess =
        "UPDATE inbox_blob SET state = 'fetched', ciphertext = ?, fetch_seq = (SELECT COALESCE(MAX(fetch_seq), 0) + 1 FROM inbox_blob), " +
            "fetch_attempts = 0, next_fetch_minute = 0, retain_until_day = ? WHERE namespace_id = ? AND blob_hash = ? AND state = 'listed'"
    private val noCandidateLeft =
        "UPDATE inbox_blob SET state = 'unavailable' WHERE namespace_id = ? AND blob_hash = ? AND state = 'listed' " +
            "AND NOT EXISTS (SELECT 1 FROM inbox_source s WHERE s.namespace_id = ? AND s.blob_hash = ? AND s.state = 'candidate')"
    private val claim = "UPDATE inbox_blob SET offers = offers + 1 WHERE namespace_id = ? AND blob_hash = ? AND state = 'fetched'"
    private val defer = "UPDATE inbox_blob SET offer_after_minute = ?, offers = 0 WHERE namespace_id = ? AND blob_hash = ? AND state = 'fetched'"
    private val markConsumed =
        "UPDATE inbox_blob SET state = 'done', ciphertext = NULL, fetch_seq = NULL, offers = 0, offer_after_minute = 0 " +
            "WHERE namespace_id = ? AND blob_hash = ? AND state = 'fetched'"

    private fun SyncFixture.setUpRelaySet() {
        db.exec("INSERT INTO namespace_relay(namespace_id, relay_id) VALUES (?, 1), (?, 2)", listOf(ns, ns))
        for (r in 1..2) {
            db.exec(
                "INSERT INTO relay_capability(relay_id, namespace_id, kind, token, expires_hour, state, generation) VALUES (?, ?, 'write', ?, NULL, 'usable', 1)",
                listOf(r, ns, bytes(82, r)),
            )
        }
    }

    private fun SyncFixture.enqueue(i: Int, now: Long) = db.transaction {
        db.exec(insertOp, listOf(opId(i), ns, hash(i), bytes(1024, i), now))
        assertEquals(2, db.execUpdate(insertDeliveries, listOf(opId(i), now, ns)))
        assertEquals(1, db.execUpdate(ownDone, listOf(ns, hash(i), ceil7(now / day + 7 + 8))))
    }

    private fun SyncFixture.d2(i: Int, now: Long) = db.execUpdate(d2, listOf(opId(i), opId(i), opId(i), opId(i), opId(i), now, skew))

    @Test
    fun outboxHappyPathAmbiguityAndCheckBeforeRestore() = SyncFixture().use { f ->
        val db = f.db
        f.setUpRelaySet()
        f.enqueue(7, t0)
        // Relay 1: lease, receipt.
        assertEquals(1, db.changes(lease, t0, t0 + 60, opId(7), 1, t0))
        assertEquals(0, db.changes(lease, t0, t0 + 60, opId(7), 1, t0))
        assertEquals(1, db.changes(receipt, t0, opId(7), 1))
        // Relay 2: lease, ambiguous outcome; M1 has nothing left to normalize.
        assertEquals(1, db.changes(lease, t0, t0 + 60, opId(7), 2, t0))
        assertEquals(1, db.changes(ambiguous, opId(7), 2))
        assertEquals(0, db.changes(m1))
        assertEquals(t0, db.queryLong("SELECT copy_hour FROM outbox_delivery WHERE relay_id = 2"))
        // Relay 1 lists h: the own done row absorbs the page; relay 1's delivery becomes verified.
        db.transaction {
            assertEquals(0, db.changes(listUpsert, f.ns, hash(7), ceil7(t0 / day + 111)))
            assertEquals(0, db.changes(listSource, 1, f.ns, hash(7)))
            assertEquals(0, db.changes(relist, f.ns, hash(7), f.ns, hash(7)))
            assertEquals(1, db.changes(verifyFromListing, 1, f.ns, hash(7)))
            assertEquals(1, db.changes(cursor, 1, f.ns, bytes(8, 1)))
        }
        assertEquals(0, db.changes(d1, opId(7), opId(7)))
        // An hour later relay 2 is due: lease, check-before-restore finds h; the earliest hour stays.
        val t1 = t0 + hour
        assertEquals(1, db.changes(lease, t1, t1 + 60, opId(7), 2, t1))
        assertEquals(1, db.changes(foundByCheck, opId(7), 2))
        assertEquals(t0, db.queryLong("SELECT copy_hour FROM outbox_delivery WHERE relay_id = 2"))
        // Decision, wipe, release, own-tombstone raise, delete.
        assertEquals(1, db.changes(d1, opId(7), opId(7)))
        assertEquals(0, f.d2(7, t1))
        assertEquals(1, db.changes(wipe, opId(7), opId(7)))
        assertEquals(1, db.changes(release, opId(7)))
        assertEquals(0, db.changes(release, opId(7)))
        val ownRetain = ceil7(t1 / day + 7 + 8)
        assertEquals(
            1,
            db.changes(
                "UPDATE inbox_blob SET retain_until_day = max(retain_until_day, ?) WHERE namespace_id = ? AND blob_hash = ? AND state = 'done'",
                ownRetain, f.ns, hash(7),
            ),
        )
        assertEquals(1, db.changes("DELETE FROM outbox_op WHERE operation_id = ?", opId(7)))
        assertEquals(0L, f.count("outbox_delivery"))
        assertEquals("done", f.inboxState(7))
    }

    @Test
    fun outboxStrikesParkingRearmClosureAndIndeterminateDecision() = SyncFixture().use { f ->
        val db = f.db
        f.setUpRelaySet()
        f.enqueue(8, t0)
        // Relay 1: acked, absent on check (strike 1, repair), acked again, absent again (failed).
        assertEquals(1, db.changes(lease, t0, t0 + 60, opId(8), 1, t0))
        assertEquals(1, db.changes(receipt, t0, opId(8), 1))
        assertEquals(1, db.changes(checkAbsent, t0 + 3600, opId(8), 1))
        assertEquals("pending", f.deliveryState(8, 1))
        assertEquals(1, db.changes(lease, t0 + 3600, t0 + 3660, opId(8), 1, t0 + 3600))
        assertEquals(1, db.changes(receipt, t0 + 3600, opId(8), 1))
        assertEquals(1, db.changes(checkAbsent, t0 + 7200, opId(8), 1))
        assertEquals("failed", f.deliveryState(8, 1))
        assertEquals(2L, db.queryLong("SELECT strikes FROM outbox_delivery WHERE relay_id = 1"))
        // Relay 2 loses its capability: M2 parks it; a new generation re-arms it.
        db.exec("UPDATE relay_capability SET state = 'rejected' WHERE relay_id = 2")
        assertEquals(1, db.changes(m2, t0))
        assertEquals("wait_capability", f.deliveryState(8, 2))
        db.exec("UPDATE relay_capability SET state = 'usable', generation = generation + 1 WHERE relay_id = 2")
        assertEquals(1, db.changes(rearm, t0 + 60, 2, f.ns))
        assertEquals("pending", f.deliveryState(8, 2))
        // Before the window closes nothing is closed; after it, relay 2 (no copy) is closed.
        val beforeClose = t0 + storeWindow - hour
        assertEquals(0, db.changes(m3, beforeClose, storeWindow, beforeClose, beforeClose, skew))
        val afterClose = t0 + storeWindow
        assertEquals(1, db.changes(m3, afterClose, storeWindow, afterClose, afterClose, skew))
        assertEquals("closed", f.deliveryState(8, 2))
        // No verified copy, but relay 1 may hold one: indeterminate, then the payload is wiped.
        assertEquals(0, db.changes(d1, opId(8), opId(8)))
        assertEquals(1, f.d2(8, afterClose))
        assertEquals("indeterminate", db.queryString("SELECT outcome FROM outbox_op WHERE operation_id = ?", listOf(opId(8))))
        assertEquals(1, db.changes(wipe, opId(8), opId(8)))
        // Late inventory is still truth for a failed delivery, but an undecided op is required.
        assertEquals(0, db.changes(verifyFromListing, 1, f.ns, hash(8)))
    }

    @Test
    fun outboxFailedWhenNoCopyWasPossible() = SyncFixture().use { f ->
        val db = f.db
        f.setUpRelaySet()
        f.enqueue(9, t0)
        // Both relays refuse definitively ("not applied"): no copy hour is recorded.
        for (r in 1..2) {
            assertEquals(1, db.changes(lease, t0, t0 + 60, opId(9), r, t0))
            assertEquals(1, db.changes("UPDATE outbox_delivery SET inflight = 0 WHERE operation_id = ? AND relay_id = ? AND inflight = 1", opId(9), r))
            assertEquals(1, f.updateDelivery(9, r, "state = 'failed'"))
        }
        assertEquals(1, f.d2(9, t0))
        assertEquals("failed", db.queryString("SELECT outcome FROM outbox_op WHERE operation_id = ?", listOf(opId(9))))
    }

    @Test
    fun inboxListFetchHandOffAndUnavailable() = SyncFixture().use { f ->
        val db = f.db
        val today = t0 / day
        val listedRetain = ceil7(today + 111)
        // Relays 1 and 2 both list h9; relay 1 lists h10.
        db.transaction {
            assertEquals(1, db.changes(listUpsert, f.ns, hash(9), listedRetain))
            assertEquals(1, db.changes(listSource, 1, f.ns, hash(9)))
            assertEquals(1, db.changes(listUpsert, f.ns, hash(10), listedRetain))
            assertEquals(1, db.changes(listSource, 1, f.ns, hash(10)))
            assertEquals(1, db.changes(cursor, 1, f.ns, bytes(8, 1)))
        }
        db.transaction {
            assertEquals(1, db.changes(listUpsert, f.ns, hash(9), listedRetain))
            assertEquals(1, db.changes(listSource, 2, f.ns, hash(9)))
            assertEquals(0, db.changes(relist, f.ns, hash(9), f.ns, hash(9)))
            assertEquals(1, db.changes(cursor, 2, f.ns, bytes(8, 2)))
        }
        // h9: relay 1 answers not_found, relay 2 serves it.
        assertEquals(1, db.changes(fetchLease, t0 + 60, f.ns, hash(9), t0))
        assertEquals(0, db.changes(fetchLease, t0 + 60, f.ns, hash(9), t0))
        assertEquals(1, db.changes("UPDATE inbox_source SET state = 'not_found' WHERE namespace_id = ? AND blob_hash = ? AND relay_id = 1", f.ns, hash(9)))
        assertEquals(0, db.changes(noCandidateLeft, f.ns, hash(9), f.ns, hash(9)))
        assertEquals(1, db.changes(fetchSuccess, bytes(16384, 9), ceil7(today + 7 + 24), f.ns, hash(9)))
        assertEquals(0L, db.queryLong("SELECT count(*) FROM inbox_source WHERE blob_hash = ?", listOf(hash(9))))
        // Hand-off: claim, defer, markConsumed exactly once; a later listing is absorbed.
        assertEquals(1, db.changes(claim, f.ns, hash(9)))
        assertEquals(1, db.changes(defer, t0 + 3600, f.ns, hash(9)))
        assertEquals(1, db.changes(markConsumed, f.ns, hash(9)))
        assertEquals(0, db.changes(markConsumed, f.ns, hash(9)))
        assertEquals(0, db.changes(listUpsert, f.ns, hash(9), listedRetain))
        assertEquals(0, db.changes(listSource, 1, f.ns, hash(9)))
        assertEquals("done", f.inboxState(9))
        // h10: its only candidate answers not_found, so it becomes unavailable; relay 2 lists it later.
        assertEquals(1, db.changes(fetchLease, t0 + 60, f.ns, hash(10), t0))
        assertEquals(1, db.changes("UPDATE inbox_source SET state = 'not_found' WHERE namespace_id = ? AND blob_hash = ? AND relay_id = 1", f.ns, hash(10)))
        assertEquals(1, db.changes(noCandidateLeft, f.ns, hash(10), f.ns, hash(10)))
        assertEquals("unavailable", f.inboxState(10))
        db.transaction {
            assertEquals(1, db.changes(listUpsert, f.ns, hash(10), ceil7(today + 1 + 111)))
            assertEquals(1, db.changes(listSource, 2, f.ns, hash(10)))
            assertEquals(1, db.changes(relist, f.ns, hash(10), f.ns, hash(10)))
        }
        assertEquals("listed", f.inboxState(10))
        assertEquals(2L, db.queryLong("SELECT count(*) FROM inbox_source WHERE blob_hash = ?", listOf(hash(10))))
    }
}
