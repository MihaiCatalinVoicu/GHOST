package org.ghost.storage

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The 12 state-machine triggers of migration v2 (docs/design/faza7-sync-engine.md §2.2, D8): each
 * legal transition is accepted and each illegal one is refused with the trigger's message.
 */
class SyncSchemaTriggersTest {
    private val deliveryStates = listOf("pending", "wait_capability", "acked", "verified", "failed", "closed")
    private val inboxStates = listOf("listed", "unavailable", "fetched", "done")

    @Test
    fun outboxOpIdentityIsImmutable() = SyncFixture().use { f ->
        f.op(1)
        f.namespace(bytes(32, 2))
        val msg = "outbox_op identity is immutable"
        val changes = listOf<Pair<String, Any?>>(
            "operation_id = ?" to opId(9),
            "namespace_id = ?" to bytes(32, 2),
            "blob_hash = ?" to hash(9),
            "ttl_seconds = ?" to 86400,
            "not_before_minute = ?" to 60,
            "deadline_hour = ?" to 7200,
            "required_operators = ?" to 3,
        )
        for ((set, value) in changes) f.rejectsOpUpdate(msg, 1, set, value)
        // The trigger fires on the column list, so even an unchanged value is refused.
        f.rejectsOpUpdate(msg, 1, "ttl_seconds = ttl_seconds")
        f.rejectsOpUpdate(msg, 1, "deadline_hour = NULL")
        // A guarded update that matches no row never fires it.
        assertEquals(0, f.db.changes("UPDATE outbox_op SET ttl_seconds = 86400 WHERE operation_id = ?", opId(42)))
        assertEquals(1, f.updateOp(1, "outcome = 'failed'"))
    }

    @Test
    fun outboxPayloadIsFrozenAndWipedOnlyAfterTheLastPossibleStore() = SyncFixture().use { f ->
        f.op(1)
        f.delivery(1, 1)
        f.delivery(1, 2)
        val msg = "outbox payload is frozen and wiped only after the last possible store"
        f.rejectsOpUpdate(msg, 1, "ciphertext = ?", bytes(4096, 1))
        f.rejectsOpUpdate(msg, 1, "ciphertext = ciphertext")
        // Not while any delivery could still store: pending, wait_capability, acked or in flight.
        f.rejectsOpUpdate(msg, 1, "ciphertext = NULL")
        assertEquals(1, f.updateDelivery(1, 1, "state = 'verified'"))
        f.rejectsOpUpdate(msg, 1, "ciphertext = NULL")
        assertEquals(1, f.updateDelivery(1, 2, "state = 'wait_capability'"))
        f.rejectsOpUpdate(msg, 1, "ciphertext = NULL")
        assertEquals(1, f.updateDelivery(1, 2, "state = 'acked', ack_minute = 60, copy_hour = 3600"))
        f.rejectsOpUpdate(msg, 1, "ciphertext = NULL")
        assertEquals(1, f.updateDelivery(1, 2, "state = 'failed', inflight = 1, lease_hour = 7200"))
        f.rejectsOpUpdate(msg, 1, "ciphertext = NULL")
        assertEquals(1, f.updateDelivery(1, 2, "inflight = 0"))
        // Every delivery terminal and idle: the wipe is accepted, and the payload never comes back.
        assertEquals(1, f.updateOp(1, "ciphertext = NULL"))
        f.rejectsOpUpdate(msg, 1, "ciphertext = ?", bytes(1024, 1))
        assertEquals(1, f.updateOp(1, "ciphertext = NULL"))
        // An op without deliveries holds nothing back.
        f.op(2)
        assertEquals(1, f.updateOp(2, "ciphertext = NULL"))
        // The W statement (§3.5) is guarded and never fires the trigger.
        f.op(3)
        f.delivery(3, 1)
        val w = "UPDATE outbox_op SET ciphertext = NULL WHERE operation_id = ? AND ciphertext IS NOT NULL " +
            "AND NOT EXISTS (SELECT 1 FROM outbox_delivery d WHERE d.operation_id = ? " +
            "AND (d.state IN ('pending', 'wait_capability', 'acked') OR d.inflight = 1))"
        assertEquals(0, f.db.changes(w, opId(3), opId(3)))
        assertEquals(1, f.updateDelivery(3, 1, "state = 'closed'"))
        assertEquals(1, f.db.changes(w, opId(3), opId(3)))
        assertEquals(0, f.db.changes(w, opId(3), opId(3)))
    }

    @Test
    fun outboxOutcomeIsDecidedOnce() = SyncFixture().use { f ->
        val msg = "outbox outcome is decided once"
        val decided = listOf("sent", "degraded", "failed", "indeterminate")
        for ((i, outcome) in decided.withIndex()) {
            val op = 10 + i
            f.op(op)
            f.rejectsOpUpdate(msg, op, "outcome = 'pending'")
            assertEquals(1, f.updateOp(op, "outcome = ?", outcome))
            for (next in decided + "pending") f.rejectsOpUpdate(msg, op, "outcome = ?", next)
            // The guarded decision statements simply match nothing once decided.
            assertEquals(0, f.db.changes("UPDATE outbox_op SET outcome = 'failed' WHERE operation_id = ? AND outcome = 'pending'", opId(op)))
            assertEquals(outcome, f.db.queryString("SELECT outcome FROM outbox_op WHERE operation_id = ?", listOf(opId(op))))
        }
    }

    @Test
    fun releaseHappensOnceAfterTheOutcome() = SyncFixture().use { f ->
        val msg = "release happens once, after the outcome"
        f.op(1)
        f.rejectsOpUpdate(msg, 1, "released = 1")
        f.rejectsOpUpdate(msg, 1, "outcome = 'sent', released = 1")
        assertEquals(1, f.updateOp(1, "outcome = 'indeterminate'"))
        f.rejectsOpUpdate(msg, 1, "released = 0")
        f.rejectsOpUpdate(msg, 1, "released = 2")
        assertEquals(1, f.updateOp(1, "released = 1"))
        f.rejectsOpUpdate(msg, 1, "released = 1")
        f.rejectsOpUpdate(msg, 1, "released = 0")
        // release() is true exactly once: its guarded statement matches once.
        f.op(2)
        assertEquals(1, f.updateOp(2, "outcome = 'sent'"))
        val release = "UPDATE outbox_op SET released = 1 WHERE operation_id = ? AND released = 0 AND outcome <> 'pending'"
        assertEquals(1, f.db.changes(release, opId(2)))
        assertEquals(0, f.db.changes(release, opId(2)))
    }

    @Test
    fun onlyReleasedOpsWithoutPayloadAreDeleted() = SyncFixture().use { f ->
        val msg = "only released ops without payload are deleted"
        val delete = "DELETE FROM outbox_op WHERE operation_id = ?"
        f.op(1)
        f.delivery(1, 1)
        f.delivery(1, 2)
        f.db.rejects(msg, delete, opId(1))
        assertEquals(1, f.updateDelivery(1, 1, "state = 'verified'"))
        assertEquals(1, f.updateDelivery(1, 2, "state = 'failed'"))
        assertEquals(1, f.updateOp(1, "outcome = 'degraded'"))
        f.db.rejects(msg, delete, opId(1))
        assertEquals(1, f.updateOp(1, "released = 1"))
        f.db.rejects(msg, delete, opId(1))
        assertEquals(1, f.updateOp(1, "ciphertext = NULL"))
        assertEquals(1, f.db.changes(delete, opId(1)))
        assertEquals(0L, f.count("outbox_delivery"))
        // Decided and wiped but not released: kept.
        f.op(2)
        assertEquals(1, f.updateOp(2, "outcome = 'failed'"))
        assertEquals(1, f.updateOp(2, "ciphertext = NULL"))
        f.db.rejects(msg, delete, opId(2))
        assertEquals(1L, f.count("outbox_op"))
    }

    @Test
    fun newDeliveriesStartPendingIdleWithoutCopiesAndNeedThePayload() = SyncFixture().use { f ->
        val db = f.db
        val msg = "a new delivery starts pending, idle, without copies, and needs the payload"
        val insert = "INSERT INTO outbox_delivery(operation_id, relay_id, state, next_attempt_minute, inflight, lease_hour, copy_hour) " +
            "VALUES (?, ?, ?, 0, ?, ?, ?)"
        f.op(1)
        for (state in deliveryStates - "pending") db.rejects(msg, insert, opId(1), 1, state, 0, null, null)
        db.rejects(msg, insert, opId(1), 1, "pending", 1, 3600, null)
        db.rejects(msg, insert, opId(1), 1, "pending", 0, null, 3600)
        db.rejects(msg, insert, opId(9), 1, "pending", 0, null, null)
        f.op(2, ciphertext = null)
        db.rejects(msg, insert, opId(2), 1, "pending", 0, null, null)
        assertEquals(1, db.changes(insert, opId(1), 1, "pending", 0, null, null))
        // INSERT OR IGNORE of an existing pair is a no-op that leaves its state alone.
        val insertOrIgnore = "INSERT OR IGNORE INTO outbox_delivery(operation_id, relay_id, state, next_attempt_minute) VALUES (?, ?, 'pending', 0)"
        assertEquals(1, f.updateDelivery(1, 1, "state = 'verified'"))
        assertEquals(0, db.changes(insertOrIgnore, opId(1), 1))
        assertEquals("verified", f.deliveryState(1, 1))
        // After the wipe, RAISE(ABORT) is not a conflict: OR IGNORE does not swallow it, not even
        // for an existing pair. Set repair (§3.9) must select only ops that still hold their payload.
        assertEquals(1, f.updateOp(1, "ciphertext = NULL"))
        db.rejects(msg, insertOrIgnore, opId(1), 2)
        db.rejects(msg, insertOrIgnore, opId(1), 1)
    }

    @Test
    fun deliveryTransitionMatrix() = SyncFixture().use { f ->
        f.op(1)
        val allowed = mapOf(
            "pending" to setOf("wait_capability", "acked", "verified", "failed", "closed"),
            "wait_capability" to setOf("pending", "acked", "verified", "failed", "closed"),
            "acked" to setOf("pending", "verified", "failed", "closed"),
            "verified" to emptySet(),
            "failed" to setOf("verified"),
            "closed" to setOf("verified"),
        )
        // The receipt columns are set on every step so that only the trigger decides.
        val set = "state = ?, ack_minute = 60, copy_hour = 3600"
        var accepted = 0
        for (from in deliveryStates) {
            for (to in deliveryStates) {
                f.delivery(1, 1)
                if (from != "pending") assertEquals(from, 1, f.updateDelivery(1, 1, set, from))
                if (to in allowed.getValue(from)) {
                    assertEquals("$from -> $to", 1, f.updateDelivery(1, 1, set, to))
                    assertEquals(to, f.deliveryState(1, 1))
                    accepted++
                } else {
                    f.rejectsDeliveryUpdate("illegal delivery transition", 1, 1, set, to)
                    assertEquals("$from -> $to", from, f.deliveryState(1, 1))
                }
                f.db.exec("DELETE FROM outbox_delivery")
            }
        }
        assertEquals(16, accepted)
    }

    @Test
    fun deliveryCannotEnterAStoringStateOnceThePayloadIsGone() = SyncFixture().use { f ->
        f.op(1)
        f.delivery(1, 1)
        assertEquals(1, f.updateDelivery(1, 1, "state = 'wait_capability'"))
        f.op(2)
        f.delivery(2, 2)
        assertEquals(1, f.updateDelivery(2, 2, "state = 'failed'"))
        assertEquals(1, f.updateOp(2, "ciphertext = NULL"))
        // The payload trigger prevents a storing delivery of a wiped op; the only way to build one
        // is to re-point a delivery row, since (operation_id, relay_id) carry no trigger of their own.
        assertEquals(1, f.db.changes("UPDATE outbox_delivery SET operation_id = ? WHERE operation_id = ? AND relay_id = 1", opId(2), opId(1)))
        for (to in listOf("pending", "acked")) {
            f.rejectsDeliveryUpdate("illegal delivery transition", 2, 1, "state = ?, ack_minute = 60, copy_hour = 3600", to)
        }
        assertEquals(1, f.updateDelivery(2, 1, "state = 'failed'"))
        assertEquals(1, f.updateDelivery(2, 1, "state = 'verified'"))
    }

    @Test
    fun possibleCopyKeepsItsEarliestHourAndIsForgottenOnlyWhenProvenAbsent() = SyncFixture().use { f ->
        val msg = "a possible copy keeps its earliest hour and is forgotten only when proven absent"
        f.op(1)
        f.delivery(1, 1)
        f.delivery(1, 2)
        fun copyHour(relay: Int) = f.db.queryLong("SELECT copy_hour FROM outbox_delivery WHERE relay_id = ?", listOf(relay))
        // First ambiguous attempt records the lease hour; later attempts keep it (COALESCE).
        assertEquals(1, f.updateDelivery(1, 1, "inflight = 1, lease_hour = 3600"))
        assertEquals(1, f.updateDelivery(1, 1, "inflight = 0, copy_hour = COALESCE(copy_hour, lease_hour)"))
        assertEquals(1, f.updateDelivery(1, 1, "inflight = 1, lease_hour = 7200"))
        assertEquals(1, f.updateDelivery(1, 1, "inflight = 0, copy_hour = COALESCE(copy_hour, lease_hour)"))
        assertEquals(3600L, copyHour(1))
        f.rejectsDeliveryUpdate(msg, 1, 1, "copy_hour = 7200")
        f.rejectsDeliveryUpdate(msg, 1, 1, "copy_hour = 0")
        // Proven absent while never acked: forgotten, and a later attempt may record a new hour.
        assertEquals(1, f.updateDelivery(1, 1, "copy_hour = NULL"))
        assertEquals(1, f.updateDelivery(1, 1, "copy_hour = 10800"))
        // After a receipt the copy is never forgotten, whatever the state becomes.
        assertEquals(1, f.updateDelivery(1, 1, "state = 'acked', ack_minute = 10800"))
        f.rejectsDeliveryUpdate(msg, 1, 1, "copy_hour = NULL")
        assertEquals(1, f.updateDelivery(1, 1, "state = 'pending', strikes = 1"))
        f.rejectsDeliveryUpdate(msg, 1, 1, "copy_hour = NULL")
        // Verified without a receipt (check found it): never forgotten either.
        assertEquals(1, f.updateDelivery(1, 2, "state = 'verified', copy_hour = COALESCE(copy_hour, 3600)"))
        f.rejectsDeliveryUpdate(msg, 1, 2, "copy_hour = NULL")
        // failed/closed with a possible copy and no receipt: resolution may clear it.
        f.op(2)
        f.delivery(2, 1)
        assertEquals(1, f.updateDelivery(2, 1, "copy_hour = 3600"))
        assertEquals(1, f.updateDelivery(2, 1, "state = 'closed'"))
        assertEquals(1, f.updateDelivery(2, 1, "copy_hour = NULL"))
    }

    @Test
    fun inboxRowsStartListedOrDoneAndUpsertsRunUnderTheTrigger() = SyncFixture().use { f ->
        val db = f.db
        val msg = "inbox rows start listed (or done for own blobs)"
        val insert = "INSERT INTO inbox_blob(namespace_id, blob_hash, state, ciphertext, fetch_seq, retain_until_day) VALUES (?, ?, ?, ?, ?, 7)"
        assertEquals(1, db.changes(insert, f.ns, hash(1), "listed", null, null))
        assertEquals(1, db.changes(insert, f.ns, hash(2), "done", null, null))
        db.rejects(msg, insert, f.ns, hash(3), "fetched", bytes(1024, 3), 1)
        db.rejects(msg, insert, f.ns, hash(3), "unavailable", null, null)
        // Own-blob UPSERT (§3.1): raises a done row, leaves any other state alone.
        val own = "INSERT INTO inbox_blob(namespace_id, blob_hash, state, retain_until_day) VALUES (?, ?, 'done', ?) " +
            "ON CONFLICT(namespace_id, blob_hash) DO UPDATE SET retain_until_day = max(inbox_blob.retain_until_day, excluded.retain_until_day) " +
            "WHERE inbox_blob.state = 'done'"
        assertEquals(1, db.changes(own, f.ns, hash(2), 21))
        assertEquals(1, db.changes(own, f.ns, hash(2), 14))
        assertEquals(21L, db.queryLong("SELECT retain_until_day FROM inbox_blob WHERE blob_hash = ?", listOf(hash(2))))
        assertEquals(0, db.changes(own, f.ns, hash(1), 21))
        assertEquals("listed", f.inboxState(1))
        // Listing UPSERT (§4.1): raises listed/unavailable rows, leaves fetched/done alone.
        val list = "INSERT INTO inbox_blob(namespace_id, blob_hash, state, retain_until_day) VALUES (?, ?, 'listed', ?) " +
            "ON CONFLICT(namespace_id, blob_hash) DO UPDATE SET retain_until_day = max(inbox_blob.retain_until_day, excluded.retain_until_day) " +
            "WHERE inbox_blob.state IN ('listed', 'unavailable')"
        assertEquals(0, db.changes(list, f.ns, hash(2), 119))
        assertEquals(21L, db.queryLong("SELECT retain_until_day FROM inbox_blob WHERE blob_hash = ?", listOf(hash(2))))
        assertEquals(1, db.changes(list, f.ns, hash(1), 119))
        assertEquals(119L, db.queryLong("SELECT retain_until_day FROM inbox_blob WHERE blob_hash = ?", listOf(hash(1))))
    }

    @Test
    fun inboxIdentityIsImmutable() = SyncFixture().use { f ->
        val msg = "inbox identity is immutable"
        f.listed(1)
        f.namespace(bytes(32, 2))
        f.db.rejects(msg, "UPDATE inbox_blob SET namespace_id = ? WHERE blob_hash = ?", bytes(32, 2), hash(1))
        f.db.rejects(msg, "UPDATE inbox_blob SET blob_hash = ? WHERE blob_hash = ?", hash(9), hash(1))
        f.db.rejects(msg, "UPDATE inbox_blob SET blob_hash = blob_hash WHERE blob_hash = ?", hash(1))
        assertEquals("listed", f.inboxState(1))
    }

    @Test
    fun inboxTransitionMatrix() = SyncFixture().use { f ->
        val db = f.db
        val allowed = mapOf(
            "listed" to setOf("fetched", "unavailable"),
            "unavailable" to setOf("listed"),
            "fetched" to setOf("done"),
            "done" to emptySet(),
        )
        // Column values consistent with each target state, so that only the trigger decides.
        fun setFor(state: String): Pair<String, List<Any?>> = when (state) {
            "fetched" -> "state = 'fetched', ciphertext = ?, fetch_seq = 1" to listOf(bytes(1024, 1))
            "done" -> "state = 'done', ciphertext = NULL, fetch_seq = NULL, fetch_attempts = 0, next_fetch_minute = 0, " +
                "offers = 0, offer_after_minute = 0" to emptyList()
            else -> "state = '$state', ciphertext = NULL, fetch_seq = NULL" to emptyList()
        }
        fun update(state: String): Pair<String, List<Any?>> {
            val (set, args) = setFor(state)
            return "UPDATE inbox_blob SET $set WHERE namespace_id = ? AND blob_hash = ?" to args + listOf(f.ns, hash(1))
        }
        var accepted = 0
        for (from in inboxStates) {
            for (to in inboxStates) {
                if (from == "done") {
                    db.exec("INSERT INTO inbox_blob(namespace_id, blob_hash, state, retain_until_day) VALUES (?, ?, 'done', 7)", listOf(f.ns, hash(1)))
                } else {
                    f.listed(1)
                    if (from != "listed") update(from).let { (sql, args) -> assertEquals(from, 1, db.execUpdate(sql, args)) }
                }
                val (sql, args) = update(to)
                if (to in allowed.getValue(from)) {
                    assertEquals("$from -> $to", 1, db.execUpdate(sql, args))
                    assertEquals(to, f.inboxState(1))
                    accepted++
                } else {
                    db.rejects("illegal inbox transition", sql, *args.toTypedArray())
                    assertEquals("$from -> $to", from, f.inboxState(1))
                }
                db.exec("DELETE FROM inbox_blob")
            }
        }
        assertEquals(4, accepted)
    }

    @Test
    fun fetchingOrConsumingABlobDeletesItsSources() = SyncFixture().use { f ->
        val db = f.db
        f.listed(1)
        f.listed(2)
        val source = "INSERT INTO inbox_source(namespace_id, blob_hash, relay_id, state) VALUES (?, ?, ?, ?)"
        db.exec(source, listOf(f.ns, hash(1), 1, "candidate"))
        db.exec(source, listOf(f.ns, hash(1), 2, "not_found"))
        db.exec(source, listOf(f.ns, hash(2), 1, "candidate"))
        fun sources(i: Int) = db.queryLong("SELECT count(*) FROM inbox_source WHERE blob_hash = ?", listOf(hash(i)))
        // listed <-> unavailable keeps the sources.
        assertEquals(1, db.changes("UPDATE inbox_blob SET state = 'unavailable' WHERE blob_hash = ?", hash(1)))
        assertEquals(1, db.changes("UPDATE inbox_blob SET state = 'listed' WHERE blob_hash = ?", hash(1)))
        assertEquals(2L, sources(1))
        // The fetch success statement (§4.2) removes the row's sources and only those; its row
        // count excludes the rows the trigger deleted.
        val fetched = "UPDATE inbox_blob SET state = 'fetched', ciphertext = ?, " +
            "fetch_seq = (SELECT COALESCE(MAX(fetch_seq), 0) + 1 FROM inbox_blob), fetch_attempts = 0, next_fetch_minute = 0, " +
            "retain_until_day = ? WHERE namespace_id = ? AND blob_hash = ? AND state = 'listed'"
        assertEquals(1, db.changes(fetched, bytes(4096, 1), 20_013, f.ns, hash(1)))
        assertEquals(0L, sources(1))
        assertEquals(1L, sources(2))
        assertEquals(1L, db.queryLong("SELECT fetch_seq FROM inbox_blob WHERE blob_hash = ?", listOf(hash(1))))
        assertEquals(1, db.changes(fetched, bytes(4096, 2), 20_013, f.ns, hash(2)))
        assertEquals(2L, db.queryLong("SELECT fetch_seq FROM inbox_blob WHERE blob_hash = ?", listOf(hash(2))))
        assertEquals(0L, f.count("inbox_source"))
        // The 'done' half of the trigger: sources present on a fetched row (the §4.1 source insert
        // never adds them, so they are inserted directly here) go when the row becomes done, and
        // only that row's. A trigger that fired on 'fetched' alone would leave both of hash 1's.
        db.exec(source, listOf(f.ns, hash(1), 1, "candidate"))
        db.exec(source, listOf(f.ns, hash(1), 2, "bad"))
        db.exec(source, listOf(f.ns, hash(2), 1, "candidate"))
        assertEquals(2L, sources(1))
        // markConsumed (§4.3) is true exactly once.
        val consumed = "UPDATE inbox_blob SET state = 'done', ciphertext = NULL, fetch_seq = NULL, offers = 0, offer_after_minute = 0 " +
            "WHERE namespace_id = ? AND blob_hash = ? AND state = 'fetched'"
        assertEquals(1, db.changes(consumed, f.ns, hash(1)))
        assertEquals(0L, sources(1))
        assertEquals(1L, sources(2))
        assertEquals(0, db.changes(consumed, f.ns, hash(1)))
        assertEquals("done", f.inboxState(1))
        assertEquals(1, db.changes(consumed, f.ns, hash(2)))
        assertEquals(0L, f.count("inbox_source"))
    }
}
