package org.ghost.storage

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * REPLACE conflict resolution against the write-once, frozen and state rules of v2 and v3 (Phase 8
 * design §19.21 point 4). With `recursive_triggers` off (SQLite's default; no GHOST connection turns it
 * on), a row that REPLACE deletes to resolve a PRIMARY KEY or UNIQUE conflict fires no DELETE trigger,
 * and the row written in its place passes no UPDATE trigger. A BEFORE INSERT trigger runs before the
 * conflict is resolved, hence the guards of migration 3 (`<table>_no_replace`):
 *  - every v3 table with rules refuses an INSERT that conflicts on any of its keys, so INSERT OR REPLACE
 *    neither deletes nor overwrites one of its rows (INSERT OR IGNORE and UPSERT are refused alike);
 *  - a table whose DELETE is restricted (ent_key, ent_schedule_fact, ent_purchase, outbox_op) also never
 *    changes a key in an UPDATE, so UPDATE OR REPLACE deletes none of its rows;
 *  - outbox_op is a released v2 table: migration 3 creates its guard, v2 is unchanged;
 *  - outbox_delivery and inbox_blob (v2) restrict transitions, not deletion, and are written with
 *    INSERT OR IGNORE and UPSERT, which a guard would refuse: there a REPLACE does what a DELETE followed
 *    by an INSERT may do, and the row it writes still passes the insert trigger.
 */
class ReplaceGuardsTest {
    /** Every form of insert; on a guarded table each is refused for a key that exists. */
    private val insertForms = listOf("INSERT OR REPLACE", "REPLACE", "INSERT OR IGNORE", "INSERT")

    private fun SqlExecutor.rejectsEveryInsert(fragment: String, into: String, vararg args: Any?) {
        for (form in insertForms) rejects(fragment, "$form INTO $into", *args)
    }

    /** One row of [sql] as `a|b|...` (NULL spelled out), for comparing rows written two ways. */
    private fun SqlExecutor.row(sql: String, columns: Int, vararg args: Any?): String {
        var out = ""
        query(sql, args.toList()) { r -> out = (0 until columns).joinToString("|") { if (r.isNull(it)) "NULL" else r.string(it) } }
        return out
    }

    @Test
    fun replaceSkipsDeleteTriggersAndEveryInsertFormRunsBeforeInsertTriggers(): Unit = JdbcSqlExecutor().use { db ->
        MigrationRunner(db).migrate()
        MigrationRunner(db).verifyIntegrity()
        assertEquals(0L, db.queryLong("PRAGMA recursive_triggers"))
        db.exec("CREATE TEMP TABLE probe (k INTEGER NOT NULL PRIMARY KEY, v INTEGER NOT NULL) WITHOUT ROWID")
        db.exec("CREATE TEMP TRIGGER probe_no_delete BEFORE DELETE ON probe BEGIN SELECT RAISE(ABORT, 'probe rows are never deleted'); END")
        db.exec("INSERT INTO probe(k, v) VALUES (1, 10), (2, 20)")
        db.rejects("probe rows are never deleted", "DELETE FROM probe WHERE k = 1")
        // The mechanism: REPLACE deletes the conflicting row without running its DELETE trigger...
        db.exec("INSERT OR REPLACE INTO probe(k, v) VALUES (1, 11)")
        assertEquals(11L, db.queryLong("SELECT v FROM probe WHERE k = 1"))
        // ...also when an UPDATE moves a row onto another row's key.
        db.exec("UPDATE OR REPLACE probe SET k = 1 WHERE k = 2")
        assertEquals(1L, db.queryLong("SELECT count(*) FROM probe"))
        assertEquals(20L, db.queryLong("SELECT v FROM probe WHERE k = 1"))
        // The guard: a BEFORE INSERT trigger runs before the conflict is resolved, for every form of
        // insert, so it refuses REPLACE and equally INSERT OR IGNORE and UPSERT (which is why
        // outbox_delivery and inbox_blob, written that way, carry none).
        db.exec(
            "CREATE TEMP TRIGGER probe_no_replace BEFORE INSERT ON probe WHEN EXISTS (SELECT 1 FROM probe WHERE k = NEW.k) " +
                "BEGIN SELECT RAISE(ABORT, 'probe rows are never replaced'); END",
        )
        db.rejectsEveryInsert("probe rows are never replaced", "probe(k, v) VALUES (1, 12)")
        db.rejects("probe rows are never replaced", "INSERT INTO probe(k, v) VALUES (1, 12) ON CONFLICT(k) DO NOTHING")
        db.rejects("probe rows are never replaced", "INSERT INTO probe(k, v) VALUES (1, 12) ON CONFLICT(k) DO UPDATE SET v = excluded.v")
        assertEquals(20L, db.queryLong("SELECT v FROM probe WHERE k = 1"))
        // A multi-row statement meets its own earlier rows, and the whole statement is undone.
        db.rejects("probe rows are never replaced", "INSERT OR REPLACE INTO probe(k, v) VALUES (3, 30), (3, 31)")
        assertEquals(null, db.queryLong("SELECT v FROM probe WHERE k = 3"))
    }

    @Test
    fun everyGuardCoversEveryKeyOfItsTableAndOnlyTwoV2TablesGoWithout(): Unit = JdbcSqlExecutor().use { db ->
        MigrationRunner(db).migrate()
        val triggers = HashMap<String, MutableList<Pair<String, String>>>()
        db.query("SELECT tbl_name, name, sql FROM sqlite_master WHERE type = 'trigger'") {
            triggers.getOrPut(it.string(0)) { ArrayList() } += it.string(1) to it.string(2).replace(Regex("\\s+"), " ")
        }
        fun tablesWhere(test: (Pair<String, String>) -> Boolean) = triggers.filterValues { it.any(test) }.keys
        val withRules = tablesWhere { (_, sql) -> Regex("BEFORE (UPDATE|DELETE)").containsMatchIn(sql) }
        val guarded = tablesWhere { (name, _) -> name.endsWith("_no_replace") }
        val deleteRules = tablesWhere { (_, sql) -> sql.contains("BEFORE DELETE ON") }
        // Every table whose DELETE is restricted is guarded: REPLACE would skip that rule.
        assertEquals(setOf("ent_key", "ent_schedule_fact", "ent_purchase", "outbox_op"), deleteRules)
        assertEquals(emptySet<String>(), deleteRules - guarded)
        // Every table with rules is guarded, except the two v2 tables whose rules are transitions only
        // and whose writers use INSERT OR IGNORE and UPSERT.
        assertEquals(setOf("outbox_delivery", "inbox_blob"), withRules - guarded)
        assertEquals(emptySet<String>(), guarded - withRules)
        for (table in guarded) {
            val (name, sql) = triggers.getValue(table).single { it.first.endsWith("_no_replace") }
            assertEquals("${table}_no_replace", name)
            assertTrue(sql, sql.contains("BEFORE INSERT ON $table WHEN EXISTS (SELECT 1 FROM $table WHERE "))
            // Every key a new row could conflict on: the primary key, each unique index, a hidden rowid.
            val keys = LinkedHashSet<String>()
            val pkTypes = ArrayList<String>()
            db.query("PRAGMA table_info($table)") {
                if (it.long(5) > 0) {
                    keys += it.string(1)
                    pkTypes += it.string(2)
                }
            }
            val unique = ArrayList<String>()
            db.query("PRAGMA index_list($table)") { if (it.long(2) == 1L) unique += it.string(1) }
            for (index in unique) db.query("PRAGMA index_info($index)") { keys += it.string(2) }
            var create = ""
            db.query("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", listOf(table)) { create = it.string(0) }
            val rowidTable = !create.trimEnd().endsWith("WITHOUT ROWID")
            if (rowidTable && pkTypes != listOf("INTEGER")) keys += "rowid"
            for (key in keys) assertTrue("$name misses $key", sql.contains("NEW.$key"))
        }
    }

    @Test
    fun esKeysAreNeverReplaced(): Unit = EntitlementFixture().use { f ->
        val db = f.db
        val msg = "ent_key is append-only"
        db.exec("INSERT INTO ent_key(kind, epoch, key_id) VALUES ('access', ?, ?), ('access', ?, ?)", listOf(WEEK0, hash(1), WEEK0 + 1, hash(2)))
        db.rejectsEveryInsert(msg, "ent_key(kind, epoch, key_id) VALUES ('access', ?, ?)", WEEK0, hash(9))
        db.rejects(msg, "INSERT OR REPLACE INTO ent_key(kind, epoch, key_id) VALUES ('invite', 726, ?), ('invite', 726, ?)", hash(3), hash(4))
        // No UPDATE runs at all, so none can move a row onto another row's key.
        db.rejects(msg, "UPDATE OR REPLACE ent_key SET epoch = ? WHERE epoch = ?", WEEK0, WEEK0 + 1)
        assertArrayEquals(hash(1), db.queryBlob("SELECT key_id FROM ent_key WHERE kind = 'access' AND epoch = ?", listOf(WEEK0)))
        assertArrayEquals(hash(2), db.queryBlob("SELECT key_id FROM ent_key WHERE kind = 'access' AND epoch = ?", listOf(WEEK0 + 1)))
        assertEquals(2L, db.queryLong("SELECT count(*) FROM ent_key"))
        // The same epoch of another kind is another key.
        db.exec("INSERT INTO ent_key(kind, epoch, key_id) VALUES ('credit', ?, ?)", listOf(WEEK0, hash(5)))
    }

    @Test
    fun scheduleFactsAndRevocationsAreNeverReplaced(): Unit = EntitlementFixture().use { f ->
        val db = f.db
        val msg = "ent_schedule_fact is append-only"
        val facts = listOf("slots" to WEEK0, "price" to 223L, "revoked_access" to 726L, "revoked_access" to 727L)
        for ((i, fact) in facts.withIndex()) {
            db.exec("INSERT INTO ent_schedule_fact(fact, epoch, digest) VALUES (?, ?, ?)", listOf(fact.first, fact.second, hash(1 + i)))
        }
        // A remembered revocation rewritten to another digest (or a slot set, or a price) would change
        // what an accepted schedule fixed; a revocation replaced away would make a leaked key valid again.
        for ((fact, epoch) in facts) {
            db.rejectsEveryInsert(msg, "ent_schedule_fact(fact, epoch, digest) VALUES (?, ?, ?)", fact, epoch, hash(9))
        }
        db.rejects(msg, "UPDATE OR REPLACE ent_schedule_fact SET epoch = 726 WHERE fact = 'revoked_access' AND epoch = 727")
        for ((i, fact) in facts.withIndex()) {
            assertArrayEquals(
                fact.first, hash(1 + i),
                db.queryBlob("SELECT digest FROM ent_schedule_fact WHERE fact = ? AND epoch = ?", listOf(fact.first, fact.second)),
            )
        }
        assertEquals(4L, db.queryLong("SELECT count(*) FROM ent_schedule_fact"))
    }

    @Test
    fun purchasesAreNeverReplacedAndKeepTheirId(): Unit = EntitlementFixture().use { f ->
        val db = f.db
        val msg = "ent_purchase rows are never replaced"
        val frozen = "issuance secrets and layout are frozen once sent"
        // A live, sent pack (never deleted) and a failed one (deleted by GC, never replaced).
        f.purchase(1)
        assertEquals(1, f.invoice(1))
        f.purchase(2)
        assertEquals(1, f.terminal(2, "failed"))
        val insert = "ent_purchase(purchase_id, kind, pay_with, state, seed, claim_key, base_week, schedule_seq, layout_digest, created_hour) " +
            "VALUES (?, 'pack', 'xmr', 'prepared', ?, ?, ?, 1, ?, ?)"
        for (i in 1..2) db.rejectsEveryInsert(msg, insert, purchaseId(i), bytes(32, 9), bytes(32, 9), WEEK0 + 1, bytes(32, 9), T0)
        assertEquals("invoiced", f.purchaseState(1))
        assertArrayEquals(bytes(32, 0x31), db.queryBlob("SELECT seed FROM ent_purchase WHERE purchase_id = ?", listOf(purchaseId(1))))
        assertArrayEquals(bytes(16, 0x71), db.queryBlob("SELECT invoice_id FROM ent_purchase WHERE purchase_id = ?", listOf(purchaseId(1))))
        assertEquals("failed", f.purchaseState(2))
        // The id never changes: UPDATE OR REPLACE would otherwise move the failed row onto the live one,
        // delete the live one past ent_purchase_delete_terminal_only, and make its credits releasable.
        db.rejects(frozen, "UPDATE OR REPLACE ent_purchase SET purchase_id = ? WHERE purchase_id = ?", purchaseId(1), purchaseId(2))
        f.rejectsPurchaseUpdate(frozen, 1, "purchase_id = ?", purchaseId(3))
        f.rejectsPurchaseUpdate(frozen, 2, "purchase_id = ?", purchaseId(3))
        assertEquals("invoiced", f.purchaseState(1))
        assertEquals("failed", f.purchaseState(2))
        assertEquals(2L, db.queryLong("SELECT count(*) FROM ent_purchase"))
        // The guard refuses only an existing key: after the GC delete the id is free again.
        assertEquals(1, db.changes("DELETE FROM ent_purchase WHERE purchase_id = ?", purchaseId(2)))
        f.purchase(2)
    }

    @Test
    fun tokensAreNeverReplacedAndAnInsertNeverTakesAHeldReservation(): Unit = EntitlementFixture().use { f ->
        val db = f.db
        val msg = "ent_token rows are never replaced"
        f.accessToken(1)
        assertEquals(1, f.reserveForRelay(1))
        val fresh = "ent_token(nullifier, kind, epoch, slot, token, state, eligible_minute) VALUES (?, 'access', ?, 3, ?, 'fresh', ?)"
        db.rejectsEveryInsert(msg, fresh, hash(1), WEEK0, bytes(354, 9), T0)
        // A new token already reserved for the same (relay, namespace, week) would make REPLACE delete
        // the reserved one through idx_ent_token_one_reservation.
        val reserved = "ent_token(nullifier, kind, epoch, slot, token, state, eligible_minute, reserved_for, reserved_relay, " +
            "reserved_namespace, request_id) VALUES (?, 'access', ?, 3, ?, 'reserved', ?, 'relay', ?, ?, ?)"
        db.rejectsEveryInsert(msg, reserved, hash(2), WEEK0, bytes(354, 2), T0, 1, f.ns, bytes(16, 2))
        // The reserved token keeps its bytes and its binding (R8).
        assertEquals("reserved", f.tokenState(1))
        assertArrayEquals(bytes(354, 1), db.queryBlob("SELECT token FROM ent_token WHERE nullifier = ?", listOf(hash(1))))
        assertArrayEquals(bytes(16, 1), db.queryBlob("SELECT request_id FROM ent_token WHERE nullifier = ?", listOf(hash(1))))
        assertEquals(null, f.tokenState(2))
        // A reservation at another relay is no conflict.
        db.exec("INSERT INTO $reserved", listOf(hash(2), WEEK0, bytes(354, 2), T0, 2, f.ns, bytes(16, 2)))
        // A credit reserved for a purchase keeps its reference too.
        f.token(3, "credit")
        f.purchase(1, payWith = "credits")
        assertEquals(1, f.reserveCredit(3, "purchase", purchaseId(1)))
        db.rejectsEveryInsert(msg, "ent_token(nullifier, kind, epoch, token, state, eligible_minute) VALUES (?, 'credit', 223, ?, 'fresh', ?)", hash(3), bytes(354, 3), T0)
        assertEquals("reserved", f.tokenState(3))
        assertArrayEquals(purchaseId(1), db.queryBlob("SELECT reserved_ref FROM ent_token WHERE nullifier = ?", listOf(hash(3))))
    }

    @Test
    fun invitesAreNeverReplaced(): Unit = EntitlementFixture().use { f ->
        val db = f.db
        val msg = "ent_invite rows are never replaced"
        f.invite(1)
        f.invite(2)
        assertEquals(1, db.changes("UPDATE ent_invite SET state = 'closed', payload = NULL WHERE invite_index = 2 AND state = 'created'"))
        val insert = "ent_invite(invite_index, state, payload, drop_namespace, listen_until_day, refresh_minute) " +
            "VALUES (?, 'created', ?, ?, ?, ?)"
        for (i in 1..2) db.rejectsEveryInsert(msg, insert, i, bytes(538, 9), bytes(32, 9), DAY0 + 90, T0)
        // A closed invite never reopens; a created one keeps its payload and its drop.
        assertEquals("closed", db.queryString("SELECT state FROM ent_invite WHERE invite_index = 2"))
        assertArrayEquals(bytes(538, 1), db.queryBlob("SELECT payload FROM ent_invite WHERE invite_index = 1"))
        assertArrayEquals(bytes(32, 1), db.queryBlob("SELECT drop_namespace FROM ent_invite WHERE invite_index = 1"))
    }

    @Test
    fun claimsAreNeverReplacedAndAnInsertNeverTakesTheOpenSlot(): Unit = EntitlementFixture().use { f ->
        val db = f.db
        val msg = "ent_claim rows are never replaced"
        f.claim(1)
        assertEquals(1, db.changes("UPDATE ent_claim SET sent = 1 WHERE claim_id = ?", claimId(1)))
        val prepared = "ent_claim(claim_id, state, payout_address, next_due_minute) VALUES (?, 'prepared', ?, ?)"
        // The open, sent claim keeps its address...
        db.rejectsEveryInsert(msg, prepared, claimId(1), subaddress(9), T0)
        // ...and a second prepared claim would make REPLACE delete it through idx_ent_claim_one_open.
        db.rejectsEveryInsert(msg, prepared, claimId(2), subaddress(2), T0)
        assertEquals(subaddress(1), db.queryString("SELECT payout_address FROM ent_claim WHERE claim_id = ?", listOf(claimId(1))))
        assertEquals(1L, db.queryLong("SELECT sent FROM ent_claim WHERE claim_id = ?", listOf(claimId(1))))
        assertEquals(1L, db.queryLong("SELECT count(*) FROM ent_claim"))
        // A decided claim never comes back as prepared.
        assertEquals(1, f.decideClaim(1, "queued", 50_000L))
        db.rejectsEveryInsert(msg, prepared, claimId(1), subaddress(1), T0)
        assertEquals("queued", db.queryString("SELECT state FROM ent_claim WHERE claim_id = ?", listOf(claimId(1))))
        // With no claim open, the next one is inserted as before.
        f.claim(2)
    }

    @Test
    fun theDropTargetIsNeverReplaced(): Unit = EntitlementFixture().use { f ->
        val db = f.db
        val msg = "ent_drop_target rows are never replaced"
        f.dropTarget()
        assertEquals(1, db.changes("UPDATE ent_drop_target SET state = 'enqueued', operation_id = ? WHERE id = 1 AND state = 'waiting'", opId(1)))
        // Back to waiting would enqueue the credit a second time.
        db.rejectsEveryInsert(
            msg, "ent_drop_target(id, drop_namespace, drop_key, drop_slots, state, drop_minute, until_day) VALUES (1, ?, ?, ?, 'waiting', ?, ?)",
            bytes(32, 9), bytes(32, 10), byteArrayOf(5, 0, 17), T0, DAY0 + 60,
        )
        assertEquals("enqueued", db.queryString("SELECT state FROM ent_drop_target WHERE id = 1"))
        assertArrayEquals(opId(1), db.queryBlob("SELECT operation_id FROM ent_drop_target WHERE id = 1"))
        assertArrayEquals(bytes(32, 9), db.queryBlob("SELECT drop_namespace FROM ent_drop_target WHERE id = 1"))
    }

    @Test
    fun outboxOpsAreNeverReplacedNorMovedOntoAnotherKey(): Unit = SyncFixture().use { f ->
        val db = f.db
        val msg = "outbox_op rows are never replaced"
        val identity = "outbox_op identity is immutable"
        // A live op (payload held, deliveries pending) and a decided, unreleased one.
        f.op(1)
        f.delivery(1, 1)
        f.delivery(1, 2)
        f.op(2)
        assertEquals(1, f.updateOp(2, "outcome = 'sent'"))
        val insert = "outbox_op(operation_id, namespace_id, blob_hash, ciphertext, ttl_seconds, not_before_minute, required_operators, outcome) " +
            "VALUES (?, ?, ?, ?, 86400, 0, 2, 'pending')"
        // The same operation id (a decided outcome reset, a payload rewritten, deliveries cascaded away)...
        for (i in 1..2) db.rejectsEveryInsert(msg, insert, opId(i), f.ns, hash(i), bytes(1024, 9))
        // ...the same bytes under another id (UNIQUE (namespace_id, blob_hash))...
        db.rejectsEveryInsert(msg, insert, opId(9), f.ns, hash(1), bytes(1024, 9))
        // ...or the hidden rowid of an existing op.
        val rowidOf = "SELECT rowid FROM outbox_op WHERE operation_id = ?"
        val rowid = db.queryLong(rowidOf, listOf(opId(1)))
        val withRowid = "outbox_op(rowid, operation_id, namespace_id, blob_hash, ciphertext, ttl_seconds, not_before_minute, required_operators, " +
            "outcome) VALUES (?, ?, ?, ?, ?, 86400, 0, 2, 'pending')"
        db.rejectsEveryInsert(msg, withRowid, rowid, opId(9), f.ns, hash(9), bytes(1024, 9))
        // No key changes in an UPDATE, so UPDATE OR REPLACE cannot delete another op either.
        f.op(3)
        db.rejects(identity, "UPDATE OR REPLACE outbox_op SET operation_id = ? WHERE operation_id = ?", opId(1), opId(3))
        db.rejects(identity, "UPDATE OR REPLACE outbox_op SET blob_hash = ? WHERE operation_id = ?", hash(1), opId(3))
        db.rejects(identity, "UPDATE OR REPLACE outbox_op SET rowid = ? WHERE operation_id = ?", rowid, opId(3))
        db.rejects(identity, "UPDATE outbox_op SET rowid = rowid + 100 WHERE operation_id = ?", opId(3))
        // Everything is as it was.
        assertEquals(rowid, db.queryLong(rowidOf, listOf(opId(1))))
        assertArrayEquals(bytes(1024, 1), db.queryBlob("SELECT ciphertext FROM outbox_op WHERE operation_id = ?", listOf(opId(1))))
        assertEquals("sent", db.queryString("SELECT outcome FROM outbox_op WHERE operation_id = ?", listOf(opId(2))))
        assertEquals(2L, db.queryLong("SELECT count(*) FROM outbox_delivery WHERE operation_id = ?", listOf(opId(1))))
        assertEquals(3L, f.count("outbox_op"))
        // Enqueue's resend of identical bytes (faza7 §9): the released, wiped op is deleted explicitly
        // first (its DELETE rule holds), then the same bytes enter under the new id.
        assertEquals(1, f.updateOp(2, "released = 1"))
        assertEquals(1, f.updateOp(2, "ciphertext = NULL"))
        db.rejectsEveryInsert(msg, insert, opId(4), f.ns, hash(2), bytes(1024, 4))
        assertEquals(1, db.changes("DELETE FROM outbox_op WHERE operation_id = ?", opId(2)))
        assertEquals(1, db.changes("INSERT INTO $insert", opId(4), f.ns, hash(2), bytes(1024, 4)))
    }

    @Test
    fun aDeliveryReplaceDoesNoMoreThanADeleteAndAnInsert(): Unit = SyncFixture().use { f ->
        val db = f.db
        val insertRule = "a new delivery starts pending, idle, without copies, and needs the payload"
        f.op(1)
        f.delivery(1, 1)
        f.delivery(1, 2)
        for (relay in 1..2) assertEquals(1, f.updateDelivery(1, relay, "state = 'acked', ack_minute = 60, copy_hour = 3600"))
        val replace = "INSERT OR REPLACE INTO outbox_delivery(operation_id, relay_id, state, next_attempt_minute, inflight, lease_hour, copy_hour, " +
            "ack_minute) VALUES (?, ?, ?, 0, ?, ?, ?, ?)"
        // The row REPLACE writes passes outbox_delivery_insert: it cannot claim a receipt, a copy or a
        // lease, and the refused statement leaves the existing row as it was.
        for (state in listOf("wait_capability", "acked", "verified", "failed", "closed")) db.rejects(insertRule, replace, opId(1), 1, state, 0, null, 3600, 60)
        db.rejects(insertRule, replace, opId(1), 1, "pending", 1, 3600, null, null)
        db.rejects(insertRule, replace, opId(1), 1, "pending", 0, null, 3600, null)
        assertEquals("acked", f.deliveryState(1, 1))
        // What it can write, a DELETE followed by an INSERT writes too: v2 restricts delivery
        // transitions, not deletion, so REPLACE bypasses no rule here.
        db.exec(replace, listOf(opId(1), 1, "pending", 0, null, null, null))
        assertEquals(1, db.changes("DELETE FROM outbox_delivery WHERE operation_id = ? AND relay_id = 2", opId(1)))
        f.delivery(1, 2)
        val row = "SELECT state, attempts, next_attempt_minute, inflight, lease_hour, copy_hour, ack_minute, strikes FROM outbox_delivery " +
            "WHERE operation_id = ? AND relay_id = ?"
        assertEquals(db.row(row, 8, opId(1), 2), db.row(row, 8, opId(1), 1))
        // Once the payload is wiped no delivery of the op is written any more, REPLACE included: the
        // deliveries its outcome was decided from stay as they are.
        assertEquals(1, f.updateDelivery(1, 1, "state = 'verified', copy_hour = 3600"))
        assertEquals(1, f.updateDelivery(1, 2, "state = 'failed'"))
        assertEquals(1, f.updateOp(1, "ciphertext = NULL"))
        for (relay in 1..2) db.rejects(insertRule, replace, opId(1), relay, "pending", 0, null, null, null)
        assertEquals("verified", f.deliveryState(1, 1))
        assertEquals("failed", f.deliveryState(1, 2))
    }

    @Test
    fun anInboxReplaceDoesNoMoreThanADeleteAndAnInsert(): Unit = SyncFixture().use { f ->
        val db = f.db
        val insertRule = "inbox rows start listed (or done for own blobs)"
        f.listed(1)
        f.listed(2)
        assertEquals(1, db.changes("UPDATE inbox_blob SET state = 'fetched', ciphertext = ?, fetch_seq = 1 WHERE blob_hash = ?", bytes(1024, 2), hash(2)))
        db.exec("INSERT INTO inbox_blob(namespace_id, blob_hash, state, retain_until_day) VALUES (?, ?, 'done', 112)", listOf(f.ns, hash(3)))
        val replace = "INSERT OR REPLACE INTO inbox_blob(namespace_id, blob_hash, state, ciphertext, fetch_seq, retain_until_day) VALUES (?, ?, ?, ?, ?, 112)"
        // The row REPLACE writes passes inbox_blob_insert: it cannot hand the consumer a fabricated
        // blob or mark one unavailable, and the refused statement leaves the existing row as it was.
        for (i in 1..3) {
            db.rejects(insertRule, replace, f.ns, hash(i), "fetched", bytes(1024, 9), 9)
            db.rejects(insertRule, replace, f.ns, hash(i), "unavailable", null, null)
        }
        assertEquals(listOf("listed", "fetched", "done"), (1..3).map { f.inboxState(it) })
        assertArrayEquals(bytes(1024, 2), db.queryBlob("SELECT ciphertext FROM inbox_blob WHERE blob_hash = ?", listOf(hash(2))))
        // What it can write (a listed or done row), a DELETE followed by an INSERT writes too: inbox rows
        // are deleted by retention, and the foreign-key cascade removes their sources either way.
        val source = "INSERT INTO inbox_source(namespace_id, blob_hash, relay_id, state) VALUES (?, ?, 1, 'candidate')"
        f.listed(4)
        db.exec(source, listOf(f.ns, hash(1)))
        db.exec(source, listOf(f.ns, hash(4)))
        db.exec(replace, listOf(f.ns, hash(1), "done", null, null))
        assertEquals(1, db.changes("DELETE FROM inbox_blob WHERE blob_hash = ?", hash(4)))
        db.exec("INSERT INTO inbox_blob(namespace_id, blob_hash, state, retain_until_day) VALUES (?, ?, 'done', 112)", listOf(f.ns, hash(4)))
        val row = "SELECT state, ciphertext IS NULL, fetch_seq IS NULL, fetch_attempts, next_fetch_minute, offers, offer_after_minute, " +
            "retain_until_day FROM inbox_blob WHERE namespace_id = ? AND blob_hash = ?"
        assertEquals(db.row(row, 8, f.ns, hash(4)), db.row(row, 8, f.ns, hash(1)))
        assertEquals(0L, f.count("inbox_source"))
    }

    @Test
    fun aNullWrittenUnderReplaceBecomesTheDefaultWithoutRelaxingAV2Rule(): Unit = SyncFixture().use { f ->
        // Under OR REPLACE a NULL written into a NOT NULL column with a DEFAULT becomes that default after
        // the BEFORE triggers ran (§19.20 point 1 for the v3 `sent`). The two v2 trigger conditions that
        // read such a column hold as written: a release never goes back, and a new delivery is idle anyway.
        val db = f.db
        val release = "release happens once, after the outcome"
        val nullRelease = "UPDATE OR REPLACE outbox_op SET released = NULL WHERE operation_id = ?"
        val released = "SELECT released FROM outbox_op WHERE operation_id = ?"
        f.op(1)
        assertEquals(1, f.updateOp(1, "outcome = 'sent'"))
        assertEquals(1, f.updateOp(1, "released = 1"))
        db.rejects(release, nullRelease, opId(1))
        assertEquals(1L, db.queryLong(released, listOf(opId(1))))
        f.op(2)
        db.rejects(release, nullRelease, opId(2))
        // Decided and not released: the NULL skips the trigger and becomes 0, which it already was.
        f.op(3)
        assertEquals(1, f.updateOp(3, "outcome = 'failed'"))
        assertEquals(1, db.changes(nullRelease, opId(3)))
        assertEquals(0L, db.queryLong(released, listOf(opId(3))))
        db.exec(
            "INSERT OR REPLACE INTO outbox_delivery(operation_id, relay_id, state, next_attempt_minute, inflight) VALUES (?, 1, 'pending', 0, NULL)",
            listOf(opId(2)),
        )
        assertEquals(0L, db.queryLong("SELECT inflight FROM outbox_delivery WHERE operation_id = ?", listOf(opId(2))))
    }
}
