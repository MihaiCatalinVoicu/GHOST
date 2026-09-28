package org.ghost.messaging.harness

import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import org.ghost.storage.Schema

/**
 * SCN-L-v3's database (§15.3 SCN-L, CS-9; design §22.38): a **v3** file — the schema a device had
 * before the DM tables, written by the real runner up to version 3 — with Phase 7 rows in its
 * outbox and inbox, and [kept], the CS-9 check of what migrations 4 and 5 must preserve.
 *
 * **What it holds.** One `channel` namespace nobody listens to; one relay, retired; three outbox
 * ops at the non-contiguous rowids [ROWIDS], each with a delivery, driven through the v2 triggers
 * to a terminal outcome, released and wiped; two inbox tombstones (`done`). **Terminal, not
 * pending**, and declared so: the migrated device runs the real Phase 7 engine, which would try to
 * deliver a pending op to a relay the crash world does not have, and the [DmScenario.nothingOwed]
 * oracle counts unreleased ops and unconsumed inbox rows. A **pending** op across the rebuild
 * stays `SchemaAndMigrationTest`'s (every statement of migration 4 interrupted, then migrated).
 *
 * **Why the rowids are not contiguous.** Migration 4 rebuilds `outbox_op` and copies each row
 * **with its rowid** (`INSERT INTO outbox_op_v4(rowid, …) SELECT rowid, …`). A copy without it
 * numbers the rows 1, 2, 3 in the same order, which on a contiguous table is the same set of
 * rowids and on this one is not — the one fixture on which MC-17's rowid half is visible at all.
 */
internal object DmV3Fixture {
    val NAMESPACE: ByteArray = ByteArray(32) { 0x2c }
    const val RELAY: Long = 900
    val ROWIDS: List<Long> = listOf(3L, 7L, 12L)
    private val OUTCOMES = listOf("sent", "failed", "degraded")
    private val TOMBSTONES = listOf(ByteArray(32) { 0x51 }, ByteArray(32) { 0x52 })

    /** A valid v3 onion address no node of a crash world uses (theirs are seeds 0 … slotCount − 1). */
    private val ONION: String = org.ghost.messaging.OwnerWorld.onion(99).toString()

    private fun operationId(i: Int) = ByteArray(16) { (0x60 + i).toByte() }
    private fun blobHash(i: Int) = ByteArray(32) { (0x40 + i).toByte() }

    /** Writes the v3 file at [raw]'s path. Nothing here is an event: [raw] is not on the bus. */
    fun build(raw: JdbcSqlExecutor) {
        check(MigrationRunner(raw, Schema.migrations.filter { it.version <= 3 }).migrate() == listOf(1, 2, 3)) {
            "the v3 fixture's file was not empty"
        }
        raw.exec(
            "INSERT INTO relay_directory(relay_id, onion_address, operator_id, state, source, retired_day) " +
                "VALUES (?, ?, ?, 'retired', 'config', 1)",
            listOf(RELAY, ONION, ByteArray(16) { 0x33 }),
        )
        raw.exec("INSERT INTO sync_namespace(namespace_id, consumer, listening) VALUES (?, 'channel', 0)", listOf(NAMESPACE))
        for ((i, rowid) in ROWIDS.withIndex()) {
            val op = operationId(i)
            raw.exec(
                "INSERT INTO outbox_op(rowid, operation_id, namespace_id, blob_hash, ciphertext, ttl_seconds, " +
                    "not_before_minute, deadline_hour, required_operators, outcome) " +
                    "VALUES (?, ?, ?, ?, ?, 86400, 0, 86400, 2, 'pending')",
                listOf(rowid, op, NAMESPACE, blobHash(i), ByteArray(1024) { (i + 1).toByte() }),
            )
            raw.exec(
                "INSERT INTO outbox_delivery(operation_id, relay_id, state, next_attempt_minute) VALUES (?, ?, 'pending', 0)",
                listOf(op, RELAY),
            )
            // Through the v2 state machines, as the Phase 7 engine would have left them.
            raw.exec("UPDATE outbox_delivery SET state = 'closed' WHERE operation_id = ?", listOf(op))
            raw.exec("UPDATE outbox_op SET outcome = ? WHERE operation_id = ?", listOf(OUTCOMES[i], op))
            raw.exec("UPDATE outbox_op SET ciphertext = NULL WHERE operation_id = ?", listOf(op))
            raw.exec("UPDATE outbox_op SET released = 1 WHERE operation_id = ?", listOf(op))
        }
        for (hash in TOMBSTONES) {
            raw.exec(
                "INSERT INTO inbox_blob(namespace_id, blob_hash, state, retain_until_day) VALUES (?, ?, 'done', 7)",
                listOf(NAMESPACE, hash),
            )
        }
        val written = rows(raw)
        check(written == expected()) { "the v3 fixture wrote $written, not ${expected()}" }
    }

    /**
     * CS-9 (§15.3 SCN-L; `SchemaAndMigrationTest`'s clause in a crash world): after migrations 4
     * and 5, every Phase 7 row of the v3 file is there, **at its rowid**, with the columns v3 had.
     */
    fun kept(raw: JdbcSqlExecutor, who: String) {
        val now = rows(raw)
        val want = expected()
        if (now != want) {
            dmViolation(
                "$who did not keep the v3 file's Phase 7 rows (CS-9): missing ${want - now.toSet()}, " +
                    "unexpected ${now - want.toSet()}",
            )
        }
    }

    /** The rows [kept] compares, one line each, in a fixed order. */
    private fun rows(raw: JdbcSqlExecutor): List<String> {
        val out = ArrayList<String>()
        raw.query(
            "SELECT rowid, operation_id, namespace_id, blob_hash, ciphertext IS NULL, ttl_seconds, not_before_minute, " +
                "deadline_hour, required_operators, outcome, released FROM outbox_op ORDER BY rowid",
        ) { r ->
            out += "outbox_op rowid ${r.long(0)} ${r.blob(1).hex()} ns ${r.blob(2).hex()} hash ${r.blob(3).hex()} " +
                "wiped ${r.long(4)} ttl ${r.long(5)} ${r.long(6)}..${r.long(7)} operators ${r.long(8)} " +
                "${r.string(9)} released ${r.long(10)}"
        }
        raw.query(
            "SELECT operation_id, relay_id, state, attempts, inflight, copy_hour IS NULL FROM outbox_delivery " +
                "ORDER BY operation_id, relay_id",
        ) { r ->
            out += "outbox_delivery ${r.blob(0).hex()} relay ${r.long(1)} ${r.string(2)} attempts ${r.long(3)} " +
                "inflight ${r.long(4)} no copy ${r.long(5)}"
        }
        raw.query("SELECT namespace_id, blob_hash, state, retain_until_day FROM inbox_blob ORDER BY namespace_id, blob_hash") { r ->
            out += "inbox_blob ${r.blob(0).hex()} ${r.blob(1).hex()} ${r.string(2)} until ${r.long(3)}"
        }
        raw.query("SELECT relay_id, onion_address, state, retired_day FROM relay_directory WHERE relay_id = ?", listOf(RELAY)) { r ->
            out += "relay ${r.long(0)} ${r.string(1)} ${r.string(2)} ${r.long(3)}"
        }
        raw.query("SELECT namespace_id, consumer, listening FROM sync_namespace WHERE namespace_id = ?", listOf(NAMESPACE)) { r ->
            out += "namespace ${r.blob(0).hex()} ${r.string(1)} listening ${r.long(2)}"
        }
        return out
    }

    private fun expected(): List<String> {
        val out = ArrayList<String>()
        for ((i, rowid) in ROWIDS.withIndex()) {
            out += "outbox_op rowid $rowid ${operationId(i).hex()} ns ${NAMESPACE.hex()} hash ${blobHash(i).hex()} " +
                "wiped 1 ttl 86400 0..86400 operators 2 ${OUTCOMES[i]} released 1"
        }
        for (i in ROWIDS.indices) {
            out += "outbox_delivery ${operationId(i).hex()} relay $RELAY closed attempts 0 inflight 0 no copy 1"
        }
        for (hash in TOMBSTONES) out += "inbox_blob ${NAMESPACE.hex()} ${hash.hex()} done until 7"
        out += "relay $RELAY $ONION retired 1"
        out += "namespace ${NAMESPACE.hex()} channel listening 0"
        return out
    }

    private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }
}
