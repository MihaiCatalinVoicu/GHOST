package org.ghost.storage

import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue

internal const val CHECK_FAILED = "CHECK constraint failed"
internal const val FOREIGN_KEY_FAILED = "FOREIGN KEY constraint failed"
internal const val UNIQUE_FAILED = "UNIQUE constraint failed"

internal fun bytes(size: Int, fill: Int) = ByteArray(size) { fill.toByte() }
internal fun opId(i: Int) = bytes(16, i)
internal fun hash(i: Int) = bytes(32, i)

/** `OnionAddress.toString()` shape: 56-character host, ".onion:", port. */
internal fun onion(i: Int, port: String = "443"): String = ('a' + i).toString().repeat(56) + ".onion:" + port

/** Asserts that [sql] fails and that the SQLite message names the expected mechanism. */
internal fun SqlExecutor.rejects(fragment: String, sql: String, vararg args: Any?) {
    val e = assertThrows(sql, java.sql.SQLException::class.java) { exec(sql, args.toList()) }
    assertTrue("expected '$fragment' for [$sql], got: ${e.message}", e.message.orEmpty().contains(fragment))
}

internal fun SqlExecutor.changes(sql: String, vararg args: Any?): Int = execUpdate(sql, args.toList())

/** A migrated v2 database with two active relays of distinct operators and one listening namespace. */
internal class SyncFixture : AutoCloseable {
    val db = JdbcSqlExecutor().also { MigrationRunner(it).migrate() }
    val ns = bytes(32, 1)

    init {
        relay(1)
        relay(2)
        namespace(ns)
    }

    fun relay(id: Int, operator: Int = id) = db.exec(
        "INSERT INTO relay_directory(relay_id, onion_address, operator_id, state, source) VALUES (?, ?, ?, 'active', 'config')",
        listOf(id, onion(id), bytes(16, operator)),
    )

    fun namespace(id: ByteArray, listening: Int = 1) =
        db.exec("INSERT INTO sync_namespace(namespace_id, consumer, listening) VALUES (?, 'dm', ?)", listOf(id, listening))

    /** A pending 7-day op in [namespace] carrying a 1 KiB payload unless [ciphertext] says otherwise. */
    fun op(i: Int, namespace: ByteArray = ns, ciphertext: ByteArray? = bytes(1024, i)) = db.exec(
        "INSERT INTO outbox_op(operation_id, namespace_id, blob_hash, ciphertext, ttl_seconds, not_before_minute, required_operators, outcome) " +
            "VALUES (?, ?, ?, ?, 604800, 0, 2, 'pending')",
        listOf(opId(i), namespace, hash(i), ciphertext),
    )

    fun delivery(i: Int, relay: Int) = db.exec(
        "INSERT INTO outbox_delivery(operation_id, relay_id, state, next_attempt_minute) VALUES (?, ?, 'pending', 0)",
        listOf(opId(i), relay),
    )

    fun deliveryState(i: Int, relay: Int): String? =
        db.queryString("SELECT state FROM outbox_delivery WHERE operation_id = ? AND relay_id = ?", listOf(opId(i), relay))

    fun updateDelivery(i: Int, relay: Int, set: String, vararg args: Any?): Int =
        db.execUpdate("UPDATE outbox_delivery SET $set WHERE operation_id = ? AND relay_id = ?", args.toList() + listOf(opId(i), relay))

    fun rejectsDeliveryUpdate(fragment: String, i: Int, relay: Int, set: String, vararg args: Any?) =
        db.rejects(fragment, "UPDATE outbox_delivery SET $set WHERE operation_id = ? AND relay_id = ?", *(args.toList() + listOf(opId(i), relay)).toTypedArray())

    fun updateOp(i: Int, set: String, vararg args: Any?): Int =
        db.execUpdate("UPDATE outbox_op SET $set WHERE operation_id = ?", args.toList() + listOf(opId(i)))

    fun rejectsOpUpdate(fragment: String, i: Int, set: String, vararg args: Any?) =
        db.rejects(fragment, "UPDATE outbox_op SET $set WHERE operation_id = ?", *(args.toList() + listOf(opId(i))).toTypedArray())

    fun listed(i: Int, namespace: ByteArray = ns) = db.exec(
        "INSERT INTO inbox_blob(namespace_id, blob_hash, state, retain_until_day) VALUES (?, ?, 'listed', 112)",
        listOf(namespace, hash(i)),
    )

    fun inboxState(i: Int, namespace: ByteArray = ns): String? =
        db.queryString("SELECT state FROM inbox_blob WHERE namespace_id = ? AND blob_hash = ?", listOf(namespace, hash(i)))

    fun count(table: String): Long = db.queryLong("SELECT count(*) FROM $table")!!

    override fun close() = db.close()
}
