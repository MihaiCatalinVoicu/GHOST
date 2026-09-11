package org.ghost.sync.store

import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.BlobHash
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.OperationId
import org.ghost.sync.api.SyncTransaction

/** Rows deleted by one garbage-collection pass. */
internal class GcReport(
    val operations: Int,
    val tombstones: Int,
    val listedRows: Int,
    val capabilities: Int,
    val relays: Int,
    val namespaces: Int,
) {
    val total: Int get() = operations + tombstones + listedRows + capabilities + relays + namespaces

    override fun toString(): String =
        "GcReport(operations=$operations, tombstones=$tombstones, listed=$listedRows, capabilities=$capabilities, " +
            "relays=$relays, namespaces=$namespaces)"
}

/**
 * Garbage collection (design §2.3, §11.2 #7 and #19). It relies on a trusted clock, so the engine
 * runs it only after the transport reached READY in this process (design §3.7). Fetched rows are
 * never collected (no loss); `done` tombstones of own blobs are kept while their op exists.
 */
internal class Gc(private val outbox: OutboxStore, private val capabilities: CapabilityStore) {

    fun pass(tx: SyncTransaction, now: Long): GcReport {
        val sql = tx.sql
        val today = Time.day(now)
        val batch = RetentionPolicy.GC_BATCH

        // Released ops without payload: raise the own tombstone to today + TTL + 8, then delete (deliveries cascade).
        val ops = sql.rows(
            "SELECT operation_id, ttl_seconds FROM outbox_op WHERE released = 1 AND ciphertext IS NULL ORDER BY operation_id LIMIT ?1",
            listOf(batch),
        ) { Pair(OperationId(it.blob(0)), it.long(1)) }
        ops.forEach { (op, ttl) -> outbox.deleteReleased(tx, op, ttl, now) }

        // Tombstones past their day whose op is gone; then listed/unavailable rows past their day.
        val tombstones = keys(
            sql,
            "SELECT b.namespace_id, b.blob_hash FROM inbox_blob b WHERE b.state = 'done' AND b.retain_until_day < ?1 " +
                "AND NOT EXISTS (SELECT 1 FROM outbox_op o WHERE o.namespace_id = b.namespace_id AND o.blob_hash = b.blob_hash) " +
                "ORDER BY b.retain_until_day LIMIT ?2",
            today,
            batch,
        )
        tombstones.forEach { (ns, h) -> deleteRow(sql, ns, h, "done") }
        val listed = keys(
            sql,
            "SELECT namespace_id, blob_hash FROM inbox_blob WHERE state IN ('listed', 'unavailable') AND retain_until_day < ?1 " +
                "ORDER BY retain_until_day LIMIT ?2",
            today,
            batch - tombstones.size,
        )
        listed.forEach { (ns, h) -> deleteRow(sql, ns, h, null) }

        val caps = capabilities.collect(tx, now)

        // Relays retired for LISTED_RETAIN days that nothing refers to (capabilities, cursors, sources cascade).
        val relays = sql.execUpdate(
            "DELETE FROM relay_directory WHERE state = 'retired' AND retired_day + ?1 <= ?2 " +
                "AND NOT EXISTS (SELECT 1 FROM namespace_relay nr WHERE nr.relay_id = relay_directory.relay_id) " +
                "AND NOT EXISTS (SELECT 1 FROM outbox_delivery d WHERE d.relay_id = relay_directory.relay_id)",
            listOf(RetentionPolicy.RETIRED_RELAY_DAYS, today),
        )

        // Removed namespaces (§11.2 #19) whose last row is gone.
        val namespaces = sql.execUpdate(
            "DELETE FROM sync_namespace WHERE listening = 0 " +
                "AND NOT EXISTS (SELECT 1 FROM namespace_relay nr WHERE nr.namespace_id = sync_namespace.namespace_id) " +
                "AND NOT EXISTS (SELECT 1 FROM relay_capability c WHERE c.namespace_id = sync_namespace.namespace_id) " +
                "AND NOT EXISTS (SELECT 1 FROM relay_cursor r WHERE r.namespace_id = sync_namespace.namespace_id) " +
                "AND NOT EXISTS (SELECT 1 FROM inbox_blob b WHERE b.namespace_id = sync_namespace.namespace_id) " +
                "AND NOT EXISTS (SELECT 1 FROM outbox_op o WHERE o.namespace_id = sync_namespace.namespace_id)",
        )
        return GcReport(ops.size, tombstones.size, listed.size, caps, relays, namespaces)
    }

    /**
     * After a pass that deleted rows: truncate the WAL so deleted pages leave the log (design §2.3).
     * Runs outside any transaction, through `query` because the pragma returns a row.
     */
    fun checkpoint(sql: SqlExecutor) {
        check(!sql.inTransaction) { "checkpoint inside a transaction" }
        sql.query("PRAGMA wal_checkpoint(TRUNCATE)") { }
    }

    /** Collects up to [limit] (namespace, hash) keys; [query] takes ?1 = today and ?2 = limit. */
    private fun keys(sql: SqlExecutor, query: String, today: Long, limit: Int): List<Pair<NamespaceId, BlobHash>> =
        if (limit <= 0) emptyList() else sql.rows(query, listOf(today, limit)) { Pair(NamespaceId(it.blob(0)), BlobHash(it.blob(1))) }

    private fun deleteRow(sql: SqlExecutor, ns: NamespaceId, hash: BlobHash, state: String?) {
        val guard = if (state == "done") "state = 'done'" else "state IN ('listed', 'unavailable')"
        sql.updateExactly(1, "DELETE FROM inbox_blob WHERE namespace_id = ?1 AND blob_hash = ?2 AND $guard", listOf(ns.raw, hash.raw))
    }
}
