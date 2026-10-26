package org.ghost.sync.store

import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.RelayEntry

/**
 * §7.8 / D19's directory application, run by the update wiring inside the ACCEPT transaction.
 * The accept owns the `BEGIN IMMEDIATE` on a raw [SqlExecutor] (no [org.ghost.sync.api.SyncTransaction]
 * exists there), so this is raw SQL next to [DirectoryStore]'s — one known follow-up: retiring
 * here does not run [OutboxStore]'s delivery-failure coupling (it needs a SyncTransaction); reads
 * filter `state = 'active'` in any case, so a retired relay simply drops out of every read set.
 */
object ManifestDirectory {

    private class Row(val id: Long, val address: String, val operator: ByteArray, val active: Boolean)

    /**
     * Syncs `relay_directory` to [entries]: new onions are inserted, known ones reactivated with
     * their source refreshed. Operator ids are write-once per onion (D19, F9 §5.2): an entry
     * whose onion exists with a different operator is left untouched and still counts as
     * present — a manifest cannot relabel the operators relay sets count.
     *
     * With [retireOthers] every active row whose onion is not in [entries] is retired: a fresh
     * verified manifest takes the directory over, bootstrap (`config`) entries included. The
     * bootstrap fill passes `retireOthers = false` on an empty table, where the step is a no-op
     * by construction.
     */
    fun apply(sql: SqlExecutor, entries: List<RelayEntry>, now: Long, retireOthers: Boolean) {
        val day = Time.day(now)
        val wanted = entries.associateBy { it.address.toString() }
        val rows = sql.rows("SELECT relay_id, onion_address, operator_id, state FROM relay_directory") {
            Row(it.long(0), it.string(1), it.blob(2), it.string(3) == "active")
        }
        val byAddress = rows.associateBy { it.address }
        for (entry in entries) {
            val existing = byAddress[entry.address.toString()]
            if (existing == null) {
                sql.execUpdate(
                    "INSERT INTO relay_directory(onion_address, operator_id, state, source, retired_day) " +
                        "VALUES (?1, ?2, 'active', ?3, NULL)",
                    listOf(entry.address.toString(), entry.rawOperatorId, entry.source.code),
                )
            } else if (existing.operator.contentEquals(entry.rawOperatorId) &&
                (!existing.active || sourceOf(sql, existing.id) != entry.source.code)
            ) {
                sql.execUpdate(
                    "UPDATE relay_directory SET state = 'active', source = ?1, retired_day = NULL WHERE relay_id = ?2",
                    listOf(entry.source.code, existing.id),
                )
            }
            // else: write-once operator mismatch — the row stays exactly as it is.
        }
        if (retireOthers) {
            for (row in rows) {
                if (row.active && row.address !in wanted) {
                    sql.execUpdate(
                        "UPDATE relay_directory SET state = 'retired', retired_day = ?1 WHERE relay_id = ?2 AND state = 'active'",
                        listOf(day, row.id),
                    )
                }
            }
        }
    }

    private fun sourceOf(sql: SqlExecutor, relayId: Long): String =
        sql.single("SELECT source FROM relay_directory WHERE relay_id = ?1", listOf(relayId)) { it.string(0) }
            ?: throw IllegalStateException("relay row vanished")
}
