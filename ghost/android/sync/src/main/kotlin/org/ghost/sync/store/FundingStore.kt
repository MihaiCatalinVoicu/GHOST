package org.ghost.sync.store

import org.ghost.sync.api.Consumer
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.SyncChange
import org.ghost.sync.api.SyncTransaction

/**
 * `sync_namespace_fund` (Phase 10 design §7.5 item 1, §9 migration 6): the presence of a row is the
 * fact that this client funds the namespace. The table has a REPLACE guard, so the flag is written
 * by an INSERT that finds no row, never by an INSERT OR IGNORE or an upsert.
 *
 * A change of the flag is a [SyncChange.CAPABILITIES] hint: which needs [CapabilityStore.needed]
 * reports and which registration rows are due both depend on it, so the engine's pair snapshot is
 * refreshed. Nothing else is touched: the flag causes no relay traffic by itself.
 */
internal class FundingStore {

    /**
     * True when the call changed the flag. Only a channel namespace can be funded: for any other the flag
     * would move the registrations of a Phase 9 owner namespace (a DM inbox, a bundle) from its write
     * capability to a second, token-bought registration capability, silently doubling its token spend
     * (Phase 10 review of S1a, §19.33). Taking the flag off is a no-op for a namespace that has none, of
     * whatever consumer.
     */
    fun set(tx: SyncTransaction, ns: NamespaceId, funded: Boolean): Boolean {
        val changed = if (funded) {
            val consumer = tx.sql.single("SELECT consumer FROM sync_namespace WHERE namespace_id = ?1", listOf(ns.raw)) { it.string(0) }
            check(consumer != null) { "namespace is not registered" }
            check(consumer == Consumer.CHANNEL.code) { "only a channel namespace can be funded" }
            tx.sql.execUpdate(
                "INSERT INTO sync_namespace_fund(namespace_id) SELECT ?1 " +
                    "WHERE NOT EXISTS (SELECT 1 FROM sync_namespace_fund WHERE namespace_id = ?1)",
                listOf(ns.raw),
            )
        } else {
            tx.sql.execUpdate("DELETE FROM sync_namespace_fund WHERE namespace_id = ?1", listOf(ns.raw))
        }
        if (changed > 0) tx.hint(SyncChange.CAPABILITIES)
        return changed > 0
    }

    fun isFunded(tx: SyncTransaction, ns: NamespaceId): Boolean =
        tx.sql.single("SELECT 1 FROM sync_namespace_fund WHERE namespace_id = ?1", listOf(ns.raw)) { 1 } != null
}
