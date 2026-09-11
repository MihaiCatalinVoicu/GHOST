package org.ghost.sync.store

import org.ghost.network.OnionAddress
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.RelayEntry
import org.ghost.sync.api.RelayId
import org.ghost.sync.api.SendDelay
import org.ghost.sync.api.SyncChange
import org.ghost.sync.api.SyncTransaction

/** A relay directory row. */
internal class RelayRow(val id: RelayId, val entry: RelayEntry, val active: Boolean) {
    override fun toString(): String = "RelayRow(redacted)"
}

/** A registered namespace. */
internal class NamespaceRow(val id: NamespaceId, val consumer: Consumer, val listening: Boolean, val sendDelay: SendDelay) {
    override fun toString(): String = "NamespaceRow($consumer, listening=$listening, $sendDelay)"
}

/** A pair the read lane lists: listening namespace × active relay of its set with a usable read (or write) token. */
internal class ReadPair(
    val relayId: RelayId,
    val relay: OnionAddress,
    val namespace: NamespaceId,
    cursor: ByteArray?,
    val capability: CapabilityToken,
) {
    private val storedCursor: ByteArray? = cursor?.copyOf()

    /** The stored cursor, or empty (from the beginning). */
    val cursor: ByteArray get() = storedCursor?.copyOf() ?: ByteArray(0)

    override fun toString(): String = "ReadPair(redacted)"
}

/**
 * `relay_directory`, `sync_namespace` and `namespace_relay` (design §3.9, §11.2 #15 and #19).
 * Relays are retired, never deleted while referenced; a retired address re-added later reactivates
 * the same row with its cursors and capabilities.
 */
internal class DirectoryStore(
    private val outbox: OutboxStore,
    private val capabilities: CapabilityStore,
) {

    // ------------------------------------------------------------------ relays

    fun upsert(tx: SyncTransaction, entries: List<RelayEntry>): Map<OnionAddress, RelayId> {
        val sql = tx.sql
        val out = LinkedHashMap<OnionAddress, RelayId>()
        for (entry in entries) {
            sql.updateExactly(
                1,
                "INSERT INTO relay_directory(onion_address, operator_id, state, source, retired_day) VALUES (?1, ?2, 'active', ?3, NULL) " +
                    "ON CONFLICT(onion_address) DO UPDATE SET operator_id = excluded.operator_id, source = excluded.source, " +
                    "state = 'active', retired_day = NULL",
                listOf(entry.address.toString(), entry.rawOperatorId, entry.source.code),
            )
            out[entry.address] = sql.single(
                "SELECT relay_id FROM relay_directory WHERE onion_address = ?1",
                listOf(entry.address.toString()),
            ) { RelayId(it.long(0)) } ?: throw IllegalStateException("relay row vanished")
        }
        if (entries.isNotEmpty()) tx.hint(SyncChange.TOPOLOGY)
        return out
    }

    /** Retires an active relay; its open deliveries fail (possible copies are kept). False if already retired. */
    fun retire(tx: SyncTransaction, relay: RelayId, now: Long): Boolean {
        val sql = tx.sql
        checkRelayExists(tx, relay)
        val changed = sql.execUpdate(
            "UPDATE relay_directory SET state = 'retired', retired_day = ?1 WHERE relay_id = ?2 AND state = 'active'",
            listOf(Time.day(now), relay.value),
        )
        if (changed == 0) return false
        outbox.failDeliveriesTo(tx, relay, null, now)
        tx.hint(SyncChange.TOPOLOGY)
        return true
    }

    fun relays(tx: SyncTransaction, activeOnly: Boolean): List<RelayRow> =
        tx.sql.rows(
            "SELECT relay_id, onion_address, operator_id, source, state FROM relay_directory " +
                (if (activeOnly) "WHERE state = 'active' " else "") + "ORDER BY relay_id",
        ) {
            RelayRow(
                RelayId(it.long(0)),
                RelayEntry(OnionAddress.parse(it.string(1)), it.blob(2), RelayEntry.Source.ofCode(it.string(3))),
                it.string(4) == "active",
            )
        }

    fun address(tx: SyncTransaction, relay: RelayId): OnionAddress? =
        tx.sql.single("SELECT onion_address FROM relay_directory WHERE relay_id = ?1", listOf(relay.value)) { OnionAddress.parse(it.string(0)) }

    private fun checkRelayExists(tx: SyncTransaction, relay: RelayId) {
        check(tx.sql.single("SELECT 1 FROM relay_directory WHERE relay_id = ?1", listOf(relay.value)) { 1 } != null) { "unknown relay" }
    }

    // ------------------------------------------------------------------ namespaces

    fun namespace(tx: SyncTransaction, ns: NamespaceId): NamespaceRow? =
        tx.sql.single(
            "SELECT consumer, listening, send_delay FROM sync_namespace WHERE namespace_id = ?1",
            listOf(ns.raw),
        ) { NamespaceRow(ns, Consumer.ofCode(it.string(0)), it.long(1) == 1L, SendDelay.ofCode(it.string(2))) }

    fun namespaces(tx: SyncTransaction): List<NamespaceRow> =
        tx.sql.rows("SELECT namespace_id, consumer, listening, send_delay FROM sync_namespace ORDER BY namespace_id") {
            NamespaceRow(NamespaceId(it.blob(0)), Consumer.ofCode(it.string(1)), it.long(2) == 1L, SendDelay.ofCode(it.string(3)))
        }

    /**
     * Registers [ns] or reuses its row (a known namespace keeps its consumer and its tombstones),
     * then applies [relays] as [setRelays] does.
     */
    fun register(
        tx: SyncTransaction,
        ns: NamespaceId,
        consumer: Consumer,
        relays: Set<RelayId>,
        listen: Boolean,
        sendDelay: SendDelay,
        now: Long,
    ) {
        val sql = tx.sql
        val existing = namespace(tx, ns)
        check(existing == null || existing.consumer == consumer) { "namespace is registered for another consumer" }
        sql.updateExactly(
            1,
            "INSERT INTO sync_namespace(namespace_id, consumer, listening, send_delay) VALUES (?1, ?2, ?3, ?4) " +
                "ON CONFLICT(namespace_id) DO UPDATE SET listening = excluded.listening, send_delay = excluded.send_delay",
            listOf(ns.raw, consumer.code, if (listen) 1 else 0, sendDelay.code),
        )
        setRelays(tx, ns, relays, now)
        tx.hint(SyncChange.TOPOLOGY)
    }

    /**
     * Replaces the relay set (design §3.9): removed relays' open deliveries fail (copy hours kept),
     * added active relays get pending deliveries for ops that still hold their payload and whose
     * window is open; D1, D2, W run for every op touched.
     */
    fun setRelays(tx: SyncTransaction, ns: NamespaceId, relays: Set<RelayId>, now: Long) {
        val sql = tx.sql
        checkNotNull(namespace(tx, ns)) { "namespace is not registered" }
        relays.forEach { checkRelayExists(tx, it) }
        val current = sql.rows("SELECT relay_id FROM namespace_relay WHERE namespace_id = ?1", listOf(ns.raw)) { RelayId(it.long(0)) }.toSet()
        for (removed in current - relays) {
            sql.updateExactly(1, "DELETE FROM namespace_relay WHERE namespace_id = ?1 AND relay_id = ?2", listOf(ns.raw, removed.value))
            outbox.failDeliveriesTo(tx, removed, ns, now)
        }
        for (added in relays - current) {
            sql.updateExactly(1, "INSERT INTO namespace_relay(namespace_id, relay_id) VALUES (?1, ?2)", listOf(ns.raw, added.value))
            outbox.addDeliveries(tx, ns, added, now)
        }
        tx.hint(SyncChange.TOPOLOGY)
    }

    fun setListening(tx: SyncTransaction, ns: NamespaceId, listen: Boolean) {
        checkNotNull(namespace(tx, ns)) { "namespace is not registered" }
        tx.sql.updateExactly(1, "UPDATE sync_namespace SET listening = ?1 WHERE namespace_id = ?2", listOf(if (listen) 1 else 0, ns.raw))
        tx.hint(SyncChange.TOPOLOGY)
    }

    fun setSendDelay(tx: SyncTransaction, ns: NamespaceId, sendDelay: SendDelay) {
        checkNotNull(namespace(tx, ns)) { "namespace is not registered" }
        tx.sql.updateExactly(1, "UPDATE sync_namespace SET send_delay = ?1 WHERE namespace_id = ?2", listOf(sendDelay.code, ns.raw))
    }

    /**
     * §11.2 #19: refuses (false) while the namespace has ops or fetched rows, and for an unknown
     * namespace. Otherwise stops listening and drops its relay set, cursors, capabilities and
     * not-yet-fetched rows; `done` tombstones stay until their retention day. The namespace row is
     * deleted now if no inbox row is left, otherwise by garbage collection after the last one.
     */
    fun remove(tx: SyncTransaction, ns: NamespaceId): Boolean {
        val sql = tx.sql
        if (namespace(tx, ns) == null) return false
        val ops = sql.single("SELECT count(*) FROM outbox_op WHERE namespace_id = ?1", listOf(ns.raw)) { it.long(0) } ?: 0L
        val fetched = sql.single(
            "SELECT count(*) FROM inbox_blob WHERE namespace_id = ?1 AND state = 'fetched'",
            listOf(ns.raw),
        ) { it.long(0) } ?: 0L
        if (ops > 0 || fetched > 0) return false
        sql.updateExactly(1, "UPDATE sync_namespace SET listening = 0 WHERE namespace_id = ?1", listOf(ns.raw))
        sql.execUpdate("DELETE FROM namespace_relay WHERE namespace_id = ?1", listOf(ns.raw))
        sql.execUpdate("DELETE FROM relay_cursor WHERE namespace_id = ?1", listOf(ns.raw))
        val capabilitiesDropped = sql.execUpdate("DELETE FROM relay_capability WHERE namespace_id = ?1", listOf(ns.raw))
        sql.execUpdate("DELETE FROM inbox_blob WHERE namespace_id = ?1 AND state IN ('listed', 'unavailable')", listOf(ns.raw))
        sql.execUpdate(
            "DELETE FROM sync_namespace WHERE namespace_id = ?1 AND NOT EXISTS (SELECT 1 FROM inbox_blob b WHERE b.namespace_id = ?1)",
            listOf(ns.raw),
        )
        if (capabilitiesDropped > 0) tx.hint(SyncChange.CAPABILITIES)
        tx.hint(SyncChange.TOPOLOGY)
        return true
    }

    // ------------------------------------------------------------------ read-lane snapshot

    /**
     * Read pairs with their stored cursor and read token (design §1.4 snapshot, §4.1): listening
     * namespaces × active relays of their set that have a usable read or write token.
     */
    fun readPairs(tx: SyncTransaction, now: Long): List<ReadPair> {
        val candidates = tx.sql.rows(
            "SELECT nr.relay_id, rd.onion_address, nr.namespace_id, cur.cursor FROM namespace_relay nr " +
                "JOIN sync_namespace n ON n.namespace_id = nr.namespace_id " +
                "JOIN relay_directory rd ON rd.relay_id = nr.relay_id " +
                "LEFT JOIN relay_cursor cur ON cur.relay_id = nr.relay_id AND cur.namespace_id = nr.namespace_id " +
                "WHERE n.listening = 1 AND rd.state = 'active' ORDER BY nr.relay_id, nr.namespace_id",
        ) { CandidatePair(RelayId(it.long(0)), it.string(1), NamespaceId(it.blob(2)), if (it.isNull(3)) null else it.blob(3)) }
        return candidates.mapNotNull { pair ->
            capabilities.forReading(tx, pair.relay, pair.namespace, now)?.let { token ->
                ReadPair(pair.relay, OnionAddress.parse(pair.address), pair.namespace, pair.cursor, token)
            }
        }
    }

    private class CandidatePair(val relay: RelayId, val address: String, val namespace: NamespaceId, val cursor: ByteArray?)
}
