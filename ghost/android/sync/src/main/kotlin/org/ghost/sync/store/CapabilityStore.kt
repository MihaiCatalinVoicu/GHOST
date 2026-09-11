package org.ghost.sync.store

import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.CapabilityNeed
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.RelayId
import org.ghost.sync.api.SyncChange
import org.ghost.sync.api.SyncTransaction

/** A usable token and the generation it was read at (the rejection race guard, design §3.8). */
internal class CapabilityToken(val kind: CapabilityKind, token: ByteArray, val generation: Long) {
    private val bytes: ByteArray = token.copyOf()

    val token: ByteArray get() = bytes.copyOf()

    override fun toString(): String = "CapabilityToken($kind, redacted)"
}

/**
 * `relay_capability` (design §3.8). Tokens are opaque bytes: stored and used, never parsed or
 * minted here. Every mutation is guarded by the expected state and, for refusals, by the
 * generation the failing call used.
 */
internal class CapabilityStore {

    /** Upserts a usable token with generation + 1 (1 for a new row); returns the new generation. */
    fun put(tx: SyncTransaction, relay: RelayId, ns: NamespaceId, kind: CapabilityKind, token: ByteArray, expiresAtEpochSeconds: Long?): Long {
        require(token.size in 1..MAX_TOKEN_SIZE) { "capability token has the wrong length" }
        val sql = tx.sql
        check(sql.single("SELECT 1 FROM relay_directory WHERE relay_id = ?1", listOf(relay.value)) { 1 } != null) { "unknown relay" }
        check(sql.single("SELECT 1 FROM sync_namespace WHERE namespace_id = ?1", listOf(ns.raw)) { 1 } != null) { "namespace is not registered" }
        val expiresHour = expiresAtEpochSeconds?.let { Time.floorHour(it) }
        sql.updateExactly(
            1,
            "INSERT INTO relay_capability(relay_id, namespace_id, kind, token, expires_hour, state, generation) " +
                "VALUES (?1, ?2, ?3, ?4, ?5, 'usable', 1) " +
                "ON CONFLICT(relay_id, namespace_id, kind) DO UPDATE SET token = excluded.token, " +
                "expires_hour = excluded.expires_hour, state = 'usable', generation = relay_capability.generation + 1",
            listOf(relay.value, ns.raw, kind.code, token, expiresHour),
        )
        tx.hint(SyncChange.CAPABILITIES)
        return generation(tx, relay, ns, kind) ?: throw IllegalStateException("capability row vanished")
    }

    /** The usable, unexpired token of this kind, or null. */
    fun usable(tx: SyncTransaction, relay: RelayId, ns: NamespaceId, kind: CapabilityKind, now: Long): CapabilityToken? =
        tx.sql.single(
            "SELECT token, generation FROM relay_capability WHERE relay_id = ?1 AND namespace_id = ?2 AND kind = ?3 " +
                "AND state = 'usable' AND (expires_hour IS NULL OR expires_hour > ?4)",
            listOf(relay.value, ns.raw, kind.code, now),
        ) { CapabilityToken(kind, it.blob(0), it.long(1)) }

    /**
     * Lists and gets use the read token, or the write token when no read token is usable (write
     * grants read). An exhausted write token still reads: the relay charges quota only on store
     * (design §3.6, `quota` cannot occur on list, get or check), so a store quota running out never
     * ends a pair's listing.
     */
    fun forReading(tx: SyncTransaction, relay: RelayId, ns: NamespaceId, now: Long): CapabilityToken? =
        usable(tx, relay, ns, CapabilityKind.READ, now) ?: readableWrite(tx, relay, ns, now)

    /**
     * Own-copy checks (verification, resolution, design §3.4, §3.5) use the write token, usable or
     * exhausted, and the read token when there is no write token that reads.
     */
    fun forChecking(tx: SyncTransaction, relay: RelayId, ns: NamespaceId, now: Long): CapabilityToken? =
        readableWrite(tx, relay, ns, now) ?: usable(tx, relay, ns, CapabilityKind.READ, now)

    private fun readableWrite(tx: SyncTransaction, relay: RelayId, ns: NamespaceId, now: Long): CapabilityToken? =
        tx.sql.single(
            "SELECT token, generation FROM relay_capability WHERE relay_id = ?1 AND namespace_id = ?2 AND kind = 'write' " +
                "AND state IN ('usable', 'exhausted') AND (expires_hour IS NULL OR expires_hour > ?3)",
            listOf(relay.value, ns.raw, now),
        ) { CapabilityToken(CapabilityKind.WRITE, it.blob(0), it.long(1)) }

    fun generation(tx: SyncTransaction, relay: RelayId, ns: NamespaceId, kind: CapabilityKind): Long? =
        tx.sql.single(
            "SELECT generation FROM relay_capability WHERE relay_id = ?1 AND namespace_id = ?2 AND kind = ?3",
            listOf(relay.value, ns.raw, kind.code),
        ) { it.long(0) }

    /**
     * A call made with [generation] was refused (`unauthorized` → rejected, `quota` → exhausted).
     * Marks the row only if it is still that generation and usable; a newer token installed
     * meanwhile stays usable. Returns true if the row was marked.
     */
    fun refuse(tx: SyncTransaction, relay: RelayId, ns: NamespaceId, kind: CapabilityKind, generation: Long, exhausted: Boolean): Boolean {
        val marked = tx.sql.execUpdate(
            "UPDATE relay_capability SET state = ?5 WHERE relay_id = ?1 AND namespace_id = ?2 AND kind = ?3 " +
                "AND generation = ?4 AND state = 'usable'",
            listOf(relay.value, ns.raw, kind.code, generation, if (exhausted) "exhausted" else "rejected"),
        ) == 1
        if (marked) tx.hint(SyncChange.CAPABILITIES)
        return marked
    }

    /**
     * What Phase 8 should obtain (design §3.8), for relays active in a namespace's set:
     *  - an existing token that is rejected, exhausted, or usable but expiring within 24 h (EXPIRING
     *    also covers an already expired one);
     *  - READ MISSING for a listening namespace with no token of either kind on that relay;
     *  - WRITE MISSING where the outbox still has work at the relay (deliveries waiting to be
     *    stored, acknowledged ones awaiting verification, possible copies still resolvable) and no
     *    write token exists.
     */
    fun needed(tx: SyncTransaction, now: Long): List<CapabilityNeed> {
        val sql = tx.sql
        val out = LinkedHashSet<CapabilityNeed>()
        sql.rows(
            "SELECT c.relay_id, c.namespace_id, c.kind, c.state, c.expires_hour FROM relay_capability c " +
                "JOIN namespace_relay nr ON nr.namespace_id = c.namespace_id AND nr.relay_id = c.relay_id " +
                "JOIN relay_directory rd ON rd.relay_id = c.relay_id WHERE rd.state = 'active' " +
                "ORDER BY c.relay_id, c.namespace_id, c.kind",
        ) { row ->
            val reason = when (row.string(3)) {
                "rejected" -> CapabilityNeed.Reason.REJECTED
                "exhausted" -> CapabilityNeed.Reason.EXHAUSTED
                else -> if (!row.isNull(4) && row.long(4) <= now + EXPIRING_SECONDS) CapabilityNeed.Reason.EXPIRING else null
            }
            reason?.let { CapabilityNeed(RelayId(row.long(0)), NamespaceId(row.blob(1)), CapabilityKind.ofCode(row.string(2)), it) }
        }.filterNotNull().forEach { out += it }
        sql.rows(
            "SELECT nr.relay_id, nr.namespace_id FROM namespace_relay nr " +
                "JOIN sync_namespace n ON n.namespace_id = nr.namespace_id " +
                "JOIN relay_directory rd ON rd.relay_id = nr.relay_id " +
                "WHERE rd.state = 'active' AND n.listening = 1 AND NOT EXISTS (SELECT 1 FROM relay_capability c " +
                "WHERE c.relay_id = nr.relay_id AND c.namespace_id = nr.namespace_id) ORDER BY nr.relay_id, nr.namespace_id",
        ) { CapabilityNeed(RelayId(it.long(0)), NamespaceId(it.blob(1)), CapabilityKind.READ, CapabilityNeed.Reason.MISSING) }
            .forEach { out += it }
        // A write token is missing wherever the outbox still has work at the relay: deliveries that
        // may store (pending, parked), acknowledged ones awaiting verification, and possible copies
        // still resolvable by a check (the same set as OutboxStore.workPairs). Without a token that
        // can check, an acknowledged delivery could never be verified or struck, and its op would
        // stay undecided for ever (found by seeded world 18694).
        sql.rows(
            "SELECT DISTINCT d.relay_id, o.namespace_id FROM outbox_delivery d " +
                "JOIN outbox_op o ON o.operation_id = d.operation_id " +
                "JOIN relay_directory rd ON rd.relay_id = d.relay_id " +
                "WHERE rd.state = 'active' AND (d.state IN ('pending', 'wait_capability', 'acked') " +
                "OR (d.copy_hour IS NOT NULL AND d.ack_minute IS NULL AND d.state IN ('failed', 'closed') " +
                "AND ?1 < d.copy_hour + o.ttl_seconds - ?2)) " +
                "AND NOT EXISTS (SELECT 1 FROM relay_capability c " +
                "WHERE c.relay_id = d.relay_id AND c.namespace_id = o.namespace_id AND c.kind = 'write') ORDER BY d.relay_id, o.namespace_id",
            listOf(now, RetentionPolicy.SKEW_SECONDS),
        ) { CapabilityNeed(RelayId(it.long(0)), NamespaceId(it.blob(1)), CapabilityKind.WRITE, CapabilityNeed.Reason.MISSING) }
            .forEach { out += it }
        return out.toList()
    }

    /** Deletes capabilities one day past their expiry hour; returns the number deleted. */
    fun collect(tx: SyncTransaction, now: Long): Int =
        tx.sql.execUpdate(
            "DELETE FROM relay_capability WHERE expires_hour IS NOT NULL AND expires_hour + ?1 <= ?2",
            listOf(RetentionPolicy.CAPABILITY_GRACE_SECONDS, now),
        )

    companion object {
        const val MAX_TOKEN_SIZE: Int = 512
        const val EXPIRING_SECONDS: Long = 24 * 3600
    }
}
