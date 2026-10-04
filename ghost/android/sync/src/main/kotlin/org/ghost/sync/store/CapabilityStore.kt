package org.ghost.sync.store

import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.CapabilityNeed
import org.ghost.sync.api.CapabilitySource
import org.ghost.sync.api.InstalledCapability
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.RelayId
import org.ghost.sync.api.SyncChange
import org.ghost.sync.api.SyncTransaction
import org.ghost.storage.SqlExecutor

/** A usable token and the generation it was read at (the rejection race guard, design §3.8). */
internal class CapabilityToken(val kind: CapabilityKind, token: ByteArray, val generation: Long) {
    private val bytes: ByteArray = token.copyOf()

    val token: ByteArray get() = bytes.copyOf()

    override fun toString(): String = "CapabilityToken($kind, redacted)"
}

/**
 * `relay_capability` (design §3.8) and, for [CapabilityKind.REGISTER], `relay_register_capability`
 * (Phase 10 design §7.5 item 2, migration 6). Tokens are opaque bytes: stored and used, never parsed
 * or minted here. Every mutation is guarded by the expected state and, for refusals, by the
 * generation the failing call used.
 *
 * The registration capability has its own table and its own statements ([put], [usable], [installed],
 * [generation] and [refuse] dispatch on the kind), and **no reader of the other kinds touches it**:
 * [forReading], [forChecking] and the outbox's store lease select from `relay_capability` alone,
 * which is how "store, list, get and check never read it" (design §7.5 item 2) holds.
 */
internal class CapabilityStore {

    /**
     * Upserts a usable token with generation + 1 (1 for a new row); returns the new generation. A
     * registration capability ([CapabilityKind.REGISTER]) must declare its expiry: its week is read from
     * it, by the relay and by the registration step's due rule, so one without an expiry names no week and
     * serves no registration, yet reads as usable, is never expiring, collected or renewed, and suppresses
     * REGISTER MISSING for its pair for ever (found by the Phase 10 review of S1a, §19.33). Every
     * redemption carries an expiry, so nothing that exists installs one without.
     */
    fun put(tx: SyncTransaction, relay: RelayId, ns: NamespaceId, kind: CapabilityKind, token: ByteArray, expiresAtEpochSeconds: Long?): Long {
        require(token.size in 1..MAX_TOKEN_SIZE) { "capability token has the wrong length" }
        require(kind != CapabilityKind.REGISTER || expiresAtEpochSeconds != null) { "a registration capability needs a declared expiry" }
        val sql = tx.sql
        check(sql.single("SELECT 1 FROM relay_directory WHERE relay_id = ?1", listOf(relay.value)) { 1 } != null) { "unknown relay" }
        check(sql.single("SELECT 1 FROM sync_namespace WHERE namespace_id = ?1", listOf(ns.raw)) { 1 } != null) { "namespace is not registered" }
        val expiresHour = expiresAtEpochSeconds?.let { Time.floorHour(it) }
        if (kind == CapabilityKind.REGISTER) {
            putRegister(sql, relay, ns, token, expiresHour)
        } else {
            sql.updateExactly(
                1,
                "INSERT INTO relay_capability(relay_id, namespace_id, kind, token, expires_hour, state, generation) " +
                    "VALUES (?1, ?2, ?3, ?4, ?5, 'usable', 1) " +
                    "ON CONFLICT(relay_id, namespace_id, kind) DO UPDATE SET token = excluded.token, " +
                    "expires_hour = excluded.expires_hour, state = 'usable', generation = relay_capability.generation + 1",
                listOf(relay.value, ns.raw, kind.code, token, expiresHour),
            )
        }
        tx.hint(SyncChange.CAPABILITIES)
        return generation(tx, relay, ns, kind) ?: throw IllegalStateException("capability row vanished")
    }

    /**
     * The registration capability of the pair: an UPDATE of the row that exists (a new generation, usable
     * again), else an INSERT at generation 1. Two statements, because the table's REPLACE guard refuses
     * every insert of an existing key, upserts included; the UPDATE keeps the generation counting up,
     * which the rejection race guard of [refuse] relies on.
     */
    private fun putRegister(sql: SqlExecutor, relay: RelayId, ns: NamespaceId, token: ByteArray, expiresHour: Long?) {
        val updated = sql.execUpdate(
            "UPDATE relay_register_capability SET token = ?1, expires_hour = ?2, state = 'usable', generation = generation + 1 " +
                "WHERE relay_id = ?3 AND namespace_id = ?4",
            listOf(token, expiresHour, relay.value, ns.raw),
        )
        if (updated == 0) {
            sql.updateExactly(
                1,
                "INSERT INTO relay_register_capability(relay_id, namespace_id, token, expires_hour, state, generation) " +
                    "VALUES (?1, ?2, ?3, ?4, 'usable', 1)",
                listOf(relay.value, ns.raw, token, expiresHour),
            )
        }
    }

    /** The usable, unexpired token of this kind, or null. */
    fun usable(tx: SyncTransaction, relay: RelayId, ns: NamespaceId, kind: CapabilityKind, now: Long): CapabilityToken? =
        if (kind == CapabilityKind.REGISTER) {
            tx.sql.single(
                "SELECT token, generation FROM relay_register_capability WHERE relay_id = ?1 AND namespace_id = ?2 " +
                    "AND state = 'usable' AND (expires_hour IS NULL OR expires_hour > ?3)",
                listOf(relay.value, ns.raw, now),
            ) { CapabilityToken(kind, it.blob(0), it.long(1)) }
        } else {
            tx.sql.single(
                "SELECT token, generation FROM relay_capability WHERE relay_id = ?1 AND namespace_id = ?2 AND kind = ?3 " +
                    "AND state = 'usable' AND (expires_hour IS NULL OR expires_hour > ?4)",
                listOf(relay.value, ns.raw, kind.code, now),
            ) { CapabilityToken(kind, it.blob(0), it.long(1)) }
        }

    /**
     * Lists and gets use the read token, or — **for a namespace whose write capability is redeemed**
     * ([CapabilitySource.REDEEM]) — the write token when no read token is usable (write grants read).
     * An exhausted write token still reads: the relay charges quota only on store (design §3.6, `quota`
     * cannot occur on list, get or check), so a store quota running out never ends a pair's listing. A
     * registration capability never reads (Phase 10 design §7.5 item 2).
     *
     * **F-6, closed by Phase 10 slice S4 (design §19.37; option (a) of §19.33).** A [CapabilitySource.LOCAL]
     * namespace's write slot holds what its consumer installed, which for a channel is the bearer DEPOSIT
     * credential: no relay lets it list (design §7.3: it serves store and check), so the fallback would
     * be refused before any I/O and stop the pair's listing for a day (a BUG flag). A LOCAL namespace
     * therefore reads with its READ credential or not at all, and [needed] reports READ MISSING for its
     * listened pairs that hold none (option (c)); the consumer re-installs it.
     */
    fun forReading(tx: SyncTransaction, relay: RelayId, ns: NamespaceId, now: Long): CapabilityToken? =
        usable(tx, relay, ns, CapabilityKind.READ, now) ?: if (writeReads(tx, ns)) readableWrite(tx, relay, ns, now) else null

    /** Whether the write token may stand in for the read token in [ns]: only where it is redeemed (F-6). */
    private fun writeReads(tx: SyncTransaction, ns: NamespaceId): Boolean =
        tx.sql.single(
            "SELECT capability_source FROM sync_namespace WHERE namespace_id = ?1",
            listOf(ns.raw),
        ) { it.string(0) } == CapabilitySource.REDEEM.code

    /**
     * Own-copy checks (verification, resolution, design §3.4, §3.5) use the write token, usable or
     * exhausted, and the read token when there is no write token that reads. A registration
     * capability never checks (Phase 10 design §7.5 item 2).
     */
    fun forChecking(tx: SyncTransaction, relay: RelayId, ns: NamespaceId, now: Long): CapabilityToken? =
        readableWrite(tx, relay, ns, now) ?: usable(tx, relay, ns, CapabilityKind.READ, now)

    private fun readableWrite(tx: SyncTransaction, relay: RelayId, ns: NamespaceId, now: Long): CapabilityToken? =
        tx.sql.single(
            "SELECT token, generation FROM relay_capability WHERE relay_id = ?1 AND namespace_id = ?2 AND kind = 'write' " +
                "AND state IN ('usable', 'exhausted') AND (expires_hour IS NULL OR expires_hour > ?3)",
            listOf(relay.value, ns.raw, now),
        ) { CapabilityToken(CapabilityKind.WRITE, it.blob(0), it.long(1)) }

    /**
     * The installed row's state and floored expiry hour, without its token (Phase 9 design §4.8:
     * the `KEEPER` step refreshes its own READ credential "when fewer than 7 days remain" and must
     * therefore be able to read back what it installed, without re-putting and bumping the
     * generation on every pass). For [CapabilityKind.REGISTER] the row of `relay_register_capability`.
     */
    fun installed(tx: SyncTransaction, relay: RelayId, ns: NamespaceId, kind: CapabilityKind): InstalledCapability? {
        val read: (SqlExecutor.Row) -> InstalledCapability = { row ->
            val state = when (val code = row.string(0)) {
                "usable" -> InstalledCapability.State.USABLE
                "rejected" -> InstalledCapability.State.REJECTED
                "exhausted" -> InstalledCapability.State.EXHAUSTED
                else -> throw IllegalStateException("unknown capability state '$code'")
            }
            InstalledCapability(state, if (row.isNull(1)) null else row.long(1))
        }
        return if (kind == CapabilityKind.REGISTER) {
            tx.sql.single(
                "SELECT state, expires_hour FROM relay_register_capability WHERE relay_id = ?1 AND namespace_id = ?2",
                listOf(relay.value, ns.raw),
                read,
            )
        } else {
            tx.sql.single(
                "SELECT state, expires_hour FROM relay_capability WHERE relay_id = ?1 AND namespace_id = ?2 AND kind = ?3",
                listOf(relay.value, ns.raw, kind.code),
                read,
            )
        }
    }

    fun generation(tx: SyncTransaction, relay: RelayId, ns: NamespaceId, kind: CapabilityKind): Long? =
        if (kind == CapabilityKind.REGISTER) {
            tx.sql.single(
                "SELECT generation FROM relay_register_capability WHERE relay_id = ?1 AND namespace_id = ?2",
                listOf(relay.value, ns.raw),
            ) { it.long(0) }
        } else {
            tx.sql.single(
                "SELECT generation FROM relay_capability WHERE relay_id = ?1 AND namespace_id = ?2 AND kind = ?3",
                listOf(relay.value, ns.raw, kind.code),
            ) { it.long(0) }
        }

    /**
     * A call made with [generation] was refused (`unauthorized` → rejected, `quota` → exhausted).
     * Marks the row only if it is still that generation and usable; a newer token installed
     * meanwhile stays usable. Returns true if the row was marked.
     */
    fun refuse(tx: SyncTransaction, relay: RelayId, ns: NamespaceId, kind: CapabilityKind, generation: Long, exhausted: Boolean): Boolean {
        val state = if (exhausted) "exhausted" else "rejected"
        val marked = (
            if (kind == CapabilityKind.REGISTER) {
                tx.sql.execUpdate(
                    "UPDATE relay_register_capability SET state = ?4 WHERE relay_id = ?1 AND namespace_id = ?2 " +
                        "AND generation = ?3 AND state = 'usable'",
                    listOf(relay.value, ns.raw, generation, state),
                )
            } else {
                tx.sql.execUpdate(
                    "UPDATE relay_capability SET state = ?5 WHERE relay_id = ?1 AND namespace_id = ?2 AND kind = ?3 " +
                        "AND generation = ?4 AND state = 'usable'",
                    listOf(relay.value, ns.raw, kind.code, generation, state),
                )
            }
            ) == 1
        if (marked) tx.hint(SyncChange.CAPABILITIES)
        return marked
    }

    /**
     * What Phase 8 should obtain (design §3.8), for relays active in a namespace's set:
     *  - an existing token that is rejected, exhausted, or usable but expiring within 24 h (EXPIRING
     *    also covers an already expired one);
     *  - READ MISSING for a listening namespace with no token of either kind on that relay — and, for
     *    a [CapabilitySource.LOCAL] one, with no READ token (its write token never reads, F-6);
     *  - WRITE MISSING where the outbox still has work at the relay (deliveries waiting to be
     *    stored, acknowledged ones awaiting verification, possible copies still resolvable) and no
     *    write token exists;
     *  - WRITE MISSING where a pending key registration of the pair exists and no write token does
     *    (Phase 9 design §13.3 item 4, Q31: a registration is write work like a delivery) — for a
     *    namespace that is not funded; the registrations of a funded one are REGISTER work;
     *  - **REGISTER** (Phase 10 design §7.5 item 1), for funded namespaces only: an existing
     *    registration capability that is rejected, exhausted or expiring, as above, and REGISTER
     *    MISSING where a pending key registration of the pair exists and no registration capability
     *    does. A REGISTER need is always [CapabilitySource.REDEEM], whatever the namespace's own
     *    source: the planner redeems it as a WRITE need of a REDEEM namespace (design §7.6), while the
     *    namespace's store and read credentials stay the consumer's own.
     *
     * Every other need carries the namespace's [CapabilitySource]; the entitlement planner never
     * redeems a LOCAL one (§13.4).
     */
    fun needed(tx: SyncTransaction, now: Long): List<CapabilityNeed> {
        val sql = tx.sql
        val out = LinkedHashSet<CapabilityNeed>()
        sql.rows(
            "SELECT c.relay_id, c.namespace_id, c.kind, c.state, c.expires_hour, n.capability_source FROM relay_capability c " +
                "JOIN namespace_relay nr ON nr.namespace_id = c.namespace_id AND nr.relay_id = c.relay_id " +
                "JOIN sync_namespace n ON n.namespace_id = c.namespace_id " +
                "JOIN relay_directory rd ON rd.relay_id = c.relay_id WHERE rd.state = 'active' " +
                "ORDER BY c.relay_id, c.namespace_id, c.kind",
        ) { row ->
            val reason = when (row.string(3)) {
                "rejected" -> CapabilityNeed.Reason.REJECTED
                "exhausted" -> CapabilityNeed.Reason.EXHAUSTED
                else -> if (!row.isNull(4) && row.long(4) <= now + EXPIRING_SECONDS) CapabilityNeed.Reason.EXPIRING else null
            }
            reason?.let {
                CapabilityNeed(
                    RelayId(row.long(0)), NamespaceId(row.blob(1)), CapabilityKind.ofCode(row.string(2)), it,
                    CapabilitySource.ofCode(row.string(5)),
                )
            }
        }.filterNotNull().forEach { out += it }
        sql.rows(
            "SELECT nr.relay_id, nr.namespace_id, n.capability_source FROM namespace_relay nr " +
                "JOIN sync_namespace n ON n.namespace_id = nr.namespace_id " +
                "JOIN relay_directory rd ON rd.relay_id = nr.relay_id " +
                "WHERE rd.state = 'active' AND n.listening = 1 AND NOT EXISTS (SELECT 1 FROM relay_capability c " +
                "WHERE c.relay_id = nr.relay_id AND c.namespace_id = nr.namespace_id " +
                "AND (n.capability_source = 'redeem' OR c.kind = 'read')) ORDER BY nr.relay_id, nr.namespace_id",
        ) {
            CapabilityNeed(
                RelayId(it.long(0)), NamespaceId(it.blob(1)), CapabilityKind.READ, CapabilityNeed.Reason.MISSING,
                CapabilitySource.ofCode(it.string(2)),
            )
        }.forEach { out += it }
        // A write token is missing wherever the outbox still has work at the relay: deliveries that
        // may store (pending, parked), acknowledged ones awaiting verification, and possible copies
        // still resolvable by a check (the same set as OutboxStore.workPairs). Without a token that
        // can check, an acknowledged delivery could never be verified or struck, and its op would
        // stay undecided for ever (found by seeded world 18694).
        sql.rows(
            "SELECT DISTINCT d.relay_id, o.namespace_id, n.capability_source FROM outbox_delivery d " +
                "JOIN outbox_op o ON o.operation_id = d.operation_id " +
                "JOIN sync_namespace n ON n.namespace_id = o.namespace_id " +
                "JOIN relay_directory rd ON rd.relay_id = d.relay_id " +
                "WHERE rd.state = 'active' AND (d.state IN ('pending', 'wait_capability', 'acked') " +
                "OR (d.copy_hour IS NOT NULL AND d.ack_minute IS NULL AND d.state IN ('failed', 'closed') " +
                "AND ?1 < d.copy_hour + o.ttl_seconds - ?2)) " +
                "AND NOT EXISTS (SELECT 1 FROM relay_capability c " +
                "WHERE c.relay_id = d.relay_id AND c.namespace_id = o.namespace_id AND c.kind = 'write') ORDER BY d.relay_id, o.namespace_id",
            listOf(now, RetentionPolicy.SKEW_SECONDS),
        ) {
            CapabilityNeed(
                RelayId(it.long(0)), NamespaceId(it.blob(1)), CapabilityKind.WRITE, CapabilityNeed.Reason.MISSING,
                CapabilitySource.ofCode(it.string(2)),
            )
        }.forEach { out += it }
        // Phase 9 design §13.3 item 4 (Q31): a pending key registration is write work too, so an
        // owner whose capabilities all lapsed redeems for it and recovers in the background (§13.4).
        // A funded namespace's registrations are served by its registration capability instead
        // (Phase 10 design §7.5 item 2), so they are not write work and are left to the REGISTER query.
        sql.rows(
            "SELECT DISTINCT r.relay_id, r.namespace_id, n.capability_source FROM relay_key_registration r " +
                "JOIN namespace_relay nr ON nr.namespace_id = r.namespace_id AND nr.relay_id = r.relay_id " +
                "JOIN sync_namespace n ON n.namespace_id = r.namespace_id " +
                "JOIN relay_directory rd ON rd.relay_id = r.relay_id " +
                "WHERE rd.state = 'active' AND r.state = 'pending' " +
                "AND NOT EXISTS (SELECT 1 FROM sync_namespace_fund f WHERE f.namespace_id = r.namespace_id) " +
                "AND NOT EXISTS (SELECT 1 FROM relay_capability c " +
                "WHERE c.relay_id = r.relay_id AND c.namespace_id = r.namespace_id AND c.kind = 'write') " +
                "ORDER BY r.relay_id, r.namespace_id",
        ) {
            CapabilityNeed(
                RelayId(it.long(0)), NamespaceId(it.blob(1)), CapabilityKind.WRITE, CapabilityNeed.Reason.MISSING,
                CapabilitySource.ofCode(it.string(2)),
            )
        }.forEach { out += it }
        // Phase 10 design §7.5 item 1: the registration capabilities of the namespaces this client funds.
        sql.rows(
            "SELECT c.relay_id, c.namespace_id, c.state, c.expires_hour FROM relay_register_capability c " +
                "JOIN sync_namespace_fund f ON f.namespace_id = c.namespace_id " +
                "JOIN namespace_relay nr ON nr.namespace_id = c.namespace_id AND nr.relay_id = c.relay_id " +
                "JOIN relay_directory rd ON rd.relay_id = c.relay_id WHERE rd.state = 'active' " +
                "ORDER BY c.relay_id, c.namespace_id",
        ) { row ->
            val reason = when (row.string(2)) {
                "rejected" -> CapabilityNeed.Reason.REJECTED
                "exhausted" -> CapabilityNeed.Reason.EXHAUSTED
                else -> if (!row.isNull(3) && row.long(3) <= now + EXPIRING_SECONDS) CapabilityNeed.Reason.EXPIRING else null
            }
            reason?.let {
                CapabilityNeed(RelayId(row.long(0)), NamespaceId(row.blob(1)), CapabilityKind.REGISTER, it, CapabilitySource.REDEEM)
            }
        }.filterNotNull().forEach { out += it }
        sql.rows(
            "SELECT DISTINCT r.relay_id, r.namespace_id FROM relay_key_registration r " +
                "JOIN sync_namespace_fund f ON f.namespace_id = r.namespace_id " +
                "JOIN namespace_relay nr ON nr.namespace_id = r.namespace_id AND nr.relay_id = r.relay_id " +
                "JOIN relay_directory rd ON rd.relay_id = r.relay_id " +
                "WHERE rd.state = 'active' AND r.state = 'pending' " +
                "AND NOT EXISTS (SELECT 1 FROM relay_register_capability c " +
                "WHERE c.relay_id = r.relay_id AND c.namespace_id = r.namespace_id) " +
                "ORDER BY r.relay_id, r.namespace_id",
        ) {
            CapabilityNeed(
                RelayId(it.long(0)), NamespaceId(it.blob(1)), CapabilityKind.REGISTER, CapabilityNeed.Reason.MISSING,
                CapabilitySource.REDEEM,
            )
        }.forEach { out += it }
        return out.toList()
    }

    /** Deletes capabilities one day past their expiry hour, registration capabilities included; returns the number deleted. */
    fun collect(tx: SyncTransaction, now: Long): Int =
        tx.sql.execUpdate(
            "DELETE FROM relay_capability WHERE expires_hour IS NOT NULL AND expires_hour + ?1 <= ?2",
            listOf(RetentionPolicy.CAPABILITY_GRACE_SECONDS, now),
        ) + tx.sql.execUpdate(
            "DELETE FROM relay_register_capability WHERE expires_hour IS NOT NULL AND expires_hour + ?1 <= ?2",
            listOf(RetentionPolicy.CAPABILITY_GRACE_SECONDS, now),
        )

    companion object {
        const val MAX_TOKEN_SIZE: Int = 512
        const val EXPIRING_SECONDS: Long = 24 * 3600
    }
}
