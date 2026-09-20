package org.ghost.sync.store

import org.ghost.network.OnionAddress
import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.KeyKind
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.RelayId
import org.ghost.sync.api.SyncTransaction
import org.ghost.sync.store.Sql.DUE_CLAMP_SECONDS

/** The key of one registration row: (relay, namespace, period, kind). */
internal class RegistrationKey(val relayId: RelayId, val namespace: NamespaceId, val periodId: Long, val kind: KeyKind) {
    override fun equals(other: Any?): Boolean =
        other is RegistrationKey && other.relayId == relayId && other.namespace == namespace &&
            other.periodId == periodId && other.kind == kind

    override fun hashCode(): Int = ((relayId.hashCode() * 31 + namespace.hashCode()) * 31 + periodId.hashCode()) * 31 + kind.hashCode()

    override fun toString(): String = "RegistrationKey($kind)"
}

/** A pending registration the work lane may run: its key and the attempts already made. */
internal class DueRegistration(val key: RegistrationKey, val attempts: Int) {
    override fun toString(): String = "DueRegistration(${key.kind})"
}

/** A leased registration: everything one `RegisterKey` call needs, read in the lease transaction. */
internal class RegistrationLease(
    val key: RegistrationKey,
    val relay: OnionAddress,
    verifier: ByteArray,
    requestId: ByteArray,
    val capability: CapabilityToken,
) {
    private val verifierBytes = verifier.copyOf()
    private val requestIdBytes = requestId.copyOf()

    fun verifier(): ByteArray = verifierBytes.copyOf()

    fun requestId(): ByteArray = requestIdBytes.copyOf()

    override fun toString(): String = "RegistrationLease(${key.kind})"
}

/**
 * `relay_key_registration` (Phase 9 design §4.8, §13.3 item 5, schema §13.6 step 4): the bearer-key
 * registrations the owner keeps at the relays of its own namespaces, and their write-ahead lease.
 *
 * A row is due when it is pending, idle, its next attempt time has come, its relay is active, and a
 * usable, unexpired **write** capability of week c exists for the pair with `period_id ∈ {c, c + 1}`
 * — the very rule the relay judges the request by (§4.4 point 3), so client and relay agree without
 * either reading the other's clock. The capability's week comes from its declared expiry
 * ([Time.capabilityWeek]); a capability whose expiry is unknown names no week and makes no row due.
 *
 * Every state change is guarded by the state it expects, so a result that arrives after the lease
 * was normalized (M1) changes nothing.
 */
internal class RegistrationStore(private val capabilities: CapabilityStore, private val requestId: () -> ByteArray) {

    /** Records that [key] must be registered with [verifier]; idempotent, and a different verifier throws. */
    fun request(tx: SyncTransaction, key: RegistrationKey, verifier: ByteArray, now: Long) {
        require(verifier.size == VERIFIER_SIZE) { "a verifier is 32 bytes" }
        require(key.periodId >= 0) { "period must not be negative" }
        val sql = tx.sql
        val stored = sql.single(
            "SELECT verifier FROM relay_key_registration WHERE relay_id = ?1 AND namespace_id = ?2 AND period_id = ?3 AND kind = ?4",
            listOf(key.relayId.value, key.namespace.raw, key.periodId, key.kind.dbCode),
        ) { it.blob(0) }
        if (stored != null) {
            check(stored.contentEquals(verifier)) { "a registration keeps the verifier it was created with" }
            return
        }
        val id = requestId()
        check(id.size == REQUEST_ID_SIZE) { "a request id is 16 bytes" }
        sql.updateExactly(
            1,
            "INSERT INTO relay_key_registration(relay_id, namespace_id, period_id, kind, verifier, request_id, state, " +
                "inflight, lease_hour, attempts, next_attempt_minute, valid_until_hour) " +
                "VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', 0, NULL, 0, ?7, NULL)",
            listOf(key.relayId.value, key.namespace.raw, key.periodId, key.kind.dbCode, verifier.copyOf(), id, Time.floorMinute(now)),
        )
    }

    /** The healing rule of §4.8: done rows of (relay, namespace) from [fromPeriod] on return to pending. */
    fun rearm(tx: SyncTransaction, relay: RelayId, ns: NamespaceId, fromPeriod: Long, now: Long): Int {
        val rows = tx.sql.rows(
            "SELECT period_id, kind FROM relay_key_registration WHERE relay_id = ?1 AND namespace_id = ?2 " +
                "AND period_id >= ?3 AND state = 'done' ORDER BY period_id, kind",
            listOf(relay.value, ns.raw, fromPeriod),
        ) { Pair(it.long(0), it.string(1)) }
        for ((period, kind) in rows) {
            val id = requestId()
            check(id.size == REQUEST_ID_SIZE) { "a request id is 16 bytes" }
            tx.sql.updateExactly(
                1,
                "UPDATE relay_key_registration SET state = 'pending', valid_until_hour = NULL, request_id = ?1, attempts = 0, " +
                    "next_attempt_minute = ?2, inflight = 0, lease_hour = NULL " +
                    "WHERE relay_id = ?3 AND namespace_id = ?4 AND period_id = ?5 AND kind = ?6 AND state = 'done'",
                listOf(id, Time.floorMinute(now), relay.value, ns.raw, period, kind),
            )
        }
        return rows.size
    }

    /**
     * Drops rows of (relay, namespace) older than [beforePeriod] (§4.8: pending rows of a week the
     * owner will not register any more). A row with a call in flight is left to its result
     * transaction, which the next call of this drops.
     */
    fun forget(tx: SyncTransaction, relay: RelayId, ns: NamespaceId, beforePeriod: Long): Int =
        tx.sql.execUpdate(
            "DELETE FROM relay_key_registration WHERE relay_id = ?1 AND namespace_id = ?2 AND period_id < ?3 AND inflight = 0",
            listOf(relay.value, ns.raw, beforePeriod),
        )

    fun pendingCount(tx: SyncTransaction): Int =
        tx.sql.single("SELECT count(*) FROM relay_key_registration WHERE state = 'pending'") { it.int(0) } ?: 0

    /**
     * A new write capability of (relay, namespace) re-arms the pair's pending rows (the M2 idea of
     * §13.3 item 5): a row the relay refused with `WRONG_PERIOD`, or one whose capability had been
     * refused, is due again on the new generation. Returns the number of rows moved.
     */
    fun rearmForCapability(tx: SyncTransaction, relay: RelayId, ns: NamespaceId, now: Long): Int =
        tx.sql.execUpdate(
            "UPDATE relay_key_registration SET attempts = 0, next_attempt_minute = ?1 " +
                "WHERE relay_id = ?2 AND namespace_id = ?3 AND state = 'pending' AND inflight = 0",
            listOf(Time.floorMinute(now), relay.value, ns.raw),
        )

    /** Pairs with pending registration work and a usable write capability (the work-lane snapshot, §13.3 item 5). */
    fun workPairs(tx: SyncTransaction, now: Long): List<Pair<RelayId, NamespaceId>> =
        due(tx, now, MAX_WORK_PAIRS, null, null).map { Pair(it.key.relayId, it.key.namespace) }.distinct()

    /**
     * Up to [limit] due rows, oldest period first. With [relay] and [ns] set, that pair's rows only
     * (HIGH mode, at the pair's event).
     */
    fun due(tx: SyncTransaction, now: Long, limit: Int, relay: RelayId?, ns: NamespaceId?): List<DueRegistration> {
        require(limit > 0) { "limit must be positive" }
        require((relay == null) == (ns == null)) { "pair filter needs relay and namespace" }
        // The week rule is decided in Kotlin, so the statement reads a multiple of the cap: a row of
        // a period the capability does not cover never crowds out one it does.
        val args = mutableListOf<Any?>(now, limit * PLAN_OVERSAMPLE)
        val pairFilter = if (relay != null && ns != null) {
            args += relay.value
            args += ns.raw
            "AND r.relay_id = ?3 AND r.namespace_id = ?4 "
        } else {
            ""
        }
        // The capability's expiry hour comes out with the row so the week rule is decided in Kotlin,
        // where the grid of Time.week lives.
        return tx.sql.rows(
            "SELECT r.relay_id, r.namespace_id, r.period_id, r.kind, r.attempts, c.expires_hour FROM relay_key_registration r " +
                "JOIN relay_directory rd ON rd.relay_id = r.relay_id " +
                "JOIN relay_capability c ON c.relay_id = r.relay_id AND c.namespace_id = r.namespace_id AND c.kind = 'write' " +
                "WHERE r.state = 'pending' AND r.inflight = 0 " +
                "AND (r.next_attempt_minute <= ?1 OR r.next_attempt_minute > ?1 + $DUE_CLAMP_SECONDS) " +
                "AND rd.state = 'active' AND c.state = 'usable' AND c.expires_hour IS NOT NULL AND c.expires_hour > ?1 " +
                pairFilter +
                "ORDER BY r.period_id, r.relay_id, r.namespace_id, r.kind LIMIT ?2",
            args,
        ) { row ->
            val key = RegistrationKey(RelayId(row.long(0)), NamespaceId(row.blob(1)), row.long(2), KeyKind.ofCode(row.string(3)))
            Triple(key, row.int(4), row.long(5))
        }.filter { (key, _, expiryHour) ->
            val week = Time.capabilityWeek(expiryHour)
            key.periodId == week || key.periodId == week + 1
        }.map { (key, attempts, _) -> DueRegistration(key, attempts) }.take(limit)
    }

    /**
     * Write-ahead lease (the store pattern of §3.3): attempts + 1, in flight, lease hour, next
     * attempt after [backoffSeconds]. The guard re-checks every planning condition except the week
     * rule, including a usable, unexpired write capability that declares its week: the caller reads
     * the due rows in an earlier transaction and makes one call per row, so another writer (or this
     * pair's own previous answer) can refuse the capability in between. Null when the guard does not
     * match; the row then stays pending and the next capability generation re-arms it.
     */
    fun lease(tx: SyncTransaction, key: RegistrationKey, now: Long, backoffSeconds: Long): RegistrationLease? {
        require(backoffSeconds in 0..Time.HOUR) { "backoff out of range" }
        val sql = tx.sql
        val leased = sql.execUpdate(
            "UPDATE relay_key_registration SET attempts = attempts + 1, inflight = 1, lease_hour = ?1, next_attempt_minute = ?2 " +
                "WHERE relay_id = ?3 AND namespace_id = ?4 AND period_id = ?5 AND kind = ?6 AND state = 'pending' AND inflight = 0 " +
                "AND (next_attempt_minute <= ?7 OR next_attempt_minute > ?7 + $DUE_CLAMP_SECONDS) " +
                "AND EXISTS (SELECT 1 FROM relay_directory rd WHERE rd.relay_id = ?3 AND rd.state = 'active') " +
                "AND EXISTS (SELECT 1 FROM relay_capability c WHERE c.relay_id = ?3 AND c.namespace_id = ?4 " +
                "AND c.kind = 'write' AND c.state = 'usable' AND c.expires_hour IS NOT NULL AND c.expires_hour > ?7)",
            listOf(
                Time.floorHour(now), Time.dueMinute(now, backoffSeconds), key.relayId.value, key.namespace.raw,
                key.periodId, key.kind.dbCode, now,
            ),
        )
        if (leased != 1) return null
        val row = sql.single(
            "SELECT r.verifier, r.request_id, rd.onion_address FROM relay_key_registration r " +
                "JOIN relay_directory rd ON rd.relay_id = r.relay_id " +
                "WHERE r.relay_id = ?1 AND r.namespace_id = ?2 AND r.period_id = ?3 AND r.kind = ?4",
            listOf(key.relayId.value, key.namespace.raw, key.periodId, key.kind.dbCode),
        ) { Triple(it.blob(0), it.blob(1), it.string(2)) } ?: throw IllegalStateException("leased registration vanished")
        // Unreachable: the guard above took the lease only over a usable, unexpired write capability.
        val token = capabilities.usable(tx, key.relayId, key.namespace, CapabilityKind.WRITE, now)
            ?: throw IllegalStateException("leased registration has no write capability")
        return RegistrationLease(key, OnionAddress.parse(row.third), row.first, row.second, token)
    }

    /** The relay recorded the registration: the row is done until [validUntilEpochSeconds]. */
    fun recordDone(tx: SyncTransaction, key: RegistrationKey, validUntilEpochSeconds: Long): Boolean =
        tx.sql.execUpdate(
            "UPDATE relay_key_registration SET state = 'done', valid_until_hour = ?1, inflight = 0, lease_hour = NULL, attempts = 0 " +
                "WHERE relay_id = ?2 AND namespace_id = ?3 AND period_id = ?4 AND kind = ?5 AND state = 'pending' AND inflight = 1",
            listOf(
                Time.floorHour(validUntilEpochSeconds), key.relayId.value, key.namespace.raw, key.periodId, key.kind.dbCode,
            ),
        ) == 1

    /**
     * The attempt ended without a record: the lease ends and the row stays pending with the backoff
     * the lease wrote. `WRONG_PERIOD` and a refused capability both land here; the next capability
     * generation re-arms the row ([rearmForCapability]).
     */
    fun endLease(tx: SyncTransaction, key: RegistrationKey): Boolean =
        tx.sql.execUpdate(
            "UPDATE relay_key_registration SET inflight = 0, lease_hour = NULL " +
                "WHERE relay_id = ?1 AND namespace_id = ?2 AND period_id = ?3 AND kind = ?4 AND inflight = 1",
            listOf(key.relayId.value, key.namespace.raw, key.periodId, key.kind.dbCode),
        ) == 1

    /**
     * M1 for registrations: a lease left in flight by a dead process or an aborted session ends,
     * and the row is due again at once (a `RegisterKey` is idempotent at the relay, so repeating an
     * attempt whose answer was lost costs one call and changes nothing).
     */
    fun normalizeLeases(tx: SyncTransaction, now: Long): Int =
        tx.sql.execUpdate(
            "UPDATE relay_key_registration SET inflight = 0, lease_hour = NULL, next_attempt_minute = ?1 WHERE inflight = 1",
            listOf(Time.floorMinute(now)),
        )

    /** Deletes done rows whose validity has passed (§4.8); returns the number deleted. */
    fun collect(tx: SyncTransaction, now: Long): Int =
        tx.sql.execUpdate(
            "DELETE FROM relay_key_registration WHERE state = 'done' AND inflight = 0 AND valid_until_hour <= ?1",
            listOf(now),
        )

    companion object {
        const val VERIFIER_SIZE: Int = 32
        const val REQUEST_ID_SIZE: Int = 16

        /** Pairs a work-lane snapshot reads at once; far above the owner's two namespaces × three relays. */
        const val MAX_WORK_PAIRS: Int = 64

        /** Rows the due statement reads per row it may return, before the week rule of §4.4 point 3. */
        const val PLAN_OVERSAMPLE: Int = 4
    }
}
