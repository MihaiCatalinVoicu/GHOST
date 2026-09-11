package org.ghost.sync.store

import org.ghost.network.OnionAddress
import org.ghost.sync.api.BlobHash
import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.EnqueueResult
import org.ghost.sync.api.InsufficientReplicasException
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.OperationId
import org.ghost.sync.api.OutboundBlob
import org.ghost.sync.api.OutboundOutcome
import org.ghost.sync.api.Outcome
import org.ghost.sync.api.OutboxProgress
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.RelayId
import org.ghost.sync.api.SendDelay
import org.ghost.sync.api.SyncChange
import org.ghost.sync.api.SyncTransaction
import org.ghost.sync.store.RetentionPolicy.SKEW_SECONDS
import org.ghost.sync.store.RetentionPolicy.STORE_WINDOW_SECONDS
import org.ghost.sync.store.Sql.DUE_CLAMP_SECONDS
import org.ghost.sync.store.Sql.LIVE_DELIVERY_D

/** A delivery the planner found due for a store attempt (design §3.3). */
internal class DueStore(val operationId: OperationId, val relayId: RelayId, val namespace: NamespaceId, val attempts: Int) {
    override fun toString(): String = "DueStore(attempts=$attempts)"
}

/**
 * A committed write-ahead lease: everything the call outside the transaction needs. When
 * [copyHour] is set a previous attempt may have left a copy, so the attempt checks first (design
 * §3.3 step 1); [clearableIfAbsent] says whether an absent answer proves the copy never existed.
 */
internal class StoreLease(
    val operationId: OperationId,
    val relayId: RelayId,
    val relay: OnionAddress,
    val namespace: NamespaceId,
    val hash: BlobHash,
    ciphertext: ByteArray,
    val ttlSeconds: Int,
    val copyHour: Long?,
    val acked: Boolean,
    val capability: CapabilityToken,
    val clearableIfAbsent: Boolean,
) {
    private val payload: ByteArray = ciphertext

    val ciphertext: ByteArray get() = payload.copyOf()

    val checkFirst: Boolean get() = copyHour != null

    override fun toString(): String = "StoreLease(redacted)"
}

/** One own delivery to verify or resolve with `check` (design §3.4, §3.5). */
internal class OwnCheck(val operationId: OperationId, val relayId: RelayId, val hash: BlobHash) {
    override fun toString(): String = "OwnCheck(redacted)"
}

/** A (relay, namespace) pair with outbox work: open deliveries or resolvable copies. */
internal class WorkPair(val relayId: RelayId, val namespace: NamespaceId) {
    override fun equals(other: Any?): Boolean = other is WorkPair && other.relayId == relayId && other.namespace == namespace

    override fun hashCode(): Int = relayId.hashCode() * 31 + namespace.hashCode()

    override fun toString(): String = "WorkPair(redacted)"
}

internal enum class ReceiptResult {
    /** The delivery became `acked`. */
    ACKED,

    /** Late receipt on a delivery already failed or closed: the possible copy is recorded. */
    LATE,

    /** No lease matched (already normalized); only the own tombstone was raised. */
    NO_LEASE,
}

internal enum class ParkResult {
    /** The token of the failing generation was refused and the delivery waits for a new one. */
    PARKED,

    /** A newer token was installed meanwhile: the delivery stays pending and is due now. */
    NEWER_GENERATION,

    /** The delivery was no longer pending. */
    NOT_PENDING,
}

/**
 * Outbox state (design §3, with §11.2 #4–#6). All statements are guarded by the expected current
 * state, so any interleaving of lanes and consumer transactions is correct; guarded transitions
 * that the design says "must be 1" are checked. Every path that may change an op's deliveries
 * runs [decide] (D1, D2, W) for that op before its transaction ends.
 */
internal class OutboxStore(private val capabilities: CapabilityStore) {

    // ------------------------------------------------------------------ enqueue (§3.1)

    /**
     * Enqueue inside the caller's transaction. [globalMode] and [sendDelaySample] (the `sendDelay`
     * PRF stream, uniform in [0, 1)) give the HIGH-mode send delay; the namespace's [SendDelay]
     * overrides the global mode.
     */
    fun enqueue(
        tx: SyncTransaction,
        blob: OutboundBlob,
        now: Long,
        globalMode: PrivacyMode,
        sendDelaySample: () -> Double,
    ): EnqueueResult {
        val sql = tx.sql
        val op = blob.operationId
        val ns = blob.namespace
        val namespace = sql.single(
            "SELECT listening, send_delay FROM sync_namespace WHERE namespace_id = ?1",
            listOf(ns.raw),
        ) { Pair(it.long(0) == 1L, SendDelay.ofCode(it.string(1))) } ?: throw IllegalStateException("namespace is not registered")
        val (listening, sendDelay) = namespace
        val ciphertext = blob.rawCiphertext
        val hash = sha256(ciphertext)

        // Conflicts (3): the same id is idempotent only for the same bytes in the same namespace.
        val sameId = sql.single(
            "SELECT namespace_id, blob_hash FROM outbox_op WHERE operation_id = ?1",
            listOf(op.raw),
        ) { Pair(it.blob(0), it.blob(1)) }
        if (sameId != null) {
            check(sameId.first.contentEquals(ns.raw) && sameId.second.contentEquals(hash.raw)) {
                "operation id is already used for other bytes"
            }
            return EnqueueResult.AlreadyEnqueued
        }

        // Quorum (1): at least two distinct operators among the active relays of the set (ADR-11).
        val operators = sql.single(
            "SELECT count(DISTINCT rd.operator_id) FROM namespace_relay nr JOIN relay_directory rd ON rd.relay_id = nr.relay_id " +
                "WHERE nr.namespace_id = ?1 AND rd.state = 'active'",
            listOf(ns.raw),
        ) { it.long(0) } ?: 0L
        if (operators < StoreLimits.QUORUM) throw InsufficientReplicasException()

        // The same bytes under another op: allowed only once that op is released and wiped (a resend of
        // identical bytes after release, §9); the old row is deleted below and the new op pins the tombstone.
        val other = sql.single(
            "SELECT operation_id, released = 1 AND ciphertext IS NULL, ttl_seconds FROM outbox_op WHERE namespace_id = ?1 AND blob_hash = ?2",
            listOf(ns.raw, hash.raw),
        ) { Triple(OperationId(it.blob(0)), it.long(1) == 1L, it.long(2)) }
        check(other == null || other.second) { "these bytes are already queued under another operation" }

        // Own tombstone (6) and the resend bound (§11.2 #6), read before any raise.
        if (listening) {
            val existing = sql.single(
                "SELECT state, retain_until_day FROM inbox_blob WHERE namespace_id = ?1 AND blob_hash = ?2",
                listOf(ns.raw, hash.raw),
            ) { Pair(it.string(0), it.long(1)) }
            if (existing != null) {
                check(existing.first == "done") { "these bytes were received from a relay" }
                check(RetentionPolicy.resendAllowed(existing.second, now)) { "identical bytes can no longer be resent" }
            }
        }
        if (other != null) deleteReleased(tx, other.first, other.third, now)

        // Timing (4): the send delay is sampled once; deadlines are hour-granular and after not_before.
        val delayed = when (sendDelay) {
            SendDelay.ON -> true
            SendDelay.OFF -> false
            SendDelay.DEFAULT -> globalMode == PrivacyMode.HIGH
        }
        val notBefore = if (delayed) {
            val u = sendDelaySample()
            require(u >= 0.0 && u < 1.0) { "send delay sample out of range" }
            Time.ceilMinute(now + (u * StoreLimits.SEND_DELAY_MAX_SECONDS).toLong())
        } else {
            Time.floorMinute(now)
        }
        val deadlineHour = blob.deadlineEpochSeconds?.let { deadline ->
            require(deadline > now) { "deadline is not in the future" }
            maxOf(Time.ceilHour(deadline), Time.floorHour(notBefore) + Time.HOUR)
        }

        // (5) The op and one pending delivery per active relay of the set.
        sql.updateExactly(
            1,
            "INSERT INTO outbox_op(operation_id, namespace_id, blob_hash, ciphertext, ttl_seconds, not_before_minute, deadline_hour, " +
                "required_operators, outcome, released) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'pending', 0)",
            listOf(op.raw, ns.raw, hash.raw, ciphertext, blob.ttl.seconds, notBefore, deadlineHour, StoreLimits.QUORUM),
        )
        val deliveries = sql.execUpdate(
            "INSERT INTO outbox_delivery(operation_id, relay_id, state, attempts, next_attempt_minute) " +
                "SELECT ?1, nr.relay_id, 'pending', 0, ?2 FROM namespace_relay nr JOIN relay_directory rd ON rd.relay_id = nr.relay_id " +
                "WHERE nr.namespace_id = ?3 AND rd.state = 'active'",
            listOf(op.raw, notBefore, ns.raw),
        )
        check(deliveries >= StoreLimits.QUORUM) { "too few deliveries" }

        // (6) Listening namespaces only: the own `done` row, so our blob is never fetched back. A
        // namespace that starts listening later gets it then ([writeOwnTombstones]).
        if (listening) sql.updateExactly(1, OWN_TOMBSTONE_UPSERT, ownTombstoneArgs(ns, hash, blob.ttl.seconds.toLong(), now))
        return EnqueueResult.Enqueued
    }

    /**
     * Listening turned on (0 → 1, design §11.5 #1): an own `done` row for every op the namespace still
     * has, with the statement and retention rule of enqueue step 6, in the caller's transaction, so no
     * blob of ours is fetched back; later receipts raise the rows ([raiseOwnTombstone]). An existing
     * `done` row is raised; a row in another state (these bytes were listed from a relay before) is
     * left to the inbox. Ops already deleted while the namespace was write-only left nothing to
     * recognize: declared in ADR-20 point 6 and design §11.5 #1. Returns the rows written or raised.
     */
    fun writeOwnTombstones(tx: SyncTransaction, ns: NamespaceId, now: Long): Int {
        val ops = tx.sql.rows(
            "SELECT blob_hash, ttl_seconds FROM outbox_op WHERE namespace_id = ?1 ORDER BY operation_id",
            listOf(ns.raw),
        ) { Pair(BlobHash(it.blob(0)), it.long(1)) }
        return ops.sumOf { (hash, ttl) -> tx.sql.execUpdate(OWN_TOMBSTONE_UPSERT, ownTombstoneArgs(ns, hash, ttl, now)) }
    }

    private fun ownTombstoneArgs(ns: NamespaceId, hash: BlobHash, ttlSeconds: Long, now: Long): List<Any?> =
        listOf(ns.raw, hash.raw, RetentionPolicy.ownRetainDay(now, ttlSeconds))

    // ------------------------------------------------------------------ planning and lease (§3.3)

    /**
     * Deliveries due for a store attempt, ordered by `not_before_minute`, then operation id. With
     * [relay] and [ns] set, only that pair's deliveries (HIGH mode, at the pair's event).
     */
    fun dueStores(tx: SyncTransaction, now: Long, limit: Int, relay: RelayId? = null, ns: NamespaceId? = null): List<DueStore> {
        require(limit > 0) { "limit must be positive" }
        require((relay == null) == (ns == null)) { "pair filter needs relay and namespace" }
        val pairFilter = if (relay != null) "AND d.relay_id = ?4 AND o.namespace_id = ?5 " else ""
        val args = mutableListOf<Any?>(now, STORE_WINDOW_SECONDS, limit)
        if (relay != null && ns != null) {
            args += relay.value
            args += ns.raw
        }
        return tx.sql.rows(
            "SELECT d.operation_id, d.relay_id, o.namespace_id, d.attempts FROM outbox_delivery d " +
                "JOIN outbox_op o ON o.operation_id = d.operation_id " +
                "JOIN relay_directory rd ON rd.relay_id = d.relay_id " +
                "WHERE d.state = 'pending' AND d.inflight = 0 " +
                "AND (d.next_attempt_minute <= ?1 OR d.next_attempt_minute > ?1 + $DUE_CLAMP_SECONDS) " +
                "AND (o.not_before_minute <= ?1 OR o.not_before_minute > ?1 + $DUE_CLAMP_SECONDS) " +
                "AND (o.deadline_hour IS NULL OR o.deadline_hour > ?1) " +
                "AND rd.state = 'active' " +
                "AND EXISTS (SELECT 1 FROM relay_capability c WHERE c.relay_id = d.relay_id AND c.namespace_id = o.namespace_id " +
                "AND c.kind = 'write' AND c.state = 'usable' AND (c.expires_hour IS NULL OR c.expires_hour > ?1)) " +
                "AND NOT EXISTS (SELECT 1 FROM outbox_delivery x WHERE x.operation_id = d.operation_id " +
                "AND x.copy_hour IS NOT NULL AND x.copy_hour + ?2 <= ?1) " +
                pairFilter +
                "ORDER BY o.not_before_minute, d.operation_id LIMIT ?3",
            args,
        ) { DueStore(OperationId(it.blob(0)), RelayId(it.long(1)), NamespaceId(it.blob(2)), it.int(3)) }
    }

    /**
     * Write-ahead lease (design §3.3): attempts + 1, in flight, lease hour, next attempt after
     * [backoffSeconds]. The guard re-checks every planning condition, including the store window
     * (W-rule) and a usable write capability. Returns null when the guard does not match.
     */
    fun lease(tx: SyncTransaction, operationId: OperationId, relay: RelayId, now: Long, backoffSeconds: Long): StoreLease? {
        require(backoffSeconds in 0..Time.HOUR) { "backoff out of range" }
        val sql = tx.sql
        val leased = sql.execUpdate(
            "UPDATE outbox_delivery SET attempts = attempts + 1, inflight = 1, lease_hour = ?1, next_attempt_minute = ?2 " +
                "WHERE operation_id = ?3 AND relay_id = ?4 AND state = 'pending' AND inflight = 0 " +
                "AND (next_attempt_minute <= ?5 OR next_attempt_minute > ?5 + $DUE_CLAMP_SECONDS) " +
                "AND EXISTS (SELECT 1 FROM outbox_op o JOIN relay_directory rd ON rd.relay_id = ?4 " +
                "WHERE o.operation_id = ?3 AND rd.state = 'active' " +
                "AND (o.not_before_minute <= ?5 OR o.not_before_minute > ?5 + $DUE_CLAMP_SECONDS) " +
                "AND (o.deadline_hour IS NULL OR o.deadline_hour > ?5) " +
                "AND EXISTS (SELECT 1 FROM relay_capability c WHERE c.relay_id = ?4 AND c.namespace_id = o.namespace_id " +
                "AND c.kind = 'write' AND c.state = 'usable' AND (c.expires_hour IS NULL OR c.expires_hour > ?5))) " +
                "AND NOT EXISTS (SELECT 1 FROM outbox_delivery x WHERE x.operation_id = ?3 " +
                "AND x.copy_hour IS NOT NULL AND x.copy_hour + ?6 <= ?5)",
            listOf(Time.floorHour(now), Time.dueMinute(now, backoffSeconds), operationId.raw, relay.value, now, STORE_WINDOW_SECONDS),
        )
        if (leased != 1) return null
        val row = sql.single(
            "SELECT o.ciphertext, o.namespace_id, o.blob_hash, o.ttl_seconds, d.copy_hour, d.ack_minute, rd.onion_address " +
                "FROM outbox_op o JOIN outbox_delivery d ON d.operation_id = o.operation_id " +
                "JOIN relay_directory rd ON rd.relay_id = d.relay_id WHERE o.operation_id = ?1 AND d.relay_id = ?2",
            listOf(operationId.raw, relay.value),
        ) { LeaseRow(it.blob(0), NamespaceId(it.blob(1)), BlobHash(it.blob(2)), it.int(3), it.longOrNull(4), !it.isNull(5), it.string(6)) }
            ?: throw IllegalStateException("leased delivery vanished")
        val token = capabilities.usable(tx, relay, row.namespace, CapabilityKind.WRITE, now)
            ?: throw IllegalStateException("leased delivery has no write capability")
        val clearable = row.copyHour != null && !row.acked && now < row.copyHour + row.ttlSeconds - SKEW_SECONDS
        return StoreLease(
            operationId, relay, OnionAddress.parse(row.address), row.namespace, row.hash, row.ciphertext, row.ttlSeconds,
            row.copyHour, row.acked, token, clearable,
        )
    }

    private class LeaseRow(
        val ciphertext: ByteArray,
        val namespace: NamespaceId,
        val hash: BlobHash,
        val ttlSeconds: Int,
        val copyHour: Long?,
        val acked: Boolean,
        val address: String,
    )

    // ------------------------------------------------------------------ result transactions (§3.3)

    /**
     * A store receipt. The caller has already checked that the receipt names the op's hash. Every
     * receipt, acked or late, raises the own tombstone to `ceil7(day(expiry) + TAIL)` (§11.2 #6).
     */
    fun recordReceipt(tx: SyncTransaction, operationId: OperationId, relay: RelayId, receiptExpiry: Long, now: Long): ReceiptResult {
        val sql = tx.sql
        val acked = sql.execUpdate(
            "UPDATE outbox_delivery SET state = 'acked', inflight = 0, ack_minute = ?1, copy_hour = COALESCE(copy_hour, lease_hour) " +
                "WHERE operation_id = ?2 AND relay_id = ?3 AND inflight = 1 AND state IN ('pending', 'wait_capability')",
            listOf(Time.floorMinute(now), operationId.raw, relay.value),
        )
        val late = if (acked == 0) {
            sql.execUpdate(
                "UPDATE outbox_delivery SET inflight = 0, copy_hour = COALESCE(copy_hour, lease_hour) " +
                    "WHERE operation_id = ?1 AND relay_id = ?2 AND inflight = 1 AND state IN ('failed', 'closed')",
                listOf(operationId.raw, relay.value),
            )
        } else {
            0
        }
        raiseOwnTombstone(tx, operationId, RetentionPolicy.expiryRetainDay(receiptExpiry))
        decide(tx, operationId, now)
        return when {
            acked == 1 -> ReceiptResult.ACKED
            late == 1 -> ReceiptResult.LATE
            else -> ReceiptResult.NO_LEASE
        }
    }

    /** `check` found h (check-before-restore, the quota path, or a resolution check): verified. */
    fun recordFoundByCheck(tx: SyncTransaction, operationId: OperationId, relay: RelayId, now: Long): Boolean {
        val changed = tx.sql.execUpdate(
            "UPDATE outbox_delivery SET state = 'verified', inflight = 0, copy_hour = COALESCE(copy_hour, lease_hour) " +
                "WHERE operation_id = ?1 AND relay_id = ?2 AND state <> 'verified'",
            listOf(operationId.raw, relay.value),
        )
        decide(tx, operationId, now)
        return changed == 1
    }

    /**
     * `check` did not find h on a delivery that was never acked: the possible copy is forgotten only
     * while a copy made at its earliest hour would still be live (`now < copy_hour + ttl − σ`,
     * design §3.3 step 1, §3.5). Returns true if the copy hour was cleared.
     */
    fun clearUnackedCopy(tx: SyncTransaction, operationId: OperationId, relay: RelayId, now: Long): Boolean {
        val changed = tx.sql.execUpdate(
            "UPDATE outbox_delivery SET copy_hour = NULL WHERE operation_id = ?1 AND relay_id = ?2 " +
                "AND copy_hour IS NOT NULL AND ack_minute IS NULL AND state IN ('pending', 'wait_capability', 'failed', 'closed') " +
                "AND ?3 < copy_hour + (SELECT ttl_seconds FROM outbox_op WHERE operation_id = ?1) - ?4",
            listOf(operationId.raw, relay.value, now, SKEW_SECONDS),
        )
        decide(tx, operationId, now)
        return changed == 1
    }

    /** Ambiguous outcome (timeout, relay_unavailable, internal, closed, malformed_response, not_stored, unknown). */
    fun recordAmbiguous(tx: SyncTransaction, operationId: OperationId, relay: RelayId, now: Long): Boolean {
        val changed = tx.sql.execUpdate(
            "UPDATE outbox_delivery SET inflight = 0, copy_hour = COALESCE(copy_hour, lease_hour) " +
                "WHERE operation_id = ?1 AND relay_id = ?2 AND inflight = 1",
            listOf(operationId.raw, relay.value),
        )
        decide(tx, operationId, now)
        return changed == 1
    }

    /** Definite "not applied" (`transport`): the lease ends without a possible copy; backoff was set at lease time. */
    fun recordNotApplied(tx: SyncTransaction, operationId: OperationId, relay: RelayId, now: Long): Boolean {
        val changed = endLeaseWithoutCopy(tx, operationId, relay)
        decide(tx, operationId, now)
        return changed == 1
    }

    /**
     * `unauthorized` (rejected) or `quota` with h absent (exhausted) on the write token of
     * [generation]: nothing was persisted. The token is refused only if it is still that
     * generation; if a newer one was installed meanwhile the delivery stays pending and is due now,
     * otherwise it waits for a capability (design §3.6, §3.8).
     */
    fun parkForCapability(
        tx: SyncTransaction,
        operationId: OperationId,
        relay: RelayId,
        ns: NamespaceId,
        generation: Long,
        exhausted: Boolean,
        now: Long,
    ): ParkResult {
        val sql = tx.sql
        endLeaseWithoutCopy(tx, operationId, relay)
        capabilities.refuse(tx, relay, ns, CapabilityKind.WRITE, generation, exhausted)
        val stored = capabilities.generation(tx, relay, ns, CapabilityKind.WRITE)
        val result = if (stored != null && stored > generation) {
            val changed = sql.execUpdate(
                "UPDATE outbox_delivery SET next_attempt_minute = ?1 WHERE operation_id = ?2 AND relay_id = ?3 AND state = 'pending'",
                listOf(Time.floorMinute(now), operationId.raw, relay.value),
            )
            if (changed == 1) ParkResult.NEWER_GENERATION else ParkResult.NOT_PENDING
        } else {
            val changed = sql.execUpdate(
                "UPDATE outbox_delivery SET state = 'wait_capability' WHERE operation_id = ?1 AND relay_id = ?2 AND state = 'pending'",
                listOf(operationId.raw, relay.value),
            )
            if (changed == 1) ParkResult.PARKED else ParkResult.NOT_PENDING
        }
        decide(tx, operationId, now)
        return result
    }

    /** `rejected` or a local bug: the delivery fails (nothing was persisted). */
    fun failDelivery(tx: SyncTransaction, operationId: OperationId, relay: RelayId, now: Long): Boolean {
        endLeaseWithoutCopy(tx, operationId, relay)
        val changed = tx.sql.execUpdate(
            "UPDATE outbox_delivery SET state = 'failed' WHERE operation_id = ?1 AND relay_id = ?2 AND state IN ('pending', 'wait_capability')",
            listOf(operationId.raw, relay.value),
        )
        decide(tx, operationId, now)
        return changed == 1
    }

    private fun endLeaseWithoutCopy(tx: SyncTransaction, operationId: OperationId, relay: RelayId): Int =
        tx.sql.execUpdate(
            "UPDATE outbox_delivery SET inflight = 0 WHERE operation_id = ?1 AND relay_id = ?2 AND inflight = 1",
            listOf(operationId.raw, relay.value),
        )

    // ------------------------------------------------------------------ verification (§3.4, §11.2 #5)

    /**
     * Relay [relay] listed h in namespace [ns]: every idle own delivery of an undecided op with
     * that hash on that relay becomes verified. Returns the op if one was promoted.
     */
    fun verifyListed(tx: SyncTransaction, relay: RelayId, ns: NamespaceId, hash: BlobHash, now: Long): OperationId? {
        val sql = tx.sql
        // The op (if any) is looked up by (namespace, hash) alone; the §11.2 #5 statement below is the guard.
        val op = sql.single(
            "SELECT operation_id FROM outbox_op WHERE namespace_id = ?1 AND blob_hash = ?2",
            listOf(ns.raw, hash.raw),
        ) { OperationId(it.blob(0)) } ?: return null
        val changed = sql.execUpdate(
            "UPDATE outbox_delivery SET state = 'verified' WHERE relay_id = ?1 AND inflight = 0 " +
                "AND state IN ('pending', 'wait_capability', 'acked', 'failed', 'closed') " +
                "AND operation_id IN (SELECT operation_id FROM outbox_op WHERE namespace_id = ?2 AND blob_hash = ?3 AND outcome = 'pending')",
            listOf(relay.value, ns.raw, hash.raw),
        )
        if (changed == 0) return null
        decide(tx, op, now)
        return op
    }

    /**
     * Acked deliveries of the pair whose receipt is at least [minAgeSeconds] old (60 s for
     * write-only pairs and pairs without a read capability, the 10-minute fallback otherwise).
     * A receipt time far in the future after a backward clock jump counts as old enough.
     */
    fun ackedAwaitingVerification(tx: SyncTransaction, relay: RelayId, ns: NamespaceId, now: Long, minAgeSeconds: Long, limit: Int): List<OwnCheck> {
        require(limit in 1..StoreLimits.CHECK_BATCH) { "check batch out of range" }
        return tx.sql.rows(
            "SELECT d.operation_id, o.blob_hash FROM outbox_delivery d JOIN outbox_op o ON o.operation_id = d.operation_id " +
                "WHERE d.relay_id = ?1 AND o.namespace_id = ?2 AND d.state = 'acked' AND d.inflight = 0 " +
                "AND (d.ack_minute + ?3 <= ?4 OR d.ack_minute > ?4 + $DUE_CLAMP_SECONDS) " +
                "ORDER BY d.ack_minute, d.operation_id LIMIT ?5",
            listOf(relay.value, ns.raw, minAgeSeconds, now, limit),
        ) { OwnCheck(OperationId(it.blob(0)), relay, BlobHash(it.blob(1))) }
    }

    /** `check` showed h for an acked delivery. */
    fun recordVerifiedAfterAck(tx: SyncTransaction, operationId: OperationId, relay: RelayId, now: Long): Boolean {
        val changed = tx.sql.execUpdate(
            "UPDATE outbox_delivery SET state = 'verified' WHERE operation_id = ?1 AND relay_id = ?2 AND state = 'acked'",
            listOf(operationId.raw, relay.value),
        )
        decide(tx, operationId, now)
        return changed == 1
    }

    /** `check` did not show h after a receipt: strike; a repair store, or failed at the second strike. */
    fun recordAbsentAfterAck(tx: SyncTransaction, operationId: OperationId, relay: RelayId, now: Long): Boolean {
        val changed = tx.sql.execUpdate(
            "UPDATE outbox_delivery SET strikes = strikes + 1, state = CASE WHEN strikes + 1 >= 2 THEN 'failed' ELSE 'pending' END, " +
                "next_attempt_minute = ?1 WHERE operation_id = ?2 AND relay_id = ?3 AND state = 'acked'",
            listOf(Time.floorMinute(now), operationId.raw, relay.value),
        )
        decide(tx, operationId, now)
        return changed == 1
    }

    /**
     * Resolvable deliveries of the pair (design §3.5): a possible copy never acked, relay active,
     * still live if made at its earliest hour. Pending ones are listed only while the op's window
     * is closed (otherwise the store attempt checks first under its lease).
     */
    fun resolvable(tx: SyncTransaction, relay: RelayId, ns: NamespaceId, now: Long, limit: Int): List<OwnCheck> {
        require(limit in 1..StoreLimits.CHECK_BATCH) { "check batch out of range" }
        return tx.sql.rows(
            "SELECT d.operation_id, o.blob_hash FROM outbox_delivery d JOIN outbox_op o ON o.operation_id = d.operation_id " +
                "JOIN relay_directory rd ON rd.relay_id = d.relay_id " +
                "WHERE d.relay_id = ?1 AND o.namespace_id = ?2 AND d.inflight = 0 AND d.copy_hour IS NOT NULL AND d.ack_minute IS NULL " +
                "AND rd.state = 'active' AND ?3 < d.copy_hour + o.ttl_seconds - ?4 " +
                "AND (d.state IN ('wait_capability', 'failed', 'closed') OR (d.state = 'pending' AND EXISTS (SELECT 1 FROM outbox_delivery x " +
                "WHERE x.operation_id = d.operation_id AND x.copy_hour IS NOT NULL AND x.copy_hour + ?5 <= ?3))) " +
                "ORDER BY d.copy_hour, d.operation_id LIMIT ?6",
            listOf(relay.value, ns.raw, now, SKEW_SECONDS, STORE_WINDOW_SECONDS, limit),
        ) { OwnCheck(OperationId(it.blob(0)), relay, BlobHash(it.blob(1))) }
    }

    /** Pairs with outbox work: open deliveries (pending, parked, acked) or resolvable copies. */
    fun workPairs(tx: SyncTransaction, now: Long): List<WorkPair> =
        tx.sql.rows(
            "SELECT DISTINCT d.relay_id, o.namespace_id FROM outbox_delivery d JOIN outbox_op o ON o.operation_id = d.operation_id " +
                "JOIN relay_directory rd ON rd.relay_id = d.relay_id WHERE rd.state = 'active' " +
                "AND (d.state IN ('pending', 'wait_capability', 'acked') OR (d.copy_hour IS NOT NULL AND d.ack_minute IS NULL " +
                "AND d.state IN ('failed', 'closed') AND ?1 < d.copy_hour + o.ttl_seconds - ?2)) ORDER BY d.relay_id, o.namespace_id",
            listOf(now, SKEW_SECONDS),
        ) { WorkPair(RelayId(it.long(0)), NamespaceId(it.blob(1))) }

    // ------------------------------------------------------------------ maintenance (§3.5, M1–M4)

    /** M1: leases left in flight by a dead process count as ambiguous. Run at session start only. */
    fun normalizeLeases(tx: SyncTransaction, now: Long): Int {
        val sql = tx.sql
        val ops = sql.rows("SELECT DISTINCT operation_id FROM outbox_delivery WHERE inflight = 1") { OperationId(it.blob(0)) }
        val changed = sql.execUpdate("UPDATE outbox_delivery SET inflight = 0, copy_hour = COALESCE(copy_hour, lease_hour) WHERE inflight = 1")
        ops.forEach { decide(tx, it, now) }
        return changed
    }

    /** M2: park idle pending deliveries that have no usable, unexpired write capability. */
    fun parkWithoutCapability(tx: SyncTransaction, now: Long): Int =
        tx.sql.execUpdate(
            "UPDATE outbox_delivery SET state = 'wait_capability' WHERE state = 'pending' AND inflight = 0 " +
                "AND NOT EXISTS (SELECT 1 FROM outbox_op o JOIN relay_capability c " +
                "ON c.relay_id = outbox_delivery.relay_id AND c.namespace_id = o.namespace_id " +
                "WHERE o.operation_id = outbox_delivery.operation_id AND c.kind = 'write' AND c.state = 'usable' " +
                "AND (c.expires_hour IS NULL OR c.expires_hour > ?1))",
            listOf(now),
        )

    /**
     * M3: closure of idle pending/parked deliveries whose caller deadline passed, or whose op's
     * window expired with nothing resolvable. Only while the transport is READY (the clock is
     * trusted); the caller enforces that.
     */
    fun close(tx: SyncTransaction, now: Long): Int {
        val sql = tx.sql
        val args = listOf(now, STORE_WINDOW_SECONDS, SKEW_SECONDS)
        val ops = sql.rows("SELECT DISTINCT operation_id FROM outbox_delivery WHERE $CLOSABLE", args) { OperationId(it.blob(0)) }
        val changed = sql.execUpdate("UPDATE outbox_delivery SET state = 'closed' WHERE $CLOSABLE", args)
        ops.forEach { decide(tx, it, now) }
        return changed
    }

    /** M4 sweep: D1, D2 and W for every undecided op and every op still holding its payload. */
    fun decideAll(tx: SyncTransaction, now: Long): Int {
        val ops = tx.sql.rows("SELECT operation_id FROM outbox_op WHERE outcome = 'pending' OR ciphertext IS NOT NULL ORDER BY operation_id") {
            OperationId(it.blob(0))
        }
        return ops.count { decide(tx, it, now) }
    }

    // ------------------------------------------------------------------ decision (§3.5 D1, D2, W)

    /** D1, then D2, then W for one op. Returns true when this call decided the outcome. */
    fun decide(tx: SyncTransaction, operationId: OperationId, now: Long): Boolean {
        val sql = tx.sql
        val sent = sql.execUpdate(
            "UPDATE outbox_op SET outcome = 'sent' WHERE operation_id = ?1 AND outcome = 'pending' " +
                "AND (SELECT COUNT(DISTINCT rd.operator_id) FROM outbox_delivery d JOIN relay_directory rd ON rd.relay_id = d.relay_id " +
                "WHERE d.operation_id = ?1 AND d.state = 'verified') >= required_operators",
            listOf(operationId.raw),
        )
        val other = if (sent == 0) {
            sql.execUpdate(
                "UPDATE outbox_op SET outcome = CASE " +
                    "WHEN EXISTS (SELECT 1 FROM outbox_delivery d WHERE d.operation_id = ?1 AND d.state = 'verified') THEN 'degraded' " +
                    "WHEN EXISTS (SELECT 1 FROM outbox_delivery d WHERE d.operation_id = ?1 AND d.copy_hour IS NOT NULL) THEN 'indeterminate' " +
                    "ELSE 'failed' END " +
                    "WHERE operation_id = ?1 AND outcome = 'pending' " +
                    "AND NOT EXISTS (SELECT 1 FROM outbox_delivery d WHERE d.operation_id = ?1 AND $LIVE_DELIVERY_D) " +
                    "AND NOT EXISTS (SELECT 1 FROM outbox_delivery d JOIN relay_directory rd ON rd.relay_id = d.relay_id " +
                    "WHERE d.operation_id = ?1 AND d.copy_hour IS NOT NULL AND d.ack_minute IS NULL AND d.state IN ('failed', 'closed') " +
                    "AND rd.state = 'active' AND ?2 < d.copy_hour + outbox_op.ttl_seconds - ?3)",
                listOf(operationId.raw, now, SKEW_SECONDS),
            )
        } else {
            0
        }
        sql.execUpdate(
            "UPDATE outbox_op SET ciphertext = NULL WHERE operation_id = ?1 AND ciphertext IS NOT NULL " +
                "AND NOT EXISTS (SELECT 1 FROM outbox_delivery d WHERE d.operation_id = ?1 AND $LIVE_DELIVERY_D)",
            listOf(operationId.raw),
        )
        val decided = sent + other == 1
        if (decided) tx.hint(SyncChange.OUTCOMES)
        return decided
    }

    // ------------------------------------------------------------------ topology (§3.9)

    /**
     * A relay joined the namespace's set: a pending delivery to it for every op that still holds
     * its payload and whose window is open (ops without payload are never selected: the insert
     * trigger would refuse them). Existing (op, relay) rows are kept as they are.
     */
    fun addDeliveries(tx: SyncTransaction, ns: NamespaceId, relay: RelayId, now: Long): Int =
        tx.sql.execUpdate(
            "INSERT INTO outbox_delivery(operation_id, relay_id, state, attempts, next_attempt_minute) " +
                "SELECT o.operation_id, ?1, 'pending', 0, max(o.not_before_minute, ?2) FROM outbox_op o " +
                "WHERE o.namespace_id = ?3 AND o.ciphertext IS NOT NULL " +
                "AND EXISTS (SELECT 1 FROM relay_directory rd WHERE rd.relay_id = ?1 AND rd.state = 'active') " +
                "AND NOT EXISTS (SELECT 1 FROM outbox_delivery e WHERE e.operation_id = o.operation_id AND e.relay_id = ?1) " +
                "AND NOT EXISTS (SELECT 1 FROM outbox_delivery x WHERE x.operation_id = o.operation_id " +
                "AND x.copy_hour IS NOT NULL AND x.copy_hour + ?4 <= ?5)",
            listOf(relay.value, Time.floorMinute(now), ns.raw, STORE_WINDOW_SECONDS, now),
        )

    /**
     * A relay left a namespace's set ([ns] set) or was retired ([ns] null): its deliveries that
     * could still store or be verified become failed (the copy hour is kept), then D1, D2, W.
     */
    fun failDeliveriesTo(tx: SyncTransaction, relay: RelayId, ns: NamespaceId?, now: Long): Int {
        val sql = tx.sql
        val nsFilter = if (ns != null) "AND operation_id IN (SELECT operation_id FROM outbox_op WHERE namespace_id = ?2)" else ""
        val args = if (ns != null) listOf<Any?>(relay.value, ns.raw) else listOf<Any?>(relay.value)
        val where = "relay_id = ?1 AND state IN ('pending', 'wait_capability', 'acked') $nsFilter"
        val ops = sql.rows("SELECT DISTINCT operation_id FROM outbox_delivery WHERE $where", args) { OperationId(it.blob(0)) }
        val changed = sql.execUpdate("UPDATE outbox_delivery SET state = 'failed' WHERE $where", args)
        ops.forEach { decide(tx, it, now) }
        return changed
    }

    /** Parked deliveries of the pair return to pending, due now (a new write token, design §3.8). */
    fun rearm(tx: SyncTransaction, relay: RelayId, ns: NamespaceId, now: Long): Int =
        tx.sql.execUpdate(
            "UPDATE outbox_delivery SET state = 'pending', next_attempt_minute = ?1 WHERE relay_id = ?2 AND state = 'wait_capability' " +
                "AND operation_id IN (SELECT operation_id FROM outbox_op WHERE namespace_id = ?3)",
            listOf(Time.floorMinute(now), relay.value, ns.raw),
        )

    // ------------------------------------------------------------------ consumer calls (§9)

    /** True only while no attempt could have left a copy; then every delivery fails and D2 decides FAILED. */
    fun cancel(tx: SyncTransaction, operationId: OperationId, now: Long): Boolean {
        val sql = tx.sql
        val outcome = sql.single("SELECT outcome FROM outbox_op WHERE operation_id = ?1", listOf(operationId.raw)) { it.string(0) }
        if (outcome != "pending") return false
        val blocking = sql.single(
            "SELECT count(*) FROM outbox_delivery WHERE operation_id = ?1 " +
                "AND (copy_hour IS NOT NULL OR inflight = 1 OR state IN ('acked', 'verified'))",
            listOf(operationId.raw),
        ) { it.long(0) } ?: 0L
        if (blocking > 0) return false
        sql.execUpdate(
            "UPDATE outbox_delivery SET state = 'failed' WHERE operation_id = ?1 AND state IN ('pending', 'wait_capability')",
            listOf(operationId.raw),
        )
        check(decide(tx, operationId, now)) { "cancelled operation was not decided" }
        return true
    }

    /** True exactly once per decided op. The row is deleted later by garbage collection. */
    fun release(tx: SyncTransaction, operationId: OperationId): Boolean =
        tx.sql.execUpdate(
            "UPDATE outbox_op SET released = 1 WHERE operation_id = ?1 AND released = 0 AND outcome <> 'pending'",
            listOf(operationId.raw),
        ) == 1

    fun progress(tx: SyncTransaction, operationId: OperationId): OutboxProgress? =
        tx.sql.single(
            "SELECT o.required_operators, o.outcome, " +
                "(SELECT COUNT(DISTINCT rd.operator_id) FROM outbox_delivery d JOIN relay_directory rd ON rd.relay_id = d.relay_id " +
                "WHERE d.operation_id = o.operation_id AND (d.ack_minute IS NOT NULL OR d.state = 'verified')), " +
                "(SELECT COUNT(DISTINCT rd.operator_id) FROM outbox_delivery d JOIN relay_directory rd ON rd.relay_id = d.relay_id " +
                "WHERE d.operation_id = o.operation_id AND d.state = 'verified') " +
                "FROM outbox_op o WHERE o.operation_id = ?1",
            listOf(operationId.raw),
        ) { OutboxProgress(it.int(2), it.int(3), it.int(0), Outcome.ofCode(it.string(1))) }

    /** Decided, unreleased outcomes of the consumer's namespaces, with the resend bound for INDETERMINATE. */
    fun outcomes(tx: SyncTransaction, consumerCode: String, limit: Int): List<OutboundOutcome> {
        require(limit > 0) { "limit must be positive" }
        return tx.sql.rows(
            "SELECT o.operation_id, o.namespace_id, o.outcome, o.ttl_seconds, " +
                "(SELECT MIN(d.copy_hour) FROM outbox_delivery d WHERE d.operation_id = o.operation_id) " +
                "FROM outbox_op o JOIN sync_namespace n ON n.namespace_id = o.namespace_id " +
                "WHERE n.consumer = ?1 AND o.outcome <> 'pending' AND o.released = 0 ORDER BY o.operation_id LIMIT ?2",
            listOf(consumerCode, limit),
        ) { row ->
            val outcome = Outcome.ofCode(row.string(2)) ?: throw IllegalStateException("undecided outcome listed")
            val earliestCopy = row.longOrNull(4)
            val resend = if (outcome == Outcome.INDETERMINATE && earliestCopy != null) {
                RetentionPolicy.resendNotAfter(earliestCopy, row.long(3))
            } else {
                null
            }
            OutboundOutcome(OperationId(row.blob(0)), NamespaceId(row.blob(1)), outcome, resend)
        }
    }

    // ------------------------------------------------------------------ deletion and own tombstone

    /**
     * Deletes a released op whose payload is wiped (garbage collection, or a resend of its identical
     * bytes). No store of it can happen any more, so its own tombstone is raised to
     * `ceil7(today + TTL + 8)` (design §2.3) before the row goes; deliveries cascade.
     */
    fun deleteReleased(tx: SyncTransaction, operationId: OperationId, ttlSeconds: Long, now: Long) {
        raiseOwnTombstone(tx, operationId, RetentionPolicy.ownRetainDay(now, ttlSeconds))
        tx.sql.updateExactly(
            1,
            "DELETE FROM outbox_op WHERE operation_id = ?1 AND released = 1 AND ciphertext IS NULL",
            listOf(operationId.raw),
        )
    }

    /** Raises the own `done` row of the op's (namespace, hash), if the namespace keeps one, to at least [day]. */
    fun raiseOwnTombstone(tx: SyncTransaction, operationId: OperationId, day: Long): Int =
        tx.sql.execUpdate(
            "UPDATE inbox_blob SET retain_until_day = ?1 WHERE state = 'done' AND retain_until_day < ?1 " +
                "AND namespace_id = (SELECT namespace_id FROM outbox_op WHERE operation_id = ?2) " +
                "AND blob_hash = (SELECT blob_hash FROM outbox_op WHERE operation_id = ?2)",
            listOf(day, operationId.raw),
        )

    companion object {
        /**
         * The own `done` row of (namespace, hash), written by enqueue step 6 and by a listening 0 → 1
         * transition (design §11.5 #1): ?1 namespace, ?2 hash, ?3 `ownRetainDay`; an existing `done`
         * row is raised, a row in another state is left alone.
         */
        private const val OWN_TOMBSTONE_UPSERT =
            "INSERT INTO inbox_blob(namespace_id, blob_hash, state, retain_until_day) VALUES (?1, ?2, 'done', ?3) " +
                "ON CONFLICT(namespace_id, blob_hash) DO UPDATE " +
                "SET retain_until_day = max(inbox_blob.retain_until_day, excluded.retain_until_day) " +
                "WHERE inbox_blob.state = 'done'"

        /** M3 closure condition; parameters ?1 now, ?2 store window, ?3 skew. */
        private const val CLOSABLE =
            "state IN ('pending', 'wait_capability') AND inflight = 0 AND operation_id IN (SELECT o.operation_id FROM outbox_op o " +
                "WHERE (o.deadline_hour IS NOT NULL AND o.deadline_hour <= ?1) " +
                "OR (EXISTS (SELECT 1 FROM outbox_delivery x WHERE x.operation_id = o.operation_id " +
                "AND x.copy_hour IS NOT NULL AND x.copy_hour + ?2 <= ?1) " +
                "AND NOT EXISTS (SELECT 1 FROM outbox_delivery y JOIN relay_directory ry ON ry.relay_id = y.relay_id " +
                "WHERE y.operation_id = o.operation_id AND y.copy_hour IS NOT NULL AND y.ack_minute IS NULL " +
                "AND y.state IN ('pending', 'wait_capability', 'failed', 'closed') AND ry.state = 'active' " +
                "AND ?1 < y.copy_hour + o.ttl_seconds - ?3)))"
    }
}
