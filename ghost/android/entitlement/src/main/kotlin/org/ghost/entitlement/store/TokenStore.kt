package org.ghost.entitlement.store

import org.ghost.sync.api.SyncTransaction

/** One `ent_token` row. The token and its bindings are copied out; `toString()` shows none (T3). */
internal class TokenRow(
    nullifier: ByteArray,
    val kind: String,
    val epoch: Long,
    val slot: Int?,
    token: ByteArray,
    val state: String,
    val eligibleMinute: Long,
    val reservedFor: String?,
    val reservedRelay: Long?,
    reservedNamespace: ByteArray?,
    requestId: ByteArray?,
    reservedRef: ByteArray?,
) {
    private val nullifierBytes = nullifier.copyOf()
    private val tokenBytes = token.copyOf()
    private val namespaceBytes = reservedNamespace?.copyOf()
    private val requestIdBytes = requestId?.copyOf()
    private val refBytes = reservedRef?.copyOf()

    fun nullifier(): ByteArray = nullifierBytes.copyOf()
    fun token(): ByteArray = tokenBytes.copyOf()
    fun reservedNamespace(): ByteArray? = namespaceBytes?.copyOf()
    fun requestId(): ByteArray = checkNotNull(requestIdBytes) { "no request id" }.copyOf()
    fun reservedRef(): ByteArray? = refBytes?.copyOf()

    override fun toString(): String = "TokenRow($kind, $state)"
}

/**
 * `ent_token` (design §11.3, §11.4): tokens keyed by their random nullifier, never marked spent. A
 * reservation ends only by deletion, except that credits of a failed flow return to fresh; a
 * reserved token keeps its relay, namespace and request id (R8, triggers). Every mutation is guarded;
 * inserts are a plain INSERT after a read (§19.22 point 4).
 */
internal class TokenStore {

    fun get(tx: SyncTransaction, nullifier: ByteArray): TokenRow? =
        tx.sql.single("SELECT $COLUMNS FROM ent_token WHERE nullifier = ?1", listOf(nullifier), ::row)

    /** A new fresh token; a nullifier already held is a fault (two tokens never share one). */
    fun insertFresh(tx: SyncTransaction, nullifier: ByteArray, kind: String, epoch: Long, slot: Int?, token: ByteArray, eligibleMinute: Long) {
        check(get(tx, nullifier) == null) { "token already held" }
        tx.sql.updateExactly(
            1,
            "INSERT INTO ent_token(nullifier, kind, epoch, slot, token, state, eligible_minute) VALUES (?1, ?2, ?3, ?4, ?5, 'fresh', ?6)",
            listOf(nullifier, kind, epoch, slot, token, eligibleMinute),
        )
    }

    /** The token reserved for (relay, namespace, week), if a redemption of it is pending (R8). */
    fun relayReservation(tx: SyncTransaction, relay: Long, namespace: ByteArray, week: Long): TokenRow? = tx.sql.single(
        "SELECT $COLUMNS FROM ent_token WHERE reserved_for = 'relay' AND reserved_relay = ?1 AND reserved_namespace = ?2 AND epoch = ?3",
        listOf(relay, namespace, week),
        ::row,
    )

    /** A fresh ACCESS token of [week] for one of [slots], eligible by [nowMinute] (the random nullifier order). */
    fun freshEligibleAccess(tx: SyncTransaction, week: Long, slots: List<Int>, nowMinute: Long): TokenRow? {
        if (slots.isEmpty()) return null
        val marks = slots.indices.joinToString(", ") { "?${it + 3}" }
        return tx.sql.rows(
            "SELECT $COLUMNS FROM ent_token WHERE kind = 'access' AND state = 'fresh' AND epoch = ?1 AND eligible_minute <= ?2 " +
                "AND slot IN ($marks) ORDER BY nullifier LIMIT 1",
            listOf<Any?>(week, nowMinute) + slots,
            ::row,
        ).firstOrNull()
    }

    /** Redeem-lane tx1 (§11.6): reserve a fresh, eligible ACCESS token for (relay, namespace) with a new request id. */
    fun reserveForRelay(tx: SyncTransaction, nullifier: ByteArray, relay: Long, namespace: ByteArray, requestId: ByteArray, nowMinute: Long) =
        tx.sql.updateExactly(
            1,
            "UPDATE ent_token SET state = 'reserved', reserved_for = 'relay', reserved_relay = ?1, reserved_namespace = ?2, request_id = ?3 " +
                "WHERE nullifier = ?4 AND kind = 'access' AND state = 'fresh' AND eligible_minute <= ?5",
            listOf(relay, namespace, requestId, nullifier, nowMinute),
        )

    /** Deletes a relay reservation by its request id (guard `state = 'reserved' AND request_id = ?`). */
    fun deleteRelayReservation(tx: SyncTransaction, nullifier: ByteArray, requestId: ByteArray): Int = tx.sql.execUpdate(
        "DELETE FROM ent_token WHERE nullifier = ?1 AND state = 'reserved' AND reserved_for = 'relay' AND request_id = ?2",
        listOf(nullifier, requestId),
    )

    fun delete(tx: SyncTransaction, nullifier: ByteArray): Int = tx.sql.execUpdate("DELETE FROM ent_token WHERE nullifier = ?1", listOf(nullifier))

    /** Fresh credits, oldest epoch first (then the random nullifier order). */
    fun freshCredits(tx: SyncTransaction): List<TokenRow> =
        tx.sql.rows("SELECT $COLUMNS FROM ent_token WHERE kind = 'credit' AND state = 'fresh' ORDER BY epoch, nullifier", map = ::row)

    fun reserveCredit(tx: SyncTransaction, nullifier: ByteArray, reservedFor: String, ref: ByteArray) = tx.sql.updateExactly(
        1,
        "UPDATE ent_token SET state = 'reserved', reserved_for = ?1, reserved_ref = ?2 WHERE nullifier = ?3 AND kind = 'credit' AND state = 'fresh'",
        listOf(reservedFor, ref, nullifier),
    )

    /** The credits reserved for flow [ref], in the stable nullifier order (identical bytes on every retry). */
    fun reservedCredits(tx: SyncTransaction, reservedFor: String, ref: ByteArray): List<TokenRow> = tx.sql.rows(
        "SELECT $COLUMNS FROM ent_token WHERE kind = 'credit' AND state = 'reserved' AND reserved_for = ?1 AND reserved_ref = ?2 ORDER BY nullifier",
        listOf(reservedFor, ref),
        ::row,
    )

    /** Credits of a failed flow return to fresh (the one permitted release path, trigger `ent_token_state`). */
    fun releaseCredits(tx: SyncTransaction, reservedFor: String, ref: ByteArray): Int = tx.sql.execUpdate(
        "UPDATE ent_token SET state = 'fresh', reserved_for = NULL, reserved_ref = NULL " +
            "WHERE kind = 'credit' AND state = 'reserved' AND reserved_for = ?1 AND reserved_ref = ?2",
        listOf(reservedFor, ref),
    )

    fun deleteReservedCredits(tx: SyncTransaction, reservedFor: String, ref: ByteArray): Int = tx.sql.execUpdate(
        "DELETE FROM ent_token WHERE kind = 'credit' AND state = 'reserved' AND reserved_for = ?1 AND reserved_ref = ?2",
        listOf(reservedFor, ref),
    )

    /** A fresh INVITE token of the newest epoch (the longest acceptance window). */
    fun freshInvite(tx: SyncTransaction): TokenRow? = tx.sql.rows(
        "SELECT $COLUMNS FROM ent_token WHERE kind = 'invite' AND state = 'fresh' ORDER BY epoch DESC, nullifier LIMIT 1",
        map = ::row,
    ).firstOrNull()

    /** An ACCESS token of [week] or a later week is held, fresh or reserved. */
    fun hasAccessFrom(tx: SyncTransaction, week: Long): Boolean =
        tx.sql.single("SELECT 1 FROM ent_token WHERE kind = 'access' AND epoch >= ?1 LIMIT 1", listOf(week)) { 1 } != null

    /** Fresh ACCESS tokens per week. */
    fun freshAccessPerWeek(tx: SyncTransaction): Map<Long, Int> = tx.sql.rows(
        "SELECT epoch, count(*) FROM ent_token WHERE kind = 'access' AND state = 'fresh' GROUP BY epoch",
    ) { it.long(0) to it.long(1).toInt() }.toMap()

    /** The last week with an ACCESS token held, fresh or reserved. */
    fun lastAccessWeek(tx: SyncTransaction): Long? = tx.sql.single("SELECT max(epoch) FROM ent_token WHERE kind = 'access'") { it.longOrNull(0) }

    fun count(tx: SyncTransaction, kind: String, state: String): Int =
        tx.sql.single("SELECT count(*) FROM ent_token WHERE kind = ?1 AND state = ?2", listOf(kind, state)) { it.long(0).toInt() } ?: 0

    /**
     * GC (design §11.4 "window over"): ACCESS tokens of weeks through [lastClosedWeek], fresh or
     * reserved for a relay; fresh INVITE tokens of epochs before [minInviteEpoch]; fresh CREDIT tokens
     * of epochs before [minCreditEpoch]. Credits reserved for a live flow stay until the flow ends.
     */
    fun collect(tx: SyncTransaction, lastClosedWeek: Long, minInviteEpoch: Long, minCreditEpoch: Long): Int =
        tx.sql.execUpdate(
            "DELETE FROM ent_token WHERE (kind = 'access' AND epoch <= ?1 AND (state = 'fresh' OR reserved_for = 'relay')) " +
                "OR (kind = 'invite' AND state = 'fresh' AND epoch < ?2) OR (kind = 'credit' AND state = 'fresh' AND epoch < ?3)",
            listOf(lastClosedWeek, minInviteEpoch, minCreditEpoch),
        )

    private fun row(it: org.ghost.storage.SqlExecutor.Row) = TokenRow(
        nullifier = it.blob(0), kind = it.string(1), epoch = it.long(2), slot = it.longOrNull(3)?.toInt(), token = it.blob(4),
        state = it.string(5), eligibleMinute = it.long(6), reservedFor = it.stringOrNull(7), reservedRelay = it.longOrNull(8),
        reservedNamespace = it.blobOrNull(9), requestId = it.blobOrNull(10), reservedRef = it.blobOrNull(11),
    )

    companion object {
        const val FRESH = "fresh"
        const val RESERVED = "reserved"
        const val FOR_RELAY = "relay"
        const val FOR_PURCHASE = "purchase"
        const val FOR_CLAIM = "claim"

        private const val COLUMNS =
            "nullifier, kind, epoch, slot, token, state, eligible_minute, reserved_for, reserved_relay, reserved_namespace, request_id, reserved_ref"
    }
}
