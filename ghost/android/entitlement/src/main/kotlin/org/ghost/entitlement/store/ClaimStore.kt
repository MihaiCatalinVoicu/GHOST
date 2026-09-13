package org.ghost.entitlement.store

import org.ghost.sync.api.SyncTransaction

/** One `ent_claim` row; the payout address is never printed (T3). */
internal class ClaimRow(
    claimId: ByteArray,
    val state: String,
    val payoutAddress: String?,
    val queuedAtomic: Long?,
    val sent: Boolean,
    val nextDueMinute: Long?,
    val attempt: Int,
    val terminalDay: Long?,
) {
    private val idBytes = claimId.copyOf()
    fun claimId(): ByteArray = idBytes.copyOf()

    override fun toString(): String = "ClaimRow($state)"
}

/**
 * `ent_claim` (payout claims, write-ahead of claim id, address and reserved credits, design §9.4) and
 * `ent_payout_used` (salted hashes of used payout addresses, RP V11). One open claim at a time
 * (unique index); a claim keeps its address and is decided once (trigger); the terminal transaction
 * drops the address and the due time.
 */
internal class ClaimStore {

    fun insert(tx: SyncTransaction, claimId: ByteArray, payoutAddress: String, nextDueMinute: Long) {
        check(get(tx, claimId) == null && open(tx) == null) { "a claim is already open" }
        tx.sql.updateExactly(
            1,
            "INSERT INTO ent_claim(claim_id, state, payout_address, next_due_minute) VALUES (?1, 'prepared', ?2, ?3)",
            listOf(claimId, payoutAddress, nextDueMinute),
        )
    }

    fun get(tx: SyncTransaction, claimId: ByteArray): ClaimRow? =
        tx.sql.single("SELECT $COLUMNS FROM ent_claim WHERE claim_id = ?1", listOf(claimId), ::row)

    fun open(tx: SyncTransaction): ClaimRow? = tx.sql.single("SELECT $COLUMNS FROM ent_claim WHERE state = 'prepared'", map = ::row)

    /** Write-ahead of one `ClaimPayout` call (§11.5): `sent = 1` and the attempt counted before the send. */
    fun countAttempt(tx: SyncTransaction, claimId: ByteArray, expectedAttempt: Int, nextDueMinute: Long) = tx.sql.updateExactly(
        1,
        "UPDATE ent_claim SET sent = 1, attempt = ?1, next_due_minute = ?2 WHERE claim_id = ?3 AND state = 'prepared' AND attempt = ?4",
        listOf(expectedAttempt + 1, nextDueMinute, claimId, expectedAttempt),
    )

    fun queued(tx: SyncTransaction, claimId: ByteArray, queuedAtomic: Long, day: Long) = tx.sql.updateExactly(
        1,
        "UPDATE ent_claim SET state = 'queued', queued_atomic = ?1, payout_address = NULL, next_due_minute = NULL, terminal_day = ?2 " +
            "WHERE claim_id = ?3 AND state = 'prepared'",
        listOf(queuedAtomic, day, claimId),
    )

    fun failed(tx: SyncTransaction, claimId: ByteArray, day: Long) = tx.sql.updateExactly(
        1,
        "UPDATE ent_claim SET state = 'failed', payout_address = NULL, next_due_minute = NULL, terminal_day = ?1 WHERE claim_id = ?2 AND state = 'prepared'",
        listOf(day, claimId),
    )

    /** The day the latest decided claim ended (at most one claim per week, §9.4). */
    fun latestTerminalDay(tx: SyncTransaction): Long? = tx.sql.single("SELECT max(terminal_day) FROM ent_claim") { it.longOrNull(0) }

    fun deleteTerminal(tx: SyncTransaction, today: Long): Int = tx.sql.execUpdate(
        "DELETE FROM ent_claim WHERE state IN ('queued', 'failed') AND terminal_day + ?1 <= ?2",
        listOf(TERMINAL_RETENTION_DAYS, today),
    )

    fun payoutUsed(tx: SyncTransaction, addressHash: ByteArray): Boolean =
        tx.sql.single("SELECT 1 FROM ent_payout_used WHERE address_hash = ?1", listOf(addressHash)) { 1 } != null

    fun insertPayoutUsed(tx: SyncTransaction, addressHash: ByteArray, untilDay: Long) {
        if (payoutUsed(tx, addressHash)) return
        tx.sql.updateExactly(1, "INSERT INTO ent_payout_used(address_hash, until_day) VALUES (?1, ?2)", listOf(addressHash, untilDay))
    }

    fun deletePayoutUsed(tx: SyncTransaction, today: Long): Int =
        tx.sql.execUpdate("DELETE FROM ent_payout_used WHERE until_day <= ?1", listOf(today))

    private fun row(it: org.ghost.storage.SqlExecutor.Row) = ClaimRow(
        it.blob(0), it.string(1), it.stringOrNull(2), it.longOrNull(3), it.long(4) == 1L, it.longOrNull(5), it.long(6).toInt(), it.longOrNull(7),
    )

    companion object {
        const val PREPARED = "prepared"
        const val QUEUED = "queued"
        const val FAILED = "failed"
        const val TERMINAL_RETENTION_DAYS = 7L

        /** Payout-address hashes are kept 365 days (design Q10). */
        const val PAYOUT_USED_DAYS = 365L

        private const val COLUMNS = "claim_id, state, payout_address, queued_atomic, sent, next_due_minute, attempt, terminal_day"
    }
}
