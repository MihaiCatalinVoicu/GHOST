package org.ghost.entitlement.store

import org.ghost.sync.api.SyncTransaction

/** One `ent_purchase` row. Secrets are copied out on request; `toString()` shows none (T3). */
internal class PurchaseRow(
    id: ByteArray,
    val kind: String,
    val payWith: String,
    val state: String,
    seed: ByteArray?,
    claimKey: ByteArray?,
    invoiceId: ByteArray?,
    val subaddress: String?,
    val amountAtomic: Long?,
    inputToken: ByteArray?,
    val baseWeek: Long?,
    val scheduleSeq: Long?,
    layoutDigest: ByteArray?,
    val sent: Boolean,
    val disclosed: Boolean,
    val shown: Boolean,
    val prevState: Int,
    val createdHour: Long?,
    val receiptMinute: Long?,
    val outstandingAtomic: Long?,
    val nextDueMinute: Long?,
    val attempt: Int,
    val terminalDay: Long?,
) {
    private val idBytes = id.copyOf()
    private val seedBytes = seed?.copyOf()
    private val claimKeyBytes = claimKey?.copyOf()
    private val invoiceIdBytes = invoiceId?.copyOf()
    private val inputTokenBytes = inputToken?.copyOf()
    private val layoutDigestBytes = layoutDigest?.copyOf()

    fun id(): ByteArray = idBytes.copyOf()
    fun seed(): ByteArray = checkNotNull(seedBytes) { "no seed" }.copyOf()
    fun claimKey(): ByteArray = checkNotNull(claimKeyBytes) { "no claim key" }.copyOf()
    fun invoiceId(): ByteArray = checkNotNull(invoiceIdBytes) { "no invoice" }.copyOf()
    fun inputToken(): ByteArray = checkNotNull(inputTokenBytes) { "no input token" }.copyOf()
    fun layoutDigest(): ByteArray = checkNotNull(layoutDigestBytes) { "no layout" }.copyOf()

    val live: Boolean get() = state == PurchaseStore.PREPARED || state == PurchaseStore.INVOICED

    override fun toString(): String = "PurchaseRow($kind, $payWith, $state)"
}

/**
 * `ent_purchase` (design §11.3, §11.4): packs, trials and refreshes. Every mutating statement is
 * guarded by its expected state and must change one row; the terminal transaction wipes every
 * issuance secret, the creation hour, the receipt minute and the outstanding amount (R10, §19.15,
 * CHECK-enforced). New rows are a plain INSERT after a read (§19.22 point 4).
 */
internal class PurchaseStore {

    fun insert(
        tx: SyncTransaction,
        id: ByteArray,
        kind: String,
        payWith: String,
        seed: ByteArray,
        claimKey: ByteArray?,
        inputToken: ByteArray?,
        baseWeek: Long,
        scheduleSeq: Long,
        layoutDigest: ByteArray,
        createdHour: Long,
        nextDueMinute: Long?,
    ) {
        check(get(tx, id) == null) { "purchase id already used" }
        tx.sql.updateExactly(
            1,
            "INSERT INTO ent_purchase(purchase_id, kind, pay_with, state, seed, claim_key, input_token, base_week, schedule_seq, " +
                "layout_digest, created_hour, next_due_minute) VALUES (?1, ?2, ?3, 'prepared', ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            listOf(id, kind, payWith, seed, claimKey, inputToken, baseWeek, scheduleSeq, layoutDigest, createdHour, nextDueMinute),
        )
    }

    fun get(tx: SyncTransaction, id: ByteArray): PurchaseRow? =
        tx.sql.single("SELECT $COLUMNS FROM ent_purchase WHERE purchase_id = ?1", listOf(id), ::row)

    fun live(tx: SyncTransaction): List<PurchaseRow> =
        tx.sql.rows("SELECT $COLUMNS FROM ent_purchase WHERE state IN ('prepared', 'invoiced') ORDER BY purchase_id", map = ::row)

    fun all(tx: SyncTransaction): List<PurchaseRow> = tx.sql.rows("SELECT $COLUMNS FROM ent_purchase ORDER BY purchase_id", map = ::row)

    /** A prepared, unsent flow takes the current week and its layout (design §11.4 "base week refreshed while sent = 0"). */
    fun refreshUnsent(tx: SyncTransaction, id: ByteArray, baseWeek: Long, scheduleSeq: Long, layoutDigest: ByteArray) = tx.sql.updateExactly(
        1,
        "UPDATE ent_purchase SET base_week = ?1, schedule_seq = ?2, layout_digest = ?3 WHERE purchase_id = ?4 AND state = 'prepared' AND sent = 0",
        listOf(baseWeek, scheduleSeq, layoutDigest, id),
    )

    /**
     * Write-ahead of one call (§11.5): `sent = 1`, the attempt counted before the call leaves the
     * device (so the cap holds across crashes) and the next due time.
     */
    fun countAttempt(tx: SyncTransaction, id: ByteArray, state: String, expectedAttempt: Int, nextDueMinute: Long?) = tx.sql.updateExactly(
        1,
        "UPDATE ent_purchase SET sent = 1, attempt = ?1, next_due_minute = ?2 WHERE purchase_id = ?3 AND state = ?4 AND attempt = ?5",
        listOf(expectedAttempt + 1, nextDueMinute, id, state, expectedAttempt),
    )

    fun setNextDue(tx: SyncTransaction, id: ByteArray, state: String, nextDueMinute: Long?) = tx.sql.updateExactly(
        1,
        "UPDATE ent_purchase SET next_due_minute = ?1 WHERE purchase_id = ?2 AND state = ?3",
        listOf(nextDueMinute, id, state),
    )

    /** The validated `RequestInvoice` answer (§11.4 prepared → invoiced); the attempt count restarts for `BlindSign`. */
    fun invoiced(
        tx: SyncTransaction,
        id: ByteArray,
        invoiceId: ByteArray,
        subaddress: String?,
        amountAtomic: Long,
        receiptMinute: Long,
        prevState: Int,
        nextDueMinute: Long,
    ) = tx.sql.updateExactly(
        1,
        "UPDATE ent_purchase SET state = 'invoiced', invoice_id = ?1, subaddress = ?2, amount_atomic = ?3, receipt_minute = ?4, " +
            "outstanding_atomic = ?3, prev_state = ?5, attempt = 0, next_due_minute = ?6 WHERE purchase_id = ?7 AND state = 'prepared' AND sent = 1",
        listOf(invoiceId, subaddress, amountAtomic, receiptMinute, prevState, nextDueMinute, id),
    )

    /** The latest invoice state and outstanding amount (§19.11). */
    fun progress(tx: SyncTransaction, id: ByteArray, prevState: Int, outstandingAtomic: Long) = tx.sql.updateExactly(
        1,
        "UPDATE ent_purchase SET prev_state = ?1, outstanding_atomic = ?2 WHERE purchase_id = ?3 AND state = 'invoiced'",
        listOf(prevState, outstandingAtomic, id),
    )

    /** The terminal transaction: [to] from [from], every secret and time but `terminal_day` wiped (R10, §19.15). */
    fun terminal(tx: SyncTransaction, id: ByteArray, from: String, to: String, terminalDay: Long) {
        require(to in TERMINAL) { "not a terminal state" }
        tx.sql.updateExactly(
            1,
            "UPDATE ent_purchase SET state = ?1, terminal_day = ?2, seed = NULL, claim_key = NULL, invoice_id = NULL, subaddress = NULL, " +
                "amount_atomic = NULL, input_token = NULL, next_due_minute = NULL, created_hour = NULL, receipt_minute = NULL, " +
                "outstanding_atomic = NULL WHERE purchase_id = ?3 AND state = ?4",
            listOf(to, terminalDay, id, from),
        )
    }

    fun setDisclosed(tx: SyncTransaction, id: ByteArray): Int =
        tx.sql.execUpdate("UPDATE ent_purchase SET disclosed = 1 WHERE purchase_id = ?1 AND state IN ('prepared', 'invoiced')", listOf(id))

    fun setShown(tx: SyncTransaction, id: ByteArray): Int =
        tx.sql.execUpdate("UPDATE ent_purchase SET shown = 1 WHERE purchase_id = ?1 AND state = 'invoiced'", listOf(id))

    /** GC: terminal rows at `terminal_day + 7` (§11.3). */
    fun deleteTerminal(tx: SyncTransaction, today: Long): Int = tx.sql.execUpdate(
        "DELETE FROM ent_purchase WHERE state IN ('finalized', 'expired', 'failed', 'lost') AND terminal_day + ?1 <= ?2",
        listOf(TERMINAL_RETENTION_DAYS, today),
    )

    private fun row(it: org.ghost.storage.SqlExecutor.Row) = PurchaseRow(
        id = it.blob(0), kind = it.string(1), payWith = it.string(2), state = it.string(3), seed = it.blobOrNull(4),
        claimKey = it.blobOrNull(5), invoiceId = it.blobOrNull(6), subaddress = it.stringOrNull(7), amountAtomic = it.longOrNull(8),
        inputToken = it.blobOrNull(9), baseWeek = it.longOrNull(10), scheduleSeq = it.longOrNull(11), layoutDigest = it.blobOrNull(12),
        sent = it.long(13) == 1L, disclosed = it.long(14) == 1L, shown = it.long(15) == 1L, prevState = it.long(16).toInt(),
        createdHour = it.longOrNull(17), receiptMinute = it.longOrNull(18), outstandingAtomic = it.longOrNull(19),
        nextDueMinute = it.longOrNull(20), attempt = it.long(21).toInt(), terminalDay = it.longOrNull(22),
    )

    companion object {
        const val PACK = "pack"
        const val TRIAL = "trial"
        const val REFRESH = "refresh"

        const val XMR = "xmr"
        const val CREDITS = "credits"
        const val INVITE = "invite"
        const val CREDIT = "credit"

        const val PREPARED = "prepared"
        const val INVOICED = "invoiced"
        const val FINALIZED = "finalized"
        const val EXPIRED = "expired"
        const val FAILED = "failed"
        const val LOST = "lost"
        val TERMINAL = setOf(FINALIZED, EXPIRED, FAILED, LOST)

        const val TERMINAL_RETENTION_DAYS = 7L

        private const val COLUMNS =
            "purchase_id, kind, pay_with, state, seed, claim_key, invoice_id, subaddress, amount_atomic, input_token, base_week, " +
                "schedule_seq, layout_digest, sent, disclosed, shown, prev_state, created_hour, receipt_minute, outstanding_atomic, " +
                "next_due_minute, attempt, terminal_day"
    }
}
