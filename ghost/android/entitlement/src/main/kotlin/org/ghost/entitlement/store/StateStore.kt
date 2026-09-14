package org.ghost.entitlement.store

import org.ghost.sync.api.SyncTransaction

/** The `ent_state` singleton. Secrets are copied out; `toString()` shows none of them (T3). */
internal class EntState(
    val scheduleSeq: Long,
    scheduleDigest: ByteArray,
    val nextInviteIndex: Int,
    payoutSalt: ByteArray,
    val autoRenewCredits: Boolean,
    val alarmFlags: Int,
    val paymentShownMinute: Long?,
    val restoreScanUntilDay: Long?,
    restoreScanRoot: ByteArray?,
) {
    private val digest = scheduleDigest.copyOf()
    private val salt = payoutSalt.copyOf()
    private val scanRoot = restoreScanRoot?.copyOf()

    fun scheduleDigest(): ByteArray = digest.copyOf()

    fun payoutSalt(): ByteArray = salt.copyOf()

    /** The commitment to the root a restore's drop scan is owed for, or null when none is owed. */
    fun restoreScanRoot(): ByteArray? = scanRoot?.copyOf()

    override fun toString(): String = "EntState(seq=$scheduleSeq)"
}

/**
 * `ent_state` (design §11.3): the accepted schedule's seq and digest, the next invite index, the
 * payout salt (created with the row, never leaves the device), auto-renewal, the persistent alarm
 * flags, the moment the payment screen was last visible, and a restore's drop scan (§8.4, §19.26): the
 * root it is owed for and its end, fixed at the install. Plain INSERT after a read (§19.22 point 4).
 */
internal class StateStore {

    fun read(tx: SyncTransaction): EntState? = tx.sql.single(
        "SELECT schedule_seq, schedule_digest, next_invite_index, payout_salt, auto_renew_credits, alarm_flags, payment_shown_minute, " +
            "restore_scan_until_day, restore_scan_root FROM ent_state WHERE id = 1",
    ) {
        EntState(it.long(0), it.blob(1), it.long(2).toInt(), it.blob(3), it.long(4) == 1L, it.long(5).toInt(), it.longOrNull(6), it.longOrNull(7), it.blobOrNull(8))
    }

    /** The row of the first accepted schedule. */
    fun create(tx: SyncTransaction, seq: Long, digest: ByteArray, payoutSalt: ByteArray) {
        check(read(tx) == null) { "entitlement state already exists" }
        tx.sql.updateExactly(
            1,
            "INSERT INTO ent_state(id, schedule_seq, schedule_digest, payout_salt) VALUES (1, ?1, ?2, ?3)",
            listOf(seq, digest, payoutSalt),
        )
    }

    fun updateSchedule(tx: SyncTransaction, seq: Long, digest: ByteArray) =
        tx.sql.updateExactly(1, "UPDATE ent_state SET schedule_seq = ?1, schedule_digest = ?2 WHERE id = 1", listOf(seq, digest))

    /** Sets [bit] in `alarm_flags` (persistent until Phase 13 acknowledges it); false without a state row. */
    fun raiseAlarm(tx: SyncTransaction, bit: Int): Boolean {
        require(bit == ALARM_SCHEDULE_CONFLICT || bit == ALARM_ISSUER_MISMATCH || bit == ALARM_REFUSED_BY_RELAY) { "unknown alarm" }
        return tx.sql.execUpdate("UPDATE ent_state SET alarm_flags = alarm_flags | ?1 WHERE id = 1", listOf(bit)) == 1
    }

    fun setAutoRenew(tx: SyncTransaction, enabled: Boolean) =
        tx.sql.execUpdate("UPDATE ent_state SET auto_renew_credits = ?1 WHERE id = 1", listOf(if (enabled) 1 else 0))

    /** Takes invite index [expected] (guarded, so two invites never share one). */
    fun takeInviteIndex(tx: SyncTransaction, expected: Int) = tx.sql.updateExactly(
        1,
        "UPDATE ent_state SET next_invite_index = ?1 WHERE id = 1 AND next_invite_index = ?2",
        listOf(expected + 1, expected),
    )

    /** Invite indices below [next] are never taken by a new invite (the drops a restore scans, §8.4). */
    fun reserveInviteIndices(tx: SyncTransaction, next: Int): Int =
        tx.sql.execUpdate("UPDATE ent_state SET next_invite_index = ?1 WHERE id = 1 AND next_invite_index < ?1", listOf(next))

    /**
     * A restore's drop scan is owed for the root [root] commits to (§8.4, §19.26 point 15), recorded before
     * the restored identity is stored; its end is fixed at the install, under a trusted clock.
     */
    fun oweRestoreScan(tx: SyncTransaction, root: ByteArray): Int {
        require(root.size == ROOT_BYTES) { "a restore-scan root is 32 bytes" }
        return tx.sql.execUpdate("UPDATE ent_state SET restore_scan_root = ?1, restore_scan_until_day = NULL WHERE id = 1", listOf(root))
    }

    /** The install fixes the end of an owed scan whose end is not fixed yet. */
    fun fixRestoreScanEnd(tx: SyncTransaction, untilDay: Long): Int = tx.sql.execUpdate(
        "UPDATE ent_state SET restore_scan_until_day = ?1 WHERE id = 1 AND restore_scan_root IS NOT NULL AND restore_scan_until_day IS NULL",
        listOf(untilDay),
    )

    /** Drops an owed scan (the stored identity is of another root, or an invite activation replaced the restore). */
    fun dropRestoreScan(tx: SyncTransaction): Int =
        tx.sql.execUpdate("UPDATE ent_state SET restore_scan_root = NULL, restore_scan_until_day = NULL WHERE id = 1 AND restore_scan_root IS NOT NULL")

    /** Forgets a restore scan whose end is [day] or earlier (GC, with its drops closed in the same pass). */
    fun clearRestoreScanUpTo(tx: SyncTransaction, day: Long): Int = tx.sql.execUpdate(
        "UPDATE ent_state SET restore_scan_root = NULL, restore_scan_until_day = NULL WHERE id = 1 AND restore_scan_until_day <= ?1",
        listOf(day),
    )

    fun setPaymentShown(tx: SyncTransaction, minute: Long) =
        tx.sql.execUpdate("UPDATE ent_state SET payment_shown_minute = ?1 WHERE id = 1", listOf(minute))

    /** Nulls a payment-screen moment at or before [minute] (older than the longest hold). */
    fun clearPaymentShownUpTo(tx: SyncTransaction, minute: Long): Int =
        tx.sql.execUpdate("UPDATE ent_state SET payment_shown_minute = NULL WHERE id = 1 AND payment_shown_minute <= ?1", listOf(minute))

    companion object {
        private const val ROOT_BYTES = 32
        const val ALARM_SCHEDULE_CONFLICT = 1
        const val ALARM_ISSUER_MISMATCH = 2
        const val ALARM_REFUSED_BY_RELAY = 4
    }
}
