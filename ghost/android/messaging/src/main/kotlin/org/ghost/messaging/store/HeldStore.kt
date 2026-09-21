package org.ghost.messaging.store

import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.SyncTransaction

/**
 * The two tables a key change and a scheduled control need (Phase 9 design §13.6 step 5):
 * `dm_held` and `dm_scheduled`.
 *
 * **`dm_held`** holds the ciphertext of a contact whose Olm identity changed, **undecrypted**,
 * until the user acknowledges, verifies or blocks (§8.3). It is the one place in the engine that
 * keeps an inbound blob's content without showing it, and the bound on it is double: at most
 * [MAX_HELD_PER_CONTACT] rows per contact (the `dm_held_limit` trigger), and each row lives at
 * most until `hold_until_minute`, which the relay expiry caps.
 *
 * **`dm_scheduled`** holds the reconnect and revocation notices of §8.6 and §8.5, each due at its
 * own `U[0, 24 h]` (revocation) or `U[0, 48 h]` (reconnect) offset drawn at the user's action and
 * **persisted**: a burst of k deposits into k inboxes in one session would show a degree of k
 * (RP §3.8), and an offset kept in memory would collapse to a burst at the next process start.
 *
 * **Neither is an expiring table for the lint's purposes** (§22.10 item 3, `DmExpiredRowLint`'s
 * scope note): both are swept by time, neither reaches a view the user sees, and the reads below
 * carry the bound each step needs — [heldFor] takes `nowMinute` and leaves a row past its hold
 * deadline alone, [due] takes it and returns nothing early. A read path a user sees would join
 * `expiringTables`; there is none.
 *
 * **Every write goes through the caller's [SyncTransaction]**, like the other DAOs, and there is
 * no `REPLACE` anywhere (gate G-DM4): `dm_scheduled` carries a `UNIQUE (contact_id, what)`, so a
 * second notice of the same kind is a guarded `UPDATE` and not a replace that would delete the row
 * its REPLACE guard exists to protect.
 */
internal class HeldStore {

    /** A `dm_held` row: one PreKey message waiting for the user's decision (§8.3). */
    class HeldRow(
        val heldId: ByteArray,
        val contactId: ByteArray,
        /** The Olm identity the held message was **bound** to, which is the pending one. */
        val identity: ByteArray,
        /** The L1 bytes under the content key (AD = [heldId]). */
        val l1Env: ByteArray,
        /** The generation the intro envelope named; `sessionInbound` needs exactly it. */
        val genId: Int,
        /** The wrapped `reply_seed` the intro envelope carried (§6.7). */
        val provEnv: ByteArray?,
        val holdUntilMinute: Long,
        /** The relay expiry the blob arrived with, for R11's unread deadline (§21.10 point 5). */
        val relayExpiryHour: Long,
        /** The minute the blob was consumed, which R9 and R11 evaluate against. */
        val consumeMinute: Long,
    ) {
        /** Never shows the ciphertext or the identity (T3). */
        override fun toString(): String = "HeldRow(gen=$genId, consume=$consumeMinute)"
    }

    /** A `dm_scheduled` row: a control message due at a drawn minute (§8.5, §8.6). */
    class ScheduledRow(
        val schedId: ByteArray,
        val contactId: ByteArray,
        val what: String,
        /** The revocation certificate v2 for `what = 'revocation'`, else null. */
        val payload: ByteArray?,
        val dueMinute: Long,
    ) {
        override fun toString(): String = "ScheduledRow(what=$what, due=$dueMinute)"
    }

    // ------------------------------------------------------------------- dm_held

    private val heldColumns =
        "held_id, contact_id, identity, l1_env, gen_id, prov_env, hold_until_minute, " +
            "relay_expiry_hour, consume_minute"

    /**
     * The **live** held rows of a contact: those whose hold deadline has not passed.
     *
     * A row past `hold_until_minute` is not replayed — §8.3's "held rows are deleted at
     * `hold_until_minute`" and §21.10 point 5's "a replayed message whose computed unread deadline
     * is ≤ `now_e` is not inserted" are the same rule seen from two ends — and it is left for SWEEP
     * to delete rather than deleted here, because HELD runs inside a user's decision and SWEEP owns
     * deletion by time (slice S9).
     *
     * The order is `consume_minute, held_id`: a deterministic starting point that [HeldReplay]
     * then regroups by session and chain index (§22.8.1 rule 1), so the SQL order decides only the
     * tie-break between two rows of one chain index.
     */
    fun heldFor(sql: SqlExecutor, contactId: ByteArray, nowMinute: Long): List<HeldRow> {
        val out = ArrayList<HeldRow>()
        sql.query(
            "SELECT $heldColumns FROM dm_held WHERE contact_id = ? AND hold_until_minute > ? " +
                "ORDER BY consume_minute, held_id",
            listOf(contactId, nowMinute),
        ) { r -> out += readHeld(r) }
        return out
    }

    /** How many rows a contact holds, for [MAX_HELD_PER_CONTACT] (the trigger aborts at it). */
    fun heldCount(sql: SqlExecutor, contactId: ByteArray): Int {
        var count = 0
        sql.query(
            "SELECT count(*) FROM dm_held WHERE contact_id = ?",
            listOf(contactId),
        ) { r -> count = r.long(0).toInt() }
        return count
    }

    /** The oldest row of a contact, which the cap evicts first (§8.3: "older ones deleted first"). */
    fun oldestHeld(sql: SqlExecutor, contactId: ByteArray): HeldRow? {
        var row: HeldRow? = null
        sql.query(
            "SELECT $heldColumns FROM dm_held WHERE contact_id = ? " +
                "ORDER BY consume_minute, held_id LIMIT 1",
            listOf(contactId),
        ) { r -> row = readHeld(r) }
        return row
    }

    @Suppress("LongParameterList")
    fun insertHeld(
        tx: SyncTransaction,
        heldId: ByteArray,
        contactId: ByteArray,
        identity: ByteArray,
        l1Env: ByteArray,
        genId: Int,
        provEnv: ByteArray?,
        holdUntilMinute: Long,
        relayExpiryHour: Long,
        consumeMinute: Long,
    ) {
        tx.sql.exec(
            "INSERT INTO dm_held($heldColumns) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            listOf(
                heldId,
                contactId,
                identity,
                l1Env,
                ContactStore.unsigned(genId),
                provEnv,
                holdUntilMinute,
                relayExpiryHour,
                consumeMinute,
            ),
        )
    }

    fun deleteHeld(tx: SyncTransaction, heldId: ByteArray): Int =
        tx.sql.execUpdate("DELETE FROM dm_held WHERE held_id = ?", listOf(heldId))

    /**
     * §8.3 "A second pending key": a valid binding for an identity outside `{OI, OI′}` replaces
     * `pending_identity` and **deletes the held rows of the superseded one**. The newest valid
     * binding wins, and two live devices under one seed flip-flop (declared, R-20).
     */
    fun deleteHeldOtherThan(tx: SyncTransaction, contactId: ByteArray, identity: ByteArray): Int =
        tx.sql.execUpdate(
            "DELETE FROM dm_held WHERE contact_id = ? AND identity IS NOT ?",
            listOf(contactId, identity),
        )

    fun deleteHeldFor(tx: SyncTransaction, contactId: ByteArray): Int =
        tx.sql.execUpdate("DELETE FROM dm_held WHERE contact_id = ?", listOf(contactId))

    private fun readHeld(r: SqlExecutor.Row) = HeldRow(
        heldId = r.blob(0),
        contactId = r.blob(1),
        identity = r.blob(2),
        l1Env = r.blob(3),
        genId = r.long(4).toInt(),
        provEnv = if (r.isNull(5)) null else r.blob(5),
        holdUntilMinute = r.long(6),
        relayExpiryHour = r.long(7),
        consumeMinute = r.long(8),
    )

    // -------------------------------------------------------------- dm_scheduled

    private val scheduledColumns = "sched_id, contact_id, what, payload, due_minute"

    /** The controls whose drawn minute has arrived (§21.9 rule 1: a **time-triggered** step). */
    fun due(sql: SqlExecutor, nowMinute: Long): List<ScheduledRow> {
        val out = ArrayList<ScheduledRow>()
        sql.query(
            "SELECT $scheduledColumns FROM dm_scheduled WHERE due_minute <= ? " +
                "ORDER BY due_minute, sched_id",
            listOf(nowMinute),
        ) { r -> out += readScheduled(r) }
        return out
    }

    fun scheduled(sql: SqlExecutor, contactId: ByteArray, what: String): ScheduledRow? {
        var row: ScheduledRow? = null
        sql.query(
            "SELECT $scheduledColumns FROM dm_scheduled WHERE contact_id = ? AND what = ?",
            listOf(contactId, what),
        ) { r -> row = readScheduled(r) }
        return row
    }

    /**
     * Schedules one control, or moves the one already scheduled for that (contact, kind).
     *
     * An `UPDATE`-then-`INSERT` pair, never a `REPLACE` (gate G-DM4): the table's REPLACE guard
     * refuses an insert that conflicts on `sched_id` **or** on `(contact_id, what)`, because a
     * replace would delete the conflicting row without running its triggers.
     */
    @Suppress("LongParameterList")
    fun putScheduled(
        tx: SyncTransaction,
        schedId: ByteArray,
        contactId: ByteArray,
        what: String,
        payload: ByteArray?,
        dueMinute: Long,
    ) {
        val changed = tx.sql.execUpdate(
            "UPDATE dm_scheduled SET payload = ?, due_minute = ? WHERE contact_id = ? AND what = ?",
            listOf(payload, dueMinute, contactId, what),
        )
        if (changed != 0) return
        tx.sql.exec(
            "INSERT INTO dm_scheduled($scheduledColumns) VALUES (?, ?, ?, ?, ?)",
            listOf(schedId, contactId, what, payload, dueMinute),
        )
    }

    fun deleteScheduled(tx: SyncTransaction, schedId: ByteArray): Int =
        tx.sql.execUpdate("DELETE FROM dm_scheduled WHERE sched_id = ?", listOf(schedId))

    private fun readScheduled(r: SqlExecutor.Row) = ScheduledRow(
        schedId = r.blob(0),
        contactId = r.blob(1),
        what = r.string(2),
        payload = if (r.isNull(3)) null else r.blob(3),
        dueMinute = r.long(4),
    )

    companion object {
        /** §8.3: at most 256 held rows per contact; the `dm_held_limit` trigger aborts at it. */
        const val MAX_HELD_PER_CONTACT: Int = 256

        /** `dm_scheduled.what` for the reconnect notice of §8.6. */
        const val WHAT_RECONNECT: String = "reconnect"

        /** `dm_scheduled.what` for the revocation notice of §8.5. */
        const val WHAT_REVOCATION: String = "revocation"
    }
}
