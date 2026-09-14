package org.ghost.entitlement.store

import org.ghost.identity.Invite
import org.ghost.sync.api.SyncTransaction

/** One `ent_invite` row (inviter side), with the refresh time drawn at its creation (§19.29). */
internal class InviteRow(
    val index: Int,
    val state: String,
    payload: ByteArray?,
    dropNamespace: ByteArray,
    val listenUntilDay: Long,
    val refreshMinute: Long,
) {
    private val payloadBytes = payload?.copyOf()
    private val namespaceBytes = dropNamespace.copyOf()

    fun payload(): ByteArray? = payloadBytes?.copyOf()
    fun dropNamespace(): ByteArray = namespaceBytes.copyOf()

    override fun toString(): String = "InviteRow($state)"
}

/** The `ent_drop_target` singleton (invitee side). */
internal class DropTargetRow(
    dropNamespace: ByteArray,
    dropKey: ByteArray,
    val dropSlots: List<Int>,
    val state: String,
    operationId: ByteArray?,
    val dropMinute: Long,
    val untilDay: Long,
) {
    private val namespaceBytes = dropNamespace.copyOf()
    private val keyBytes = dropKey.copyOf()
    private val operationBytes = operationId?.copyOf()

    fun dropNamespace(): ByteArray = namespaceBytes.copyOf()
    fun dropKey(): ByteArray = keyBytes.copyOf()
    fun operationId(): ByteArray? = operationBytes?.copyOf()

    override fun toString(): String = "DropTargetRow($state)"
}

/**
 * `ent_invite` (invites this identity created, design §8.5, with the refresh time of a credit sent
 * to the drop, §19.29) and `ent_drop_target` (the drop this identity owes its first XMR-pack
 * credit to, §9.3, §19.12). Guarded transitions; plain INSERT after a read (§19.22 point 4). The
 * payload is dropped when an invite leaves `created`; a `created` row without a payload is a drop a
 * restore scans (§8.4).
 */
internal class InviteStore {

    /** A new invite; [refreshMinute] is the refresh time of a credit sent to its drop (§19.29). */
    fun insert(tx: SyncTransaction, index: Int, payload: ByteArray, dropNamespace: ByteArray, listenUntilDay: Long, refreshMinute: Long) {
        check(get(tx, index) == null) { "invite index already used" }
        tx.sql.updateExactly(
            1,
            "INSERT INTO ent_invite(invite_index, state, payload, drop_namespace, listen_until_day, refresh_minute) " +
                "VALUES (?1, 'created', ?2, ?3, ?4, ?5)",
            listOf(index, payload, dropNamespace, listenUntilDay, refreshMinute),
        )
    }

    /**
     * The drop of invite [index], which this identity may have created before a restore (§8.4): its
     * payload is unknown, its namespace re-derived from the root entropy, listened until [listenUntilDay],
     * with the refresh time drawn as every drop's (`RefreshPlan.time`, §19.29).
     */
    fun insertScanned(tx: SyncTransaction, index: Int, dropNamespace: ByteArray, listenUntilDay: Long, refreshMinute: Long) {
        check(get(tx, index) == null) { "invite index already used" }
        tx.sql.updateExactly(
            1,
            "INSERT INTO ent_invite(invite_index, state, payload, drop_namespace, listen_until_day, refresh_minute) " +
                "VALUES (?1, 'created', NULL, ?2, ?3, ?4)",
            listOf(index, dropNamespace, listenUntilDay, refreshMinute),
        )
    }

    /**
     * A later restore listens to a scanned drop until its own scan ends, with a refresh time drawn after
     * that end; the drop holds no received credit (it is still `created`), so none was due at the old one.
     */
    fun extendScanned(tx: SyncTransaction, index: Int, listenUntilDay: Long, refreshMinute: Long): Int = tx.sql.execUpdate(
        "UPDATE ent_invite SET listen_until_day = ?2, refresh_minute = ?3 " +
            "WHERE invite_index = ?1 AND state = 'created' AND payload IS NULL AND listen_until_day < ?2",
        listOf(index, listenUntilDay, refreshMinute),
    )

    fun get(tx: SyncTransaction, index: Int): InviteRow? =
        tx.sql.single("SELECT $COLUMNS FROM ent_invite WHERE invite_index = ?1", listOf(index), ::row)

    fun all(tx: SyncTransaction): List<InviteRow> = tx.sql.rows("SELECT $COLUMNS FROM ent_invite ORDER BY invite_index", map = ::row)

    fun byNamespace(tx: SyncTransaction, dropNamespace: ByteArray): InviteRow? =
        tx.sql.single("SELECT $COLUMNS FROM ent_invite WHERE drop_namespace = ?1", listOf(dropNamespace), ::row)

    /** A credit arrived through the drop: `created` → `credited`. */
    fun credit(tx: SyncTransaction, index: Int) = tx.sql.updateExactly(
        1,
        "UPDATE ent_invite SET state = 'credited', payload = NULL WHERE invite_index = ?1 AND state = 'created'",
        listOf(index),
    )

    /** Listening ended or the invite was revoked. */
    fun close(tx: SyncTransaction, index: Int) = tx.sql.updateExactly(
        1,
        "UPDATE ent_invite SET state = 'closed', payload = NULL WHERE invite_index = ?1 AND state IN ('created', 'credited')",
        listOf(index),
    )

    fun deleteClosed(tx: SyncTransaction, index: Int): Int =
        tx.sql.execUpdate("DELETE FROM ent_invite WHERE invite_index = ?1 AND state = 'closed'", listOf(index))

    fun dropTarget(tx: SyncTransaction): DropTargetRow? = tx.sql.single(
        "SELECT drop_namespace, drop_key, drop_slots, state, operation_id, drop_minute, until_day FROM ent_drop_target WHERE id = 1",
    ) {
        val slots = it.blob(2)
        DropTargetRow(it.blob(0), it.blob(1), slots.map { b -> b.toInt() and 0xff }, it.string(3), it.blobOrNull(4), it.long(5), it.long(6))
    }

    fun insertDropTarget(tx: SyncTransaction, dropNamespace: ByteArray, dropKey: ByteArray, dropSlots: List<Int>, dropMinute: Long, untilDay: Long) {
        check(dropTarget(tx) == null) { "drop target already recorded" }
        require(dropSlots.size == Invite.DROP_SLOTS) { "three drop slots" }
        tx.sql.updateExactly(
            1,
            "INSERT INTO ent_drop_target(id, drop_namespace, drop_key, drop_slots, state, drop_minute, until_day) VALUES (1, ?1, ?2, ?3, 'waiting', ?4, ?5)",
            listOf(dropNamespace, dropKey, ByteArray(dropSlots.size) { dropSlots[it].toByte() }, dropMinute, untilDay),
        )
    }

    /** The blob was enqueued with its Outbox op in the same transaction (§11.5). */
    fun markEnqueued(tx: SyncTransaction, operationId: ByteArray) = tx.sql.updateExactly(
        1,
        "UPDATE ent_drop_target SET state = 'enqueued', operation_id = ?1 WHERE id = 1 AND state = 'waiting'",
        listOf(operationId),
    )

    fun deleteDropTarget(tx: SyncTransaction): Int = tx.sql.execUpdate("DELETE FROM ent_drop_target WHERE id = 1")

    private fun row(it: org.ghost.storage.SqlExecutor.Row) =
        InviteRow(it.long(0).toInt(), it.string(1), it.blobOrNull(2), it.blob(3), it.long(4), it.long(5))

    companion object {
        const val CREATED = "created"
        const val CREDITED = "credited"
        const val CLOSED = "closed"
        const val WAITING = "waiting"
        const val ENQUEUED = "enqueued"

        private const val COLUMNS = "invite_index, state, payload, drop_namespace, listen_until_day, refresh_minute"
    }
}

/**
 * [Invite.NonceStore] bound to the activation transaction (design §8.3 step 2, §19.20 point 6): the
 * nonce is recorded in `invite_nonces` inside the same transaction as the trial and the drop target,
 * so a refused or rolled-back activation never consumes it. `seen_at` holds the UTC day's start only.
 */
internal class TransactionNonceStore(private val tx: SyncTransaction, private val seenDayStart: Long) : Invite.NonceStore {
    override fun recordIfFresh(nonce: ByteArray): Boolean {
        require(nonce.size == Invite.NONCE_BYTES) { "invite nonce has the wrong length" }
        if (tx.sql.single("SELECT 1 FROM invite_nonces WHERE nonce = ?1", listOf(nonce)) { 1 } != null) return false
        tx.sql.updateExactly(1, "INSERT INTO invite_nonces(nonce, seen_at) VALUES (?1, ?2)", listOf(nonce, seenDayStart))
        return true
    }

    override fun toString(): String = "TransactionNonceStore"
}
