package org.ghost.messaging.store

import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.SyncTransaction

/**
 * The Olm rows of schema v5 (Phase 9 design §13.6 step 5, §8.1): `olm_session` and
 * `olm_prekey_used`.
 *
 * At most **two** rows per contact, `current` and `previous` (§8.2). The selection rules
 * R-SS0 … R-SS5 are `SessionSlots`'; this class is where the rows live and nothing more.
 *
 * **A slot change is a delete-and-insert in one transaction** (§13.6 step 6): the
 * `olm_session_identity` trigger makes `session_id`, `role` and `peer_gen_id` immutable, so a row
 * cannot be moved between slots by an `UPDATE`, and the envelope bytes travel unchanged because
 * their binding names the contact and the session, not the slot (§22.8.3).
 */
internal class SessionStore {

    /** An `olm_session` row. */
    class SessionRow(
        val slot: String,
        val sessionId: ByteArray,
        val initiator: Boolean,
        val acknowledged: Boolean,
        val stateEnv: ByteArray,
        val provEnv: ByteArray?,
        val provEraseMinute: Long?,
        val peerGenId: Int?,
        val unackSinceDay: Long?,
        val retireDay: Long?,
        val peerBindMinute: Long?,
        val provAnchorMinute: Long?,
        val pairSent: Boolean,
    ) {
        /** Never shows the wrapped state (T3). */
        override fun toString(): String =
            "SessionRow(slot=$slot, initiator=$initiator, acknowledged=$acknowledged)"
    }

    private val columns =
        "slot, session_id, role, acknowledged, state_env, prov_env, prov_erase_minute, " +
            "peer_gen_id, unack_since_day, retire_day, peer_bind_minute, prov_anchor_minute, pair_sent"

    fun sessions(sql: SqlExecutor, contactId: ByteArray): List<SessionRow> {
        val out = ArrayList<SessionRow>()
        sql.query(
            "SELECT $columns FROM olm_session WHERE contact_id = ? ORDER BY slot",
            listOf(contactId),
        ) { r -> out += readSession(r) }
        return out
    }

    fun session(sql: SqlExecutor, contactId: ByteArray, slot: String): SessionRow? =
        sessions(sql, contactId).firstOrNull { it.slot == slot }

    fun current(sql: SqlExecutor, contactId: ByteArray): SessionRow? =
        session(sql, contactId, SLOT_CURRENT)

    fun previous(sql: SqlExecutor, contactId: ByteArray): SessionRow? =
        session(sql, contactId, SLOT_PREVIOUS)

    /** Every session of every contact, for the peek order's candidate set (§7.7 point 1). */
    fun allSessions(sql: SqlExecutor): List<Pair<ByteArray, SessionRow>> {
        val out = ArrayList<Pair<ByteArray, SessionRow>>()
        sql.query(
            "SELECT contact_id, $columns FROM olm_session ORDER BY contact_id, slot",
        ) { r ->
            val contactId = r.blob(0)
            out += contactId to SessionRow(
                slot = r.string(1),
                sessionId = r.blob(2),
                initiator = r.string(3) == ROLE_INITIATOR,
                acknowledged = r.long(4) != 0L,
                stateEnv = r.blob(5),
                provEnv = if (r.isNull(6)) null else r.blob(6),
                provEraseMinute = if (r.isNull(7)) null else r.long(7),
                peerGenId = if (r.isNull(8)) null else r.long(8).toInt(),
                unackSinceDay = if (r.isNull(9)) null else r.long(9),
                retireDay = if (r.isNull(10)) null else r.long(10),
                peerBindMinute = if (r.isNull(11)) null else r.long(11),
                provAnchorMinute = if (r.isNull(12)) null else r.long(12),
                pairSent = r.long(13) != 0L,
            )
        }
        return out
    }

    @Suppress("LongParameterList")
    fun insertSession(
        tx: SyncTransaction,
        contactId: ByteArray,
        slot: String,
        sessionId: ByteArray,
        initiator: Boolean,
        acknowledged: Boolean,
        stateEnv: ByteArray,
        provEnv: ByteArray?,
        peerGenId: Int?,
        unackSinceDay: Long?,
        retireDay: Long?,
        peerBindMinute: Long?,
    ) {
        tx.sql.exec(
            "INSERT INTO olm_session(contact_id, slot, session_id, role, acknowledged, state_env, " +
                "prov_env, prov_erase_minute, peer_gen_id, unack_since_day, retire_day, " +
                "peer_bind_minute, prov_anchor_minute, pair_sent) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, NULL, 0)",
            listOf(
                contactId,
                slot,
                sessionId,
                if (initiator) ROLE_INITIATOR else ROLE_RESPONDER,
                if (acknowledged) 1L else 0L,
                stateEnv,
                provEnv,
                peerGenId?.let { ContactStore.unsigned(it) },
                unackSinceDay,
                retireDay,
                peerBindMinute,
            ),
        )
    }

    /** The one column a ratchet step writes back (§7.9 point 1: value semantics). */
    fun setStateEnv(tx: SyncTransaction, contactId: ByteArray, slot: String, stateEnv: ByteArray) {
        tx.sql.exec(
            "UPDATE olm_session SET state_env = ? WHERE contact_id = ? AND slot = ?",
            listOf(stateEnv, contactId, slot),
        )
    }

    /**
     * The peer answered: `acknowledged` goes 0 → 1 and `unack_since_day` to NULL, which is all the
     * `olm_session_identity` trigger allows on those two columns.
     */
    fun acknowledge(tx: SyncTransaction, contactId: ByteArray, slot: String) {
        tx.sql.exec(
            "UPDATE olm_session SET acknowledged = 1, unack_since_day = NULL " +
                "WHERE contact_id = ? AND slot = ? AND acknowledged = 0",
            listOf(contactId, slot),
        )
    }

    /** `peer_bind_minute` only increases (§22.8.4 rule 1). */
    fun raisePeerBindMinute(tx: SyncTransaction, contactId: ByteArray, slot: String, minute: Long) {
        tx.sql.exec(
            "UPDATE olm_session SET peer_bind_minute = ? WHERE contact_id = ? AND slot = ? " +
                "AND peer_bind_minute < ?",
            listOf(minute, contactId, slot, minute),
        )
    }

    /** `prov_anchor_minute` is write-once (§22.8.5 rule 4). */
    fun setProvisionalAnchor(
        tx: SyncTransaction,
        contactId: ByteArray,
        slot: String,
        minute: Long,
    ) {
        tx.sql.exec(
            "UPDATE olm_session SET prov_anchor_minute = ? WHERE contact_id = ? AND slot = ? " +
                "AND prov_anchor_minute IS NULL",
            listOf(minute, contactId, slot),
        )
    }

    /** `pair_sent` only goes 0 → 1: a pair envelope was sealed on this session (§22.8.5 rule 3). */
    fun markPairSent(tx: SyncTransaction, contactId: ByteArray, slot: String) {
        tx.sql.exec(
            "UPDATE olm_session SET pair_sent = 1 WHERE contact_id = ? AND slot = ? AND pair_sent = 0",
            listOf(contactId, slot),
        )
    }

    /** `prov_erase_minute` is the schedule §6.7 gives the `reply_seed`; it only decreases. */
    fun setProvisionalEraseMinute(
        tx: SyncTransaction,
        contactId: ByteArray,
        slot: String,
        minute: Long,
    ) {
        tx.sql.exec(
            "UPDATE olm_session SET prov_erase_minute = ? WHERE contact_id = ? AND slot = ? " +
                "AND prov_env IS NOT NULL AND (prov_erase_minute IS NULL OR prov_erase_minute > ?)",
            listOf(minute, contactId, slot, minute),
        )
    }

    fun deleteSession(tx: SyncTransaction, contactId: ByteArray, slot: String): Int =
        tx.sql.execUpdate(
            "DELETE FROM olm_session WHERE contact_id = ? AND slot = ?",
            listOf(contactId, slot),
        )

    fun deleteSessions(tx: SyncTransaction, contactId: ByteArray): Int =
        tx.sql.execUpdate("DELETE FROM olm_session WHERE contact_id = ?", listOf(contactId))

    // ------------------------------------------------------------ olm_prekey_used

    /**
     * D2b (§7.6): the first-flight reuse set. `INSERT OR IGNORE` — a replayed first flight of a
     * live generation must not insert a second tuple, and the row is a primary key of its own.
     * The insert happens in the **same** transaction that created the session, so a crash between
     * the two is impossible (§7.8 "a crash after `sessionInbound` rolls back the session row and
     * the reuse tuple together").
     */
    fun markFirstFlightUsed(tx: SyncTransaction, genId: Int, sessionId: ByteArray): Boolean =
        tx.sql.execUpdate(
            "INSERT OR IGNORE INTO olm_prekey_used(gen_id, session_id) VALUES (?, ?)",
            listOf(ContactStore.unsigned(genId), sessionId),
        ) == 1

    /** Whether this first flight was already used on a generation this device still holds. */
    fun firstFlightUsed(sql: SqlExecutor, genId: Int, sessionId: ByteArray): Boolean {
        var used = false
        sql.query(
            "SELECT 1 FROM olm_prekey_used WHERE gen_id = ? AND session_id = ?",
            listOf(ContactStore.unsigned(genId), sessionId),
        ) { used = true }
        return used
    }

    private fun readSession(r: SqlExecutor.Row) = SessionRow(
        slot = r.string(0),
        sessionId = r.blob(1),
        initiator = r.string(2) == ROLE_INITIATOR,
        acknowledged = r.long(3) != 0L,
        stateEnv = r.blob(4),
        provEnv = if (r.isNull(5)) null else r.blob(5),
        provEraseMinute = if (r.isNull(6)) null else r.long(6),
        peerGenId = if (r.isNull(7)) null else r.long(7).toInt(),
        unackSinceDay = if (r.isNull(8)) null else r.long(8),
        retireDay = if (r.isNull(9)) null else r.long(9),
        peerBindMinute = if (r.isNull(10)) null else r.long(10),
        provAnchorMinute = if (r.isNull(11)) null else r.long(11),
        pairSent = r.long(12) != 0L,
    )

    companion object {
        /** The slot every send uses (§8.2). */
        const val SLOT_CURRENT: String = "current"

        /** Receive only, with a `retire_day` (§8.2, R-SS4). */
        const val SLOT_PREVIOUS: String = "previous"

        /** This device started the session. */
        const val ROLE_INITIATOR: String = "initiator"

        /** The contact started it. */
        const val ROLE_RESPONDER: String = "responder"

        /** R-SS1: a demoted session is retired 46 days later, past FRESH (§8.2 R-SS4). */
        const val RETIRE_DAYS: Long = 46
    }
}
