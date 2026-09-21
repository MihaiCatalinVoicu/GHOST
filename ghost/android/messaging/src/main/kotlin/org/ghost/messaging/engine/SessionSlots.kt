package org.ghost.messaging.engine

import org.ghost.messaging.store.SessionStore
import org.ghost.sync.api.SyncTransaction

/**
 * The session-selection rules R-SS0 … R-SS5 (Phase 9 design §8.2, as amended by §22.8.4).
 *
 * At most two rows per contact: `current`, which every send uses, and `previous`, which receives
 * only and carries a `retire_day`. The rules are deterministic, which is what makes two devices
 * converge on one session without a negotiation (R-SS3), and they are **GHOST's decisions**, not
 * the library's: vodozemac creates a session whenever a PreKey message decrypts, and which of the
 * two slots it lands in — or whether it lands at all — is decided here (§8.2's "an explicit GHOST
 * decision rather than a library side effect").
 *
 * **Why the age rules of §22.8.4 exist.** R-SS1 used to promote every new inbound session, and a
 * responder session is acknowledged by CHECK, so R-SS2 could never undo a wrong promotion: a
 * contact's older first flight, sealed before its restore and processed after its newer reconnect
 * intro, became `current`, and the user's replies went to a session the contact no longer had
 * until its own `UNACK_MAX` re-establishment — a loss outside CS-3. The age order applies **only**
 * to traffic that proves the contact no longer answers on the older session: first-flight (PreKey)
 * traffic, and replies authored before the newer session was sealed.
 *
 * **A slot change is a delete-and-insert in one transaction** (§13.6 step 6): `session_id`, `role`
 * and `peer_gen_id` are immutable, and the envelope bytes travel unchanged because their binding
 * names the contact and the session, not the slot (§22.8.3).
 */
internal class SessionSlots(private val sessions: SessionStore = SessionStore()) {

    /** What [admitNewInbound] decided for a first flight that decrypted (R-SS1). */
    enum class Admission {
        /** It became `current`; the old one was demoted. This is a **renewal from c** (§21.3). */
        CURRENT,

        /** It became `previous`: `current` is a responder session with a newer binding minute. */
        PREVIOUS,

        /**
         * `drop(stale_session)` (§22.8.4 rule 2): an older first flight of a contact that has
         * since restored or reset, with both slots already holding newer responder sessions. No
         * session, no reuse tuple, counted — a declared loss inside CS-3.
         */
        STALE,
    }

    /**
     * R-SS1 as amended by §22.8.4 rule 2: where a newly created inbound session goes.
     *
     * [bindingSeconds] is the sealing minute of the intro envelope that carried the first flight,
     * written by the **contact's** clock; so is every `peer_bind_minute` it is compared with,
     * which is what makes the comparison meaningful across two devices (§22.8.4 rule 5 declares
     * the case where the contact's own clock moved backwards). It is on the **minute grid in epoch
     * seconds**, like every other minute column of §13.6 and like the `author_minute` of
     * [swapAfterPreviousDecrypted], never the wire's minute index.
     */
    fun admitNewInbound(
        tx: SyncTransaction,
        contactId: ByteArray,
        bindingSeconds: Long,
        today: Long,
    ): Admission {
        val current = sessions.current(tx.sql, contactId)
        val previous = sessions.previous(tx.sql, contactId)
        val currentIsNewerResponder = current != null &&
            !current.initiator &&
            (current.peerBindMinute ?: Long.MIN_VALUE) > bindingSeconds
        if (!currentIsNewerResponder) {
            if (current != null) {
                demote(tx, contactId, current, today)
            } else if (previous != null) {
                // No `current` but a `previous`: the new session takes the empty slot and the old
                // `previous` keeps its own retirement.
                Unit
            }
            return Admission.CURRENT
        }
        // `current` is a responder session the contact sealed **later** than this first flight.
        val previousIsOlderResponder = previous == null ||
            (!previous.initiator && (previous.peerBindMinute ?: Long.MIN_VALUE) < bindingSeconds)
        if (!previousIsOlderResponder) return Admission.STALE
        if (previous != null) sessions.deleteSession(tx, contactId, SessionStore.SLOT_PREVIOUS)
        return Admission.PREVIOUS
    }

    /**
     * R-SS2 as amended by §22.8.4 rule 3: whether a message that decrypted on `previous` swaps
     * the two slots.
     *
     * [isPreKey] and [authorMinute] are the two the age guards read: a **PreKey** message on a
     * responder `previous` with a smaller `peer_bind_minute` than a responder `current` never
     * swaps, and a **normal** message on an initiator `previous` whose author minute is smaller
     * than a responder `current`'s `peer_bind_minute` never swaps. Both are stale traffic of a
     * session the contact has dropped.
     *
     * Otherwise the existing rules stand, and they are symmetric so both devices agree: an
     * unacknowledged `current` is swapped out (the peer never answered our newer session, for
     * example because it restored and our session used its lost bundle), and between two
     * acknowledged sessions the smaller `session_id` wins.
     */
    fun swapAfterPreviousDecrypted(
        tx: SyncTransaction,
        contactId: ByteArray,
        isPreKey: Boolean,
        authorMinute: Long?,
        today: Long,
    ): Boolean {
        val current = sessions.current(tx.sql, contactId) ?: return false
        val previous = sessions.previous(tx.sql, contactId) ?: return false
        if (!current.initiator) {
            val currentBind = current.peerBindMinute ?: Long.MIN_VALUE
            if (isPreKey && !previous.initiator &&
                (previous.peerBindMinute ?: Long.MIN_VALUE) < currentBind
            ) {
                return false
            }
            if (!isPreKey && previous.initiator && authorMinute != null && authorMinute < currentBind) {
                return false
            }
        }
        val swap = when {
            !current.acknowledged -> true
            previous.acknowledged -> compareUnsigned(previous.sessionId, current.sessionId) < 0
            else -> false
        }
        if (!swap) return false
        swapSlots(tx, contactId, current, previous, today)
        return true
    }

    /**
     * R-SS0: an explicit reset, a reconnect, a KEYDEC acceptance or a block deletes **both** rows
     * before any new session; a re-establishment caused by `UNACK_MAX` or `NO_SEAL_KEY` demotes
     * `current` instead, because the peer may still answer it.
     */
    fun demoteForReestablishment(tx: SyncTransaction, contactId: ByteArray, today: Long) {
        val current = sessions.current(tx.sql, contactId) ?: return
        demote(tx, contactId, current, today)
    }

    /** Moves `current` to `previous`, deleting whatever was there (R-SS1). */
    private fun demote(
        tx: SyncTransaction,
        contactId: ByteArray,
        current: SessionStore.SessionRow,
        today: Long,
    ) {
        sessions.deleteSession(tx, contactId, SessionStore.SLOT_PREVIOUS)
        sessions.deleteSession(tx, contactId, SessionStore.SLOT_CURRENT)
        insertAs(tx, contactId, SessionStore.SLOT_PREVIOUS, current, today + SessionStore.RETIRE_DAYS)
    }

    /** Exchanges the two rows, resetting the demoted one's `retire_day` (R-SS2). */
    private fun swapSlots(
        tx: SyncTransaction,
        contactId: ByteArray,
        current: SessionStore.SessionRow,
        previous: SessionStore.SessionRow,
        today: Long,
    ) {
        sessions.deleteSession(tx, contactId, SessionStore.SLOT_CURRENT)
        sessions.deleteSession(tx, contactId, SessionStore.SLOT_PREVIOUS)
        insertAs(tx, contactId, SessionStore.SLOT_CURRENT, previous, null)
        insertAs(
            tx,
            contactId,
            SessionStore.SLOT_PREVIOUS,
            current,
            today + SessionStore.RETIRE_DAYS,
        )
    }

    /**
     * Re-inserts a row in another slot, carrying every column across.
     *
     * `prov_erase_minute`, `prov_anchor_minute` and `pair_sent` are write-once or monotonic
     * columns the insert cannot set (§13.6 step 6's `olm_session_identity` trigger), so they are
     * applied again after the row exists — which is what makes a slot change lose nothing.
     */
    private fun insertAs(
        tx: SyncTransaction,
        contactId: ByteArray,
        slot: String,
        row: SessionStore.SessionRow,
        retireDay: Long?,
    ) {
        sessions.insertSession(
            tx = tx,
            contactId = contactId,
            slot = slot,
            sessionId = row.sessionId,
            initiator = row.initiator,
            acknowledged = row.acknowledged,
            stateEnv = row.stateEnv,
            provEnv = row.provEnv,
            peerGenId = row.peerGenId,
            unackSinceDay = row.unackSinceDay,
            retireDay = retireDay,
            peerBindMinute = row.peerBindMinute,
        )
        row.provAnchorMinute?.let { sessions.setProvisionalAnchor(tx, contactId, slot, it) }
        row.provEraseMinute?.let { sessions.setProvisionalEraseMinute(tx, contactId, slot, it) }
        if (row.pairSent) sessions.markPairSent(tx, contactId, slot)
    }

    companion object {
        /** §8.7: `UNACK_MAX`. */
        const val UNACK_MAX_DAYS: Long = 28

        /**
         * §8.7: an **initiator** session unacknowledged for `UNACK_MAX = 28 days` is stale, and it
         * is no longer a *usable* session for §21.7 point 4's purposes — the contact never answered
         * it and may have erased the generation it was built on.
         *
         * It lives here rather than in [SendStep] because three steps have to agree on it: the
         * send that asks for a re-establishment, the flush that must not seal onto the session
         * being replaced, and `EST-READY`, whose "unless a **usable** session already exists" is
         * this predicate and not "unless a row exists". A copy in each of them is how a session
         * becomes permanent (the send keeps asking, the establishment keeps refusing).
         */
        fun isStale(session: SessionStore.SessionRow, now: Long): Boolean {
            if (!session.initiator || session.acknowledged) return false
            val since = session.unackSinceDay ?: return false
            return DmTime.day(now) - since >= UNACK_MAX_DAYS
        }
    }

    /** Bytewise, as §8.2's tie-break reads it: "the smaller session id wins". */
    private fun compareUnsigned(left: ByteArray, right: ByteArray): Int {
        val size = minOf(left.size, right.size)
        for (i in 0 until size) {
            val diff = (left[i].toInt() and 0xff) - (right[i].toInt() and 0xff)
            if (diff != 0) return diff
        }
        return left.size - right.size
    }
}
