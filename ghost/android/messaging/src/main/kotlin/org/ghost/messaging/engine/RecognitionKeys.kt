package org.ghost.messaging.engine

import org.ghost.crypto.bridge.DmPairing
import org.ghost.crypto.bridge.Recognition
import org.ghost.messaging.port.DmEnvelopes
import org.ghost.messaging.store.ContactStore
import org.ghost.messaging.store.SessionStore
import org.ghost.storage.SqlExecutor

/**
 * The candidate recognition keys of rule R-S5 (Phase 9 design §6.2), and the one-attempt match
 * over them.
 *
 * > The recipient computes the hints of its candidate recognition keys and opens with **at most
 * > one** key, the one whose hint matches. There is no trial decryption across keys, so the
 * > partitioning-oracle attack on the non-committing AEAD does not apply. A hint match whose AEAD
 * > fails is a forgery: dropped, counted.
 *
 * **The candidate set per contact** (E-13, as the revision amends it): the in-week recognition
 * keys of every live root generation, the `K_prov` recognition keys of its sessions that still
 * hold a `prov_env`, and — once per device, not per contact — `KIO_0` of the own card. At
 * `MAX_CONTACTS = 1 000` that is at most 22 001 HMAC-SHA256 evaluations for a blob nothing
 * matches, which is the cost the V-13 benchmark measures.
 *
 * **Order and laziness.** Hints are computed lazily, most recent first, stopping at the first
 * match, and contacts are walked in an in-memory most-recently-matched order that is **never
 * persisted** (T33): a persisted order would be a per-conversation activity record, which is what
 * `dm_conversation` deliberately does not carry.
 *
 * **Why the provisional keys are derived and not stored.** `K_prov(dir)` is a function of a
 * session's `reply_seed` and its Olm session keys (§6.7), and `olm_session` has no column for
 * either key. Deriving them costs one call per session and keeps the erasure schedule honest:
 * when `prov_env` goes, the keys go with it, which is what rule R-S6 means by "a recognition key
 * follows the erasure schedule of its opening key" (mutant PM-36).
 */
internal class RecognitionKeys(private val envelopes: DmEnvelopes) {

    private val contacts = ContactStore()
    private val sessions = SessionStore()

    /** The most-recently-matched contacts, newest first. Never persisted (T33). */
    private val recent = ArrayList<List<Byte>>()

    /** `sessionId -> the two provisional keys`, for as long as the session holds a `prov_env`. */
    private val provisional = HashMap<List<Byte>, DmPairing.Provisional>()

    /** What a matched hint names. */
    sealed interface Match {
        /** A pair envelope of [contactId], under the week key of [rootGen] and [week] (§6.3). */
        class Pair(
            val contactId: ByteArray,
            val rootGen: Int,
            val week: Long,
            val openEnv: ByteArray,
        ) : Match

        /** A provisional envelope of [contactId]'s session [sessionId] (§6.7). */
        class Provisional(
            val contactId: ByteArray,
            val sessionId: ByteArray,
            val direction: Int,
            val openEnv: ByteArray,
        ) : Match

        /** An intro envelope addressed to this device's own card (§6.4). */
        data object Intro : Match
    }

    /**
     * The first candidate whose hint matches [blob], or null — `drop(unknown_seal)` of §6.5
     * step 2.
     *
     * [self] supplies `KIO_0`, which is tried **last**: an intro envelope is the rare case (a
     * first contact, a reset, a reconnect, every PreKey message of a session the peer has not
     * answered), and trying it first would cost every established conversation an extra HMAC.
     */
    fun match(
        sql: SqlExecutor,
        self: SelfContext,
        blob: ByteArray,
        candidates: List<ContactStore.ContactRow> = contacts.contacts(sql),
    ): Match? {
        for (contactId in ordered(candidates)) {
            matchContact(sql, contactId, blob)?.let { hit ->
                remember(contactId)
                return hit
            }
        }
        if (envelopes.hintMatches(blob, self.card.recognitionIntro)) return Match.Intro
        return null
    }

    /**
     * The contacts an inbound envelope can belong to, read **once** per pass.
     *
     * A peek walks up to 256 blobs (§7.7 point 1) and `MAX_CONTACTS` is 1 000, so reading the
     * contact table per blob would be 256 000 row reads for one pass; the candidate **keys** are
     * what rule R-S5 bounds, not the row reads behind them.
     */
    fun candidates(sql: SqlExecutor): List<ContactStore.ContactRow> = contacts.contacts(sql)

    /** Drops a session's cached provisional keys: it was deleted, or its `prov_env` was erased. */
    fun forgetSession(sessionId: ByteArray) {
        provisional.remove(sessionId.toList())
    }

    /** Drops every cached key: the DM context closed, or the identity changed (§2.5). */
    fun clear() {
        provisional.clear()
        recent.clear()
    }

    private fun matchContact(sql: SqlExecutor, contactId: ByteArray, blob: ByteArray): Match? {
        // Pair keys first, newest generation and week first: an answered conversation is the
        // common case and its newest week is the likeliest match.
        for (key in contacts.pairKeys(sql, contactId, ContactStore.DIRECTION_IN)) {
            if (envelopes.hintMatches(blob, key.recognitionKey)) {
                return Match.Pair(contactId, key.rootGen, key.week, key.openEnv)
            }
        }
        for (session in sessions.sessions(sql, contactId)) {
            val keys = provisionalOf(sql, contactId, session) ?: continue
            if (envelopes.hintMatches(blob, keys.recognitionIn)) {
                return Match.Provisional(contactId, session.sessionId, keys.inDirection, keys.inEnv)
            }
        }
        return null
    }

    private fun provisionalOf(
        sql: SqlExecutor,
        contactId: ByteArray,
        session: SessionStore.SessionRow,
    ): DmPairing.Provisional? {
        val provEnv = session.provEnv ?: return null
        val key = session.sessionId.toList()
        provisional[key]?.let { return it }
        val contact = contacts.contact(sql, contactId) ?: return null
        val pinned = contact.pinnedIdentity ?: return null
        val derived = envelopes.provisionalKeys(
            contactId = contactId,
            sessionId = session.sessionId,
            stateEnv = session.stateEnv,
            replySeedEnv = provEnv,
            peerOlmIdentity = pinned,
        )
        if (derived !is DmPairing.ProvisionalResult.Ok) return null
        provisional[key] = derived.keys
        return derived.keys
    }

    /** Every contact that can own an inbound envelope, most recently matched first. */
    private fun ordered(candidates: List<ContactStore.ContactRow>): List<ByteArray> {
        val all = candidates
            .filter { it.trust != ContactStore.Trust.BLOCKED && it.trust != ContactStore.Trust.REVOKED }
            .associateBy { it.contactId.toList() }
        val out = ArrayList<ByteArray>(all.size)
        for (id in recent) all[id]?.let { out += it.contactId }
        for ((id, row) in all) if (id !in recent) out += row.contactId
        return out
    }

    private fun remember(contactId: ByteArray) {
        val key = contactId.toList()
        recent.remove(key)
        recent.add(0, key)
        while (recent.size > RECENT_MAX) recent.removeAt(recent.size - 1)
    }

    companion object {
        /**
         * How many contacts the most-recently-matched order keeps. Past this the walk is in row
         * order, which costs the full hint set for a blob of a quiet conversation and nothing in
         * correctness — the order is an optimisation, and rule R-S5 bounds the worst case anyway.
         */
        const val RECENT_MAX: Int = 64

        /** A blob shorter than a seal header cannot carry a hint (§6.2). */
        const val MIN_BLOB_BYTES: Int = Recognition.HEADER_BYTES
    }
}
