package org.ghost.messaging.engine

import org.ghost.crypto.bridge.DmSeal
import org.ghost.crypto.bridge.DmSessions
import org.ghost.messaging.port.DmClock
import org.ghost.messaging.port.DmEnvelopes
import org.ghost.messaging.store.ContactStore
import org.ghost.messaging.store.OwnerStore
import org.ghost.messaging.store.SessionStore
import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.PeekedBlob
import org.ghost.sync.api.SyncDatabase

/**
 * **Peek ordering and the bounded gap hold** (Phase 9 design §7.7 points 1 and 2).
 *
 * Olm keeps at most **40 skipped message keys per receiver chain** and **5 receiver chains per
 * session**, and those limits are not configurable — the audit's suggestion 8 was declined. GHOST
 * reorders where HIGH mode delays each store by `U[0, 10 min]` independently, where relays are
 * listed on independent schedules, and where a refusing or withholding relay makes one copy late.
 * Two mitigations bring the loss to zero in every configuration S0′ measured (V-7):
 *
 *  1. **Peek ordering.** The actor reads up to `SORT_WINDOW = 256` fetched blobs with the
 *     read-only `Inbox.peek`, opens each seal **in memory**, groups by (contact, session match or
 *     ratchet key), orders each group by chain index, and processes each blob in that order in
 *     its own `RECV` transaction after `Inbox.claimOne`.
 *  2. **The gap hold.** A peeked blob of a session under ratchet key `R` with chain index `i` is
 *     left `fetched` on **every** pass for which `i > n` and some index in `[n, i)` is not in that
 *     pass's peek set, where `n` is the next chain index of the session's receiver chain for `R`,
 *     **read from the stored state** by `chainPosition`. The hold ends at
 *     `first_seen + HOLD_MAX (12 min)`: from that moment the blob is consumed whatever the gap.
 *
 * **Nothing here writes and nothing here sends** (T28). `peek` changes no offer counter,
 * `chainPosition` writes nothing, and opening a seal in memory commits nothing — which is why a
 * decapsulation error during a peek is `NOT_OPEN` and not a crash (§22.8.2): a peek commits no
 * offer counter, so a crash loop here would have no poison guard to stop it.
 *
 * **Why the expected index comes from the stored session.** Round 9 kept a "highest decrypted
 * chain index per process" in memory, which loses 0.5 % of HIGH bursts when every pass runs in a
 * fresh process; the stored session already holds the exact expected index and makes the hold
 * restart-proof (§7.7 point 2 as S0′ rewrote it, V-7). Only `first_seen` is in memory, and a
 * restart there costs a fresh 12-minute hold and nothing else.
 */
internal class PeekOrder(
    private val database: SyncDatabase,
    private val sync: DmSyncPorts,
    private val envelopes: DmEnvelopes,
    private val recognition: RecognitionKeys,
    private val clock: DmClock,
    private val contexts: SelfContexts,
) {
    private val contacts = ContactStore()
    private val sessions = SessionStore()
    private val owner = OwnerStore()

    /** `(namespace || hash) -> the second this pass first saw the blob`. In memory only (T33). */
    private val firstSeen = HashMap<List<Byte>, Long>()

    /** One peeked blob, with what the in-memory open told us about it. */
    private class Ordered(
        val blob: PeekedBlob,
        /** The group a blob belongs to: one contact's one receiver chain, or one new session. */
        val group: List<Byte>,
        /** Its index inside that chain. */
        val chainIndex: Long,
        /** The next index the stored session expects for that chain, or 0 for a new one. */
        val expectedIndex: Long,
    )

    /**
     * The blobs to claim, in the order to claim them (§7.7 point 1), with the held ones left out.
     *
     * A blob whose seal does not open in memory is **kept**: it may be a forgery, and dropping it
     * here would mean never consuming it, so it goes to `RECV` in arrival order to be counted and
     * consumed there (R-P2). Only the ordering is decided here; every decision that changes state
     * is `RECV`'s.
     */
    fun order(): List<PeekedBlob> {
        val self = contexts.get() ?: return emptyList()
        val peeked = sync.inbox.peek(Consumer.DM, SORT_WINDOW)
        if (peeked.isEmpty()) {
            firstSeen.clear()
            return emptyList()
        }
        val now = clock.nowEpochSeconds()
        val seen = HashSet<List<Byte>>(peeked.size)
        for (blob in peeked) seen += keyOf(blob)
        firstSeen.keys.retainAll(seen)
        // A wall clock stepped **back** restarts a hold from the new time (phase review ENG-8).
        // `now − first_seen` was negative until the clock came back to where it had been, so a
        // step of a day held a gap for a day where §7.7 point 2 promises at most 12 minutes. The
        // wall clock and not the monotonic one, because `first_seen` is a wall time by design and
        // every world of the harness moves the wall clock; a restart costs at most one more hold.
        firstSeen.replaceAll { _, since -> minOf(since, now) }

        val examined = database.transaction { tx -> examine(tx.sql, self, peeked) }
        val unordered = ArrayList<PeekedBlob>()
        val groups = LinkedHashMap<List<Byte>, MutableList<Ordered>>()
        for ((blob, ordered) in examined) {
            firstSeen.putIfAbsent(keyOf(blob), now)
            if (ordered == null) unordered += blob else groups.getOrPut(ordered.group) { ArrayList() } += ordered
        }

        val out = ArrayList<PeekedBlob>(peeked.size)
        for (group in groups.values) {
            group.sortBy { it.chainIndex }
            val present = group.mapTo(HashSet()) { it.chainIndex }
            for (entry in group) {
                if (held(entry, present, now)) continue
                out += entry.blob
            }
        }
        out += unordered
        return out
    }

    /** Forgets what a pass remembered: the DM context closed, or the identity changed. */
    fun clear() {
        firstSeen.clear()
    }

    /**
     * §7.7 point 2: `i > n` and some index in `[n, i)` missing from this pass's set, until
     * `first_seen + HOLD_MAX`.
     *
     * The window is `[n, i)` and not `[0, i)`: the keys below `n` are already used or evicted, so
     * waiting for them would hold a blob for ever.
     */
    private fun held(entry: Ordered, present: Set<Long>, now: Long): Boolean {
        if (entry.chainIndex <= entry.expectedIndex) return false
        val since = firstSeen[keyOf(entry.blob)] ?: now
        if (now - since >= HOLD_MAX_SECONDS) return false
        var index = entry.expectedIndex
        while (index < entry.chainIndex) {
            if (index !in present) return true
            index += 1
        }
        return false
    }

    /**
     * Opens each peeked blob in memory and reports its chain, or null when it cannot be placed.
     *
     * The transaction is a **read**: it reads contacts, sessions and generations, and writes
     * nothing. Every native call it makes — the hint matches, the two symmetric openings, the
     * intro decapsulation and `chainPosition` — writes nothing either (T28).
     */
    private fun examine(
        sql: SqlExecutor,
        self: SelfContext,
        peeked: List<PeekedBlob>,
    ): List<Pair<PeekedBlob, Ordered?>> {
        val candidates = recognition.candidates(sql)
        val generations = owner.generations(sql)
        return peeked.map { blob ->
            blob to place(sql, self, blob, candidates, generations)
        }
    }

    @Suppress("ReturnCount")
    private fun place(
        sql: SqlExecutor,
        self: SelfContext,
        blob: PeekedBlob,
        candidates: List<ContactStore.ContactRow>,
        generations: List<OwnerStore.GenerationRow>,
    ): Ordered? {
        val ciphertext = blob.ciphertext
        return when (val match = recognition.match(sql, self, ciphertext, candidates)) {
            is RecognitionKeys.Match.Pair -> {
                val pinned = pinnedOf(sql, match.contactId) ?: return null
                val opened = envelopes.openPair(
                    namespace = self.inboxNamespace,
                    blob = ciphertext,
                    openEnv = match.openEnv,
                    contactId = match.contactId,
                    rootGen = match.rootGen,
                    week = match.week,
                    oiSender = pinned,
                    oiRecipient = self.olmIdentity,
                )
                symmetric(sql, match.contactId, opened, blob)
            }
            is RecognitionKeys.Match.Provisional -> {
                val pinned = pinnedOf(sql, match.contactId) ?: return null
                val opened = envelopes.openProvisional(
                    namespace = self.inboxNamespace,
                    blob = ciphertext,
                    openEnv = match.openEnv,
                    direction = match.direction,
                    sessionId = match.sessionId,
                    oiSender = pinned,
                    oiRecipient = self.olmIdentity,
                )
                symmetric(sql, match.contactId, opened, blob)
            }
            RecognitionKeys.Match.Intro -> intro(sql, self, blob, generations)
            null -> null
        }
    }

    private fun symmetric(
        sql: SqlExecutor,
        contactId: ByteArray,
        opened: DmSeal.OuterSymmetric,
        blob: PeekedBlob,
    ): Ordered? {
        if (opened !is DmSeal.OuterSymmetric.Ok) return null
        // A pair or provisional envelope names no session, so the chain is found by asking each
        // stored slot where that ratchet key stands. The slot that knows it owns the chain; when
        // neither does the message opens a new chain, whose next index is 0.
        var expected = 0L
        for (session in sessions.sessions(sql, contactId)) {
            val position = envelopes.chainPosition(
                contactId = contactId,
                slot = DmSessions.StoredSlot(session.sessionId, session.stateEnv),
                ratchetKey = opened.ratchetKey,
            )
            if (position is DmSessions.ChainPosition.Index) {
                expected = position.nextIndex
                break
            }
        }
        return Ordered(
            blob = blob,
            group = contactId.toList() + opened.ratchetKey.toList(),
            chainIndex = opened.chainIndex,
            expectedIndex = expected,
        )
    }

    /**
     * An intro envelope carries a PreKey message, whose **inner** chain index orders the first
     * flights of one session (§2.6 function 12 returns it for exactly this).
     *
     * Opening it costs one decapsulation per pass, which §7.7 point 1 spends deliberately: a
     * re-sent PreKey message of an unacknowledged session is the one case where several blobs of
     * one chain arrive with nothing else to order them by.
     */
    private fun intro(
        sql: SqlExecutor,
        self: SelfContext,
        blob: PeekedBlob,
        generations: List<OwnerStore.GenerationRow>,
    ): Ordered? {
        val outer = envelopes.openOuterIntro(self.cardIndex, self.inboxNamespace, blob.ciphertext)
        if (outer !is DmSeal.OuterIntro.Ok) return null
        val generation = generations.firstOrNull { it.genId == outer.genId.toLong() and U32 }
            ?: return null
        val opened = envelopes.openIntro(
            cardIndex = self.cardIndex,
            namespace = self.inboxNamespace,
            genId = outer.genId,
            genSecretsEnv = generation.secretsEnv,
            genFallbackPublic = generation.fallbackPublic,
            blob = blob.ciphertext,
        )
        if (opened !is DmSeal.OpenedIntro.Ok) return null
        val sessionId = opened.intro.sessionId
        var expected = 0L
        for ((contactId, session) in sessions.allSessions(sql)) {
            if (!session.sessionId.contentEquals(sessionId)) continue
            val position = envelopes.chainPosition(
                contactId = contactId,
                slot = DmSessions.StoredSlot(session.sessionId, session.stateEnv),
                ratchetKey = opened.intro.ratchetKey,
            )
            if (position is DmSessions.ChainPosition.Index) expected = position.nextIndex
            break
        }
        return Ordered(
            blob = blob,
            group = sessionId.toList(),
            chainIndex = opened.intro.chainIndex,
            expectedIndex = expected,
        )
    }

    private fun pinnedOf(sql: SqlExecutor, contactId: ByteArray): ByteArray? =
        contacts.contact(sql, contactId)?.pinnedIdentity

    private fun keyOf(blob: PeekedBlob): List<Byte> =
        blob.namespace.toByteArray().toList() + blob.hash.toByteArray().toList()

    companion object {
        /** §7.7 point 1: how many fetched rows one peek reads. */
        const val SORT_WINDOW: Int = 256

        /**
         * §7.7 point 2: the hold ends 12 minutes after a blob was first seen, whatever the gap.
         *
         * It delays display by at most that, measured at 10.6 minutes in HIGH and about two
         * minutes elsewhere (V-7), and held blobs count against `FETCHED_CAP`.
         */
        const val HOLD_MAX_SECONDS: Long = 12 * DmTime.MINUTE

        /** `gen_id` crosses as a signed `Int` and is stored as an unsigned `u32` (§13.6). */
        private const val U32 = 0xffff_ffffL
    }
}
