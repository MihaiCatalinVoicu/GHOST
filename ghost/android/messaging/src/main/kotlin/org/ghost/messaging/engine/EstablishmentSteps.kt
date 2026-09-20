package org.ghost.messaging.engine

import org.ghost.crypto.bridge.CredentialV3
import org.ghost.crypto.bridge.DmBundles
import org.ghost.crypto.bridge.DmSessions
import org.ghost.messaging.port.DmClock
import org.ghost.messaging.port.DmEnvelopes
import org.ghost.messaging.store.ContactStore
import org.ghost.messaging.store.ContentCipher
import org.ghost.messaging.store.MessageStore
import org.ghost.messaging.store.SessionStore
import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.CapabilitySource
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.SyncDatabase
import org.ghost.sync.api.SyncTransaction
import java.security.MessageDigest

/**
 * Establishment: `EST-START`, `BUNDLE`, `EST-READY` and `EST-END` (Phase 9 design §5.5, §7.2,
 * §21.7).
 *
 *  - **`EST-START`** runs from a **user send** that finds no usable session, and from the
 *    time-triggered pass that continues one — never from an inbound blob (T28). It forgets the
 *    bundle namespace's consumed tombstones (Phase 7 keeps them across `remove` and re-register,
 *    so a reset or a re-added contact could otherwise never see a bundle it consumed before,
 *    §21.7 point 2), registers `P_c` listening with `CapabilitySource.LOCAL`, installs the
 *    card-derived FETCH credentials, and opens a 15-minute attempt window.
 *  - **`BUNDLE`** consumes one fetched bundle blob and keeps the **best verified candidate**, and
 *    nothing else. It never enqueues, registers or starts a session — that is `EST-READY`'s, and
 *    it is what keeps the static half of T28 true on the consumer path (gate G-DM2).
 *  - **`EST-READY`** is **time-triggered** (§21.9 rule 1): two minutes after the first candidate,
 *    or at the window's end with a usable session. It pins the identity, stores the peer's X-Wing
 *    key and builds the initiator session; the pending items are flushed by [SendStep.flushPending]
 *    in the same pass.
 *  - **`EST-END`** closes a window that produced nothing: the next attempt starts at a relay
 *    session start at least six hours later, and after the third the contact is `unreachable` and
 *    its pending items fail (§21.7 point 5).
 *
 * **Why the window and the wait share one column.** `dm_contact.fetch_listen_until_minute` is the
 * next decision minute, and its CHECK ties it to `establishment = 'fetching'`; the bit that says
 * whether the window is **open** is `P_c`'s listening flag, read back through
 * `Namespaces.listening`. A copy in memory would be lost at every restart and would turn a
 * mid-window restart into either a lost attempt or an endless deferral.
 */
internal class EstablishmentSteps(
    private val database: SyncDatabase,
    private val sync: DmSyncPorts,
    private val envelopes: DmEnvelopes,
    private val material: ContactMaterial,
    private val relays: RelaySetResolver,
    private val clock: DmClock,
    private val contexts: SelfContexts,
) {
    private val contacts = ContactStore()
    private val messages = MessageStore()
    private val sessions = SessionStore()

    /** What a step did; counts and enums only (T3). */
    enum class Result {
        /** The step ran and changed something. */
        DONE,

        /** Its guard held: nothing to do, nothing written. */
        UNCHANGED,

        /** The DM context is closed or the native library is missing. */
        CRYPTO_UNAVAILABLE,

        /** This week's ES slot table yields no relay set (§5.2). */
        NO_RELAYS,
    }

    // -------------------------------------------------------------- EST-START

    /**
     * Opens an attempt window for [contactId] (§21.7 point 2).
     *
     * Every credential is minted **before** the transaction opens, for the reason KEEPER does the
     * same (§7.2's "each step is exactly one transaction", §22.11 item 17): a `CRYPTO_UNAVAILABLE`
     * decided inside it would be a normal return, and a normal return commits what the earlier
     * loop iterations already wrote while reporting an error.
     */
    fun estStart(contactId: ByteArray): Result {
        contexts.get() ?: return Result.CRYPTO_UNAVAILABLE
        val now = clock.nowEpochSeconds()
        val week = DmTime.week(now)

        val card = database.transaction { tx ->
            val contact = contacts.contact(tx.sql, contactId) ?: return@transaction null
            if (contact.fetchAttempts >= MAX_FETCH_ATTEMPTS) return@transaction null
            material.card(contact)
        } ?: return Result.UNCHANGED
        val namespaces = material.namespaces(card) ?: return Result.CRYPTO_UNAVAILABLE
        val set = relays.forNamespace(namespaces.bundle, week) ?: return Result.NO_RELAYS

        val credentials = LinkedHashMap<Long, ByteArray>()
        for (slot in set) {
            val derived = material.fromCard(card, slot.slot) ?: return Result.CRYPTO_UNAVAILABLE
            credentials[slot.relay.value] = try {
                CredentialV3.credential(
                    CredentialV3.Kind.FETCH,
                    slot.slot,
                    namespaces.bundle,
                    derived.fetch,
                )
            } finally {
                derived.clearSecrets()
            }
        }

        return database.transaction { tx ->
            val contact = contacts.contact(tx.sql, contactId) ?: return@transaction Result.UNCHANGED
            if (contact.fetchAttempts >= MAX_FETCH_ATTEMPTS) return@transaction Result.UNCHANGED
            val bundleNs = NamespaceId(namespaces.bundle)
            // §21.7 point 2 writes the forget **before** the register; the order here is the other
            // way round because `Inbox.forgetConsumed` refuses a namespace that is not registered
            // at all, which `P_c` is not before the first establishment. Inside one transaction
            // the outcome is the same — the register reuses the row and keeps its tombstones, and
            // the forget then deletes them — and nothing can fetch in between, which is the whole
            // point of the rule ("a bundle consumed during an earlier establishment must be
            // fetchable again after a reset, a key change or a re-added contact").
            sync.namespaces.register(
                tx = tx,
                namespace = bundleNs,
                consumer = Consumer.PREKEYS,
                relays = set.map { it.relay }.toSet(),
                listen = true,
                capabilitySource = CapabilitySource.LOCAL,
            )
            sync.inbox.forgetConsumed(tx, bundleNs)
            for (slot in set) {
                sync.capabilities.put(
                    tx,
                    slot.relay,
                    bundleNs,
                    CapabilityKind.READ,
                    credentials.getValue(slot.relay.value),
                    DmTime.ceilHour(now) + FETCH_CREDENTIAL_LIFETIME_SECONDS,
                )
            }
            contacts.setEstablishment(
                tx = tx,
                contactId = contactId,
                establishment = ContactStore.Establishment.FETCHING,
                fetchAttempts = contact.fetchAttempts + 1,
                listenUntilMinute = DmTime.ceilMinute(now + FETCH_WINDOW_SECONDS),
            )
            Result.DONE
        }
    }

    // ----------------------------------------------------------------- BUNDLE

    /**
     * `BUNDLE` (§21.7 point 3): one consumed bundle blob, opened and verified, and the better
     * candidate kept. Runs inside the caller's transaction, beside `markConsumed`.
     *
     * Everything a clock decides stays here rather than in the crate: validity
     * (`now < start(bundle_week + 2)` and `bundle_week ≤ week(now) + 1`, §5.4) and the
     * `(bundle_week, bundle_rank)` rollback rule against `dm_contact.bundle_week_seen` — relays
     * cannot delete old bundles and at most five are live, so a replayed older one must not
     * replace a newer (mutant PM-22).
     *
     * **It enqueues nothing and registers nothing** (T28's static half, gate G-DM2).
     */
    fun bundle(tx: SyncTransaction, contactId: ByteArray, blob: ByteArray): Boolean {
        val self = contexts.get() ?: return false
        val contact = contacts.contact(tx.sql, contactId) ?: return false
        val card = material.card(contact) ?: return false
        val derived = material.fromCard(card, ANY_SLOT) ?: return false
        return try {
            val opened = envelopes.openBundle(
                bundleKeyEnv = derived.bundleKeyEnv,
                bundleNamespace = derived.bundleNamespace,
                blob = blob,
                expectedIdentityPk = contact.identityPk,
                expectedCardIndex = contact.cardIndex,
            )
            if (opened !is DmBundles.OpenResult.Ok) return false
            val verified = opened.bundle
            if (!isValid(verified.bundleWeek, DmTime.week(clock.nowEpochSeconds()))) return false
            val seen = contact.bundleWeekSeen
            if (seen != null && verified.bundleWeek < seen) return false
            contacts.putBundleCandidate(
                tx = tx,
                contactId = contactId,
                bundleEnv = self.content.seal(
                    nonce = candidateNonce(contactId, verified),
                    associatedData = contactId,
                    plaintext = candidatePlain(verified),
                ),
                bundleWeek = verified.bundleWeek,
                bundleRank = verified.bundleRank,
            )
            contacts.setBundleWeekSeen(tx, contactId, verified.bundleWeek)
            true
        } finally {
            derived.clearSecrets()
        }
    }

    // -------------------------------------------------------------- EST-READY

    /**
     * `EST-READY` (§21.7 point 4), time-triggered.
     *
     * The pin happens **before** `sessionOutbound`, so §8.2 rule 2 ("`sessionOutbound` is called
     * only with the pinned `OI`") holds by construction rather than by a check; a pending item
     * whose deadline is within a minute fails here rather than being sealed into an op that can
     * never be stored (R-T5).
     *
     * **Key change is slice S8's.** A bundle that verifies under the pinned Ed25519 key but names
     * another Olm identity is a key change (§5.5, §8.3): until S8 classifies and holds it, the
     * candidate is dropped, `reset_needed` is set and **no session is built**. Refusing is the
     * safe half of the rule; silently pinning the new identity would be mutant PM-16.
     */
    fun estReady(contactId: ByteArray): Result {
        val self = contexts.get() ?: return Result.CRYPTO_UNAVAILABLE
        val now = clock.nowEpochSeconds()
        val today = DmTime.day(now).toInt()
        val week = DmTime.week(now)

        return database.transaction { tx ->
            val contact = contacts.contact(tx.sql, contactId) ?: return@transaction Result.UNCHANGED
            if (contact.establishment != ContactStore.Establishment.FETCHING) {
                return@transaction Result.UNCHANGED
            }
            if (contact.trust != ContactStore.Trust.UNVERIFIED &&
                contact.trust != ContactStore.Trust.VERIFIED
            ) {
                // Keep the pending items and the candidate, and stop: a `changed` contact's
                // decision is the user's (§8.3), and a `request` has not been accepted (§12.3).
                return@transaction Result.UNCHANGED
            }
            val card = material.card(contact) ?: return@transaction Result.UNCHANGED
            val namespaces = material.namespaces(card) ?: return@transaction Result.UNCHANGED
            val existing = sessions.current(tx.sql, contactId)
            val candidate = contacts.bundleCandidate(tx.sql, contactId)
            if (existing == null && candidate == null) return@transaction Result.UNCHANGED

            failExpiredPending(tx, contactId, now)

            if (existing == null && candidate != null) {
                val plain = self.content.open(candidate.bundleEnv, contactId)
                    ?: return@transaction Result.UNCHANGED
                val bundle = readCandidate(plain)
                if (!isValid(bundle.bundleWeek, week)) {
                    contacts.deleteBundleCandidate(tx, contactId)
                    return@transaction Result.UNCHANGED
                }
                val pinned = contact.pinnedIdentity
                if (pinned == null) {
                    contacts.pinIdentity(tx, contactId, bundle.olmIdentity)
                } else if (!pinned.contentEquals(bundle.olmIdentity)) {
                    contacts.deleteBundleCandidate(tx, contactId)
                    contacts.setResetNeeded(tx, contactId, true)
                    return@transaction Result.UNCHANGED
                }
                contacts.putPeerPq(
                    tx = tx,
                    contactId = contactId,
                    genId = bundle.genId,
                    bundleWeek = bundle.bundleWeek,
                    source = ContactStore.PQ_SOURCE_BUNDLE,
                    xwingPublic = bundle.xwingPublic,
                )
                when (
                    val outbound = envelopes.outbound(
                        contactId = contactId,
                        peerOlmIdentity = bundle.olmIdentity,
                        peerFallbackKey = bundle.fallbackKey,
                        today = today,
                    )
                ) {
                    is DmSessions.Outbound.Ok -> sessions.insertSession(
                        tx = tx,
                        contactId = contactId,
                        slot = SessionStore.SLOT_CURRENT,
                        sessionId = outbound.sessionId,
                        initiator = true,
                        acknowledged = false,
                        stateEnv = outbound.stateEnv,
                        provEnv = outbound.replySeedEnv,
                        peerGenId = bundle.genId,
                        unackSinceDay = DmTime.day(now),
                        retireDay = null,
                        peerBindMinute = null,
                    )
                    // §21.7 point 4: drop the candidate, count, and let the attempt continue —
                    // the contact published a key no session can be built on (§22.8.2 rule 1).
                    DmSessions.Outbound.InvalidKey,
                    DmSessions.Outbound.StateCorrupt,
                    -> {
                        contacts.deleteBundleCandidate(tx, contactId)
                        return@transaction Result.UNCHANGED
                    }
                    DmSessions.Outbound.Unavailable -> return@transaction Result.CRYPTO_UNAVAILABLE
                }
            }

            contacts.deleteBundleCandidate(tx, contactId)
            contacts.setEstablishment(
                tx = tx,
                contactId = contactId,
                establishment = ContactStore.Establishment.READY,
                fetchAttempts = 0,
                listenUntilMinute = null,
            )
            sync.namespaces.setListening(tx, NamespaceId(namespaces.bundle), false)
            Result.DONE
        }
    }

    // ---------------------------------------------------------------- EST-END

    /**
     * `EST-END` (§21.7 point 5), time-triggered at the end of an attempt window that produced no
     * candidate and found no usable session.
     *
     * The window closes, and the contact either waits for its next attempt — at least six hours,
     * the spacing L7-D6 declares — or, after the third, becomes `unreachable` and its pending
     * items fail. The user may retry, which is another [estStart].
     */
    fun estEnd(contactId: ByteArray): Result {
        val now = clock.nowEpochSeconds()
        return database.transaction { tx ->
            val contact = contacts.contact(tx.sql, contactId) ?: return@transaction Result.UNCHANGED
            if (contact.establishment != ContactStore.Establishment.FETCHING) {
                return@transaction Result.UNCHANGED
            }
            val card = material.card(contact) ?: return@transaction Result.UNCHANGED
            val namespaces = material.namespaces(card) ?: return@transaction Result.UNCHANGED
            val bundleNs = NamespaceId(namespaces.bundle)
            sync.namespaces.setListening(tx, bundleNs, false)
            if (contact.fetchAttempts < MAX_FETCH_ATTEMPTS) {
                contacts.setEstablishment(
                    tx = tx,
                    contactId = contactId,
                    establishment = ContactStore.Establishment.FETCHING,
                    fetchAttempts = contact.fetchAttempts,
                    listenUntilMinute = DmTime.ceilMinute(now + NEXT_ATTEMPT_SECONDS),
                )
                return@transaction Result.DONE
            }
            for (pending in messages.pendingSends(tx.sql, contactId)) failPending(tx, pending.itemId)
            contacts.setEstablishment(
                tx = tx,
                contactId = contactId,
                establishment = ContactStore.Establishment.UNREACHABLE,
                fetchAttempts = contact.fetchAttempts,
                listenUntilMinute = null,
            )
            // §21.7 point 5: the namespace goes once nothing is fetched for it any more. `remove`
            // answers false while a fetched row is left, and SWEEP retries it (slice S9).
            sync.namespaces.remove(tx, bundleNs)
            Result.DONE
        }
    }

    /**
     * Which of the two time-triggered steps a `fetching` contact is due for (§21.9 rule 1).
     *
     * The decision minute is `dm_contact.fetch_listen_until_minute`, and the listening flag of
     * `P_c` says whether the window is open: an open window that has run out is `EST-END`'s, and
     * a closed one whose wait has run out is the next attempt's `EST-START`.
     */
    fun dueStep(tx: SyncTransaction, contact: ContactStore.ContactRow, now: Long): Due {
        val until = contact.fetchListenUntilMinute ?: return Due.NONE
        if (now < until) return Due.NONE
        val card = material.card(contact) ?: return Due.NONE
        val namespaces = material.namespaces(card) ?: return Due.NONE
        val listening = sync.namespaces.listening(tx, NamespaceId(namespaces.bundle)) ?: false
        return if (listening) Due.END else Due.START
    }

    /** What [dueStep] found. */
    enum class Due {
        /** Nothing is due for this contact. */
        NONE,

        /** The attempt window has ended: [estEnd]. */
        END,

        /** The wait between attempts has ended: [estStart]. */
        START,
    }

    // --------------------------------------------------------------- internals

    /** The six fields a candidate row carries (§13.6's one `bundle_env`). */
    class Candidate(
        val bundleWeek: Long,
        val bundleRank: Int,
        val genId: Int,
        val olmIdentity: ByteArray,
        val fallbackKey: ByteArray,
        val xwingPublic: ByteArray,
    ) {
        override fun toString(): String = "Candidate(week=$bundleWeek, rank=$bundleRank)"
    }

    /**
     * §5.4 "Validity": a bundle of week `w` is valid while `now < start(w + 2)` and
     * `w ≤ week(now) + 1`. Both need a clock, which is why neither is in the crate.
     */
    private fun isValid(bundleWeek: Long, currentWeek: Long): Boolean =
        bundleWeek + 2 > currentWeek && bundleWeek <= currentWeek + 1

    private fun failExpiredPending(tx: SyncTransaction, contactId: ByteArray, now: Long) {
        for (pending in messages.pendingSends(tx.sql, contactId)) {
            if (pending.failAfterHour > now + DmTime.MINUTE) continue
            failPending(tx, pending.itemId)
        }
    }

    private fun failPending(tx: SyncTransaction, itemId: ByteArray) {
        messages.deletePendingSend(tx, itemId)
        messages.setItemState(tx, itemId, MessageStore.ITEM_PENDING, STATE_FAILED)
        messages.setMessageState(tx, itemId, MessageStore.STATE_QUEUED, STATE_FAILED)
    }

    /**
     * The candidate plaintext: the six fields, then zeros to the 1 393 bytes the schema fixes
     * `bundle_env` at (1 421 = 1 393 + the content key's 28 bytes of overhead, §13.6).
     *
     * Padding to the sealed bundle's own length rather than to the fields' length is deliberate:
     * the column's CHECK is the one place a wrong layout shows up as a constraint failure instead
     * of as a silently short read, and a fixed length also means the row says nothing about which
     * fields it carries (T33).
     */
    private fun candidatePlain(bundle: DmBundles.Verified): ByteArray {
        val out = ByteArray(CANDIDATE_PLAIN_BYTES)
        writeLong(out, 0, bundle.bundleWeek)
        writeInt(out, 8, bundle.bundleRank)
        writeInt(out, 12, bundle.genId)
        bundle.olmIdentity.copyInto(out, 16)
        bundle.fallbackKey.copyInto(out, 48)
        bundle.xwingPublic.copyInto(out, 80)
        return out
    }

    private fun readCandidate(plain: ByteArray): Candidate {
        check(plain.size == CANDIDATE_PLAIN_BYTES) { "a bundle candidate has the wrong length" }
        return Candidate(
            bundleWeek = readLong(plain, 0),
            bundleRank = readInt(plain, 8),
            genId = readInt(plain, 12),
            olmIdentity = plain.copyOfRange(16, 48),
            fallbackKey = plain.copyOfRange(48, 80),
            xwingPublic = plain.copyOfRange(80, 80 + XWING_PUBLIC_BYTES),
        )
    }

    /**
     * The nonce of a candidate envelope, derived from the bundle rather than drawn.
     *
     * Consuming the **same** bundle twice — a rolled-back `BUNDLE` sees its blob again (§7.8) —
     * then produces the same bytes, so the UPDATE-then-INSERT of `putBundleCandidate` is
     * idempotent and a re-offer cannot leave two candidates that differ only in a nonce.
     */
    private fun candidateNonce(contactId: ByteArray, bundle: DmBundles.Verified): ByteArray {
        val week = ByteArray(8)
        writeLong(week, 0, bundle.bundleWeek)
        return MessageDigest.getInstance("SHA-256").apply {
            update(contactId)
            update(bundle.olmIdentity)
            update(bundle.fallbackKey)
            update(week)
        }.digest().copyOf(ContentCipher.NONCE_BYTES)
    }

    private fun writeLong(out: ByteArray, at: Int, value: Long) {
        for (i in 0 until 8) out[at + i] = ((value shr (8 * (7 - i))) and 0xff).toByte()
    }

    private fun readLong(bytes: ByteArray, at: Int): Long {
        var value = 0L
        for (i in 0 until 8) value = (value shl 8) or (bytes[at + i].toLong() and 0xff)
        return value
    }

    private fun writeInt(out: ByteArray, at: Int, value: Int) {
        for (i in 0 until 4) out[at + i] = ((value shr (8 * (3 - i))) and 0xff).toByte()
    }

    private fun readInt(bytes: ByteArray, at: Int): Int {
        var value = 0
        for (i in 0 until 4) value = (value shl 8) or (bytes[at + i].toInt() and 0xff)
        return value
    }

    companion object {
        /** §21.7 point 5: at most three 15-minute attempts per establishment. */
        const val MAX_FETCH_ATTEMPTS: Int = 3

        /** The attempt window (§21.7 point 2). */
        const val FETCH_WINDOW_SECONDS: Long = 15 * DmTime.MINUTE

        /** The spacing between attempts (§21.7 point 5), which L7-D6 declares. */
        const val NEXT_ATTEMPT_SECONDS: Long = 6 * DmTime.HOUR

        /** `EST-READY` runs two minutes after the first candidate (§21.7 point 4). */
        const val READY_DELAY_SECONDS: Long = 2 * DmTime.MINUTE

        /** The FETCH credential's lifetime, as KEEPER gives the owner's READ one (§4.8). */
        const val FETCH_CREDENTIAL_LIFETIME_SECONDS: Long = 8 * DmTime.DAY

        /** `dm_message.state` and `dm_outbound_item.state` for an item that will not be stored. */
        const val STATE_FAILED: String = "failed"

        /**
         * The namespaces a card derives are slot-independent (§21.2 point 1): only the bearer
         * secrets carry the slot, so any slot answers a question about `X_c` or `P_c`.
         */
        private const val ANY_SLOT: Int = 0

        /** An X-Wing encapsulation key (§5.3). */
        private const val XWING_PUBLIC_BYTES: Int = 1216

        /** `dm_bundle_candidate.bundle_env` is 1 421 bytes: 1 393 of plaintext plus 28 (§13.6). */
        private const val CANDIDATE_PLAIN_BYTES: Int = 1393
    }
}
