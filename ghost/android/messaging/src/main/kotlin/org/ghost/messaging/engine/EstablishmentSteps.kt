package org.ghost.messaging.engine

import org.ghost.crypto.bridge.CredentialV3
import org.ghost.crypto.bridge.DmSessions
import org.ghost.messaging.port.DmClock
import org.ghost.messaging.port.DmEnvelopes
import org.ghost.messaging.store.ContactStore
import org.ghost.messaging.store.MessageStore
import org.ghost.messaging.store.SessionStore
import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.CapabilitySource
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.SyncDatabase
import org.ghost.sync.api.SyncTransaction

/**
 * Establishment: `EST-START`, `EST-READY` and `EST-END` (Phase 9 design §5.5, §7.2, §21.7).
 *
 *  - **`EST-START`** runs from a **user send** that finds no usable session, and from the
 *    time-triggered pass that continues one — never from an inbound blob (T28). It forgets the
 *    bundle namespace's consumed tombstones (Phase 7 keeps them across `remove` and re-register,
 *    so a reset or a re-added contact could otherwise never see a bundle it consumed before,
 *    §21.7 point 2), registers `P_c` listening with `CapabilitySource.LOCAL`, installs the
 *    card-derived FETCH credentials, and opens a 15-minute attempt window.
 *  - **`EST-READY`** is **time-triggered** (§21.9 rule 1): two minutes after the first candidate,
 *    or at the window's end with a usable session. It pins the identity, stores the peer's X-Wing
 *    key and builds the initiator session; the pending items are flushed by [SendStep.flushPending]
 *    in the same pass.
 *  - **`EST-END`** closes a window that produced nothing: the next attempt starts at a relay
 *    session start at least six hours later, and after the third the contact is `unreachable` and
 *    its pending items fail (§21.7 point 5).
 *
 * **`BUNDLE` is deliberately not here.** It is the one establishment transaction driven directly
 * by an arriving blob, and gate G-DM2's allowlist is **by file**, on the stated argument that a
 * Kotlin file holds one step. Keeping `BUNDLE` in this file would have silently granted the
 * forbidden side of T28 the permission this file needs for the three steps above; it lives in
 * [BundleStep], which the gate does not allowlist, so §21.7 point 7 ("RECV, BUNDLE and HELD never
 * call `Outbox.enqueue`, `Namespaces.*`, `Registrations` or `Capabilities.put`") is enforced by
 * construction rather than by inspection.
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
    private val slots: SessionSlots = SessionSlots(),
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
     *
     * **[userRetry] is the `unreachable → fetching` edge of §13.5.** `fetch_attempts` bounds the
     * **automatic** continuation at three windows (§21.7 point 5, mutant PM-31), and it is never
     * reset outside `EST-READY` — so without this parameter a contact that failed three times is
     * absorbing: every later send stores a pending item, gets `UNCHANGED` here, and the message
     * expires at `fail_after_hour` with delete-and-re-add the only escape. §21.7 point 5 ends "the
     * user may retry" and §13.5 draws the edge; this is it. The reset is not a way round the
     * bound: it takes a new user action, which is exactly what T28 allows to cause a fetch.
     */
    fun estStart(contactId: ByteArray, userRetry: Boolean = false): Result {
        contexts.get() ?: return Result.CRYPTO_UNAVAILABLE
        val now = clock.nowEpochSeconds()
        val week = DmTime.week(now)

        val card = database.transaction { tx ->
            val contact = contacts.contact(tx.sql, contactId) ?: return@transaction null
            if (attemptsFor(contact, userRetry) >= MAX_FETCH_ATTEMPTS) return@transaction null
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
            val attempts = attemptsFor(contact, userRetry)
            if (attempts >= MAX_FETCH_ATTEMPTS) return@transaction Result.UNCHANGED
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
                fetchAttempts = attempts + 1,
                listenUntilMinute = DmTime.ceilMinute(now + FETCH_WINDOW_SECONDS),
            )
            Result.DONE
        }
    }

    /**
     * The attempt count this call starts from: zero when the user is retrying a contact the three
     * automatic windows already gave up on (§13.5's `unreachable → fetching`), and the stored one
     * otherwise.
     */
    private fun attemptsFor(contact: ContactStore.ContactRow, userRetry: Boolean): Int =
        if (userRetry && contact.establishment == ContactStore.Establishment.UNREACHABLE) {
            0
        } else {
            contact.fetchAttempts
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
     * **"Unless a *usable* session already exists" (§21.7 point 4) is a predicate, not a row
     * count.** The session this step may keep instead of building is one an inbound PreKey message
     * created (R-SS1): acknowledged, answering. A **stale** initiator session — `UNACK_MAX` days
     * unanswered, §8.7 — is precisely the session the user's send asked to replace, so keeping it
     * would make the establishment a no-op that runs again at every send: the candidate thrown
     * away, the pending items flushed onto the same dead session, the contact's `fetch_attempts`
     * reset, and the L7-D6 bound of "at most three session starts per establishment" turned into
     * three per send for ever (mutant PM-31). It is demoted under R-SS0 — the peer may still
     * answer it, so it receives on `previous` until its `retire_day` — and the candidate builds the
     * new `current`.
     *
     * The `NO_SEAL_KEY` half of R-SS0 is not decided here: it is decided where the output is, by
     * [SendStep], which demotes before asking for the establishment. This step only has to be sure
     * it is not fooled by a row.
     *
     * **Key change is slice S8's.** A bundle that verifies under the pinned Ed25519 key but names
     * another Olm identity is a key change (§5.5, §8.3): until S8 classifies and holds it, the
     * candidate is dropped, `reset_needed` is set and **no session is built**. Refusing is the
     * safe half of the rule; silently pinning the new identity would be mutant PM-16.
     */
    @Suppress("LongMethod")
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
            val usable = existing != null && !SessionSlots.isStale(existing, now)
            val candidate = contacts.bundleCandidate(tx.sql, contactId)
            // Nothing this step can finish with. A **usable** session and no candidate is the
            // other half of §21.7 point 4 — an inbound PreKey built the session (R-SS1) and the
            // window's end makes the contact `ready` — and it falls through below; an **unusable**
            // one and no candidate does not, because reporting `ready` with nothing that can send
            // is how the contact stops re-establishing. That case lets the window run its course,
            // and `EST-END` decides the next attempt.
            if (!usable && candidate == null) return@transaction Result.UNCHANGED

            failExpiredPending(tx, contactId, now)

            if (!usable && candidate != null) {
                val plain = self.content.open(candidate.bundleEnv, contactId)
                    ?: return@transaction Result.UNCHANGED
                val bundle = BundleCandidates.read(plain)
                if (!BundleCandidates.isValid(bundle.bundleWeek, week)) {
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
                    is DmSessions.Outbound.Ok -> {
                        // R-SS0: the stale session the send asked to replace goes to `previous`
                        // (the peer may still answer it) and its old `previous` is deleted. It
                        // happens **here**, once the replacement is known to exist, so a failed
                        // `sessionOutbound` above leaves the contact exactly as it was.
                        if (existing != null) {
                            slots.demoteForReestablishment(tx, contactId, DmTime.day(now))
                        }
                        sessions.insertSession(
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
                    }
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

    // ------------------------------------------------- the block / delete half

    /**
     * The `EST-END` half a **block** or a **delete** causes: the attempt window closes at once.
     *
     * §12.4 puts block and delete entirely in `ContactSteps`, and §12.4's table says both are
     * relay-visible: *nothing*. Without this, they were not: `block` sets `establishment =
     * 'card_only'` and `deleteContact` removes the row, and the actor only ever visits contacts
     * whose establishment is `fetching` — so a block thirty seconds after the first send to a new
     * contact left `P_c` **listening**, with its 8-day READ credentials installed, and this device
     * kept issuing `list` and `get` against the blocked contact's bundle namespace indefinitely.
     * That is the opposite of §12.4's promise and it breaks the L7-D6 bound of "a listening `P_c`
     * co-occurs with at most three session starts per establishment" in the direction mutant
     * PM-31 names (unbounded attempts).
     *
     * **Why the call lives here and not in `ContactSteps`.** `Namespaces.setListening` is one of
     * the calls gate G-DM2 confines to the steps of §7.2, and `ContactSteps` is deliberately not on
     * that allowlist (its own header says it must not become so). Closing a fetch window *is* an
     * establishment step — it is `EST-END`'s own first line — so it belongs in this file, and
     * `ContactSteps` asks for it in the transaction it is already writing.
     *
     * `Namespaces.remove` is **not** called: §21.12 point 3 gives that to SWEEP, once the
     * contact's ops are released, and the `dm_orphan_namespace` row `ContactSteps` writes is what
     * carries it there.
     */
    fun abandonFetch(tx: SyncTransaction, contact: ContactStore.ContactRow) {
        if (contact.establishment != ContactStore.Establishment.FETCHING) return
        val card = material.card(contact) ?: return
        val namespaces = material.namespaces(card) ?: return
        sync.namespaces.setListening(tx, NamespaceId(namespaces.bundle), false)
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
        messages.failPending(tx, itemId)
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

        /**
         * `dm_message.state` and `dm_outbound_item.state` for an item that will not be stored.
         * The three writes it takes live in [MessageStore.failPending], because every caller owes
         * all three.
         */
        const val STATE_FAILED: String = MessageStore.STATE_FAILED
    }
}
