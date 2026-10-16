package org.ghost.messaging.engine

import org.ghost.crypto.bridge.DmCards
import org.ghost.crypto.bridge.DmContent
import org.ghost.crypto.bridge.DmPairing
import org.ghost.crypto.bridge.DmRevocations
import org.ghost.crypto.bridge.DmSeal
import org.ghost.crypto.bridge.DmSessions
import org.ghost.messaging.port.DmClock
import org.ghost.messaging.port.DmCrypto
import org.ghost.messaging.port.DmEnvelopes
import org.ghost.messaging.port.DmRandom
import org.ghost.messaging.store.ContactStore
import org.ghost.messaging.store.ContentCipher
import org.ghost.messaging.store.HeldStore
import org.ghost.messaging.store.MessageStore
import org.ghost.messaging.store.OwnerStore
import org.ghost.messaging.store.SessionStore
import org.ghost.sync.api.BlobHash
import org.ghost.sync.api.InboundBlob
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.SyncDatabase
import org.ghost.sync.api.SyncTransaction
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * **RECV** (Phase 9 design §7.4, §6.5), one blob per transaction.
 *
 * The steps are R1 … R12 as the design numbers them, and the two properties they exist for are:
 *
 *  - **R-P1 (commit together).** `markConsumed`, the session state, the reuse tuple, `dm_seen`,
 *    the message row and the contact changes commit in **one** transaction. A crash anywhere
 *    re-offers the blob against rolled-back state, so a second attempt decrypts the same way (the
 *    stored session envelope is unchanged, §7.9).
 *  - **R-P2 (drop is final and silent).** A `drop` is `markConsumed` plus one in-memory counter,
 *    and nothing else: no outbound blob, no redemption, no registration, no read-schedule change
 *    and no `Inbox.defer` (T28). The only kept data are a request (§12.3), bounded at 64.
 *
 * **What this file may not do**, and what gate G-DM2 checks by reading it: `Outbox.enqueue`,
 * `Registrations.*`, `Namespaces.*` and `Capabilities.put` do not appear here. A pending send is
 * flushed by the **time-triggered** `EST-READY` (§21.7), never by the arrival of a blob.
 *
 * **Key change (§8.3), since S8.** An intro PreKey message that names an Olm identity other than
 * the pinned one, **under a binding valid by the contact's own Ed25519 key**, is a key change: the
 * ciphertext is held undecrypted in `dm_held`, the contact moves to `changed`, and nothing is
 * shown and nothing is sent until the user acknowledges, verifies or blocks (CS-5, T28). The
 * binding is what separates a key change from a forgery (E-1): anyone holding the contact's card
 * can build an intro envelope naming it, and nobody without its Ed25519 secret can sign a binding
 * for a second Olm identity — so `IDENTITY_MISMATCH` alone is never a key change, and a binding
 * that does not verify never reaches here at all (`openIntro` refuses it).
 *
 * [replayHeld] is the other half: after the user decides, `HELD` (§22.8.1) runs R7 … R12 on each
 * stored L1 through **this** code, which is what "exactly RECV's R7 dispatch" means.
 */
internal class ReceiveStep(
    private val database: SyncDatabase,
    private val sync: DmSyncPorts,
    private val envelopes: DmEnvelopes,
    private val crypto: DmCrypto,
    private val material: ContactMaterial,
    private val recognition: RecognitionKeys,
    private val slots: SessionSlots,
    private val clock: DmClock,
    private val random: DmRandom,
    private val contexts: SelfContexts,
    private val counters: DmCounters,
    /**
     * R9, `accept_after_minute` and binding B1 ([ContentFreshness]). Production never names it and
     * runs [ContentFreshness.RULE]; the crash worlds install mutant MC-9 here (design §22.38).
     */
    private val freshness: ContentFreshness = ContentFreshness.RULE,
) {
    private val contacts = ContactStore()
    private val messages = MessageStore()
    private val sessions = SessionStore()
    private val owner = OwnerStore()
    private val heldRows = HeldStore()
    private val expiry = ExpiryClock(database, clock)

    /** §7.2's descriptor half: the media object an incoming kind-5 L0 names, created in RECV's transaction. */
    private val mediaFragments = org.ghost.media.store.MediaFragments()
    private val mediaObjects = org.ghost.media.store.MediaObjects(mediaFragments)

    /** What one blob did. Counts only ever leave through [DmCounters] (T33). */
    enum class Result {
        /** A message row, a reaction or a contact event was applied. */
        APPLIED,

        /** The blob was consumed and dropped: a counter moved and nothing else (R-P2). */
        DROPPED,

        /** The blob was consumed unprocessed after three process deaths on it (R2, §7.8). */
        POISONED,

        /** The DM context is closed: the actor claims no more blobs (§21.12 point 1). */
        CRYPTO_UNAVAILABLE,
    }

    /**
     * One claimed blob, R1 … R12.
     *
     * [blob] came from `Inbox.claimOne`, which committed its offer counter before the hand-off,
     * so a native crash inside this transaction is counted against the poison guard even though
     * the transaction rolled back (§7.8).
     */
    @Suppress("ReturnCount")
    fun receive(blob: InboundBlob): Result {
        val self = contexts.get() ?: return Result.CRYPTO_UNAVAILABLE
        val now = clock.nowEpochSeconds()
        return database.transaction { tx ->
            // R1: exactly once per (namespace, hash), whatever the outcome below.
            if (!sync.inbox.markConsumed(tx, blob.namespace, blob.hash)) {
                return@transaction Result.DROPPED
            }
            // R2: three earlier offers died unconsumed, so this one is consumed unprocessed —
            // no crash loop, and a double crash during recovery still processes a blob at its
            // third offer (G-1).
            if (blob.offers >= POISON_OFFERS) {
                counters.poisoned()
                return@transaction Result.POISONED
            }
            // R3: an own inbox, and nothing else. A blob of another namespace is a relay that
            // copied it (binding B1 would refuse it anyway, R-S3).
            if (!isOwnInbox(tx, blob.namespace)) {
                counters.drop(DmCounters.Reason.FOREIGN_NS)
                return@transaction Result.DROPPED
            }
            val ciphertext = blob.ciphertext
            if (ciphertext.size !in BUCKETS) {
                counters.drop(DmCounters.Reason.NON_CANONICAL)
                return@transaction Result.DROPPED
            }
            // R4: at most **one** AEAD attempt, chosen by the recognition hint (rule R-S5).
            val match = recognition.match(tx.sql, self, ciphertext)
            if (match == null) {
                counters.drop(DmCounters.Reason.UNKNOWN_SEAL)
                return@transaction Result.DROPPED
            }
            when (match) {
                is RecognitionKeys.Match.Pair ->
                    symmetric(tx, self, blob, ciphertext, match, now)
                is RecognitionKeys.Match.Provisional ->
                    symmetric(tx, self, blob, ciphertext, match, now)
                RecognitionKeys.Match.Intro -> intro(tx, self, blob, ciphertext, now)
            }
        }
    }

    // ----------------------------------------------------------- pair and provisional

    /**
     * §6.5 step 5: a pair or provisional envelope. The contact is the matched key's, and the
     * session identity was fixed at creation, so R6 is not needed; a PreKey L1 in either mode is
     * `drop(non_canonical)`, which the crate's symmetric body parser already refuses.
     */
    @Suppress("ReturnCount")
    private fun symmetric(
        tx: SyncTransaction,
        self: SelfContext,
        blob: InboundBlob,
        ciphertext: ByteArray,
        match: RecognitionKeys.Match,
        now: Long,
    ): Result {
        val contactId: ByteArray
        val opened: DmSeal.OuterSymmetric
        val pairWeek: Long?
        val pairRootGen: Int?
        val contact: ContactStore.ContactRow
        when (match) {
            is RecognitionKeys.Match.Pair -> {
                contactId = match.contactId
                contact = contacts.contact(tx.sql, contactId) ?: return dropped(DmCounters.Reason.UNKNOWN_SEAL)
                val pinned = contact.pinnedIdentity ?: return dropped(DmCounters.Reason.UNKNOWN_SEAL)
                opened = envelopes.openPair(
                    namespace = self.inboxNamespace,
                    blob = ciphertext,
                    openEnv = match.openEnv,
                    contactId = contactId,
                    rootGen = match.rootGen,
                    week = match.week,
                    oiSender = pinned,
                    oiRecipient = self.olmIdentity,
                )
                pairWeek = match.week
                pairRootGen = match.rootGen
            }
            is RecognitionKeys.Match.Provisional -> {
                contactId = match.contactId
                contact = contacts.contact(tx.sql, contactId) ?: return dropped(DmCounters.Reason.UNKNOWN_SEAL)
                val pinned = contact.pinnedIdentity ?: return dropped(DmCounters.Reason.UNKNOWN_SEAL)
                opened = envelopes.openProvisional(
                    namespace = self.inboxNamespace,
                    blob = ciphertext,
                    openEnv = match.openEnv,
                    direction = match.direction,
                    sessionId = match.sessionId,
                    oiSender = pinned,
                    oiRecipient = self.olmIdentity,
                )
                pairWeek = null
                pairRootGen = null
            }
            RecognitionKeys.Match.Intro -> throw IllegalStateException("intro is not symmetric")
        }
        val symmetric = when (opened) {
            is DmSeal.OuterSymmetric.Ok -> opened
            DmSeal.OuterSymmetric.Unavailable -> return Result.CRYPTO_UNAVAILABLE
            // A hint match whose AEAD fails is a forgery (rule R-S5): dropped, counted, and
            // **not** retried under another key.
            DmSeal.OuterSymmetric.NotOpen -> return dropped(DmCounters.Reason.NOT_OPEN)
            DmSeal.OuterSymmetric.NonCanonical -> return dropped(DmCounters.Reason.NON_CANONICAL)
            DmSeal.OuterSymmetric.StateCorrupt -> return dropped(DmCounters.Reason.STATE_CORRUPT)
        }
        // R5: blocked and revoked contacts are dropped before any session call (§7.4).
        if (contact.trust == ContactStore.Trust.BLOCKED ||
            contact.trust == ContactStore.Trust.REVOKED
        ) {
            return dropped(DmCounters.Reason.BLOCKED)
        }
        return decryptAndApply(
            tx = tx,
            self = self,
            relayExpiryHour = blob.relayExpiryHour,
            arrivalSeconds = now,
            contact = contact,
            l1 = symmetric.l1,
            isPreKey = false,
            now = now,
            pairWeek = pairWeek,
            pairRootGen = pairRootGen,
            bindingSeconds = null,
            intro = null,
        )
    }

    // ------------------------------------------------------------------- intro

    /**
     * §6.5 step 4 and §7.4 R4 … R6: an intro envelope.
     *
     * The generation named by `gen_id` must still exist (`drop(unknown_generation)` before any
     * state change, which is what keeps a replay of an erased generation from reaching the
     * request path at all, §21.4 point 4), the inner layer must open under the X-Wing key,
     * binding v3 must verify, and the three equalities of §6.5 step 4 must hold — all inside the
     * crate. What is left for here is what needs a clock or a row: the binding's **freshness**,
     * the card, the request path and the identity pre-check.
     */
    @Suppress("ReturnCount", "LongMethod")
    private fun intro(
        tx: SyncTransaction,
        self: SelfContext,
        blob: InboundBlob,
        ciphertext: ByteArray,
        now: Long,
    ): Result {
        val outer = envelopes.openOuterIntro(self.cardIndex, self.inboxNamespace, ciphertext)
        val genId = when (outer) {
            is DmSeal.OuterIntro.Ok -> outer.genId
            DmSeal.OuterIntro.Unavailable -> return Result.CRYPTO_UNAVAILABLE
            DmSeal.OuterIntro.NotOpen -> return dropped(DmCounters.Reason.NOT_OPEN)
            DmSeal.OuterIntro.NonCanonical -> return dropped(DmCounters.Reason.NON_CANONICAL)
            DmSeal.OuterIntro.StateCorrupt -> return dropped(DmCounters.Reason.STATE_CORRUPT)
        }
        val generation = owner.generations(tx.sql).firstOrNull { it.genId == genId.toLong() and U32 }
            ?: return dropped(DmCounters.Reason.UNKNOWN_GENERATION)
        val opened = envelopes.openIntro(
            cardIndex = self.cardIndex,
            namespace = self.inboxNamespace,
            genId = genId,
            genSecretsEnv = generation.secretsEnv,
            genFallbackPublic = generation.fallbackPublic,
            blob = ciphertext,
        )
        val introduced = when (opened) {
            is DmSeal.OpenedIntro.Ok -> opened.intro
            DmSeal.OpenedIntro.Unavailable -> return Result.CRYPTO_UNAVAILABLE
            DmSeal.OpenedIntro.NotOpen -> return dropped(DmCounters.Reason.NOT_OPEN)
            DmSeal.OpenedIntro.NonCanonical -> return dropped(DmCounters.Reason.NON_CANONICAL)
            DmSeal.OpenedIntro.BadSignature -> return dropped(DmCounters.Reason.BAD_BINDING)
            DmSeal.OpenedIntro.InvalidKey -> return dropped(DmCounters.Reason.UNDECRYPTABLE)
            DmSeal.OpenedIntro.StateCorrupt -> return dropped(DmCounters.Reason.STATE_CORRUPT)
        }

        // R5, before any state change (§21.4 point 2): the card parses, and the binding's minute
        // is inside `[now − FRESH, now + 2σ]`. A replay older than FRESH stops here, which is
        // what keeps a relay from resurrecting a rejected requester for ever (L7-D8).
        val parsed = when (val card = crypto.parseCard(introduced.senderCard)) {
            is DmCards.ParseResult.Ok -> card.card
            DmCards.ParseResult.InvalidCard -> return dropped(DmCounters.Reason.NON_CANONICAL)
            DmCards.ParseResult.Unavailable -> return Result.CRYPTO_UNAVAILABLE
        }
        // The `identity_pk ≠ own` half of §3.3's parse, which `card::parse_foreign` is in the
        // crate and which the user-add path already applies. Binding v3 is signed under the card's
        // own Ed25519 key, so an attacker cannot reach here with the victim's key — but the parse
        // §3.3 fixes is stated as fail-closed, and a path that completes only half of it is one
        // more thing a later change has to remember.
        if (parsed.identityPk.contentEquals(self.identityPk)) {
            return dropped(DmCounters.Reason.NON_CANONICAL)
        }
        val bindingSeconds = introduced.bindingMinute * DmTime.MINUTE
        if (bindingSeconds < now - DmTimers.FRESH_SECONDS ||
            bindingSeconds > now + 2 * DmTimers.SIGMA_SECONDS
        ) {
            return dropped(DmCounters.Reason.STALE)
        }

        var createdRequest = false
        var contact = contacts.contactByIdentity(tx.sql, parsed.identityPk)
        if (contact == null) {
            // §12.3: an unknown card holder becomes a **request**, capped at 64. The row lives
            // only with its message (R-P2b): every drop below deletes it again.
            if (contacts.requestCount(tx.sql) >= ContactSteps.MAX_PENDING_REQUESTS) {
                return dropped(DmCounters.Reason.REQUEST_OVERFLOW)
            }
            if (contacts.contactCount(tx.sql) >= ContactSteps.MAX_CONTACTS) {
                return dropped(DmCounters.Reason.REQUEST_OVERFLOW)
            }
            val contactId = random.bytes(ContactSteps.CONTACT_ID_BYTES)
            contacts.insertContact(
                tx = tx,
                contactId = contactId,
                identityPk = parsed.identityPk,
                cardEnv = self.content.seal(
                    random.bytes(ContentCipher.NONCE_BYTES),
                    contactId,
                    introduced.senderCard,
                ),
                cardIndex = parsed.cardIndex,
                trust = ContactStore.Trust.REQUEST,
                source = ContactStore.Source.REQUEST,
                requestUntilDay = DmTime.day(now) + REQUEST_DAYS,
            )
            contacts.insertConversation(
                tx,
                random.bytes(ContactSteps.CONVERSATION_ID_BYTES),
                contactId,
            )
            // §21.4 rule 5: a row that vanished inside the transaction that wrote it is always a
            // bug, and a `dropped(...)` here would be an exit that skips the R-P2b deletion below
            // — the one shape the withdrawal of R-P2b exists to forbid ("a forged, replayed or
            // undecryptable intro envelope leaves no contact behind"). It throws instead, which
            // rolls the insert back with everything else.
            contact = checkNotNull(contacts.contact(tx.sql, contactId)) {
                "the contact row inserted by this transaction is not readable in it"
            }
            createdRequest = true
        }
        if (contact.trust == ContactStore.Trust.BLOCKED ||
            contact.trust == ContactStore.Trust.REVOKED
        ) {
            return dropped(DmCounters.Reason.BLOCKED)
        }

        // R6: the identity pre-check, before any session call (§8.3, E-1).
        val pinned = contact.pinnedIdentity
        if (pinned == null) {
            contacts.pinIdentity(tx, contact.contactId, introduced.olmIdentity)
            // §21.4 rule 5 again, and R-P2b again: an exit here would leave the request row of a
            // message that was never applied.
            contact = checkNotNull(contacts.contact(tx.sql, contact.contactId)) {
                "the contact row this transaction just pinned is not readable in it"
            }
        } else if (!pinned.contentEquals(introduced.olmIdentity)) {
            // §21.4 point 5: a `request` contact that sends a second Olm identity is dropped, and
            // its row goes with the message (R-P2b). A request has not been accepted, so there is
            // nothing to block in either direction and nothing for the user to decide about.
            if (contact.trust == ContactStore.Trust.REQUEST) {
                if (createdRequest) deleteRequest(tx, contact.contactId)
                return dropped(DmCounters.Reason.REQUEST_KEY_MISMATCH)
            }
            // §8.3: a **key change**. The binding verified under this contact's own Ed25519 key
            // inside `openIntro` (a forgery never gets here, E-1), and R5 already bounded its
            // minute, so a valid binding for another Olm identity can only have been signed by the
            // holder of the contact's Ed25519 secret. Hold the ciphertext, block both directions,
            // and wait for the user.
            return hold(tx, self, contact, introduced, genId, blob, now)
        } else if (contact.trust == ContactStore.Trust.CHANGED) {
            // §8.2 rule 4: "No session row is created for a contact in `changed`, `blocked` or
            // `revoked`." A first flight under the **old** pinned identity while a key change is
            // undecided is neither of §7.4 R6's two `changed` cases — it is not a PreKey message
            // under the pending key, and it is not a normal message of a session that already
            // exists — so it is dropped rather than allowed to build a third session for a contact
            // the user is being asked about. Holding it would buy nothing: a hold is replayed only
            // under the identity the user accepted, and this one is the other.
            return dropped(DmCounters.Reason.UNTRUSTED)
        }

        val result = decryptAndApply(
            tx = tx,
            self = self,
            relayExpiryHour = blob.relayExpiryHour,
            arrivalSeconds = now,
            contact = contact,
            l1 = introduced.l1,
            isPreKey = true,
            now = now,
            pairWeek = null,
            pairRootGen = null,
            bindingSeconds = bindingSeconds,
            intro = Intro(
                genId = genId,
                genSecretsEnv = generation.secretsEnv,
                genFallbackPublic = generation.fallbackPublic,
                sessionId = introduced.sessionId,
                replySeedEnv = introduced.replySeedEnv,
            ),
        )
        // R-P2b: a request row lives only with its message. A forged, replayed or undecryptable
        // intro envelope therefore leaves no contact behind.
        if (createdRequest && result != Result.APPLIED) deleteRequest(tx, contact.contactId)
        return result
    }

    /**
     * §8.3: the key change itself — the ciphertext kept, the contact stopped, nothing sent.
     *
     * Three rules live here beside the insert:
     *
     *  - **The newest valid binding wins.** A contact already `changed` under another pending key
     *    takes this one, and the held rows of the superseded key go in the same transaction. Two
     *    live devices under one seed flip-flop between two pending keys; that is declared (R-20)
     *    rather than arbitrated, because nothing on this device can tell them apart.
     *  - **The cap is 256 rows per contact** (the `dm_held_limit` trigger, CS-8), and the oldest
     *    goes first. A trigger abort inside a DM transaction is a bug (§21.4 rule 5), so the
     *    eviction happens **before** the insert rather than being caught after it.
     *  - **Nothing reaches a relay** (T28, T31, NI-DM5): a hold is a row and a counter, and the
     *    contact is not told. A PreKey envelope has the same bucket as any message (T29), so the
     *    hold is not visible in the shape either.
     */
    @Suppress("LongParameterList")
    private fun hold(
        tx: SyncTransaction,
        self: SelfContext,
        contact: ContactStore.ContactRow,
        introduced: DmSeal.Intro,
        genId: Int,
        blob: InboundBlob,
        now: Long,
    ): Result {
        val pending = introduced.olmIdentity
        if (contact.pendingIdentity == null || !contact.pendingIdentity.contentEquals(pending)) {
            if (!contacts.setChanged(tx, contact.contactId, pending)) {
                // The row moved under us (a delete or a block in the same pass): nothing to hold.
                return dropped(DmCounters.Reason.UNTRUSTED)
            }
            heldRows.deleteHeldOtherThan(tx, contact.contactId, pending)
        }
        while (heldRows.heldCount(tx.sql, contact.contactId) >= HeldStore.MAX_HELD_PER_CONTACT) {
            val oldest = heldRows.oldestHeld(tx.sql, contact.contactId) ?: break
            heldRows.deleteHeld(tx, oldest.heldId)
            counters.drop(DmCounters.Reason.HOLD_OVERFLOW)
        }
        val heldId = random.bytes(HELD_ID_BYTES)
        heldRows.insertHeld(
            tx = tx,
            heldId = heldId,
            contactId = contact.contactId,
            identity = pending,
            l1Env = self.content.seal(
                random.bytes(ContentCipher.NONCE_BYTES),
                heldId,
                introduced.l1,
            ),
            genId = genId,
            provEnv = introduced.replySeedEnv,
            holdUntilMinute = DmTimers.holdUntilMinute(now, blob.relayExpiryHour),
            relayExpiryHour = blob.relayExpiryHour,
            consumeMinute = DmTime.floorMinute(now),
        )
        counters.drop(DmCounters.Reason.KEY_CHANGE_HELD)
        return Result.DROPPED
    }

    /**
     * What a first flight carries into the session step — an intro envelope's, or a held row's.
     *
     * It holds **fields**, not the opened envelope, because `HELD` has no envelope left: a held
     * row stores the L1, the generation id and the wrapped `reply_seed`, which is exactly this
     * list (§8.3, §22.8.1 rule 2).
     */
    private class Intro(
        val genId: Int,
        val genSecretsEnv: ByteArray,
        val genFallbackPublic: ByteArray,
        val sessionId: ByteArray,
        val replySeedEnv: ByteArray?,
    )

    // --------------------------------------------------------------- R7 … R12

    @Suppress("LongParameterList", "ReturnCount", "LongMethod")
    private fun decryptAndApply(
        tx: SyncTransaction,
        self: SelfContext,
        /** The relay expiry the blob arrived with; a held row keeps its own (§21.10 point 5). */
        relayExpiryHour: Long,
        /**
         * When the ciphertext **arrived**, which R9's freshness, R-O1's `sort_minute` and C-11's
         * unread deadline are all measured from.
         *
         * For `RECV` it is `now`. For `HELD` it is the held row's `consume_minute`: §21.10 point 5
         * says "HELD evaluates R9 at the held row's consume minute", and it has to — a message held
         * for three weeks while the user thought about a key change would otherwise be refused as
         * stale by the very decision that released it, and would be given a `sort_minute` weeks
         * after the one its neighbours in the same burst got.
         */
        arrivalSeconds: Long,
        contact: ContactStore.ContactRow,
        l1: ByteArray,
        isPreKey: Boolean,
        now: Long,
        pairWeek: Long?,
        pairRootGen: Int?,
        // The **minute grid in epoch seconds**, not the wire's minute index: `peer_bind_minute` is
        // an `x % 60 = 0` column (§13.6) and is compared with `author_minute` in the same unit, so
        // the one multiplication happens where the envelope is opened and nowhere else.
        bindingSeconds: Long?,
        intro: Intro?,
    ): Result {
        val today = DmTime.day(now).toInt()
        val current = sessions.current(tx.sql, contact.contactId)
        val previous = sessions.previous(tx.sql, contact.contactId)
        val plaintext: ByteArray
        var usedSlot: String
        var createdSession = false
        // Phase 11 §4.2: present exactly when the decrypted L0 is kind 5 — the native side wrapped
        // the slot's K_f into a fresh envelope bound to (in, contactId, objectId, manifestHash)
        // and re-zeroed the slot. Whichever function produced the L0 (13 or 14), RECV stores it
        // in media_object in the same transaction — except in a request (D28), where it is dropped.
        var mediaKeyEnv: ByteArray? = null

        val matchesStored = intro != null &&
            listOfNotNull(current, previous).any { it.sessionId.contentEquals(intro.sessionId) }

        if (intro != null && !matchesStored) {
            // D2b (§7.6): a replayed first flight of a live generation, whose session was
            // replaced or deleted, must not create a second session — vodozemac would, because
            // fallback keys are not consumed.
            if (sessions.firstFlightUsed(tx.sql, intro.genId, intro.sessionId)) {
                return dropped(DmCounters.Reason.REPLAY)
            }
            val pinned = contact.pinnedIdentity ?: return dropped(DmCounters.Reason.UNTRUSTED)
            val inbound = envelopes.inbound(
                contactId = contact.contactId,
                genId = intro.genId,
                genSecretsEnv = intro.genSecretsEnv,
                genFallbackPublic = intro.genFallbackPublic,
                expectedPeerIdentity = pinned,
                l1 = l1,
                today = today,
            )
            val created = when (inbound) {
                is DmSessions.Inbound.Ok -> inbound
                DmSessions.Inbound.Unavailable -> return Result.CRYPTO_UNAVAILABLE
                DmSessions.Inbound.MissingKey -> return dropped(DmCounters.Reason.UNKNOWN_GENERATION)
                // `IDENTITY_MISMATCH` is **never** a key change on its own (E-1): a drop.
                DmSessions.Inbound.IdentityMismatch -> return dropped(DmCounters.Reason.UNTRUSTED)
                DmSessions.Inbound.InvalidKey,
                DmSessions.Inbound.Undecryptable,
                -> return dropped(DmCounters.Reason.UNDECRYPTABLE)
                DmSessions.Inbound.StateCorrupt -> return dropped(DmCounters.Reason.STATE_CORRUPT)
            }
            val admission = slots.admitNewInbound(
                tx = tx,
                contactId = contact.contactId,
                bindingSeconds = requireNotNull(bindingSeconds),
                today = DmTime.day(now),
            )
            if (admission == SessionSlots.Admission.STALE) {
                // §22.8.4 rule 2: no session and **no reuse tuple** — the first flight is older
                // than both stored responder sessions, so the contact has moved on.
                return dropped(DmCounters.Reason.STALE_SESSION)
            }
            val slot = if (admission == SessionSlots.Admission.CURRENT) {
                SessionStore.SLOT_CURRENT
            } else {
                SessionStore.SLOT_PREVIOUS
            }
            sessions.insertSession(
                tx = tx,
                contactId = contact.contactId,
                slot = slot,
                sessionId = created.sessionId,
                initiator = false,
                acknowledged = true,
                stateEnv = created.stateEnv,
                provEnv = intro.replySeedEnv,
                peerGenId = null,
                unackSinceDay = null,
                retireDay = if (slot == SessionStore.SLOT_PREVIOUS) {
                    DmTime.day(now) + SessionStore.RETIRE_DAYS
                } else {
                    null
                },
                peerBindMinute = bindingSeconds,
            )
            sessions.markFirstFlightUsed(tx, intro.genId, created.sessionId)
            if (admission == SessionSlots.Admission.CURRENT) {
                // §21.3 point 2: a **renewal from c**. Every out key for c goes, so the next root
                // TLV from c is accepted whatever its generation.
                contacts.deleteOutPairKeys(tx, contact.contactId)
                // §22.8.6 rule 1 (slice S13): c restored, reset or reconnected, so a key it
                // announced before is one its new state may not hold. Its in-band keys go, and
                // every bundle key the new `current` does not name — a responder session names
                // none. This device's unacknowledged PQ-C offers were encapsulated to such keys:
                // they are discarded (the rows and generation numbers stay), and the next send
                // mints a classical offer until a fresh `pq_key` from the new session arrives.
                // And c's new state may lack this device's key: the next send announces it again.
                contacts.deletePeerPqOnRenewal(tx, contact.contactId, keepGenId = null)
                contacts.discardPqOffers(tx, contact.contactId)
                contacts.setPqAnnouncedWeek(tx, contact.contactId, null)
                // §21.3 point 2(b): "inserts a new offer for c unless an unacknowledged one
                // exists" — c may have lost the out key my acknowledged root gave it.
                contacts.supersedeOffers(tx, contact.contactId)
            }
            plaintext = created.plaintext
            mediaKeyEnv = created.mediaKeyEnv
            usedSlot = slot
            createdSession = true
        } else {
            if (current == null && previous == null) return dropped(DmCounters.Reason.UNDECRYPTABLE)
            val decrypted = envelopes.decrypt(
                contactId = contact.contactId,
                current = current?.let { DmSessions.StoredSlot(it.sessionId, it.stateEnv) },
                previous = previous?.let { DmSessions.StoredSlot(it.sessionId, it.stateEnv) },
                l1 = l1,
                isPreKey = isPreKey,
                today = today,
            )
            val ok = when (decrypted) {
                is DmSessions.Decrypted.Ok -> decrypted
                DmSessions.Decrypted.Unavailable -> return Result.CRYPTO_UNAVAILABLE
                DmSessions.Decrypted.Duplicate -> return dropped(DmCounters.Reason.DUPLICATE)
                DmSessions.Decrypted.GapTooBig,
                DmSessions.Decrypted.Undecryptable,
                -> return dropped(DmCounters.Reason.UNDECRYPTABLE)
                DmSessions.Decrypted.StateCorrupt -> return dropped(DmCounters.Reason.STATE_CORRUPT)
            }
            usedSlot = if (ok.slot == DmSessions.Slot.CURRENT) {
                SessionStore.SLOT_CURRENT
            } else {
                SessionStore.SLOT_PREVIOUS
            }
            sessions.setStateEnv(tx, contact.contactId, usedSlot, ok.stateEnv)
            if (ok.acknowledged) sessions.acknowledge(tx, contact.contactId, usedSlot)
            if (bindingSeconds != null && usedSlot.isNotEmpty()) {
                // §22.8.4 rule 1: a responder session's `peer_bind_minute` only rises.
                sessions.raisePeerBindMinute(tx, contact.contactId, usedSlot, bindingSeconds)
            }
            plaintext = ok.plaintext
            mediaKeyEnv = ok.mediaKeyEnv
        }

        // R8: the canonical L0. The new session state commits anyway — the message key was used.
        val decoded = envelopes.decodeContent(contact.contactId, plaintext)
        val content = when (decoded) {
            is DmContent.DecodeResult.Ok -> decoded.content
            DmContent.DecodeResult.Unavailable -> return Result.CRYPTO_UNAVAILABLE
            DmContent.DecodeResult.NonCanonical,
            DmContent.DecodeResult.Oversize,
            -> return dropped(DmCounters.Reason.BAD_CONTENT)
            DmContent.DecodeResult.StateCorrupt -> return dropped(DmCounters.Reason.STATE_CORRUPT)
        }
        // **An unquoted empty TEXT is content this device cannot store** (phase review ENG-1,
        // ENG-3). The codec accepts it — `check_body` bounds only length and UTF-8 — and its
        // one-byte stored body seals to 29 bytes, which `dm_message.body_env`'s CHECK (30 …) refuses:
        // a peer's L0 turned into a constraint abort inside `RECV` (three aborted passes, then R2's
        // poison count) and inside `HELD` (every pass aborted until the hold expired). §21.4 rule 5
        // calls such an abort a bug, so the content is refused here, as bad content, before any
        // effect of it. A **quoted** empty text is stored (its reference makes it 45 bytes) and is
        // not touched. Whether an empty text should exist at all is the facade question §22.21
        // item 3 left to the owner; this rule only stops a peer from crashing the receiver with it.
        if (content.kind == DmContent.Kind.TEXT && content.quoteRef == null && content.body.isEmpty()) {
            return dropped(DmCounters.Reason.BAD_CONTENT)
        }

        // Phase 11 §7.2: a kind-5 L0 carries the media descriptor (§4.1). A malformed descriptor,
        // or one whose key envelope the native side did not return, is bad content — refused
        // before R9/R10 and before any row exists, exactly as the empty text above.
        val mediaDescriptor: MediaDescriptors.Parsed? = if (content.kind == DmContent.Kind.MEDIA) {
            val parsed = MediaDescriptors.parse(content.body)
            if (parsed == null || mediaKeyEnv == null) return dropped(DmCounters.Reason.BAD_CONTENT)
            parsed
        } else {
            null
        }

        // R9: freshness (§7.6, §21.10 points 3 and 5), measured from when the ciphertext arrived;
        // `accept_after_minute` (§8.6); binding B1 (§7.6): in pair mode the author's own week must be
        // the key's week, so an old L0 cannot be re-sealed under a later week key. The rule is
        // [ContentFreshness.RULE]; the self row is read only once the age bound has passed.
        val authorSeconds = content.authorMinute * DmTime.MINUTE
        val fresh = DmTimers.freshSeconds(DmTimers.bucketOf(content.timerCode))
        if (!freshness.admits(authorSeconds, arrivalSeconds, fresh, pairWeek) { owner.self(tx.sql)?.acceptAfterMinute }) {
            return dropped(DmCounters.Reason.STALE)
        }

        // R10: D3, the content-level dedup, which catches the same logical message under
        // different bytes — a re-encryption after a wrongly reported FAILED, a replay after a
        // session reset, a resurrection after the Phase 7 tombstone expired.
        val tag = seenTag(self, contact.contactId, content.messageId)
        val untilDay = DmTimers.seenUntilDay(authorSeconds, DmTimers.bucketOf(content.timerCode))
        if (!messages.markSeen(tx, tag, untilDay)) {
            return dropped(DmCounters.Reason.DUPLICATE)
        }

        // R11 and R12.
        // R-SS2 (§8.2, §22.8.4 rule 3): a message that decrypted on `previous` may promote it. It
        // is decided here rather than beside the decrypt because the normal-message guard reads
        // `author_minute`, which only exists once R8 decoded the L0 — and only a message that
        // survived R9 and R10 should move the slots, because a stale or replayed one is exactly
        // the traffic §22.8.4 rule 3 refuses to promote on.
        if (!createdSession && usedSlot == SessionStore.SLOT_PREVIOUS) {
            val swapped = slots.swapAfterPreviousDecrypted(
                tx = tx,
                contactId = contact.contactId,
                isPreKey = isPreKey,
                authorMinute = authorSeconds,
                today = DmTime.day(now),
            )
            if (swapped) usedSlot = SessionStore.SLOT_CURRENT
        }

        val applied = apply(
            tx = tx,
            self = self,
            contact = contact,
            content = content,
            relayExpiryHour = relayExpiryHour,
            arrivalSeconds = arrivalSeconds,
            now = now,
            createdSession = createdSession,
            usedSlot = usedSlot,
            mediaDescriptor = mediaDescriptor,
            mediaKeyEnv = mediaKeyEnv,
        )
        // An id another row already holds (see [insertIncoming]): the message is dropped whole, its
        // TLVs and its timer version with it, as R10 drops a duplicate — under its own reason, so a
        // D3 that stopped working is not hidden by this layer (mutant MC-5).
        if (!applied) return dropped(DmCounters.Reason.ID_TAKEN)
        val available = applyTlvs(tx, contact, content, isPreKey, usedSlot, now)
        if (pairRootGen != null) acknowledgeOffer(tx, contact, pairRootGen, now)
        return if (available) Result.APPLIED else Result.CRYPTO_UNAVAILABLE
    }

    // ----------------------------------------------------------------- R11, R12

    /** False when the message's id is already taken by another row, and nothing was applied. */
    @Suppress("LongParameterList", "ReturnCount")
    private fun apply(
        tx: SyncTransaction,
        self: SelfContext,
        contact: ContactStore.ContactRow,
        content: DmContent.Decoded,
        relayExpiryHour: Long,
        arrivalSeconds: Long,
        now: Long,
        createdSession: Boolean,
        usedSlot: String,
        mediaDescriptor: MediaDescriptors.Parsed?,
        mediaKeyEnv: ByteArray?,
    ): Boolean {
        val conversation = contacts.conversation(tx.sql, contact.contactId) ?: return true
        // §22.8.5 rule 4: an initiator session's anchor is its **first decryption**, which is its
        // acknowledgement; a responder's is its first provisional seal (SEND's).
        if (!createdSession) {
            sessions.session(tx.sql, contact.contactId, usedSlot)?.let { row ->
                if (row.initiator && row.provAnchorMinute == null && row.provEnv != null) {
                    sessions.setProvisionalAnchor(
                        tx,
                        contact.contactId,
                        usedSlot,
                        DmTime.floorMinute(now),
                    )
                }
            }
        }
        when (content.kind) {
            DmContent.Kind.TEXT -> {
                val inserted = insertIncoming(
                    tx, self, conversation, content, relayExpiryHour, arrivalSeconds, now,
                    body = content.body,
                )
                if (!inserted) return false
            }
            DmContent.Kind.TIMER_SET -> {
                // ADR-27 C.8: a timer change is shown to both sides, as a row with no body.
                val inserted = insertIncoming(
                    tx, self, conversation, content, relayExpiryHour, arrivalSeconds, now,
                    body = null,
                )
                if (!inserted) return false
            }
            DmContent.Kind.REACTION -> {
                val target = content.body.copyOf(minOf(REACTION_TARGET_BYTES, content.body.size))
                // The target is read through §10.7 point 4's filter, bound to `now_e` (R-T7): a
                // reaction must not land on a message this device has already expired.
                if (target.size == REACTION_TARGET_BYTES &&
                    messages.message(tx.sql, target, expiry.nowMinute(tx.sql)) != null
                ) {
                    val grapheme = content.body.copyOfRange(REACTION_TARGET_BYTES, content.body.size)
                    if (grapheme.isEmpty()) {
                        messages.deleteReaction(tx, target, fromSelf = false)
                    } else {
                        messages.putReaction(
                            tx = tx,
                            targetId = target,
                            fromSelf = false,
                            graphemeEnv = self.content.seal(
                                random.bytes(ContentCipher.NONCE_BYTES),
                                target,
                                grapheme,
                            ),
                        )
                    }
                }
            }
            // §7.1: a CONTROL message carries TLVs and no row.
            DmContent.Kind.CONTROL -> Unit

            // Phase 11 §7.2: the message row (the caption, like a text request) is stored as F9
            // stores any incoming message; the media object follows in the same transaction —
            // except in a request (D28), where the key_env the native side returned is dropped
            // unstored and no media_object exists: media in a request is downloaded but never
            // kept openable, before or after the request is accepted (Q36), and mediaState of
            // the message answers NOT_KEPT. Both decrypt (13) and sessionInbound (14) — a first
            // message that is media, and the held replay — land the envelope through this one
            // branch.
            DmContent.Kind.MEDIA -> {
                // Refused as bad content before apply (MediaDescriptors.parse is fail-closed).
                val descriptor = mediaDescriptor ?: return true
                val inserted = insertIncoming(
                    tx, self, conversation, content, relayExpiryHour, arrivalSeconds, now,
                    body = descriptor.caption,
                    framed = false,
                )
                if (!inserted) return false
                if (contact.trust != ContactStore.Trust.REQUEST) {
                    // A second descriptor naming an existing object_id is drop(duplicate_object)
                    // for the object: the message row stands (F9's dedup decided it), the object
                    // is not created twice.
                    mediaObjects.onDescriptor(
                        tx = tx,
                        messageId = content.messageId,
                        contactId = contact.contactId,
                        descriptor = descriptor.store,
                        keyEnv = mediaKeyEnv!!,
                        incompleteAfterHour = relayExpiryHour,
                    )
                }
            }
        }
        // R-T9 (§10.5): a greater timer version is adopted from **any** message, so a lost
        // TIMER_SET heals implicitly; equal versions take the shorter timer.
        //
        // **A version this device could not send again is never adopted** (S9 review). The wire
        // field is a `u32` and nothing bounded it, so one crafted L0 from an established contact
        // with `timer_version = 0xFFFF_FFFF` was adopted here, stored, and then read back by the
        // next send of *any* kind — which re-encodes the conversation's version and narrows it to
        // a signed 32-bit integer. The throw escaped the facade, and that conversation could never
        // send again, across restarts. `DmContent.MAX_TIMER_VERSION` is refused at the decoder
        // now, in both directions; this is the second half, because the value arrives from a peer
        // and a rule that holds in one place only is a rule waiting for a second caller.
        // An ignored version changes nothing, exactly as a lower one does, and the message itself
        // is still stored and shown.
        if (content.timerVersion > DmContent.MAX_TIMER_VERSION) return true
        if (content.timerVersion > conversation.timerVersion) {
            contacts.adoptTimer(
                tx,
                conversation.conversationId,
                content.timerCode,
                content.timerVersion,
            )
        } else if (content.timerVersion == conversation.timerVersion &&
            DmTimers.timerSeconds(content.timerCode) != 0L &&
            (
                conversation.timerCode == DmTimers.TIMER_OFF ||
                    DmTimers.timerSeconds(content.timerCode) <
                    DmTimers.timerSeconds(conversation.timerCode)
                )
        ) {
            contacts.adoptTimer(
                tx,
                conversation.conversationId,
                content.timerCode,
                content.timerVersion,
            )
        }
        return true
    }

    /**
     * The row of an incoming TEXT, TIMER_SET or MEDIA message. False only when another row
     * already holds the message's id (phase review ENG-1, ENG-3: [MessageStore.insertIncomingIfAbsent]);
     * a message past its unread cap is counted and not inserted, and that is still true — it was applied.
     * [framed] is false for a media caption, which §13.6's kind-5 CHECK bounds to `28 + 1 024`
     * bytes with no byte left for the quote flag (F-S6-1 in §22.9).
     */
    @Suppress("LongParameterList")
    private fun insertIncoming(
        tx: SyncTransaction,
        self: SelfContext,
        conversation: ContactStore.ConversationRow,
        content: DmContent.Decoded,
        relayExpiryHour: Long,
        arrivalSeconds: Long,
        now: Long,
        body: ByteArray?,
        framed: Boolean = true,
    ): Boolean {
        val authorSeconds = content.authorMinute * DmTime.MINUTE
        val unreadDeadline = DmTimers.unreadDeadlineMinute(
            consumeSeconds = arrivalSeconds,
            relayExpiryHour = relayExpiryHour,
            timerCode = content.timerCode,
        )
        // §21.10 point 5: a held message released after its own unread cap is **not** inserted.
        // The cap was fixed when the ciphertext arrived — `min(E, consume + bucket + 1 h)` — and a
        // user who takes three weeks to decide a key change must not be shown a one-hour message
        // as if it were new. The row is never written, so the T25 bound needs nothing extra.
        //
        // The cap is compared against `now_e` (R-T7), like every other deadline: on the wall clock
        // a backwards step would insert a message whose cap has already passed, and the next sweep
        // would delete it again.
        if (unreadDeadline != null && unreadDeadline <= expiry.nowMinute(tx.sql)) {
            counters.drop(DmCounters.Reason.EXPIRED_WHILE_HELD)
            return true
        }
        return messages.insertIncomingIfAbsent(
            tx = tx,
            messageId = content.messageId,
            conversationId = conversation.conversationId,
            kind = content.kind.wire,
            authorMinute = authorSeconds,
            // R-O1: `min(author_minute, receive_minute)`, which stops a peer with a future clock
            // from pinning its messages below every later one. `receive_minute` is used here and
            // never stored (§7.7); for a held row it is the minute the **ciphertext** arrived, so
            // a released hold sorts where the burst it belonged to did.
            sortMinute = minOf(authorSeconds, DmTime.floorMinute(arrivalSeconds)),
            minuteIndex = content.minuteIndex,
            timerCode = content.timerCode,
            bodyEnv = body?.let {
                self.content.seal(
                    random.bytes(ContentCipher.NONCE_BYTES),
                    content.messageId,
                    if (framed) quotedBody(content.quoteRef, it) else it,
                )
            },
            unreadDeadlineMinute = unreadDeadline,
        )
    }

    /**
     * R11's TLVs (§7.4): `seal_root` becomes this device's **out** pair key for the contact, and
     * the root itself never leaves the native side — it arrives wrapped and goes straight into
     * [DmEnvelopes.pairKeys] (rule R-S6).
     *
     * **§21.3 rule 1 is enforced here, on receipt**, and [isPreKey] is what enforces it: a root TLV
     * carried by a PreKey message is dropped and counted (`root_in_prekey`). This device's own
     * sender side never produces one — [SendStep] attaches an offer only to an acknowledged
     * session — but that is a statement about *this* sender, and the rule is normative for every
     * peer. A modified or older client that puts `seal_root` in the L0 of its first flight would
     * otherwise install out pair keys from a root riding inside an Olm PreKey message, whose
     * decryption keys this device keeps until `superseded_day + 91`: mutant PM-29, and the P-7 /
     * T34 seizure the rule exists to prevent.
     *
     * **`revocation` (§8.5)** is verified in Rust under the contact's **pinned** `identity_pk` and,
     * when it verifies, moves the contact to the terminal `revoked` state and takes its sessions,
     * pair keys, held rows and pending sends with it — in this transaction, so a crash leaves
     * either the whole revocation or none of it. A certificate that does not parse, does not
     * verify, or names another identity is counted and ignored: it can only ever **block**, so
     * refusing a bad one costs nothing and accepting a forged one would be a denial of service
     * anyone holding a card could mount. It returns early, because the rest of the TLVs would
     * install key material for a contact that no longer has a session.
     *
     * **`session_reset` (§8.6)** is a content-free contact event and writes no row of its own: the
     * renewal it announces is R-SS1's — the contact's first flight under the **same** Olm identity
     * created a new session and deleted this device's out keys for it — and by the time this runs
     * that has already happened. It is counted so the notice is not silently indistinguishable
     * from its absence.
     *
     * **PQ-C (§9.4, slice S13).** A `seal_root_pq` follows the `seal_root` rules — never from a
     * PreKey message, never a generation not newer than the stored one — and is opened with this
     * device's generation it names; one that does not open is ignored and counted (§22.8.6 rule
     * 3). A `pq_key` becomes the contact's in-band X-Wing key when it is newer than every key
     * stored for the contact, still usable, and arrived on the contact's `current` session — see
     * [applyPqKey]. An invalid one is counted (§22.8.2 rule 3).
     *
     * Returns false when the DM context was unavailable for the `seal_root_pq`'s opening (slice
     * S13 review): that is not the peer's doing and is not counted as `pq_root_unopenable`; the
     * caller answers `CRYPTO_UNAVAILABLE` like every other unavailable native call of RECV. The
     * rest of this L0 is applied and commits, as after R8's own `Unavailable`, and the offer is not
     * lost: it stays unacknowledged at the contact, which re-attaches it until it is.
     */
    @Suppress("ReturnCount", "LongParameterList")
    private fun applyTlvs(
        tx: SyncTransaction,
        contact: ContactStore.ContactRow,
        content: DmContent.Decoded,
        isPreKey: Boolean,
        usedSlot: String,
        now: Long,
    ): Boolean {
        if (content.pqIgnored) counters.drop(DmCounters.Reason.PQ_TLV_IGNORED)
        if (content.pqKeyInvalid) counters.drop(DmCounters.Reason.BAD_PQ_KEY)
        if (content.sessionReset) counters.drop(DmCounters.Reason.SESSION_RENEWED)
        content.revocation?.let { certificate ->
            if (applyRevocation(tx, contact, certificate)) return true
        }
        content.sealRoot?.let { root ->
            if (isPreKey) {
                counters.drop(DmCounters.Reason.ROOT_IN_PREKEY)
            } else {
                installOutRoot(tx, contact, root.rootGen, root.baseWeek, root.rootEnv, now)
            }
        }
        var available = true
        content.sealRootPq?.let { root ->
            if (isPreKey) {
                counters.drop(DmCounters.Reason.ROOT_IN_PREKEY)
            } else {
                available = applyPqRoot(tx, contact, root, now)
            }
        }
        content.pqKey?.let { key -> applyPqKey(tx, contact, key, usedSlot, now) }
        return available
    }

    /**
     * The out key of a received root, classical or PQ-C (§6.3): the rules of `seal_root`, applied
     * once the root exists and is wrapped.
     */
    @Suppress("ReturnCount", "LongParameterList")
    private fun installOutRoot(
        tx: SyncTransaction,
        contact: ContactStore.ContactRow,
        rootGen: Int,
        baseWeek: Long,
        rootEnv: ByteArray,
        now: Long,
    ) {
        if (!rootMayApply(tx, contact, rootGen, baseWeek, now)) {
            counters.drop(DmCounters.Reason.ROOT_NOT_NEWER)
            return
        }
        val week = DmTime.week(now)
        val keys = envelopes.pairKeys(
            contactId = contact.contactId,
            direction = DmSeal.PairDirection.OUT,
            rootGen = rootGen,
            from = DmPairing.From.ROOT,
            keyEnv = rootEnv,
            baseWeek = baseWeek,
            fromWeek = maxOf(baseWeek, week),
            toWeek = maxOf(baseWeek, week),
        )
        if (keys !is DmPairing.KeysResult.Ok) {
            counters.drop(DmCounters.Reason.ROOT_NOT_NEWER)
            return
        }
        // The previous generation's out keys go with the new one: §6.3's sender "keeps
        // `K_{week(now)}` of the newest generation".
        contacts.deleteOutPairKeys(tx, contact.contactId)
        for (key in keys.weeks) {
            contacts.putPairKey(
                tx = tx,
                contactId = contact.contactId,
                direction = ContactStore.DIRECTION_OUT,
                rootGen = rootGen,
                week = key.week,
                recognitionKey = key.recognitionKey,
                openEnv = key.openEnv,
            )
        }
    }

    /**
     * §6.3: "a `root_gen` not greater than the stored out generation is ignored", and a base week
     * this side could not have a key for is refused.
     */
    private fun rootMayApply(
        tx: SyncTransaction,
        contact: ContactStore.ContactRow,
        rootGen: Int,
        baseWeek: Long,
        now: Long,
    ): Boolean {
        val week = DmTime.week(now)
        val floor = contacts.pairKeys(tx.sql, contact.contactId, ContactStore.DIRECTION_OUT)
            .maxOfOrNull { it.rootGen }
        if (floor != null && rootGen <= floor) return false
        return baseWeek <= week + 1 && week - baseWeek <= MAX_ROOT_AGE_WEEKS
    }

    /**
     * §9.4 R11: a `seal_root_pq`, opened with this device's generation `peer_gen_id` and then
     * installed exactly as a classical root is.
     *
     * The generation-number rule is checked **first**, so a replayed or superseded offer costs no
     * decapsulation. A generation this device does not hold — never had, or erased — and a
     * ciphertext that does not decapsulate are `pq_root_unopenable` (§22.8.6 rule 3): counted,
     * and the rest of the L0 applies. The contact is the offerer here, so its pinned Olm identity
     * is the first half of the root's salt.
     *
     * Returns false only when the DM context is unavailable (see [applyTlvs]); a `NON_CANONICAL`
     * (a `rootGen` other than the TLV's, which one decode cannot produce) is ignored and counted
     * with the unopenable ones rather than thrown out of RECV.
     */
    @Suppress("ReturnCount")
    private fun applyPqRoot(
        tx: SyncTransaction,
        contact: ContactStore.ContactRow,
        root: DmContent.SealRootPq,
        now: Long,
    ): Boolean {
        if (!rootMayApply(tx, contact, root.rootGen, root.baseWeek, now)) {
            counters.drop(DmCounters.Reason.ROOT_NOT_NEWER)
            return true
        }
        val generation = owner.generations(tx.sql).firstOrNull { it.genId == root.peerGenId }
        val pinned = contact.pinnedIdentity
        if (generation == null || pinned == null) {
            counters.drop(DmCounters.Reason.PQ_ROOT_UNOPENABLE)
            return true
        }
        when (
            val opened = envelopes.pqRootOpen(
                contactId = contact.contactId,
                rootGen = root.rootGen,
                genId = generation.genId,
                genSecretsEnv = generation.secretsEnv,
                genFallbackPublic = generation.fallbackPublic,
                tlv = root.tlv,
                peerOlmIdentity = pinned,
            )
        ) {
            is DmPairing.PqOpenResult.Ok ->
                installOutRoot(tx, contact, opened.rootGen, opened.baseWeek, opened.rootEnv, now)
            DmPairing.PqOpenResult.StateCorrupt -> counters.drop(DmCounters.Reason.STATE_CORRUPT)
            DmPairing.PqOpenResult.NotOpen,
            DmPairing.PqOpenResult.NonCanonical,
            -> counters.drop(DmCounters.Reason.PQ_ROOT_UNOPENABLE)
            // Not the peer's doing (slice S13 review): the caller answers CRYPTO_UNAVAILABLE.
            DmPairing.PqOpenResult.Unavailable -> return false
        }
        return true
    }

    /**
     * §9.4 R11: a `pq_key` (validated whole by the crate, §22.8.2 rule 3) becomes the contact's
     * in-band X-Wing key (`dm_peer_pq`, source `in_band`) when all of these hold:
     *  - it arrived on the contact's **`current`** session (after any R-SS2 swap). §22.8.6 rule 1
     *    uses a PQ offer again "only after a `pq_key` whose `bundle_week` is at least the week of
     *    the renewal has arrived"; no column records that week, and a key carried by the new
     *    `current` is by construction one the contact announced from its post-renewal state,
     *    while one decrypted on the demoted `previous` may predate it;
     *  - its week is **newer** than every key stored for the contact (§7.1's "if its week is
     *    newer"), so a re-announcement of a known key and a late older one change nothing;
     *  - it is **usable**, `week(now) < bundle_week + 5` (§5.4 step 3), and not from a week past
     *    `week(now) + 1`, a bundle's own validity bound.
     * Anything else is ignored without a counter: re-announcements are the normal case.
     * `putPeerPq` keeps the three-row cap (`dm_peer_pq_limit`) by dropping the oldest.
     */
    @Suppress("ReturnCount")
    private fun applyPqKey(
        tx: SyncTransaction,
        contact: ContactStore.ContactRow,
        key: DmContent.PqKey,
        usedSlot: String,
        now: Long,
    ) {
        if (usedSlot != SessionStore.SLOT_CURRENT) return
        val week = DmTime.week(now)
        if (key.bundleWeek > week + 1 || week >= key.bundleWeek + ContactStore.PQ_KEY_WEEKS) return
        val stored = contacts.peerPq(tx.sql, contact.contactId)
        if (stored.any { it.bundleWeek >= key.bundleWeek }) return
        contacts.putPeerPq(
            tx = tx,
            contactId = contact.contactId,
            genId = key.genId.toInt(),
            bundleWeek = key.bundleWeek,
            source = ContactStore.PQ_SOURCE_IN_BAND,
            xwingPublic = key.xwingPublic,
        )
    }

    /**
     * R12 (§7.4, §6.3): a pair envelope that opened under **my** offered generation acknowledges
     * that offer — the root's secret is erased, and the session's `prov_env` erase minute is
     * brought forward to `pair-open + 45 d` when that is earlier than the `anchor + 119 d` the
     * anchor already scheduled (§6.7, §22.8.5 rule 4; [SessionStore.boundProvisionalErase]).
     */
    private fun acknowledgeOffer(
        tx: SyncTransaction,
        contact: ContactStore.ContactRow,
        rootGen: Int,
        now: Long,
    ) {
        if (!contacts.acknowledgeOffer(tx, contact.contactId, rootGen)) return
        for (session in sessions.sessions(tx.sql, contact.contactId)) {
            if (session.provEnv == null) continue
            val anchor = session.provAnchorMinute
            val byPairOpen = DmTime.floorMinute(now) + PROV_ERASE_AFTER_PAIR_SECONDS
            val byAnchor = if (anchor != null) anchor + PROV_ERASE_MAX_SECONDS else Long.MAX_VALUE
            sessions.setProvisionalEraseMinute(
                tx,
                contact.contactId,
                session.slot,
                minOf(byPairOpen, byAnchor),
            )
        }
    }

    /**
     * §8.5: a revocation certificate v2 that arrived in a `revocation` TLV.
     *
     * True when the contact was revoked, so the caller stops applying the rest of the TLVs. The
     * message that carried it keeps its row: it decrypted under a session the contact still had,
     * and the user is entitled to read the message that told them.
     *
     * "A revocation can only block, so a thief holding the seed gains nothing by forging one" —
     * which is also why there is no freshness rule and no user decision: the state is terminal,
     * and the way out is `deleteContact`.
     */
    private fun applyRevocation(
        tx: SyncTransaction,
        contact: ContactStore.ContactRow,
        certificate: ByteArray,
    ): Boolean {
        val verified = crypto.verifyRevocation(certificate, contact.identityPk)
        if (verified !is DmRevocations.Verified.Ok) {
            counters.drop(DmCounters.Reason.BAD_REVOCATION)
            return false
        }
        if (!contacts.revoke(tx, contact.contactId)) return false
        // §8.5: "sessions, pair keys, held rows and pending sends deleted in the same
        // transaction". The pending sends are **failed** rather than deleted, for the reason
        // §12.4's block has to do the same: the row is the only thing that could ever resolve the
        // item and its message, and with the timer off neither would expire (§22.12 item 18(c)).
        sessions.deleteSessions(tx, contact.contactId)
        contacts.deleteOutPairKeys(tx, contact.contactId)
        tx.sql.exec(
            "DELETE FROM dm_pair_key WHERE contact_id = ?",
            listOf(contact.contactId),
        )
        contacts.discardOfferSecrets(tx, contact.contactId)
        contacts.deletePeerPq(tx, contact.contactId)
        heldRows.deleteHeldFor(tx, contact.contactId)
        for (pending in messages.pendingSends(tx.sql, contact.contactId)) {
            messages.failPending(tx, pending.itemId)
        }
        heldRows.deleteScheduledFor(tx, contact.contactId)
        counters.drop(DmCounters.Reason.REVOKED)
        return true
    }

    // ------------------------------------------------------------------- HELD

    /**
     * **HELD** (§22.8.1 rule 2): one held row, replayed through RECV's R7 dispatch and R8 … R12.
     *
     * The caller ([HeldReplay]) owns the transaction, the order and the deletion of the row; what
     * belongs here is the dispatch, and it is **this** code rather than a copy of it — "exactly
     * RECV's R7" in §22.8.1's own words, which a second implementation could not stay.
     *
     * Two inputs differ from RECV's, and both are the held row's own (§21.10 point 5): the relay
     * expiry the ciphertext arrived with, and the minute it was consumed, which R9's freshness,
     * R-O1's `sort_minute` and C-11's unread cap are all measured from.
     *
     * **The session-age input differs too, and this is the one place it is not the contact's
     * clock.** §22.8.4's R-SS1 compares an intro envelope's `binding_minute` with a stored
     * `peer_bind_minute`, both written by the contact; `dm_held` carries no binding minute (§13.6
     * step 5 fixes its columns and migration 5 is closed), so the replay supplies a consume minute
     * — this device's own arrival minute, and the same value §22.8.1 rule 1 orders the groups by.
     * It is sound where it is used: a KEYDEC acceptance deletes **both** sessions (R-SS0) before
     * HELD runs, so every comparison is between two held rows of the same window, and their
     * arrival order at this device is the only order either side agrees on anyway.
     *
     * [bindingSeconds] is therefore the **group's** smallest consume minute and not the row's own
     * (§22.13 item 3a): it has to be the number the groups were ordered by, or the groups reach
     * `admitNewInbound` out of order and §22.8.4 rule 2 drops one whole session's worth of held
     * rows. [HeldReplay] computes it; this function does not, because it sees one row at a time.
     */
    @Suppress("LongParameterList", "ReturnCount")
    internal fun replayHeld(
        tx: SyncTransaction,
        self: SelfContext,
        contact: ContactStore.ContactRow,
        row: HeldStore.HeldRow,
        l1: ByteArray,
        sessionId: ByteArray,
        bindingSeconds: Long,
        now: Long,
    ): Result {
        val generation = owner.generations(tx.sql)
            .firstOrNull { it.genId == row.genId.toLong() and U32 }
            ?: return dropped(DmCounters.Reason.UNKNOWN_GENERATION)
        return decryptAndApply(
            tx = tx,
            self = self,
            relayExpiryHour = row.relayExpiryHour,
            arrivalSeconds = row.consumeMinute,
            contact = contact,
            l1 = l1,
            isPreKey = true,
            now = now,
            pairWeek = null,
            pairRootGen = null,
            bindingSeconds = bindingSeconds,
            intro = Intro(
                genId = row.genId,
                genSecretsEnv = generation.secretsEnv,
                genFallbackPublic = generation.fallbackPublic,
                sessionId = sessionId,
                replySeedEnv = row.provEnv,
            ),
        )
    }

    // --------------------------------------------------------------- internals

    private fun deleteRequest(tx: SyncTransaction, contactId: ByteArray) {
        contacts.deleteContact(tx, contactId)
    }

    private fun dropped(reason: DmCounters.Reason): Result {
        counters.drop(reason)
        return Result.DROPPED
    }

    private fun isOwnInbox(tx: SyncTransaction, namespace: NamespaceId): Boolean {
        var found = false
        tx.sql.query(
            "SELECT 1 FROM dm_own_namespace WHERE namespace_id = ? AND role = 'inbox'",
            listOf(namespace.toByteArray()),
        ) { found = true }
        return found
    }

    /** `tag = HMAC-SHA256(seen_key, contact_id || message_id)[0..16]` (§7.6). */
    private fun seenTag(self: SelfContext, contactId: ByteArray, messageId: ByteArray): ByteArray {
        val key = self.seenKey
        return try {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(key, "HmacSHA256"))
            mac.update(contactId)
            mac.update(messageId)
            mac.doFinal().copyOf(SEEN_TAG_BYTES)
        } finally {
            key.fill(0)
        }
    }

    /** The `body_env` layout of §21.8 point 6, as [SendStep] writes it. */
    private fun quotedBody(quoteRef: ByteArray?, body: ByteArray): ByteArray {
        val out = ByteArray(1 + (quoteRef?.size ?: 0) + body.size)
        out[0] = (if (quoteRef != null) SendStep.FLAG_HAS_QUOTE else 0).toByte()
        var at = 1
        quoteRef?.let { it.copyInto(out, at); at += it.size }
        body.copyInto(out, at)
        return out
    }

    companion object {
        /** R2: three earlier offers died unconsumed (§7.8, G-1). */
        const val POISON_OFFERS: Int = 4

        /** §7.6: the D3 tag is the first 16 bytes of the HMAC. */
        const val SEEN_TAG_BYTES: Int = 16

        /** §12.3: a request lives seven days. */
        const val REQUEST_DAYS: Long = 7

        /** A REACTION body is `target message_id(16) || grapheme` (§7.1). */
        const val REACTION_TARGET_BYTES: Int = 16

        /** `dm_held.held_id` is 16 random bytes, like every other id of the schema (T33). */
        const val HELD_ID_BYTES: Int = 16

        /** §22.8.5 rule 4: 45 days after a pair envelope under the newest root first opened. */
        const val PROV_ERASE_AFTER_PAIR_SECONDS: Long = 45 * DmTime.DAY

        /**
         * And at the latest `prov_anchor_minute + 119 d` (§22.8.5 rule 5's derivation), which
         * [SessionStore.boundProvisionalErase] already scheduled when the anchor was set.
         */
        const val PROV_ERASE_MAX_SECONDS: Long = SessionStore.PROV_ERASE_MAX_SECONDS

        /**
         * How old a root's base week may be. A week key is erased at `start(w + 1) + FRESH`
         * (§6.3), so a root whose base week is further back than that has no usable key left and
         * ratcheting to it would be wasted work.
         */
        const val MAX_ROOT_AGE_WEEKS: Long = 8

        /** The three bucket sizes a DM blob can be (§6.6). */
        private val BUCKETS = setOf(4096, 16_384, 65_536)

        /** `gen_id` crosses as a signed `Int` and is stored as an unsigned `u32` (§13.6). */
        private const val U32 = 0xffff_ffffL
    }
}
