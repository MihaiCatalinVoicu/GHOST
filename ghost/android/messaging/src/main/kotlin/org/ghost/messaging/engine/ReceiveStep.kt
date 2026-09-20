package org.ghost.messaging.engine

import org.ghost.crypto.bridge.DmCards
import org.ghost.crypto.bridge.DmContent
import org.ghost.crypto.bridge.DmPairing
import org.ghost.crypto.bridge.DmSeal
import org.ghost.crypto.bridge.DmSessions
import org.ghost.messaging.port.DmClock
import org.ghost.messaging.port.DmCrypto
import org.ghost.messaging.port.DmEnvelopes
import org.ghost.messaging.port.DmRandom
import org.ghost.messaging.store.ContactStore
import org.ghost.messaging.store.ContentCipher
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
 * **Key change is slice S8's, and S7 refuses rather than classifies.** §8.3 holds an intro PreKey
 * message that names an Olm identity other than the pinned one under a valid binding, moves the
 * contact to `changed` and waits for the user. S7 has no `KEYDEC` to resolve that state, so it
 * would strand the contact; until S8 lands, such a message is `drop(untrusted)` and counted.
 * CS-5's guarantee still holds — nothing is decrypted from the new identity and nothing is shown
 * — what is missing is the **detection**, and it is recorded in the design's forward notes.
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
) {
    private val contacts = ContactStore()
    private val messages = MessageStore()
    private val sessions = SessionStore()
    private val owner = OwnerStore()

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
            blob = blob,
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
            contact = contacts.contact(tx.sql, contactId)
                ?: return dropped(DmCounters.Reason.NON_CANONICAL)
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
            contact = contacts.contact(tx.sql, contact.contactId) ?: return dropped(
                DmCounters.Reason.NON_CANONICAL,
            )
        } else if (!pinned.contentEquals(introduced.olmIdentity)) {
            // §21.4 point 5 for a `request`; for every other state this is where §8.3's hold
            // belongs, and S7 refuses instead (see the class comment).
            if (createdRequest) deleteRequest(tx, contact.contactId)
            return dropped(
                if (contact.trust == ContactStore.Trust.REQUEST) {
                    DmCounters.Reason.REQUEST_KEY_MISMATCH
                } else {
                    DmCounters.Reason.UNTRUSTED
                },
            )
        }

        val result = decryptAndApply(
            tx = tx,
            self = self,
            blob = blob,
            contact = contact,
            l1 = introduced.l1,
            isPreKey = true,
            now = now,
            pairWeek = null,
            pairRootGen = null,
            bindingSeconds = bindingSeconds,
            intro = Intro(genId, generation.secretsEnv, generation.fallbackPublic, introduced),
        )
        // R-P2b: a request row lives only with its message. A forged, replayed or undecryptable
        // intro envelope therefore leaves no contact behind.
        if (createdRequest && result != Result.APPLIED) deleteRequest(tx, contact.contactId)
        return result
    }

    /** What an intro envelope carries into the session step. */
    private class Intro(
        val genId: Int,
        val genSecretsEnv: ByteArray,
        val genFallbackPublic: ByteArray,
        val opened: DmSeal.Intro,
    )

    // --------------------------------------------------------------- R7 … R12

    @Suppress("LongParameterList", "ReturnCount", "LongMethod")
    private fun decryptAndApply(
        tx: SyncTransaction,
        self: SelfContext,
        blob: InboundBlob,
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

        val matchesStored = intro != null &&
            listOfNotNull(current, previous).any { it.sessionId.contentEquals(intro.opened.sessionId) }

        if (intro != null && !matchesStored) {
            // D2b (§7.6): a replayed first flight of a live generation, whose session was
            // replaced or deleted, must not create a second session — vodozemac would, because
            // fallback keys are not consumed.
            if (sessions.firstFlightUsed(tx.sql, intro.genId, intro.opened.sessionId)) {
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
                provEnv = intro.opened.replySeedEnv,
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
            }
            plaintext = created.plaintext
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

        // R9: freshness (§7.6, §21.10 point 3).
        val authorSeconds = content.authorMinute * DmTime.MINUTE
        val fresh = DmTimers.freshSeconds(DmTimers.bucketOf(content.timerCode))
        if (authorSeconds < now - fresh || authorSeconds > now + 2 * DmTimers.SIGMA_SECONDS) {
            return dropped(DmCounters.Reason.STALE)
        }
        val acceptAfter = owner.self(tx.sql)?.acceptAfterMinute
        if (acceptAfter != null && authorSeconds < acceptAfter) {
            return dropped(DmCounters.Reason.STALE)
        }
        // Binding B1 (§7.6): in pair mode the author's own week must be the key's week, so an old
        // L0 cannot be re-sealed under a later week key.
        if (pairWeek != null && DmTime.week(authorSeconds) != pairWeek) {
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
        apply(tx, self, contact, content, blob, now, createdSession, usedSlot)
        applyTlvs(tx, contact, content, now)
        if (pairRootGen != null) acknowledgeOffer(tx, contact, pairRootGen, now)
        return Result.APPLIED
    }

    // ----------------------------------------------------------------- R11, R12

    @Suppress("LongParameterList")
    private fun apply(
        tx: SyncTransaction,
        self: SelfContext,
        contact: ContactStore.ContactRow,
        content: DmContent.Decoded,
        blob: InboundBlob,
        now: Long,
        createdSession: Boolean,
        usedSlot: String,
    ) {
        val conversation = contacts.conversation(tx.sql, contact.contactId) ?: return
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
            DmContent.Kind.TEXT -> insertIncoming(
                tx, self, conversation, content, blob, now, body = content.body,
            )
            DmContent.Kind.TIMER_SET -> {
                // ADR-27 C.8: a timer change is shown to both sides, as a row with no body.
                insertIncoming(tx, self, conversation, content, blob, now, body = null)
            }
            DmContent.Kind.REACTION -> {
                val target = content.body.copyOf(minOf(REACTION_TARGET_BYTES, content.body.size))
                if (target.size == REACTION_TARGET_BYTES &&
                    messages.message(tx.sql, target, DmTime.floorMinute(now)) != null
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
        }
        // R-T9 (§10.5): a greater timer version is adopted from **any** message, so a lost
        // TIMER_SET heals implicitly; equal versions take the shorter timer.
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
    }

    @Suppress("LongParameterList")
    private fun insertIncoming(
        tx: SyncTransaction,
        self: SelfContext,
        conversation: ContactStore.ConversationRow,
        content: DmContent.Decoded,
        blob: InboundBlob,
        now: Long,
        body: ByteArray?,
    ) {
        val authorSeconds = content.authorMinute * DmTime.MINUTE
        messages.insertMessage(
            tx = tx,
            messageId = content.messageId,
            conversationId = conversation.conversationId,
            outgoing = false,
            kind = content.kind.wire,
            authorMinute = authorSeconds,
            // R-O1: `min(author_minute, receive_minute)`, which stops a peer with a future clock
            // from pinning its messages below every later one. `receive_minute` is used here and
            // never stored (§7.7).
            sortMinute = minOf(authorSeconds, DmTime.floorMinute(now)),
            minuteIndex = content.minuteIndex,
            timerCode = content.timerCode,
            bodyEnv = body?.let {
                self.content.seal(
                    random.bytes(ContentCipher.NONCE_BYTES),
                    content.messageId,
                    quotedBody(content.quoteRef, it),
                )
            },
            state = MessageStore.STATE_UNREAD,
            expireAtMinute = null,
            unreadDeadlineMinute = DmTimers.unreadDeadlineMinute(
                consumeSeconds = now,
                relayExpiryHour = blob.relayExpiryHour,
                timerCode = content.timerCode,
            ),
        )
    }

    /**
     * R11's TLVs (§7.4): `seal_root` becomes this device's **out** pair key for the contact, and
     * the root itself never leaves the native side — it arrives wrapped and goes straight into
     * [DmEnvelopes.pairKeys] (rule R-S6).
     *
     * `revocation` and `session_reset` are slice S8's; a PQ-C TLV is counted and ignored (§9.4).
     */
    private fun applyTlvs(
        tx: SyncTransaction,
        contact: ContactStore.ContactRow,
        content: DmContent.Decoded,
        now: Long,
    ) {
        if (content.sawPqTlv) counters.drop(DmCounters.Reason.PQ_TLV_IGNORED)
        if (content.revocation != null) counters.drop(DmCounters.Reason.REVOCATION_DEFERRED)
        if (content.sessionReset) counters.drop(DmCounters.Reason.SESSION_RESET_DEFERRED)
        val root = content.sealRoot ?: return
        // §21.3 point 1: a root TLV in a PreKey message is ignored. The symmetric path is the only
        // one that reaches here with one, because an intro envelope's L1 is a PreKey message.
        val week = DmTime.week(now)
        val existing = contacts.pairKeys(tx.sql, contact.contactId, ContactStore.DIRECTION_OUT)
        // §6.3: "a `root_gen` not greater than the stored out generation is ignored".
        val floor = existing.maxOfOrNull { it.rootGen }
        if (floor != null && root.rootGen <= floor) {
            counters.drop(DmCounters.Reason.ROOT_NOT_NEWER)
            return
        }
        if (root.baseWeek > week + 1 || week - root.baseWeek > MAX_ROOT_AGE_WEEKS) {
            counters.drop(DmCounters.Reason.ROOT_NOT_NEWER)
            return
        }
        val keys = envelopes.pairKeys(
            contactId = contact.contactId,
            direction = DmSeal.PairDirection.OUT,
            rootGen = root.rootGen,
            from = DmPairing.From.ROOT,
            keyEnv = root.rootEnv,
            baseWeek = root.baseWeek,
            fromWeek = maxOf(root.baseWeek, week),
            toWeek = maxOf(root.baseWeek, week),
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
                rootGen = root.rootGen,
                week = key.week,
                recognitionKey = key.recognitionKey,
                openEnv = key.openEnv,
            )
        }
    }

    /**
     * R12 (§7.4, §6.3): a pair envelope that opened under **my** offered generation acknowledges
     * that offer — the root's secret is erased, and the session's `prov_env` gets its erase
     * minute (§6.7, §22.8.5 rule 4).
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

        /** §22.8.5 rule 4: 45 days after a pair envelope under the newest root first opened. */
        const val PROV_ERASE_AFTER_PAIR_SECONDS: Long = 45 * DmTime.DAY

        /** And at the latest `prov_anchor_minute + 119 d` (§22.8.5 rule 5's derivation). */
        const val PROV_ERASE_MAX_SECONDS: Long = 119 * DmTime.DAY

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
