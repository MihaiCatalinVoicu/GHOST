package org.ghost.messaging.engine

import org.ghost.crypto.bridge.CredentialV3
import org.ghost.crypto.bridge.DmContent
import org.ghost.crypto.bridge.DmPairing
import org.ghost.crypto.bridge.DmSeal
import org.ghost.crypto.bridge.DmSessions
import org.ghost.messaging.port.DmClock
import org.ghost.messaging.port.DmEnvelopes
import org.ghost.messaging.port.DmRandom
import org.ghost.messaging.port.EsSlot
import org.ghost.messaging.store.ContactStore
import org.ghost.messaging.store.ContentCipher
import org.ghost.messaging.store.HeldStore
import org.ghost.messaging.store.MessageStore
import org.ghost.messaging.store.SessionStore
import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.CapabilitySource
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.InstalledCapability
import org.ghost.sync.api.InsufficientReplicasException
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.OperationId
import org.ghost.sync.api.OutboundBlob
import org.ghost.sync.api.SendDelay
import org.ghost.sync.api.SyncDatabase
import org.ghost.sync.api.SyncTransaction
import org.ghost.sync.api.TtlBucket
import org.ghost.storage.StorageFullException

/**
 * **SEND** and **RESEND** (Phase 9 design §7.3, §7.5, §21.8).
 *
 * Why a send is safe (CS-1), in the design's own words:
 *
 * > The session state is passed into the native call as a stored envelope and comes back as a new
 * > envelope that Kotlin writes through `tx.sql` in the same transaction; no native session object
 * > survives the call (§7.9). The ciphertext leaves the device only through the outbox, which sees
 * > it only after commit. A crash before commit leaves no ratchet step, row or op; after commit,
 * > an op the engine sends. A message key is used only inside a transaction that either commits
 * > the op or leaves no trace.
 *
 * **Two phases, one writer.** The relay set, the deposit credentials and the L0 are prepared
 * **before** the writing transaction opens, because minting or encoding inside it would commit
 * half a step while reporting an error (§7.2's first sentence, §22.11 item 17). That is sound only
 * because the DM actor is the single DM writer (§13.7): nothing else can write DM state between
 * the two phases, and the writing transaction re-reads every guard it depends on anyway.
 *
 * **The mode rule is §6.8's, and all of it**: a PreKey output is intro; a normal output with an
 * out pair key for `week(author_minute)` is pair; a normal output with a `prov_env`, no pair
 * envelope ever sealed on the session and an anchor inside 28 days is provisional; anything else
 * is `NO_SEAL_KEY`, which keeps the item pending and re-establishes — a user-caused
 * re-establishment, never an inbound one (T28).
 */
internal class SendStep(
    private val database: SyncDatabase,
    private val sync: DmSyncPorts,
    private val envelopes: DmEnvelopes,
    private val material: ContactMaterial,
    private val relays: RelaySetResolver,
    private val clock: DmClock,
    private val random: DmRandom,
    private val contexts: SelfContexts,
    private val slots: SessionSlots = SessionSlots(),
) {
    private val contacts = ContactStore()
    private val messages = MessageStore()
    private val sessions = SessionStore()
    private val scheduled = HeldStore()

    /** The facade's `send` result (§13.2), plus the two the engine needs internally. */
    enum class Outcome {
        /** The message is stored and either enqueued or waiting for establishment. */
        QUEUED,

        /** A key change is pending the user's decision; no ciphertext is produced (§8.3, CS-5). */
        KEY_CHANGED,

        /** The contact is blocked (§12.4). */
        BLOCKED,

        /** The contact's identity is revoked: terminal (§8.5). */
        REVOKED,

        /** The contact is a request the user has not accepted (§12.3). */
        REQUEST_NOT_ACCEPTED,

        /** `|body| > MAX_BODY_BYTES`; Phase 11 media carries more (§6.6, §12.6). */
        TOO_LARGE,

        /** The week's ES slot table cannot span two operators (ADR-11, §5.2). */
        NO_REPLICAS,

        /** The local database is full (`SQLITE_FULL`, §7.8). */
        STORAGE_FULL,

        /** The DM context is closed or the native library is missing (§13.2). */
        CRYPTO_UNAVAILABLE,

        /** No such contact, or no conversation for it. */
        UNKNOWN_CONTACT,

        /** A user retry past the original deadline (§7.5). */
        DEADLINE_PASSED,
    }

    /** What [send] decided, so the caller knows whether to run `EST-START` after it commits. */
    class Sent(val outcome: Outcome, val establish: Boolean) {
        override fun toString(): String = "Sent($outcome, establish=$establish)"
    }

    // ------------------------------------------------------------------- SEND

    /**
     * §7.3: one user-initiated send.
     *
     * [timerCode] is null for a TEXT or a REACTION, which take the conversation's timer, and the
     * new code for a TIMER_SET, whose blob takes the larger of the two buckets (R-T3).
     */
    @Suppress("ReturnCount")
    fun send(
        contactId: ByteArray,
        kind: DmContent.Kind,
        body: ByteArray,
        quoteRef: ByteArray?,
        timerCode: Int?,
    ): Sent {
        val self = contexts.get() ?: return Sent(Outcome.CRYPTO_UNAVAILABLE, establish = false)
        if (body.size > DmContent.MAX_BODY_BYTES) return Sent(Outcome.TOO_LARGE, establish = false)
        val now = clock.nowEpochSeconds()
        val authorMinute = DmTime.floorMinute(now)

        val plan = database.transaction { tx ->
            plan(tx, contactId, kind, timerCode, now, createOffer = true)
        }
        plan.refusal?.let { return Sent(it, establish = false) }
        val prepared = plan.prepared ?: return Sent(Outcome.CRYPTO_UNAVAILABLE, establish = false)
        val minted = mintOffer(contactId, prepared)
        val rootGen = prepared.offer?.rootGen ?: minted?.rootGen ?: 0
        val offerEnv = prepared.offer?.offerEnv ?: minted?.offerEnv ?: EMPTY

        val messageId = random.bytes(MESSAGE_ID_BYTES)
        val encoded = envelopes.encodeContent(
            kind = kind,
            messageId = messageId,
            authorMinute = authorMinute / DmTime.MINUTE,
            minuteIndex = prepared.minuteIndex,
            timerCode = prepared.timerCode,
            timerVersion = prepared.timerVersion,
            quoteRef = quoteRef,
            body = body,
            contactId = contactId,
            offerRootGen = rootGen,
            offerEnv = offerEnv,
            revocation = EMPTY,
            sessionReset = false,
        )
        val l0 = when (encoded) {
            is DmContent.Encoded.Ok -> encoded
            DmContent.Encoded.Oversize -> return Sent(Outcome.TOO_LARGE, establish = false)
            // A record this engine built that the codec refuses is a bug, not an outcome: the
            // fields come from the schema's own ranges and the TLVs from R-C3's own list.
            DmContent.Encoded.NonCanonical ->
                throw IllegalStateException("the engine built a non-canonical L0")
            DmContent.Encoded.StateCorrupt,
            DmContent.Encoded.Unavailable,
            -> return Sent(Outcome.CRYPTO_UNAVAILABLE, establish = false)
        }

        val credentials = depositCredentials(prepared)
            ?: return Sent(Outcome.CRYPTO_UNAVAILABLE, establish = false)

        return commit(
            self = self,
            contactId = contactId,
            kind = kind,
            control = null,
            messageId = messageId,
            authorMinute = authorMinute,
            now = now,
            prepared = prepared,
            l0 = l0,
            body = body,
            quoteRef = quoteRef,
            credentials = credentials,
            minted = minted,
        )
    }

    /**
     * §7.2's SEND row, control half: the **scheduled CONTROL** of a reconnect or a revocation
     * notice, and the `reset` control of an explicit `resetSession`.
     *
     * It is the same transaction as a user send, minus the rows a CONTROL has no business writing:
     * `dm_message` carries TEXT and TIMER_SET only (§21.8 point 2), so a control is an item, an op
     * and nothing else. It still waits for establishment like any other item when there is no
     * usable session — which is the whole point of §21.8's "a reconnect could not wait for a
     * bundle" defect: the reconnect notice of §8.6 is **exactly** the message that has to travel as
     * an intro envelope, so its item has to be able to sit in `dm_pending_send` while `EST-START`
     * and `EST-READY` run.
     *
     * **It is not a reflex** (T28, §21.9 rule 2). The three controls are caused by a user action —
     * `reconnect(contacts)`, `notifyContactsOfRevocation()`, `resetSession(c)` — and the moment
     * each one goes out is a minute drawn at that action and persisted, never the minute something
     * arrived. Gate G-DM2 reads this file for the `Outbox.enqueue` that follows.
     *
     * **[scheduledId] retires the `dm_scheduled` row in this send's own transaction** (the S8
     * review; the same shape the S7 review fixed for RESEND in 8bd2f0a). Deleting it afterwards,
     * in a transaction of its own, means a crash in between deposits the notice **twice**: a
     * second `sendControl` mints a fresh `message_id`, so D3's `seen_tag` cannot dedup it, and it
     * is a fresh ratchet step, so D2b cannot either. Null for the `reset` control of
     * `resetSession`, which has no scheduled row.
     */
    @Suppress("ReturnCount")
    fun sendControl(
        contactId: ByteArray,
        control: Control,
        revocation: ByteArray,
        sessionReset: Boolean,
        scheduledId: ByteArray? = null,
    ): Sent {
        val self = contexts.get() ?: return Sent(Outcome.CRYPTO_UNAVAILABLE, establish = false)
        val now = clock.nowEpochSeconds()
        val authorMinute = DmTime.floorMinute(now)

        val plan = database.transaction { tx ->
            plan(tx, contactId, DmContent.Kind.CONTROL, null, now, createOffer = true)
        }
        plan.refusal?.let { return Sent(it, establish = false) }
        val prepared = plan.prepared ?: return Sent(Outcome.CRYPTO_UNAVAILABLE, establish = false)
        val minted = mintOffer(contactId, prepared)
        val rootGen = prepared.offer?.rootGen ?: minted?.rootGen ?: 0
        val offerEnv = prepared.offer?.offerEnv ?: minted?.offerEnv ?: EMPTY

        val messageId = random.bytes(MESSAGE_ID_BYTES)
        val encoded = envelopes.encodeContent(
            kind = DmContent.Kind.CONTROL,
            messageId = messageId,
            authorMinute = authorMinute / DmTime.MINUTE,
            minuteIndex = 0,
            timerCode = prepared.timerCode,
            timerVersion = prepared.timerVersion,
            quoteRef = null,
            body = EMPTY,
            contactId = contactId,
            offerRootGen = rootGen,
            offerEnv = offerEnv,
            revocation = revocation,
            sessionReset = sessionReset,
        )
        val l0 = when (encoded) {
            is DmContent.Encoded.Ok -> encoded
            DmContent.Encoded.Oversize -> return Sent(Outcome.TOO_LARGE, establish = false)
            DmContent.Encoded.NonCanonical ->
                throw IllegalStateException("the engine built a non-canonical control L0")
            DmContent.Encoded.StateCorrupt,
            DmContent.Encoded.Unavailable,
            -> return Sent(Outcome.CRYPTO_UNAVAILABLE, establish = false)
        }
        val credentials = depositCredentials(prepared)
            ?: return Sent(Outcome.CRYPTO_UNAVAILABLE, establish = false)

        return commit(
            self = self,
            contactId = contactId,
            kind = DmContent.Kind.CONTROL,
            control = control,
            messageId = messageId,
            authorMinute = authorMinute,
            now = now,
            prepared = prepared,
            l0 = l0,
            body = EMPTY,
            quoteRef = null,
            credentials = credentials,
            minted = minted,
            scheduledId = scheduledId,
        )
    }

    /** `dm_outbound_item.control` (§21.8 point 1): which CONTROL an item is. */
    enum class Control(val wire: String) {
        /** §8.6: the `session_reset` notice a `reconnect(contacts)` schedules. */
        RECONNECT("reconnect"),

        /** §8.5: the revocation certificate a `notifyContactsOfRevocation()` schedules. */
        REVOCATION("revocation"),

        /** §8.7: the control an explicit `resetSession(c)` sends once the new session exists. */
        RESET("reset"),
    }

    /**
     * §21.7 point 4: every pending item of a contact, sealed and enqueued once a session exists.
     *
     * One transaction **per item**, not one for all of them: an item whose seal fails must not
     * roll back the ones already enqueued, and each item's ratchet step has to commit with its own
     * op (CS-1).
     */
    fun flushPending(contactId: ByteArray): Int {
        val self = contexts.get() ?: return 0
        var sent = 0
        val pending = database.transaction { tx -> messages.pendingSends(tx.sql, contactId) }
        for (row in pending) if (flushOne(self, contactId, row.itemId)) sent += 1
        return sent
    }

    /**
     * §7.5: the **user retry** of a FAILED item.
     *
     * It re-encrypts the **same L0** — same `message_id`, author minute, minute index and timer
     * fields — under the next ratchet step, as a new op, while `now` is before the original
     * deadline. No copy ever existed, so re-encrypting is safe, and D3 dedups by `message_id` if
     * one somehow did (§7.6).
     *
     * SEND's guards run again against `now` (§22.8.5 rule 2): the trust check, the no-session
     * check and the mode rule of §6.8. The out key of the **author's own week** is what makes the
     * pair branch reachable across a week boundary, which is why the maintenance step keeps it
     * while a retryable item of that week lives (§22.8.5 rule 1).
     *
     * **It returns [Sent], not an outcome alone**, for the reason SEND does: a retry that finds no
     * usable session queues a pending item, and a pending item nobody establishes for is a message
     * that waits until its deadline and then fails while later ones go out. The caller runs
     * `EST-START` on `establish`, exactly as it does after a send.
     */
    @Suppress("ReturnCount")
    fun retry(itemId: ByteArray): Sent {
        val self = contexts.get() ?: return Sent(Outcome.CRYPTO_UNAVAILABLE, establish = false)
        val now = clock.nowEpochSeconds()
        val row = database.transaction { tx -> messages.item(tx.sql, itemId) }
            ?: return Sent(Outcome.UNKNOWN_CONTACT, establish = false)
        if (row.state != STATE_FAILED) return Sent(Outcome.UNKNOWN_CONTACT, establish = false)
        if (now >= row.deadlineHour) return Sent(Outcome.DEADLINE_PASSED, establish = false)
        val plan = database.transaction { tx ->
            plan(tx, row.contactId, DmContent.Kind.TEXT, null, now, createOffer = false)
        }
        plan.refusal?.let { return Sent(it, establish = false) }
        val prepared = plan.prepared
            ?: return Sent(Outcome.CRYPTO_UNAVAILABLE, establish = false)
        val credentials = depositCredentials(prepared)
            ?: return Sent(Outcome.CRYPTO_UNAVAILABLE, establish = false)
        val operationId = random.bytes(OperationId.SIZE)
        return try {
            database.transaction { tx ->
                val contact = contacts.contact(tx.sql, row.contactId)
                    ?: return@transaction Sent(Outcome.UNKNOWN_CONTACT, false)
                refusalFor(contact.trust)?.let { return@transaction Sent(it, false) }
                val item = messages.item(tx.sql, itemId)
                    ?: return@transaction Sent(Outcome.UNKNOWN_CONTACT, false)
                if (item.state != STATE_FAILED) {
                    return@transaction Sent(Outcome.UNKNOWN_CONTACT, false)
                }
                val l0Env = item.l0Env ?: return@transaction Sent(Outcome.UNKNOWN_CONTACT, false)
                val l0 = self.content.open(l0Env, itemId)
                    ?: return@transaction Sent(Outcome.UNKNOWN_CONTACT, false)
                val decoded = envelopes.decodeContent(row.contactId, l0)
                if (decoded !is DmContent.DecodeResult.Ok) {
                    return@transaction Sent(Outcome.UNKNOWN_CONTACT, false)
                }
                // The **exact** deadline, not the hour it was rounded up to: `author_minute` is on
                // the minute grid, so `ceil_hour(deadline)` can be up to 59 minutes past it, and
                // `Outbox.enqueue` requires `deadline > now` with an `IllegalArgumentException`
                // that no caller on this path catches (Phase 7 `OutboxStore`).
                val ttl = DmTimers.bucketOf(decoded.content.timerCode)
                val authorMinute = decoded.content.authorMinute * DmTime.MINUTE
                if (now >= DmTimers.deadlineSeconds(authorMinute, ttl)) {
                    return@transaction Sent(Outcome.DEADLINE_PASSED, false)
                }
                val session = sessions.current(tx.sql, row.contactId)
                if (session == null || isStale(session, now)) {
                    if (session != null) demoteForReestablishment(tx, row.contactId, now)
                    messages.setItemState(tx, itemId, STATE_FAILED, MessageStore.ITEM_PENDING)
                    messages.setMessageState(tx, itemId, STATE_FAILED, MessageStore.STATE_QUEUED)
                    messages.insertPendingSend(tx, itemId, row.contactId, item.deadlineHour)
                    return@transaction Sent(Outcome.QUEUED, establish = true)
                }
                messages.setItemState(tx, itemId, STATE_FAILED, MessageStore.ITEM_PENDING)
                messages.setMessageState(tx, itemId, STATE_FAILED, MessageStore.STATE_QUEUED)
                val outcome = sealAndEnqueue(
                    tx = tx,
                    self = self,
                    contact = contact,
                    prepared = prepared,
                    session = session,
                    itemId = itemId,
                    l0 = l0,
                    bucket = decoded.content.bucket,
                    authorMinute = authorMinute,
                    now = now,
                    operationId = operationId,
                    deadlineHour = item.deadlineHour,
                    ttl = ttl,
                    credentials = credentials,
                )
                when (outcome) {
                    SealOutcome.OK -> Sent(Outcome.QUEUED, establish = false)
                    SealOutcome.NO_SEAL_KEY, SealOutcome.INVALID_SESSION -> {
                        if (outcome == SealOutcome.INVALID_SESSION) {
                            sessions.deleteSessions(tx, row.contactId)
                        } else {
                            demoteForReestablishment(tx, row.contactId, now)
                        }
                        messages.insertPendingSend(tx, itemId, row.contactId, item.deadlineHour)
                        Sent(Outcome.QUEUED, establish = true)
                    }
                    SealOutcome.UNAVAILABLE -> Sent(Outcome.CRYPTO_UNAVAILABLE, false)
                }
            }
        } catch (e: InsufficientReplicasException) {
            Sent(Outcome.NO_REPLICAS, establish = false)
        } catch (e: StorageFullException) {
            Sent(Outcome.STORAGE_FULL, establish = false)
        }
    }

    // ----------------------------------------------------------------- RESEND

    /**
     * §7.5: the automatic **identical-bytes** resend of an INDETERMINATE op (G-7, C-15).
     *
     * The bytes are the retained ones, never a re-encryption: a second ratchet step would produce
     * a second ciphertext the recipient would have to dedup at D3 instead of at D1, and would cost
     * a message key for nothing (mutant MC-3). At most two, only while `now < resendNotAfter` and
     * before the op's deadline — both checked by the caller against the Phase 7 contract — and
     * only while the contact is `unverified` or `verified` (§22.8.5 rule 2).
     *
     * **It runs in the caller's transaction, which is OUTCOME's** (§7.5, §7.8). `Outbox.release`
     * answers true exactly once per operation, so the release and the new op have to commit
     * together: a resend in a second transaction is lost for good if the process dies between the
     * two — the op is released, the item is still `enqueued`, no op carries it, and nothing looks
     * for it again. That is the structural invariant of §15 ("every `pending` or `enqueued` item
     * has a pending send or an unreleased op") broken by a crash, which is exactly the class of
     * bug §7.8 is about. The `Outbox.enqueue` call site stays in this file, which is what gate
     * G-DM2 reads.
     *
     * **Why the enqueue goes first, and which failure is caught.** `InsufficientReplicasException`
     * is raised by the quorum check before `enqueue` writes anything (`OutboxStore.enqueue` step
     * 1), so swallowing it leaves the caller's transaction untouched and the item ends
     * `indeterminate` — "may not have been delivered", which is what is true when this week's slot
     * table cannot give two operators. `StorageFullException` is a failed **write** and is
     * deliberately **not** caught: it rolls the release back with everything else, and the outcome
     * is offered again at the next pass, which is the right answer to a full disk and the wrong
     * answer to give a user as "indeterminate". Nothing else is written before the enqueue, so
     * there is nothing to undo either way.
     */
    @Suppress("LongParameterList")
    fun resend(
        tx: SyncTransaction,
        contactId: ByteArray,
        previousOperationId: ByteArray,
        namespace: ByteArray,
        blob: ByteArray,
        ttl: TtlBucket,
        deadlineHour: Long,
        itemId: ByteArray,
        resendCount: Int,
    ): Boolean {
        val contact = contacts.contact(tx.sql, contactId) ?: return false
        if (!maySend(contact.trust)) return false
        val operationId = random.bytes(OperationId.SIZE)
        try {
            sync.outbox.enqueue(
                tx,
                OutboundBlob(
                    OperationId(operationId),
                    NamespaceId(namespace),
                    blob,
                    ttl,
                    deadlineEpochSeconds = deadlineHour,
                ),
            )
        } catch (e: InsufficientReplicasException) {
            return false
        }
        messages.insertItemOp(tx, operationId, itemId, blob, resendCount + 1, deadlineHour)
        messages.clearOpBlob(tx, previousOperationId)
        return true
    }

    // ---------------------------------------------------------------- planning

    /** Everything the first phase read, so the second can act without reading it again. */
    private class Prepared(
        val card: ByteArray,
        val conversation: ContactStore.ConversationRow,
        val inboxNamespace: ByteArray,
        val minuteIndex: Int,
        val timerCode: Int,
        val timerVersion: Long,
        val offer: PendingOffer?,
        /**
         * The generation a **new** root offer would take, when the planning read found no
         * unacknowledged one to re-attach and the caller asked for one. The offer itself is minted
         * between the two transactions and written by the second; see [mintOffer].
         */
        val nextRootGen: Int?,
        val week: Long,
        val set: List<EsSlot>,
        val needCredential: Set<Long>,
    )

    /** A root offer waiting to ride on the next normal-output send (§6.3, R-C3). */
    private class PendingOffer(val rootGen: Int, val offerEnv: ByteArray)

    /**
     * A root offer this send minted and the second transaction has to write: the offer row and the
     * **in** recognition key of its base week (§6.3, rule R-S5).
     */
    private class MintedOffer(
        val rootGen: Int,
        val rootEnv: ByteArray,
        val offerEnv: ByteArray,
        val baseWeek: Long,
        val keys: List<DmPairing.WeekKey>,
    )

    private class Plan(val refusal: Outcome?, val prepared: Prepared?)

    @Suppress("LongParameterList", "ReturnCount")
    private fun plan(
        tx: SyncTransaction,
        contactId: ByteArray,
        kind: DmContent.Kind,
        timerCode: Int?,
        now: Long,
        createOffer: Boolean,
    ): Plan {
        val contact = contacts.contact(tx.sql, contactId)
            ?: return Plan(Outcome.UNKNOWN_CONTACT, null)
        // S1, before any native session call: sessions exist only for the pinned identity (§8.2).
        refusalFor(contact.trust)?.let { return Plan(it, null) }
        val conversation = contacts.conversation(tx.sql, contactId)
            ?: return Plan(Outcome.UNKNOWN_CONTACT, null)
        val card = material.card(contact) ?: return Plan(Outcome.CRYPTO_UNAVAILABLE, null)
        val namespaces = material.namespaces(card) ?: return Plan(Outcome.CRYPTO_UNAVAILABLE, null)
        val week = DmTime.week(now)
        val set = relays.forNamespace(namespaces.inbox, week)
            ?: return Plan(Outcome.NO_REPLICAS, null)

        val current = sessions.current(tx.sql, contactId)
        // §21.3 point 1: a root never rides in a PreKey message, and an unacknowledged session's
        // output is one — `acknowledged` is exactly vodozemac's `has_received_message()`.
        var offer: PendingOffer? = null
        var nextRootGen: Int? = null
        if (createOffer && current != null && current.acknowledged) {
            val offers = contacts.pairOffers(tx.sql, contactId)
            // §6.3's replacement rule (c), added by S8: `week(now) ≥ base_week +
            // ROOT_REPLACE_WEEKS` for my **newest** root for this contact, acknowledged or not.
            //
            // Triggers (a) and (b) — a restore, and a KEYDEC acceptance — are already here by
            // construction: a restored device has no offer rows at all, and KEYDEC erases the
            // secrets of the ones it has, so the `live` search below finds nothing and a new
            // generation is minted. (c) is the one that needs a clock, and without it a root
            // acknowledged once is never replaced: a stolen device's state would open every pair
            // envelope of that conversation for as long as it lasted, which is exactly the window
            // the bound exists to close.
            val newest = offers.maxByOrNull { it.rootGen }
            val expired = newest != null && week >= newest.baseWeek + ROOT_REPLACE_WEEKS
            val live = if (expired) {
                null
            } else {
                offers.firstOrNull { !it.acknowledged && it.offerEnv != null }
            }
            if (live != null) {
                offer = PendingOffer(live.rootGen, requireNotNull(live.offerEnv))
            } else {
                // An unacknowledged offer whose bytes are gone is one this device already erased;
                // a new generation is what §21.3 point 3 asks for, not a second offer of the same
                // one. The generation is decided here, but nothing is written: this transaction is
                // the planning read, and §7.2's "each step is exactly one transaction" means a
                // send that ends `TOO_LARGE`, `NO_REPLICAS` or rolled back must leave no offer and
                // no recognition key behind.
                val rootGen = (offers.maxOfOrNull { it.rootGen } ?: -1) + 1
                if (rootGen <= MAX_ROOT_GEN) nextRootGen = rootGen
            }
        }

        val inboxNs = NamespaceId(namespaces.inbox)
        val needCredential = set.filter { slot ->
            val installed = sync.capabilities.installed(tx, slot.relay, inboxNs, CapabilityKind.WRITE)
            installed == null ||
                installed.state != InstalledCapability.State.USABLE ||
                (installed.expiresHour ?: Long.MAX_VALUE) - now < CREDENTIAL_REFRESH_SECONDS
        }.map { it.relay.value }.toSet()

        val authorMinute = DmTime.floorMinute(now)
        return Plan(
            null,
            Prepared(
                card = card,
                conversation = conversation,
                inboxNamespace = namespaces.inbox,
                minuteIndex = messages.nextMinuteIndex(
                    sql = tx.sql,
                    conversationId = conversation.conversationId,
                    authorMinute = authorMinute,
                    nowMinute = authorMinute,
                ),
                timerCode = timerCode ?: conversation.timerCode,
                timerVersion = if (kind == DmContent.Kind.TIMER_SET) {
                    conversation.timerVersion + 1
                } else {
                    conversation.timerVersion
                },
                offer = offer,
                nextRootGen = nextRootGen,
                week = week,
                set = set,
                needCredential = needCredential,
            ),
        )
    }

    /**
     * §6.3: the root this device offers for `c → me`, created at the first send whose output is a
     * normal message and re-attached, byte for byte, until a pair envelope under it opens (§9.4's
     * `offer_env` is stored for exactly that reason).
     *
     * It is **minted between the two transactions** and written by the second ([writeOffer]), with
     * the relay set and the deposit credentials, for the reason the class comment gives: the
     * planning transaction is a read, and a native call inside a writing transaction commits half
     * a step while reporting an error. The generation was decided by the planning read as
     * `1 + max(root_gen)` over the contact's rows (§21.3 point 3), so it never repeats on a device
     * that kept the contact and the peer's "a `root_gen` not greater than the stored one is
     * ignored" rule cannot reject it.
     */
    private fun mintOffer(contactId: ByteArray, prepared: Prepared): MintedOffer? {
        val rootGen = prepared.nextRootGen ?: return null
        val created = envelopes.pairOffer(contactId, rootGen, prepared.week)
        if (created !is DmPairing.OfferResult.Ok) return null
        // The **in** key of the base week exists from the moment the root does, so a pair envelope
        // that arrives before the next maintenance pass is recognisable (§6.3, rule R-S5).
        val keys = envelopes.pairKeys(
            contactId = contactId,
            direction = DmSeal.PairDirection.IN,
            rootGen = rootGen,
            from = DmPairing.From.ROOT,
            keyEnv = created.offer.rootEnv,
            baseWeek = prepared.week,
            fromWeek = prepared.week,
            toWeek = prepared.week,
        )
        return MintedOffer(
            rootGen = rootGen,
            rootEnv = created.offer.rootEnv,
            offerEnv = created.offer.offerEnv,
            baseWeek = prepared.week,
            keys = if (keys is DmPairing.KeysResult.Ok) keys.weeks else emptyList(),
        )
    }

    /** The offer rows of [mintOffer], written inside the one transaction the send commits. */
    private fun writeOffer(tx: SyncTransaction, contactId: ByteArray, minted: MintedOffer) {
        contacts.insertPairOffer(
            tx = tx,
            contactId = contactId,
            rootGen = minted.rootGen,
            rootEnv = minted.rootEnv,
            offerEnv = minted.offerEnv,
            baseWeek = minted.baseWeek,
        )
        for (key in minted.keys) {
            contacts.putPairKey(
                tx = tx,
                contactId = contactId,
                direction = ContactStore.DIRECTION_IN,
                rootGen = minted.rootGen,
                week = key.week,
                recognitionKey = key.recognitionKey,
                openEnv = key.openEnv,
            )
        }
    }

    /** The deposit credentials of the relays that need one, minted outside the transaction. */
    private fun depositCredentials(prepared: Prepared): Map<Long, ByteArray>? {
        val out = LinkedHashMap<Long, ByteArray>()
        for (slot in prepared.set) {
            if (slot.relay.value !in prepared.needCredential) continue
            val derived = material.fromCard(prepared.card, slot.slot) ?: return null
            out[slot.relay.value] = try {
                CredentialV3.credential(
                    CredentialV3.Kind.DEPOSIT,
                    slot.slot,
                    prepared.inboxNamespace,
                    derived.deposit,
                )
            } finally {
                derived.clearSecrets()
            }
        }
        return out
    }

    // ----------------------------------------------------------------- commit

    @Suppress("LongParameterList", "ReturnCount", "LongMethod")
    private fun commit(
        self: SelfContext,
        contactId: ByteArray,
        kind: DmContent.Kind,
        control: Control?,
        messageId: ByteArray,
        authorMinute: Long,
        now: Long,
        prepared: Prepared,
        l0: DmContent.Encoded.Ok,
        body: ByteArray,
        quoteRef: ByteArray?,
        credentials: Map<Long, ByteArray>,
        minted: MintedOffer?,
        scheduledId: ByteArray? = null,
    ): Sent {
        val ttl = if (kind == DmContent.Kind.TIMER_SET) {
            DmTimers.timerSetBucket(prepared.conversation.timerCode, prepared.timerCode)
        } else {
            DmTimers.bucketOf(prepared.timerCode)
        }
        val deadline = DmTimers.deadlineSeconds(authorMinute, ttl)
        val deadlineHour = DmTime.ceilHour(deadline)
        val failAfterHour = DmTime.ceilHour(
            minOf(authorMinute + DmTimers.DEADLINE_CAP_SECONDS, deadline),
        )
        val bodyNonce = random.bytes(ContentCipher.NONCE_BYTES)
        val l0Nonce = random.bytes(ContentCipher.NONCE_BYTES)
        val operationId = random.bytes(OperationId.SIZE)

        return try {
            database.transaction { tx ->
                // The scheduled row this send discharges, retired **first** and inside this
                // transaction (§8.5, §8.6, and the S7 RESEND precedent). It goes whatever the rest
                // of the transaction decides, including a refusal below: a contact blocked between
                // the drawn minute and now is one the user's own later action supersedes, and the
                // notice must not be re-offered for ever. What must **not** delete it is a
                // transient failure, and none of those reaches this transaction — they are
                // refused before it opens, or they throw and roll it back (see `runDue`).
                scheduledId?.let { scheduled.deleteScheduled(tx, it) }
                // §8.6: "a `dm_scheduled` row … (skipped if the user sends to that contact
                // earlier)". A user send with no usable session **is** the intro PreKey message
                // the reconnect notice would have caused, so the row goes with it; a control is
                // not a user send and does not skip it.
                if (control == null) {
                    scheduled.deleteScheduledOfKind(tx, contactId, HeldStore.WHAT_RECONNECT)
                }

                val contact = contacts.contact(tx.sql, contactId)
                    ?: return@transaction Sent(Outcome.UNKNOWN_CONTACT, false)
                refusalFor(contact.trust)?.let { return@transaction Sent(it, false) }

                // The root offer this send attached, written here and nowhere earlier: the L0 that
                // carries it is in this transaction's item row, so the offer and its bytes commit
                // together or not at all (§7.2, §6.3).
                minted?.let { writeOffer(tx, contactId, it) }

                // S3: the message row (TEXT and TIMER_SET only) and the item row (every kind).
                if (kind == DmContent.Kind.TEXT || kind == DmContent.Kind.TIMER_SET) {
                    messages.insertMessage(
                        tx = tx,
                        messageId = messageId,
                        conversationId = prepared.conversation.conversationId,
                        outgoing = true,
                        kind = kind.wire,
                        authorMinute = authorMinute,
                        sortMinute = authorMinute,
                        minuteIndex = prepared.minuteIndex,
                        timerCode = prepared.timerCode,
                        bodyEnv = if (kind == DmContent.Kind.TEXT) {
                            self.content.seal(bodyNonce, messageId, bodyPlain(quoteRef, body))
                        } else {
                            null
                        },
                        state = MessageStore.STATE_QUEUED,
                        expireAtMinute = DmTimers.senderExpireMinute(now, prepared.timerCode),
                        unreadDeadlineMinute = null,
                    )
                }
                if (kind == DmContent.Kind.TIMER_SET) {
                    contacts.adoptTimer(
                        tx,
                        prepared.conversation.conversationId,
                        prepared.timerCode,
                        prepared.timerVersion,
                    )
                }
                if (kind == DmContent.Kind.REACTION) {
                    messages.putReaction(
                        tx = tx,
                        targetId = reactionTarget(body),
                        fromSelf = true,
                        graphemeEnv = self.content.seal(
                            bodyNonce,
                            reactionTarget(body),
                            body.copyOfRange(REACTION_TARGET_BYTES, body.size),
                        ),
                    )
                }
                messages.insertItem(
                    tx = tx,
                    itemId = messageId,
                    contactId = contactId,
                    // §21.8 point 1: TEXT and TIMER_SET point at themselves, a REACTION at its
                    // target, and a CONTROL at nothing — it has no `dm_message` row to point at,
                    // which is what `CHECK (kind = 4 OR message_ref IS NOT NULL)` says.
                    messageRef = when {
                        control != null -> null
                        kind == DmContent.Kind.REACTION -> reactionTarget(body)
                        else -> messageId
                    },
                    kind = kind.wire,
                    control = control?.wire,
                    l0Env = self.content.seal(l0Nonce, messageId, l0.l0),
                    deadlineHour = deadlineHour,
                    state = MessageStore.ITEM_PENDING,
                )

                // S4: no usable session, so the item waits and the caller runs `EST-START`.
                val current = sessions.current(tx.sql, contactId)
                if (current == null || isStale(current, now)) {
                    // R-SS0: `UNACK_MAX` demotes `current`, which is also what makes `EST-READY`'s
                    // "unless a usable session already exists" find an empty slot to fill.
                    if (current != null) demoteForReestablishment(tx, contactId, now)
                    messages.insertPendingSend(tx, messageId, contactId, failAfterHour)
                    return@transaction Sent(Outcome.QUEUED, establish = true)
                }

                when (
                    sealAndEnqueue(
                        tx = tx,
                        self = self,
                        contact = contact,
                        prepared = prepared,
                        session = current,
                        itemId = messageId,
                        l0 = l0.l0,
                        bucket = l0.bucket,
                        authorMinute = authorMinute,
                        now = now,
                        operationId = operationId,
                        deadlineHour = deadlineHour,
                        ttl = ttl,
                        credentials = credentials,
                    )
                ) {
                    SealOutcome.OK -> Sent(Outcome.QUEUED, establish = false)
                    // §6.8 rule 4: the item stays pending and the caller re-establishes. The rows
                    // written above stay — the message is the user's, and it is queued, not lost.
                    SealOutcome.NO_SEAL_KEY -> {
                        // R-SS0 again: this session cannot produce an output any more (§6.8 rule
                        // 4), so it is demoted and the establishment that follows fills the slot.
                        demoteForReestablishment(tx, contactId, now)
                        messages.insertPendingSend(tx, messageId, contactId, failAfterHour)
                        Sent(Outcome.QUEUED, establish = true)
                    }
                    // §22.8.2 rule 2 and §21.5: the session cannot encrypt again, so it goes, the
                    // item stays pending, and the next establishment builds a new one.
                    SealOutcome.INVALID_SESSION -> {
                        sessions.deleteSessions(tx, contactId)
                        messages.insertPendingSend(tx, messageId, contactId, failAfterHour)
                        Sent(Outcome.QUEUED, establish = true)
                    }
                    SealOutcome.UNAVAILABLE -> Sent(Outcome.CRYPTO_UNAVAILABLE, false)
                }
            }
        } catch (e: InsufficientReplicasException) {
            Sent(Outcome.NO_REPLICAS, establish = false)
        } catch (e: StorageFullException) {
            Sent(Outcome.STORAGE_FULL, establish = false)
        }
    }

    /** What [sealAndEnqueue] decided. */
    private enum class SealOutcome { OK, NO_SEAL_KEY, UNAVAILABLE, INVALID_SESSION }

    @Suppress("LongParameterList", "ReturnCount")
    private fun sealAndEnqueue(
        tx: SyncTransaction,
        self: SelfContext,
        contact: ContactStore.ContactRow,
        prepared: Prepared,
        session: SessionStore.SessionRow,
        itemId: ByteArray,
        l0: ByteArray,
        bucket: Int,
        authorMinute: Long,
        now: Long,
        operationId: ByteArray,
        deadlineHour: Long,
        ttl: TtlBucket,
        credentials: Map<Long, ByteArray>,
    ): SealOutcome {
        val step = when (
            val encrypted = envelopes.encrypt(
                contactId = contact.contactId,
                current = DmSessions.StoredSlot(session.sessionId, session.stateEnv),
                l0 = l0,
                today = DmTime.day(now).toInt(),
            )
        ) {
            is DmSessions.Encrypted.Ok -> encrypted
            DmSessions.Encrypted.Unavailable -> return SealOutcome.UNAVAILABLE
            DmSessions.Encrypted.InvalidSession,
            DmSessions.Encrypted.StateCorrupt,
            DmSessions.Encrypted.Oversize,
            -> return SealOutcome.INVALID_SESSION
        }

        val pinned = contact.pinnedIdentity ?: return SealOutcome.NO_SEAL_KEY
        val blob = when (
            val sealed = seal(tx, self, contact, prepared, session, step, pinned, bucket, authorMinute)
                ?: return SealOutcome.NO_SEAL_KEY
        ) {
            is DmSeal.Sealed.Ok -> sealed.blob
            DmSeal.Sealed.Unavailable -> return SealOutcome.UNAVAILABLE
            DmSeal.Sealed.InvalidKey -> return SealOutcome.NO_SEAL_KEY
            DmSeal.Sealed.StateCorrupt -> return SealOutcome.INVALID_SESSION
            // R-B1 chose the bucket from the body length before encryption and the crate asserts
            // the fit after sealing, so `NO_FIT` is a bug and never a peer's doing (§6.6); the
            // same is true of a malformed own card or row value. Both leave as exceptions and roll
            // the transaction back before the session state commits (§7.3's table).
            DmSeal.Sealed.NoFit ->
                throw IllegalStateException("a sealed DM blob does not fit its bucket")
            DmSeal.Sealed.NonCanonical, DmSeal.Sealed.InvalidCard ->
                throw IllegalStateException("the own card or a row value is malformed")
        }

        // The ratchet step commits here, with the op, and never without it (CS-1).
        sessions.setStateEnv(tx, contact.contactId, session.slot, step.stateEnv)
        if (step.acknowledged) sessions.acknowledge(tx, contact.contactId, session.slot)

        // S7: the namespace and the deposit credential, idempotently (§7.3).
        val inboxNs = NamespaceId(prepared.inboxNamespace)
        sync.namespaces.register(
            tx = tx,
            namespace = inboxNs,
            consumer = Consumer.DM,
            relays = prepared.set.map { it.relay }.toSet(),
            listen = false,
            sendDelay = SendDelay.DEFAULT,
            capabilitySource = CapabilitySource.LOCAL,
        )
        for (slot in prepared.set) {
            val credential = credentials[slot.relay.value] ?: continue
            sync.capabilities.put(
                tx,
                slot.relay,
                inboxNs,
                CapabilityKind.WRITE,
                credential,
                DmTime.ceilHour(now) + CREDENTIAL_LIFETIME_SECONDS,
            )
        }

        messages.insertItemOp(tx, operationId, itemId, blob, 0, deadlineHour)
        messages.setItemState(tx, itemId, MessageStore.ITEM_PENDING, MessageStore.ITEM_ENQUEUED)
        sync.outbox.enqueue(
            tx,
            OutboundBlob(
                OperationId(operationId),
                inboxNs,
                blob,
                ttl,
                deadlineEpochSeconds = DmTimers.deadlineSeconds(authorMinute, ttl),
            ),
        )
        return SealOutcome.OK
    }

    /** §6.8, in the order the rule gives: intro, pair, provisional, `NO_SEAL_KEY`. */
    @Suppress("LongParameterList", "ReturnCount")
    private fun seal(
        tx: SyncTransaction,
        self: SelfContext,
        contact: ContactStore.ContactRow,
        prepared: Prepared,
        session: SessionStore.SessionRow,
        step: DmSessions.Encrypted.Ok,
        pinned: ByteArray,
        bucket: Int,
        authorMinute: Long,
    ): DmSeal.Sealed? {
        if (step.isPreKey) {
            // Rule 1: every PreKey message is intro, addressed to the generation the session was
            // built on (`peer_gen_id`), whose key is in `dm_peer_pq`.
            val genId = session.peerGenId ?: return null
            val peer = contacts.peerPq(tx.sql, contact.contactId).firstOrNull { it.genId == genId }
                ?: return null
            val replySeedEnv = session.provEnv ?: return null
            val derived = material.fromCard(prepared.card, ANY_SLOT) ?: return null
            return try {
                envelopes.sealIntro(
                    cardIndex = self.cardIndex,
                    namespace = prepared.inboxNamespace,
                    bucket = bucket,
                    introKeyEnv = derived.introKeyEnv,
                    peerIdentityPk = contact.identityPk,
                    peerOlmIdentity = pinned,
                    genId = genId,
                    genPublic = peer.xwingPublic,
                    // §21.4 point 1: the sealing minute, not the compose minute — a pending send
                    // may be sealed days after the user wrote it.
                    bindingMinute = DmTime.floorMinute(clock.nowEpochSeconds()) / DmTime.MINUTE,
                    sessionId = session.sessionId,
                    replySeedEnv = replySeedEnv,
                    l1 = step.l1,
                )
            } finally {
                derived.clearSecrets()
            }
        }

        // Rule 2: a normal message with an out pair key for the author's own week. R9 on the
        // other side requires `week(author_minute)` to equal the key's week (binding B1).
        val week = DmTime.week(authorMinute)
        val outKey = contacts.pairKeys(tx.sql, contact.contactId, ContactStore.DIRECTION_OUT)
            .firstOrNull { it.week == week }
        if (outKey != null) {
            val sealed = envelopes.sealPair(
                namespace = prepared.inboxNamespace,
                bucket = bucket,
                openEnv = outKey.openEnv,
                contactId = contact.contactId,
                rootGen = outKey.rootGen,
                week = outKey.week,
                oiSender = self.olmIdentity,
                oiRecipient = pinned,
                l1 = step.l1,
            )
            // **After** the seal, never before. `pair_sent` permanently disables §6.8 rule 3 for
            // this session, and an `InvalidKey` here is a `NO_SEAL_KEY` the caller returns
            // *normally* — so the transaction commits. Writing it first would mark a session as
            // having sealed a pair envelope that was never produced, and every later normal
            // output would fall through rule 3 to `NO_SEAL_KEY` and a re-establishment.
            if (sealed is DmSeal.Sealed.Ok) sessions.markPairSent(tx, contact.contactId, session.slot)
            return sealed
        }

        // Rule 3: provisional, while the session holds a `reply_seed`, no pair envelope was ever
        // sealed on it, and its anchor is inside 28 days (§22.8.5 rule 3).
        val provEnv = session.provEnv ?: return null
        if (session.pairSent) return null
        val nowSeconds = clock.nowEpochSeconds()
        val anchor = session.provAnchorMinute
        if (anchor != null && nowSeconds >= anchor + PROVISIONAL_SEAL_WINDOW_SECONDS) return null
        val keys = envelopes.provisionalKeys(
            contactId = contact.contactId,
            sessionId = session.sessionId,
            stateEnv = step.stateEnv,
            replySeedEnv = provEnv,
            peerOlmIdentity = pinned,
        )
        if (keys !is DmPairing.ProvisionalResult.Ok) return null
        val sealed = envelopes.sealProvisional(
            namespace = prepared.inboxNamespace,
            bucket = bucket,
            openEnv = keys.keys.outEnv,
            direction = keys.keys.outDirection,
            sessionId = session.sessionId,
            oiSender = self.olmIdentity,
            oiRecipient = pinned,
            l1 = step.l1,
        )
        // §22.8.5 rule 4: a responder session's anchor is its **first provisional seal** — so it is
        // written once one exists, and not before. The anchor starts the 28-day window of rule 3,
        // and a failed seal that started it would shorten the window of the first envelope that
        // really goes out.
        if (sealed is DmSeal.Sealed.Ok && anchor == null) {
            sessions.setProvisionalAnchor(
                tx,
                contact.contactId,
                session.slot,
                DmTime.floorMinute(nowSeconds),
            )
        }
        return sealed
    }

    /**
     * One pending item, sealed and enqueued in its own transaction (§21.7 point 4).
     *
     * Three guards the first implementation did not have, each of which left an item that no later
     * pass would look at again:
     *
     *  - **the session must be usable**, not merely present: sealing onto a session the contact
     *    dropped 28 days ago produces an intro envelope addressed to a generation it may already
     *    have erased. A stale one is demoted here (R-SS0) and the item stays pending for the
     *    establishment that follows;
     *  - **the exact deadline**, because `deadline_hour` is `ceil_hour` of it and `Outbox.enqueue`
     *    refuses `deadline <= now` by throwing. An item past it is failed here rather than left to
     *    sit until `fail_after_hour`;
     *  - **`NO_SEAL_KEY` demotes** (R-SS0, §6.8 rule 4), so the next establishment has an empty
     *    `current` to fill instead of finding a session it decides is good enough.
     */
    @Suppress("ReturnCount", "LongMethod")
    private fun flushOne(self: SelfContext, contactId: ByteArray, itemId: ByteArray): Boolean {
        val now = clock.nowEpochSeconds()
        val plan = database.transaction { tx ->
            // No new root offer on this path: the L0 was encoded at the send that queued it, and
            // attaching an offer now would produce bytes nobody sealed (R-C3).
            plan(tx, contactId, DmContent.Kind.TEXT, null, now, createOffer = false)
        }
        val prepared = plan.prepared ?: return false
        val credentials = depositCredentials(prepared) ?: return false
        val operationId = random.bytes(OperationId.SIZE)
        return try {
            database.transaction { tx ->
                val contact = contacts.contact(tx.sql, contactId) ?: return@transaction false
                if (!maySend(contact.trust)) return@transaction false
                val item = messages.item(tx.sql, itemId) ?: return@transaction false
                if (item.state != MessageStore.ITEM_PENDING) return@transaction false
                val l0 = self.content.open(item.l0Env ?: return@transaction false, itemId)
                    ?: return@transaction false
                val decoded = envelopes.decodeContent(contactId, l0)
                if (decoded !is DmContent.DecodeResult.Ok) return@transaction false
                val ttl = DmTimers.bucketOf(decoded.content.timerCode)
                val authorMinute = decoded.content.authorMinute * DmTime.MINUTE
                if (now >= DmTimers.deadlineSeconds(authorMinute, ttl)) {
                    messages.failPending(tx, itemId)
                    return@transaction false
                }
                val session = sessions.current(tx.sql, contactId) ?: return@transaction false
                if (isStale(session, now)) {
                    demoteForReestablishment(tx, contactId, now)
                    return@transaction false
                }
                val outcome = sealAndEnqueue(
                    tx = tx,
                    self = self,
                    contact = contact,
                    prepared = prepared,
                    session = session,
                    itemId = itemId,
                    l0 = l0,
                    bucket = decoded.content.bucket,
                    authorMinute = authorMinute,
                    now = now,
                    operationId = operationId,
                    deadlineHour = item.deadlineHour,
                    ttl = ttl,
                    credentials = credentials,
                )
                if (outcome == SealOutcome.NO_SEAL_KEY) {
                    demoteForReestablishment(tx, contactId, now)
                    return@transaction false
                }
                if (outcome == SealOutcome.INVALID_SESSION) {
                    sessions.deleteSessions(tx, contactId)
                    return@transaction false
                }
                if (outcome != SealOutcome.OK) return@transaction false
                messages.deletePendingSend(tx, itemId)
                true
            }
        } catch (e: InsufficientReplicasException) {
            // Both are retried, which is why the item keeps its `dm_pending_send` row: §21.7 point
            // 4 names `StorageFullException` explicitly ("retried at the next time-triggered
            // pass") and a week whose slot table cannot span two operators is the same shape of
            // transient. The retry is [flushStranded]'s, which visits every contact with pending
            // items and not only the ones still fetching.
            false
        } catch (e: StorageFullException) {
            false
        }
    }


    // --------------------------------------------------------------- internals

    /**
     * §21.8 point 6: `body_env = AEAD(flags(1) || quote_ref(0 | 16) || body)`.
     *
     * The quote reference lives **inside** the envelope and never in a column of its own: a
     * plaintext column equal to a quoted `message_id` fails the T25 physical scan legitimately,
     * while content inside `body_env` is invisible to a byte scan.
     */
    private fun bodyPlain(quoteRef: ByteArray?, body: ByteArray): ByteArray {
        val out = ByteArray(1 + (quoteRef?.size ?: 0) + body.size)
        out[0] = (if (quoteRef != null) FLAG_HAS_QUOTE else 0).toByte()
        var at = 1
        quoteRef?.let { it.copyInto(out, at); at += it.size }
        body.copyInto(out, at)
        return out
    }

    /** A REACTION body is `target message_id(16) || grapheme` (§7.1). */
    private fun reactionTarget(body: ByteArray): ByteArray {
        require(body.size >= REACTION_TARGET_BYTES) { "a reaction names no target" }
        return body.copyOf(REACTION_TARGET_BYTES)
    }

    /**
     * §8.7: an **initiator** session unacknowledged for `UNACK_MAX = 28 days` is stale, and the
     * next user send re-establishes. There is no time-triggered re-establishment (T28, T31).
     *
     * The predicate itself is [SessionSlots.isStale], because `EST-READY` and the pending flush
     * have to read it the same way (§21.7 point 4's "unless a **usable** session already exists").
     */
    private fun isStale(session: SessionStore.SessionRow, now: Long): Boolean =
        SessionSlots.isStale(session, now)

    /**
     * R-SS0 (§8.2): "a re-establishment caused by `UNACK_MAX` or `NO_SEAL_KEY` demotes `current`
     * to `previous` (the peer may still answer it) and deletes the old `previous`."
     *
     * It runs **where the re-establishment is decided** — the send, the retry or the flush that
     * found the session unusable — and not in `EST-READY`, so that the slot the establishment then
     * fills is empty by the time it looks: without it, `EST-READY` sees a row, decides a usable
     * session already exists, throws the fetched candidate away and leaves the conversation on a
     * session that can never send again. The demoted row keeps receiving until its `retire_day`.
     */
    private fun demoteForReestablishment(tx: SyncTransaction, contactId: ByteArray, now: Long) {
        slots.demoteForReestablishment(tx, contactId, DmTime.day(now))
    }

    private fun maySend(trust: ContactStore.Trust): Boolean =
        trust == ContactStore.Trust.UNVERIFIED || trust == ContactStore.Trust.VERIFIED

    private fun refusalFor(trust: ContactStore.Trust): Outcome? = when (trust) {
        ContactStore.Trust.UNVERIFIED, ContactStore.Trust.VERIFIED -> null
        ContactStore.Trust.CHANGED -> Outcome.KEY_CHANGED
        ContactStore.Trust.BLOCKED -> Outcome.BLOCKED
        ContactStore.Trust.REVOKED -> Outcome.REVOKED
        ContactStore.Trust.REQUEST -> Outcome.REQUEST_NOT_ACCEPTED
    }

    companion object {
        /** `dm_message.message_id` and `dm_outbound_item.item_id`: the same 16 random bytes. */
        const val MESSAGE_ID_BYTES: Int = 16

        /** §22.8.5 rule 3: provisional sealing stops 28 days after the session's anchor. */
        const val PROVISIONAL_SEAL_WINDOW_SECONDS: Long = 28 * DmTime.DAY

        /** The deposit credential's lifetime, as §4.8 gives the owner's READ credential. */
        const val CREDENTIAL_LIFETIME_SECONDS: Long = 8 * DmTime.DAY

        /** Refreshed when fewer than 7 days remain (§4.8, §21.2 point 7). */
        const val CREDENTIAL_REFRESH_SECONDS: Long = 7 * DmTime.DAY

        /** `flags` bit 0 of a `body_env` (§7.1). */
        const val FLAG_HAS_QUOTE: Int = 0x01

        /** A REACTION body starts with the target's `message_id` (§7.1). */
        const val REACTION_TARGET_BYTES: Int = 16

        /** `dm_pair_offer.root_gen` is a `u16` (§13.6). */
        const val MAX_ROOT_GEN: Int = 65_535

        /**
         * §6.3's `ROOT_REPLACE_WEEKS`: **13** without PQ-C, 4 with it (slice S13, Q49).
         *
         * It bounds a stolen-state window. A pair root opens every pair envelope of its
         * conversation from its base week onwards, so a seizer of either device reads that much of
         * the history whatever the ratchet did; replacing it means the seizure reaches back at
         * most this far. Q68 asks for one week, and S13's four is the PQ-C cadence — this is the
         * value §6.3 gives for a client without PQ-C, which Phase 9 ships.
         */
        const val ROOT_REPLACE_WEEKS: Long = 13

        /** `dm_outbound_item.state` and `dm_message.state` for a decided-FAILED item (§13.5). */
        const val STATE_FAILED: String = "failed"

        /** The namespaces a card derives are slot-independent (§21.2 point 1). */
        private const val ANY_SLOT: Int = 0

        private val EMPTY = ByteArray(0)
    }
}
