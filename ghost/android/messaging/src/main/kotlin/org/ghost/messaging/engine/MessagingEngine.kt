package org.ghost.messaging.engine

import org.ghost.crypto.bridge.DmContent
import org.ghost.messaging.api.ActivationOutcome
import org.ghost.messaging.api.AddContactResult
import org.ghost.messaging.api.CardExport
import org.ghost.messaging.api.CardSource
import org.ghost.messaging.api.ContactId
import org.ghost.messaging.api.ContactView
import org.ghost.messaging.api.Establishment
import org.ghost.messaging.api.MaintenanceReport
import org.ghost.messaging.api.ChangeKind
import org.ghost.messaging.api.Messaging
import org.ghost.messaging.api.MessagingListener
import org.ghost.messaging.api.MessagingStatus
import org.ghost.messaging.api.MessageCursor
import org.ghost.messaging.api.MessageId
import org.ghost.messaging.api.MessageKind
import org.ghost.messaging.api.MessageState
import org.ghost.messaging.api.MessageView
import org.ghost.messaging.api.MediaPreview
import org.ghost.messaging.api.MediaHandle
import org.ghost.messaging.api.MediaSendResult
import org.ghost.messaging.api.MediaStateView
import org.ghost.messaging.api.MediaSource
import org.ghost.messaging.api.NotificationPort
import org.ghost.messaging.api.PreparationId
import org.ghost.messaging.api.PreparationView
import org.ghost.messaging.api.RevocationReason
import org.ghost.messaging.api.SafetyNumberView
import org.ghost.messaging.api.SendResult
import org.ghost.messaging.api.Timer
import org.ghost.messaging.api.TrustState
import org.ghost.messaging.api.VerifyResult
import org.ghost.messaging.port.DmClock
import org.ghost.messaging.store.ContactStore
import org.ghost.messaging.store.MessageStore
import org.ghost.sync.api.SyncDatabase

/**
 * The DM engine behind the facade (Phase 9 design §13.1 `…messaging.engine`), at the size slices
 * S6, S7 and S8 give it: the owner side; contacts, sending and receiving; and trust, reset,
 * reconnect and revocation.
 *
 * **Every method posts to the DM actor** (§13.7, §13.2): one thread owns every `:messaging`
 * transaction and every session call, which is what the value-state rule of §7.9 point 3 needs
 * and what makes the two-phase shape of SEND and the establishment steps sound.
 *
 * It holds no state of its own beyond the steps; each step's own guard makes a repeated call
 * idempotent, and the pass order between them is [DmActor]'s.
 */
internal class MessagingEngine(
    private val database: SyncDatabase,
    private val steps: OwnerSteps,
    private val contactSteps: ContactSteps,
    private val sendStep: SendStep,
    private val establishment: EstablishmentSteps,
    private val keyDecision: KeyDecision,
    private val heldReplay: HeldReplay,
    private val scheduledSteps: ScheduledSteps,
    /** DISPLAY (§7.2, §10.3): the recipient's countdown starts at the first display. */
    private val displayStep: DisplayStep,
    /** §7.2's "After commit" column, which DISPLAY owes exactly as a pass does. */
    private val schedule: ExpirySchedule,
    private val counters: DmCounters,
    private val clock: DmClock,
    private val contexts: SelfContexts,
    /**
     * Only so that [onActivated] and [onRestored] can drop its cache: §2.5's "drops every cached
     * key … the identity changed". `SelfContexts.invalidate()` alone left the previous identity's
     * derived provisional session keys live in the process heap across the `clearForeignIdentity`
     * branch of ACTIVATE (found by the S8 review).
     */
    private val recognition: RecognitionKeys,
    /** Phase 11 §6.5's media half; null where the sender pipeline is not wired (Phase 9 worlds). */
    private val media: MediaEngineSupport? = null,
) : Messaging {

    private val contacts = ContactStore()
    private val messages = MessageStore()
    private val expiry = ExpiryClock(database, clock)

    /**
     * The actor every method posts to. It is set after construction because the actor needs the
     * engine's own maintenance entry point, which §21.9 rule 1 gives three triggers and which
     * gate G-DM2 lets only the actor and the app wiring call.
     */
    @Volatile
    private var actor: DmActor? = null

    /** Wires the actor. Called once, by `MessagingWiring` (slice S12) or by a test world. */
    fun attach(actor: DmActor) {
        this.actor = actor
    }

    /**
     * Runs [body] on the actor (§13.7), or inline when no actor is attached (a test world that
     * drives its passes directly).
     *
     * **Not `actor?.call(body) ?: body()`**, which is what this was until slice S12 attached the
     * first real actor: the Elvis operator reads a `null` *result* as "no actor", so every facade
     * method that answers null — `myCard()` on a closed context, `safetyNumber` of an unknown
     * contact, `issueRevocation` that could not issue — ran its body a **second time, on the
     * caller's thread**, which is exactly the second DM thread §7.9 point 3 forbids.
     */
    private fun <T> onActor(body: () -> T): T {
        val attached = actor ?: return body()
        return attached.call(body)
    }

    // ------------------------------------------------------------- owner side

    override fun myCard(): CardExport? =
        onActor { steps.myCard()?.let { CardExport(it.card, it.link) } }

    override fun onActivated(): ActivationOutcome = onActor {
        val result = ActivationOutcome.of(steps.activate(restored = false))
        forgetCachedKeys()
        hint(ChangeKind.STATUS, ChangeKind.CONTACTS)
        result
    }

    override fun onRestored(): ActivationOutcome = onActor {
        val result = ActivationOutcome.of(steps.activate(restored = true))
        forgetCachedKeys()
        hint(ChangeKind.STATUS, ChangeKind.CONTACTS)
        result
    }

    /** §2.5: the identity may have changed under us, so every cached key goes. */
    private fun forgetCachedKeys() {
        contexts.invalidate()
        recognition.clear()
    }

    /**
     * OWNER-WEEK, then KEEPER, then REGROWS (§13.7's pass order for the time-triggered steps).
     *
     * The order matters in one direction only, and it is this one: OWNER-WEEK may move the bundle
     * week, KEEPER then recomputes the relay sets and installs the READ credential for the set as
     * it now is, and REGROWS finally records the registrations for those relays. Reversed, a week
     * change would leave a registration row for a relay the owner no longer reads from until the
     * next pass.
     *
     * **§4.8's healing rule is KEEPER's because of this order** (mutant MC-14). KEEPER decides
     * whether a refused own READ credential is re-put, and a step that ran after it would only
     * ever see the credential KEEPER had just made usable again.
     *
     * Each step's own guard makes the pass idempotent: a second pass in the same week, on the
     * same slot table, with credentials that are not near expiry, writes nothing at all.
     */
    override fun runOwnerMaintenance(): MaintenanceReport = onActor {
        MaintenanceReport(
            ownerWeek = steps.ownerWeek(),
            keeper = steps.keeper(),
            regrows = steps.regrows(),
        )
    }

    // --------------------------------------------------------------- contacts

    override fun addContact(card: ByteArray, source: CardSource): AddContactResult =
        onActor { AddContactResult.of(contactSteps.addContact(card, source.toStore())) }

    override fun contacts(): List<ContactView> = onActor {
        contactSteps.contacts().map { view ->
            ContactView(
                id = ContactId(view.contactId),
                trust = trustOf(view.trust),
                establishment = establishmentOf(view.establishment),
                source = sourceOf(view.source),
                resetNeeded = view.resetNeeded,
            )
        }
    }

    override fun conversation(
        contact: ContactId,
        limit: Int,
        before: MessageCursor?,
    ): List<MessageView> = onActor {
        val self = contexts.get() ?: return@onActor emptyList()
        val contactId = contact.toByteArray()
        database.transaction { tx ->
            // §10.7 point 4's read filter, bound to `now_e` and not to the wall clock (R-T7):
            // after a backwards clock step the two differ, and the wall-clock bind is the one
            // that shows rows SWEEP has already decided are gone.
            val nowMinute = expiry.nowMinute(tx.sql)
            val conversation = contacts.conversation(tx.sql, contactId)
                ?: return@transaction emptyList()
            val rows = if (before == null) {
                messages.conversationPage(tx.sql, conversation.conversationId, nowMinute, limit)
            } else {
                messages.conversationPageBefore(
                    sql = tx.sql,
                    conversationId = conversation.conversationId,
                    nowMinute = nowMinute,
                    limit = limit,
                    beforeSortMinute = before.sortMinute,
                    beforeMinuteIndex = before.minuteIndex,
                    beforeMessageId = before.messageId.toByteArray(),
                )
            }
            rows.map { row -> view(self, row) }
        }
    }

    /**
     * §7.2's DISPLAY row, with the two things it owes after the commit: the notification count and
     * the rescheduled timer and alarm.
     *
     * Both run on the actor thread inside this same call — [DmActor.afterPass] never posts to
     * itself — so a UI that marks a screenful displayed has, by the time the call returns, a badge
     * that matches and a wake set to whichever of those messages expires first.
     */
    override fun markDisplayed(ids: List<MessageId>): Int = onActor {
        val displayed = displayStep.markDisplayed(ids.map { it.toByteArray() })
        if (displayed > 0) {
            schedule.afterCommit()
            hint(ChangeKind.MESSAGES)
        }
        displayed
    }

    override fun setNotificationPort(port: NotificationPort?) {
        onActor { schedule.setNotificationPort(port) }
    }

    /** Phase 13 §3.6: the UI's listener; content-free kinds after commits, on the actor thread. */
    private val uiListener = java.util.concurrent.atomic.AtomicReference<MessagingListener?>()

    override fun setListener(listener: MessagingListener?) {
        uiListener.set(listener)
    }

    /**
     * Emits [kinds] to the listener, if any. Called at the END of the committing pass, still on
     * the actor thread, so a UI that acted on a call sees the hint before the call returns. The
     * listener must hand off and return (the UI's hub tryEmits; §13.7's hand-off rule).
     */
    private fun hint(vararg kinds: ChangeKind) {
        uiListener.get()?.onChanged(kinds.toSet())
    }

    override fun acceptRequest(contact: ContactId): Boolean = onActor {
        val done = contactSteps.acceptRequest(contact.toByteArray()) == ContactSteps.RequestResult.DONE
        if (done) hint(ChangeKind.REQUESTS, ChangeKind.CONTACTS)
        done
    }

    override fun rejectRequest(contact: ContactId): Boolean = onActor {
        val done = contactSteps.rejectRequest(contact.toByteArray()) == ContactSteps.RequestResult.DONE
        if (done) hint(ChangeKind.REQUESTS)
        done
    }

    override fun blockRequest(contact: ContactId): Boolean = onActor {
        val done = contactSteps.blockRequest(contact.toByteArray()) == ContactSteps.RequestResult.DONE
        if (done) hint(ChangeKind.REQUESTS)
        done
    }

    override fun block(contact: ContactId): Boolean = onActor {
        val blocked = contactSteps.block(contact.toByteArray())
        if (blocked) hint(ChangeKind.CONTACTS, ChangeKind.TRUST)
        blocked
    }

    override fun unblock(contact: ContactId): Boolean = onActor {
        contactSteps.unblock(contact.toByteArray())
    }

    override fun deleteContact(contact: ContactId): Boolean = onActor {
        contactSteps.deleteContact(contact.toByteArray())
    }

    // ------------------------------------------------------------------- send

    override fun send(contact: ContactId, text: String, quote: MessageId?): SendResult = onActor {
        dispatch(
            contact = contact,
            kind = DmContent.Kind.TEXT,
            body = text.toByteArray(Charsets.UTF_8),
            quote = quote?.toByteArray(),
            timerCode = null,
        ).also { hint(ChangeKind.MESSAGES, ChangeKind.OUTCOMES) }
    }

    override fun react(contact: ContactId, target: MessageId, grapheme: String?): SendResult =
        onActor {
            val body = target.toByteArray() + (grapheme?.toByteArray(Charsets.UTF_8) ?: ByteArray(0))
            dispatch(
                contact = contact,
                kind = DmContent.Kind.REACTION,
                body = body,
                quote = null,
                timerCode = null,
            )
        }

    override fun setTimer(contact: ContactId, timer: Timer): SendResult = onActor {
        dispatch(
            contact = contact,
            kind = DmContent.Kind.TIMER_SET,
            body = ByteArray(0),
            quote = null,
            timerCode = timer.code,
        )
    }

    /**
     * §7.5's user retry, with the `EST-START` it owes.
     *
     * A retry that finds no usable session re-queues the item as a pending send, exactly as a
     * fresh send does — so it owes the same follow-up. Without it the retry answered `QUEUED` and
     * left an item no step would ever flush and no establishment would ever start.
     */
    override fun sendMedia(
        contact: ContactId,
        source: MediaSource,
        caption: String?,
        viewOnce: Boolean,
    ): MediaSendResult = onActor {
        val support = media ?: return@onActor MediaSendResult.Refused(SendResult.CRYPTO_UNAVAILABLE)
        val contactId = contact.toByteArray()
        val captionBytes = caption?.toByteArray(Charsets.UTF_8) ?: ByteArray(0)
        if (captionBytes.size > org.ghost.media.send.MediaSendLimits.MAX_CAPTION_BYTES) {
            return@onActor MediaSendResult.Refused(SendResult.TOO_LARGE)
        }
        // The contact checks mirror a text's (the caller's own list, §6.5): the refusal is local.
        val contactRow = database.transaction { tx -> contacts.contact(tx.sql, contactId) }
            ?: return@onActor MediaSendResult.Refused(SendResult.UNKNOWN)
        when (contactRow.trust) {
            ContactStore.Trust.BLOCKED -> return@onActor MediaSendResult.Refused(SendResult.BLOCKED)
            ContactStore.Trust.REVOKED -> return@onActor MediaSendResult.Refused(SendResult.REVOKED)
            ContactStore.Trust.REQUEST -> return@onActor MediaSendResult.Refused(SendResult.REQUEST_NOT_ACCEPTED)
            else -> Unit
        }
        // §6.1's sniff: the magic bytes decide which pipeline runs; anything else refuses before work.
        val sniffed = org.ghost.crypto.bridge.MediaCrypto.sniff(
            source.imageBytes?.copyOfRange(0, 64) ?: source.videoFirst64 ?: ByteArray(0),
        )
        val isImage = source.imageBytes != null
        if (isImage && sniffed !is org.ghost.crypto.bridge.MediaCrypto.Sniffed.Ok) {
            return@onActor MediaSendResult.Refused(SendResult.UNKNOWN)
        }
        if (!isImage && (sniffed !is org.ghost.crypto.bridge.MediaCrypto.Sniffed.Ok ||
                sniffed.type != org.ghost.crypto.bridge.MediaCrypto.SourceType.ISO_BMFF_VIDEO)
        ) {
            return@onActor MediaSendResult.Refused(SendResult.UNKNOWN)
        }
        // §6.1's header limits, before a byte is re-encoded.
        if (isImage && source.imageBytes!!.size.toLong() > org.ghost.media.send.MediaSendLimits.IMAGE_SOURCE_MAX_BYTES) {
            return@onActor MediaSendResult.Refused(SendResult.TOO_LARGE)
        }
        val conversation = database.transaction { tx -> contacts.conversation(tx.sql, contactId) }
        if (!isImage) {
            val durationUs = source.videoSource!!.durationUs()
            val shortTimer = conversation != null && conversation.timerCode == 0 // 1-hour bucket, R-MT2
            val boundMs = if (shortTimer) {
                org.ghost.media.send.MediaSendLimits.VIDEO_MAX_MS_SHORT
            } else {
                org.ghost.media.send.MediaSendLimits.VIDEO_MAX_MS
            }
            if (durationUs < 0 || durationUs / 1_000 > boundMs) {
                return@onActor MediaSendResult.Refused(SendResult.TOO_LARGE)
            }
        }
        // §6.6's free-space floor: 3 × F × 64 KiB at the largest class.
        val free = try {
            support.freeSpace()
        } catch (e: org.ghost.media.store.CiphertextFilesException) {
            -1L
        }
        if (free < org.ghost.media.send.MediaSendLimits.SEND_FREE_FLOOR) {
            return@onActor MediaSendResult.Refused(SendResult.STORAGE_FULL)
        }
        val preparation = support.newPreparationId()
        if (!support.begin(preparation)) {
            return@onActor MediaSendResult.Refused(SendResult.LIMIT_REACHED)
        }
        support.startPreparation(
            preparation = preparation,
            caption = captionBytes,
            contactId = contactId,
            run = {
                if (isImage) {
                    support.prepareImage(source.imageBytes!!, contactId, viewOnce)
                } else {
                    val shortTimer = conversation != null && conversation.timerCode == 0
                    support.prepareVideo(
                        source.videoSource!!, contactId, viewOnce,
                        maxClass = if (shortTimer) 8 else 10,
                    )
                }
            },
        )
        MediaSendResult.Queued(preparation)
    }

    override fun preparationState(preparation: PreparationId): PreparationView? =
        media?.preparationState(preparation)

    override fun retryMedia(message: MessageId): SendResult = onActor {
        media?.retryMedia(message.toByteArray()) ?: SendResult.CRYPTO_UNAVAILABLE
    }

    override fun mediaState(message: MessageId): MediaStateView? = onActor {
        media?.mediaState(message.toByteArray())
    }

    override fun setConversationOnScreen(contact: ContactId?) {
        // A volatile write, not a pass: no transaction, nothing a relay can see.
        media?.onScreen(contact?.toByteArray())
    }

    override fun mediaPreview(message: MessageId): MediaPreview? =
        // Deliberately not onActor: the gates run on the actor, the sandbox decode blocks this
        // caller (the UI's thread), never the DM actor.
        media?.preview(message.toByteArray())

    override fun openMedia(message: MessageId): MediaHandle? =
        // The same shape as mediaPreview: the gates run on the actor; the reader's native open
        // and the chunk reads run on this caller's and Media3's threads, never the DM actor.
        media?.openMedia(message.toByteArray())

    override fun openViewOnce(message: MessageId): MediaHandle? =
        // §11.2's order lives in the support: the row half on the actor, the checkpoint after
        // the commit and before the answer, the reader and the reads off it.
        media?.openViewOnce(message.toByteArray())

    override fun retry(message: MessageId): SendResult = onActor {
        val itemId = message.toByteArray()
        val sent = sendStep.retry(itemId)
        if (sent.establish) {
            contactOf(itemId)?.let { establishment.estStart(it, userRetry = true) }
        }
        SendResult.of(sent.outcome)
    }

    /** The contact an outbound item belongs to, for the `EST-START` a retry may owe. */
    private fun contactOf(itemId: ByteArray): ByteArray? =
        database.transaction { tx -> messages.item(tx.sql, itemId)?.contactId }

    /**
     * One send, and the `EST-START` that follows it when there was no usable session.
     *
     * The two are **separate transactions**, as §7.3's table says ("a separate `EST-START`
     * transaction keeps the message as a pending send"): the message is the user's and is stored
     * whatever the establishment does, and the establishment's relay work must not be able to roll
     * the message back.
     */
    private fun dispatch(
        contact: ContactId,
        kind: DmContent.Kind,
        body: ByteArray,
        quote: ByteArray?,
        timerCode: Int?,
    ): SendResult {
        val contactId = contact.toByteArray()
        val sent = sendStep.send(contactId, kind, body, quote, timerCode)
        // `userRetry`: a send starts an establishment of its own with a fresh count (§21.7 point
        // 2), so it reopens a contact the three automatic windows gave up on — "the user may
        // retry", §13.5's `unreachable → fetching` — and does not spend the budget of one that is
        // still fetching (`EstablishmentSteps.estStart`).
        if (sent.establish) establishment.estStart(contactId, userRetry = true)
        return SendResult.of(sent.outcome)
    }

    // -------------------------------------------------- trust, reset, revocation

    override fun safetyNumber(contact: ContactId): SafetyNumberView? = onActor {
        keyDecision.safetyNumber(contact.toByteArray())?.let {
            SafetyNumberView(it.digits, it.scannable)
        }
    }

    override fun pendingSafetyNumber(contact: ContactId): SafetyNumberView? = onActor {
        keyDecision.pendingSafetyNumber(contact.toByteArray())?.let {
            SafetyNumberView(it.digits, it.scannable)
        }
    }

    override fun markVerified(contact: ContactId, scanned: ByteArray): VerifyResult = onActor {
        VerifyResult.of(keyDecision.markVerified(contact.toByteArray(), scanned))
    }

    override fun markVerifiedManually(contact: ContactId): VerifyResult = onActor {
        VerifyResult.of(keyDecision.markVerifiedManually(contact.toByteArray()))
    }

    /**
     * §8.3: the acceptance and the replay it owes.
     *
     * The two are **separate transactions**, and §22.8.1 rule 2 requires it: each held row runs in
     * its own HELD transaction, so a row that drops cannot roll back the decision or the rows
     * already applied. A crash between the two leaves the decision taken and the rows held; the
     * next pass replays them, because [DmActor] runs HELD for every contact that still has live
     * held rows and is no longer `changed`.
     */
    override fun acknowledgeKeyChange(contact: ContactId): Boolean = onActor {
        val contactId = contact.toByteArray()
        val done = keyDecision.acknowledge(contactId) == KeyDecision.Outcome.DONE
        if (done) heldReplay.replay(contactId)
        done
    }

    override fun verifyKeyChange(contact: ContactId, scanned: ByteArray): VerifyResult = onActor {
        val contactId = contact.toByteArray()
        val outcome = keyDecision.verifyKeyChange(contactId, scanned)
        if (outcome == KeyDecision.Outcome.DONE) heldReplay.replay(contactId)
        VerifyResult.of(outcome)
    }

    /**
     * §8.7: the rows go, a `reset` control is queued, and the establishment that follows is the
     * one-shot bundle fetch of §5.5.
     *
     * The control is what makes the reset reach the contact at all: a session deleted on one side
     * and kept on the other produces nothing until the other side happens to write.
     */
    override fun resetSession(contact: ContactId): SendResult = onActor {
        val contactId = contact.toByteArray()
        if (!contactSteps.resetSession(contactId)) return@onActor SendResult.UNKNOWN
        val sent = sendStep.sendControl(
            contactId = contactId,
            control = SendStep.Control.RESET,
            revocation = ByteArray(0),
            sessionReset = false,
        )
        if (sent.establish) establishment.estStart(contactId, userRetry = true)
        SendResult.of(sent.outcome)
    }

    override fun reconnect(contacts: List<ContactId>): Int = onActor {
        scheduledSteps.reconnect(contacts.map { it.toByteArray() })
    }

    override fun issueRevocation(reason: RevocationReason): ByteArray? = onActor {
        scheduledSteps.issueRevocation(reason.toBridge())
    }

    override fun notifyContactsOfRevocation(certificate: ByteArray): Int = onActor {
        scheduledSteps.notifyContactsOfRevocation(certificate)
    }

    // ----------------------------------------------------------------- status

    override fun status(): MessagingStatus = onActor {
        val rows = database.transaction { tx -> contacts.contacts(tx.sql) }
        val byTrust = LinkedHashMap<TrustState, Int>()
        for (row in rows) {
            val trust = trustOf(row.trust)
            byTrust[trust] = (byTrust[trust] ?: 0) + 1
        }
        val pending = database.transaction { tx ->
            rows.sumOf { messages.pendingSends(tx.sql, it.contactId).size }
        }
        MessagingStatus(
            drops = counters.snapshot()
                .mapKeys { (reason, _) -> MessagingStatus.reasonName(reason) },
            poisoned = counters.poisonedCount(),
            contactsByTrust = byTrust,
            establishing = rows.count {
                it.establishment == ContactStore.Establishment.FETCHING
            },
            pendingSends = pending,
            pq = counters.pqSnapshot().mapKeys { (event, _) -> MessagingStatus.pqEventName(event) },
        )
    }

    // -------------------------------------------------------------- internals

    private fun view(self: SelfContext, row: MessageStore.MessageRow): MessageView {
        val plain = row.bodyEnv?.let { self.content.open(it, row.messageId) }
        var quote: ByteArray? = null
        var text: String? = null
        if (plain != null && plain.isNotEmpty()) {
            var at = 1
            if (plain[0].toInt() and SendStep.FLAG_HAS_QUOTE != 0 &&
                plain.size >= 1 + QUOTE_BYTES
            ) {
                quote = plain.copyOfRange(at, at + QUOTE_BYTES)
                at += QUOTE_BYTES
            }
            text = String(plain, at, plain.size - at, Charsets.UTF_8)
        }
        return MessageView(
            id = MessageId(row.messageId),
            outgoing = row.outgoing,
            kind = if (row.kind == DmContent.Kind.TEXT.wire) MessageKind.TEXT else MessageKind.TIMER_SET,
            authorMinute = row.authorMinute,
            state = MessageState.valueOf(row.state.uppercase()),
            text = text,
            quote = quote?.let { MessageId(it) },
            cursor = MessageCursor(row.sortMinute, row.minuteIndex, MessageId(row.messageId)),
        )
    }

    private fun trustOf(trust: ContactStore.Trust): TrustState = when (trust) {
        ContactStore.Trust.REQUEST -> TrustState.REQUEST
        ContactStore.Trust.UNVERIFIED -> TrustState.UNVERIFIED
        ContactStore.Trust.VERIFIED -> TrustState.VERIFIED
        ContactStore.Trust.CHANGED -> TrustState.CHANGED
        ContactStore.Trust.BLOCKED -> TrustState.BLOCKED
        ContactStore.Trust.REVOKED -> TrustState.REVOKED
    }

    private fun establishmentOf(value: ContactStore.Establishment): Establishment = when (value) {
        ContactStore.Establishment.CARD_ONLY -> Establishment.CARD_ONLY
        ContactStore.Establishment.FETCHING -> Establishment.FETCHING
        ContactStore.Establishment.READY -> Establishment.READY
        ContactStore.Establishment.UNREACHABLE -> Establishment.UNREACHABLE
    }

    private fun sourceOf(source: ContactStore.Source): CardSource? = when (source) {
        ContactStore.Source.QR_IN_PERSON -> CardSource.QR_IN_PERSON
        ContactStore.Source.LINK -> CardSource.LINK
        // §12.3: a request's card arrived inside an intro envelope, which is neither of the two
        // ways a **user** obtains one, so the facade shows no source for it.
        ContactStore.Source.REQUEST -> null
    }

    override fun toString(): String = "MessagingEngine"

    private companion object {
        /** A quote reference inside a `body_env` is a `message_id` (§21.8 point 6). */
        const val QUOTE_BYTES = 16
    }
}
