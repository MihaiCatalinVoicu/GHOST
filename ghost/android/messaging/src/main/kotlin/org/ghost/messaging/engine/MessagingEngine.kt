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
import org.ghost.messaging.api.Messaging
import org.ghost.messaging.api.MessageCursor
import org.ghost.messaging.api.MessageId
import org.ghost.messaging.api.MessageKind
import org.ghost.messaging.api.MessageState
import org.ghost.messaging.api.MessageView
import org.ghost.messaging.api.MessagingStatus
import org.ghost.messaging.api.SendResult
import org.ghost.messaging.api.Timer
import org.ghost.messaging.api.TrustState
import org.ghost.messaging.port.DmClock
import org.ghost.messaging.store.ContactStore
import org.ghost.messaging.store.MessageStore
import org.ghost.sync.api.SyncDatabase

/**
 * The DM engine behind the facade (Phase 9 design §13.1 `…messaging.engine`), at the size slices
 * S6 and S7 give it: the owner side, and contacts, sending and receiving.
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
    private val counters: DmCounters,
    private val clock: DmClock,
    private val contexts: SelfContexts,
) : Messaging {

    private val contacts = ContactStore()
    private val messages = MessageStore()

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

    private fun <T> onActor(body: () -> T): T = actor?.call(body) ?: body()

    // ------------------------------------------------------------- owner side

    override fun myCard(): CardExport? =
        onActor { steps.myCard()?.let { CardExport(it.card, it.link) } }

    override fun onActivated(): ActivationOutcome = onActor {
        val result = ActivationOutcome.of(steps.activate(restored = false))
        contexts.invalidate()
        result
    }

    override fun onRestored(): ActivationOutcome = onActor {
        val result = ActivationOutcome.of(steps.activate(restored = true))
        contexts.invalidate()
        result
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
        val nowMinute = DmTime.floorMinute(clock.nowEpochSeconds())
        database.transaction { tx ->
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

    override fun acceptRequest(contact: ContactId): Boolean = onActor {
        contactSteps.acceptRequest(contact.toByteArray()) == ContactSteps.RequestResult.DONE
    }

    override fun rejectRequest(contact: ContactId): Boolean = onActor {
        contactSteps.rejectRequest(contact.toByteArray()) == ContactSteps.RequestResult.DONE
    }

    override fun blockRequest(contact: ContactId): Boolean = onActor {
        contactSteps.blockRequest(contact.toByteArray()) == ContactSteps.RequestResult.DONE
    }

    override fun block(contact: ContactId): Boolean = onActor {
        contactSteps.block(contact.toByteArray())
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
        )
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

    override fun retry(message: MessageId): SendResult =
        onActor { SendResult.of(sendStep.retry(message.toByteArray())) }

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
        if (sent.establish) establishment.estStart(contactId)
        return SendResult.of(sent.outcome)
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
