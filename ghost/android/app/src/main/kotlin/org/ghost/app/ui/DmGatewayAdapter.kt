package org.ghost.app.ui

import kotlinx.coroutines.withContext
import org.ghost.messaging.api.CardSource
import org.ghost.messaging.api.ContactId
import org.ghost.messaging.api.MessageId
import org.ghost.messaging.api.Messaging
import org.ghost.messaging.api.Timer
import org.ghost.ui.gateway.ConversationSummary
import org.ghost.ui.gateway.ConversationView
import org.ghost.ui.gateway.DmGateway
import org.ghost.ui.gateway.MessageState
import org.ghost.ui.gateway.MessageView
import org.ghost.ui.gateway.RequestView
import org.ghost.ui.protect.SensitiveText

/**
 * Phase 13 design §3.2, §3.6: the [DmGateway] over the [Messaging] facade. Everything runs on
 * `ghost-ui-io` (CS-U6); the facade arrives through [messaging] each call (it is null before the
 * first database open and after a wipe — §3.2's Unavailable mapping), and the ids cross as hex
 * of the engine's 16-byte local ids.
 *
 * The message text decrypts in the engine into memory only; this adapter wraps it in
 * [SensitiveText] before it reaches `:ui`, and the state maps to the UI's six verbs.
 */
class DmGatewayAdapter(
    private val messaging: () -> Messaging?,
    private val hex: (ByteArray) -> String = { b -> b.joinToString("") { "%02x".format(it) } },
    private val unhex: (String) -> ByteArray = { s ->
        require(s.length % 2 == 0) { "an id is hex" }
        ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
    },
) : DmGateway {

    override suspend fun conversationSummaries(): List<ConversationSummary> = onIo {
        messaging()?.conversationSummaries()?.map { s ->
            ConversationSummary(contactId = hex(s.contactId), unread = s.unread, newestMinute = s.newestAuthorMinute)
        } ?: emptyList()
    }

    override suspend fun conversation(contactId: String): ConversationView? = onIo {
        val m = messaging() ?: return@onIo null
        val id = ContactId(unhex(contactId))
        val messages = m.conversation(id, limit = CONVERSATION_PAGE, before = null)
        ConversationView(
            contactId = contactId,
            items = messages.map { msg ->
                MessageView(
                    id = hex(msg.id.toByteArray()),
                    mine = msg.outgoing,
                    minute = msg.authorMinute,
                    body = SensitiveText(msg.text ?: ""),
                    state = stateOf(msg.state),
                    // §3.6's per-message timer/reaction fields land with the MessageView additions
                    // (the facade's conversation query does not select them yet); nulls until then.
                    timerMinutes = null,
                    expireAtMinute = null,
                    myReaction = null,
                    peerReaction = null,
                )
            },
            // The conversation timer is the dm_conversation row's own code (§7.1).
            timerMinutes = m.conversationTimer(id)?.let { timerMinutes(it) },
            draftKeptInMemory = true, // Q34: drafts live in the session, never persisted
        )
    }

    override suspend fun requests(): List<RequestView> = onIo {
        messaging()?.contacts()
            ?.filter { it.trust == org.ghost.messaging.api.TrustState.REQUEST }
            ?.map { RequestView(contactId = hex(it.id.toByteArray()), receivedMinute = 0L) }
            ?: emptyList()
    }

    @org.ghost.ui.gateway.UserAction
    override suspend fun send(contactId: String, body: SensitiveText, replyTo: String?) = onIo {
        val m = messaging() ?: return@onIo
        val reply = replyTo?.let { MessageId(unhex(it)) }
        // The composer is the one field paste reaches (§4.2); the body unwraps only here, at the
        // facade edge, never into a persisted form.
        m.send(ContactId(unhex(contactId)), body.value, reply)
    }

    @org.ghost.ui.gateway.UserAction
    override suspend fun markDisplayed(contactId: String, messageIds: List<String>) = onIo {
        messaging()?.markDisplayed(messageIds.map { MessageId(unhex(it)) })
        Unit
    }

    @org.ghost.ui.gateway.UserAction
    override suspend fun setConversationOnScreen(contactId: String?) = onIo {
        // The "on screen" signal of §3.5: the UI layer keeps it in the session; no facade call
        // exists for it (the actor's on-screen state is the conversation read itself).
        Unit
    }

    @org.ghost.ui.gateway.UserAction
    override suspend fun setTimer(contactId: String, minutes: Int?) = onIo {
        val m = messaging() ?: return@onIo
        m.setTimer(ContactId(unhex(contactId)), timerOf(minutes))
    }

    @org.ghost.ui.gateway.UserAction
    override suspend fun retry(messageId: String): Unit = onIo {
        messaging()?.retry(MessageId(unhex(messageId)))
        Unit
    }

    @org.ghost.ui.gateway.UserAction
    override suspend fun addContact(cardText: String, source: String, name: String?) = onIo {
        val m = messaging() ?: return@onIo
        val card = unhex(cardText)
        val src = when (source.uppercase()) {
            "QR_IN_PERSON" -> CardSource.QR_IN_PERSON
            "LINK" -> CardSource.LINK
            else -> CardSource.QR_IN_PERSON
        }
        m.addContact(card, src, name)
    }

    @org.ghost.ui.gateway.UserAction
    override suspend fun rename(contactId: String, name: String?) = onIo {
        messaging()?.rename(ContactId(unhex(contactId)), name)
        Unit
    }

    private fun stateOf(s: org.ghost.messaging.api.MessageState): MessageState = when (s) {
        org.ghost.messaging.api.MessageState.QUEUED -> MessageState.SENDING
        org.ghost.messaging.api.MessageState.SENT -> MessageState.SENT
        org.ghost.messaging.api.MessageState.DEGRADED -> MessageState.DELIVERED
        org.ghost.messaging.api.MessageState.FAILED -> MessageState.FAILED
        org.ghost.messaging.api.MessageState.INDETERMINATE -> MessageState.HELD
        org.ghost.messaging.api.MessageState.UNREAD -> MessageState.SENT
        org.ghost.messaging.api.MessageState.READ -> MessageState.READ
    }

    private fun timerMinutes(t: Timer): Int = when (t) {
        Timer.OFF -> 0
        Timer.MIN_5 -> 5
        Timer.HOUR_1 -> 60
        Timer.DAY_1 -> 1440
        Timer.DAYS_7 -> 10_080
        Timer.DAYS_30 -> 43_200
    }

    private fun timerOf(minutes: Int?): Timer = when (minutes) {
        null, 0 -> Timer.OFF
        5 -> Timer.MIN_5
        60 -> Timer.HOUR_1
        1440 -> Timer.DAY_1
        10_080 -> Timer.DAYS_7
        43_200 -> Timer.DAYS_30
        else -> throw IllegalArgumentException("not a timer bucket: $minutes (ADR-27 C.7)")
    }

    private suspend fun <T> onIo(block: () -> T): T = withContext(GhostUiIo.dispatcher) {
        GhostUiIo.assertThread()
        block()
    }

    companion object {
        const val CONVERSATION_PAGE = 120
    }
}
