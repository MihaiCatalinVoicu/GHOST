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
) : DmGateway, org.ghost.ui.gateway.ContactGateway {

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
                    timerMinutes = msg.timer?.let { timerMinutes(it) },
                    expireAtMinute = msg.expireAtMinute,
                    myReaction = msg.myReaction,
                    peerReaction = msg.peerReaction,
                    mediaKind = m.mediaState(msg.id)?.kind?.code ?: 0,
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

    override suspend fun contactNames(): Map<String, String> = onIo {
        messaging()?.contacts()?.mapNotNull { contact ->
            contact.name?.takeIf { it.isNotBlank() }?.let { name -> hex(contact.id.toByteArray()) to name }
        }?.toMap() ?: emptyMap()
    }

    override suspend fun myCard(): SensitiveText? = onIo {
        messaging()?.myCard()?.link?.let(::SensitiveText)
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
        messaging()?.setConversationOnScreen(contactId?.let { ContactId(unhex(it)) })
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
        val trimmed = cardText.trim()
        val card = if (trimmed.startsWith(CARD_LINK_PREFIX)) {
            org.ghost.identity.ZBase32.decode(trimmed.removePrefix(CARD_LINK_PREFIX), CONTACT_CARD_BYTES)
        } else {
            unhex(trimmed)
        }
        val src = when (source.uppercase()) {
            "QR_IN_PERSON" -> CardSource.QR_IN_PERSON
            else -> CardSource.LINK
        }
        m.addContact(card, src, name)
    }

    @org.ghost.ui.gateway.UserAction
    override suspend fun rename(contactId: String, name: String?): Boolean = onIo {
        messaging()?.rename(ContactId(unhex(contactId)), name) == true
    }

    override suspend fun trustState(contactId: String): String? = onIo {
        val id = unhex(contactId)
        messaging()?.contacts()?.firstOrNull { it.id.toByteArray().contentEquals(id) }?.trust?.name
    }

    override suspend fun safetyNumber(contactId: String, pending: Boolean): org.ghost.ui.gateway.SafetyNumberData? = onIo {
        val m = messaging() ?: return@onIo null
        val id = ContactId(unhex(contactId))
        val view = if (pending) m.pendingSafetyNumber(id) else m.safetyNumber(id)
        view?.let { number ->
            val raw = number.scannable
            val encoded = try {
                java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(raw)
            } finally {
                raw.fill(0)
            }
            org.ghost.ui.gateway.SafetyNumberData(
                digits = number.digits,
                qrPayload = SensitiveText("GHOST-SN-" + encoded),
            )
        }
    }

    @org.ghost.ui.gateway.UserAction
    override suspend fun acceptRequest(contactId: String): Boolean = onIo {
        messaging()?.acceptRequest(ContactId(unhex(contactId))) == true
    }

    @org.ghost.ui.gateway.UserAction
    override suspend fun rejectRequest(contactId: String): Boolean = onIo {
        messaging()?.rejectRequest(ContactId(unhex(contactId))) == true
    }

    @org.ghost.ui.gateway.UserAction
    override suspend fun blockRequest(contactId: String): Boolean = onIo {
        messaging()?.blockRequest(ContactId(unhex(contactId))) == true
    }

    @org.ghost.ui.gateway.UserAction
    override suspend fun verify(contactId: String, pending: Boolean, scannedPayload: String): Boolean = onIo {
        val m = messaging() ?: return@onIo false
        val encoded = scannedPayload.trim().removePrefix("GHOST-SN-")
        val scanned = try {
            java.util.Base64.getUrlDecoder().decode(encoded)
        } catch (e: IllegalArgumentException) {
            return@onIo false
        }
        try {
            val id = ContactId(unhex(contactId))
            val result = if (pending) m.verifyKeyChange(id, scanned) else m.markVerified(id, scanned)
            result == org.ghost.messaging.api.VerifyResult.VERIFIED
        } finally {
            scanned.fill(0)
        }
    }

    @org.ghost.ui.gateway.UserAction
    override suspend fun verifyManually(contactId: String): Boolean = onIo {
        messaging()?.markVerifiedManually(ContactId(unhex(contactId))) == org.ghost.messaging.api.VerifyResult.VERIFIED
    }

    @org.ghost.ui.gateway.UserAction
    override suspend fun acknowledgeKeyChange(contactId: String): Boolean = onIo {
        messaging()?.acknowledgeKeyChange(ContactId(unhex(contactId))) == true
    }

    @org.ghost.ui.gateway.UserAction
    override suspend fun block(contactId: String): Boolean = onIo {
        messaging()?.block(ContactId(unhex(contactId))) == true
    }

    @org.ghost.ui.gateway.UserAction
    override suspend fun unblock(contactId: String): Boolean = onIo {
        messaging()?.unblock(ContactId(unhex(contactId))) == true
    }

    @org.ghost.ui.gateway.UserAction
    override suspend fun deleteContact(contactId: String): Boolean = onIo {
        messaging()?.deleteContact(ContactId(unhex(contactId))) == true
    }

    @org.ghost.ui.gateway.UserAction
    override suspend fun resetSession(contactId: String): Boolean = onIo {
        messaging()?.resetSession(ContactId(unhex(contactId))) == org.ghost.messaging.api.SendResult.QUEUED
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
        private const val CONTACT_CARD_BYTES = 131
        private const val CARD_LINK_PREFIX = "ghost://contact/"
    }
}
