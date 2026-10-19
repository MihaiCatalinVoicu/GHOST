package org.ghost.app.ui

import kotlinx.coroutines.runBlocking
import org.ghost.messaging.api.ActivationOutcome
import org.ghost.messaging.api.AddContactResult
import org.ghost.messaging.api.CardExport
import org.ghost.messaging.api.CardSource
import org.ghost.messaging.api.ContactId
import org.ghost.messaging.api.ContactView
import org.ghost.messaging.api.MaintenanceReport
import org.ghost.messaging.api.MediaPreview
import org.ghost.messaging.api.MediaSendResult
import org.ghost.messaging.api.MediaSource
import org.ghost.messaging.api.MediaStateView
import org.ghost.messaging.api.MessageCursor
import org.ghost.messaging.api.MessageId
import org.ghost.messaging.api.MessageKind
import org.ghost.messaging.api.MessageState
import org.ghost.messaging.api.MessageView
import org.ghost.messaging.api.Messaging
import org.ghost.messaging.api.MessagingStatus
import org.ghost.messaging.api.NotificationPort
import org.ghost.messaging.api.PreparationId
import org.ghost.messaging.api.PreparationView
import org.ghost.messaging.api.SafetyNumberView
import org.ghost.messaging.api.SendResult
import org.ghost.messaging.api.Timer
import org.ghost.ui.gateway.MessageState as UiMessageState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * Phase 13 §3.2, §3.6: the DmGateway adapter over a fake Messaging - the summary/conversation
 * mappings, the state and timer buckets, the null-facade answers, and the SensitiveText unwrap
 * happening exactly at the facade edge.
 */
class DmGatewayAdapterTest {
    private class FakeMessaging : Messaging {
        var summaries = emptyList<org.ghost.messaging.api.ConversationSummary>()
        var conversation = emptyList<MessageView>()
        var timer: Timer? = null
        var sentBody: String? = null
        var displayed: List<MessageId>? = null
        var setTimerArg: Timer? = null

        override fun conversationSummaries() = summaries
        override fun conversationTimer(contact: ContactId): Timer? = timer
        override fun conversation(contact: ContactId, limit: Int, before: MessageCursor?) = conversation
        override fun send(contact: ContactId, text: String, quote: MessageId?): SendResult {
            sentBody = text
            return SendResult.QUEUED
        }

        override fun markDisplayed(ids: List<MessageId>): Int {
            displayed = ids
            return ids.size
        }

        override fun setTimer(contact: ContactId, timer: Timer): SendResult {
            setTimerArg = timer
            return SendResult.QUEUED
        }

        override fun contacts(): List<ContactView> = emptyList()
        override fun myCard(): CardExport? = null
        override fun onActivated(): ActivationOutcome = error("not used")
        override fun onRestored(): ActivationOutcome = error("not used")
        override fun runOwnerMaintenance(): MaintenanceReport = error("not used")
        override fun addContact(card: ByteArray, source: CardSource): AddContactResult = AddContactResult.ADDED
        override fun addContact(card: ByteArray, source: CardSource, name: String?): AddContactResult = AddContactResult.ADDED
        override fun rename(contact: ContactId, name: String?): Boolean = true
        override fun acceptRequest(contact: ContactId): Boolean = error("not used")
        override fun rejectRequest(contact: ContactId): Boolean = error("not used")
        override fun blockRequest(contact: ContactId): Boolean = error("not used")
        override fun block(contact: ContactId): Boolean = error("not used")
        override fun unblock(contact: ContactId): Boolean = error("not used")
        override fun deleteContact(contact: ContactId): Boolean = error("not used")
        override fun react(contact: ContactId, target: MessageId, grapheme: String?): SendResult = error("not used")
        override fun setNotificationPort(port: NotificationPort?) = Unit
        override fun retry(message: MessageId): SendResult = error("not used")
        override fun status(): MessagingStatus = MessagingStatus(emptyMap(), 0, emptyMap(), 0, 0)
        override fun setListener(listener: org.ghost.messaging.api.MessagingListener?) = Unit
        override fun setConversationOnScreen(contact: ContactId?) = Unit
        override fun markVerified(contact: ContactId, scanned: ByteArray): org.ghost.messaging.api.VerifyResult = error("not used")
        override fun markVerifiedManually(contact: ContactId): org.ghost.messaging.api.VerifyResult = error("not used")
        override fun acknowledgeKeyChange(contact: ContactId): Boolean = error("not used")
        override fun verifyKeyChange(contact: ContactId, scanned: ByteArray): org.ghost.messaging.api.VerifyResult = error("not used")
        override fun resetSession(contact: ContactId): SendResult = error("not used")
        override fun reconnect(contacts: List<ContactId>): Int = error("not used")
        override fun issueRevocation(reason: org.ghost.messaging.api.RevocationReason): ByteArray? = null
        override fun notifyContactsOfRevocation(certificate: ByteArray): Int = 0
        override fun openMedia(message: MessageId): org.ghost.messaging.api.MediaHandle? = null
        override fun openViewOnce(message: MessageId): org.ghost.messaging.api.MediaHandle? = null
        override fun sendMedia(contact: ContactId, source: MediaSource, caption: String?, viewOnce: Boolean): MediaSendResult = error("not used")
        override fun preparationState(preparation: PreparationId): PreparationView? = null
        override fun retryMedia(message: MessageId): SendResult = error("not used")
        override fun mediaState(message: MessageId): MediaStateView? = null
        override fun mediaPreview(message: MessageId): MediaPreview? = null
        override fun safetyNumber(contact: ContactId): SafetyNumberView? = null
        override fun pendingSafetyNumber(contact: ContactId): SafetyNumberView? = null
    }

    private fun msg(id: Int, outgoing: Boolean, state: MessageState, text: String) = MessageView(
        id = MessageId(ByteArray(16) { id.toByte() }),
        outgoing = outgoing,
        kind = MessageKind.TEXT,
        authorMinute = 9_000,
        state = state,
        text = text,
        quote = null,
        cursor = MessageCursor(9_000, 0, MessageId(ByteArray(16) { id.toByte() })),
    )

    @Test
    fun summariesAndConversationMapWithHexIdsAndUiStates(): Unit = runBlocking {
        val fake = FakeMessaging()
        fake.summaries = listOf(org.ghost.messaging.api.ConversationSummary(ByteArray(16) { 1 }, 3, 9_060))
        fake.timer = Timer.HOUR_1
        fake.conversation = listOf(
            msg(2, outgoing = true, state = MessageState.QUEUED, text = "hello"),
            msg(3, outgoing = false, state = MessageState.UNREAD, text = "hi there"),
        )
        val g = DmGatewayAdapter({ fake })
        val summaries = g.conversationSummaries()
        assertEquals("01".repeat(16), summaries[0].contactId)
        assertEquals(3, summaries[0].unread)
        val conv = g.conversation("01".repeat(16))!!
        assertEquals(60, conv.timerMinutes)
        assertEquals(2, conv.items.size)
        assertEquals(UiMessageState.SENDING, conv.items[0].state)
        assertEquals(UiMessageState.SENT, conv.items[1].state)
        assertEquals("hi there", conv.items[1].body.value)
        assertNull("the fake's messages carry no timers", conv.items[0].timerMinutes)
    }

    @Test
    fun sendUnwrapsAtTheEdgeAndMarkDisplayedBatches(): Unit = runBlocking {
        val fake = FakeMessaging()
        val g = DmGatewayAdapter({ fake })
        g.send("01".repeat(16), org.ghost.ui.protect.SensitiveText("secret body"), replyTo = null)
        assertEquals("secret body", fake.sentBody)
        val ids = listOf("02".repeat(16), "03".repeat(16))
        g.markDisplayed("01".repeat(16), ids)
        assertEquals(2, fake.displayed!!.size)
    }

    @Test
    fun aNullFacadeAnswersEmptyNeverThrows(): Unit = runBlocking {
        val g = DmGatewayAdapter({ null })
        assertEquals(emptyList<org.ghost.ui.gateway.ConversationSummary>(), g.conversationSummaries())
        assertNull(g.conversation("01".repeat(16)))
    }

    @Test
    fun theTimerBucketsMapBothWays(): Unit = runBlocking {
        val fake = FakeMessaging()
        val g = DmGatewayAdapter({ fake })
        g.setTimer("01".repeat(16), 10_080)
        assertEquals(Timer.DAYS_7, fake.setTimerArg)
        g.setTimer("01".repeat(16), null)
        assertEquals(Timer.OFF, fake.setTimerArg)
        assertThrows(IllegalArgumentException::class.java) {
            runBlocking { g.setTimer("01".repeat(16), 90) }
        }
    }
}
