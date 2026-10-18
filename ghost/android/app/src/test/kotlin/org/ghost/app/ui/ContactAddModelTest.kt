package org.ghost.app.ui

import kotlinx.coroutines.runBlocking
import org.ghost.ui.feature.dm.ContactAddModel
import org.ghost.ui.gateway.ConversationSummary
import org.ghost.ui.gateway.ConversationView
import org.ghost.ui.gateway.DmGateway
import org.ghost.ui.gateway.InviteView
import org.ghost.ui.gateway.PaymentView
import org.ghost.ui.gateway.RequestView
import org.ghost.ui.protect.SensitiveText
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Phase 13 §4.7 (D34; PM-U30): the provenance question decides the trust path — only the
 * in-person answer records QR_IN_PERSON; the preselected default and the other answer record LINK
 * and ask for the safety number.
 */
class ContactAddModelTest {
    private class RecordingDm : DmGateway {
        val added = ArrayList<Triple<String, String, String?>>()
        override suspend fun conversationSummaries(): List<ConversationSummary> = emptyList()
        override suspend fun conversation(contactId: String): ConversationView? = null
        override suspend fun requests(): List<RequestView> = emptyList()
        override suspend fun send(contactId: String, body: SensitiveText, replyTo: String?) = Unit
        override suspend fun markDisplayed(contactId: String, messageIds: List<String>) = Unit
        override suspend fun setConversationOnScreen(contactId: String?) = Unit
        override suspend fun setTimer(contactId: String, minutes: Int?) = Unit
        override suspend fun retry(messageId: String) = Unit
        override suspend fun addContact(cardText: String, source: String, name: String?) {
            added.add(Triple(cardText, source, name))
        }

        override suspend fun rename(contactId: String, name: String?) = Unit
    }

    @Test
    fun onlyTheInPersonAnswerRecordsQrInPerson(): Unit = runBlocking {
        val dm = RecordingDm()
        val m = ContactAddModel(dm)
        assertEquals(
            ContactAddModel.Provenance.QR_IN_PERSON,
            m.onScanned("card-hex", ContactAddModel.Answer.IN_FRONT_OF_ME),
        )
        assertFalse(m.needsSafetyNumberPrompt)
        assertEquals("QR_IN_PERSON", dm.added.single().second)
    }

    @Test
    fun thePreselectedDefaultAndTheOtherAnswerRecordLinkAndAskForTheSafetyNumber(): Unit = runBlocking {
        val dm = RecordingDm()
        val m = ContactAddModel(dm)
        // PM-U30: the default is DON'T KNOW, never the in-person value.
        assertEquals(
            ContactAddModel.Provenance.LINK,
            m.onScanned("card-hex"),
        )
        assertTrue("a link asks for the safety number", m.needsSafetyNumberPrompt)
        assertEquals("LINK", dm.added.single().second)

        val dm2 = RecordingDm()
        val m2 = ContactAddModel(dm2)
        assertEquals(
            ContactAddModel.Provenance.LINK,
            m2.onScanned("card-hex", ContactAddModel.Answer.ELSEWHERE_ON_A_SCREEN),
        )
        assertTrue(m2.needsSafetyNumberPrompt)
        assertEquals("LINK", dm2.added.single().second)
    }
}
