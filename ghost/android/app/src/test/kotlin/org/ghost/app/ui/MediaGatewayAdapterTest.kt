package org.ghost.app.ui

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import androidx.test.core.app.ApplicationProvider
import java.io.ByteArrayInputStream
import kotlinx.coroutines.runBlocking
import org.ghost.messaging.api.ActivationOutcome
import org.ghost.messaging.api.AddContactResult
import org.ghost.messaging.api.CardExport
import org.ghost.messaging.api.CardSource
import org.ghost.messaging.api.ContactId
import org.ghost.messaging.api.ContactView
import org.ghost.messaging.api.MaintenanceReport
import org.ghost.messaging.api.MediaHandle
import org.ghost.messaging.api.MediaPreview
import org.ghost.messaging.api.MediaSendResult
import org.ghost.messaging.api.MediaSource
import org.ghost.messaging.api.MediaStateView
import org.ghost.messaging.api.MessageCursor
import org.ghost.messaging.api.MessageId
import org.ghost.messaging.api.MessageView
import org.ghost.messaging.api.Messaging
import org.ghost.messaging.api.MessagingStatus
import org.ghost.messaging.api.NotificationPort
import org.ghost.messaging.api.PreparationId
import org.ghost.messaging.api.PreparationView
import org.ghost.messaging.api.SafetyNumberView
import org.ghost.messaging.api.SendResult
import org.ghost.messaging.api.Timer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows
import org.robolectric.annotation.Config

/**
 * Phase 13 §3.2, §6.6 (J5): the MediaGateway adapter on the JVM tier — the picked URI resolves
 * in :app (a still's bytes straight into memory, a video as the source port plus its head for
 * the sniff), the retry maps the item id, the null facade refuses quietly, and the download
 * pause acknowledges without effect until F-U9 lands.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35], application = BareTestApp::class)
class MediaGatewayAdapterTest {
    /** A provider for the mime types only; the bytes come from the shadow's input streams. */
    class TypeProvider : ContentProvider() {
        val types = HashMap<String, String>()
        override fun onCreate(): Boolean = true
        override fun getType(uri: Uri): String? = types[uri.path]
        override fun query(u: Uri, p: Array<String>?, s: String?, a: Array<String>?, o: String?): Cursor? = null
        override fun insert(u: Uri, v: ContentValues?): Uri? = null
        override fun delete(u: Uri, s: String?, a: Array<String>?): Int = 0
        override fun update(u: Uri, v: ContentValues?, s: String?, a: Array<String>?): Int = 0
    }

    private val provider = TypeProvider().also {
        org.robolectric.shadows.ShadowContentResolver.registerProviderInternal("media.test", it)
    }

    private class RecordingMessaging : Messaging {
        val log = ArrayList<String>()
        override fun sendMedia(contact: ContactId, source: MediaSource, caption: String?, viewOnce: Boolean): MediaSendResult {
            log.add("send")
            return MediaSendResult.Queued(PreparationId("prep"))
        }

        override fun retryMedia(message: MessageId): SendResult = log.add("retry").let { SendResult.QUEUED }
        override fun conversationSummaries() = emptyList<org.ghost.messaging.api.ConversationSummary>()
        override fun conversationTimer(contact: ContactId): Timer? = null
        override fun conversation(contact: ContactId, limit: Int, before: MessageCursor?): List<MessageView> = emptyList()
        override fun send(contact: ContactId, text: String, quote: MessageId?): SendResult = error("not used")
        override fun markDisplayed(ids: List<MessageId>): Int = 0
        override fun setTimer(contact: ContactId, timer: Timer): SendResult = error("not used")
        override fun contacts(): List<ContactView> = emptyList()
        override fun myCard(): CardExport? = null
        override fun onActivated(): ActivationOutcome = error("not used")
        override fun onRestored(): ActivationOutcome = error("not used")
        override fun runOwnerMaintenance(): MaintenanceReport = error("not used")
        override fun addContact(card: ByteArray, source: CardSource): AddContactResult = error("not used")
        override fun addContact(card: ByteArray, source: CardSource, name: String?): AddContactResult = error("not used")
        override fun rename(contact: ContactId, name: String?): Boolean = error("not used")
        override fun acceptRequest(contact: ContactId): Boolean = error("not used")
        override fun rejectRequest(contact: ContactId): Boolean = error("not used")
        override fun blockRequest(contact: ContactId): Boolean = error("not used")
        override fun block(contact: ContactId): Boolean = error("not used")
        override fun unblock(contact: ContactId): Boolean = error("not used")
        override fun deleteContact(contact: ContactId): Boolean = error("not used")
        override fun react(contact: ContactId, target: MessageId, grapheme: String?): SendResult = error("not used")
        override fun setNotificationPort(port: NotificationPort?) = Unit
        override fun retry(message: MessageId): SendResult = error("not used")
        override fun status(): MessagingStatus = error("not used")
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
        override fun openMedia(message: MessageId): MediaHandle? = null
        override fun openViewOnce(message: MessageId): MediaHandle? = null
        override fun preparationState(preparation: PreparationId): PreparationView? = null
        override fun mediaState(message: MessageId): MediaStateView? = null
        override fun mediaPreview(message: MessageId): MediaPreview? = null
        override fun safetyNumber(contact: ContactId): SafetyNumberView? = null
        override fun pendingSafetyNumber(contact: ContactId): SafetyNumberView? = null
    }

    private fun uri(path: String) = Uri.parse("content://media.test/$path")

    /** Registers the stream and its mime type for a content URI on the test resolver. */
    private fun serve(path: String, mime: String?, bytes: ByteArray) {
        val resolver = ApplicationProvider.getApplicationContext<BareTestApp>().contentResolver
        val u = uri(path)
        Shadows.shadowOf(resolver).registerInputStream(u, ByteArrayInputStream(bytes))
        if (mime != null) provider.types["/$path"] = mime
    }

    @Test
    fun aPickedStillCrossesAsImageBytesAndAVideoAsSourcePlusHead(): Unit = runBlocking {
        val context = ApplicationProvider.getApplicationContext<BareTestApp>()
        serve("photo.jpg", "image/jpeg", ByteArray(100) { 7 })
        serve("clip.mp4", "video/mp4", ByteArray(64) { 3 })
        val messaging = RecordingMessaging()
        val g = MediaGatewayAdapter(context) { messaging }

        g.sendMedia("01".repeat(16), uri("photo.jpg").toString())
        g.sendMedia("01".repeat(16), uri("clip.mp4").toString())
        assertEquals(listOf("send", "send"), messaging.log)
    }

    @Test
    fun aTinyStillIsRefusedByTheFacadesSniffContract(): Unit = runBlocking {
        val context = ApplicationProvider.getApplicationContext<BareTestApp>()
        serve("tiny.jpg", "image/jpeg", ByteArray(8))
        val g = MediaGatewayAdapter(context) { RecordingMessaging() }
        assertThrows(IllegalArgumentException::class.java) {
            runBlocking { g.sendMedia("01".repeat(16), uri("tiny.jpg").toString()) }
        }
    }

    @Test
    fun retryMapsTheItemAndANullFacadeRefusesQuietly(): Unit = runBlocking {
        val context = ApplicationProvider.getApplicationContext<BareTestApp>()
        val messaging = RecordingMessaging()
        val g = MediaGatewayAdapter(context) { messaging }
        g.retryMedia("ab".repeat(16))
        assertEquals(listOf("retry"), messaging.log)

        val empty = MediaGatewayAdapter(context) { null }
        empty.sendMedia("01".repeat(16), uri("photo.jpg").toString()) // no facade: no throw
        empty.retryMedia("01".repeat(16))
        empty.setDownloadsPaused(true) // F-U9 pending: acknowledges without effect
        assertEquals(listOf("retry"), messaging.log)
    }
}
