package org.ghost.app.ui

import kotlinx.coroutines.runBlocking
import org.ghost.ui.feature.media.MediaAttachModel
import org.ghost.ui.feature.media.MediaDownloadsModel
import org.ghost.ui.feature.media.MediaProgressModel
import org.ghost.ui.gateway.MediaGateway
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Phase 13 §6.6 (J5): the media models over a recording gateway — the attach and the retry
 * forward exactly one traffic call each, and the download pause mirrors the user's choice until
 * F-U9's state read exists.
 */
class MediaModelsTest {
    private class RecordingMedia : MediaGateway {
        val log = ArrayList<String>()
        var sentUri: String? = null
        override suspend fun sendMedia(conversationId: String, pickedUri: String) {
            log.add("send:$conversationId")
            sentUri = pickedUri
        }
        override suspend fun retryMedia(itemId: String) = log.add("retry:$itemId").let { }
        override suspend fun setDownloadsPaused(paused: Boolean) = log.add("pause:$paused").let { }
    }

    @Test
    fun attachForwardsThePickedUriOnce(): Unit = runBlocking {
        val media = RecordingMedia()
        val m = MediaAttachModel(media)
        m.onSendMedia("01".repeat(16), "content://picked/1")
        assertEquals(listOf("send:" + "01".repeat(16)), media.log)
        assertEquals("content://picked/1", media.sentUri)
    }

    @Test
    fun retryForwardsTheItemId(): Unit = runBlocking {
        val media = RecordingMedia()
        val m = MediaProgressModel(media)
        m.onRetryMedia("ab".repeat(16))
        assertEquals(listOf("retry:" + "ab".repeat(16)), media.log)
    }

    @Test
    fun thePauseToggleMirrorsItsChoiceUntilFU9(): Unit = runBlocking {
        val media = RecordingMedia()
        val m = MediaDownloadsModel(media)
        assertTrue(!m.paused)
        m.onSetDownloadsPaused(true)
        assertTrue(m.paused)
        assertEquals(listOf("pause:true"), media.log)
        m.onSetDownloadsPaused(false)
        assertTrue(!m.paused)
        assertEquals(listOf("pause:true", "pause:false"), media.log)
    }
}
