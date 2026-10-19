package org.ghost.app.ui

import android.content.Context
import android.net.Uri
import kotlinx.coroutines.withContext
import org.ghost.app.media.PickedVideo
import org.ghost.messaging.api.ContactId
import org.ghost.messaging.api.MediaSource
import org.ghost.messaging.api.MessageId
import org.ghost.messaging.api.Messaging
import org.ghost.ui.gateway.MediaGateway

/**
 * Phase 13 design §3.2, §6.6 (J5): the [MediaGateway] over the [Messaging] facade. Everything
 * runs on `ghost-ui-io` (CS-U6); the facade arrives through [messaging] each call (null before
 * the first database open and after a wipe). The picked URI is resolved here, in :app — the
 * engine receives [MediaSource] only, and no platform content-handle package name crosses into
 * the messaging modules (G-DM1, the `PickedVideo` pattern).
 *
 * The bytes of a picked still are read straight into memory (the facade's contract; the engine
 * sniffs the head and the pipeline seals from there). A picked video crosses as the [PickedVideo]
 * port plus its first bytes for the sniff. The caption and the view-once flag are not on the
 * gateway yet — they land with Phase 11's facade slice, declared here.
 */
class MediaGatewayAdapter(
    private val context: Context,
    private val messaging: () -> Messaging?,
) : MediaGateway {
    private val unhex: (String) -> ByteArray = { s ->
        require(s.length % 2 == 0) { "an id is hex" }
        ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
    }

    override suspend fun sendMedia(conversationId: String, pickedUri: String) = onIo {
        val m = messaging() ?: return@onIo
        val uri = Uri.parse(pickedUri)
        val source = if (context.contentResolver.getType(uri)?.startsWith("video/") == true) {
            MediaSource.video(PickedVideo(context, uri), headOf(uri, 64))
        } else {
            MediaSource.image(bytesOf(uri))
        }
        // Caption and viewOnce are not on the :ui gateway yet (Phase 11's facade slice); the
        // send crosses without them rather than through a half-built shape.
        m.sendMedia(ContactId(unhex(conversationId)), source, caption = null, viewOnce = false)
        Unit
    }

    override suspend fun retryMedia(itemId: String) = onIo {
        messaging()?.retryMedia(MessageId(unhex(itemId)))
        Unit
    }

    override suspend fun setDownloadsPaused(paused: Boolean) = onIo {
        // F-U9's pause method lands with Phase 11's coordination items; until then the toggle
        // acknowledges without effect — declared here, like the channel list's empty read.
        Unit
    }

    /** The picked still's full encoded bytes; the facade requires the head for the sniff. */
    private fun bytesOf(uri: Uri): ByteArray =
        context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
            ?: throw IllegalStateException("the picked source no longer resolves")

    /** The first [n] bytes of the picked source (the video sniff needs the ftyp box). */
    private fun headOf(uri: Uri, n: Int): ByteArray =
        context.contentResolver.openInputStream(uri)?.use { stream ->
            val head = ByteArray(n)
            val read = stream.read(head)
            if (read < 0) ByteArray(0) else head.copyOf(read)
        } ?: throw IllegalStateException("the picked source no longer resolves")

    private suspend fun <T> onIo(block: () -> T): T = withContext(GhostUiIo.dispatcher) {
        GhostUiIo.assertThread()
        block()
    }
}
