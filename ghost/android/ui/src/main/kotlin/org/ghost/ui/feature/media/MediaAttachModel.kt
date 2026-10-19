package org.ghost.ui.feature.media

import org.ghost.ui.gateway.MediaGateway

/**
 * Phase 13 design §6.6 (J5): the attach intent. The screen launches [org.ghost.ui.platform.SystemIntents.pickImage]
 * and hands the picked content URI here; the adapter reads the bytes in :app and the facade's
 * local checks (size, timer fit, source) refuse before any work — the refusal reasons land on
 * the gateway with Phase 11's facade slice, declared here. The upload continues in the
 * background and can take hours (D26: no upload service exists to promise less).
 */
class MediaAttachModel(private val media: MediaGateway) {
    /**
     * Sends the picked source to [conversationId]. [pickedUri] is the content URI the picker
     * returned; nothing of it is kept here.
     */
    suspend fun onSendMedia(conversationId: String, pickedUri: String) {
        media.sendMedia(conversationId, pickedUri)
    }
}
