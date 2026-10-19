package org.ghost.ui.feature.media

import org.ghost.ui.gateway.MediaGateway

/**
 * Phase 13 design §6.6 (J5): the retry of a failed object, at most three times before its
 * deadline (F11 §6.5 — the engine counts; the model only forwards the intent). The transfer's
 * visible state — held fragments of F, `corrupt`, `incomplete` — lands with Phase 11's
 * coordination items; this model is the retry verb until then.
 */
class MediaProgressModel(private val media: MediaGateway) {
    /** Retries the failed object [itemId] (traffic at the next passes). */
    suspend fun onRetryMedia(itemId: String) {
        media.retryMedia(itemId)
    }
}
