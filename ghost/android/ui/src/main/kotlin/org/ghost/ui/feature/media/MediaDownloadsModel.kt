package org.ghost.ui.feature.media

import org.ghost.ui.gateway.MediaGateway

/**
 * Phase 13 design §6.6 (J5), §6.8: the download-pause toggle. Pausing stops the automatic
 * `M_0` listing the relays see — the residue sentence L9-M3 names this beside the switch. The
 * facade's pause method is F-U9's coordination item; until it lands the toggle mirrors its own
 * state (the setting reads back what the user chose), declared here like the channel list's
 * empty read — the row exists, the engine effect arrives with Phase 11's slice.
 */
class MediaDownloadsModel(private val media: MediaGateway) {
    /** The mirror of the user's choice until F-U9's state read exists. */
    var paused: Boolean = false
        private set

    /** Sets the pause; relays see the listing stop or resume (L9-M3, on the switch's copy). */
    suspend fun onSetDownloadsPaused(paused: Boolean) {
        media.setDownloadsPaused(paused)
        this.paused = paused
    }
}
