package org.ghost.ui.feature.channel

import org.ghost.ui.gateway.ChannelGateway
import org.ghost.ui.gateway.ChannelView
import org.ghost.ui.protect.SensitiveText

/**
 * Phase 13 design §6.5 (J4): one channel's screen. The model loads the row the list built (the
 * gateway exposes no single-channel read; the list's row is the read model), sends a post, and
 * owns the two user actions that change membership: leave, and the rejoin (the design's
 * "Resincronizare") offered on `resync_needed` only.
 *
 * The posts themselves land with Phase 10's coordination items (§3.6) — the facade exposes no
 * post list yet, so the screen renders an honest empty state rather than a half-built one; that
 * is declared here, not hidden.
 */
class ChannelModel(
    private val channels: ChannelGateway,
    private val channelId: String,
) {
    /** The channel row, loaded by [load]; null until then or when the channel is gone. */
    var channel: ChannelView? = null
        private set

    /** Loads this channel's row from the list read. */
    suspend fun load() {
        channel = channels.channels().firstOrNull { it.id == channelId }
    }

    /** Posts [body] to the channel (traffic at the next passes). */
    suspend fun onPost(body: SensitiveText) {
        channels.post(channelId, body)
    }

    /** Leaves the channel (a committer resigns or transfers first — the engine enforces it). */
    suspend fun onLeave() {
        channels.leave(channelId)
    }

    /** The rejoin user action (§6.7's CH-REJOIN), offered on `resync_needed` only. */
    suspend fun onRejoin() {
        channels.rejoin(channelId)
    }
}
