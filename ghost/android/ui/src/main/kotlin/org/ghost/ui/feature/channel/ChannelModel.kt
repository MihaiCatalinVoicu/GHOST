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
 * The post list is the Phase 10 facade's local, decrypted read model. Opening or refreshing it
 * performs no fetch; the app re-queries while the screen is visible so engine-pass outcomes render.
 */
class ChannelModel(
    private val channels: ChannelGateway,
    private val channelId: String,
) {
    /** The channel row, loaded by [load]; null until then or when the channel is gone. */
    var channel: ChannelView? = null
        private set

    /** The newest local posts; opening the screen never triggers a fetch. */
    var posts: List<org.ghost.ui.gateway.ChannelPostView> = emptyList()
        private set

    /** Loads this channel's row and its newest local posts. */
    suspend fun load() {
        channel = channels.channels().firstOrNull { it.id == channelId }
        posts = channels.posts(channelId)
    }

    /** Posts [body] to the channel (traffic at the next passes). */
    suspend fun onPost(body: SensitiveText) {
        channels.post(channelId, body)
        posts = channels.posts(channelId)
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
