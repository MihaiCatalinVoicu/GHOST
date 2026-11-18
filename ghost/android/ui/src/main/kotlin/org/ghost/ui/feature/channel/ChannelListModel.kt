package org.ghost.ui.feature.channel

import org.ghost.ui.gateway.ChannelGateway
import org.ghost.ui.gateway.ChannelView

/**
 * Phase 13 design §6.5 (J4): the channel list's model. The list is name, role surface and the
 * live unread count only (never a post preview — the same Q14/T33 rule as the DM list). The
 * gateway reads the real local channel rows; the empty state is a real state, not an error.
 */
class ChannelListModel(private val channels: ChannelGateway) {
    /** The loaded rows; empty both before the first load and when there is nothing to show. */
    var items: List<ChannelView> = emptyList()
        private set

    /** Loads (or reloads) the rows — a read, not a user action. */
    suspend fun load() {
        items = channels.channels()
    }
}
