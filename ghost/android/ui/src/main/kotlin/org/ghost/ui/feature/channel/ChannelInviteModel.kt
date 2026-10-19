package org.ghost.ui.feature.channel

import org.ghost.ui.gateway.ChannelGateway
import org.ghost.ui.protect.SensitiveText

/**
 * Phase 13 design §6.5 (J4), §19.29: the invite issuance. The link appears once — QR and
 * copyable text — and is not kept on the phone; in a password channel the passphrase is retyped
 * at each issue (Q50 (a)), which lands with Phase 10's coordination items. The model holds the
 * issued link only until the screen has shown it.
 */
class ChannelInviteModel(private val channels: ChannelGateway) {
    /** The issued link, for the one-time display; null until issued. */
    var issuedLink: SensitiveText? = null
        private set

    /** Issues the invite; a second issue replaces the first — each link is its own store. */
    suspend fun onCreateInvite(channelId: String) {
        issuedLink = channels.createInvite(channelId)
    }

    /** The screen showed the link; the model keeps nothing of it. */
    fun onLinkDisplayed() {
        issuedLink = null
    }
}
