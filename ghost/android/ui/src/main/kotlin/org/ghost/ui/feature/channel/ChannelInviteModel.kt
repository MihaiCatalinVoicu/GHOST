package org.ghost.ui.feature.channel

import org.ghost.ui.gateway.ChannelGateway
import org.ghost.ui.gateway.IdentityGateway
import org.ghost.ui.protect.SensitiveText

/**
 * Phase 13 design §6.5 (J4), §19.29: the invite issuance. The link appears once — QR and
 * copyable text. In a password channel the five words are retyped at each issue (Q50 (a)); they
 * cross as word-list indices and are zeroed after the call. The model holds the issued link only
 * until the screen has shown it.
 */
class ChannelInviteModel(
    private val channels: ChannelGateway,
    private val identity: IdentityGateway,
) {
    /** The issued link, for the one-time display; null until issued. */
    var issuedLink: SensitiveText? = null
        private set

    /** Whether this channel requires the sponsor to retype its passphrase. */
    var passwordProtected: Boolean = false
        private set

    /** The fixed failure state; no native detail or secret reaches the screen. */
    var failed: Boolean = false
        private set

    /** The keyboard's suggestions, loaded only for a password channel. */
    var wordList: List<String> = emptyList()
        private set

    suspend fun onLoad(channelId: String) {
        val channel = channels.channels().firstOrNull { it.id == channelId }
        failed = channel == null
        passwordProtected = channel?.passwordProtected == true
        if (passwordProtected) wordList = identity.wordList()
    }

    /** Maps keyboard words without putting the joined passphrase in a String or an error message. */
    fun indicesForPassphrase(words: List<String>): IntArray {
        require(words.size == ChannelCreateModel.PASSPHRASE_WORDS) { "five passphrase words are required" }
        return IntArray(words.size) { i ->
            val index = wordList.indexOf(words[i])
            if (index < 0) throw IllegalArgumentException("not a list word")
            index
        }
    }

    /** Issues the invite; a second issue replaces the first — each link is its own store. */
    suspend fun onCreateInvite(channelId: String, passwordIndices: IntArray? = null) {
        try {
            val link = channels.createInvite(channelId, passwordIndices)
            issuedLink = link.takeIf { !it.isEmpty() }
            failed = issuedLink == null
        } finally {
            passwordIndices?.fill(0)
        }
    }

    /** The screen showed the link; the model keeps nothing of it. */
    fun onLinkDisplayed() {
        issuedLink = null
    }
}
