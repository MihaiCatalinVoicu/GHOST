package org.ghost.ui.feature.channel

import org.ghost.ui.gateway.ChannelGateway
import org.ghost.ui.gateway.ChannelInvitePreview
import org.ghost.ui.gateway.IdentityGateway

/**
 * Phase 13 design §6.5 (J4): joining from a link. The local preview comes first — nothing is
 * written before the user sees the kind of channel (FE-6) — then the accept posts a join request
 * at the next passes and the user waits for a moderator. In a password channel the passphrase
 * is typed on the WordKeyboard and crosses as indices, like at create.
 */
class ChannelAcceptModel(
    private val channels: ChannelGateway,
    private val identity: IdentityGateway,
) {
    /** The preview of the link under consideration; null until inspected or unparseable. */
    var preview: ChannelInvitePreview? = null
        private set

    /** True once the accept was posted; the screen then shows the moderator-wait copy. */
    var accepted: Boolean = false
        private set

    /** The BIP-39 list for the keyboard's suggestion chips (:ui holds no copy of its own, §3.2). */
    var wordList: List<String> = emptyList()
        private set

    /** Loads the list the WordKeyboard suggests from (a read, not a user action). */
    suspend fun onLoadWordList() {
        wordList = identity.wordList()
    }

    /** Parses the link locally (no state, no traffic) and remembers the preview. */
    suspend fun onInspect(link: String) {
        preview = channels.inspectInvite(link)
        accepted = false
    }

    /**
     * Maps the words typed on the WordKeyboard back to the list's indices (the keyboard only
     * produces list words; an unknown word is a model error, not a silent skip).
     */
    suspend fun indicesForPassphrase(words: List<String>): IntArray {
        val list = identity.wordList()
        return IntArray(words.size) { i ->
            list.indexOf(words[i].trim().lowercase()).also { if (it < 0) error("not a list word: ${words[i]}") }
        }
    }

    /** Posts the join request; [passwordIndices] is null for an open channel. */
    suspend fun onAccept(link: String, passwordIndices: IntArray?) {
        channels.acceptInvite(link, passwordIndices)
        accepted = true
    }
}
