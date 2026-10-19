package org.ghost.ui.feature.channel

import org.ghost.ui.gateway.ChannelGateway
import org.ghost.ui.gateway.IdentityGateway

/**
 * Phase 13 design §6.5 (J4), §6.5.1: the create flow. The channel name, an optional password
 * drawn as five BIP-39 words (Q44 (a): ~55 bits, the owner cannot choose a weaker one), and the
 * create itself. The drawn words are shown once — "Scrie-o pe hârtie…; nu o copia" — and the
 * indices cross to the adapter, never a joined string. After the create the model forgets the
 * indices (they are zeroed); a restore needs the paper, not the phone (Q48 (a)).
 */
class ChannelCreateModel(
    private val channels: ChannelGateway,
    private val identity: IdentityGateway,
) {
    companion object {
        /** §6.5.1's five words, uniform from the 2 048-word list. */
        const val PASSPHRASE_WORDS: Int = 5
    }

    /** The drawn passphrase, for the one-time display; null until drawn or without a password. */
    var passphrase: List<String>? = null
        private set

    /** True once the user confirmed the words are on paper; the create button unlocks then. */
    var passphraseWritten: Boolean = false
        private set

    private var passphraseIndices: IntArray? = null

    /**
     * Draws a fresh passphrase (§6.5.1's distinct framing: the title names the channel, never
     * the seed). Drawing twice replaces the first draw — only the last reaches the create.
     */
    suspend fun onDrawPassphrase() {
        val indices = identity.newPassphraseIndices(PASSPHRASE_WORDS)
        val words = identity.wordList()
        discardIndices()
        passphraseIndices = indices
        passphrase = indices.map { words[it] }
        passphraseWritten = false
    }

    /** The user confirmed the paper copy; nothing is persisted. */
    fun onPassphraseWritten() {
        passphraseWritten = true
    }

    /** Drops a drawn passphrase without creating (the user turned the password off). */
    fun onPassphraseDiscarded() {
        discardIndices()
        passphrase = null
        passphraseWritten = false
    }

    /**
     * Creates the channel; the drawn indices cross as indices (the adapter expands them inside
     * the call). After the call the model holds nothing: the indices are zeroed here, the words
     * stay only on paper.
     */
    suspend fun onCreate(name: String) {
        channels.create(name, passphraseIndices)
        discardIndices()
        passphrase = null
        passphraseWritten = false
    }

    private fun discardIndices() {
        passphraseIndices?.fill(0)
        passphraseIndices = null
    }
}
