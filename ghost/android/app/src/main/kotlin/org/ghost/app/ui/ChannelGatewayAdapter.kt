package org.ghost.app.ui

import kotlinx.coroutines.withContext
import org.ghost.messaging.api.AcceptResult
import org.ghost.messaging.api.ChannelId
import org.ghost.messaging.api.Channels
import org.ghost.messaging.api.PostId
import org.ghost.ui.gateway.ChannelGateway
import org.ghost.ui.gateway.ChannelInvitePreview
import org.ghost.ui.gateway.ChannelView
import org.ghost.ui.protect.SensitiveText

/**
 * Phase 13 design §3.2, §3.6 (J4): the [ChannelGateway] over the [Channels] facade. Everything
 * runs on `ghost-ui-io` (CS-U6); the facade arrives through [channels] each call (null in a build
 * without channels, and after a wipe). The channel passphrase (Q35) crosses as indices and is
 * expanded through the word list inside the call, never as a joined string.
 */
class ChannelGatewayAdapter(
    private val facade: () -> Channels?,
    private val wordList: () -> List<String>,
) : ChannelGateway {
    private val hex: (ByteArray) -> String = { b -> b.joinToString("") { "%02x".format(it) } }
    private val unhex: (String) -> ByteArray = { s ->
        require(s.length % 2 == 0) { "an id is hex" }
        ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
    }

    override suspend fun channels(): List<ChannelView> = onIo {
        // The J4 list's read model lands with Phase 10's coordination items (§3.6's ChannelView
        // additions); until they exist, the list is empty rather than half-built.
        emptyList()
    }

    override suspend fun create(name: String, passwordIndices: IntArray?) = onIo {
        val c = facade() ?: return@onIo
        val password = passwordIndices?.let { expand(it) }
        c.create(
            name = name.toByteArray(Charsets.UTF_8),
            timerCode = 0,
            sizeClass = 0,
            passwordRequired = password != null,
        )
        Unit
    }

    override suspend fun createInvite(channelId: String): SensitiveText = onIo {
        val c = facade() ?: throw IllegalStateException("channels unavailable")
        // §6.5: the sponsor chooses the expiry up to 7 days; the adapter fixes the normative cap.
        val result = c.invite(ChannelId(unhex(channelId)), expiryDays = 7, password = null)
        SensitiveText(result.link?.let { String(it, Charsets.US_ASCII) } ?: "")
    }

    override suspend fun inspectInvite(link: String): ChannelInvitePreview? = onIo {
        // §3.6's inspectInvite is the local parse of Phase 10's coordination items; the password
        // requirement and expiry live in the link's sealed form, so the parse lands with them.
        null
    }

    override suspend fun acceptInvite(link: String, passwordIndices: IntArray?) = onIo {
        val c = facade() ?: return@onIo
        val password = passwordIndices?.let { expand(it) }
        // The accept is posted; the journey asserts the refusal reasons (PENDING/INVALID/EXPIRED/
        // PASSWORD_REQUIRED...) through the world, not through a return value here.
        c.accept(link.toByteArray(Charsets.US_ASCII), password)
        Unit
    }

    override suspend fun post(channelId: String, body: SensitiveText) = onIo {
        val c = facade() ?: return@onIo
        c.post(ChannelId(unhex(channelId)), body.value.toByteArray(Charsets.UTF_8), replyTo = null)
        Unit
    }

    override suspend fun leave(channelId: String) = onIo {
        facade()?.leave(ChannelId(unhex(channelId)))
        Unit
    }

    override suspend fun rejoin(channelId: String) = onIo {
        facade()?.rejoin(ChannelId(unhex(channelId)))
        Unit
    }

    /**
     * Indices -> words -> space-joined passphrase (Q35's distinct framing happens in the UI).
     * Built directly into the CharArray: no intermediate String holds the passphrase, and every
     * word copy is zeroed once copied (a `joinToString` result cannot be wiped).
     */
    private fun expand(indices: IntArray): CharArray {
        if (indices.isEmpty()) return CharArray(0)
        val words = wordList()
        val parts = indices.map { words[it].toCharArray() }
        val out = CharArray(parts.sumOf { it.size } + parts.size - 1)
        var at = 0
        parts.forEachIndexed { i, w ->
            if (i > 0) out[at++] = ' '
            System.arraycopy(w, 0, out, at, w.size)
            at += w.size
            java.util.Arrays.fill(w, '0')
        }
        return out
    }

    private suspend fun <T> onIo(block: () -> T): T = withContext(GhostUiIo.dispatcher) {
        GhostUiIo.assertThread()
        block()
    }
}
