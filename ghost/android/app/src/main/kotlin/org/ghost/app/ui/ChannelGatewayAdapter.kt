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
        facade()?.channels()?.map { channel ->
            ChannelView(
                id = hex(channel.channelId),
                name = channel.name,
                unread = 0,
                passwordProtected = channel.passwordProtected,
            )
        } ?: emptyList()
    }

    override suspend fun posts(channelId: String): List<org.ghost.ui.gateway.ChannelPostView> = onIo {
        facade()?.posts(ChannelId(unhex(channelId)), 120)?.map { post ->
            org.ghost.ui.gateway.ChannelPostView(
                id = hex(post.opId),
                body = SensitiveText(post.body),
                mine = post.mine,
                minute = post.authorMinute,
                state = post.state,
                kind = post.kind,
            )
        } ?: emptyList()
    }

    override suspend fun members(channelId: String): List<org.ghost.ui.gateway.ChannelMemberView> = onIo {
        facade()?.members(ChannelId(unhex(channelId)))?.map { member ->
            org.ghost.ui.gateway.ChannelMemberView(id = hex(member.pseudonym), committer = member.committer, mine = member.mine)
        } ?: emptyList()
    }

    override suspend fun fingerprint(channelId: String): org.ghost.ui.gateway.ChannelFingerprintView? = onIo {
        facade()?.fingerprint(ChannelId(unhex(channelId)))?.let { fingerprint ->
            org.ghost.ui.gateway.ChannelFingerprintView(fingerprint.epoch, hex(fingerprint.code))
        }
    }

    @org.ghost.ui.gateway.UserAction
    override suspend fun removeMember(channelId: String, memberId: String): Boolean = onIo {
        facade()?.remove(ChannelId(unhex(channelId)), unhex(memberId)) == org.ghost.messaging.api.ChannelActionResult.DONE
    }

    @org.ghost.ui.gateway.UserAction
    override suspend fun reveal(channelId: String, memberId: String): Boolean = onIo {
        facade()?.reveal(ChannelId(unhex(channelId)), unhex(memberId)) == org.ghost.messaging.api.ChannelActionResult.DONE
    }

    override suspend fun create(name: String, passwordIndices: IntArray?): String = onIo {
        val c = facade() ?: return@onIo "UNAVAILABLE"
        val password = passwordIndices?.let { expand(it) }
        try {
            c.create(
                name = name.toByteArray(Charsets.UTF_8),
                timerCode = 0,
                sizeClass = 0,
                passwordRequired = password != null,
            ).status.name
        } finally {
            password?.fill('0')
        }
    }

    override suspend fun createInvite(channelId: String, passwordIndices: IntArray?): SensitiveText = onIo {
        val c = facade() ?: throw IllegalStateException("channels unavailable")
        // §6.5: the sponsor chooses the expiry up to 7 days; the adapter fixes the normative cap.
        val password = passwordIndices?.let { expand(it) }
        try {
            val result = c.invite(ChannelId(unhex(channelId)), expiryDays = 7, password = password)
            SensitiveText(result.link?.let { String(it, Charsets.US_ASCII) } ?: "")
        } finally {
            password?.fill('0')
        }
    }

    override suspend fun inspectInvite(link: String): ChannelInvitePreview? = onIo {
        val invite = org.ghost.crypto.bridge.ChannelInvite.fromLink(link.trim()) ?: return@onIo null
        try {
            ChannelInvitePreview(
                channelName = "",
                passwordRequired = org.ghost.crypto.bridge.ChannelInvite.needsPassword(invite),
                expiryDay = null,
                alreadyMember = false,
            )
        } finally {
            invite.fill(0)
        }
    }

    override suspend fun acceptInvite(link: String, passwordIndices: IntArray?): String = onIo {
        val c = facade() ?: return@onIo "UNAVAILABLE"
        val password = passwordIndices?.let { expand(it) }
        try {
            c.accept(link.toByteArray(Charsets.US_ASCII), password).name
        } finally {
            password?.fill('0')
        }
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
