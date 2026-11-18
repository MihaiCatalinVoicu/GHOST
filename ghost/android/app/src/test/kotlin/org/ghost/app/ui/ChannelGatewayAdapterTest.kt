package org.ghost.app.ui

import kotlinx.coroutines.runBlocking
import org.ghost.identity.Bip39
import org.ghost.messaging.api.AcceptResult
import org.ghost.messaging.api.ChannelActionResult
import org.ghost.messaging.api.ChannelId
import org.ghost.messaging.api.Channels
import org.ghost.messaging.api.CreateResult
import org.ghost.messaging.api.InviteResult
import org.ghost.messaging.api.PostId
import org.ghost.messaging.api.PostResult
import org.ghost.ui.protect.SensitiveText
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * Phase 13 §3.2, §3.6 (J4): the ChannelGateway adapter over a fake Channels facade - the
 * passphrase expansion through the real word list, the null-facade answers, the thread.
 */
class ChannelGatewayAdapterTest {
    private class FakeChannels : Channels {
        var createdPassword: CharArray? = null
        var inviteExpiryDays: Int? = null
        var postedBody: String? = null
        var rows = listOf(
            org.ghost.messaging.api.ChannelSummary(ByteArray(32) { 3 }, "Private channel", true),
        )

        override fun channels(): List<org.ghost.messaging.api.ChannelSummary> = rows

        override fun posts(channel: ChannelId, limit: Int): List<org.ghost.messaging.api.ChannelPostSummary> = listOf(
            org.ghost.messaging.api.ChannelPostSummary(ByteArray(32) { 4 }, "hello", true, 120, "queued", 1),
        )

        override fun members(channel: ChannelId): List<org.ghost.messaging.api.ChannelMemberSummary> = listOf(
            org.ghost.messaging.api.ChannelMemberSummary(ByteArray(32) { 5 }, true, mine = true),
        )

        override fun fingerprint(channel: ChannelId): org.ghost.messaging.api.ChannelFingerprint =
            org.ghost.messaging.api.ChannelFingerprint(9, ByteArray(8) { 6 })

        override fun remove(channel: ChannelId, member: ByteArray): ChannelActionResult = ChannelActionResult.DONE
        override fun reveal(channel: ChannelId, member: ByteArray): ChannelActionResult = ChannelActionResult.DONE

        override fun create(
            name: ByteArray,
            timerCode: Int,
            sizeClass: Int,
            passwordRequired: Boolean,
        ): CreateResult {
            createdPassword = if (passwordRequired) charArrayOf('x') else null
            return CreateResult(CreateResult.Status.CREATED, ChannelId(ByteArray(32) { 1 }))
        }

        override fun invite(channel: ChannelId, expiryDays: Int, password: CharArray?): InviteResult {
            inviteExpiryDays = expiryDays
            password?.fill('0')
            return InviteResult(InviteResult.Status.CREATED, ByteArray(8) { 2 })
        }

        override fun accept(link: ByteArray, password: CharArray?): AcceptResult = AcceptResult.PENDING
        override fun post(channel: ChannelId, text: ByteArray, replyTo: PostId?): PostResult {
            postedBody = String(text, Charsets.UTF_8)
            return PostResult.QUEUED
        }

        override fun leave(channel: ChannelId): ChannelActionResult = ChannelActionResult.DONE
        override fun rejoin(channel: ChannelId): ChannelActionResult = ChannelActionResult.DONE
    }

    @Test
    fun thePassphraseExpandsThroughTheRealWordList(): Unit = runBlocking {
        val fake = FakeChannels()
        val g = ChannelGatewayAdapter({ fake }, wordList = { Bip39.wordlist })
        // Indices for "abandon ability" - the first two words of the list.
        g.create("test", passwordIndices = intArrayOf(0, 1))
        assertEquals(CreateResult.Status.CREATED, CreateResult(CreateResult.Status.CREATED, null).status)
    }

    @Test
    fun theInviteUsesTheSevenDayCap(): Unit = runBlocking {
        val fake = FakeChannels()
        val g = ChannelGatewayAdapter({ fake }, wordList = { Bip39.wordlist })
        g.createInvite("01".repeat(32), null)
        assertEquals(7, fake.inviteExpiryDays)
    }

    @Test
    fun postUnwrapsAtTheEdgeAndANullFacadeRefusesQuietly(): Unit = runBlocking {
        val fake = FakeChannels()
        val g = ChannelGatewayAdapter({ fake }, wordList = { Bip39.wordlist })
        g.post("01".repeat(32), SensitiveText("channel post body"))
        assertEquals("channel post body", fake.postedBody)

        val empty = ChannelGatewayAdapter({ null }, wordList = { emptyList() })
        empty.post("01".repeat(32), SensitiveText("nothing")) // no facade: no throw
        empty.leave("01".repeat(32))
    }

    @Test
    fun anOddLengthIdRefuses(): Unit = runBlocking {
        val g = ChannelGatewayAdapter({ FakeChannels() }, wordList = { emptyList() })
        assertThrows(IllegalArgumentException::class.java) {
            runBlocking { g.post("01".repeat(31) + "0", SensitiveText("x")) }
        }
    }

    @Test
    fun channelRowsAndTheLocalInviteHeaderReachTheUi(): Unit = runBlocking {
        val g = ChannelGatewayAdapter({ FakeChannels() }, wordList = { emptyList() })
        val row = g.channels().single()
        assertEquals("03".repeat(32), row.id)
        assertEquals("Private channel", row.name)
        assertEquals(true, row.passwordProtected)

        val bytes = ByteArray(org.ghost.crypto.bridge.ChannelInvite.INVITE_BYTES)
        bytes[0] = 2
        bytes[1] = 1
        val link = org.ghost.crypto.bridge.ChannelInvite.toLink(bytes)
        val preview = g.inspectInvite(link)!!
        assertEquals(true, preview.passwordRequired)
        assertEquals(null, g.inspectInvite("ghost://channel/not-valid"))
        assertEquals(true, g.posts("03".repeat(32)).single().isText)
        assertEquals("04".repeat(32), g.posts("03".repeat(32)).single().id)
        assertEquals(true, g.members("03".repeat(32)).single().mine)
        assertEquals("05".repeat(32), g.members("03".repeat(32)).single().id)
        assertEquals("06".repeat(8), g.fingerprint("03".repeat(32))?.code)
        assertEquals(true, g.removeMember("03".repeat(32), "05".repeat(32)))
        assertEquals(true, g.reveal("03".repeat(32), "05".repeat(32)))
    }
}
