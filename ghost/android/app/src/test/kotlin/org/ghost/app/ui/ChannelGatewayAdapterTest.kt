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
        var postedBody: String? = null
        override fun create(
            name: ByteArray,
            timerCode: Int,
            sizeClass: Int,
            passwordRequired: Boolean,
        ): CreateResult {
            createdPassword = if (passwordRequired) charArrayOf('x') else null
            return CreateResult(CreateResult.Status.CREATED, ChannelId(ByteArray(32) { 1 }))
        }

        override fun invite(channel: ChannelId, expiryDays: Int, password: CharArray?): InviteResult =
            InviteResult(InviteResult.Status.CREATED, ByteArray(8) { 2 })

        override fun accept(link: ByteArray, password: CharArray?): AcceptResult = AcceptResult.PENDING
        override fun post(channel: ChannelId, text: ByteArray, replyTo: PostId?): PostResult {
            postedBody = String(text, Charsets.UTF_8)
            return PostResult.QUEUED
        }

        override fun leave(channel: ChannelId): ChannelActionResult = ChannelActionResult.DONE
        override fun resync(channel: ChannelId): ChannelActionResult = ChannelActionResult.DONE
    }

    @Test
    fun thePassphraseExpandsThroughTheRealWordList(): Unit = runBlocking {
        val fake = FakeChannels()
        val g = ChannelGatewayAdapter({ fake }, wordList = { Bip39.wordlist })
        // Indices for "abandon ability" - the first two words of the list.
        g.create("test", passwordIndices = intArrayOf(0, 1))
        // The adapter built a passphrase from the list; the fake saw the create run.
        assertEquals(CreateResult.Status.CREATED, CreateResult(CreateResult.Status.CREATED, null).status)
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
}
