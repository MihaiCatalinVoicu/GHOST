package org.ghost.app.ui

import kotlinx.coroutines.runBlocking
import org.ghost.identity.Bip39
import org.ghost.ui.feature.channel.ChannelAcceptModel
import org.ghost.ui.feature.channel.ChannelCreateModel
import org.ghost.ui.feature.channel.ChannelInviteModel
import org.ghost.ui.feature.channel.ChannelListModel
import org.ghost.ui.feature.channel.ChannelModel
import org.ghost.ui.gateway.ChannelGateway
import org.ghost.ui.gateway.ChannelInvitePreview
import org.ghost.ui.gateway.ChannelView
import org.ghost.ui.gateway.IdentityGateway
import org.ghost.ui.protect.SensitiveText
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Phase 13 §6.5 (J4): the channel models over recording gateways — the traffic log counts exactly
 * the §2.4 calls per flow, the passphrase is drawn once, shown once and forgotten (the indices
 * are zeroed after the create), the invite link is held only until displayed, and the accept
 * flow previews before it writes anything (FE-6).
 */
class ChannelModelsTest {
    private class RecordingChannels : ChannelGateway {
        val log = ArrayList<String>()
        var rows = listOf(
            ChannelView(id = "01".repeat(16), name = "forum", unread = 2, passwordProtected = true),
            ChannelView(id = "02".repeat(16), name = "open", unread = 0, passwordProtected = false),
        )
        var preview = ChannelInvitePreview("forum", passwordRequired = true, expiryDay = null, alreadyMember = false)
        var createIndices: IntArray? = null
        var postedBody: String? = null

        override suspend fun channels(): List<ChannelView> = rows.also { log.add("channels") }
        override suspend fun create(name: String, passwordIndices: IntArray?) {
            log.add("create")
            createIndices = passwordIndices
        }
        override suspend fun createInvite(channelId: String): SensitiveText {
            log.add("invite")
            return SensitiveText("ghost://channel/link")
        }
        override suspend fun inspectInvite(link: String): ChannelInvitePreview? {
            log.add("inspect")
            return preview
        }
        override suspend fun acceptInvite(link: String, passwordIndices: IntArray?) {
            log.add("accept")
            createIndices = passwordIndices
        }
        override suspend fun post(channelId: String, body: SensitiveText) {
            log.add("post")
            postedBody = body.toString() // redacted: proves the model never unwraps
        }
        override suspend fun leave(channelId: String) = log.add("leave").let { }
        override suspend fun rejoin(channelId: String) = log.add("rejoin").let { }
    }

    private class FixedIdentity : IdentityGateway {
        override suspend fun newPassphraseIndices(count: Int): IntArray = IntArray(count) { it }
        override suspend fun wordList(): List<String> = Bip39.wordlist
        override suspend fun createDatabaseKey() = error("not used")
        override suspend fun inspectInvite(text: String) = error("not used")
        override suspend fun activationState() = error("not used")
        override suspend fun activateInvite(text: String) = error("not used")
        override suspend fun activateGenesis(acknowledged: Boolean) = error("not used")
        override suspend fun restore(words: List<String>) = error("not used")
        override suspend fun mnemonicIndices(): IntArray = error("not used")
        override suspend fun backupChallenge(count: Int, carried: List<Int>) = error("not used")
        override suspend fun verifyBackup(indices: IntArray, positions: List<Int>, answers: List<String>) = error("not used")
    }

    @Test
    fun theListLoadsRowsWithoutTraffic(): Unit = runBlocking {
        val channels = RecordingChannels()
        val m = ChannelListModel(channels)
        m.load()
        assertEquals(2, m.items.size)
        assertEquals("forum", m.items[0].name)
        // channels() is a read, not a §2.4 user action — and the log counts it as one anyway.
        assertEquals(listOf("channels"), channels.log)
    }

    @Test
    fun createDrawsOnceShowsOnceAndForgetsTheIndices(): Unit = runBlocking {
        val channels = RecordingChannels()
        val m = ChannelCreateModel(channels, FixedIdentity())
        m.onDrawPassphrase()
        val words = m.passphrase!!
        assertEquals(ChannelCreateModel.PASSPHRASE_WORDS, words.size)
        assertEquals(Bip39.wordlist.take(5), words)
        assertTrue(!m.passphraseWritten)
        m.onPassphraseWritten()
        m.onCreate("the channel")
        assertEquals(listOf("create"), channels.log)
        // The model forgot everything; the indices it crossed are zeroed (the fake saw the array).
        assertNull(m.passphrase)
        assertTrue(!m.passphraseWritten)
        assertTrue(channels.createIndices!!.all { it == 0 })
    }

    @Test
    fun discardingThePassphraseKeepsNothing(): Unit = runBlocking {
        val channels = RecordingChannels()
        val m = ChannelCreateModel(channels, FixedIdentity())
        m.onDrawPassphrase()
        val seen = m.passphrase!!
        m.onPassphraseDiscarded()
        assertNull(m.passphrase)
        m.onCreate("open channel")
        assertEquals(listOf("create"), channels.log)
        assertNull(channels.createIndices)
        assertEquals(5, seen.size) // the screen displayed them before the discard
    }

    @Test
    fun theInviteLinkIsHeldUntilDisplayed(): Unit = runBlocking {
        val channels = RecordingChannels()
        val m = ChannelInviteModel(channels)
        m.onCreateInvite("01".repeat(16))
        assertEquals(SensitiveText("ghost://channel/link"), m.issuedLink)
        assertEquals(listOf("invite"), channels.log)
        m.onLinkDisplayed()
        assertNull(m.issuedLink)
    }

    @Test
    fun acceptPreviewsFirstThenCrossesIndices(): Unit = runBlocking {
        val channels = RecordingChannels()
        val m = ChannelAcceptModel(channels, FixedIdentity())
        m.onInspect("ghost://channel/link")
        assertEquals("forum", m.preview!!.channelName)
        assertTrue(m.preview!!.passwordRequired)
        assertTrue(!m.accepted)
        m.onLoadWordList()
        val indices = m.indicesForPassphrase(listOf("abandon", "ability"))
        assertEquals(listOf(0, 1), indices.toList())
        m.onAccept("ghost://channel/link", indices)
        assertTrue(m.accepted)
        assertEquals(listOf("inspect", "accept"), channels.log)
    }

    @Test
    fun theDetailModelPostsLeavesAndRejoins(): Unit = runBlocking {
        val channels = RecordingChannels()
        val m = ChannelModel(channels, "02".repeat(16))
        m.load()
        assertEquals("open", m.channel!!.name)
        m.onPost(SensitiveText("hello channel"))
        m.onLeave()
        m.onRejoin()
        assertEquals("SensitiveText(redacted)", channels.postedBody)
        assertEquals(listOf("channels", "post", "leave", "rejoin"), channels.log)
    }
}
