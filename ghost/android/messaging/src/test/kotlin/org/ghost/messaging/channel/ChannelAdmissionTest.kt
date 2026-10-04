package org.ghost.messaging.channel

import org.ghost.messaging.DmWorld
import org.ghost.messaging.api.AcceptResult
import org.ghost.messaging.api.ChannelId
import org.ghost.messaging.api.CreateResult
import org.ghost.messaging.api.InviteResult
import org.ghost.messaging.api.PostResult
import org.ghost.messaging.channel.store.ChannelState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test

/**
 * **SCN-CA without faults** (Phase 10 design §12.4; slice S4): create, invite, accept, the join request, the committer's
 * pass, the settle, the Welcome, the join — and a post each way, over the real OpenMLS. The crash singles of the same
 * scenario are [ChannelCrashTest]'s.
 */
class ChannelAdmissionTest {

    @Before
    fun native() {
        assumeTrue("ghost-dm-host is not loaded (-Dghost.dm.native)", ChannelWorld.nativeAvailable())
    }

    @Test
    fun createInviteAcceptAdmitJoinAndPostBothWays() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = create(owner)
        val link = invite(owner, id)
        assertEquals(AcceptResult.PENDING, bob.engine.accept(link, null))
        assertEquals(ChannelState.JOINING, bob.channel(id)!!.state)
        w.quiesce()
        assertEquals("the owner recorded the request", 1L, owner.count("ch_join_request"))
        w.admissionPass(owner)
        assertEquals("the pass committed", 1L, owner.count("ch_candidate", "own = 1"))
        w.quiesce()
        assertEquals("the commit's copy is verified (CO-4)", 1L, owner.count("ch_candidate", "own = 1 AND verified = 1"))
        w.pastSettleWindow()
        assertEquals("the owner settled its own commit", 1L, owner.channel(id)!!.epoch)
        w.quiesce()
        assertEquals(ChannelState.ACTIVE, bob.channel(id)!!.state)
        assertEquals(1L, bob.channel(id)!!.epoch)
        assertTrue(bob.integrity().isEmpty())
        assertTrue(owner.integrity().isEmpty())

        assertEquals(PostResult.QUEUED, bob.engine.post(id, "salut".toByteArray(), null))
        w.quiesce()
        assertEquals(listOf("salut"), owner.displayed(id))
        w.advance(DmWorld.MINUTE)
        assertEquals(PostResult.QUEUED, owner.engine.post(id, "bună".toByteArray(), null))
        w.quiesce()
        assertEquals(listOf("bună", "salut"), bob.displayed(id))
        assertEquals(listOf("bună", "salut"), owner.displayed(id))
    }

    companion object {
        internal fun create(owner: ChannelClient, password: Boolean = false): ChannelId {
            val created = owner.engine.create("salon".toByteArray(), 4, 0, password)
            assertEquals(CreateResult.Status.CREATED, created.status)
            assertNotNull(created.channel)
            return created.channel!!
        }

        internal fun invite(sponsor: ChannelClient, id: ChannelId, password: CharArray? = null): ByteArray {
            val invite = sponsor.engine.invite(id, 7, password)
            assertEquals(InviteResult.Status.CREATED, invite.status)
            return invite.link!!
        }
    }
}
