package org.ghost.messaging.channel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test

/**
 * **The joiner oracle** of S4's exit (Phase 10 design §14 S4, §12.8, T39; [JoinerOracle]) over a world with history before
 * each join: posts and commits of epoch 0 and 1 before carol joins at epoch 2, of epoch 0 before bob joins at epoch 1.
 * The second clause of T39 (a joiner joins only the channel it was invited to) is JN's FAKE_WELCOME case
 * ([ChannelJoinTest]).
 */
class ChannelJoinerOracleTest {

    @Before
    fun native() {
        assumeTrue("ghost-dm-host is not loaded (-Dghost.dm.native)", ChannelWorld.nativeAvailable())
    }

    @Test
    fun aJoinerOpensNothingOfTheEpochsBeforeItsJoin() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val carol = w.client("carol")
        val id = ChannelScenes.channelOf(w, owner, bob)
        ChannelScenes.post(owner, id, "epoch 1, the owner")
        ChannelScenes.post(bob, id, "epoch 1, bob")
        w.quiesce()
        ChannelScenes.admit(w, owner, id, carol)
        assertEquals(2L, carol.channel(id)!!.epoch)
        ChannelScenes.post(owner, id, "epoch 2, the owner")
        ChannelScenes.post(carol, id, "epoch 2, carol")
        w.quiesce()

        val forCarol = JoinerOracle.run(w, carol, id, joinEpoch = 2)
        assertEquals("$forCarol", 0, forCarol.openedBeforeJoin)
        assertEquals("$forCarol", 0L, forCarol.postsBeforeJoin)
        assertTrue("$forCarol", forCarol.openedSinceJoin >= 2)
        // the declared exception, reported: the generation's join traffic (both requests, both Welcomes)
        val joinTraffic = w.relay.stored.filter { it.purpose == "join" || it.purpose == "welcome" }
            .distinctBy { ModelChannelRelay.hex(it.hash) }.size
        assertEquals("$forCarol", joinTraffic, forCarol.joinTraffic)
        assertEquals(setOf("epoch 2, the owner", "epoch 2, carol"), carol.displayed(id).toSet())

        val forBob = JoinerOracle.run(w, bob, id, joinEpoch = 1)
        assertEquals("$forBob", 0, forBob.openedBeforeJoin)
        assertEquals("$forBob", 0L, forBob.postsBeforeJoin)
        assertTrue("$forBob", forBob.openedSinceJoin >= 4)
    }
}
