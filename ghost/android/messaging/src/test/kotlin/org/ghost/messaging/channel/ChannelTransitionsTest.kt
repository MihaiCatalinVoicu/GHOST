package org.ghost.messaging.channel

import org.ghost.messaging.DmWorld
import org.ghost.messaging.api.AcceptResult
import org.ghost.messaging.api.PostId
import org.ghost.messaging.api.PostResult
import org.ghost.messaging.channel.ChannelScenes.get
import org.ghost.messaging.channel.engine.ChannelAd
import org.ghost.messaging.channel.engine.ChannelCounters.Reason
import org.ghost.messaging.channel.store.ChannelState
import org.ghost.messaging.engine.DmTime
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test

/**
 * **The state machines of §6.11 as the engine drives them** (slice S4; the stores' legal and illegal edges are S3's
 * `ChannelStateMachinesTest`). Here: every edge of the outgoing post (`pending_plaintext → queued → sent | degraded |
 * failed | indeterminate`, `failed → queued`), the own commit cleared after a FAILED op with its join request pending
 * again, and the epoch's `open → final`. The channel's `joining → active`, `joining → join_expired` and `join_expired →
 * joining` are [ChannelJoinTest]'s and [ChannelAdmissionTest]'s; the join request's `pending → admitted` SCN-CA's and its
 * `ignored` edges JN's refusals. Not driven in S4 (§19.37): `active → leaving → left | removed | replaced`, the role, the
 * generation's rotation and the invite's expiry, whose transactions are slices S5 … S8's.
 */
class ChannelTransitionsTest {

    @Before
    fun native() {
        assumeTrue("ghost-dm-host is not loaded (-Dghost.dm.native)", ChannelWorld.nativeAvailable())
    }

    @Test
    fun everyEdgeOfTheOutgoingPostMachine() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        val c = id.toByteArray()
        // pending_plaintext: a removal hold on bob's epoch (CO-13: a held valid candidate that removes a pseudonym)
        val epoch = bob.channel(id)!!.epoch
        val hash = ChannelWorld.sha256("a removing candidate")
        bob.database.transaction { tx ->
            bob.channelStores.candidates.insert(
                tx, c, epoch, hash, ChannelWorld.sha256("someone"), 0, false,
                bob.env.seal(bob.content, ChannelAd.candidate(c, epoch, hash), ByteArray(64)), DmTime.floorMinute(w.now),
                removes = true,
            )
        }
        ChannelScenes.post(bob, id, "held")
        assertEquals(1L, bob.count("ch_pending_post"))
        assertEquals(0L, bob.count("ch_post", "direction = 'out'"))
        w.quiesce()
        assertEquals("nothing left bob", emptyList<String>(), owner.displayed(id))
        // → queued: the hold ends, the next pass encrypts it (§6.3.1, CH-POST "the channel becoming current")
        bob.database.transaction { tx -> bob.channelStores.candidates.delete(tx, c, epoch, hash) }
        bob.hintPass()
        assertEquals(0L, bob.count("ch_pending_post"))
        assertEquals(1L, bob.count("ch_post", "state = 'queued'"))
        // → sent
        w.quiesce()
        assertEquals(1L, bob.count("ch_post", "state = 'sent'"))
        assertEquals(listOf("held"), owner.displayed(id))
        // → degraded, failed, indeterminate: what the outcome reports (CH-OUTCOME)
        for (outcome in listOf("degraded", "failed", "indeterminate")) {
            w.relay.outcomeFor = { client, purpose -> if (client.name == "bob" && purpose == "post") outcome else "sent" }
            w.advance(DmWorld.MINUTE)
            ChannelScenes.post(bob, id, outcome)
            w.quiesce()
            assertEquals(outcome, 1L, bob.count("ch_post", "state = ?", outcome))
        }
        // failed → queued (the user's retry) → sent
        w.relay.outcomeFor = { _, _ -> "sent" }
        val failed = PostId(ChannelScenes.opIdOf(bob, id, "failed"))
        w.advance(DmWorld.MINUTE)
        assertEquals(PostResult.QUEUED, bob.engine.retry(id, failed))
        assertEquals(0L, bob.count("ch_post", "state = 'failed'"))
        w.quiesce()
        assertEquals(0L, bob.count("ch_post", "state = 'failed'"))
        // The failed op left a hole in bob's `seq` that nothing fills: the owner holds bob's later posts behind it for
        // the 12 minutes of §6.3.3, then decrypts past it (the retry is a new message with a new `seq`).
        assertTrue(!owner.displayed(id).contains("indeterminate"))
        w.advance(13 * DmWorld.MINUTE)
        owner.timePass()
        assertTrue(owner.displayed(id).containsAll(listOf("indeterminate", "failed")))
        // a retry while the channel is not current waits as a pending post, the row still failed; a second tap is a no-op
        w.relay.outcomeFor = { client, purpose -> if (client.name == "bob" && purpose == "post") "failed" else "sent" }
        w.advance(DmWorld.MINUTE)
        ChannelScenes.post(bob, id, "again")
        w.quiesce()
        val again = PostId(ChannelScenes.opIdOf(bob, id, "again"))
        w.relay.outcomeFor = { _, _ -> "sent" }
        bob.database.transaction { tx ->
            bob.channelStores.candidates.insert(
                tx, c, epoch, hash, ChannelWorld.sha256("someone"), 0, false,
                bob.env.seal(bob.content, ChannelAd.candidate(c, epoch, hash), ByteArray(64)), DmTime.floorMinute(w.now),
                removes = true,
            )
        }
        assertEquals(PostResult.QUEUED, bob.engine.retry(id, again))
        assertEquals(PostResult.QUEUED, bob.engine.retry(id, again))
        assertEquals(1L, bob.count("ch_pending_post"))
        assertEquals(1L, bob.count("ch_post", "state = 'failed'"))
        bob.database.transaction { tx -> bob.channelStores.candidates.delete(tx, c, epoch, hash) }
        w.quiesce()
        assertEquals(0L, bob.count("ch_post", "state = 'failed'"))
        w.advance(13 * DmWorld.MINUTE)
        owner.timePass()
        assertTrue(owner.displayed(id).contains("again"))
        // and a retry of a post that is not an own failed one is refused
        assertEquals(PostResult.NOT_FAILED, bob.engine.retry(id, again))
        assertEquals(emptyList<String>(), bob.integrity())
    }

    @Test
    fun anOwnCommitWhoseOpFailedIsClearedAndItsRequestWaitsForTheNextPass() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelAdmissionTest.create(owner)
        val link = ChannelAdmissionTest.invite(owner, id)
        assertEquals(AcceptResult.PENDING, bob.engine.accept(link, null))
        w.quiesce()
        w.relay.outcomeFor = { client, purpose -> if (client.name == "owner" && purpose == "commit") "failed" else "sent" }
        w.admissionPass(owner)
        assertEquals("own commit pending", 1L, owner.count("ch_candidate", "own = 1"))
        w.quiesce()
        // pending → cleared (CO-4: a FAILED op leaves no copy anywhere)
        assertEquals(0L, owner.count("ch_candidate", "own = 1"))
        assertEquals(1, owner[Reason.OWN_COMMIT_CLEARED])
        assertEquals("the request is pending again", 1L, owner.count("ch_join_request"))
        assertEquals(0L, owner.channel(id)!!.epoch)
        assertEquals(ChannelState.JOINING, bob.channel(id)!!.state)
        // the next pass (CO-8's spacing) commits again and wins: pending → merged; epoch 0 open → final
        w.relay.outcomeFor = { _, _ -> "sent" }
        w.advance(6 * DmWorld.HOUR)
        w.admissionPass(owner)
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        assertEquals(ChannelState.ACTIVE, bob.channel(id)!!.state)
        assertEquals(1L, owner.channel(id)!!.epoch)
        assertEquals(1L, owner.count("ch_epoch", "epoch = 0 AND state = 'final' AND winner_hash IS NOT NULL"))
        assertEquals(0L, owner.count("ch_join_request"))
        assertEquals(emptyList<String>(), owner.integrity())
    }
}
