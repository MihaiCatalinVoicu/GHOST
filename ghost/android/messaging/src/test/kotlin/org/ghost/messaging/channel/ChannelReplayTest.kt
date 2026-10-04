package org.ghost.messaging.channel

import org.ghost.crypto.bridge.ChannelCrypto
import org.ghost.messaging.DmWorld
import org.ghost.messaging.api.PostId
import org.ghost.messaging.api.PostResult
import org.ghost.messaging.channel.ChannelScenes.get
import org.ghost.messaging.channel.engine.ChannelCounters.Reason
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test

/**
 * **RP-C, the replay suite** (Phase 10 design §12.6, §6.3.4; slice S4), over the real OpenMLS: each dedup layer isolated —
 * the copy stopped by that layer and by none before it, which the counters tell apart — a resurrected commit, a member's
 * proposal (dropped unprocessed; the receiver's next post is not refused, MM-30) and a forged "own" message (dropped and
 * counted, FORGE_OWN). Layer 3 (a copy into another namespace) is [ChannelPostsTest]'s COPY_NAMESPACE case; a copied and a
 * replayed join request are [ChannelJoinTest]'s (COPY_JOIN, REPLAY_JOIN).
 */
class ChannelReplayTest {

    @Before
    fun native() {
        assumeTrue("ghost-dm-host is not loaded (-Dghost.dm.native)", ChannelWorld.nativeAvailable())
    }

    @Test
    fun layerOneTheCopiesOfOtherRelaysDieAtTheTombstone() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        w.relay.modes = setOf(ModelChannelRelay.Mode.REPEATS)
        w.relay.relayCount = 3
        ChannelScenes.post(bob, id, "three relays")
        w.quiesce()
        assertEquals(listOf("three relays"), owner.displayed(id))
        assertTrue(w.relay.repeatsRefused >= 2)
        // nothing reached the engine twice
        assertEquals(0, owner[Reason.UNDECRYPTABLE])
        assertEquals(0, owner[Reason.DUPLICATE])
    }

    @Test
    fun layerTwoAMemberReplayFailsToDecryptBeforeItsOpIdIsRead() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val carol = w.client("carol")
        val id = ChannelScenes.channelOf(w, owner, bob, carol)
        ChannelScenes.post(bob, id, "said once")
        w.quiesce()
        // carol re-seals bob's message: the same MLS bytes, a new blob hash, past every tombstone
        val copy = ChannelAdversary.reseal(carol, id, ChannelScenes.postsOf(w, bob).single().ciphertext)
        w.relay.inject(ChannelAdversary.namespace(carol, id), copy, w.now, "replay")
        w.quiesce()
        assertEquals(listOf("said once"), owner.displayed(id))
        assertEquals("MLS refused the reused generation", 1, owner[Reason.UNDECRYPTABLE])
        assertEquals("…so layer 4 never saw it", 0, owner[Reason.DUPLICATE])
    }

    @Test
    fun layerFourARetryAfterFailedKeepsItsOpIdAndShowsOnce() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        // bob's op ends FAILED although one relay kept the blob
        w.relay.outcomeFor = { c, purpose -> if (c.name == "bob" && purpose == "post") "failed" else "sent" }
        w.relay.storedThoughFailed = { c, _ -> c.name == "bob" }
        ChannelScenes.post(bob, id, "did it go?")
        w.quiesce()
        assertEquals(listOf("did it go?"), owner.displayed(id))
        assertEquals(1L, bob.count("ch_post", "state = 'failed'"))
        w.relay.outcomeFor = { _, _ -> "sent" }
        w.relay.storedThoughFailed = { _, _ -> false }
        w.advance(DmWorld.MINUTE)
        val post = PostId(ChannelScenes.opIdOf(bob, id, "did it go?"))
        assertEquals(PostResult.QUEUED, bob.engine.retry(id, post))
        w.quiesce()
        assertEquals("the retry was sent", 1L, bob.count("ch_post", "state = 'sent'"))
        assertEquals(listOf("did it go?"), owner.displayed(id))
        assertEquals("a new MLS message: layer 2 passed it", 0, owner[Reason.UNDECRYPTABLE])
        assertEquals("layer 4 dropped it", 1, owner[Reason.DUPLICATE])
        // a retry of a post that is not failed is refused
        assertEquals(PostResult.NOT_FAILED, bob.engine.retry(id, post))
    }

    @Test
    fun layerFourOnlyTheSeenTagRemembersASweptPost() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        w.relay.outcomeFor = { c, purpose -> if (c.name == "bob" && purpose == "post") "failed" else "sent" }
        w.relay.storedThoughFailed = { c, _ -> c.name == "bob" }
        ChannelScenes.post(bob, id, "gone, then again")
        w.quiesce()
        assertEquals(listOf("gone, then again"), owner.displayed(id))
        // the owner's post is swept (its row deleted, as CH-SWEEP deletes an expired post): only ch_seen remembers it
        val opId = ChannelScenes.opIdOf(owner, id, "gone, then again")
        owner.database.transaction { tx -> owner.channelStores.posts.deletePost(tx, opId) }
        assertEquals(emptyList<String>(), owner.displayed(id))
        w.relay.outcomeFor = { _, _ -> "sent" }
        w.relay.storedThoughFailed = { _, _ -> false }
        w.advance(DmWorld.MINUTE)
        assertEquals(PostResult.QUEUED, bob.engine.retry(id, PostId(opId)))
        w.quiesce()
        assertEquals("the swept post does not come back", emptyList<String>(), owner.displayed(id))
        assertEquals(1, owner[Reason.DUPLICATE])
    }

    @Test
    fun aResurrectedCommitIsTheWinnerAndIsIgnored() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val carol = w.client("carol")
        val id = ChannelScenes.channelOf(w, owner, bob)
        ChannelScenes.admit(w, owner, id, carol)
        assertEquals(2L, bob.channel(id)!!.epoch)
        // the commit of epoch 1, which bob held as a candidate and settled
        val commit = w.relay.stored.last { it.from == "owner" && it.purpose == "commit" }
        bob.sql.exec("DELETE FROM inbox_blob WHERE namespace_id = ? AND blob_hash = ?", listOf(commit.namespace, commit.hash))
        assertEquals(1, w.relay.resurrect(w.now) { it === commit })
        w.quiesce()
        assertEquals(1, bob[Reason.RESURRECTED_COMMIT])
        assertEquals("no fork signal", 0, bob[Reason.LATE_CANDIDATE])
        assertEquals(2L, bob.channel(id)!!.epoch)
        assertEquals(0L, bob.count("ch_fork_signal"))
        ChannelScenes.post(owner, id, "still one branch")
        w.quiesce()
        assertEquals(listOf("still one branch"), bob.displayed(id))
    }

    @Test
    fun aMessageOfAnOldEpochSealedUnderTheCurrentKeyNeverDecrypts() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val carol = w.client("carol")
        val id = ChannelScenes.channelOf(w, owner, bob)
        ChannelScenes.post(owner, id, "epoch one")
        w.quiesce()
        ChannelScenes.admit(w, owner, id, carol)
        val old = ChannelScenes.postsOf(w, owner).first()
        // bob, a member of both epochs, asks its native context to seal the epoch-1 message under epoch 2's key (whose
        // hint carol, who joined at 2, would match): the epoch is bound to the key (§19.31), so the seal is refused.
        // The receive step's own check (an opened header naming another epoch than the key's is dropped, CS-S7) is the
        // line behind it, which no client built on this facade can reach (recorded in §19.37 with its mutant).
        val sealed = ChannelAdversary.trySealUnder(bob, id, old.ciphertext, keyEpoch = 2)
        assertEquals(org.ghost.crypto.bridge.MlsCode.INVALID_POLICY, sealed.code)
        assertEquals(emptyList<String>(), carol.displayed(id))
    }

    @Test
    fun aMemberProposalIsDroppedUnprocessedAndThePostsGoOn() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val carol = w.client("carol")
        val id = ChannelScenes.channelOf(w, owner, bob, carol)
        ChannelScenes.post(carol, id, "carrier")
        w.quiesce()
        val carrier = ChannelScenes.postsOf(w, carol).single().ciphertext
        val epoch = ChannelAdversary.openEpochBlob(carol, id, carrier).order.epoch
        // PROPOSE: carol's message turned into a proposal by its header, sealed with a handshake's order
        val proposal = ChannelAdversary.reseal(carol, id, carrier, ChannelCrypto.SealOrder(epoch, 0, 0), ChannelAdversary::asProposal)
        w.relay.inject(ChannelAdversary.namespace(carol, id), proposal, w.now, "propose")
        w.quiesce()
        assertEquals("dropped by its header", 1, bob[Reason.PROPOSAL])
        assertEquals("…before any decryption", 0, bob[Reason.UNDECRYPTABLE])
        // MM-30: a stored proposal would make OpenMLS refuse bob's next post; nothing was stored
        ChannelScenes.post(bob, id, "after the proposal")
        assertEquals("encrypted at once", 0L, bob.count("ch_pending_post"))
        w.quiesce()
        assertTrue(owner.displayed(id).contains("after the proposal"))
        assertTrue(carol.displayed(id).contains("after the proposal"))
    }

    @Test
    fun aForgedOwnMessageIsDroppedAndCounted() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val carol = w.client("carol")
        val id = ChannelScenes.channelOf(w, owner, bob, carol)
        ChannelScenes.post(bob, id, "mine")
        w.quiesce()
        // carol re-seals bob's own message and the relay serves it to bob: OpenMLS reports it as bob's own
        val forged = ChannelAdversary.reseal(carol, id, ChannelScenes.postsOf(w, bob).single().ciphertext)
        w.relay.inject(ChannelAdversary.namespace(carol, id), forged, w.now, "forge-own")
        w.quiesce()
        assertEquals(1, bob[Reason.FORGED_OWN])
        assertEquals(listOf("mine"), bob.displayed(id))
        // bob's own bookkeeping is untouched: its next post goes out and shows everywhere
        ChannelScenes.post(bob, id, "still mine")
        w.quiesce()
        assertTrue(owner.displayed(id).contains("still mine"))
        assertEquals(emptyList<String>(), bob.integrity())
    }
}
