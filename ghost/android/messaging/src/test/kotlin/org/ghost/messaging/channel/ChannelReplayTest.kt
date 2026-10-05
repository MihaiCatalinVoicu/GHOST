package org.ghost.messaging.channel

import org.ghost.crypto.bridge.ChannelContentFields
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
 * replayed join request are [ChannelJoinTest]'s (COPY_JOIN, REPLAY_JOIN). Since §19.38: another author's reuse of an op id
 * (a clash, not a duplicate, and the known gap F-S4-15), the deferral backoff of a blob no key opens, and a post whose
 * relay copy expired before it was received.
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

    /**
     * §19.38 (the review of S4, finding 4): a member reuses another member's op id. Layer 4's tag now names the author, so
     * the reuse is not taken for a duplicate: it reaches the insert, the first holder keeps the id, and the reuse is
     * counted as the clash it is (`OP_ID_CLASH`, which no test reached before). **The known gap** (recorded in §19.38,
     * F-S4-13, for the owner): whichever copy a member holds first keeps the id, so a reuse that arrives first suppresses
     * the real post at that member — `ch_post` and the reactions are keyed by the op id alone, and the wire names a
     * reaction's target by the op id alone.
     */
    @Test
    fun layerFourAnotherAuthorsReuseOfAnOpIdIsAClashNotADuplicate() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val carol = w.client("carol")
        val dave = w.client("dave")
        val id = ChannelScenes.channelOf(w, owner, bob, carol, dave)
        // dave is served bob's post only after the reuse below
        w.relay.holdAt = { client, s -> client == "dave" && s.from == "bob" && s.purpose == "post" }
        ChannelScenes.post(bob, id, "the real post")
        w.quiesce()
        val x = ChannelScenes.opIdOf(carol, id, "the real post")
        // the owner, a member, posts under bob's op id (its own engine keeps one row per id, so its copy goes first)
        owner.database.transaction { tx -> owner.channelStores.posts.deletePost(tx, x) }
        ChannelAdversary.postAs(
            owner, id,
            ChannelContentFields(kind = 1, opId = x, authorMinute = Math.floorDiv(w.now, DmWorld.MINUTE), timerCode = 4, text = "reused".toByteArray()),
            handshake = false,
        )
        w.quiesce()
        assertEquals("the first holder keeps the id", listOf("the real post"), carol.displayed(id))
        assertEquals("another author's reuse is a clash", 1, carol[Reason.OP_ID_CLASH])
        assertEquals("…and no duplicate", 0, carol[Reason.DUPLICATE])
        // The known gap, pinned (F-S4-13): at dave the reuse came first, and the real post is the one that clashes.
        w.relay.holdAt = { _, _ -> false }
        w.quiesce()
        assertEquals(listOf("reused"), dave.displayed(id))
        assertEquals(1, dave[Reason.OP_ID_CLASH])
        assertEquals(0, dave[Reason.DUPLICATE])
    }

    /**
     * §19.38 (the review of S4, finding 6): a blob no key opens is deferred 60 s, then 120 s, 240 s … up to 6 h. The first
     * version pruned the backoff to each pass's peek, and a deferred blob is in no peek until it is due, so every deferral
     * started over at 60 s: a junk blob was claimed and re-written each minute until its relay expiry.
     */
    @Test
    fun aBlobNoKeyOpensIsDeferredForLongerEachTime() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        val junk = ByteArray(4096) { (it * 31 + 7).toByte() }
        w.relay.inject(ChannelAdversary.namespace(owner, id), junk, w.now, "junk", ttl = 30 * DmWorld.DAY)
        w.quiesce()
        val hash = ModelChannelRelay.sha256(junk)
        val ns = ChannelAdversary.namespace(owner, id)
        val offerAfter = {
            var at = 0L
            bob.sql.query("SELECT offer_after_minute FROM inbox_blob WHERE blob_hash = ?", listOf(hash)) { at = it.long(0) }
            at
        }
        val delays = ArrayList<Long>()
        repeat(6) { i ->
            val due = offerAfter()
            // `Inbox.defer` counts from the minute the deferral was written
            delays += due - (w.now - Math.floorMod(w.now, DmWorld.MINUTE))
            // a pass while the blob waits (any hint): the first version forgot the blob's backoff there — pruned it to the
            // peek when the peek held another blob (every other round a fresh one arrives), cleared it when the peek was empty
            if (i % 2 == 0) {
                w.relay.inject(ns, ByteArray(4096) { ((it * 17 + i) % 251).toByte() }, w.now, "junk-$i", ttl = 30 * DmWorld.DAY)
                w.pump()
            }
            bob.hintPass()
            w.advance(due - w.now + 1)
            bob.timePass()
        }
        assertEquals(listOf(60L, 120L, 240L, 480L, 960L, 1920L), delays)
        assertEquals("waiting, never consumed", 0, bob[Reason.UNOPENABLE])
    }

    /**
     * §19.38 (the review of S4, finding 12): a post fetched before its relay expiry and received after it — held behind a
     * gap, deferred, or the process closed — is past both its lives (the relay copy, and the unread post's `min(E, …)`).
     * The DM drops such a message (`EXPIRED_WHILE_HELD`); the first version inserted the post, hidden by the read filters
     * until a sweep.
     */
    @Test
    fun aPostWhoseRelayCopyExpiredBeforeItWasReceivedIsNotInserted() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        w.relay.expiryFor = { if (it.purpose == "post") it.storedAt + DmWorld.HOUR else it.storedAt + it.ttl }
        ChannelScenes.post(bob, id, "short-lived")
        w.pump()
        assertEquals("fetched, not yet received", 1L, owner.count("inbox_blob", "state = 'fetched'"))
        w.advance(3 * DmWorld.HOUR)
        owner.hintPass()
        assertEquals(0L, owner.count("ch_post"))
        assertEquals(1, owner[Reason.EXPIRED_WHILE_HELD])
        assertEquals("consumed", 0L, owner.count("inbox_blob", "state = 'fetched'"))
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
