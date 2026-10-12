package org.ghost.messaging.channel

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
 * **SCN-CB** (Phase 10 design §12.4, CS-C2, CS-C5, CS-C6; slice S4), over the real OpenMLS: three members, 30 posts with
 * SHUFFLE and REPEATS across 3 relays, a burst of 40 from one sender (peek ordering, §6.3.3), a RESURRECTed post and a
 * COPY_NAMESPACE'd post — every post shown **once** by every member, in **one order** everywhere; and (§19.38) a reaction
 * that arrives a pass before its post.
 */
class ChannelPostsTest {

    @Before
    fun native() {
        assumeTrue("ghost-dm-host is not loaded (-Dghost.dm.native)", ChannelWorld.nativeAvailable())
    }

    @Test
    fun thirtyPostsShuffledAndRepeatedAcrossThreeRelaysShowOnceInOneOrderEverywhere() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val carol = w.client("carol")
        val id = ChannelScenes.channelOf(w, owner, bob, carol)
        w.relay.modes = setOf(ModelChannelRelay.Mode.SHUFFLE, ModelChannelRelay.Mode.REPEATS)
        w.relay.relayCount = 3
        val members = listOf(owner, bob, carol)
        val texts = (0 until 30).map { "post $it" }
        for ((i, text) in texts.withIndex()) {
            ChannelScenes.post(members[i % 3], id, text)
            // some posts settle before the next is written, some are in flight together; minutes advance
            if (i % 4 == 3) {
                w.quiesce()
                w.advance(DmWorld.MINUTE)
            }
        }
        w.quiesce()
        val shown = owner.displayed(id)
        assertEquals(texts.toSet(), shown.toSet())
        assertEquals("CS-C2: every post once", 30, shown.size)
        for (m in members) {
            assertEquals("CS-C6: one order at ${m.name}", shown, m.displayed(id))
            assertEquals(0, m[Reason.UNDECRYPTABLE])
            assertEquals(0, m[Reason.DUPLICATE])
            assertEquals(0, m[Reason.POISONED])
            assertEquals(emptyList<String>(), m.integrity())
        }
        assertTrue("REPEATS offered copies the tombstone refused", w.relay.repeatsRefused > 0)
        // every own post's op closed SENT
        for (m in members) assertEquals(0L, m.count("ch_post", "direction = 'out' AND state <> 'sent'"))
    }

    @Test
    fun aBurstOfFortyFromOneSenderDecryptsInPeekOrder() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val carol = w.client("carol")
        val id = ChannelScenes.channelOf(w, owner, bob, carol)
        w.relay.modes = setOf(ModelChannelRelay.Mode.SHUFFLE)
        // 40 posts in one minute, stored in one round and served scrambled: the receivers peek all 40 at once
        val texts = (0 until 40).map { "burst $it" }
        for (text in texts) ChannelScenes.post(bob, id, text)
        w.quiesce()
        for (m in listOf(owner, carol)) {
            assertEquals("all 40 at ${m.name}", texts.toSet(), m.displayed(id).toSet())
            assertEquals("none past the ratchet's tolerance at ${m.name}", 0, m[Reason.UNDECRYPTABLE])
        }
        assertEquals(owner.displayed(id), carol.displayed(id))
    }

    @Test
    fun aReactionThatSortsBeforeItsPostInABatchStillLands() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val carol = w.client("carol")
        val id = ChannelScenes.channelOf(w, owner, bob, carol)
        // carol's post, then the owner's reaction to it, reach bob in one batch: the owner's leaf (0) sorts before
        // carol's, so the reaction comes first in peek order (§19.35 F-4: posts are applied before reactions)
        w.relay.holdAt = { client, s -> client == "bob" && s.purpose == "post" && (s.from == "carol" || s.from == "owner") }
        ChannelScenes.post(carol, id, "a post")
        w.quiesce()
        val target = PostId(ChannelScenes.opIdOf(owner, id, "a post"))
        assertEquals(PostResult.QUEUED, owner.engine.react(id, target, "👍".toByteArray()))
        w.quiesce()
        assertEquals("bob holds neither yet", 0L, bob.count("ch_post"))
        w.relay.holdAt = { _, _ -> false }
        w.quiesce()
        assertEquals(listOf("a post"), bob.displayed(id))
        assertEquals(0, bob[Reason.REACTION_ORPHAN])
        assertEquals(1L, bob.count("ch_reaction"))
    }

    /**
     * §19.38 (the review of S4, finding 7): a reaction that reaches a member in an earlier pass than its post — the post
     * withheld from carol by a relay — is held until the post lands. The first version applied reactions after the posts of
     * the same batch only, and dropped one whose post was not on the device (`REACTION_ORPHAN`): carol never saw it.
     */
    @Test
    fun aReactionThatArrivesBeforeItsPostInAnEarlierPassLandsWithThePost() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val carol = w.client("carol")
        val id = ChannelScenes.channelOf(w, owner, bob, carol)
        w.relay.holdAt = { client, s -> client == "carol" && s.purpose == "post" && s.from == "owner" }
        ChannelScenes.post(owner, id, "a post")
        w.quiesce()
        val target = PostId(ChannelScenes.opIdOf(bob, id, "a post"))
        assertEquals(PostResult.QUEUED, bob.engine.react(id, target, "👍".toByteArray()))
        w.quiesce()
        assertEquals("held at carol, not dropped", 1, carol[Reason.REACTION_HELD])
        assertEquals(0L, carol.count("ch_reaction"))
        w.relay.holdAt = { _, _ -> false }
        w.quiesce()
        assertEquals(listOf("a post"), carol.displayed(id))
        assertEquals("the reaction landed with its post", 1L, carol.count("ch_reaction"))
        assertEquals(0, carol[Reason.REACTION_ORPHAN])
        assertEquals(owner.count("ch_reaction"), carol.count("ch_reaction"))
    }

    /**
     * F-S4-16's fix over the engine (slice S13c, §19.54 row 6): ten posts of one author inside one minute
     * read back in `seq` order — the author's send order, newest first — at **every** member, not in `op_id`
     * order. At the author's device the rows carry the `seq` the encryption drew; at the others the receive
     * step stores the `seq` of the decrypted `ChannelOrder`, so all three pages are the same. The store-level
     * twin (op ids run against the seqs, so the failure is deterministic) is
     * [org.ghost.messaging.channel.store.PostStoreTest]'s ten-in-a-minute test — the mutant's named killer.
     */
    @Test
    fun tenPostsOfOneAuthorInOneMinuteReadBackInSeqOrderAtEveryMember() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val carol = w.client("carol")
        val id = ChannelScenes.channelOf(w, owner, bob, carol)
        val texts = (0 until 10).map { "ordine $it" }
        for (text in texts) ChannelScenes.post(bob, id, text)
        w.quiesce()
        val expected = texts.reversed()
        for (m in listOf(owner, bob, carol)) {
            assertEquals("the author's posts of one minute, in seq order, at ${m.name}", expected, m.displayed(id))
        }
    }

    /**
     * F-S4-10 over the engine (slice S13c, §19.54 rows 2 and 6): a retried post takes the retry's `seq`
     * (and epoch and minute) — its order is the retry's, so a post retried in the same minute sorts by the
     * `seq` the retry drew, ahead of the posts that came between the attempt and the retry. The first copy
     * never reached a relay (a `failed` op, `storedThoughFailed` false), so every member holds the retry's
     * copy; the `seq` hole the lost attempt left holds the members' copies for the 12-minute gap hold, which
     * is why the order is asserted after it.
     */
    @Test
    fun aRetriedPostSortsByItsRetrySeq() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val carol = w.client("carol")
        val id = ChannelScenes.channelOf(w, owner, bob, carol)
        w.relay.outcomeFor = { client, purpose -> if (client.name == "bob" && purpose == "post") "failed" else "sent" }
        ChannelScenes.post(bob, id, "first")
        w.quiesce()
        assertEquals(1L, bob.count("ch_post", "state = 'failed'"))
        w.relay.outcomeFor = { _, _ -> "sent" }
        ChannelScenes.post(bob, id, "second")
        w.quiesce()
        assertEquals(PostResult.QUEUED, bob.engine.retry(id, PostId(ChannelScenes.opIdOf(bob, id, "first"))))
        w.quiesce()
        // the author's own page already: the retry's seq (2) outranks "second" (1) inside the same minute
        assertEquals(listOf("first", "second"), bob.displayed(id))
        w.advance(13 * DmWorld.MINUTE)
        for (m in listOf(owner, carol)) m.timePass()
        w.quiesce()
        for (m in listOf(owner, bob, carol)) {
            assertEquals("the retry's order everywhere, at ${m.name}", listOf("first", "second"), m.displayed(id))
        }
        assertEquals(emptyList<String>(), owner.integrity())
    }

    @Test
    fun aResurrectedPostAndACopyIntoAnotherNamespaceShowNothingNew() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        // a second channel of the owner's; the relay learns its namespace from its first post
        val other = ChannelAdmissionTest.create(owner)
        ChannelScenes.post(owner, other, "elsewhere")
        w.quiesce()
        // the copies of the post below expire at the relay an hour after they were stored
        w.relay.expiryFor = { if (it.purpose == "post-copy") it.storedAt + DmWorld.HOUR else it.storedAt + it.ttl }
        w.relay.modes = setOf(ModelChannelRelay.Mode.COPY_NAMESPACE)
        ChannelScenes.post(bob, id, "once")
        w.quiesce()
        w.relay.modes = emptySet()
        assertTrue("the copy reached the other namespace", w.relay.copies >= 1)
        assertEquals(listOf("once"), owner.displayed(id))
        assertEquals("§6.3.4 layer 3: the copy shows nowhere", listOf("elsewhere"), owner.displayed(other))
        assertEquals(0, owner[Reason.UNDECRYPTABLE])
        // RESURRECT: the same bytes stored again. The tombstone refuses them at the insert (layer 1).
        val original = ChannelScenes.postsOf(w, bob).single()
        val refusedBefore = owner.count("inbox_blob")
        assertEquals(1, w.relay.resurrect(w.now) { it === original })
        w.quiesce()
        assertEquals(refusedBefore, owner.count("inbox_blob"))
        assertEquals(listOf("once"), owner.displayed(id))
        // Its tombstone gone (its retention passed), the copy reaches the engine: MLS refuses the replay (layer 2).
        owner.sql.exec("DELETE FROM inbox_blob WHERE namespace_id = ? AND blob_hash = ?", listOf(original.namespace, original.hash))
        assertEquals(1, w.relay.resurrect(w.now) { it === original })
        w.quiesce()
        assertEquals(listOf("once"), owner.displayed(id))
        assertEquals("the replay failed to decrypt", 1, owner[Reason.UNDECRYPTABLE])
        assertEquals("…before the op id was ever read", 0, owner[Reason.DUPLICATE])
        // At the copy's relay expiry the owner consumes it unopened.
        w.advance(2 * DmWorld.HOUR)
        owner.timePass()
        assertTrue("the copy consumed as unopenable", owner[Reason.UNOPENABLE] >= 1)
        assertEquals(listOf("elsewhere"), owner.displayed(other))
        assertEquals(emptyList<String>(), owner.integrity())
    }
}
