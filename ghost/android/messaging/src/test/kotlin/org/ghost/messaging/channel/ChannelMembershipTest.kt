package org.ghost.messaging.channel

import org.ghost.messaging.DmWorld
import org.ghost.messaging.api.AcceptResult
import org.ghost.messaging.api.ChannelId
import org.ghost.messaging.api.PostResult
import org.ghost.messaging.channel.engine.ChannelCounters
import org.ghost.messaging.channel.engine.ChannelEngine
import org.ghost.messaging.channel.engine.ChannelPostStep
import org.ghost.messaging.channel.store.ChannelState
import org.ghost.messaging.engine.DmTime
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test

/**
 * **SCN-CK's leave and eviction half** (Phase 10 design §12.4: "a leave, an eviction at 63 days, ... a
 * moderator's resignation and leave, the owner's transfer of rank 0 and its leave"; §19.13 item 3) and the
 * removal hold's full flow (CO-13, §19.6): the leave's two halves (the LEAVE post and the committer's
 * pending work), the idle eviction's rank rule and `ch_member_refresh` bookkeeping (joins, commits,
 * self-updates — MM-17's shape), a committer's two-step leave (resignation / transfer, then the member
 * leave) and F-S4-8's ghost member (a joiner whose Welcome was lost is evicted at idle expiry). The
 * restore/rejoin swaps of SCN-CK are S7's (recorded in §19.41).
 */
class ChannelMembershipTest {

    @Before
    fun native() {
        assumeTrue("ghost-dm-host is not loaded (-Dghost.dm.native)", ChannelWorld.nativeAvailable())
    }

    /** §6.6: the leaving member stops posting; a committer records the leave and removes the leaver at its next pass. */
    @Test
    fun aLeaveIsPendingWorkAndTheCommitterRemovesTheLeaverAtItsNextPass() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        val ns0 = generationNs(owner, id, 0)

        // The member half: the LEAVE post is out, the channel is `leaving`, no more posts.
        assertEquals(ChannelPostStep.LeaveResult.LEFT, bob.engine.leave(id))
        assertEquals(ChannelState.LEAVING, bob.channel(id)!!.state)
        assertEquals("the LEAVE is a handshake post", 1L, bob.count("ch_outbound_op", "purpose = 'request'"))
        assertEquals("no more posts", PostResult.NOT_MEMBER, bob.engine.post(id, "nu mai pot".toByteArray(), null))

        // The committer half: the LEAVE post, once received, is a recorded leave request.
        w.pump()
        owner.hintPass()
        assertEquals("the committer recorded the leave", 1L, owner.count("ch_request", "kind = 'leave'"))
        w.advance(6 * DmWorld.HOUR)
        duePass(w, owner)
        assertEquals("the pass commits the removal", 1L, owner.count("ch_candidate", "own = 1 AND removes = 1"))
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()

        // The leaver merges the removal: removed, the MLS state deleted at the merge (§6.6), the old
        // generation drains, and it keeps listening to ns_0 until the drain ends (§6.5).
        assertEquals(ChannelState.REMOVED, bob.channel(id)!!.state)
        assertEquals("the MLS state went with the merge", 0L, bob.count("mls_kv"))
        assertEquals("the generation drains", 1L, bob.count("ch_generation", "state = 'draining'"))
        assertEquals(1L, bob.count("sync_namespace", "namespace_id = ? AND listening = 1", ns0))
        assertTrue(owner.integrity().isEmpty())
    }

    /** §6.6: a member idle longer than `idle_evict_days` (63) is evicted at the next pass; self-updates count. */
    @Test
    fun anIdleMemberIsEvictedAtSixtyThreeDaysAndSelfUpdatesCountAsRefresh() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        // Open epoch 2 (at epoch 1 in a 2-member channel CO-14 refuses a KeyPackage leaf, e < k = 2) and
        // let bob self-update at his slot: a leaf refresh, which restarts the eviction clock (MM-17).
        agePcsClock(owner, id, 7)
        duePass(w, owner)
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        assertEquals(2L, owner.channel(id)!!.epoch)
        bringSlotTo(w, bob, id)
        duePass(w, bob)
        assertEquals(1L, bob.count("ch_candidate", "own = 1 AND rank = 255"))
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        assertEquals(
            "the self-update refreshed the leaf",
            DmTime.day(w.now), refreshDayOf(owner, id, pseudonymOf(bob, id)),
        )

        // 63 days of silence after the self-update: the owner's pass evicts bob.
        w.advance(64 * DmWorld.DAY)
        duePass(w, owner)
        assertEquals("the idle member is removed at the next pass", 1L, owner.count("ch_candidate", "own = 1 AND removes = 1"))
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        assertEquals(ChannelState.REMOVED, bob.channel(id)!!.state)
        assertTrue(owner.integrity().isEmpty())
    }

    /** §6.6, CO-2: the rank rule — a moderator cannot evict the owner or an equal rank (declared L8-C16). */
    @Test
    fun evictionIsLowerRankOnlyAndNeverTheOwner() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        makeCommitter(w, owner, bob, id)
        // Everyone idle far past the eviction days: the moderator (rank 1) evicts nobody at or below its
        // rank — the owner (rank 0) least of all — and the owner evicts the moderator.
        backdateRefresh(owner, id, 100)
        backdateRefresh(bob, id, 100)
        w.advance(2 * DmWorld.DAY)
        duePass(w, bob)
        assertEquals("a moderator evicts nobody at or below its rank", 0L, bob.count("ch_candidate", "own = 1"))
        duePass(w, owner)
        assertEquals("the owner evicts the idle moderator", 1L, owner.count("ch_candidate", "own = 1 AND removes = 1"))
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        assertEquals(ChannelState.REMOVED, bob.channel(id)!!.state)
        assertEquals("the owner stays", ChannelState.ACTIVE, owner.channel(id)!!.state)
        assertTrue(owner.integrity().isEmpty())
    }

    /** §6.6, §19.13 item 3: a moderator resigns (a context change) and then leaves as a member. */
    @Test
    fun aModeratorResignsAndThenLeavesAsAMember() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        makeCommitter(w, owner, bob, id)
        assertEquals(2, ChannelAdversary.policy(owner, id).committers.size)

        // A committer's leave is refused until it resigned (MM-55's shape).
        assertEquals(ChannelPostStep.LeaveResult.NOT_ALLOWED, bob.engine.leave(id))
        assertEquals(ChannelState.ACTIVE, bob.channel(id)!!.state)

        // The resignation: bob's own key leaves `committers` (a pass at once; §19.13 item 3 lets any
        // committer drop its own key — the native CO-2 refuses the last committer).
        assertEquals(ChannelEngine.RemoveResult.REMOVED, bob.engine.resign(id))
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        assertEquals(1, ChannelAdversary.policy(owner, id).committers.size)
        assertEquals("a resignation does not rotate (§6.5's rule)", 0L, owner.count("ch_generation", "generation = 1"))

        // The member leave: bob is no committer any more, so the leave is allowed.
        assertEquals(ChannelPostStep.LeaveResult.LEFT, bob.engine.leave(id))
        w.pump()
        owner.hintPass()
        assertEquals(1L, owner.count("ch_request", "kind = 'leave'"))
        w.advance(6 * DmWorld.HOUR)
        duePass(w, owner)
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        assertEquals(ChannelState.REMOVED, bob.channel(id)!!.state)
        assertTrue(owner.integrity().isEmpty())
    }

    /** §6.6, §19.13 item 3: rank 0 refuses its own resignation; it transfers rank 0, resigns, then leaves. */
    @Test
    fun theOwnerTransfersRankZeroResignsAndThenLeaves() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        makeCommitter(w, owner, bob, id)
        assertEquals("a committer's leave is refused until it resigned or transferred", ChannelPostStep.LeaveResult.NOT_ALLOWED, owner.engine.leave(id))
        assertEquals("rank 0 refuses its own resignation", ChannelEngine.RemoveResult.NOTHING, owner.engine.resign(id))
        assertEquals(0L, owner.count("ch_candidate", "own = 1"))

        // The transfer: bob leads the committers now; the digest does not change (MM-45's sorted set).
        val digestBefore = owner.channel(id)!!.committersDigest
        assertEquals(ChannelEngine.RemoveResult.REMOVED, owner.engine.transfer(id, pseudonymOf(bob, id)))
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        val policy = ChannelAdversary.policy(bob, id)
        assertTrue("bob is rank 0 now", policy.committers.first().contentEquals(pseudonymOf(bob, id)))
        assertNotNull("the digest is kept", digestBefore)
        assertArrayEquals("a transfer keeps the digest", digestBefore, bob.channel(id)!!.committersDigest)

        // The former owner is a rank-1 committer now: it resigns, then leaves as an ordinary member.
        assertEquals(ChannelEngine.RemoveResult.REMOVED, owner.engine.resign(id))
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        assertEquals(1, ChannelAdversary.policy(bob, id).committers.size)
        assertEquals(ChannelPostStep.LeaveResult.LEFT, owner.engine.leave(id))
        w.pump()
        bob.hintPass()
        assertEquals(1L, bob.count("ch_request", "kind = 'leave'"))
        w.advance(6 * DmWorld.HOUR)
        duePass(w, bob)
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        assertEquals(ChannelState.REMOVED, owner.channel(id)!!.state)
        assertEquals(ChannelState.ACTIVE, bob.channel(id)!!.state)
        assertTrue(bob.integrity().isEmpty())
    }

    /** F-S4-8: a joiner whose Welcome is lost is a ghost member — evicted at the idle expiry. */
    @Test
    fun aGhostMemberIsEvictedAtIdleExpiry() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        assertEquals(2, rosterSize(owner, id))
        // dave accepts; the relay drops his Welcome: his leaf is in the tree, his join expires.
        w.relay.modes = setOf(ModelChannelRelay.Mode.DROP_WELCOME)
        val dave = w.client("dave")
        assertEquals(AcceptResult.PENDING, dave.engine.accept(ChannelAdmissionTest.invite(owner, id), null))
        w.quiesce()
        w.advance(6 * DmWorld.HOUR)
        w.admissionPass(owner)
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        assertEquals("the ghost member is in the tree", 3, rosterSize(owner, id))
        w.relay.modes = emptySet()
        // Its join expires (a sweep at a time-triggered pass of the joiner itself). The +8-day pass
        // also PCS-committed at the owner: give the commit its outcome and settle, so no own candidate
        // delays the eviction pass (CO-7).
        w.advance(8 * DmWorld.DAY)
        for (c in w.clients) c.timePass()
        assertEquals("the join expired", ChannelState.JOIN_EXPIRED, dave.channel(id)!!.state)
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        // 63 idle days: the owner's pass evicts the ghost leaf.
        backdateRefresh(owner, id, 64, pseudonymOf(dave, id))
        w.advance(2 * DmWorld.DAY)
        duePass(w, owner)
        assertEquals("the ghost member is evicted", 1L, owner.count("ch_candidate", "own = 1 AND removes = 1"))
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        assertEquals(2, rosterSize(owner, id))
        assertTrue(owner.integrity().isEmpty())
    }

    /** CO-13's full flow (§19.6): a member's posts wait while a removing candidate is held, and reach no removing epoch. */
    @Test
    fun theRemovalHoldKeepsPostsComposedAfterTheRemovingCandidatesSightingOutOfItsEpoch() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val carol = w.client("carol")
        val id = ChannelScenes.channelOf(w, owner, bob, carol)
        // The owner removes carol; bob sights the removing candidate and composes a post before the settle.
        owner.engine.remove(id, pseudonymOf(carol, id))
        w.quiesce()
        assertEquals("the removing candidate holds the posts (CO-13)", 1L, bob.count("ch_candidate", "own = 0 AND removes = 1"))
        ChannelScenes.post(bob, id, "dupa ce am vazut candidatul")
        assertEquals("the post waits (the channel is not current)", 1L, bob.count("ch_pending_post"))
        w.advance(21 * DmWorld.MINUTE)
        w.pump()
        for (c in listOf(owner, bob, carol)) c.timePass()
        // The settle ran and the rotation pends: the post is still plaintext (§6.3.1's pending_switch wait).
        assertEquals(1L, bob.count("ch_pending_post"))
        w.advance(40 * DmWorld.MINUTE)
        bob.hintPass()
        assertEquals("the post encrypted only at the switch, into the new generation", 0L, bob.count("ch_pending_post"))
        w.pump()
        val ns0 = generationNs(bob, id, 0)
        val ns1 = generationNs(bob, id, 1)
        assertTrue(
            "no post of the hold ever entered the removing epoch's namespace",
            w.relay.stored.none { it.purpose == "post" && it.namespace.contentEquals(ns0) && !it.injected },
        )
        assertTrue(
            "the post went out in the new generation's namespace",
            w.relay.stored.any { it.purpose == "post" && it.namespace.contentEquals(ns1) && !it.injected },
        )
        w.quiesce()
        assertTrue(bob.integrity().isEmpty())
    }

    /**
     * The review of S6 (§19.42): a join request recorded against a generation whose drain has ended must
     * not null the committer's whole pass — the eviction riding along would be skipped, the request
     * re-selected and the commit re-dropped until its expiry. The reviewer's world: the request is
     * recorded in a draining generation; a second rotation ends that generation at once; the rank-1
     * committer's pass refuses the dead admission **and** evicts the idle member in the one commit.
     */
    @Test
    fun aRequestOfAnEndedGenerationIsRefusedAtSelectionAndThePassContinues() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val carol = w.client("carol")
        val erin = w.client("erin")
        val frank = w.client("frank")
        val id = ChannelScenes.channelOf(w, owner, bob, carol, erin, frank)
        makeCommitter(w, owner, bob, id) // bob at rank 1
        // dave's invite, day 0 (after the committer change: the digest of bob's passes must match).
        val link = ChannelAdmissionTest.invite(owner, id)
        // Rotation 1, day 0: carol goes; the switch leaves generation 0 draining (until day 14).
        owner.engine.remove(id, pseudonymOf(carol, id))
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        w.advance(70 * DmWorld.MINUTE)
        for (c in w.clients) c.hintPass()
        assertEquals(1L, owner.count("ch_generation", "generation = 0 AND state = 'draining'"))

        // Day 5: dave accepts the day-0 invite; the committers fetch his request from ns_0 — still
        // draining and listened — and record it against generation 0.
        w.advance(5 * DmWorld.DAY)
        val dave = w.client("dave")
        assertEquals(AcceptResult.PENDING, dave.engine.accept(link, null))
        w.quiesce()
        assertEquals("the request is recorded at the rank-1 committer", 1L, bob.count("ch_join_request"))

        // Day 6: rotation 2 — bob (rank 1) removes erin. The owner's pass may not run here: dave's
        // request is aged work for rank 0, and the owner's pass would admit him. For bob it is not aged
        // (day 5 + 2 × 48 h > day 6), so his pass takes only the Remove.
        w.advance(DmWorld.DAY)
        assertEquals(ChannelEngine.RemoveResult.REMOVED, bob.engine.remove(id, pseudonymOf(erin, id)))
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        // The production GC (the model relay runs none) collects released ops before a drain can end —
        // at every member: one member's open op of ns_0 refuses its removal and strands its switch.
        for (c in w.clients) collectOps(c)
        w.advance(70 * DmWorld.MINUTE)
        for (c in w.clients) c.hintPass()
        // A member's pass can defer once more — an unconsumed fetched row of ns_0 refuses the removal;
        // the row is consumed in the same pass and the next one switches.
        w.pump()
        for (c in w.clients) c.hintPass()
        assertEquals("generation 0 ended at once", 0L, owner.count("ch_generation", "generation = 0"))

        // Day 7: frank has been silent since his admission; bob's pass must evict frank AND refuse
        // dave — one commit with the Remove, the request deleted and counted.
        w.advance(DmWorld.DAY)
        backdateRefresh(bob, id, 70, pseudonymOf(frank, id))
        duePass(w, bob)
        assertEquals("the pass evicts frank", 1L, bob.count("ch_candidate", "own = 1 AND removes = 1"))
        assertEquals("and refuses dave", 0L, bob.count("ch_join_request"))
        assertTrue("the refusal is counted", bob.counters[ChannelCounters.Reason.ADMISSION_REFUSED] >= 1)
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        assertEquals("frank is removed", ChannelState.REMOVED, frank.channel(id)!!.state)
        assertEquals("dave is never admitted", ChannelState.JOINING, dave.channel(id)!!.state)
        assertTrue(bob.integrity().isEmpty())
    }

    /**
     * The review of S6 (§19.42), probe B: removed members' refresh rows starve the idle-eviction scan —
     * the SQL LIMIT applies before the roster filter, and 8 stale rows crowd out the real idler. The
     * stale rows of a pre-fix device (or one written before this fix ships) survive the removal, so the
     * pass walks the candidate set beyond one round; the idler is evicted at the +72-day pass and stays
     * removed at +102.
     */
    @Test
    fun idleEvictionWalksPastRemovedMembersStaleRowsToTheRealIdler() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val members = (1..9).map { w.client("m$it") }
        // one commit's floor fits four KeyPackages: the creating pass admits four, five more follow
        val id = ChannelScenes.channelOf(w, owner, members[0], members[1], members[2], members[3])
        for (m in members.drop(4)) ChannelScenes.admit(w, owner, id, m)
        val idler = members[8]
        // m1..m8 idle for 100 days; m9 (the idler) stays fresh.
        for (m in members.take(8)) backdateRefresh(owner, id, 100, pseudonymOf(m, id))
        w.advance(2 * DmWorld.DAY)
        duePass(w, owner)
        assertEquals("the pass evicts the eight idle members", 1L, owner.count("ch_candidate", "own = 1 AND removes = 1"))
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        for (m in members.take(8)) assertEquals("${m.name} is removed", ChannelState.REMOVED, m.channel(id)!!.state)

        // Everyone switches the new generation first (a member's pass can defer once — an unconsumed
        // fetched row of the old namespace refuses the removal; the next pass switches).
        w.advance(70 * DmWorld.MINUTE)
        for (c in w.clients) c.hintPass()
        w.pump()
        for (c in w.clients) c.hintPass()

        // The residue a pre-fix device holds: the eight removed members' stale rows, written as the
        // admission-day rows were.
        for (m in members.take(8)) backdateRefresh(owner, id, 100, pseudonymOf(m, id))

        // +72 days: the idler's last refresh (its admission) is past the 63-day policy, and the eight
        // stale rows sit ahead of it in the scan. Without the fix the SQL round returns exactly the
        // stale rows and the idler is never evicted.
        w.advance(72 * DmWorld.DAY)
        duePass(w, owner)
        assertEquals("the idler is evicted despite the stale rows", 1L, owner.count("ch_candidate", "own = 1 AND removes = 1"))
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        assertEquals(ChannelState.REMOVED, idler.channel(id)!!.state)

        // +102 days: the idler stays removed; no pass starves or resurrects anything.
        w.advance(30 * DmWorld.DAY)
        duePass(w, owner)
        assertEquals(0L, owner.count("ch_candidate", "own = 1 AND removes = 1"))
        assertEquals(ChannelState.REMOVED, idler.channel(id)!!.state)
        assertTrue(owner.integrity().isEmpty())
    }

    /**
     * §8.5, the review of S6 (§19.42): a removed member's rows — refresh, member-seen, sponsor — go at
     * its removal. The sponsor row lives on every other member's device (deleted where the winner's
     * merge learns of the removal); the member's own refresh row lives on its own device once it has
     * committed (its own commit's update path refreshes its leaf) — deleted where it merges its removal.
     */
    @Test
    fun aRemovedMembersRowsGoWithItsRemoval() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        makeCommitter(w, owner, bob, id) // bob at rank 1
        // bob resigns: his own commit's update path refreshes his leaf, and his device merges the winner
        // as a committer — his own `ch_member_refresh` row exists from here on.
        assertEquals(ChannelEngine.RemoveResult.REMOVED, bob.engine.resign(id))
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        val bobP = pseudonymOf(bob, id)
        assertEquals("the sponsor row of the admission", 1L, owner.count("ch_sponsor", "member = ?", bobP))
        assertTrue("the member's own refresh row (its own commit merged)", refreshDayOf(bob, id, bobP) >= 0)

        // The member leave and the committer's removal of the leaver.
        assertEquals(ChannelPostStep.LeaveResult.LEFT, bob.engine.leave(id))
        w.pump()
        owner.hintPass()
        assertEquals(1L, owner.count("ch_request", "kind = 'leave'"))
        w.advance(6 * DmWorld.HOUR)
        duePass(w, owner)
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        assertEquals(ChannelState.REMOVED, bob.channel(id)!!.state)
        assertEquals("the sponsor row went with the removal", 0L, owner.count("ch_sponsor", "member = ?", bobP))
        assertEquals("the removed member's own refresh row went at the merge", -1L, refreshDayOf(bob, id, bobP))
        assertTrue(owner.integrity().isEmpty())
    }

    // ----------------------------------------------------------------------------------------------- helpers

    /** The production GC's op collection (the model relay runs no GC): released ops die long before a drain ends. */
    private fun collectOps(client: ChannelClient) {
        client.database.transaction { tx ->
            tx.sql.exec("UPDATE outbox_op SET released = 1 WHERE released = 0 AND outcome <> 'pending'")
            tx.sql.exec("DELETE FROM outbox_op WHERE released = 1 AND ciphertext IS NULL")
        }
    }

    private fun rosterSize(client: ChannelClient, id: ChannelId): Int = client.database.transaction { tx ->
        val rows = org.ghost.messaging.channel.engine.MlsRows.of(
            client.channelStores.mls.rows(tx.sql, id.toByteArray(), DmTime.day(client.clock.now)),
        )
        client.contexts.open(id.toByteArray())!!.crypto
            .roster(id.toByteArray(), rows, DmTime.day(client.clock.now).toInt()).valueOrNull()!!.members.size
    }

    private fun pseudonymOf(client: ChannelClient, id: ChannelId): ByteArray =
        client.contexts.open(id.toByteArray())!!.pseudonym

    private fun generationNs(client: ChannelClient, id: ChannelId, generation: Long): ByteArray =
        client.database.transaction { tx ->
            var ns: ByteArray? = null
            tx.sql.query("SELECT namespace_id FROM ch_generation WHERE channel_id = ? AND generation = ?", listOf(id.toByteArray(), generation)) { ns = it.blob(0) }
            ns!!
        }

    private fun refreshDayOf(client: ChannelClient, id: ChannelId, member: ByteArray): Long =
        client.database.transaction { tx ->
            var d = -1L
            tx.sql.query("SELECT refresh_day FROM ch_member_refresh WHERE channel_id = ? AND member = ?", listOf(id.toByteArray(), member)) { d = it.long(0) }
            d
        }


    /** Every refresh day aged [days] back (what quiet days would say), or one member's. */
    private fun backdateRefresh(client: ChannelClient, id: ChannelId, days: Long, only: ByteArray? = null) {
        val day = DmTime.day(client.clock.now) - days
        client.database.transaction { tx ->
            if (only != null) {
                client.channelStores.members.putRefresh(tx, id.toByteArray(), only, day)
            } else {
                tx.sql.query("SELECT member FROM ch_member_refresh WHERE channel_id = ?", listOf(id.toByteArray())) { r ->
                    client.channelStores.members.putRefresh(tx, id.toByteArray(), r.blob(0), day)
                }
            }
        }
    }

    /** The member's PCS clock aged [days] back (the schedule row written directly). */
    private fun agePcsClock(client: ChannelClient, id: ChannelId, days: Long) {
        val day = DmTime.day(client.clock.now) - days
        client.database.transaction { tx ->
            val row = client.channelStores.channels.schedule(tx.sql, id.toByteArray())
            client.channelStores.channels.putSchedule(tx, id.toByteArray(), row?.nextSelfupdateDay ?: day, day, row?.nextPassMinute)
        }
    }

    /** A rank-0 context-change commit adding [bob] to the committers; recorded and settled everywhere. */
    private fun makeCommitter(w: ChannelWorld, owner: ChannelClient, bob: ChannelClient, id: ChannelId) {
        val before = ChannelAdversary.policy(owner, id)
        val after = org.ghost.crypto.bridge.ChannelPolicy(
            before.channelId, before.sizeClass, before.timerCode, before.timerVersion, before.historyPolicy,
            before.flags, before.idleEvictDays, before.pwVersion, before.name,
            listOf(pseudonymOf(owner, id), pseudonymOf(bob, id)), before.funders,
        )
        val change = ChannelAdversary.commit(owner, id, after)
        w.relay.holdAt = { name, s -> s.purpose == "committers" && name == "owner" }
        ChannelAdversary.stageOwn(owner, id, change, rank = 0)
        ChannelAdversary.inject(w, owner, id, change, "committers")
        w.quiesce()
        w.advance(21 * DmWorld.MINUTE)
        w.pump()
        for (client in w.clients) client.timePass()
        w.quiesce()
    }

    /** A session with a due scheduled pass (the spacing arm cleared first). */
    private fun duePass(w: ChannelWorld, client: ChannelClient) {
        clearArm(client, currentChannelId(client))
        client.sessionStart()
        w.advance(6 * DmWorld.MINUTE)
        client.timePass()
    }

    private fun currentChannelId(client: ChannelClient): ChannelId =
        client.database.transaction { tx ->
            var cid: ByteArray? = null
            tx.sql.query("SELECT channel_id FROM ch_channel") { cid = it.blob(0) }
            ChannelId(cid!!)
        }

    private fun clearArm(client: ChannelClient, id: ChannelId) {
        client.database.transaction { tx ->
            val row = client.channelStores.channels.schedule(tx.sql, id.toByteArray()) ?: return@transaction
            client.channelStores.channels.putSchedule(tx, id.toByteArray(), row.nextSelfupdateDay, row.lastOwnCommitDay, null)
        }
    }

    /** The member's `next_selfupdate_day` brought to today (its PRF slot, whenever it was). */
    private fun bringSlotTo(w: ChannelWorld, client: ChannelClient, id: ChannelId) {
        val day = DmTime.day(w.now)
        client.database.transaction { tx ->
            val row = client.channelStores.channels.schedule(tx.sql, id.toByteArray())
            client.channelStores.channels.putSchedule(tx, id.toByteArray(), day, row?.lastOwnCommitDay ?: day, row?.nextPassMinute)
        }
    }
}
