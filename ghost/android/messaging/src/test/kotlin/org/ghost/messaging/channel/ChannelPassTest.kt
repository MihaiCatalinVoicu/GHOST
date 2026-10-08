package org.ghost.messaging.channel

import org.ghost.crypto.bridge.ChannelPolicy
import org.ghost.messaging.DmWorld
import org.ghost.messaging.api.AcceptResult
import org.ghost.messaging.api.ChannelId
import org.ghost.messaging.api.CreateResult
import org.ghost.messaging.channel.engine.ChannelEngine
import org.ghost.messaging.channel.store.ChannelState
import org.ghost.messaging.channel.store.ChannelStore
import org.ghost.messaging.engine.DmTime
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test

/**
 * **The full committer pass (CH-PASS, slice S5b2)** — Phase 10 design §6.4 CO-7 … CO-9, CO-14 and §19.13 over the
 * real OpenMLS: the work-age rule (a moderator's scheduled pass ignores work younger than `r × 48 h` and takes it
 * once aged; the owner returning re-takes its work), the PCS cadence (7 days in a quiet channel, 1 day in channels
 * with timers ≤ 1 d), CO-9's self-update slots (the PRF slot fires at the first session after it, the retry at the
 * next session after 24 h when the tie-break was lost, the skip when CO-14 would refuse the commit), CO-7's
 * settle-first (a pass is never built over a held candidate; it is delayed to the settle point, never blocked, and
 * works in e + 1 afterwards), the user-action Remove (a moderator removes a member at once; removing a committer
 * updates the context), and SCN-CD: ranks 0 and 1 commit on one epoch, the loser — with an Add — clears, deletes
 * its staged Welcome and re-passes; the joiner receives exactly one Welcome and its KeyPackage is consumed once
 * (MM-19); the INDETERMINATE variant (MM-32's engine half: the committer's store closes INDETERMINATE while the
 * relays kept the copy; the others merge it and post; the committer adopts its own from their successors).
 */
class ChannelPassTest {

    @Before
    fun native() {
        assumeTrue("ghost-dm-host is not loaded (-Dghost.dm.native)", ChannelWorld.nativeAvailable())
    }

    // ------------------------------------------------------------------------------------ the work-age rule

    /** §19.13 item 4: rank 1's scheduled pass does not commit a request it recorded less than 48 h ago. */
    @Test
    fun aModeratorsScheduledPassIgnoresWorkYoungerThanFortyEightHours() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        makeCommitter(w, owner, bob, id)
        assertEquals(2L, owner.channel(id)!!.epoch)
        // dave's request, recorded today: fresh for rank 1, the owner's to take.
        val dave = w.client("dave")
        assertEquals(AcceptResult.PENDING, dave.engine.accept(ChannelAdmissionTest.invite(owner, id), null))
        w.quiesce()
        assertEquals(1L, bob.count("ch_join_request"))
        w.advance(6 * DmWorld.HOUR)
        duePass(w, bob)
        assertEquals("fresh work is not the moderator's", 0L, bob.count("ch_candidate", "own = 1"))
        assertEquals("the request waits", 1L, bob.count("ch_join_request"))
        w.advance(2 * DmWorld.DAY)
        duePass(w, bob)
        assertEquals("aged 48 h, the moderator takes it", 1L, bob.count("ch_candidate", "own = 1 AND rank = 1"))
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        assertEquals(ChannelState.ACTIVE, dave.channel(id)!!.state)
        assertTrue(bob.integrity().isEmpty())
    }

    /** The owner returning re-takes work a moderator could have taken: rank 0 has no age filter and wins the race. */
    @Test
    fun theOwnerReturningTakesAgedWorkFirst() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        makeCommitter(w, owner, bob, id)
        val dave = w.client("dave")
        assertEquals(AcceptResult.PENDING, dave.engine.accept(ChannelAdmissionTest.invite(owner, id), null))
        w.quiesce()
        w.advance(2 * DmWorld.DAY)
        duePass(w, owner)
        assertEquals("the owner's pass takes the aged work at once", 1L, owner.count("ch_candidate", "own = 1 AND rank = 0"))
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        assertEquals(ChannelState.ACTIVE, dave.channel(id)!!.state)
        // the moderator's later pass finds the member admitted: the request is refused and deleted, no commit.
        w.advance(6 * DmWorld.HOUR)
        duePass(w, bob)
        assertEquals(0L, bob.count("ch_join_request"))
        assertEquals(0L, bob.count("ch_candidate", "own = 1"))
        assertTrue(bob.integrity().isEmpty())
    }

    // ------------------------------------------------------------------------------------------ the PCS cadence

    /** §6.8, CO-8: a quiet 7-day channel gets the empty PCS commit when the owner's last commit is 7 days old. */
    @Test
    fun aQuietChannelPcsCommitsAfterSevenDays() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        w.pastSettleWindow()
        w.quiesce()
        assertEquals(1L, owner.channel(id)!!.epoch)
        agePcsClock(owner, id, 7)
        duePass(w, owner)
        assertEquals("the PCS commit, empty with a path", 1L, owner.count("ch_candidate", "own = 1"))
        assertEquals("the schedule saw the commit", DmTime.day(w.now), scheduleOf(owner, id)!!.lastOwnCommitDay)
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        assertEquals(2L, owner.channel(id)!!.epoch)
        assertEquals(2L, bob.channel(id)!!.epoch)
        assertTrue(owner.integrity().isEmpty())
    }

    /** Q36, §19.19: in a channel with timers ≤ 1 d the PCS cadence is a day (timer code 1 = one hour). */
    @Test
    fun aShortTimerChannelPcsCommitsDaily() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val created = owner.engine.create("scurt".toByteArray(), 1, 0, false)
        assertEquals(CreateResult.Status.CREATED, created.status)
        val id = created.channel!!
        agePcsClock(owner, id, 1)
        duePass(w, owner)
        assertEquals("a day-old last commit PCS-commits in a short-timer channel", 1L, owner.count("ch_candidate", "own = 1"))
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        assertEquals(1L, owner.channel(id)!!.epoch)
        assertTrue(owner.integrity().isEmpty())
    }

    // ---------------------------------------------------------------------------------------------- CO-9 slots

    /** CO-9: the PRF slot fires at the first session after it — an empty commit, rank 255, with a path. */
    @Test
    fun aRank255MemberSelfUpdatesAtItsSlot() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val dave = w.client("dave")
        val id = ChannelScenes.channelOf(w, owner, dave)
        // At epoch 1 in a 2-member channel CO-14 refuses a KeyPackage leaf (e < k = 2): open epoch 2 with an
        // own PCS commit first, then let the slot fire.
        agePcsClock(owner, id, 7)
        duePass(w, owner)
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        assertEquals(2L, owner.channel(id)!!.epoch)
        bringSlotTo(w, dave, id)
        duePass(w, dave)
        assertEquals("the self-update commits at the first session after the slot", 1L, dave.count("ch_candidate", "own = 1 AND rank = 255"))
        val schedule = scheduleOf(dave, id)!!
        assertTrue("the next period's slot is armed", schedule.nextSelfupdateDay > DmTime.day(w.now))
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        assertEquals(3L, owner.channel(id)!!.epoch)
        assertTrue(dave.integrity().isEmpty())
    }

    /** CO-14 at the pass: a slot at which the rule would refuse the member's own commit is skipped, not retried. */
    @Test
    fun aSlotCO14WouldRefuseIsSkipped() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val dave = w.client("dave")
        val id = ChannelScenes.channelOf(w, owner, bob, dave)
        // Epoch 1, three members: k = min(8, 3) = 3 and dave's KeyPackage leaf has refresh_epoch 0 — the rule
        // refuses (e < k), so the pass skips the slot and arms the next period's.
        bringSlotTo(w, dave, id)
        duePass(w, dave)
        assertEquals("CO-14 would refuse it: no self-update", 0L, dave.count("ch_candidate"))
        val schedule = scheduleOf(dave, id)!!
        assertTrue("the slot is consumed", schedule.nextSelfupdateDay > DmTime.day(w.now))
        assertTrue(dave.integrity().isEmpty())
    }

    /** CO-9: a self-update that lost the tie-break retries at the next session after 24 h (day-granular). */
    @Test
    fun aLostSelfUpdateRetriesAtTheNextSessionAfterADay() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val dave = w.client("dave")
        val id = ChannelScenes.channelOf(w, owner, dave)
        agePcsClock(owner, id, 7)
        duePass(w, owner)
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        assertEquals(2L, owner.channel(id)!!.epoch)
        // Both commit on epoch 2, neither seeing the other: dave's self-update at its slot, the owner's PCS.
        bringSlotTo(w, dave, id)
        duePass(w, dave)
        assertEquals(1L, dave.count("ch_candidate", "own = 1 AND rank = 255"))
        agePcsClock(owner, id, 7)
        duePass(w, owner)
        assertEquals(1L, owner.count("ch_candidate", "own = 1 AND rank = 0"))
        val settledDay = DmTime.day(w.now)
        w.quiesce()
        assertEquals("dave holds both candidates", 2L, dave.count("ch_candidate"))
        w.pastSettleWindow()
        w.quiesce()
        assertEquals("rank 0 wins the tie (CO-3)", 3L, owner.channel(id)!!.epoch)
        assertEquals("dave converged", 3L, dave.channel(id)!!.epoch)
        assertArrayEquals("no fork", winnerOf(owner, id, 2), winnerOf(dave, id, 2))
        assertEquals("dave lost", 0L, dave.count("ch_candidate"))
        val schedule = scheduleOf(dave, id)!!
        assertEquals("the retry is armed for the next day", settledDay + 1, schedule.nextSelfupdateDay)
        w.advance(1 * DmWorld.DAY)
        duePass(w, dave)
        assertEquals("the retry commits at the next session", 1L, dave.count("ch_candidate", "own = 1 AND rank = 255"))
        assertTrue(dave.integrity().isEmpty())
    }

    // ------------------------------------------------------------------------------------------------- CO-7

    /** CO-7 (D-1): the pass is never built over a held candidate; it is delayed to the settle point, not blocked. */
    @Test
    fun aPassIsNeverBuiltOverAHeldCandidate() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        makeCommitter(w, owner, bob, id)
        assertEquals(2L, owner.channel(id)!!.epoch)
        // Work pending at the owner, and a held valid candidate (rank 1, not CO-14-governed): the pass waits.
        val dave = w.client("dave")
        assertEquals(AcceptResult.PENDING, dave.engine.accept(ChannelAdmissionTest.invite(owner, id), null))
        w.quiesce()
        val b = ChannelAdversary.commit(bob, id)
        ChannelAdversary.stageOwn(bob, id, b, rank = 1)
        ChannelAdversary.inject(w, bob, id, b, "co7-B")
        w.pump()
        owner.hintPass()
        assertEquals(1L, owner.count("ch_candidate", "own = 0"))
        duePass(w, owner)
        assertEquals("the pass is delayed, not blocked", 0L, owner.count("ch_candidate", "own = 1"))
        // The window passes with one relay round (CO-4 (ii)) and the time-triggered pass settles the epoch;
        // the next scheduled pass works in e + 1.
        w.advance(21 * DmWorld.MINUTE)
        w.pump()
        owner.timePass()
        assertEquals(3L, owner.channel(id)!!.epoch)
        duePass(w, owner)
        assertEquals("the pass worked in e + 1", 1L, owner.count("ch_candidate", "own = 1 AND rank = 0"))
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        assertEquals(ChannelState.ACTIVE, dave.channel(id)!!.state)
        assertTrue(owner.integrity().isEmpty())
    }

    // --------------------------------------------------------------------------------------- the user Remove

    /** §6.6, §19.13: a moderator's user-action Remove is a pass at once — no scheduling, whatever its rank. */
    @Test
    fun aModeratorRemovesAMemberAtOnce() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val carol = w.client("carol")
        val id = ChannelScenes.channelOf(w, owner, bob, carol)
        makeCommitter(w, owner, bob, id)
        assertEquals(2L, owner.channel(id)!!.epoch)
        val carolP = pseudonymOf(carol, id)
        assertEquals(ChannelEngine.RemoveResult.REMOVED, bob.engine.remove(id, carolP))
        assertEquals("the Remove commits immediately", 1L, bob.count("ch_candidate", "own = 1 AND rank = 1"))
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        assertEquals("carol is removed everywhere", ChannelState.REMOVED, carol.channel(id)!!.state)
        assertEquals(3L, owner.channel(id)!!.epoch)
        assertEquals(3L, bob.channel(id)!!.epoch)
        assertTrue(owner.integrity().isEmpty())
    }

    /** Removing a committer carries the context change: its key leaves `committers` (and the digest changes). */
    @Test
    fun removingACommitterUpdatesTheCommitters() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        makeCommitter(w, owner, bob, id)
        assertEquals(2, ChannelAdversary.policy(owner, id).committers.size)
        val bobP = pseudonymOf(bob, id)
        assertEquals(ChannelEngine.RemoveResult.REMOVED, owner.engine.remove(id, bobP))
        assertEquals("a removing candidate holds the posts (CO-13)", 1L, owner.count("ch_candidate", "own = 1 AND removes = 1"))
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        assertEquals(ChannelState.REMOVED, bob.channel(id)!!.state)
        assertEquals(1, ChannelAdversary.policy(owner, id).committers.size)
        assertTrue(owner.integrity().isEmpty())
    }

    /** SCN-CM's shape: a flooding rank-255 member delays the pass to the settle point, never blocks it — and a committer's pass still runs and can remove the flooder. */
    @Test
    fun aFloodedSelfUpdateDelaysThePassAndTheFlooderCanBeRemoved() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val dave = w.client("dave")
        val id = ChannelScenes.channelOf(w, owner, dave)
        // Open epoch 2 (at epoch 1 CO-14 would refuse the flood outright) and flood it with self-updates:
        // one candidate per sender and epoch is kept (§6.3.5), the copies are the same.
        agePcsClock(owner, id, 7)
        duePass(w, owner)
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        assertEquals(2L, owner.channel(id)!!.epoch)
        val flood = ChannelAdversary.commit(dave, id)
        // The relay never serves an author its own blob: stage the flood at dave like his pass would, so
        // dave advances with everyone when the epoch settles.
        ChannelAdversary.stageOwn(dave, id, flood, rank = 255)
        ChannelAdversary.inject(w, dave, id, flood, "flood-1")
        ChannelAdversary.inject(w, dave, id, flood, "flood-2")
        ChannelAdversary.inject(w, dave, id, flood, "flood-3")
        w.pump()
        owner.hintPass()
        assertEquals("one candidate per sender and epoch, however many copies", 1L, owner.count("ch_candidate", "own = 0"))
        // Work pending (carol's request) and the flood candidate: the pass waits for the settle point.
        val carol = w.client("carol")
        assertEquals(AcceptResult.PENDING, carol.engine.accept(ChannelAdmissionTest.invite(owner, id), null))
        w.quiesce()
        duePass(w, owner)
        assertEquals("the flood delays the pass, it never blocks it", 0L, owner.count("ch_candidate", "own = 1"))
        w.advance(21 * DmWorld.MINUTE)
        w.pump()
        owner.timePass()
        assertEquals(3L, owner.channel(id)!!.epoch)
        duePass(w, owner)
        assertEquals("the pass ran in e + 1", 1L, owner.count("ch_candidate", "own = 1 AND rank = 0"))
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        assertEquals(ChannelState.ACTIVE, carol.channel(id)!!.state)
        assertEquals(4L, owner.channel(id)!!.epoch)
        // The committer removes the flooder (a removal rotates — §6.5 — so this is the test's last pass).
        val daveP = pseudonymOf(dave, id)
        assertEquals(ChannelEngine.RemoveResult.REMOVED, owner.engine.remove(id, daveP))
        w.quiesce()
        assertEquals("dave recorded the removing candidate", 1L, dave.count("ch_candidate", "own = 0"))
        assertEquals("dave is at the owner's epoch", owner.channel(id)!!.epoch, dave.channel(id)!!.epoch)
        w.pastSettleWindow()
        w.quiesce()
        // A removed member keeps its removal epoch (it merges no next one); the others advance.
        assertEquals(4L, dave.channel(id)!!.epoch)
        assertEquals(ChannelState.REMOVED, dave.channel(id)!!.state)
        assertTrue(owner.integrity().isEmpty())
    }

    // ------------------------------------------------------------------------------------------------ SCN-CD

    /** SCN-CD: ranks 0 and 1 commit on one epoch, the loser with an Add; the joiner gets exactly one Welcome. */
    @Test
    fun ranksZeroAndOneCommitOnOneEpochAndTheLoserRePasses() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        makeCommitter(w, owner, bob, id)
        assertEquals(2L, owner.channel(id)!!.epoch)
        val dave = w.client("dave")
        assertEquals(AcceptResult.PENDING, dave.engine.accept(ChannelAdmissionTest.invite(owner, id), null))
        w.quiesce()
        val welcomesBefore = w.relay.stored.count { it.purpose == "welcome" && !it.injected }
        // Age the request 48 h so rank 1 may take it, then both passes run before either sees the other:
        // two candidates on epoch 2, each with dave's Add.
        w.advance(2 * DmWorld.DAY)
        clearArm(owner, id)
        clearArm(bob, id)
        owner.sessionStart()
        bob.sessionStart()
        w.advance(6 * DmWorld.MINUTE)
        bob.timePass()
        owner.timePass()
        assertEquals(1L, bob.count("ch_candidate", "own = 1 AND rank = 1"))
        assertEquals(1L, owner.count("ch_candidate", "own = 1 AND rank = 0"))
        w.pump()
        owner.hintPass()
        bob.hintPass()
        w.advance(21 * DmWorld.MINUTE)
        w.pump()
        owner.timePass()
        bob.timePass()
        // CO-3, no successors: rank 0 wins everywhere; the loser cleared its pending commit, its staged
        // Welcome dying with the candidate row.
        assertEquals(3L, owner.channel(id)!!.epoch)
        assertEquals(3L, bob.channel(id)!!.epoch)
        assertNull("the loser's candidate is gone", ownRow(bob, id))
        w.quiesce()
        // Exactly one Welcome (the winner's) reaches dave; his KeyPackage is consumed exactly once.
        val welcomes = w.relay.stored.count { it.purpose == "welcome" && !it.injected }
        assertEquals("one Welcome, of the winning commit (MM-19)", welcomesBefore + 1, welcomes)
        w.quiesce()
        assertEquals(ChannelState.ACTIVE, dave.channel(id)!!.state)
        assertEquals("the join state is consumed once", 0L, dave.count("ch_join"))
        assertEquals(3L, dave.channel(id)!!.epoch)
        // The loser re-passes: the work is already done by the winner, so it is refused and deleted.
        w.advance(6 * DmWorld.HOUR)
        duePass(w, bob)
        assertEquals(0L, bob.count("ch_join_request"))
        assertEquals(0L, bob.count("ch_candidate", "own = 1"))
        assertTrue(bob.integrity().isEmpty())
    }

    /**
     * SCN-CD's INDETERMINATE variant (MM-32's engine half): the committer's store closes INDETERMINATE while the
     * relays kept the copy; the others merge it and post; the committer adopts its own commit from their
     * successors — and its staged Welcome goes out exactly once.
     */
    @Test
    fun anIndeterminateOwnCommitWithAnAddIsAdoptedFromTheSuccessors() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val alice = w.client("alice")
        val id = ChannelScenes.channelOf(w, owner, bob, alice)
        val dave = w.client("dave")
        assertEquals(AcceptResult.PENDING, dave.engine.accept(ChannelAdmissionTest.invite(owner, id), null))
        w.quiesce()
        val welcomesBefore = w.relay.stored.count { it.purpose == "welcome" && !it.injected }
        w.relay.outcomeFor = { client, purpose -> if (client.name == "owner" && purpose == "commit") "indeterminate" else "sent" }
        w.advance(6 * DmWorld.HOUR)
        w.admissionPass(owner)
        // INDETERMINATE is not FAILED: the relays kept a copy, and everyone but the owner records it.
        w.pump()
        for (c in listOf(owner, bob, alice)) c.hintPass()
        assertEquals(1L, bob.count("ch_candidate"))
        assertEquals(1L, alice.count("ch_candidate"))
        assertEquals(1L, owner.count("ch_candidate", "own = 1 AND verified = 0"))
        // bob and alice settle the commit and post on the branch it opened — the successor senders.
        w.advance(21 * DmWorld.MINUTE)
        w.pump()
        bob.timePass()
        alice.timePass()
        assertEquals(2L, bob.channel(id)!!.epoch)
        ChannelScenes.post(bob, id, "de la bob")
        ChannelScenes.post(alice, id, "de la alice")
        w.pump()
        // the owner's op never verified; the posts stay unopenable and deferred, and the trial of its own
        // commit shows the successors: adopted (CO-4 (a)).
        w.advance(21 * DmWorld.MINUTE)
        w.pump()
        owner.timePass()
        assertEquals("the committer adopted its own commit from the successors", 2L, owner.channel(id)!!.epoch)
        assertArrayEquals(
            "both branches settled the same winner (CS-C3)",
            winnerOf(bob, id, 1), winnerOf(owner, id, 1),
        )
        w.quiesce()
        val welcomes = w.relay.stored.count { it.purpose == "welcome" && !it.injected }
        assertEquals("the adopted commit's Welcome went out exactly once", welcomesBefore + 1, welcomes)
        w.quiesce()
        assertEquals(ChannelState.ACTIVE, dave.channel(id)!!.state)
        assertTrue(owner.displayed(id).containsAll(listOf("de la bob", "de la alice")))
        assertTrue(owner.integrity().isEmpty())
    }

    // ----------------------------------------------------------------------------------------------- helpers

    /**
     * A session with a due scheduled pass: the arm a previous pass left is cleared (the spacing is not what
     * these scenes test), a relay session start schedules the pass `U[0, 5 min]` later, and the time-triggered
     * pass after the jitter runs it.
     */
    private fun duePass(w: ChannelWorld, client: ChannelClient) {
        clearArm(client, currentChannelId(client))
        client.sessionStart()
        w.advance(6 * DmWorld.MINUTE)
        client.timePass()
    }

    /** The client's only channel (these scenes run one channel per world). */
    private fun currentChannelId(client: ChannelClient): ChannelId =
        client.database.transaction { tx ->
            var id: ByteArray? = null
            tx.sql.query("SELECT channel_id FROM ch_channel") { id = it.blob(0) }
            ChannelId(id!!)
        }

    /** Clears the channel's scheduled-pass arm (`next_pass_minute`), keeping the rest of the row. */
    private fun clearArm(client: ChannelClient, id: ChannelId) {
        client.database.transaction { tx ->
            val row = client.channelStores.channels.schedule(tx.sql, id.toByteArray()) ?: return@transaction
            client.channelStores.channels.putSchedule(tx, id.toByteArray(), row.nextSelfupdateDay, row.lastOwnCommitDay, null)
        }
    }

    /** The member's PCS clock aged [days] back (the schedule row written directly, what quiet days would say). */
    private fun agePcsClock(client: ChannelClient, id: ChannelId, days: Long) {
        val day = DmTime.day(client.clock.now) - days
        client.database.transaction { tx ->
            val row = client.channelStores.channels.schedule(tx.sql, id.toByteArray())
            client.channelStores.channels.putSchedule(
                tx, id.toByteArray(),
                row?.nextSelfupdateDay ?: day, day, row?.nextPassMinute,
            )
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

    private fun scheduleOf(client: ChannelClient, id: ChannelId): ChannelStore.ScheduleRow? =
        client.database.transaction { tx -> client.channelStores.channels.schedule(tx.sql, id.toByteArray()) }

    private fun pseudonymOf(client: ChannelClient, id: ChannelId): ByteArray =
        client.contexts.open(id.toByteArray())!!.pseudonym

    private fun ownRow(client: ChannelClient, id: ChannelId): org.ghost.messaging.channel.store.CandidateStore.CandidateRow? {
        val epoch = client.channel(id)!!.epoch
        return client.database.transaction { tx ->
            client.channelStores.candidates.own(tx.sql, id.toByteArray(), epoch)
        }
    }

    private fun winnerOf(client: ChannelClient, id: ChannelId, epoch: Long): ByteArray? =
        client.database.transaction { tx -> client.channelStores.epochs.logged(tx.sql, id.toByteArray(), epoch)?.winnerHash }

    /** A rank-0 context-change commit adding [bob] to the committers; recorded and settled everywhere (one epoch). */
    private fun makeCommitter(w: ChannelWorld, owner: ChannelClient, bob: ChannelClient, id: ChannelId) {
        val before = ChannelAdversary.policy(owner, id)
        val after = ChannelPolicy(
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
}
