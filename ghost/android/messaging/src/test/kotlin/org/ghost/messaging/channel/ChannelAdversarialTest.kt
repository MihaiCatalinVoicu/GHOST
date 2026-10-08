package org.ghost.messaging.channel

import org.ghost.crypto.bridge.ChannelPolicy
import org.ghost.messaging.DmWorld
import org.ghost.messaging.api.AcceptResult
import org.ghost.messaging.api.ChannelId
import org.ghost.messaging.channel.ChannelScenes.get
import org.ghost.messaging.channel.engine.ChannelCounters
import org.ghost.messaging.channel.engine.ChannelLivenessStep
import org.ghost.messaging.channel.store.ChannelState
import org.ghost.messaging.engine.DmTime
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test

/**
 * **SCN-CM, the adversarial-members suite** (Phase 10 design §12.4 SCN-CM, §12.6; slice S5c), over
 * the real OpenMLS — the cases S5's engine can reach without the S6/S7 flows (the rejoin/restore
 * cases, the draining-namespace spam and the silent orphan are S6/S7's, §19.37 row 46 and §19.15):
 *
 *  - **LATE_COMMIT** with a better rank after everyone settled: nobody moves (CO-6's finality is
 *    sticky, MM-16) — the settled members record a fork signal and stay on the winner;
 *  - a **returning member** that holds a successor sender of the winner when it settles picks the
 *    successors' branch even with the late better-ranked copy in front of it (CO-3, MM-24, D-2);
 *  - **GRIND**: a member that kept its pre-settle state stores a hash-ground self-update for the
 *    settled epoch — nobody moves, and catch-up picks the successors' branch (CO-6/CO-3);
 *  - **SPAM_UNOPENABLE** in a quiet channel: bulk junk a member seals under the current epoch's key
 *    id (the recognition matches, nothing opens) pushes the victim to `resync_needed` once CO-11's
 *    window matures, and the next progress (one other member's message, `min(2, n − 1)` in a
 *    2-member channel) returns it to `active`; with continuing progress the victim instead raises
 *    `split_suspected` (CO-12, the adopted D-3 wording);
 *  - a member whose clock runs **10 days slow** processes every commit like the others — the
 *    constant KeyPackage lifetime (Q42 (a), §19.29.1) leaves no clock a commit's validity reads,
 *    so there is no stall and no divergence (the withdrawn `clock_blocked` state does not exist).
 *
 * The FLOOD shape (CO-14 refuses the excess, the committer still passes and removes the flooder)
 * is S5b2's [ChannelPassTest]; RESEAL_ORDER is S4's RO-C; PROPOSE and FORGE_OWN are S4's RP-C;
 * the finite-lifetime commit (MM-46) is [ChannelSettleTest]; REPLACE_BOOTSTRAP is S4's JN — each
 * verified green in this package's run.
 */
class ChannelAdversarialTest {

    @Before
    fun native() {
        assumeTrue("ghost-dm-host is not loaded (-Dghost.dm.native)", ChannelWorld.nativeAvailable())
    }

    /** LATE_COMMIT: everyone settled the rank-1 winner (carol's post was its successor); the late rank-0 commit moves nobody. */
    @Test
    fun aLateBetterRankCommitAfterEveryoneSettledMovesNobody() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val alice = w.client("alice")
        val carol = w.client("carol")
        val id = ChannelScenes.channelOf(w, owner, bob, alice, carol)
        makeCommitter(w, owner, bob, id)
        assertEquals(2L, owner.channel(id)!!.epoch)
        // The race on epoch 2: bob's rank-1 self-update B against the owner's rank-0 commit O.
        // B is held from its author alone; O is held from everyone but alice — so the owner holds
        // his staged O and received B, alice holds both, and carol's branch is B's (S5b1's pattern).
        val b = ChannelAdversary.commit(bob, id)
        val o = ChannelAdversary.commit(owner, id)
        w.relay.holdAt = { name, s ->
            (s.purpose == "committers" && name == "owner") ||
                (s.purpose == "late-B" && name == "bob") ||
                (s.purpose == "late-O" && (name == "owner" || name == "bob" || name == "carol"))
        }
        ChannelAdversary.stageOwn(bob, id, b, rank = 1)
        ChannelAdversary.stageOwn(owner, id, o, rank = 0)
        ChannelAdversary.inject(w, bob, id, b, "late-B")
        ChannelAdversary.inject(w, owner, id, o, "late-O")
        deliver(w, owner, alice, carol)
        // bob settles his own B and posts on the branch it opened; carol — holding B only — settles
        // B too and posts on its branch: the successor sender that decides the others' trials.
        w.advance(21 * DmWorld.MINUTE)
        w.pump()
        bob.timePass()
        assertEquals(3L, bob.channel(id)!!.epoch)
        ChannelScenes.post(bob, id, "ramura lui bob")
        w.pump()
        carol.hintPass()
        w.advance(21 * DmWorld.MINUTE)
        w.pump()
        carol.timePass()
        assertArrayEquals(b.hash, winnerOf(carol, id, 2))
        ChannelScenes.post(carol, id, "si de la carol")
        w.pump()
        owner.hintPass()
        alice.hintPass()
        // The online majority settles B: carol is a successor sender of B (bob, its committer, is
        // excluded) — the successor count beats the rank (CO-3).
        w.advance(21 * DmWorld.MINUTE)
        w.pump()
        owner.timePass()
        alice.timePass()
        assertEquals(3L, owner.channel(id)!!.epoch)
        assertEquals(3L, alice.channel(id)!!.epoch)
        assertEquals(0, owner[ChannelCounters.Reason.RESURRECTED_COMMIT])
        assertArrayEquals(
            "the owner settles B too: counters=${owner.counters.snapshot().filter { it.value > 0 }} " +
                "o=${o.hash.joinToString("") { "%02x".format(it) }}",
            b.hash, winnerOf(owner, id, 2),
        )
        assertArrayEquals(b.hash, winnerOf(alice, id, 2))
        // The late better-ranked copy: O (rank 0) is released to the members that never held it —
        // at bob and carol it is a late candidate of a final epoch; at alice it was a candidate
        // before the settle (consumed with the epoch's rows).
        w.relay.holdAt = { name, s -> s.purpose == "committers" || (s.purpose == "late-O" && name == "owner") }
        w.pump()
        for (client in listOf(bob, carol)) {
            client.hintPass()
            assertEquals("a late better rank never moves a settled member (CO-6)", 3L, client.channel(id)!!.epoch)
            assertEquals(1, client[ChannelCounters.Reason.LATE_CANDIDATE])
            assertEquals(1L, client.count("ch_fork_signal"))
            assertArrayEquals("the winner stands", b.hash, winnerOf(client, id, 2))
        }
        alice.hintPass()
        assertEquals(3L, alice.channel(id)!!.epoch)
        assertEquals(0, alice[ChannelCounters.Reason.LATE_CANDIDATE])
        assertArrayEquals(b.hash, winnerOf(alice, id, 2))
        assertEquals(0, owner[ChannelCounters.Reason.RESURRECTED_COMMIT])
        assertTrue(owner.integrity().isEmpty())
    }

    /** A member that was offline through the race converges on the successors' branch when it returns (MM-24, D-2). */
    @Test
    fun aReturningMemberHoldingASuccessorPicksTheMajorityBranch() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val alice = w.client("alice")
        val carol = w.client("carol")
        val id = ChannelScenes.channelOf(w, owner, bob, alice, carol)
        makeCommitter(w, owner, bob, id)
        // dave joins at epoch 3, then goes dark before the race on epoch 3.
        val dave = w.client("dave")
        ChannelScenes.admit(w, owner, id, dave)
        assertEquals(3L, owner.channel(id)!!.epoch)
        // The race: bob's rank-1 commit B against the owner's rank-0 O. B is held from its author;
        // O is held from everyone but alice (S5b1's delivery); dave, dark since before the race,
        // sees none of it — and the late O stays held at the relay for his return.
        val b = ChannelAdversary.commit(bob, id)
        val o = ChannelAdversary.commit(owner, id)
        w.relay.holdAt = { name, s ->
            (s.purpose == "ret-B" && (name == "bob" || name == "dave")) ||
                (s.purpose == "ret-O" && (name == "owner" || name == "bob" || name == "carol" || name == "dave"))
        }
        ChannelAdversary.stageOwn(bob, id, b, rank = 1)
        ChannelAdversary.stageOwn(owner, id, o, rank = 0)
        ChannelAdversary.inject(w, bob, id, b, "ret-B")
        ChannelAdversary.inject(w, owner, id, o, "ret-O")
        // The online four: carol holds B alone and settles it first; bob posts on his branch; then
        // carol's post is the successor sender that decides alice's and the owner's trials.
        deliver(w, owner, alice, carol)
        w.advance(21 * DmWorld.MINUTE)
        w.pump()
        carol.timePass()
        assertArrayEquals("carol settles the only candidate she holds", b.hash, winnerOf(carol, id, 3))
        ChannelScenes.post(bob, id, "ramura lui bob")
        w.pump()
        carol.hintPass()
        w.advance(21 * DmWorld.MINUTE)
        w.pump()
        carol.timePass()
        ChannelScenes.post(carol, id, "si de la carol")
        w.pump()
        owner.hintPass()
        alice.hintPass()
        w.advance(21 * DmWorld.MINUTE)
        w.pump()
        owner.timePass()
        alice.timePass()
        assertArrayEquals("the successor beats the rank at the owner too (CO-3)", b.hash, winnerOf(owner, id, 3))
        assertArrayEquals(b.hash, winnerOf(alice, id, 3))
        assertArrayEquals(b.hash, winnerOf(carol, id, 3))
        // dave returns once the race's store hours lie past the settle window (CO-4 (i) reads the
        // relay's store hour + 60 min): his first listing pass fetches B, the held O and the
        // successors' posts together; the posts defer (epoch 4), the trials count them under B's
        // branch (CO-3) — the rank-0 copy loses to the successors' branch.
        w.advance(2 * DmWorld.HOUR)
        w.relay.holdAt = { _, _ -> false }
        w.pump()
        dave.hintPass()
        assertEquals("dave caught up in one pass (CO-4's anchors lie in the past)", 4L, dave.channel(id)!!.epoch)
        assertArrayEquals("the successors' branch, not the better rank (MM-24)", b.hash, winnerOf(dave, id, 3))
        assertTrue(dave.displayed(id).contains("si de la carol"))
        assertTrue(dave.integrity().isEmpty())
    }

    /** GRIND: a member keeps its pre-settle state, grinds a self-update below the settled rank-255 winner — nobody moves. */
    @Test
    fun aGroundSelfUpdateForASettledEpochMovesNobodyAndCatchUpFollowsTheSuccessors() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val dave = w.client("dave")
        val id = ChannelScenes.channelOf(w, owner, dave)
        // The rank-255 winner: dave's self-update takes epoch 2 (the owner's PCS is the
        // alternative). At epoch 1 CO-14 refuses the KeyPackage leaf (e < k), so open epoch 2
        // with the owner's PCS first (S5b2's shape) and let it settle.
        agePcsClock(owner, id, 7)
        duePass(w, owner)
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        assertEquals(2L, owner.channel(id)!!.epoch)
        // dave builds his self-update W and — before staging anything (a staged pending commit
        // would refuse a second build) — grinds: each attempt burns one native draw (a discarded
        // KeyPackage build; the seeded stream would else redraw the identical commit) and builds
        // a fresh self-update, until one hashes below W.
        val w1 = ChannelAdversary.commit(dave, id)
        fun groundOnce(): ChannelAdversary.Built {
            ChannelAdversary.burnDraw(dave, id)
            return ChannelAdversary.commit(dave, id)
        }
        var ground = groundOnce()
        var tries = 1
        // The process-global seeded stream (F-S5-10) makes the draws here depend on every test that
        // ran before this one: the cap must clear the unluckiest stream position, not the average
        // one — 64 consecutive misses is 2^-64 for a uniform hash.
        while (compareHash(ground.hash, w1.hash) >= 0 && tries < 64) {
            ground = groundOnce()
            tries++
        }
        assertTrue("a uniform hash grinds below another in a few tries ($tries)", compareHash(ground.hash, w1.hash) < 0)
        assertNotEquals(w1.hash.toList(), ground.hash.toList())
        ChannelAdversary.stageOwn(dave, id, w1, rank = 255)
        ChannelAdversary.inject(w, dave, id, w1, "grind-W")
        // Everyone settles W; then the ground copy is stored for the now-final epoch 2.
        settleEveryone(w, owner)
        assertEquals(3L, owner.channel(id)!!.epoch)
        assertEquals(3L, dave.channel(id)!!.epoch)
        assertArrayEquals(w1.hash, winnerOf(owner, id, 2))
        w.relay.holdAt = { name, s -> s.purpose == "grind-G" && name == "dave" }
        ChannelAdversary.inject(w, dave, id, ground, "grind-G")
        ChannelScenes.post(owner, id, "ramura invingatoare")
        w.pump()
        owner.hintPass()
        assertEquals("the ground self-update never moves a settled member (CO-6)", 3L, owner.channel(id)!!.epoch)
        assertEquals(1, owner[ChannelCounters.Reason.LATE_CANDIDATE])
        assertEquals(1L, owner.count("ch_fork_signal"))
        assertArrayEquals(w1.hash, winnerOf(owner, id, 2))
        // A newcomer admitted afterwards lands on the same branch (the ground copy reached nobody
        // new: it is held from everyone but the owner, who is settled).
        val alice = w.client("alice")
        ChannelScenes.admit(w, owner, id, alice)
        assertEquals(owner.channel(id)!!.epoch, alice.channel(id)!!.epoch)
        assertArrayEquals("the same winner everywhere (CS-C3)", winnerOf(owner, id, 2), winnerOf(dave, id, 2))
        assertTrue(owner.displayed(id).contains("ramura invingatoare"))
        assertTrue(owner.integrity().isEmpty())
    }

    /** SPAM_UNOPENABLE: three junk blobs under the epoch's key id push the victim to resync_needed; the next progress returns it. */
    @Test
    fun spamUnopenableEntersResyncAndProgressReturnsToActive() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        w.relay.modes = setOf(ModelChannelRelay.Mode.SPAM_UNOPENABLE)
        // bob, a modified client, seals junk any member could seal: the recognition matches R_ep,
        // nothing opens it. The victim consumes all three (FORGED_SEAL) — the liveness window opens.
        for (i in 0 until 3) {
            val junk = ByteArray(900) { ((it * 31 + i * 17) % 251).toByte() }
            w.relay.inject(ChannelAdversary.namespace(bob, id), ChannelAdversary.sealJunk(bob, id, junk), w.now, "spam-$i")
        }
        w.pump()
        owner.hintPass()
        assertEquals(
            "the junk is consumed unopened (the outer seal parses, the body is not a message)",
            3, owner[ChannelCounters.Reason.FORGED_SEAL] + owner[ChannelCounters.Reason.NON_CANONICAL],
        )
        val liveness = livenessOf(owner, id)
        assertEquals("the window opened on the first unopenable", 3, liveness.first)
        assertTrue("both operators attributed (the store reached every relay)", liveness.second >= 2)
        // Three quiet days, one session a day: no progress (nobody posts), the window matures.
        repeat(3) {
            w.advance(1 * DmWorld.DAY)
            w.pump()
            owner.sessionStart()
            owner.timePass()
        }
        assertEquals("CO-11: 3 unopenable, 2 operators, 72 h, 3 sessions, no progress",
            ChannelState.RESYNC_NEEDED, owner.channel(id)!!.state)
        val row = owner.channel(id)!!
        assertTrue("no flag without a split", !row.splitSuspected)
        // The next progress: bob's message opens (one other member is min(2, n − 1) here).
        ChannelScenes.post(bob, id, "progresul")
        w.pump()
        owner.hintPass()
        assertEquals("progress returns the member to active (CO-11)",
            ChannelState.ACTIVE, owner.channel(id)!!.state)
        assertEquals("the window closed", 0, livenessOf(owner, id).first)
        assertTrue(owner.displayed(id).contains("progresul"))
        assertTrue(owner.integrity().isEmpty())
    }

    /** SPAM with continuing progress: the victim stays active and raises split_suspected (CO-12, the adopted D-3). */
    @Test
    fun spamWithProgressRaisesSplitSuspectedAndNeverEntersResync() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val carol = w.client("carol")
        val id = ChannelScenes.channelOf(w, owner, bob, carol)
        w.relay.modes = setOf(ModelChannelRelay.Mode.SPAM_UNOPENABLE)
        for (i in 0 until 3) {
            val junk = ByteArray(900) { ((it * 13 + i * 29) % 253).toByte() }
            w.relay.inject(ChannelAdversary.namespace(bob, id), ChannelAdversary.sealJunk(bob, id, junk), w.now, "spam-$i")
        }
        w.pump()
        owner.hintPass()
        assertEquals(
            "the junk is consumed unopened",
            3, owner[ChannelCounters.Reason.FORGED_SEAL] + owner[ChannelCounters.Reason.NON_CANONICAL],
        )
        // Progress continues through the window: bob and carol keep posting (2 ≥ min(2, 3 − 1)).
        repeat(3) {
            w.advance(1 * DmWorld.DAY)
            ChannelScenes.post(bob, id, "ziua ${DmTime.day(w.now)} din bob")
            ChannelScenes.post(carol, id, "ziua ${DmTime.day(w.now)} din carol")
            w.pump()
            owner.sessionStart()
            owner.timePass()
        }
        assertEquals("progress keeps the member out of resync_needed", ChannelState.ACTIVE, owner.channel(id)!!.state)
        assertTrue("and raises split_suspected (CO-12, D-3)", owner.channel(id)!!.splitSuspected)
        assertTrue(owner.integrity().isEmpty())
    }

    /** CO-12's 9-day clocks: an idle member raises stale_suspected; a member who hears posts but no committer commit raises partition_suspected (the owner, the only committer, never does). */
    @Test
    fun nineDaysQuietRaiseStaleAndPartitionSuspected() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val carol = w.client("carol")
        val dave = w.client("dave")
        // Channel 1: nobody posts. Channel 2: dave posts daily; bob stays silent in both.
        val quiet = ChannelScenes.channelOf(w, owner, bob, carol)
        val chatty = ChannelScenes.channelOf(w, owner, bob, dave)
        // The PCS cadence would break the silence: the owner's clock says it committed today,
        // and the owner never runs a pass in this scene.
        silencePcsClock(owner, quiet)
        silencePcsClock(owner, chatty)
        val startDay = DmTime.day(w.now)
        repeat(10) {
            w.advance(1 * DmWorld.DAY)
            ChannelScenes.post(dave, chatty, "ziua ${DmTime.day(w.now)}")
            w.pump()
            dave.hintPass()
            bob.hintPass()
        }
        assertEquals("ten quiet days in channel 1", startDay + 10, DmTime.day(w.now))
        val bobQuiet = bob.channel(quiet)!!
        assertTrue("no committer commit and no message for 9 days (CO-12): $bobQuiet", bobQuiet.staleSuspected)
        assertTrue("…and not the partition flag", !bobQuiet.partitionSuspected)
        assertEquals("still active: flags change nothing by themselves", ChannelState.ACTIVE, bobQuiet.state)
        val bobChatty = bob.channel(chatty)!!
        assertTrue("dave's posts arrive but no committer commits (CO-12): $bobChatty", bobChatty.partitionSuspected)
        assertTrue("messages keep the stale flag down", !bobChatty.staleSuspected)
        // The owner is the only committer of both channels: nobody else is named, so no stale flag.
        assertTrue(!owner.channel(quiet)!!.staleSuspected)
        assertTrue(!owner.channel(chatty)!!.partitionSuspected)
        assertTrue(bob.integrity().isEmpty())
    }

    /** CO-12: one SPAM_UNOPENABLE junk blob must not raise partition_suspected nor touch the stale flag — a window opened by an unopenable is no arrived message (§19.40). */
    @Test
    fun oneUnopenableJunkBlobNeitherRaisesPartitionNorResetsTheStaleClock() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        // The committer's last commit is 10 days back (what quiet days would say), then nine quiet
        // days: CO-12's stale clock fires alone at bob, a non-committer — the owner's own flag
        // needs someone else named in committers, and no message ever opened.
        backdateCommitterCommit(bob, id, 10)
        repeat(9) {
            w.advance(1 * DmWorld.DAY)
            w.pump()
            bob.hintPass()
        }
        val quiet = bob.channel(id)!!
        assertTrue("nine quiet days on a 10-day-old committer commit: stale alone (CO-12): $quiet", quiet.staleSuspected)
        assertTrue("no partition without an opened message", !quiet.partitionSuspected)
        // ONE junk blob: it opens the liveness window, but nothing opened — no message arrived.
        w.relay.modes = setOf(ModelChannelRelay.Mode.SPAM_UNOPENABLE)
        val junk = ByteArray(900) { ((it * 31 + 7) % 251).toByte() }
        w.relay.inject(ChannelAdversary.namespace(bob, id), ChannelAdversary.sealJunk(bob, id, junk), w.now, "spam-0")
        w.pump()
        bob.hintPass()
        assertEquals(
            "the junk was consumed unopened (the code path ran)",
            1, bob[ChannelCounters.Reason.FORGED_SEAL] + bob[ChannelCounters.Reason.NON_CANONICAL],
        )
        assertEquals("the window opened on the junk", 1, livenessOf(bob, id).first)
        val after = bob.channel(id)!!
        assertTrue(
            "one junk blob never raises partition_suspected (CO-12 needs an authenticated message): $after",
            !after.partitionSuspected,
        )
        assertTrue("…and the stale flag stands", after.staleSuspected)
        assertEquals("flags change nothing by themselves", ChannelState.ACTIVE, after.state)
        assertTrue(bob.integrity().isEmpty())
    }

    /** A member 10 days slow processes every commit like the others (Q42 (a): validity reads no clock). */
    @Test
    fun aMemberTenDaysSlowProcessesEveryCommitLikeTheOthers() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        // bob's trusted clock falls 10 days behind and stays behind whatever the world does —
        // now and the monotonic clock move together (the settle's window math reads both).
        fun skew() {
            val target = w.now - 10 * DmWorld.DAY
            val delta = target - bob.clock.now
            bob.clock.now = target
            bob.clock.monotonic += delta * 1_000
        }
        skew()
        // A quiet week, then the owner's PCS commit; bob merges it like the owner does.
        w.advance(7 * DmWorld.DAY)
        skew()
        agePcsClock(owner, id, 7)
        duePass(w, owner)
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        skew()
        assertEquals(2L, owner.channel(id)!!.epoch)
        assertEquals("the slow member is at the same epoch: no stall", 2L, bob.channel(id)!!.epoch)
        assertArrayEquals("and the same winner (no divergence)", winnerOf(owner, id, 1), winnerOf(bob, id, 1))
        // Posts in the new epoch decrypt at bob like everywhere.
        ChannelScenes.post(owner, id, "cea mai recenta")
        w.quiesce()
        skew()
        w.quiesce()
        assertTrue(bob.displayed(id).contains("cea mai recenta"))
        assertTrue(bob.integrity().isEmpty())
    }

    // --------------------------------------------------------------------------------------------- helpers

    /** The window's (unopenable count, operators) at [client]. */
    private fun livenessOf(client: ChannelClient, id: ChannelId): Pair<Int, Int> =
        client.database.transaction { tx ->
            val row = client.channelStores.channels.liveness(tx.sql, id.toByteArray())
            (row?.unopenableCount ?: 0) to (row?.unopenableOperators ?: 0)
        }

    private fun compareHash(a: ByteArray, b: ByteArray): Int =
        org.ghost.messaging.channel.engine.ChannelReceiveStep.compareUnsigned(a, b)

    private fun winnerOf(client: ChannelClient, id: ChannelId, epoch: Long): ByteArray? =
        client.database.transaction { tx -> client.channelStores.epochs.logged(tx.sql, id.toByteArray(), epoch)?.winnerHash }

    private fun deliver(w: ChannelWorld, vararg cs: ChannelClient) {
        w.pump()
        for (client in cs) client.hintPass()
    }

    private fun settleEveryone(w: ChannelWorld, vararg cs: ChannelClient) {
        w.quiesce()
        w.advance(21 * DmWorld.MINUTE)
        w.pump()
        for (client in cs) client.timePass()
        w.quiesce()
    }

    /** A rank-0 context-change commit adding [bob] to the committers; recorded and settled everywhere (one epoch). */
    private fun makeCommitter(w: ChannelWorld, owner: ChannelClient, bob: ChannelClient, id: ChannelId) {
        val before = ChannelAdversary.policy(owner, id)
        val ownerP = pseudonymOf(owner, id)
        val bobP = pseudonymOf(bob, id)
        val after = ChannelPolicy(
            before.channelId, before.sizeClass, before.timerCode, before.timerVersion, before.historyPolicy,
            before.flags, before.idleEvictDays, before.pwVersion, before.name, listOf(ownerP, bobP), before.funders,
        )
        val change = ChannelAdversary.commit(owner, id, after)
        w.relay.holdAt = { name, s -> s.purpose == "committers" && name == "owner" }
        ChannelAdversary.stageOwn(owner, id, change, rank = 0)
        ChannelAdversary.inject(w, owner, id, change, "committers")
        settleEveryone(w, *w.clients.toTypedArray())
    }

    /** A session with a due scheduled pass: the arm a previous pass left is cleared (the spacing is not what these scenes test); the PCS clock and the slot stay as the scene set them. */
    private fun duePass(w: ChannelWorld, client: ChannelClient) {
        val id = currentChannelId(client)
        client.database.transaction { tx ->
            val row = client.channelStores.channels.schedule(tx.sql, id.toByteArray()) ?: return@transaction
            client.channelStores.channels.putSchedule(
                tx, id.toByteArray(), row.nextSelfupdateDay, row.lastOwnCommitDay, null,
            )
        }
        client.sessionStart()
        w.advance(6 * DmWorld.MINUTE)
        client.timePass()
    }

    /** The member's PCS clock silenced ([client] committed "today", so the cadence fires far out). */
    private fun silencePcsClock(client: ChannelClient, id: ChannelId) {
        val day = DmTime.day(client.clock.now)
        client.database.transaction { tx ->
            val row = client.channelStores.channels.schedule(tx.sql, id.toByteArray())
            client.channelStores.channels.putSchedule(tx, id.toByteArray(), row?.nextSelfupdateDay ?: day, day, row?.nextPassMinute)
        }
    }

    /** The member's `last_committer_commit_day` moved [days] back (what quiet days would say). */
    private fun backdateCommitterCommit(client: ChannelClient, id: ChannelId, days: Long) {
        val day = DmTime.day(client.clock.now) - days
        client.database.transaction { tx ->
            client.channelStores.channels.setLastCommitterCommitDay(tx, id.toByteArray(), day)
        }
    }

    private fun agePcsClock(client: ChannelClient, id: ChannelId, days: Long) {
        val day = DmTime.day(client.clock.now) - days
        client.database.transaction { tx ->
            val row = client.channelStores.channels.schedule(tx.sql, id.toByteArray())
            client.channelStores.channels.putSchedule(tx, id.toByteArray(), row?.nextSelfupdateDay ?: day, day, row?.nextPassMinute)
        }
    }

    private fun currentChannelId(client: ChannelClient): ChannelId =
        client.database.transaction { tx ->
            var id: ByteArray? = null
            tx.sql.query("SELECT channel_id FROM ch_channel") { id = it.blob(0) }
            ChannelId(id!!)
        }

    private fun pseudonymOf(client: ChannelClient, id: ChannelId): ByteArray =
        client.contexts.open(id.toByteArray())!!.pseudonym
}
