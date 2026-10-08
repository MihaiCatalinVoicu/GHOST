package org.ghost.messaging.channel

import org.ghost.messaging.DmWorld
import org.ghost.messaging.api.AcceptResult
import org.ghost.messaging.api.ChannelId
import org.ghost.messaging.api.PostResult
import org.ghost.messaging.channel.store.ChannelState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * **SCN-CA's crash singles** (Phase 10 design §12.4, CS-C1 and CS-C2; the F7 §8.3 method): a process death **at every
 * event** of `CH-ACCEPT` and of the pass that runs `CH-JOIN` — before each statement, before each commit, after each
 * commit — then a reboot (a new client over the same database: a new native context, a new random stream) and the rest of
 * the scenario. After every reboot: `integrity_check`, `foreign_key_check` and the world's invariants
 * ([ChannelClient.integrity]); **atomicity** (the accept left nothing or everything, the join left the joining state and
 * the unconsumed Welcome or the active channel and the consumed Welcome); and at the end **liveness**: the joiner is
 * active and a post goes both ways.
 *
 * The world before the action is built once and snapshotted (`VACUUM INTO`); every run restores it, so a run costs the
 * action and the scenario's end, never a fresh admission.
 */
class ChannelCrashTest {

    @get:Rule
    val folder = TemporaryFolder()

    @Before
    fun native() {
        assumeTrue("ghost-dm-host is not loaded (-Dghost.dm.native)", ChannelWorld.nativeAvailable())
    }

    /** A world frozen before an action: the two databases, the relay and the time. */
    private class Frozen(
        val owner: java.io.File,
        val bob: java.io.File,
        val relay: ModelChannelRelay,
        val now: Long,
        val channel: ChannelId,
        val link: ByteArray,
    )

    /** A world restored from [frozen], bob over a crash executor. */
    private class Thawed(val world: ChannelWorld, val owner: ChannelClient, var bob: ChannelClient, val crash: CrashingSqlExecutor) {
        fun reboot(boot: Int): ChannelClient {
            bob.die()
            crash.armAt = null
            bob = world.client("bob", crash, boot)
            return bob
        }
    }

    private fun thaw(frozen: Frozen, boot: Int): Thawed {
        val world = ChannelWorld(startSeconds = frozen.now, relay = frozen.relay.copy())
        val owner = world.client("owner", ChannelWorld.restore(frozen.owner), boot)
        val crash = CrashingSqlExecutor(ChannelWorld.restore(frozen.bob))
        val bob = world.client("bob", crash, boot)
        return Thawed(world, owner, bob, crash)
    }

    /** The world just after the owner invited bob, before bob accepts. */
    private fun beforeAccept(): Frozen {
        val w = ChannelWorld()
        try {
            val ownerFile = folder.newFile("owner-before-accept.db").also { it.delete() }
            val bobFile = folder.newFile("bob-before-accept.db").also { it.delete() }
            val owner = w.client("owner", path = ownerFile.absolutePath)
            w.client("bob", path = bobFile.absolutePath)
            val id = ChannelAdmissionTest.create(owner)
            val link = ChannelAdmissionTest.invite(owner, id)
            w.quiesce()
            val relay = w.relay.copy()
            val now = w.now
            // closing the world closes both files, which are then copied whole for each run
            w.close()
            return Frozen(ownerFile, bobFile, relay, now, id, link)
        } finally {
            w.close()
        }
    }

    /** The world just after bob's inbox received the Welcome, before bob's pass runs CH-JOIN. */
    private fun beforeJoin(): Frozen {
        val w = ChannelWorld()
        try {
            val ownerFile = folder.newFile("owner-before-join.db").also { it.delete() }
            val bobFile = folder.newFile("bob-before-join.db").also { it.delete() }
            val owner = w.client("owner", path = ownerFile.absolutePath)
            val bob = w.client("bob", path = bobFile.absolutePath)
            val id = ChannelAdmissionTest.create(owner)
            val link = ChannelAdmissionTest.invite(owner, id)
            assertEquals(AcceptResult.PENDING, bob.engine.accept(link, null))
            w.quiesce()
            w.admissionPass(owner)
            w.quiesce()
            w.advance(21 * DmWorld.MINUTE)
            w.pump()
            owner.timePass()
            assertEquals(1L, owner.channel(id)!!.epoch)
            // one round: the Welcome reaches the relay and bob's inbox; bob has not run a pass since
            w.pump()
            assertTrue("the Welcome is in bob's inbox", bob.count("inbox_blob", "state = 'fetched'") >= 1)
            val relay = w.relay.copy()
            val now = w.now
            w.close()
            return Frozen(ownerFile, bobFile, relay, now, id, link)
        } finally {
            w.close()
        }
    }

    /** The rest of SCN-CA from wherever bob stands, and liveness: bob active, a post each way. */
    private fun finish(t: Thawed, id: ChannelId) {
        val w = t.world
        repeat(3) {
            w.quiesce()
            if (t.bob.channel(id)?.state == ChannelState.JOINING && t.owner.count("ch_join_request") > 0) {
                w.admissionPass(t.owner)
                w.quiesce()
                w.pastSettleWindow()
            }
        }
        w.quiesce()
        assertEquals(ChannelState.ACTIVE, t.bob.channel(id)!!.state)
        assertEquals(PostResult.QUEUED, t.bob.engine.post(id, "după".toByteArray(), null))
        w.quiesce()
        assertTrue(t.owner.displayed(id).contains("după"))
        w.advance(DmWorld.MINUTE)
        assertEquals(PostResult.QUEUED, t.owner.engine.post(id, "înapoi".toByteArray(), null))
        w.quiesce()
        assertTrue(t.bob.displayed(id).contains("înapoi"))
        assertEquals(emptyList<String>(), t.bob.integrity())
        assertEquals(emptyList<String>(), t.owner.integrity())
    }

    @Test
    fun aCrashAtEveryEventOfAcceptLeavesNothingOrEverythingAndTheJoinCompletes() {
        val frozen = beforeAccept()
        // the reference run: how many events CH-ACCEPT raises
        val events = thaw(frozen, 1).let { t ->
            try {
                t.crash.reset()
                assertEquals(AcceptResult.PENDING, t.bob.engine.accept(frozen.link, null))
                t.crash.count
            } finally {
                t.world.close()
                t.crash.delegate.close()
                (t.owner.sql as org.ghost.storage.JdbcSqlExecutor).close()
            }
        }
        assertTrue("CH-ACCEPT raised $events events", events >= 10)
        // the measurement §19.37 reports (the JUnit report's system-out)
        println("SCN-CA crash singles: CH-ACCEPT raises $events events")
        var crashed = 0
        for (k in 1..events) {
            val t = thaw(frozen, 1)
            try {
                t.crash.reset()
                t.crash.armAt = k
                try {
                    t.bob.engine.accept(frozen.link, null)
                    fail("no crash at event $k of $events")
                } catch (e: SimulatedCrash) {
                    crashed++
                }
                val bob = t.reboot(2)
                assertEquals("after a crash at $k: ${bob.integrity()}", emptyList<String>(), bob.integrity())
                val state = bob.channel(frozen.channel)?.state
                // Atomicity: nothing of the channel, or the whole joining state with its request op and listening.
                if (state == null) {
                    assertEquals("crash at $k: a join row without its channel", 0L, bob.count("ch_join"))
                    assertEquals("crash at $k: a channel namespace without its channel", 0L, bob.count("sync_namespace", "consumer = 'channel'"))
                    assertEquals("crash at $k: an op without its channel", 0L, bob.count("outbox_op"))
                    // the user taps the link again
                    assertEquals("crash at $k", AcceptResult.PENDING, bob.engine.accept(frozen.link, null))
                } else {
                    assertEquals("crash at $k", ChannelState.JOINING, state)
                    assertEquals(1L, bob.count("ch_join"))
                    assertEquals(1L, bob.count("outbox_op"))
                    assertEquals(1L, bob.count("ch_outbound_op", "purpose = 'join'"))
                    assertEquals(1L, bob.count("sync_namespace", "consumer = 'channel' AND listening = 1"))
                    // a second tap is refused, and writes nothing
                    assertEquals("crash at $k", AcceptResult.ALREADY_MEMBER, bob.engine.accept(frozen.link, null))
                    assertEquals(1L, bob.count("outbox_op"))
                }
                finish(t, frozen.channel)
            } finally {
                t.world.close()
                t.crash.delegate.close()
                (t.owner.sql as org.ghost.storage.JdbcSqlExecutor).close()
            }
        }
        assertEquals(events, crashed)
    }

    @Test
    fun aCrashAtEveryEventOfTheJoinPassLeavesTheJoinOrTheMemberAndTheWelcomeOnce() {
        val frozen = beforeJoin()
        val events = thaw(frozen, 1).let { t ->
            try {
                t.crash.reset()
                t.bob.hintPass()
                // read before any check: a check reads the database, and its events are not the pass's
                val count = t.crash.count
                assertEquals(ChannelState.ACTIVE, t.bob.channel(frozen.channel)!!.state)
                count
            } finally {
                t.world.close()
                t.crash.delegate.close()
                (t.owner.sql as org.ghost.storage.JdbcSqlExecutor).close()
            }
        }
        assertTrue("the join pass raised $events events", events >= 10)
        println("SCN-CA crash singles: the join pass (CH-JOIN) raises $events events")
        var crashed = 0
        for (k in 1..events) {
            val t = thaw(frozen, 1)
            try {
                t.crash.reset()
                t.crash.armAt = k
                try {
                    t.bob.hintPass()
                    fail("no crash at event $k of $events")
                } catch (e: SimulatedCrash) {
                    crashed++
                }
                val bob = t.reboot(2)
                assertEquals("after a crash at $k: ${bob.integrity()}", emptyList<String>(), bob.integrity())
                when (bob.channel(frozen.channel)!!.state) {
                    ChannelState.JOINING -> {
                        // nothing of the join applied: the join state and the KeyPackage stay for the Welcome
                        assertEquals("crash at $k", 1L, bob.count("ch_join"))
                        assertEquals("crash at $k", 0L, bob.count("ch_generation"))
                        assertTrue("crash at $k", bob.count("mls_global_kv") > 0)
                    }
                    ChannelState.ACTIVE -> {
                        assertEquals("crash at $k", 0L, bob.count("ch_join"))
                        assertEquals("crash at $k", 1L, bob.count("ch_generation"))
                        assertEquals("crash at $k", 1L, bob.count("ch_epoch"))
                    }
                    else -> fail("crash at $k left ${bob.channel(frozen.channel)!!.state}")
                }
                // the pass runs again after the reboot
                bob.hintPass()
                assertEquals("crash at $k", ChannelState.ACTIVE, bob.channel(frozen.channel)!!.state)
                finish(t, frozen.channel)
            } finally {
                t.world.close()
                t.crash.delegate.close()
                (t.owner.sql as org.ghost.storage.JdbcSqlExecutor).close()
            }
        }
        assertEquals(events, crashed)
    }

    /** The world just before the owner's pass that settles a committers change (slice S5's `CH-SETTLE`): window passed, one relay round done, no pass since. */
    private fun beforeVoidingSettle(): Frozen {
        val w = ChannelWorld()
        try {
            val ownerFile = folder.newFile("owner-before-settle.db").also { it.delete() }
            val bobFile = folder.newFile("bob-before-settle.db").also { it.delete() }
            val owner = w.client("owner", path = ownerFile.absolutePath)
            val bob = w.client("bob", path = bobFile.absolutePath)
            val id = ChannelScenes.channelOf(w, owner, bob)
            // an unconsumed invite, and a rank-0 context change that adds bob to the committers
            ChannelAdmissionTest.invite(owner, id)
            w.quiesce()
            val before = ChannelAdversary.policy(owner, id)
            val ownerP = owner.contexts.open(id.toByteArray())!!.pseudonym
            val bobP = bob.contexts.open(id.toByteArray())!!.pseudonym
            val after = org.ghost.crypto.bridge.ChannelPolicy(
                before.channelId, before.sizeClass, before.timerCode, before.timerVersion, before.historyPolicy,
                before.flags, before.idleEvictDays, before.pwVersion, before.name, listOf(ownerP, bobP), before.funders,
            )
            val change = ChannelAdversary.commit(owner, id, after)
            w.relay.holdAt = { name, s -> s.purpose == "committers" && name == "owner" }
            ChannelAdversary.stageOwn(owner, id, change, rank = 0)
            ChannelAdversary.inject(w, owner, id, change, "committers")
            w.quiesce()
            // (i) and (ii) of CO-4 both hold at the next pass; no client has passed since
            w.advance(21 * DmWorld.MINUTE)
            w.pump()
            val relay = w.relay.copy()
            val now = w.now
            w.close()
            return Frozen(ownerFile, bobFile, relay, now, id, ByteArray(0))
        } finally {
            w.close()
        }
    }

    /** A world restored from [frozen], the owner over a crash executor. */
    private class ThawedOwner(val world: ChannelWorld, var owner: ChannelClient, val bob: ChannelClient, val crash: CrashingSqlExecutor) {
        fun reboot(boot: Int): ChannelClient {
            owner.die()
            crash.armAt = null
            owner = world.client("owner", crash, boot)
            return owner
        }
    }

    private fun thawOwner(frozen: Frozen, boot: Int): ThawedOwner {
        val world = ChannelWorld(startSeconds = frozen.now, relay = frozen.relay.copy())
        val crash = CrashingSqlExecutor(ChannelWorld.restore(frozen.owner))
        val owner = world.client("owner", crash, boot)
        val bob = world.client("bob", ChannelWorld.restore(frozen.bob), boot)
        return ThawedOwner(world, owner, bob, crash)
    }

    /**
     * **The full settle's crash singles** (Phase 10 design §12.4, CS-C1/CS-C2; slice S5): a process
     * death at every event of the pass that runs `CH-SETTLE` — the custody check, the trial's held
     * reads, the merge's writes, the invite voiding — then a reboot (a new native context over the
     * same database) and the pass again. After every crash: integrity and foreign keys; the epoch is
     * open with its candidates or final with the winner logged and the old-digest invite voided;
     * the retried pass settles, the other member converges, and a post goes both ways.
     */
    @Test
    fun aCrashAtEveryEventOfTheSettleLeavesTheEpochOpenOrFinalAndTheInvitesVoid() {
        val frozen = beforeVoidingSettle()
        val events = thawOwner(frozen, 1).let { t ->
            try {
                // one relay round first: the rebuilt world's in-memory tails are empty (a reboot
                // forgets them), and CO-4 (ii) needs a pass after the window; not part of the count
                t.world.pump()
                t.crash.reset()
                t.owner.timePass()
                val seen = t.crash.count
                assertEquals(2L, t.owner.channel(frozen.channel)!!.epoch)
                seen
            } finally {
                t.world.close()
                t.crash.delegate.close()
                (t.bob.sql as org.ghost.storage.JdbcSqlExecutor).close()
            }
        }
        assertTrue("CH-SETTLE raised $events events", events >= 10)
        println("SCN-CD crash singles: CH-SETTLE (the full settle) raises $events events")
        var crashed = 0
        for (k in 1..events) {
            val t = thawOwner(frozen, 1)
            try {
                t.world.pump()
                t.crash.reset()
                t.crash.armAt = k
                try {
                    t.owner.timePass()
                    fail("no crash at event $k of $events")
                } catch (e: SimulatedCrash) {
                    crashed++
                }
                val owner = t.reboot(2)
                assertEquals("after a crash at $k: ${owner.integrity()}", emptyList<String>(), owner.integrity())
                val epoch = owner.channel(frozen.channel)!!.epoch
                assertTrue("crash at $k left epoch $epoch", epoch == 1L || epoch == 2L)
                if (epoch == 2L) {
                    // the settle is whole: the winner is logged and the old-digest invite is void
                    assertEquals("crash at $k", 1L, owner.count("ch_epoch", "epoch = 1 AND state = 'final'"))
                    assertEquals("crash at $k", 1L, owner.count("ch_invite_issued", "consumed = 0 AND void = 1"))
                    assertEquals(0L, owner.count("ch_candidate"))
                } else {
                    assertEquals("crash at $k", 1L, owner.count("ch_candidate"))
                    assertEquals("crash at $k", 1L, owner.count("ch_invite_issued", "consumed = 0 AND void = 0"))
                }
                // the pass retries after the reboot (a listing round re-arms (ii))
                t.world.pump()
                owner.timePass()
                assertEquals("crash at $k", 2L, owner.channel(frozen.channel)!!.epoch)
                assertEquals("crash at $k", 1L, owner.count("ch_invite_issued", "consumed = 0 AND void = 1"))
                t.world.pump()
                t.bob.timePass()
                assertEquals("crash at $k", 2L, t.bob.channel(frozen.channel)!!.epoch)
                assertEquals("crash at $k", 1L, t.bob.count("ch_invite_issued", "consumed = 0 AND void = 1"))
                assertEquals(PostResult.QUEUED, t.bob.engine.post(frozen.channel, "după".toByteArray(), null))
                t.world.quiesce()
                assertTrue(t.owner.displayed(frozen.channel).contains("după"))
                assertEquals(emptyList<String>(), owner.integrity())
                assertEquals(emptyList<String>(), t.bob.integrity())
            } finally {
                t.world.close()
                t.crash.delegate.close()
                (t.bob.sql as org.ghost.storage.JdbcSqlExecutor).close()
            }
        }
        assertEquals(events, crashed)
    }

    /** The world just before the owner's user-action Remove of a committer (slice S5b2's `CH-PASS`): bob is rank 1, the channel is current, no candidate held. */
    private fun beforeRemove(): Frozen {
        val w = ChannelWorld()
        try {
            val ownerFile = folder.newFile("owner-before-remove.db").also { it.delete() }
            val bobFile = folder.newFile("bob-before-remove.db").also { it.delete() }
            val owner = w.client("owner", path = ownerFile.absolutePath)
            val bob = w.client("bob", path = bobFile.absolutePath)
            val id = ChannelScenes.channelOf(w, owner, bob)
            // bob at rank 1 (a context change, epoch 2), so the Remove drops a committer key.
            val before = ChannelAdversary.policy(owner, id)
            val ownerP = owner.contexts.open(id.toByteArray())!!.pseudonym
            val bobP = bob.contexts.open(id.toByteArray())!!.pseudonym
            val after = org.ghost.crypto.bridge.ChannelPolicy(
                before.channelId, before.sizeClass, before.timerCode, before.timerVersion, before.historyPolicy,
                before.flags, before.idleEvictDays, before.pwVersion, before.name, listOf(ownerP, bobP), before.funders,
            )
            val change = ChannelAdversary.commit(owner, id, after)
            w.relay.holdAt = { name, s -> s.purpose == "committers" && name == "owner" }
            ChannelAdversary.stageOwn(owner, id, change, rank = 0)
            ChannelAdversary.inject(w, owner, id, change, "committers")
            w.quiesce()
            w.advance(21 * DmWorld.MINUTE)
            w.pump()
            for (c in w.clients) c.timePass()
            w.quiesce()
            assertEquals(2L, owner.channel(id)!!.epoch)
            val relay = w.relay.copy()
            val now = w.now
            w.close()
            return Frozen(ownerFile, bobFile, relay, now, id, bobP)
        } finally {
            w.close()
        }
    }

    /**
     * **The Remove pass's crash singles** (Phase 10 design §12.4, CS-C1/CS-C2; slice S5b2): a process death at
     * every event of the user-action `CH-PASS` that removes a committer — the settle-first check, the native
     * commit, the candidate, the op, the schedule — then a reboot and the pass again. After every crash:
     * integrity; the channel is as it was (no own candidate, bob a committer) or the commit is whole (the own
     * candidate, the op, the schedule's last-own-commit day); the retried pass removes bob, the settle merges the
     * removal everywhere, and the epoch is final.
     */
    @Test
    fun aCrashAtEveryEventOfTheRemovePassLeavesNoCommitOrAWholeOneAndBobIsRemoved() {
        val frozen = beforeRemove()
        val bobP = frozen.link
        val events = thawOwner(frozen, 1).let { t ->
            try {
                t.crash.reset()
                assertEquals(org.ghost.messaging.channel.engine.ChannelEngine.RemoveResult.REMOVED, t.owner.engine.remove(frozen.channel, bobP))
                val seen = t.crash.count
                assertEquals(1L, t.owner.count("ch_candidate", "own = 1"))
                seen
            } finally {
                t.world.close()
                t.crash.delegate.close()
                (t.bob.sql as org.ghost.storage.JdbcSqlExecutor).close()
            }
        }
        assertTrue("the Remove pass raised $events events", events >= 10)
        println("SCN-CD crash singles: the Remove pass (CH-PASS) raises $events events")
        var crashed = 0
        for (k in 1..events) {
            val t = thawOwner(frozen, 1)
            try {
                t.crash.reset()
                t.crash.armAt = k
                try {
                    t.owner.engine.remove(frozen.channel, bobP)
                    fail("no crash at event $k of $events")
                } catch (e: SimulatedCrash) {
                    crashed++
                }
                val owner = t.reboot(2)
                assertEquals("after a crash at $k: ${owner.integrity()}", emptyList<String>(), owner.integrity())
                val whole = owner.count("ch_candidate", "own = 1") == 1L
                if (!whole) {
                    assertEquals("crash at $k", 0L, owner.count("ch_outbound_op", "purpose = 'commit'"))
                    assertEquals("crash at $k", 2, ChannelAdversary.policy(owner, frozen.channel).committers.size)
                } else {
                    assertEquals("crash at $k", 1L, owner.count("ch_outbound_op", "purpose = 'commit'"))
                    assertEquals("crash at $k", org.ghost.messaging.engine.DmTime.day(t.world.now), ownerScheduleDay(owner, frozen.channel))
                }
                // A whole commit finishes itself: the op's outcome verifies the candidate (CO-4) and the
                // settle merges the removal. A partial one retries the user action.
                if (!whole) {
                    assertEquals("crash at $k", org.ghost.messaging.channel.engine.ChannelEngine.RemoveResult.REMOVED, owner.engine.remove(frozen.channel, bobP))
                }
                t.world.quiesce()
                t.world.advance(21 * DmWorld.MINUTE)
                t.world.pump()
                owner.timePass()
                t.bob.timePass()
                t.world.quiesce()
                assertEquals("crash at $k", ChannelState.REMOVED, t.bob.channel(frozen.channel)!!.state)
                assertEquals("crash at $k", 3L, owner.channel(frozen.channel)!!.epoch)
                assertEquals("crash at $k", 1, ChannelAdversary.policy(owner, frozen.channel).committers.size)
                assertEquals(emptyList<String>(), owner.integrity())
                assertEquals(emptyList<String>(), t.bob.integrity())
            } finally {
                t.world.close()
                t.crash.delegate.close()
                (t.bob.sql as org.ghost.storage.JdbcSqlExecutor).close()
            }
        }
        assertEquals(events, crashed)
    }

    /** The schedule row's `last_own_commit_day` (what a whole Remove pass wrote). */
    private fun ownerScheduleDay(owner: ChannelClient, id: ChannelId): Long =
        owner.database.transaction { tx -> owner.channelStores.channels.schedule(tx.sql, id.toByteArray()) }!!.lastOwnCommitDay!!

    // ------------------------------------------------------------------------------------------- slice S6

    /** The world just before the owner's pass that runs `CH-SWITCH` (slice S6): the removal settled, the switch hour passed, no pass since. */
    private fun beforeSwitch(): Frozen {
        val w = ChannelWorld()
        try {
            val ownerFile = folder.newFile("owner-before-switch.db").also { it.delete() }
            val bobFile = folder.newFile("bob-before-switch.db").also { it.delete() }
            val owner = w.client("owner", path = ownerFile.absolutePath)
            val bob = w.client("bob", path = bobFile.absolutePath)
            val id = ChannelScenes.channelOf(w, owner, bob)
            owner.engine.remove(id, bob.contexts.open(id.toByteArray())!!.pseudonym)
            w.quiesce()
            w.pastSettleWindow()
            w.quiesce()
            assertEquals(1L, owner.count("ch_generation", "state = 'pending_switch'"))
            w.advance(40 * DmWorld.MINUTE)
            val relay = w.relay.copy()
            val now = w.now
            w.close()
            return Frozen(ownerFile, bobFile, relay, now, id, ByteArray(0))
        } finally {
            w.close()
        }
    }

    /**
     * **CH-SWITCH's crash singles** (Phase 10 design §12.4, CS-C1/CS-C2; slice S6): a process death at every
     * event of the pass that runs the generation switch — then a reboot and the pass again. After every
     * crash: integrity; the generation is `pending_switch` (nothing of ns_1) or whole (`current`, the old one
     * `draining`, ns_1 registered with its credentials and the rotating committer's funding and week
     * registrations); the retried pass switches, the other member converges, and a post goes out in ns_1.
     */
    @Test
    fun aCrashAtEveryEventOfTheSwitchLeavesTheGenerationPendingOrSwitchedWhole() {
        val frozen = beforeSwitch()
        val events = thawOwner(frozen, 1).let { t ->
            try {
                t.crash.reset()
                t.owner.hintPass()
                val seen = t.crash.count
                assertEquals(1L, t.owner.count("ch_generation", "generation = 1 AND state = 'current'"))
                seen
            } finally {
                t.world.close()
                t.crash.delegate.close()
                (t.bob.sql as org.ghost.storage.JdbcSqlExecutor).close()
            }
        }
        assertTrue("CH-SWITCH raised $events events", events >= 10)
        println("SCN-CC crash singles: CH-SWITCH raises $events events")
        var crashed = 0
        for (k in 1..events) {
            val t = thawOwner(frozen, 1)
            try {
                t.crash.reset()
                t.crash.armAt = k
                try {
                    t.owner.hintPass()
                    fail("no crash at event $k of $events")
                } catch (e: SimulatedCrash) {
                    crashed++
                }
                val owner = t.reboot(2)
                assertEquals("after a crash at $k: ${owner.integrity()}", emptyList<String>(), owner.integrity())
                val ns1 = generationNs(owner, frozen.channel, 1)
                val switched = owner.count("ch_generation", "generation = 1 AND state = 'current'") == 1L
                if (!switched) {
                    assertEquals("crash at $k", 1L, owner.count("ch_generation", "state = 'pending_switch'"))
                    assertEquals("crash at $k", 0L, owner.count("sync_namespace", "namespace_id = ?", ns1))
                } else {
                    assertEquals("crash at $k", 1L, owner.count("ch_generation", "generation = 0 AND state = 'draining'"))
                    assertEquals("crash at $k", 1L, owner.count("sync_namespace", "namespace_id = ? AND listening = 1", ns1))
                    assertEquals("crash at $k", 6L, owner.count("relay_capability", "namespace_id = ?", ns1))
                    assertEquals("crash at $k", 1L, owner.count("sync_namespace_fund", "namespace_id = ?", ns1))
                }
                owner.hintPass()
                assertEquals("crash at $k", 1L, owner.count("ch_generation", "generation = 1 AND state = 'current'"))
                assertEquals(PostResult.QUEUED, owner.engine.post(frozen.channel, "în g_1".toByteArray(), null))
                t.world.quiesce()
                assertEquals(emptyList<String>(), owner.integrity())
                assertEquals(emptyList<String>(), t.bob.integrity())
            } finally {
                t.world.close()
                t.crash.delegate.close()
                (t.bob.sql as org.ghost.storage.JdbcSqlExecutor).close()
            }
        }
        assertEquals(events, crashed)
    }

    /** The world just before the owner's pass that runs the drain's end (slice S6's `CH-SWEEP`): the switch ran, 15 days passed, no pass since. */
    private fun beforeDrainEnd(): Frozen {
        val w = ChannelWorld()
        try {
            val ownerFile = folder.newFile("owner-before-drain.db").also { it.delete() }
            val bobFile = folder.newFile("bob-before-drain.db").also { it.delete() }
            val owner = w.client("owner", path = ownerFile.absolutePath)
            val bob = w.client("bob", path = bobFile.absolutePath)
            val id = ChannelScenes.channelOf(w, owner, bob)
            owner.engine.remove(id, bob.contexts.open(id.toByteArray())!!.pseudonym)
            w.quiesce()
            w.pastSettleWindow()
            w.quiesce()
            w.advance(40 * DmWorld.MINUTE)
            owner.hintPass()
            assertEquals(1L, owner.count("ch_generation", "generation = 0 AND state = 'draining'"))
            // the production GC (the model relay runs none) deletes released ops long before a drain ends
            owner.database.transaction { tx ->
                tx.sql.exec("UPDATE outbox_op SET released = 1 WHERE released = 0 AND outcome <> 'pending'")
                tx.sql.exec("DELETE FROM outbox_op WHERE released = 1 AND ciphertext IS NULL")
            }
            w.advance(15 * DmWorld.DAY)
            val ns0 = generationNs(owner, id, 0)
            val relay = w.relay.copy()
            val now = w.now
            w.close()
            return Frozen(ownerFile, bobFile, relay, now, id, ns0)
        } finally {
            w.close()
        }
    }

    /**
     * **The drain end's crash singles** (§12.4, CS-C1/CS-C2; slice S6): a process death at every event of the
     * pass that runs `CH-SWEEP`'s drain half. After every crash: integrity; the drained generation's row and
     * its namespace are both there or both gone (`Namespaces.remove` and the `ch_generation` delete are one
     * transaction); the retried pass removes them.
     */
    @Test
    fun aCrashAtEveryEventOfTheDrainEndLeavesTheGenerationAndItsNamespaceTogether() {
        val frozen = beforeDrainEnd()
        val events = thawOwner(frozen, 1).let { t ->
            try {
                t.crash.reset()
                t.owner.timePass()
                val seen = t.crash.count
                assertEquals(0L, t.owner.count("ch_generation", "generation = 0"))
                seen
            } finally {
                t.world.close()
                t.crash.delegate.close()
                (t.bob.sql as org.ghost.storage.JdbcSqlExecutor).close()
            }
        }
        assertTrue("the drain end raised $events events", events >= 10)
        println("SCN-CC crash singles: the drain end (CH-SWEEP) raises $events events")
        var crashed = 0
        for (k in 1..events) {
            val t = thawOwner(frozen, 1)
            try {
                t.crash.reset()
                t.crash.armAt = k
                try {
                    t.owner.timePass()
                    fail("no crash at event $k of $events")
                } catch (e: SimulatedCrash) {
                    crashed++
                }
                val owner = t.reboot(2)
                assertEquals("after a crash at $k: ${owner.integrity()}", emptyList<String>(), owner.integrity())
                val ns0 = frozen.link
                val gone = owner.count("ch_generation", "generation = 0") == 0L
                // the namespace's listening moves with the row; the row itself is the GC's once the
                // tombstones go (§11.2 #19), so only the flag is asserted here
                assertEquals("crash at $k: the row and the namespace's listening move together", !gone,
                    owner.count("sync_namespace", "namespace_id = ? AND listening = 1", ns0) == 1L)
                owner.timePass()
                assertEquals("crash at $k", 0L, owner.count("ch_generation", "generation = 0"))
                assertEquals("crash at $k", 0L, owner.count("sync_namespace", "namespace_id = ? AND listening = 1", ns0))
                assertEquals(emptyList<String>(), owner.integrity())
            } finally {
                t.world.close()
                t.crash.delegate.close()
                (t.bob.sql as org.ghost.storage.JdbcSqlExecutor).close()
            }
        }
        assertEquals(events, crashed)
    }

    /** The world just before the leaving member's `CH-LEAVE` (slice S6). */
    private fun beforeLeave(): Frozen {
        val w = ChannelWorld()
        try {
            val ownerFile = folder.newFile("owner-before-leave.db").also { it.delete() }
            val bobFile = folder.newFile("bob-before-leave.db").also { it.delete() }
            val owner = w.client("owner", path = ownerFile.absolutePath)
            val bob = w.client("bob", path = bobFile.absolutePath)
            val id = ChannelScenes.channelOf(w, owner, bob)
            val relay = w.relay.copy()
            val now = w.now
            w.close()
            return Frozen(ownerFile, bobFile, relay, now, id, ByteArray(0))
        } finally {
            w.close()
        }
    }

    /**
     * **CH-LEAVE's crash singles** (§12.4, CS-C1/CS-C2; slice S6): a process death at every event of the
     * member's leave. After every crash: integrity; the channel is `active` with no leave op, or `leaving`
     * with the op; the leave completes, the committer removes the leaver, and the leaver merges its removal.
     */
    @Test
    fun aCrashAtEveryEventOfTheLeaveLeavesNoLeaveOrAWholeOne() {
        val frozen = beforeLeave()
        val events = thaw(frozen, 1).let { t ->
            try {
                t.crash.reset()
                assertEquals(org.ghost.messaging.channel.engine.ChannelPostStep.LeaveResult.LEFT, t.bob.engine.leave(frozen.channel))
                val seen = t.crash.count
                assertEquals(ChannelState.LEAVING, t.bob.channel(frozen.channel)!!.state)
                seen
            } finally {
                t.world.close()
                t.crash.delegate.close()
                (t.owner.sql as org.ghost.storage.JdbcSqlExecutor).close()
            }
        }
        assertTrue("CH-LEAVE raised $events events", events >= 10)
        println("SCN-CK crash singles: CH-LEAVE raises $events events")
        var crashed = 0
        for (k in 1..events) {
            val t = thaw(frozen, 1)
            try {
                t.crash.reset()
                t.crash.armAt = k
                try {
                    t.bob.engine.leave(frozen.channel)
                    fail("no crash at event $k of $events")
                } catch (e: SimulatedCrash) {
                    crashed++
                }
                val bob = t.reboot(2)
                assertEquals("after a crash at $k: ${bob.integrity()}", emptyList<String>(), bob.integrity())
                val state = bob.channel(frozen.channel)!!.state
                assertTrue("crash at $k left $state", state == ChannelState.ACTIVE || state == ChannelState.LEAVING)
                if (state == ChannelState.ACTIVE) {
                    assertEquals("crash at $k", 0L, bob.count("ch_outbound_op", "purpose = 'request'"))
                    assertEquals("crash at $k", org.ghost.messaging.channel.engine.ChannelPostStep.LeaveResult.LEFT, bob.engine.leave(frozen.channel))
                } else {
                    assertEquals("crash at $k", 1L, bob.count("ch_outbound_op", "purpose = 'request'"))
                }
                // the leave completes: the owner records the request and removes the leaver
                t.world.pump()
                t.owner.hintPass()
                assertEquals("crash at $k", 1L, t.owner.count("ch_request", "kind = 'leave'"))
                t.world.advance(6 * DmWorld.HOUR)
                t.owner.sessionStart()
                t.world.advance(6 * DmWorld.MINUTE)
                t.owner.timePass()
                t.world.quiesce()
                t.world.advance(21 * DmWorld.MINUTE)
                t.world.pump()
                bob.timePass()
                t.owner.timePass()
                t.world.quiesce()
                assertEquals("crash at $k", ChannelState.REMOVED, bob.channel(frozen.channel)!!.state)
                assertEquals(emptyList<String>(), bob.integrity())
                assertEquals(emptyList<String>(), t.owner.integrity())
            } finally {
                t.world.close()
                t.crash.delegate.close()
                (t.owner.sql as org.ghost.storage.JdbcSqlExecutor).close()
            }
        }
        assertEquals(events, crashed)
    }

    /** The world just before the owner's pass that evicts an idle member (slice S6's `CH-PASS` half). */
    private fun beforeEviction(): Frozen {
        val w = ChannelWorld()
        try {
            val ownerFile = folder.newFile("owner-before-eviction.db").also { it.delete() }
            val bobFile = folder.newFile("bob-before-eviction.db").also { it.delete() }
            val owner = w.client("owner", path = ownerFile.absolutePath)
            val bob = w.client("bob", path = bobFile.absolutePath)
            val id = ChannelScenes.channelOf(w, owner, bob)
            val day = org.ghost.messaging.engine.DmTime.day(w.now)
            owner.database.transaction { tx ->
                owner.channelStores.members.putRefresh(tx, id.toByteArray(), bob.contexts.open(id.toByteArray())!!.pseudonym, day - 100)
            }
            w.advance(2 * DmWorld.DAY)
            owner.database.transaction { tx ->
                val row = owner.channelStores.channels.schedule(tx.sql, id.toByteArray())
                owner.channelStores.channels.putSchedule(tx, id.toByteArray(), row!!.nextSelfupdateDay, row.lastOwnCommitDay, null)
            }
            owner.sessionStart()
            w.advance(6 * DmWorld.MINUTE)
            val relay = w.relay.copy()
            val now = w.now
            w.close()
            return Frozen(ownerFile, bobFile, relay, now, id, ByteArray(0))
        } finally {
            w.close()
        }
    }

    /**
     * **The eviction pass's crash singles** (§12.4, CS-C1/CS-C2; slice S6): a process death at every event
     * of the scheduled pass that evicts an idle member. After every crash: integrity; no own candidate (the
     * member stays) or a whole commit (the candidate, the op, the schedule); the retried pass evicts, the
     * settle merges the removal, and the epoch is final.
     */
    @Test
    fun aCrashAtEveryEventOfTheEvictionPassLeavesNoCommitOrAWholeOne() {
        val frozen = beforeEviction()
        val events = thawOwner(frozen, 1).let { t ->
            try {
                t.crash.reset()
                t.owner.timePass()
                val seen = t.crash.count
                assertEquals(1L, t.owner.count("ch_candidate", "own = 1 AND removes = 1"))
                seen
            } finally {
                t.world.close()
                t.crash.delegate.close()
                (t.bob.sql as org.ghost.storage.JdbcSqlExecutor).close()
            }
        }
        assertTrue("the eviction pass raised $events events", events >= 10)
        println("SCN-CK crash singles: the eviction pass (CH-PASS) raises $events events")
        var crashed = 0
        for (k in 1..events) {
            val t = thawOwner(frozen, 1)
            try {
                t.crash.reset()
                t.crash.armAt = k
                try {
                    t.owner.timePass()
                    fail("no crash at event $k of $events")
                } catch (e: SimulatedCrash) {
                    crashed++
                }
                val owner = t.reboot(2)
                assertEquals("after a crash at $k: ${owner.integrity()}", emptyList<String>(), owner.integrity())
                val whole = owner.count("ch_candidate", "own = 1") == 1L
                if (!whole) {
                    assertEquals("crash at $k", 0L, owner.count("ch_outbound_op", "purpose = 'commit'"))
                } else {
                    assertEquals("crash at $k", 1L, owner.count("ch_outbound_op", "purpose = 'commit'"))
                }
                // A partial pass retries the eviction (the scheduled arm is still due); then the commit
                // is delivered, its window passes, and the merges run.
                if (!whole) owner.timePass()
                t.world.quiesce()
                t.world.advance(21 * DmWorld.MINUTE)
                t.world.pump()
                owner.timePass()
                t.bob.timePass()
                t.world.quiesce()
                assertEquals("crash at $k", ChannelState.REMOVED, t.bob.channel(frozen.channel)!!.state)
                assertEquals(emptyList<String>(), owner.integrity())
                assertEquals(emptyList<String>(), t.bob.integrity())
            } finally {
                t.world.close()
                t.crash.delegate.close()
                (t.bob.sql as org.ghost.storage.JdbcSqlExecutor).close()
            }
        }
        assertEquals(events, crashed)
    }

    /** The namespace of a generation (what the crash singles assert on). */
    private fun generationNs(client: ChannelClient, id: ChannelId, generation: Long): ByteArray =
        client.database.transaction { tx ->
            var ns: ByteArray? = null
            tx.sql.query("SELECT namespace_id FROM ch_generation WHERE channel_id = ? AND generation = ?", listOf(id.toByteArray(), generation)) { ns = it.blob(0) }
            ns!!
        }
}
