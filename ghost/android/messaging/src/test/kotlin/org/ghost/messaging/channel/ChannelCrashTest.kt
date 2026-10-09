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

    // ------------------------------------------------------------------------------------------- the review of S6

    /**
     * The world just before the owner's pass that runs the **second** `CH-SWITCH` (the review of S6,
     * §19.42): two rotations inside one drain, the older one still draining, the switch hour of the
     * second rotation passed, no pass since. [opsCollected] mirrors production GC (the model relay
     * runs none): when false, an op of the older namespace is still open and `Namespaces.remove`
     * refuses — the switch's end-or-defer path.
     */
    private fun beforeSecondSwitch(opsCollected: Boolean): Frozen {
        val w = ChannelWorld()
        try {
            val ownerFile = folder.newFile("owner-before-second-switch.db").also { it.delete() }
            val bobFile = folder.newFile("bob-before-second-switch.db").also { it.delete() }
            val owner = w.client("owner", path = ownerFile.absolutePath)
            val bob = w.client("bob", path = bobFile.absolutePath)
            val carol = w.client("carol")
            val dave = w.client("dave")
            val id = ChannelScenes.channelOf(w, owner, bob, carol, dave)
            val ns0 = generationNs(owner, id, 0)
            owner.engine.remove(id, carol.contexts.open(id.toByteArray())!!.pseudonym)
            w.quiesce()
            w.pastSettleWindow()
            w.quiesce()
            // 70 minutes: the switch hour is ceil(commit + 30 min), up to an hour after the commit
            w.advance(70 * DmWorld.MINUTE)
            for (c in w.clients) c.hintPass()
            assertEquals(1L, owner.count("ch_generation", "generation = 0 AND state = 'draining'"))
            if (opsCollected) collectOps(owner)
            owner.engine.remove(id, dave.contexts.open(id.toByteArray())!!.pseudonym)
            w.quiesce()
            w.pastSettleWindow()
            w.quiesce()
            w.advance(70 * DmWorld.MINUTE)
            val relay = w.relay.copy()
            val now = w.now
            w.close()
            return Frozen(ownerFile, bobFile, relay, now, id, ns0)
        } finally {
            w.close()
        }
    }

    /** The production GC's op collection (the model relay runs no GC): released ops die long before a drain ends. */
    private fun collectOps(client: ChannelClient) {
        client.database.transaction { tx ->
            tx.sql.exec("UPDATE outbox_op SET released = 1 WHERE released = 0 AND outcome <> 'pending'")
            tx.sql.exec("DELETE FROM outbox_op WHERE released = 1 AND ciphertext IS NULL")
        }
    }

    /**
     * **The second switch's crash singles, the removal path** (§12.4, CS-C1/CS-C2; the review of S6):
     * a process death at every event of the pass that ends the older drain at once — the held rows'
     * consumption, the namespace's removal, the older row's deletion, the demotion, the promotion, the
     * new namespace's registration, credentials and the rotating committer's funding. After every crash:
     * integrity; the second generation is `pending_switch` (nothing of it) or whole (`current`, the older
     * drain gone, the previous one draining); the retried pass switches and a post goes out in ns_2.
     */
    @Test
    fun aCrashAtEveryEventOfTheSecondSwitchEndsTheOlderDrainWholeOrNotAtAll() {
        val frozen = beforeSecondSwitch(opsCollected = true)
        val day = org.ghost.messaging.engine.DmTime.day(frozen.now)
        val events = thawOwner(frozen, 1).let { t ->
            try {
                t.crash.reset()
                t.owner.hintPass()
                val seen = t.crash.count
                assertEquals(1L, t.owner.count("ch_generation", "generation = 2 AND state = 'current'"))
                assertEquals(0L, t.owner.count("ch_generation", "generation = 0"))
                seen
            } finally {
                t.world.close()
                t.crash.delegate.close()
                (t.bob.sql as org.ghost.storage.JdbcSqlExecutor).close()
            }
        }
        assertTrue("the second switch raised $events events", events >= 10)
        println("SCN-CC crash singles: the second switch (CH-SWITCH, the older drain removed) raises $events events")
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
                val ns2 = generationNs(owner, frozen.channel, 2)
                val switched = owner.count("ch_generation", "generation = 2 AND state = 'current'") == 1L
                if (!switched) {
                    assertEquals("crash at $k", 1L, owner.count("ch_generation", "state = 'pending_switch'"))
                    assertEquals("crash at $k", 1L, owner.count("ch_generation", "generation = 1 AND state = 'current'"))
                    assertEquals("crash at $k", 1L, owner.count("ch_generation", "generation = 0 AND state = 'draining'"))
                    assertEquals("crash at $k", 0L, owner.count("sync_namespace", "namespace_id = ?", ns2))
                } else {
                    assertEquals("crash at $k", 0L, owner.count("ch_generation", "generation = 0"))
                    assertEquals("crash at $k", 1L, owner.count("ch_generation", "generation = 1 AND state = 'draining'"))
                    assertEquals("crash at $k", 1L, owner.count("sync_namespace", "namespace_id = ? AND listening = 1", ns2))
                    assertEquals("crash at $k", 6L, owner.count("relay_capability", "namespace_id = ?", ns2))
                    assertEquals("crash at $k", 1L, owner.count("sync_namespace_fund", "namespace_id = ?", ns2))
                }
                // a pass can defer once more (an unconsumed fetched row refuses the older drain's
                // removal; the row is consumed in the same pass) — two rounds settle it
                t.world.pump()
                owner.hintPass()
                t.world.pump()
                owner.hintPass()
                assertEquals("crash at $k", 1L, owner.count("ch_generation", "generation = 2 AND state = 'current'"))
                assertEquals(PostResult.QUEUED, owner.engine.post(frozen.channel, "în g_2".toByteArray(), null))
                // bob's switch needs his own ops of ns_0 collected (production GC), then the same
                // pass-or-two his fetched rows may defer
                // three passes: one may defer (a fetched row of ns_0 refuses the removal), the next
                // switches, the one after receives the post
                collectOps(t.bob)
                t.world.pump()
                t.bob.hintPass()
                t.world.pump()
                t.bob.hintPass()
                t.world.pump()
                t.bob.hintPass()
                assertTrue("crash at $k", t.bob.displayed(frozen.channel).contains("în g_2"))
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

    /**
     * **The second switch's crash singles, the defer path** (§12.4; the review of S6): an op of the
     * older namespace is still open, so the switch ends the older drain early, turns its listening off
     * and defers — a process death at every event of that pass. After every crash: integrity; the defer
     * is whole or not there at all (the drain's day and the namespace's listening move together, in the
     * switch's one transaction); once the op closes (production GC) the retried pass switches.
     */
    @Test
    fun aCrashAtEveryEventOfTheDeferredSecondSwitchLeavesTheDeferWholeOrNotAtAll() {
        val frozen = beforeSecondSwitch(opsCollected = false)
        val day = org.ghost.messaging.engine.DmTime.day(frozen.now)
        val events = thawOwner(frozen, 1).let { t ->
            try {
                t.crash.reset()
                t.owner.hintPass()
                val seen = t.crash.count
                // the defer: the older drain ended early, its listening off, the switch still pending
                assertEquals(1L, t.owner.count("ch_generation", "generation = 2 AND state = 'pending_switch'"))
                assertEquals(1L, t.owner.count("ch_generation", "generation = 0 AND drain_until_day = ?", day - 1))
                assertEquals(0L, t.owner.count("sync_namespace", "namespace_id = ? AND listening = 1", frozen.link))
                seen
            } finally {
                t.world.close()
                t.crash.delegate.close()
                (t.bob.sql as org.ghost.storage.JdbcSqlExecutor).close()
            }
        }
        assertTrue("the deferred second switch raised $events events", events >= 10)
        println("SCN-CC crash singles: the deferred second switch (CH-SWITCH, the older drain ended early) raises $events events")
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
                // the switch's transaction is the defer's whole: the early end and the listening move together
                val deferred = owner.count("ch_generation", "generation = 0 AND drain_until_day = ?", day - 1) == 1L
                assertEquals("crash at $k: the defer is whole or absent", deferred,
                    owner.count("sync_namespace", "namespace_id = ? AND listening = 1", frozen.link) == 0L)
                assertEquals("crash at $k", 1L, owner.count("ch_generation", "generation = 2 AND state = 'pending_switch'"))
                // the op closes (production GC); the retried pass completes the switch (a pass can
                // defer once more — an unconsumed fetched row refuses the removal — so two rounds)
                collectOps(owner)
                t.world.pump()
                owner.hintPass()
                t.world.pump()
                owner.hintPass()
                assertEquals("crash at $k", 1L, owner.count("ch_generation", "generation = 2 AND state = 'current'"))
                assertEquals("crash at $k", 0L, owner.count("ch_generation", "generation = 0"))
                assertEquals(PostResult.QUEUED, owner.engine.post(frozen.channel, "după amânare".toByteArray(), null))
                collectOps(t.bob)
                t.world.pump()
                t.bob.hintPass()
                t.world.pump()
                t.bob.hintPass()
                t.world.pump()
                t.bob.hintPass()
                assertTrue("crash at $k", t.bob.displayed(frozen.channel).contains("după amânare"))
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

    /**
     * **The FIX-1 corner's crash singles** (§12.4; the review of S6): the older drain's end has already
     * moved to before today — the row is invisible to every live read but still `draining`, and the
     * demotion's trigger would abort the switch on it (the double-rotation deadlock: CH-SWITCH runs
     * before CH-SWEEP, so the sweep's removal retry never runs). The fixed switch reads the row without
     * the drain filter and takes the same end-or-defer path. A process death at every event of the
     * retry pass; after every crash the state is the defer's, whole or absent; once the op closes the
     * switch completes.
     */
    @Test
    fun aCrashAtEveryEventOfTheRetrySwitchOverAnExpiredDrainingRowLeavesTheDeferWholeOrNotAtAll() {
        val frozen = beforeSecondSwitch(opsCollected = false)
        val day = org.ghost.messaging.engine.DmTime.day(frozen.now)
        // the defer runs unarmed in the frozen world; the measured window is the retry pass over the
        // expired draining row (a different, smaller event set: no held rows, one more draining read)
        val events = thawOwner(frozen, 1).let { t ->
            try {
                t.crash.reset()
                t.owner.hintPass()
                assertEquals(1L, t.owner.count("ch_generation", "generation = 0 AND drain_until_day = ?", day - 1))
                t.crash.reset()
                t.owner.hintPass()
                val seen = t.crash.count
                assertEquals(1L, t.owner.count("ch_generation", "generation = 2 AND state = 'pending_switch'"))
                seen
            } finally {
                t.world.close()
                t.crash.delegate.close()
                (t.bob.sql as org.ghost.storage.JdbcSqlExecutor).close()
            }
        }
        assertTrue("the retry switch raised $events events", events >= 10)
        println("SCN-CC crash singles: the retry switch over an expired draining row raises $events events")
        var crashed = 0
        for (k in 1..events) {
            val t = thawOwner(frozen, 1)
            try {
                // the defer first (unarmed), then the retry pass over the expired draining row
                t.crash.reset()
                t.owner.hintPass()
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
                val stillDeferred = owner.count("ch_generation", "generation = 0 AND drain_until_day = ?", day - 1) == 1L
                assertEquals("crash at $k: the defer is whole or absent", stillDeferred,
                    owner.count("sync_namespace", "namespace_id = ? AND listening = 1", frozen.link) == 0L)
                assertEquals("crash at $k", 1L, owner.count("ch_generation", "generation = 2 AND state = 'pending_switch'"))
                collectOps(owner)
                t.world.pump()
                owner.hintPass()
                t.world.pump()
                owner.hintPass()
                assertEquals("crash at $k", 1L, owner.count("ch_generation", "generation = 2 AND state = 'current'"))
                assertEquals("crash at $k", 0L, owner.count("ch_generation", "generation = 0"))
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

    /** The world just before the funder's renewal pass in the EXPIRING window (the review of S6): the funder named by a policy change, nothing pending. */
    private fun beforeRenewal(): Frozen {
        val w = ChannelWorld()
        try {
            val ownerFile = folder.newFile("owner-before-renewal.db").also { it.delete() }
            val bobFile = folder.newFile("bob-before-renewal.db").also { it.delete() }
            val owner = w.client("owner", path = ownerFile.absolutePath)
            val bob = w.client("bob", path = bobFile.absolutePath)
            val id = ChannelScenes.channelOf(w, owner, bob)
            val before = ChannelAdversary.policy(owner, id)
            val after = org.ghost.crypto.bridge.ChannelPolicy(
                before.channelId, before.sizeClass, before.timerCode, before.timerVersion, before.historyPolicy,
                before.flags, before.idleEvictDays, before.pwVersion, before.name, before.committers,
                listOf(before.funders.first(), bob.contexts.open(id.toByteArray())!!.pseudonym),
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
            // into the renewal window, with the scheduled pass arm cleared: the pass runs the renewal alone
            val target = org.ghost.messaging.engine.DmTime.weekStart(org.ghost.messaging.engine.DmTime.week(w.now) + 1) -
                org.ghost.messaging.channel.engine.ChannelFunderStep.RENEWAL_WINDOW_SECONDS + 60
            if (target > w.now) w.advance(target - w.now)
            bob.database.transaction { tx ->
                val row = bob.channelStores.channels.schedule(tx.sql, id.toByteArray())
                    ?: return@transaction
                bob.channelStores.channels.putSchedule(tx, id.toByteArray(), row.nextSelfupdateDay, row.lastOwnCommitDay, null)
            }
            assertEquals(0L, bob.count("relay_key_registration"))
            val relay = w.relay.copy()
            val now = w.now
            w.close()
            return Frozen(ownerFile, bobFile, relay, now, id, ByteArray(0))
        } finally {
            w.close()
        }
    }

    /**
     * **The funder renewal's crash singles** (§12.4; the review of S6): a process death at every event
     * of the renewal step's transaction — `Funding.set` (the flag a policy change named), the
     * write-only pending-namespace registration, `Registrations.keep` of the week and the pair's
     * periods. After every crash: integrity; the registration rows are all there or none (one
     * transaction); the retried pass renews, idempotently.
     */
    @Test
    fun aCrashAtEveryEventOfTheRenewalLeavesTheRowsAllOrNone() {
        val frozen = beforeRenewal()
        val week = org.ghost.messaging.engine.DmTime.week(frozen.now)
        val events = thaw(frozen, 1).let { t ->
            try {
                t.crash.reset()
                t.bob.timePass()
                val seen = t.crash.count
                assertEquals(1L, t.bob.count("sync_namespace_fund"))
                assertTrue("the renewal kept the week's rows", t.bob.count("relay_key_registration", "period_id = ?", week) >= 6)
                seen
            } finally {
                t.world.close()
                t.crash.delegate.close()
                (t.owner.sql as org.ghost.storage.JdbcSqlExecutor).close()
            }
        }
        assertTrue("the renewal raised $events events", events >= 10)
        println("SCN-FD crash singles: the funder renewal raises $events events")
        var crashed = 0
        for (k in 1..events) {
            val t = thaw(frozen, 1)
            try {
                t.crash.reset()
                t.crash.armAt = k
                try {
                    t.bob.timePass()
                    fail("no crash at event $k of $events")
                } catch (e: SimulatedCrash) {
                    crashed++
                }
                val bob = t.reboot(2)
                assertEquals("after a crash at $k: ${bob.integrity()}", emptyList<String>(), bob.integrity())
                // one transaction: the rows are all there or none
                assertTrue(
                    "crash at $k: partial renewal rows",
                    bob.count("relay_key_registration") == 0L || bob.count("relay_key_registration", "period_id = ?", week) >= 6,
                )
                bob.timePass()
                assertEquals("crash at $k", 1L, bob.count("sync_namespace_fund"))
                assertTrue("crash at $k", bob.count("relay_key_registration", "period_id = ?", week) >= 6)
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

    /** The world just before the sweep removes a removed member's older generation and demotes its current one (§19.41's F-S6-3 corner, deferred half). */
    private fun beforeRemovedMemberSweepDemotion(): Frozen {
        val w = ChannelWorld()
        try {
            val ownerFile = folder.newFile("owner-before-removed-sweep.db").also { it.delete() }
            val bobFile = folder.newFile("bob-before-removed-sweep.db").also { it.delete() }
            val owner = w.client("owner", path = ownerFile.absolutePath)
            val bob = w.client("bob", path = bobFile.absolutePath)
            val carol = w.client("carol")
            val id = ChannelScenes.channelOf(w, owner, bob, carol)
            // rotation 1: carol goes; everyone switches — generation 0 drains, generation 1 is current
            owner.engine.remove(id, carol.contexts.open(id.toByteArray())!!.pseudonym)
            w.quiesce()
            w.pastSettleWindow()
            w.quiesce()
            w.advance(70 * DmWorld.MINUTE)
            for (c in w.clients) c.hintPass()
            // rotation 2 removes bob while generation 0 drains: his settle ends the older drain at once
            // and defers his current generation's demotion to the sweep (at most one draining row)
            owner.engine.remove(id, bob.contexts.open(id.toByteArray())!!.pseudonym)
            w.quiesce()
            w.pastSettleWindow()
            w.quiesce()
            assertEquals(ChannelState.REMOVED, bob.channel(id)!!.state)
            val day = org.ghost.messaging.engine.DmTime.day(w.now)
            assertEquals(1L, bob.count("ch_generation", "generation = 0 AND drain_until_day = ?", day - 1))
            collectOps(bob)
            w.advance(DmWorld.DAY)
            val ns0 = generationNs(bob, id, 0)
            val relay = w.relay.copy()
            val now = w.now
            w.close()
            return Frozen(ownerFile, bobFile, relay, now, id, ns0)
        } finally {
            w.close()
        }
    }

    /**
     * **The removed-member sweep demotion's crash singles** (§12.4; §19.41's F-S6-3 corner): a process
     * death at every event of the sweep pass that removes the older generation and demotes the removed
     * member's current one. After every crash: integrity; the older generation's row and its namespace's
     * listening move together, and the current generation's demotion rides the same transaction; the
     * retried pass finishes the corner.
     */
    @Test
    fun aCrashAtEveryEventOfTheRemovedMemberSweepDemotionLeavesTheGenerationsTogether() {
        val frozen = beforeRemovedMemberSweepDemotion()
        val events = thaw(frozen, 1).let { t ->
            try {
                t.crash.reset()
                t.bob.timePass()
                val seen = t.crash.count
                assertEquals(0L, t.bob.count("ch_generation", "generation = 0"))
                assertEquals(1L, t.bob.count("ch_generation", "generation = 1 AND state = 'draining'"))
                seen
            } finally {
                t.world.close()
                t.crash.delegate.close()
                (t.owner.sql as org.ghost.storage.JdbcSqlExecutor).close()
            }
        }
        assertTrue("the removed-member sweep demotion raised $events events", events >= 10)
        println("SCN-CK crash singles: the removed-member sweep demotion raises $events events")
        var crashed = 0
        for (k in 1..events) {
            val t = thaw(frozen, 1)
            try {
                t.crash.reset()
                t.crash.armAt = k
                try {
                    t.bob.timePass()
                    fail("no crash at event $k of $events")
                } catch (e: SimulatedCrash) {
                    crashed++
                }
                val bob = t.reboot(2)
                assertEquals("after a crash at $k: ${bob.integrity()}", emptyList<String>(), bob.integrity())
                val gone = bob.count("ch_generation", "generation = 0") == 0L
                // the row's deletion and the demotion are one transaction (the namespace's listening went
                // off at the removal settle, before the sweep)
                assertEquals("crash at $k: the demotion rides the same transaction", gone,
                    bob.count("ch_generation", "generation = 1 AND state = 'draining'") == 1L)
                // the sweep retries its removal while anything refuses it; two rounds settle it
                t.world.pump()
                bob.timePass()
                t.world.pump()
                bob.timePass()
                assertEquals("crash at $k", 0L, bob.count("ch_generation", "generation = 0"))
                assertEquals("crash at $k", 1L, bob.count("ch_generation", "generation = 1 AND state = 'draining'"))
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

    /** The world just before the joiner's session-start switch (§19.8 (c)): the hour-less pending generation, no pass since the join. */
    private fun beforeJoinerSwitch(): Frozen {
        val w = ChannelWorld()
        try {
            val ownerFile = folder.newFile("owner-before-joiner-switch.db").also { it.delete() }
            val daveFile = folder.newFile("dave-before-joiner-switch.db").also { it.delete() }
            val owner = w.client("owner", path = ownerFile.absolutePath)
            val bob = w.client("bob")
            val carol = w.client("carol")
            val id = ChannelScenes.channelOf(w, owner, bob, carol)
            // dave accepts; the same pass admits him and removes carol: the Welcome's bootstrap names
            // generation 1 — dave keeps it pending with no hour
            val dave = w.client("dave", path = daveFile.absolutePath)
            assertEquals(AcceptResult.PENDING, dave.engine.accept(ChannelAdmissionTest.invite(owner, id), null))
            w.quiesce()
            owner.engine.remove(id, carol.contexts.open(id.toByteArray())!!.pseudonym)
            w.quiesce()
            w.pastSettleWindow()
            w.quiesce()
            // the staying members switch; dave's hour-less pending row waits for its session start
            w.advance(70 * DmWorld.MINUTE)
            for (c in listOf(owner, bob, carol)) c.hintPass()
            assertEquals(1L, owner.count("ch_generation", "generation = 1 AND state = 'current'"))
            assertEquals(ChannelState.ACTIVE, dave.channel(id)!!.state)
            assertEquals(1L, dave.count("ch_generation", "generation = 1 AND state = 'pending_switch' AND switch_hour IS NULL"))
            val relay = w.relay.copy()
            val now = w.now
            w.close()
            return Frozen(ownerFile, daveFile, relay, now, id, ByteArray(0))
        } finally {
            w.close()
        }
    }

    /** A world restored from [frozen]; the client over the crash executor is named [name] (its pseudonym seeds derive from the name). */
    private class ThawedTarget(val world: ChannelWorld, var target: ChannelClient, val other: ChannelClient, val crash: CrashingSqlExecutor, private val name: String) {
        fun reboot(boot: Int): ChannelClient {
            target.die()
            crash.armAt = null
            target = world.client(name, crash, boot)
            return target
        }
    }

    private fun thawNamed(frozen: Frozen, boot: Int, name: String): ThawedTarget {
        val world = ChannelWorld(startSeconds = frozen.now, relay = frozen.relay.copy())
        val other = world.client("owner", ChannelWorld.restore(frozen.owner), boot)
        val crash = CrashingSqlExecutor(ChannelWorld.restore(frozen.bob))
        val target = world.client(name, crash, boot)
        return ThawedTarget(world, target, other, crash, name)
    }

    /**
     * **The joiner's session-start switch crash singles** (§12.4; §19.8 (c)): a process death at every
     * event of the session-start pass that switches the joiner's hour-less pending generation (a
     * distinct transaction: no demotion — the joiner has no older generation). After every crash:
     * integrity; the generation is `pending_switch` with no namespace, or whole (`current`, ns_1
     * registered and listened); the retried pass switches and posts go both ways.
     */
    @Test
    fun aCrashAtEveryEventOfTheJoinerSessionSwitchLeavesTheGenerationPendingOrWhole() {
        val frozen = beforeJoinerSwitch()
        val events = thawNamed(frozen, 1, "dave").let { t ->
            try {
                t.crash.reset()
                t.target.sessionStart()
                val seen = t.crash.count
                assertEquals(1L, t.target.count("ch_generation", "generation = 1 AND state = 'current'"))
                seen
            } finally {
                t.world.close()
                t.crash.delegate.close()
                (t.other.sql as org.ghost.storage.JdbcSqlExecutor).close()
            }
        }
        assertTrue("the joiner's switch raised $events events", events >= 10)
        println("SCN-CC crash singles: the joiner's session-start switch raises $events events")
        var crashed = 0
        for (k in 1..events) {
            val t = thawNamed(frozen, 1, "dave")
            try {
                t.crash.reset()
                t.crash.armAt = k
                try {
                    t.target.sessionStart()
                    fail("no crash at event $k of $events")
                } catch (e: SimulatedCrash) {
                    crashed++
                }
                val dave = t.reboot(2)
                assertEquals("after a crash at $k: ${dave.integrity()}", emptyList<String>(), dave.integrity())
                val ns1 = generationNs(dave, frozen.channel, 1)
                val switched = dave.count("ch_generation", "generation = 1 AND state = 'current'") == 1L
                if (!switched) {
                    assertEquals("crash at $k", 1L, dave.count("ch_generation", "state = 'pending_switch'"))
                    assertEquals("crash at $k", 0L, dave.count("sync_namespace", "namespace_id = ?", ns1))
                } else {
                    assertEquals("crash at $k", 1L, dave.count("sync_namespace", "namespace_id = ? AND listening = 1", ns1))
                    assertEquals("crash at $k", 6L, dave.count("relay_capability", "namespace_id = ?", ns1))
                }
                dave.sessionStart()
                assertEquals("crash at $k", 1L, dave.count("ch_generation", "generation = 1 AND state = 'current'"))
                assertEquals(PostResult.QUEUED, dave.engine.post(frozen.channel, "din g_1".toByteArray(), null))
                t.world.quiesce()
                assertTrue("crash at $k", t.other.displayed(frozen.channel).contains("din g_1"))
                t.world.advance(DmWorld.MINUTE)
                assertEquals(PostResult.QUEUED, t.other.engine.post(frozen.channel, "înapoi".toByteArray(), null))
                t.world.quiesce()
                assertTrue("crash at $k", dave.displayed(frozen.channel).contains("înapoi"))
                assertEquals(emptyList<String>(), dave.integrity())
                assertEquals(emptyList<String>(), t.other.integrity())
            } finally {
                t.world.close()
                t.crash.delegate.close()
                (t.other.sql as org.ghost.storage.JdbcSqlExecutor).close()
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
