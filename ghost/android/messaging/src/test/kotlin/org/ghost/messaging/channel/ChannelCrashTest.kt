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
}
