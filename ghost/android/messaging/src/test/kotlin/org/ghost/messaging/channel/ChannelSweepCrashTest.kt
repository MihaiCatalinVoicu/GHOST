package org.ghost.messaging.channel

import org.ghost.messaging.DmWorld
import org.ghost.messaging.api.ChannelId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test

/**
 * **Crash singles for `CH-SWEEP`'s ephemeral half** (Phase 10 design §12.4, CS-C1, CS-C2; the F7 §8.3
 * method; slice S8): a process death **at every event** of the sweep's transactions — the post cascade's
 * batches, the expired-pending edge, the epoch sweep with its native `sweepPast` call, the invites and the
 * tags — then a reboot (a new client over the same database: a new native context, a new random stream) and
 * the rest of the scenario. After every reboot: `integrity_check`, `foreign_key_check`, the world's
 * invariants ([ChannelClient.integrity]), the atomicity of what the crash found half-done (a batch's posts
 * and their pending rows commit together; an epoch row, its fork signals and the box keys never name an
 * epoch the rows no longer hold), and the retried sweep runs to the same fixed point; at the end, liveness:
 * a fresh post flows to the other member.
 *
 * The world before the sweep is built once and frozen (`VACUUM INTO` copies via [ChannelWorld.restore]), so
 * a run costs the sweep and the scenario's end, never a fresh admission.
 */
class ChannelSweepCrashTest {

    /** The scratch directory: the system drive is the CI's, the module's build dir is this machine's. */
    private val scratch = java.io.File("build/tmp/channel-sweep-crash").apply {
        deleteRecursively()
        mkdirs()
    }

    @Before
    fun native() {
        assumeTrue("ghost-dm-host is not loaded (-Dghost.dm.native)", ChannelWorld.nativeAvailable())
    }

    /** A world frozen an hour before the sweep: everything expired, nothing swept yet. */
    private class Frozen(val owner: java.io.File, val bob: java.io.File, val relay: ModelChannelRelay, val now: Long, val channel: ChannelId)

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

    /** The whole ephemeral half, the order [ChannelEngine.runPass] runs it in. */
    private fun sweepAll(client: ChannelClient) {
        val s = client.engine.sweepStep
        s.sweepPosts()
        s.sweepPending()
        s.sweepReveals()
        s.sweepSeen()
        s.sweepEpochs()
        s.sweepInvites()
        s.sweepJoinRequests()
        s.sweepKpTags()
        s.sweepGlobalRows()
    }

    /** What the sweep must reach on both members: every expired row gone, the live state intact. */
    private fun assertSwept(owner: ChannelClient, bob: ChannelClient, id: ChannelId) {
        for (c in listOf(owner, bob)) {
            assertEquals("${c.name}: expired posts", 0L, c.count("ch_post"))
            assertEquals("${c.name}: the cascade", 0L, c.count("ch_reaction"))
            assertEquals("${c.name}: the expired pending", 0L, c.count("ch_pending_post"))
            assertEquals("${c.name}: epoch 0 past retention", 0L, c.count("ch_epoch", "epoch = 0"))
            assertEquals("${c.name}: its fork signals", 0L, c.count("ch_fork_signal"))
            assertEquals("${c.name}: the expired invites", 0L, c.count("ch_invite_issued"))
            assertEquals("${c.name}: the expired links", 0L, c.count("ch_invite_own"))
            assertEquals("integrity after the sweep at ${c.name}", emptyList<String>(), c.integrity())
        }
        // the current epoch and the open channel survive
        assertEquals(1L, owner.count("ch_epoch"))
        assertEquals("the channel is live", 1L, owner.count("ch_channel", "state = 'active'"))
    }

    /** The invariants a crash must not break, whatever prefix committed. */
    private fun assertIntact(owner: ChannelClient, bob: ChannelClient) {
        for (c in listOf(owner, bob)) {
            c.sql.query("PRAGMA integrity_check") { assertEquals("integrity at ${c.name}", "ok", it.string(0)) }
            c.sql.query("PRAGMA foreign_key_check") { fail("foreign key violation at ${c.name}: ${it.string(0)}") }
            assertEquals("world invariants at ${c.name}", emptyList<String>(), c.integrity())
            // a reaction never outlives its post (the FK says so too; the sweep's batch deletes them together)
            assertEquals(0L, c.count("ch_reaction", "NOT EXISTS (SELECT 1 FROM ch_post p WHERE p.op_id = target)"))
        }
    }

    /** Nine days into a 7-day channel: the post, the pending one, epoch 0 and the invites are all expired. */
    private fun freeze(): Frozen {
        val w = ChannelWorld()
        try {
            val ownerFile = java.io.File(scratch, "owner-before-sweep.db")
            val bobFile = java.io.File(scratch, "bob-before-sweep.db")
            ownerFile.delete(); bobFile.delete()
            val owner = w.client("owner", path = ownerFile.absolutePath)
            val bob = w.client("bob", path = bobFile.absolutePath)
            val id = ChannelScenes.channelOf(w, owner, bob)
            ChannelScenes.post(bob, id, "sweep me")
            // a pending post past its op deadline: the removal hold keeps the channel not current
            val c = id.toByteArray()
            val epoch = bob.channel(id)!!.epoch
            val hash = ChannelWorld.sha256("a removing candidate")
            bob.database.transaction { tx ->
                bob.channelStores.candidates.insert(
                    tx, c, epoch, hash, ChannelWorld.sha256("someone"), 0, false,
                    bob.env.seal(bob.content, org.ghost.messaging.channel.engine.ChannelAd.candidate(c, epoch, hash), ByteArray(64)),
                    org.ghost.messaging.engine.DmTime.floorMinute(w.now), removes = true,
                )
            }
            ChannelScenes.post(bob, id, "held")
            w.quiesce()
            w.advance(9 * DmWorld.DAY + DmWorld.HOUR)
            val relay = w.relay.copy()
            val now = w.now
            w.close()
            return Frozen(ownerFile, bobFile, relay, now, id)
        } finally {
            w.close()
        }
    }

    @Test
    fun theEphemeralSweepSurvivesACrashAtEveryEvent() {
        val frozen = freeze()
        // the envelope: how many events the whole sweep is, measured on a crash-free probe
        val probe = thaw(frozen, 0)
        probe.crash.reset()
        sweepAll(probe.bob)
        val events = probe.crash.count
        probe.world.close()

        for (i in 1..events) {
            val t = thaw(frozen, i)
            t.crash.reset()
            t.crash.armAt = i
            try {
                sweepAll(t.bob)
                fail("event $i of ${events}: the sweep ran past the armed crash")
            } catch (e: SimulatedCrash) {
                assertEquals("the crash fired where it was armed", i, e.at)
            }
            // a reboot over the same database; the invariants hold whatever prefix committed
            t.reboot(1_000 + i)
            assertIntact(t.owner, t.bob)
            // the retried path runs to the same fixed point
            sweepAll(t.bob)
            sweepAll(t.owner)
            assertSwept(t.owner, t.bob, frozen.channel)
            t.world.close()
        }

        // liveness at the fixed point: a fresh post flows to the other member
        val end = thaw(frozen, 9_999)
        sweepAll(end.bob)
        sweepAll(end.owner)
        assertSwept(end.owner, end.bob, frozen.channel)
        ChannelScenes.post(end.owner, frozen.channel, "after the storms")
        end.world.quiesce()
        assertEquals(listOf("after the storms"), end.bob.displayed(frozen.channel))
        end.world.close()
    }
}
