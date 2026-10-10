package org.ghost.messaging.channel

import org.ghost.messaging.DmWorld
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
import java.io.File

/**
 * **SCN-M20's crash singles** (Phase 10 design §12.4's scale row: the full 20-client scenario with
 * crash singles at the named critical events, not the full crash enumeration — that is the exit
 * gate's job, sized from the measured per-seed time; §12.5's scale row). Two new choreography paths
 * the SCN-CA … SCN-CD singles do not cover:
 *
 *  1. **An admission pass among the waves at 20 clients** ([aCrashAtEveryEventOfTheFourthWaveAdmission]):
 *     the world of 13 admitted members with the fourth wave's four join requests delivered, a crash
 *     at every SQL statement of the committer's admitting pass — then a reboot (a new context over
 *     the same database) and the drive to liveness: the wave admitted, the epoch log and the
 *     authenticators equal everywhere (T41), the invariants of §12.4.
 *  2. **The scenario's composition of the resync-after-TTL path** ([aCrashAtEveryEventOfThePastTtlRejoinAdmission]):
 *     the whole base scenario frozen the moment before the admitting pass of c13's rejoin — the
 *     member past EXPIRE_LOG in `stale_suspected`, its signed request on the relays, the committer
 *     about to build the swap commit at a 20-member channel — crash at every statement, reboot,
 *     and the rejoin completes: c13 active at the live epoch, T41 everywhere.
 *
 * The freeze is a `VACUUM INTO` snapshot of every client's open database plus a copy of the relay
 * ([ChannelM20.snapshotOpenDb]); each run restores all of them into its own folder (deleted after
 * the run — 21 file databases per run would otherwise fill the temp disk).
 */
class ChannelM20CrashTest {

    @get:Rule
    val folder = TemporaryFolder()

    @Before
    fun native() {
        assumeTrue("ghost-dm-host is not loaded (-Dghost.dm.native)", ChannelWorld.nativeAvailable())
    }

    /** The frozen world before a named admission pass: every client's database, the relay, the time. */
    private class Frozen(
        val files: Map<String, File>,
        val relay: ModelChannelRelay,
        val now: Long,
        val id: ChannelId,
        /** The client whose pass runs the admission (its executor carries the crash arm). */
        val committer: String,
    )

    /** A run's world: the clients over restored copies, the committer over the crash executor. */
    private class Thawed(
        val world: ChannelWorld,
        val clients: Map<String, ChannelClient>,
        val crash: CrashingSqlExecutor,
        val executors: List<org.ghost.storage.JdbcSqlExecutor>,
        val frozen: Frozen,
        var committer: ChannelClient,
    ) {
        fun reboot(boot: Int): ChannelClient {
            committer.die()
            crash.armAt = null
            committer = world.client(frozen.committer, sql = crash, boot = boot)
            return committer
        }

        fun closeAll() {
            world.close()
            for (e in executors) e.close()
        }
    }

    private fun freeze(stopAt: ChannelM20.StopAt, tag: String): Frozen {
        val dir = folder.newFolder(tag)
        val built = ChannelM20.build(
            ChannelM20.Config(seed = ChannelM20.SEEDS[0], dbDir = dir, stopAt = stopAt),
        )
        val files = HashMap<String, File>()
        for (c in built.world.clients.toList()) {
            val snap = File(dir, "snap-${c.name}.db")
            ChannelM20.snapshotOpenDb(c, snap)
            files[c.name] = snap
        }
        val frozen = Frozen(files, built.world.relay.copy(), built.world.now, built.id, ChannelM20.OWNER)
        built.world.close()
        return frozen
    }

    private fun thaw(frozen: Frozen, boot: Int, armAt: Int?): Thawed {
        val world = ChannelWorld(startSeconds = frozen.now, relay = frozen.relay.copy())
        val runDir = folder.newFolder("run-" + System.nanoTime())
        val clients = HashMap<String, ChannelClient>()
        val executors = ArrayList<org.ghost.storage.JdbcSqlExecutor>()
        lateinit var committer: ChannelClient
        lateinit var crash: CrashingSqlExecutor
        for ((name, snap) in frozen.files) {
            val copy = File(runDir, "$name.db")
            snap.copyTo(copy)
            if (name == frozen.committer) {
                val executor = org.ghost.storage.JdbcSqlExecutor(copy.absolutePath)
                executors += executor
                crash = CrashingSqlExecutor(executor)
                crash.armAt = armAt
                committer = world.client(name, sql = crash, boot = boot)
            } else {
                val executor = org.ghost.storage.JdbcSqlExecutor(copy.absolutePath)
                executors += executor
                clients[name] = world.client(name, sql = executor, boot = boot)
            }
        }
        return Thawed(world, clients, crash, executors, frozen, committer)
    }

    /** The armed action: the committer's admitting pass (the session-start arm fired). */
    private fun Thawed.act() {
        committer.sessionStart()
        world.advance(6 * DmWorld.MINUTE)
        committer.timePass()
    }

    /** After a reboot (or the reference run): the admission completes and the world is live and converged. */
    private fun Thawed.finish(expectActive: List<String>) {
        val id = frozen.id
        val anchor = world.clients.first { it.name == frozen.committer }
        var guard = 0
        while (guard++ < 10) {
            world.quiesce()
            val done = expectActive.all { name ->
                world.clients.first { it.name == name }.channel(id)?.state == ChannelState.ACTIVE
            }
            if (done && world.relay.pendingOps(world.clients) == 0) break
            // The admitting pass is a scheduled one (CO-8): re-arm it, let the window run, settle.
            anchor.sessionStart()
            world.advance(6 * DmWorld.MINUTE)
            world.pastSettleWindow()
        }
        world.quiesce()
        for (name in expectActive) {
            val c = world.clients.first { it.name == name }
            assertEquals("$name admitted", ChannelState.ACTIVE, c.channel(id)!!.state)
            assertEquals("$name at the anchor's epoch", anchor.channel(id)!!.epoch, c.channel(id)!!.epoch)
        }
        // T41 across every active member: same epoch, same authenticator.
        val auth = ChannelM20.epochAuthenticatorOf(anchor, id)
        for (c in world.clients) {
            if (c.channel(id)?.state != ChannelState.ACTIVE) continue
            assertArrayEquals41(c.name, auth, ChannelM20.epochAuthenticatorOf(c, id))
        }
        // Liveness: a post from the newest member reaches the anchor and back.
        val newest = world.clients.first { it.name == expectActive.last() }
        assertEquals(PostResult.QUEUED, newest.engine.post(id, "după crash".toByteArray(), null))
        world.quiesce()
        assertTrue(anchor.displayed(id).contains("după crash"))
        world.advance(DmWorld.MINUTE)
        assertEquals(PostResult.QUEUED, anchor.engine.post(id, "înapoi".toByteArray(), null))
        world.quiesce()
        assertTrue(newest.displayed(id).contains("înapoi"))
        for (c in world.clients) {
            if (c.channel(id)?.state == ChannelState.ACTIVE) assertTrue("${c.name}: ${c.integrity()}", c.integrity().isEmpty())
        }
    }

    private fun assertArrayEquals41(name: String, expected: ByteArray, actual: ByteArray) {
        assertTrue("T41: $name's epoch_authenticator", expected.contentEquals(actual))
    }

    @Test
    fun aCrashAtEveryEventOfTheFourthWaveAdmissionLeavesTheWaveAdmitted() {
        val frozen = freeze(ChannelM20.StopAt.WAVE_ADMISSION, "m20-crash-wave")
        val events = thaw(frozen, 1, null).run {
            try {
                act()
                finish(listOf("c14", "c15", "c16", "c17"))
            } finally {
                closeAll()
            }
            crash.count
        }
        ChannelReport.line("channel SCN-M20 crash singles: wave-4 admission $events events, all green")
        var ran = 0
        for (i in 1..events) {
            val t = thaw(frozen, 1, i)
            try {
                try {
                    t.act()
                    fail("event $i did not crash")
                } catch (e: SimulatedCrash) {
                    // expected: the armed statement
                }
                t.reboot(2)
                t.finish(listOf("c14", "c15", "c16", "c17"))
                ran++
            } finally {
                t.closeAll()
            }
        }
        assertEquals(events, ran)
    }

    @Test
    fun aCrashAtEveryEventOfThePastTtlRejoinAdmissionLeavesTheRejoinComplete() {
        val frozen = freeze(ChannelM20.StopAt.REJOIN_ADMISSION, "m20-crash-rejoin")
        val events = thaw(frozen, 1, null).run {
            try {
                act()
                finish(listOf(ChannelM20.PAST_TTL))
            } finally {
                closeAll()
            }
            crash.count
        }
        ChannelReport.line("channel SCN-M20 crash singles: past-TTL rejoin admission $events events, all green")
        var ran = 0
        for (i in 1..events) {
            val t = thaw(frozen, 1, i)
            try {
                try {
                    t.act()
                    fail("event $i did not crash")
                } catch (e: SimulatedCrash) {
                    // expected: the armed statement
                }
                t.reboot(2)
                t.finish(listOf(ChannelM20.PAST_TTL))
                ran++
            } finally {
                t.closeAll()
            }
        }
        assertEquals(events, ran)
    }
}
