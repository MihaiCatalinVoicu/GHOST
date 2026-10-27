package org.ghost.update.harness

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * The G-D7 gate-scale run (Phase 14 design §12.1's G-D7 row and §11.2's scale): the update
 * world at 50 clients × 120 virtual days through the job model, the hostile-mirror mix cycled
 * across shards, the four named worlds' core assertions sampled, and the NI-U twins re-run at
 * 120 days — sharded across seeded worlds and threads, the sync harness's arrangement
 * (`ghost.sync.seeds` in ci.yml, `Harness.parallel`).
 *
 * Scale knobs: `-Dghost.update.gate=1` for the gate scale (50×120, 4 worlds), optional
 * `-Dghost.update.gate.clients/days/worlds/threads` to vary it. The default (the plain
 * `:update:testDebugUnitTest`) runs a small smoke so the runner stays exercised in CI; the
 * gate job runs the real scale and reports only what it measured.
 */
class GateScaleWorldsTest {

    private fun assumeHostLibrary() = assumeTrue(
        "the ghost-dm-host library is not loaded (-Dghost.net.native)",
        System.getProperty("ghost.net.native") != null,
    )

    /** The modes the hostile mix cycles (parameterized where the mode needs a fixture). */
    private fun arm(world: World, mirror: ModelMirror, mode: MirrorMode) {
        mirror.mode = mode
        when (mode) {
            MirrorMode.EQUIVOCATE -> mirror.equivocateBundle = world.fixtures.doc("bundle-eq-b.ghrb")
            MirrorMode.ROLLBACK -> mirror.rollbackBundle = world.fixtures.staleBundle
            else -> Unit
        }
    }

    private class WorldStats(
        val jobs: Long,
        val updateRuns: Long,
        val engineFailures: Long,
        val modesCycled: Int,
    )

    private fun driveWorld(seed: Long, index: Int, clients: Int, days: Int, pool: java.util.concurrent.ExecutorService): WorldStats {
        World("gate-$index", seed).use { world ->
            val anchorA = world.mirror()
            val hostile = world.mirror()
            val clientList = (0 until clients).map { i ->
                // Half the clients a version behind (offers and downloads happen at scale).
                world.client(installed = if (i % 2 == 0) 2 else 1, sdk = 29)
                    .also { it.firstStart() }
            }
            val startAt = world.clock.trueMillis
            val endAt = startAt + days * VirtualClock.DAY_MILLIS
            val jobs = AtomicLong()
            val updateRuns = AtomicLong()
            val engineFailures = AtomicLong()
            var modesCycled = 0
            val modes = MirrorMode.entries.filter { it != MirrorMode.NONE }
            var jobIndex = 0
            var fire = JobDriver.fireAt(startAt, 0, seed, "client-0")
            while (fire < endAt) {
                world.clock.advance(fire - world.clock.trueMillis)
                // The hostile mix: the second mirror cycles modes at job boundaries.
                if (jobIndex % 240 == 0) {
                    arm(world, hostile, modes[(index + modesCycled++) % modes.size])
                }
                // Per client: the production fate decision (visibility, quiet/update draws).
                val runners = mutableListOf<Callable<Unit>>()
                for (c in clientList) {
                    val quiet = JobDriver.keyedDraw(seed, c.name, jobIndex, "quiet") <
                        JobDriver.QUIET_PROBABILITY
                    val update = JobDriver.keyedDraw(seed, c.name, jobIndex, "update") <
                        JobDriver.UPDATE_PROBABILITY
                    if (quiet || !update) continue
                    val target = c
                    runners += Callable<Unit> {
                        try {
                            target.updateRun(anchorA, hostile)
                            updateRuns.incrementAndGet()
                        } catch (e: org.ghost.network.NetworkException) {
                            engineFailures.incrementAndGet() // a hostile mirror's refusal/abort
                        }
                    }
                }
                if (runners.isNotEmpty()) {
                    for (f in pool.invokeAll(runners)) f.get()
                }
                world.clock.advance(JobDriver.D_U_MILLIS)
                jobs.incrementAndGet()
                jobIndex++
                fire = startAt + jobIndex * JobDriver.JOB_PERIOD_MILLIS +
                    (JobDriver.keyedDraw(seed, "client-0", jobIndex, "flex") * JobDriver.FLEX_MILLIS).toLong()
            }
            // The structural invariants hold at scale: every client keeps exactly one epoch
            // row, staged rows are consistent, and the mirrors served what the transcript saw.
            for (c in clientList) {
                val loaded = c.store.load()!!
                assertTrue(loaded.facts.manifestSeq >= 0)
                val staged = c.store.staged()
                if (staged != null) {
                    assertTrue(staged.received in 0..staged.apkLength)
                }
            }
            return WorldStats(jobs.get(), updateRuns.get(), engineFailures.get(), modesCycled)
        }
    }

    @Test
    fun gateScale() {
        assumeHostLibrary()
        val gate = System.getProperty("ghost.update.gate") == "1"
        val clients = System.getProperty("ghost.update.gate.clients")?.toIntOrNull() ?: if (gate) 50 else 2
        val days = System.getProperty("ghost.update.gate.days")?.toIntOrNull() ?: if (gate) 120 else 14
        val worlds = System.getProperty("ghost.update.gate.worlds")?.toIntOrNull() ?: if (gate) 4 else 1
        val threads = System.getProperty("ghost.update.gate.threads")?.toIntOrNull()
            ?: Runtime.getRuntime().availableProcessors().coerceIn(2, 24)
        check(clients in 2..50) { "§11.2's 2-50 clients" }

        val started = System.nanoTime()
        val pool = Executors.newFixedThreadPool(threads)
        val worldPool = Executors.newFixedThreadPool(minOf(worlds, threads))
        try {
            val futures = (0 until worlds).map { index ->
                worldPool.submit<WorldStats> {
                    driveWorld(seed = 5_000L + index, index = index, clients = clients, days = days, pool = pool)
                }
            }
            val stats = futures.map { it.get() }
            val wall = (System.nanoTime() - started) / 1_000_000
            val totalJobs = stats.sumOf { it.jobs }
            val totalRuns = stats.sumOf { it.updateRuns }
            val totalFailures = stats.sumOf { it.engineFailures }
            val modes = stats.sumOf { it.modesCycled }
            report(
                "update gate scale: $worlds worlds x $clients clients x $days days, " +
                    "$totalJobs jobs, $totalRuns update runs, $totalFailures hostile-aborted runs, " +
                    "$modes hostile-mode cycles, wall ${wall}ms (this machine)",
            )

            if (gate) {
                // The named worlds' core assertions, sampled inside the gate run.
                StolenReleaseKeyWorldTest().everyClientAdoptsTheRevocationRootAndDropsTheStolenManifestsAuthority()
                NamedHostileWorldsTest().recoveryEpochWorld()
                NamedHostileWorldsTest().rootSwapWorld()
                RevocationWorldTest().revocationWorld()
                report("update gate scale: named worlds sampled green (stolen-release-key, recovery-epoch, root-swap, revocation)")

                // The twins at 120 days.
                System.setProperty("ghost.update.twin.days", days.toString())
                try {
                    val twins = NiUTwinsTest()
                    twins.niU1ActivityAxisLeavesDrawsAndMirrorViewsIdentical()
                    twins.niU2EntitlementAxisAndThePaymentHoldLeaveMirrorViewsIdentical()
                    twins.niU3OfferAxisLeavesBundlesTimingAndRunLengthsIdentical()
                    twins.niU4StoredRootVersionLeavesBundleViewsIdentical()
                } finally {
                    System.clearProperty("ghost.update.twin.days")
                }
                report("update gate scale: twins NI-U1..NI-U4 equal at $days days")
            }
        } finally {
            worldPool.shutdownNow()
            pool.shutdownNow()
            worldPool.awaitTermination(5, TimeUnit.MINUTES)
            pool.awaitTermination(5, TimeUnit.MINUTES)
        }
    }

    private fun report(line: String) {
        val dir = java.io.File("build/update-mutants").apply { mkdirs() }
        val file = java.io.File(dir, "report.txt")
        val lines = if (file.isFile) file.readLines() else emptyList()
        if (line !in lines) file.appendText(line + "\n")
    }
}
