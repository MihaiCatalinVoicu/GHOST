package org.ghost.entitlement.harness

import org.ghost.sync.harness.Harness
import org.ghost.sync.harness.HarnessReport
import org.ghost.sync.harness.JournalMode
import org.ghost.sync.harness.RunSpec
import org.ghost.sync.harness.Runner
import org.junit.Test
import java.util.concurrent.atomic.AtomicLong

/**
 * The seeded `:entitlement` liveness worlds (Phase 8 design §13.2, §13.6): 1 000 seeds by default,
 * `-Dghost.entitlement.seeds=N` for more (the entitlement-exit-gate workflow runs 20 000),
 * `-Dghost.entitlement.seed=S` to replay one. Seeds alternate between the DELETE and WAL journal
 * modes. The Phase 7 invariants are checked after every reboot, at every commit and at quiescence, the
 * entitlement invariants after every reboot, every capability commit and at the end; a failure names
 * its seed and world.
 */
class EntitlementSeededWorldsTest {

    @Test
    fun seededLivenessWorlds() {
        val single = System.getProperty("ghost.entitlement.seed")?.toLongOrNull()
        val count = System.getProperty("ghost.entitlement.seeds")?.toLongOrNull() ?: DEFAULT_SEEDS
        val part = EntitlementExhaustiveTest.shard
        val seeds = if (single != null) listOf(single) else (1L..count).filter { part == null || (it - 1) % part.second == part.first.toLong() }
        val crashes = AtomicLong()
        val events = AtomicLong()
        val started = System.nanoTime()
        val timings = Harness.parallel(seeds.map { seed ->
            Pair("entitlement seed $seed (replay with -Dghost.entitlement.seed=$seed)") {
                val world = EntitlementSeededWorld(seed)
                val journal = if (seed % 2 == 0L) JournalMode.WAL else JournalMode.DELETE
                try {
                    val r = Runner(world, journal, seed).run(RunSpec(plan = { w -> world.plan(w) }))
                    crashes.addAndGet(r.crashes.toLong())
                    events.addAndGet(r.events)
                    Pair(r.millis, seed)
                } catch (e: Throwable) {
                    throw AssertionError("entitlement seed $seed [$journal] ${world.description}: ${e.message}", e)
                }
            }
        })
        HarnessReport.add(
            "entitlement seeded worlds: ${seeds.size} seeds, ${crashes.get()} crashes, ${events.get()} events, " +
                "time=${(System.nanoTime() - started) / 1_000_000}ms on ${Harness.threads} threads, " +
                "slowest=${timings.sortedByDescending { it.first }.take(5).map { "${it.second}:${it.first}ms" }}",
        )
    }

    private companion object {
        const val DEFAULT_SEEDS = 1_000L
    }
}
