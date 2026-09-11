package org.ghost.sync.harness

import org.junit.Test
import java.util.concurrent.atomic.AtomicLong

/**
 * Seeded random worlds (design §8.5): 1 000 seeds by default, `-Dghost.sync.seeds=N` for more (the
 * sync-exit-gate job runs 20 000), `-Dghost.sync.seed=S` to replay one. Seeds alternate between the
 * DELETE and WAL journal modes. Every invariant of §8.4 is checked after every reboot, at every
 * commit (outcome truth) and at quiescence; a failure names its seed and world.
 */
class SeededWorldsTest {

    @Test
    fun seededWorlds() {
        val single = System.getProperty("ghost.sync.seed")?.toLongOrNull()
        val seeds = if (single != null) listOf(single) else (1L..Harness.seeds.toLong()).toList()
        val crashes = AtomicLong()
        val events = AtomicLong()
        val started = System.nanoTime()
        val timings = Harness.parallel(seeds.map { seed ->
            Pair("seed $seed (replay with -Dghost.sync.seed=$seed)") {
                val world = SeededWorld(seed)
                val journal = if (seed % 2 == 0L) JournalMode.WAL else JournalMode.DELETE
                try {
                    val r = Runner(world, journal, seed).run(RunSpec(plan = { w -> world.plan(w) }))
                    crashes.addAndGet(r.crashes.toLong())
                    events.addAndGet(r.events)
                    Pair(r.millis, seed)
                } catch (e: Throwable) {
                    throw AssertionError("seed $seed [$journal] ${world.description}: ${e.message}", e)
                }
            }
        })
        HarnessReport.add(
            "seeded worlds: ${seeds.size} seeds, ${crashes.get()} crashes, ${events.get()} events, " +
                "time=${(System.nanoTime() - started) / 1_000_000}ms, slowest=${timings.sortedByDescending { it.first }.take(5).map { "${it.second}:${it.first}ms" }}",
        )
    }
}
