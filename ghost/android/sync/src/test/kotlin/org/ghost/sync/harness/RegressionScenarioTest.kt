package org.ghost.sync.harness

import org.junit.Test

/**
 * Regression scenarios for the S9 review findings, fault-free in both journal modes (S-L also runs
 * in the exhaustive enumeration, `ExhaustiveScenarioTest`):
 *  - S-L: listening turned on after ops were enqueued in a write-only namespace (#1, #4);
 *  - S-K: READY, a transport fault, a forward clock step with the hourly GC due (#2).
 *
 * And one pinned seeded world, so the 20 000-seed job is not the only place that covers it.
 */
class RegressionScenarioTest {

    /**
     * Seed 8015 of the seeded worlds (design §8.5), the world the `sync-exit-gate` job found once
     * [org.ghost.sync.api.TtlBucket.HOUR_1] joined `TtlBucket.entries` and the seeded TTL draw began
     * producing ops with a TTL of at most σ. Its op14 (1 h, no deadline) is acknowledged by R0, whose
     * membership expires before either check sees it, so two strikes fail that delivery and D2 decides
     * DEGRADED beside R1's verified copy — the liveness design §10.4 (G-10) declares for these buckets.
     * The world must reach quiescence; before [SeededWorld.allowed] knew the case its tail ran to the
     * 9 216-round cap. Replayed exactly as `SeededWorldsTest` runs it (odd seed → DELETE).
     */
    @Test
    fun seed8015_shortTtlDegraded() {
        val world = SeededWorld(8015)
        Runner(world, JournalMode.DELETE, 8015).run(RunSpec(plan = { w -> world.plan(w) }))
    }

    @Test
    fun sL_listenLater() {
        for (mode in JournalMode.entries) Runner(ScenarioListenLater(), mode).run(RunSpec())
    }

    @Test
    fun sK_clockStepOffline() {
        for (mode in JournalMode.entries) Runner(ScenarioClockStepOffline(), mode).run(RunSpec())
    }
}
