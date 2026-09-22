package org.ghost.messaging.harness

import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The seeded worlds of Phase 9 design §15.4 (G-13).
 *
 * > plain JUnit loops with `SplittableRandom`; a failure message carries its seed and the recorded
 * > transcript
 *
 * Two loops, because they prove different things. The **fault-free** loop is the wide one: every
 * seed draws a different topology, message mix, timer mix, offline window, clock step and hostile
 * relay, and the world has to settle with every structural invariant intact. The **faulted** loop
 * draws a crash point and a `SQLITE_FULL` point from the same seed, so a red seed names one run
 * and not a family of them.
 *
 * **Scale.** [DmHarness.seeds] per run: the default is small enough for a PR and
 * `-Dghost.dm.crash=full` raises it for `messaging-exit-gate.yml`. §15.4's own numbers (1 000 per
 * PR, 20 000 in the gate) are for a world that costs what a `:sync` world costs; a DM world opens
 * DM contexts and runs the real ratchet, so the gate number this slice can actually run is in the
 * report rather than asserted from the design, and §22.15 records the gap.
 */
class DmSeededWorldTest {

    private fun requireNative() = assumeTrue(DmHarness.SKIP_MESSAGE, DmHarness.nativeAvailable())

    @Test
    fun seededWorldsSettleWithEveryInvariantIntact() {
        requireNative()
        val seeds = DmHarness.seeds
        val tasks = (1..seeds).map { seed ->
            val world = DmSeededWorld(seed.toLong())
            "seed $seed" to {
                try {
                    DmCrashRunner(world.scenario()).run(DmRunSpec())
                } catch (e: Throwable) {
                    throw AssertionError("${world.description}: ${e.message}", e)
                }
            }
        }
        DmHarness.parallel(tasks)
        DmReport.line("dm seeded worlds: $seeds seeds, 0 failures")
    }

    @Test
    fun seededWorldsSurviveTheirOwnCrashPoint() {
        requireNative()
        val seeds = DmHarness.seeds
        var faulted = 0
        val tasks = (1..seeds).map { seed ->
            val world = DmSeededWorld(seed.toLong())
            val scenario = world.scenario()
            val plan = world.faultPlan()
            "seed $seed faulted" to {
                try {
                    DmCrashRunner(scenario).run(DmRunSpec(plan = { plan }))
                } catch (e: Throwable) {
                    throw AssertionError("${world.description}: ${e.message}", e)
                }
            }
        }
        val results = DmHarness.parallel(tasks)
        for (result in results) if (result.crashes > 0 || result.storageFulls > 0) faulted++
        // A loop in which nothing was ever injected proves nothing about crashes, and §15.6's
        // report rule — "refuses a PASS on an empty sample" — is the same rule here.
        check(faulted > 0) { "no seeded world drew a fault: the loop tested nothing" }
        DmReport.line("dm seeded worlds (faulted): $seeds seeds, $faulted drew a fault, 0 failures")
    }
}
