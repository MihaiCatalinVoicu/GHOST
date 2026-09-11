package org.ghost.sync.harness

import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.TtlBucket
import org.junit.AfterClass
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The exit-gate enumeration (design §8.3, §11.3): scenarios S-A to S-H, each in journal modes
 * DELETE and WAL, with a crash at every event (single crashes), a "timeout after apply" at every
 * relay call, and double crashes for S-A, S-D and S-F. The K/R counts and timings go to
 * `build/harness/report.txt` (the sync-exit-gate job publishes them).
 */
class ExhaustiveScenarioTest {

    private fun both(name: String, doubles: Boolean, modes: List<JournalMode> = JournalMode.entries, factory: () -> Scenario) {
        for (mode in modes) {
            val r = Exhaustive.run(name, factory, mode, doubles && (mode == JournalMode.WAL || Harness.fullExhaustive))
            assertTrue("$name: no events", r.k > 0)
            assertEquals(r.k.toInt(), r.singles)
        }
    }

    @Test
    fun sA_outbox() = both("S-A", doubles = true) { ScenarioA() }

    @Test
    fun sB_inboxStandard() = both("S-B/STANDARD", doubles = false) { ScenarioB(PrivacyMode.STANDARD) }

    @Test
    fun sB_inboxHigh() = both("S-B/HIGH", doubles = false) { ScenarioB(PrivacyMode.HIGH) }

    @Test
    fun sC_mixed() = both("S-C", doubles = false) { ScenarioC() }

    @Test
    fun sD_capability() = both("S-D", doubles = true) { ScenarioD() }

    @Test
    fun sE_topology() = both("S-E", doubles = false) { ScenarioE() }

    @Test
    fun sF_window() {
        for (applied in listOf(true, false)) {
            for (days in listOf(3, 8, 40)) {
                for (ttl in listOf(TtlBucket.DAYS_7, TtlBucket.DAYS_30)) {
                    // Double crashes on the two variants where resolution decides the outcome.
                    val doubles = (applied && days == 8 && ttl == TtlBucket.DAYS_30) || (!applied && days == 8 && ttl == TtlBucket.DAYS_30)
                    // CI time budget (design §11.3): the default build enumerates the 3-day variants in
                    // WAL only (the same code paths as the 8-day ones, where resolution decides);
                    // the sync-exit-gate job runs every variant in both journal modes.
                    val modes = if (days == 3 && !Harness.fullExhaustive) listOf(JournalMode.WAL) else JournalMode.entries
                    both("S-F/${if (applied) "applied" else "lost"}/${days}d/${ttl.days}d", doubles, modes) { ScenarioF(applied, days, ttl) }
                }
            }
        }
    }

    @Test
    fun sG_verification() = both("S-G", doubles = false) { ScenarioG() }

    @Test
    fun sH_backlog() = both("S-H", doubles = false) { ScenarioH() }

    companion object {
        private val started = System.nanoTime()

        @JvmStatic
        @AfterClass
        fun everyInjectedCrashReachedTheTopLevel() {
            assertEquals("injected crashes that did not reach the top level", Harness.injectedCrashes.get(), Harness.caughtCrashes.get())
            HarnessReport.add("crashes injected=${Harness.injectedCrashes.get()} caught at the top level=${Harness.caughtCrashes.get()}")
            HarnessReport.add(
                "exhaustive enumeration: ${(System.nanoTime() - started) / 1_000_000_000} s on ${Harness.threads} threads " +
                    "(mode=${if (Harness.fullExhaustive) "full" else "default"}; budget: default :sync tests under ~10 min on CI)",
            )
        }
    }
}
