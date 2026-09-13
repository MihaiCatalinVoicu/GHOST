package org.ghost.entitlement.harness

import org.ghost.sync.harness.Exhaustive
import org.ghost.sync.harness.Harness
import org.ghost.sync.harness.HarnessReport
import org.ghost.sync.harness.JournalMode
import org.junit.AfterClass
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The client crash enumeration of the entitlement exit gate (Phase 8 design §13.2): E-A … E-I, each
 * in journal modes DELETE and WAL, with a crash at every event of the armed client (every SQL
 * statement, pre-commit and post-commit point, transport ensure, and the three events of every
 * redeem and issuer call: fail before, succeed but lose the response, succeed), a "timeout after
 * apply" at every call, and double crashes (a crash during recovery) for E-A, E-D and E-F. Every
 * reboot is checked (Phase 7 structural invariants, R10, RED-2, MS-1), every commit that changed a
 * capability (capability installed ⇔ token deleted), and every run's end after a fault-free tail to
 * quiescence (the Phase 7 invariants with the real redeem lane, MS-6 and the token accounting, the
 * T3 canaries).
 *
 * Budget (measured in S9, see the entitlement-exit-gate workflow): single crashes always run in both
 * modes. The default build runs the double crashes of every [DEFAULT_STRIDE]-th first-crash class in
 * WAL mode; `-Dghost.entitlement.exhaustive=full` runs every double crash in both modes.
 * `-Dghost.entitlement.shard=i/n` runs part i of n, so the exit gate spreads the enumeration over a job
 * matrix: the single crashes of every crash class whose number is i modulo n (a class stays whole, so
 * its digests are compared), every n-th "timeout after apply" run and every n-th first-crash class's
 * double crashes (both from i); `EntitlementSeededWorldsTest` runs the seeds s with (s − 1) mod n = i.
 */
class EntitlementExhaustiveTest {

    private fun both(name: String, doubles: Boolean, factory: () -> EntScenario) {
        for (mode in JournalMode.entries) {
            val runDoubles = doubles && (mode == JournalMode.WAL || Harness.fullExhaustive)
            val stride = if (Harness.fullExhaustive) 1 else DEFAULT_STRIDE
            val r = Exhaustive.run(name, factory, mode, runDoubles, stride, shard)
            assertTrue("$name: no events", r.k > 0)
            if (shard == null) assertEquals(r.k.toInt(), r.singles)
        }
    }

    @Test
    fun eA_packPaidInXmr() = both("E-A", doubles = true) { ScenarioEA() }

    @Test
    fun eB_underpayTopUpConfirm() = both("E-B", doubles = false) { ScenarioEB() }

    @Test
    fun eC_expired() = both("E-C/expired", doubles = false) { ScenarioECExpired() }

    @Test
    fun eC_lost() = both("E-C/lost", doubles = false) { ScenarioECLost() }

    @Test
    fun eD_packPaidWithCredits() = both("E-D", doubles = true) { ScenarioED() }

    @Test
    fun eE_trial() = both("E-E/trial", doubles = false) { ScenarioETrial() }

    @Test
    fun eE_wipe() = both("E-E/wipe", doubles = false) { ScenarioEWipe() }

    @Test
    fun eF_redeemAcrossTheWeekBoundary() = both("E-F", doubles = true) { ScenarioEF() }

    @Test
    fun eG_dropSendAndReceive() = both("E-G", doubles = false) { ScenarioEG() }

    @Test
    fun eH_claim() = both("E-H", doubles = false) { ScenarioEH() }

    @Test
    fun eI_wrongPeriodRePrepare() = both("E-I", doubles = false) { ScenarioEI() }

    companion object {
        private val started = System.nanoTime()

        /** Default build: the double crashes of every 8th first-crash class (the exit gate runs all). */
        const val DEFAULT_STRIDE = 8
        /** `ghost.entitlement.shard=i/n`: this job's part of the exit-gate matrix, or null for everything. */
        val shard: Pair<Int, Int>? = System.getProperty("ghost.entitlement.shard")?.takeIf { it.isNotBlank() }?.let { s ->
            val parts = s.split('/').map { it.trim().toInt() }
            require(parts.size == 2 && parts[1] >= 1 && parts[0] in 0 until parts[1]) { "ghost.entitlement.shard must be i/n with 0 <= i < n" }
            parts[0] to parts[1]
        }

        @JvmStatic
        @AfterClass
        fun everyInjectedCrashReachedTheTopLevel() {
            assertEquals("injected crashes that did not reach the top level", Harness.injectedCrashes.get(), Harness.caughtCrashes.get())
            HarnessReport.add("entitlement crashes injected=${Harness.injectedCrashes.get()} caught=${Harness.caughtCrashes.get()}")
            HarnessReport.add(
                "entitlement exhaustive enumeration: ${(System.nanoTime() - started) / 1_000_000_000} s on ${Harness.threads} threads " +
                    "(mode=${if (Harness.fullExhaustive) "full" else "default, stride $DEFAULT_STRIDE"}${shard?.let { ", shard ${it.first}/${it.second}" } ?: ""})",
            )
        }
    }
}
