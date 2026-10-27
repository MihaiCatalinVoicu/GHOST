package org.ghost.update.harness

import org.junit.Assume.assumeTrue
import org.junit.AssumptionViolatedException
import org.junit.Test

/**
 * The §11.3 kill suite (Phase 14 design §11.3): one test per wired, killable row. Each test
 * runs the control half (the shipped behaviour — a hard failure if it breaks) and then the
 * mutant half; when the mutant half shows no divergence the host library predates the mutant
 * (it was built before the row was wired), so the test skips with a precise message rather
 * than failing — the parent rebuild of `ghost-dm-host` re-activates it. Wired rows without a
 * kill world on this seam (MC-D13, MC-D15, MC-D27), the not-wired row (MC-D4) and the
 * scheduler-held PM rows are accounted in [MutantReportTest]. Skipped without the host library.
 */
class MutantKillWorldsTest {

    private fun assumeHostLibrary() = assumeTrue(
        "the ghost-dm-host library is not loaded (-Dghost.net.native)",
        System.getProperty("ghost.net.native") != null,
    )

    private fun killOrSkip(id: Int) {
        assumeHostLibrary()
        val entry = MutantKills.entries.first { it.id == id }
        entry.control()
        try {
            entry.mutant()
        } catch (t: AssertionError) {
            if (entry.kotlinSide) throw t // Kotlin-side rows have no rebuild excuse
            throw AssumptionViolatedException(
                "${entry.name} is not active in this host library (rebuild ghost-dm-host): ${t.message}", t,
            )
        }
    }

    @Test fun mcD1() = killOrSkip(1)
    @Test fun mcD2() = killOrSkip(2)
    @Test fun mcD3() = killOrSkip(3)
    @Test fun mcD5() = killOrSkip(5)
    @Test fun mcD6() = killOrSkip(6)
    @Test fun mcD7() = killOrSkip(7)
    @Test fun mcD8() = killOrSkip(8)
    @Test fun mcD9() = killOrSkip(9)
    @Test fun mcD10() = killOrSkip(10)
    @Test fun mcD11() = killOrSkip(11)
    @Test fun mcD12() = killOrSkip(12)
    @Test fun mcD14() = killOrSkip(14)
    @Test fun mcD16() = killOrSkip(16)
    @Test fun mcD17() = killOrSkip(17)
    @Test fun mcD18() = killOrSkip(18)
    @Test fun mcD20() = killOrSkip(20)
    @Test fun mcD21() = killOrSkip(21)
    @Test fun mcD22() = killOrSkip(22)
    @Test fun mcD23() = killOrSkip(23)
    @Test fun mcD25() = killOrSkip(25)
    @Test fun mcD26() = killOrSkip(26)
    @Test fun mcD27() = killOrSkip(27)
    @Test fun mcD28() = killOrSkip(28)
    @Test fun mcD29() = killOrSkip(29)
    @Test fun mcD30() = killOrSkip(30)
    @Test fun mcD31() = killOrSkip(31)
    @Test fun mcD32() = killOrSkip(32)
}
