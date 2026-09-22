package org.ghost.messaging.harness

import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The functional-suite sub-cases of Phase 9 design §15.5 this slice implements, run fault-free and
 * then under the crash enumeration.
 *
 * Running them under the enumeration is the point of writing them as [DmScenario]s: RP6's D3, the
 * §12.3 replay's D2b and EP's read guard are all properties of *transactions*, and a case that only
 * ever runs without faults proves the property for the one interleaving it happened to take.
 */
class DmSuiteTest {

    private fun requireNative() = assumeTrue(DmHarness.SKIP_MESSAGE, DmHarness.nativeAvailable())

    @Test
    fun suiteCasesPassFaultFree() {
        requireNative()
        for (scenario in DmSuiteCases.all()) {
            DmCrashRunner(scenario).run(DmRunSpec())
        }
        DmReport.line("dm suite cases: ${DmSuiteCases.all().size} run, 0 failures")
    }

    @Test
    fun suiteCasesSurviveTheCrashEnumeration() {
        requireNative()
        for (scenario in DmSuiteCases.all()) {
            val report = DmCrashRunner(scenario).enumerate(DmHarness.sample)
            check(report.singles > 0) { "${scenario.name}: an enumeration with no crash point" }
            DmReport.scenario(report)
        }
    }
}
