package org.ghost.messaging.harness

import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The crash enumeration of Phase 9 design §15.3, over the scenarios slices S10, S10b and S10c
 * implement.
 *
 * Each test records its scenario's K events, then crashes at every sampled one, reboots, checks
 * the structural invariants at the reboot, runs to quiescence and checks everything again — plus,
 * at every store (the relay's after-apply event, the one at which the fault exists), the "timeout
 * after apply" run §15.3 asks for, and, for the scenarios that ask for it (SCN-A, B, F, I and J), a
 * double crash whose second lands during recovery.
 *
 * **Scale.** `-Dghost.dm.crash=full` runs every event (the `messaging-exit-gate.yml` job); the
 * default samples every [DmHarness.DEFAULT_SAMPLE]-th, which was ~900 runs over S10's seven
 * scenarios, ~4 200 over the eleven scenario lines of S10b and is ~4 800 over the twelve since
 * S10c (SCN-H alone is 1 340 singles, SCN-C 583, SCN-I 517 singles and 517 doubles) — about ten
 * minutes of the whole `:messaging` suite on the owner's workstation (§22.23 item 10). Sampling
 * is on the event index alone, so a sampled run is a subset of the full one — never a different
 * enumeration. Runs are independent and go through [DmHarness.parallel].
 *
 * Every run writes its line into [DmReport], which `scripts/gates/dm-report-check.sh` then refuses
 * to pass on a missing scenario or an empty enumeration.
 */
class DmCrashEnumerationTest {

    private fun requireNative() = assumeTrue(DmHarness.SKIP_MESSAGE, DmHarness.nativeAvailable())

    private fun enumerate(scenario: DmScenario) {
        requireNative()
        val report = DmCrashRunner(scenario).enumerate(DmHarness.sample)
        check(report.singles > 0) { "${scenario.name}: an enumeration with no crash point" }
        DmReport.scenario(report)
    }

    @Test fun scnASend() = enumerate(DmScenarios.scnA())

    @Test fun scnBReceive() = enumerate(DmScenarios.scnB())

    /**
     * S10c: the establishment through a relay that withholds the newest bundle — three empty
     * windows and `unreachable`, then a fetch of the older bundle, intro, request, provisional
     * reply and pair mode on both sides, with a second fetcher of the same bundle.
     */
    @Test fun scnCEstablishment() = enumerate(DmScenarios.scnC())

    @Test fun scnDKeyChange() = enumerate(DmScenarios.scnD())

    @Test fun scnFEphemeral() = enumerate(DmScenarios.scnF())

    @Test fun scnGOutcomes() = enumerate(DmScenarios.scnG())

    /** S10b: SCN-G's week-boundary FAILED retry (§22.8.5), as a scenario of its own. */
    @Test fun scnGWeekBoundaryRetry() = enumerate(DmScenarios.scnGWeek())

    /**
     * S10b: sixteen weeks of world time with a publication at every step (not every week) and a
     * late first flight — SCN-H in part; §22.19 says what is not here.
     */
    @Test fun scnHBundleGenerations() = enumerate(DmScenarios.scnH())

    /** S10b: the restore, with the double crashes §15.3 names for it. */
    @Test fun scnIRestore() = enumerate(DmScenarios.scnI())

    @Test fun scnJFaults() = enumerate(DmScenarios.scnJ())

    /** S10b: the revocation notice, driven to delivery and applied. */
    @Test fun scnKRevocation() = enumerate(DmScenarios.scnK())

    @Test fun scnLMigration() = enumerate(DmScenarios.scnL())

    /**
     * SCN-J's other half: `SQLITE_FULL` at every statement of SEND, RECV, BUNDLE and SWEEP.
     *
     * A full disk is a typed failure and not a death, so what this proves is different from a
     * crash run: the transaction rolls back, the pass reports it, the next pass does the work, and
     * the structural invariants hold at every one of those points. §15.3's "single and double SQL
     * crashes never reach the threshold" is the crash half above; this is the `SQLITE_FULL` half.
     */
    @Test
    fun scnJStorageFullAtEveryStatement() {
        requireNative()
        val injected = DmCrashRunner(DmScenarios.scnJ()).enumerateStorageFull(DmHarness.sample)
        check(injected > 0) { "SCN-J: no statement took a SQLITE_FULL injection" }
        DmReport.line("dm storage-full: SCN-J $injected statements injected")
    }
}
