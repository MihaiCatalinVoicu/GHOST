package org.ghost.sync.harness

import org.junit.Test

/**
 * Regression scenarios for the S9 review findings, fault-free in both journal modes (S-L also runs
 * in the exhaustive enumeration, `ExhaustiveScenarioTest`):
 *  - S-L: listening turned on after ops were enqueued in a write-only namespace (#1, #4);
 *  - S-K: READY, a transport fault, a forward clock step with the hourly GC due (#2).
 */
class RegressionScenarioTest {

    @Test
    fun sL_listenLater() {
        for (mode in JournalMode.entries) Runner(ScenarioListenLater(), mode).run(RunSpec())
    }

    @Test
    fun sK_clockStepOffline() {
        for (mode in JournalMode.entries) Runner(ScenarioClockStepOffline(), mode).run(RunSpec())
    }
}
