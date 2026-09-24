package org.ghost.messaging.dmworld

import org.ghost.messaging.DmWorld
import org.ghost.messaging.entworld.Jd8
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * JD8 (Phase 9 design §15.6, §14.1 T27) over the twin worlds of the entitlement world (`entworld/
 * EntDmJd8.kt`): a client's redemptions and registrations, as relays saw them, are the same — in
 * count, relay, namespace and week — with 0 and with 4 contacts and 95 texts, and every one is on a
 * namespace the client owns; T27's minute is measured and reported, not compared (`Jd8`'s note,
 * §22.24), and the pairs this run moved are printed. The line goes to the privacy report, which
 * `dm-report-check.sh privacy-suite` and `privacy-pr` require.
 *
 * Scale-independent, like the twins of `DmPrivacyWorldTest`: one twin pair of the first pinned seed.
 * The control computed here is the one `DmPrivacyMutantTest` holds the JD8 mutants against (one run
 * per JVM).
 */
class DmJd8Test {

    @Test
    fun jd8RedemptionsAndRegistrationsDependOnlyOnOwnNamespacesAndTheWeek() {
        assumeTrue(SKIP, DmWorld.nativeAvailable())
        assumeTrue("-Dghost.dm.privacy=off: the privacy worlds are skipped", PrivacyScale.enabled)
        val result = Jd8.run(PrivacySeeds.ALL[0], CONTROL, null)
        PrivacyReport.line(result.line())
        println("JD8 twins: idle ${result.idle.millis} ms, active ${result.active.millis} ms")
        for (d in Jd8.timingDetail(result)) println("JD8 timing: $d")
        assertTrue(result.line(), result.passed)
    }

    internal companion object {
        const val CONTROL = "control"
        const val SKIP = "set -Dghost.dm.native to the ghost-dm-host library: every privacy world runs the real stack"
    }
}
