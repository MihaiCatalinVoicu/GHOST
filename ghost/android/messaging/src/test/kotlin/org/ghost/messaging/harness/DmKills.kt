package org.ghost.messaging.harness

import java.util.concurrent.ConcurrentHashMap

/**
 * The kills a run actually performed, and the only source of the `dm mutants:` lines in the report
 * (Phase 9 design §15.7, §15.6 "Report").
 *
 * **Why this object exists.** The first version of the gate wrote `dm mutants: 6 run, 6 detected`
 * from a test that ran no mutant: it asserted that every registered `Mutation` had a mechanism and
 * two non-blank strings, and then printed the count of the registry. `@Ignore` on a kill test — or
 * deleting one — left the report byte-identical and `dm-report-check.sh` green, which is precisely
 * the failure a report-checked gate exists to prevent, and precisely what [DmMutants]'s own opening
 * paragraph calls "a number a run did not measure". The entitlement gate does not have that shape;
 * it counts the ` DETECTED: ` lines the detection runs themselves emit. This does the same.
 *
 * So a kill is *recorded here by the run that performed it*, with the failure message it observed,
 * and the report lines are written from the recorded set at the end of the JVM. A mutant nothing
 * killed has no line and is not counted, whatever the registry says.
 *
 * **Why the end of the JVM.** The kills live in three test classes — `DmMutantDetectionTest`,
 * `DmPoisonTest`, because MC-12's is the native-crash loop, and `entworld.ScnETest`, because MC-14's
 * and MC-15's run on SCN-E's entitlement world (§22.25) — and JUnit gives no ordering across
 * classes. A shutdown hook is the one place that runs after both. It is armed by
 * `DmMutantDetectionTest.theRegistryAndTheKillsAgree`, which is also what asserts the registry is
 * well formed; if *that* test is skipped or removed the lines are absent altogether and the check
 * script fails on the missing count, which is the right answer too.
 */
internal object DmKills {

    /** One recorded kill: what the killing run said, and the rule the kill was held to. */
    class Kill(val failure: String, val rule: String)

    /** `mutant id -> the kill`. */
    private val kills = ConcurrentHashMap<String, Kill>()

    @Volatile
    private var armed = false

    /** The rule of every S10 kill but MC-1's: the mutated run fails, the clean control passes. */
    const val FAULT_FREE: String = "fault-free, beside a clean control"

    /**
     * Records a kill with [rule], which the report prints (S10b review).
     *
     * Until then the line was the registry's `detectedBy` and nothing else, so moving one of S10b's
     * four kills back from "fault-free and at every crash point tried" to the fault-free-only rule
     * left the report — and `dm-report-check.sh` — byte-identical. The rule is written by the test
     * that applied it, from the numbers it measured.
     */
    fun record(id: String, failure: String, rule: String) {
        kills[id] = Kill(failure, rule)
    }

    fun recorded(): Map<String, Kill> = kills.toMap()

    /** Registers the hook that writes the report lines once every test class has finished. */
    @Synchronized
    fun arm() {
        if (armed) return
        armed = true
        Runtime.getRuntime().addShutdownHook(Thread { write() })
    }

    /**
     * The lines, from the kills and not from the registry.
     *
     * The count's denominator is the registry — "how many mutants this slice claims" — and its
     * numerator is what ran, so the two disagreeing is visible in the report itself rather than
     * only in a failed test.
     */
    private fun write() {
        val registered = DmMutants.all()
        val done = recorded()
        DmReport.line("dm mutants: ${registered.size} run, ${done.size} detected")
        for (mutant in registered) {
            val kill = done[mutant.id]
            if (kill != null) {
                DmReport.line("dm mutant ${mutant.id}: detected by ${mutant.detectedBy}; kill rule: ${kill.rule}")
            } else {
                DmReport.line("dm mutant ${mutant.id}: NOT DETECTED (no run recorded a kill)")
            }
        }
    }
}
