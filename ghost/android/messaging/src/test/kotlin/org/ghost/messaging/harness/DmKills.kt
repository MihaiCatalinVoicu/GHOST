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
 * **Why the end of the JVM.** The kills live in two test classes — `DmMutantDetectionTest` and
 * `DmPoisonTest`, because MC-12's is the native-crash loop — and JUnit gives no ordering across
 * classes. A shutdown hook is the one place that runs after both. It is armed by
 * `DmMutantDetectionTest.theRegistryAndTheKillsAgree`, which is also what asserts the registry is
 * well formed; if *that* test is skipped or removed the lines are absent altogether and the check
 * script fails on the missing count, which is the right answer too.
 */
internal object DmKills {

    /** `mutant id -> the failure message the killing run observed`. */
    private val kills = ConcurrentHashMap<String, String>()

    @Volatile
    private var armed = false

    fun record(id: String, failure: String) {
        kills[id] = failure
    }

    fun recorded(): Map<String, String> = kills.toMap()

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
            if (mutant.id in done) {
                DmReport.line("dm mutant ${mutant.id}: detected by ${mutant.detectedBy}")
            } else {
                DmReport.line("dm mutant ${mutant.id}: NOT DETECTED (no run recorded a kill)")
            }
        }
    }
}
