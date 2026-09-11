package org.ghost.sync.harness

import java.io.File

/** Counts of one exhaustive enumeration (design §8.3, §11.3 K/R counts). */
internal class ExhaustiveReport(
    val scenario: String,
    val journal: JournalMode,
    /** Events of the fault-free run. */
    val k: Long,
    /** Crash classes among them (distinct post-crash worlds, verified by digest). */
    val classes: Int,
    /** Single-crash runs (one per event). */
    val singles: Int,
    /** "timeout after apply" runs (one per relay call). */
    val timeouts: Int,
    /** Recovery events per first-crash class: min / max / total. */
    val rMin: Long,
    val rMax: Long,
    val rTotal: Long,
    /** Double-crash runs (k1 class × recovery class). */
    val doubles: Int,
    /** (k1, k2) event pairs those runs cover. */
    val pairsCovered: Long,
    val millis: Long,
) {
    fun line(): String =
        "$scenario ${journal.name}: K=$k classes=$classes singles=$singles timeouts=$timeouts " +
            "R=[$rMin..$rMax] R_total=$rTotal doubles=$doubles pairs=$pairsCovered time=${millis}ms"
}

/**
 * Exhaustive crash-point enumeration (design §8.3):
 *  1. the fault-free run records K events and, for each event, the classification key of the world
 *     a crash there would leave behind;
 *  2. single crashes: a crash is injected at every k in 1..K; each reboot is checked structurally
 *     and must reach the top level; the first crash point of each class runs to quiescence and is
 *     checked fully, the others stop after reboot and must leave a world with the same digest as
 *     their class representative (so the classification is verified, not assumed);
 *  3. every relay call also runs as the non-crash variant "timeout after apply";
 *  4. double crashes (when asked): for every first-crash class, the recovery is classified the same
 *     way and a second crash is injected at the representative of every recovery class; each pair
 *     runs to quiescence and is checked fully.
 */
internal object Exhaustive {

    fun run(name: String, factory: () -> Scenario, journal: JournalMode, doubles: Boolean): ExhaustiveReport {
        val started = System.nanoTime()
        val ff = Runner(factory(), journal).run(RunSpec(classify = true))
        check(ff.crashes == 0) { "fault-free run crashed" }
        val k = ff.events
        check(ff.keys.size.toLong() == k && k > 0) { "no events recorded" }
        val firstOf = HashMap<CrashKey, Long>()
        ff.keys.forEachIndexed { i, key -> firstOf.putIfAbsent(key, i + 1L) }

        // 2. Single crashes at every event.
        val singles = Harness.parallel((1..k).map { index ->
            val key = ff.keys[(index - 1).toInt()]
            val representative = firstOf.getValue(key) == index
            Pair("$name ${journal.name} crash at k=$index") {
                val r = Runner(factory(), journal).run(RunSpec(crashAt = index, stopAfterFirstReboot = !representative))
                check(r.crashes == 1) { "the crash at k=$index was not injected (${r.crashes})" }
                Triple(index, key, r.firstRebootDigest ?: error("no digest"))
            }
        })
        val digestOf = HashMap<CrashKey, String>()
        for ((index, key, digest) in singles.sortedBy { it.first }) {
            val known = digestOf.putIfAbsent(key, digest)
            if (known != null && known != digest) {
                throw AssertionError("$name ${journal.name}: crash at k=$index leaves another world than its class representative ${firstOf[key]}")
            }
        }

        // 3. Timeout after apply at every relay call.
        val applies = ff.kinds.withIndex().filter { it.value == EventKind.RELAY_AFTER_APPLY }.map { it.index + 1L }
        Harness.parallel(applies.map { e ->
            Pair("$name ${journal.name} timeout after apply at event $e") {
                Runner(factory(), journal).run(RunSpec(networkFaultAt = e, networkCategory = "timeout"))
            }
        })

        // 4. Double crashes.
        var rMin = 0L
        var rMax = 0L
        var rTotal = 0L
        var doubleRuns = 0
        var pairs = 0L
        if (doubles) {
            val reps = firstOf.values.sorted()
            val recoveries = Harness.parallel(reps.map { k1 ->
                Pair("$name ${journal.name} classify recovery after k1=$k1") {
                    val r = Runner(factory(), journal).run(RunSpec(crashAt = k1, classify = true))
                    check(r.crashes == 1) { "first crash not injected" }
                    Pair(k1, r.recoveryKeys)
                }
            })
            rMin = recoveries.minOf { it.second.size.toLong() }
            rMax = recoveries.maxOf { it.second.size.toLong() }
            rTotal = recoveries.sumOf { it.second.size.toLong() }
            pairs = recoveries.sumOf { (k1, rk) -> k1.let { ff.keys.count { key -> firstOf[key] == k1 }.toLong() } * rk.size }
            val tasks = recoveries.flatMap { (k1, rk) ->
                val firstRecovery = LinkedHashMap<CrashKey, Long>()
                rk.forEachIndexed { i, key -> firstRecovery.putIfAbsent(key, i + 1L) }
                firstRecovery.values.map { k2 ->
                    Pair("$name ${journal.name} double crash k1=$k1 k2=$k2") {
                        val r = Runner(factory(), journal).run(RunSpec(crashAt = k1, secondCrashAt = k2))
                        check(r.crashes == 2) { "second crash not injected (${r.crashes})" }
                        Unit
                    }
                }
            }
            doubleRuns = tasks.size
            Harness.parallel(tasks)
        }
        val report = ExhaustiveReport(
            name, journal, k, firstOf.size, singles.size, applies.size, rMin, rMax, rTotal, doubleRuns, pairs,
            (System.nanoTime() - started) / 1_000_000,
        )
        HarnessReport.add(report.line())
        return report
    }
}

/** Collects K/R counts and timings; written to `build/harness/report.txt` for the CI job summary. */
internal object HarnessReport {
    private val lines = ArrayList<String>()

    @Synchronized
    fun add(line: String) {
        lines += line
        val dir = File("build/harness")
        dir.mkdirs()
        File(dir, "report.txt").appendText(line + "\n")
    }

    @Synchronized
    fun all(): List<String> = lines.toList()
}
