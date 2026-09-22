package org.ghost.messaging.dmworld

import java.io.File

/**
 * The privacy report (Phase 9 design §15.6 "**Report.** `scripts/gates/dm-report-check.sh` (the
 * `t2-report-check.sh` pattern) requires every line and refuses a PASS on an empty sample").
 *
 * A file of its own, not S10's `report.txt`: `dm-privacy-gate.yml` runs only these tests and checks
 * only these lines (`dm-report-check.sh <report> privacy-pr|privacy-gate`), and `messaging-exit-gate`
 * keeps checking S10's file, which these tests never write to. Truncated by the first line a JVM
 * writes, like S10's.
 */
internal object PrivacyReport {

    private val lock = Any()

    @Volatile
    private var started = false

    val path: String
        get() = System.getProperty("ghost.dm.privacy.report") ?: "build/reports/dm/privacy.txt"

    fun line(text: String) {
        synchronized(lock) {
            val file = File(path).also { it.parentFile?.mkdirs() }
            if (!started) {
                val scale = PrivacyScale.selected()
                file.writeText(
                    "GHOST DM privacy gate (Phase 9 design §15.6, §15.7; slice S11)\n" +
                        "scale: ${scale.name.lowercase()} (N = ${scale.clients}, ${scale.days} days), " +
                        "seed pairs ${PrivacySeeds.selected().size}, STANDARD\n",
                )
                started = true
            }
            file.appendText(text.trimEnd() + "\n")
        }
    }
}

/**
 * The pinned seeds (§15.6: "10 seed pairs" at the gate, "one seed pair per mode" on a PR). A seed
 * "pair" is a behaviour seed and the seed of the statistics' random guesses; HIGH mode is not built
 * (§22.16), so a pair here is run in STANDARD only. A failure on a correct implementation is
 * investigated, never re-seeded (the T2 rule).
 */
internal object PrivacySeeds {
    val ALL: List<Long> = listOf(
        0x5eed_0001L, 0x5eed_0002L, 0x5eed_0003L, 0x5eed_0004L, 0x5eed_0005L,
        0x5eed_0006L, 0x5eed_0007L, 0x5eed_0008L, 0x5eed_0009L, 0x5eed_000aL,
    )

    /**
     * `-Dghost.dm.privacy.seed=<index>` runs that one pair (a matrix job of `dm-privacy-gate.yml`);
     * `-Dghost.dm.privacy.seeds=all` or a count runs the first ones; one pair otherwise.
     */
    fun selected(): List<Long> {
        System.getProperty("ghost.dm.privacy.seed")?.let { return listOf(ALL[it.toInt()]) }
        return when (val v = System.getProperty("ghost.dm.privacy.seeds")) {
            null -> ALL.take(1)
            "all" -> ALL
            else -> ALL.take(v.toInt().coerceIn(1, ALL.size))
        }
    }
}
