package org.ghost.messaging.harness

import java.io.File

/**
 * The exit-gate report (Phase 9 design §15.3 "The job summary prints `dm crash classes: <n>
 * singles, <m> doubles` per scenario (report-checked)", §15.6 "**Report.**
 * `scripts/gates/dm-report-check.sh` (the `t2-report-check.sh` pattern) requires every line and
 * refuses a PASS on an empty sample").
 *
 * Tests append lines as they finish; the file is the one `dm-report-check.sh` reads. Lines are
 * written under a lock and the file is truncated by whichever test writes to it first in a JVM, so
 * a re-run does not accumulate two runs' lines.
 *
 * **That truncation is per JVM, which is correct only because there is one.** `:messaging` sets no
 * `maxParallelForks`, so every harness test runs in one test JVM and one of them truncates. A
 * future fork setting would give each fork its own `started` flag, each would truncate the shared
 * file, and the gate would check whichever fork wrote last — a report that looks complete because
 * the lines it is missing were overwritten rather than never produced. Whoever sets
 * `maxParallelForks` on this module owes this object a per-fork file name and the check script a
 * concatenation step; there is no way for the harness to notice on its own.
 *
 * **Why the check script matters as much as the report.** A report is evidence only if something
 * refuses an incomplete one. `t2-report-check.sh` is the pattern: a required line per check, and a
 * PASS on an empty sample is a failure rather than a pass.
 */
internal object DmReport {

    private val lock = Any()

    @Volatile
    private var started = false

    private val file: File
        get() = File(DmHarness.reportPath).also { it.parentFile?.mkdirs() }

    fun line(text: String) {
        synchronized(lock) {
            val target = file
            if (!started) {
                target.writeText(header())
                started = true
            }
            target.appendText(text.trimEnd() + "\n")
        }
    }

    /** One scenario's line, formatted by [DmScenarioReport] itself and nowhere else. */
    fun scenario(report: DmScenarioReport) = line(report.toString())

    /**
     * The header, whose scale is derived from the **enumeration density** and not from the switch.
     *
     * `DmHarness.full` is only one of the two things that decide the density: `-Dghost.dm.sample`
     * overrides it, and `messaging/build.gradle.kts` forwards both to the test JVM. So
     * `-Dghost.dm.crash=full -Dghost.dm.sample=13` used to write "gate (every event)" over a 1-in-13
     * enumeration and `dm-report-check.sh` accepted it — the report claiming a scale it did not run,
     * which is the one thing this gate exists to prevent. The label now comes from `sample == 1`,
     * which *is* "every event", and the gate half of the check script additionally requires the
     * singles of every line to equal its events.
     */
    private fun header(): String = buildString {
        append("GHOST DM exit gate (Phase 9 design §15.3, §15.4, §15.7; slices S10, S10b, S10c and SCN-E)\n")
        append("scale: ")
        append(
            if (DmHarness.sample == 1) {
                "gate (every event)"
            } else {
                "pr (every ${DmHarness.sample}th event)"
            },
        )
        append(", seeds ${DmHarness.seeds}\n")
        // The scale line is the `dm crash classes:` lines' density. SCN-E's lines are sampled at
        // every scale (§22.25 item 8), and the header says so, so "every event" is never read as
        // covering them (the review, §22.25 item 14).
        append("coverage: the scale is the density of the dm crash classes lines; the dm crash sample lines (SCN-E) are sampled, not every event\n")
    }
}
