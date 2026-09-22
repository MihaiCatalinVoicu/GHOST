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

    fun scenario(report: DmScenarioReport) {
        line(
            "dm crash classes: ${report.scenario} ${report.events} events, " +
                "${report.singles} singles, ${report.doubles} doubles, ${report.timeouts} timeouts",
        )
    }

    private fun header(): String = buildString {
        append("GHOST DM exit gate (Phase 9 design §15.3, §15.4, §15.7; slice S10)\n")
        append("scale: ")
        append(if (DmHarness.full) "gate (every event)" else "pr (every ${DmHarness.sample}th event)")
        append(", seeds ${DmHarness.seeds}\n")
    }
}
