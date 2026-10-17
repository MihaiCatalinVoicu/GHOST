package org.ghost.messaging.media

import java.io.File

/**
 * The media gate's report (Phase 11 design §15.6/§15.9; the F9 PrivacyReport pattern): the file
 * `-Dghost.media.report` names (default `build/reports/media/exit.txt`), shared by the suites of
 * one gate run (the privacy world, the EP-M suite, the mutant close-out). Append-only — the
 * invoking script (`scripts/ci/media-exit-gate.sh`) owns truncation between runs — and the header
 * is written by the first writer of the file.
 */
internal object MediaPrivacyReport {

    private val lock = Any()

    val path: String
        get() = System.getProperty("ghost.media.report") ?: "build/reports/media/exit.txt"

    fun line(text: String) {
        synchronized(lock) {
            val file = File(path).also { it.parentFile?.mkdirs() }
            if (!file.exists() || file.length() == 0L) {
                file.writeText(
                    "GHOST media exit gate (Phase 11 design faza11-media.md §15.3-§15.9; slice S9)\n",
                )
            }
            file.appendText(text.trimEnd() + "\n")
        }
    }
}
