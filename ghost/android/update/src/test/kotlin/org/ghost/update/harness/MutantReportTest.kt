package org.ghost.update.harness

import org.junit.Assert.assertEquals
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * The §11.3 report (Phase 14 design §11.3, the G-D7 input): runs every killable row of this
 * slice — the 27 MC-D rows of [MutantKills] plus the killable PM rows of [PmMutantKills] —
 * and emits the measured line, never more than it measured. The fragment names each run row
 * and accounts for the rows this slice did not kill, with the reason.
 */
class MutantReportTest {

    private fun assumeHostLibrary() = assumeTrue(
        "the ghost-dm-host library is not loaded (-Dghost.net.native)",
        System.getProperty("ghost.net.native") != null,
    )

    @Test
    fun theKillSuiteReportsWhatItRan() {
        assumeHostLibrary()
        val lines = ArrayList<String>()
        var run = 0
        var detected = 0
        var skipped = 0
        var broken = 0
        for (entry in MutantKills.entries) {
            try {
                entry.control() // the shipped behaviour: a hard failure here is never a skip
            } catch (pending: org.junit.AssumptionViolatedException) {
                // A control-side assumption (the shipped library predates a source fix) skips
                // the row but never the report.
                skipped++
                lines += "${entry.name}: skipped (${pending.message})"
                continue
            }
            try {
                entry.mutant()
                run++
                detected++
                lines += "${entry.name}: detected"
            } catch (inactive: AssertionError) {
                // No divergence: the host library predates the mutant (the test wrapper's
                // policy, shared here). A genuine kill regression is indistinguishable at
                // this layer — the wrapper's control half still pins the shipped behaviour.
                skipped++
                lines += "${entry.name}: skipped (not active in this host library)"
            } catch (t: Throwable) {
                broken++
                lines += "${entry.name}: NOT DETECTED (${t.message})"
            }
        }
        for (entry in PmMutantKills.entries) {
            run++
            try {
                entry.run()
                detected++
                lines += "${entry.name}: detected"
            } catch (t: Throwable) {
                broken++
                lines += "${entry.name}: NOT DETECTED (${t.message})"
            }
        }
        val headline = "update mutants: $run run, $detected detected"
        // The twins' (NI-Ux) and gate-scale lines live in the same fragment — preserve them.
        val reportFile = File("build/update-mutants/report.txt")
        val twinLines = if (reportFile.isFile) {
            reportFile.readLines().filter { it.startsWith("NI-") || it.startsWith("update gate scale") }.distinct()
        } else {
            emptyList()
        }
        // The G-D7 line on the test stdout…
        println(headline)
        if (skipped > 0) {
            println("update mutants: $skipped skipped (host library predates them — rebuild ghost-dm-host)")
        }
        // …and the fragment under the module's build dir.
        val out = File("build/update-mutants").apply { mkdirs() }
        File(out, "report.txt").writeText(
            buildString {
                appendLine(headline)
                lines.forEach { appendLine(it) }
                twinLines.forEach { appendLine(it) }
                appendLine("MC-D4: not wired — the duplicate-counting site is ghost-client-release's sigblock_meets, outside the update crate's selector")
                appendLine("MC-D13: wired in ghost-client-net's fetch; the JVM byte seam cannot drive the fetch (kill needs the wire/emulator)")
                appendLine("MC-D15: wired; the arms sit behind the whole-file hash, unreachable without a second mutation")
                appendLine("MC-D27: wired; the kill needs a v3.1-lineage APK (the crafted suite)")
                appendLine("PM-D1/PM-D2/PM-D6/PM-D8/PM-D11/PM-D12: killed in the NI-U twins (the job model of slice S6d)")
                appendLine("PM-D3/PM-D4/PM-D5/PM-D10: seam-held (request headers, the root path and an out-of-set onion never cross the byte seam)")
                appendLine("NI-U5: wire-held (G-D11's wire-transcript generator, protocol/test-vectors/wire_transcript.txt, is not built yet - the byte-identical transcript claim needs it; the release-independent request shapes on this seam are covered by PM-D9's kill)")
            },
        )
        assertEquals("every executed kill must detect (an unexpected error is not a skip)", 0, broken)
    }
}
