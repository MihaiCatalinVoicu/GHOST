package org.ghost.messaging.dmworld

import org.ghost.messaging.DmWorld
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The controls of S-DM1 and S-DM2 (Phase 9 design §15.6, R-17: "mutants that must move the
 * statistics"; §22.30): the same statistics as the privacy world's report, on MEDIUM worlds (N = 56
 * over 2 days, the scale S-DM3's kill already uses for the n ≥ 100 floor), each held against the
 * same-scale unmutated world of the same seed — which must pass S-DM1 — so a statistic that stays green
 * over a leak is shown to be blind, not the engine to be clean.
 *
 *  - **the fetch window left open** ([EdgeLeaks.OPEN_FETCH_WINDOW]): reads outside LD that link a
 *    conversation with no message on it. S-DM1's comparison must flag it and JD7 must fail on it
 *    (its exact killer, run here because this control is no §15.7 entry); what the comparison does
 *    when the full view keeps only 10 %, 3 %, 1 % and 0.3 % of those reads is reported; and —
 *    because the reads that fall where a second or third attempt window could be are LD (L7-D6
 *    declares three) — S-DM2's strongest LD attacker must rise above this scale's control by more
 *    than the 0.02 allowance. That is S-DM2's allowance exceeded at MEDIUM against a MEDIUM control;
 *    the report check's rule pins a PR-scale baseline, and the same leak run once on the PR world
 *    (outside this test) stays inside it — on production's triggers +0.0075 over the strongest
 *    attacker's baseline and +0.0073 over the 7 d class's (§22.36 item 12 (h); +0.0084 on the old
 *    cadence, §22.30 item 5) — while S-DM1 and JD7 fail on it;
 *  - **a conversation tag in the envelope bytes** ([EdgeLeaks.CONVERSATION_TAG]): a link through
 *    bytes only. S-DM1's exact half must flag it; what its comparison did, and which exact joins
 *    fail on its world, are reported (declared: the comparison cannot show a leak that needs a message
 *    here, because LD already names every message's sender);
 *  - **PM-2** (an automatic receipt): a leak inside LD's categories. S-DM1 must **not** flag it (a
 *    receipt is a store into an inbox, which LD shows), and what it does to S-DM2 and S-DM4 is
 *    measured and reported, not required: its exact detectors are JD6 and NI-DM1.
 * The control's line also counts the undecryptable blobs its world holds: PM-6's reflex acts on
 * nothing else.
 */
class DmEdgeStatisticsTest {

    private fun requireNative() {
        assumeTrue(SKIP, DmWorld.nativeAvailable())
        assumeTrue("-Dghost.dm.privacy=off: the privacy worlds are skipped", PrivacyScale.enabled)
    }

    internal class Outcome(
        val sdm1: EdgeStatistics.Sdm1,
        val sdm2: EdgeStatistics.Sdm2,
        val sdm4: EdgeStatistics.Sdm4,
        /** The exact joins run on this world (none for the control and PM-2). */
        val joins: List<JoinResult>,
        /** Blobs of this world that failed to open (PM-6 acts on these alone). */
        val undecryptable: Int,
        /**
         * S-DM1 over this world with the full view keeping only a share of its events outside LD —
         * (per mille kept, the result) — so a leak's dose can be read: how few of those events the
         * comparison still flags. Reported, not required (none for the worlds without such events).
         */
        val thinned: List<Pair<Int, EdgeStatistics.Sdm1>> = emptyList(),
    )

    private fun run(
        mutant: PrivacyMutant?,
        seed: Long,
        thin: List<Int> = emptyList(),
        joins: (Joins) -> List<JoinResult> = { emptyList() },
    ): Outcome =
        PrivacyWorld(PrivacyWorldConfig.of(PrivacyScale.MEDIUM, seed, mutant)).use { world ->
            world.run()
            val views = EdgeStatistics.Views(world)
            val outcome = Outcome(
                sdm1 = EdgeStatistics.sdm1(views, seed),
                sdm2 = EdgeStatistics.sdm2(views, null, world, null),
                sdm4 = EdgeStatistics.sdm4(views, world, seed, null),
                joins = joins(Joins(world)),
                undecryptable = world.truth.undecryptable.size + world.truth.undecryptableSessions.size,
                // The events kept are chosen by a fixed hash of their index in the record, never by
                // what they are or whom they link.
                thinned = thin.map { permille ->
                    val kept = EdgeStatistics.Views(world, keepOutside = { Math.floorMod(EdgeMath.mix(it.toLong()), 1_000) < permille })
                    permille to EdgeStatistics.sdm1(kept, seed)
                },
            )
            // Each world's own lines, in the test's output (the report carries the controls' line).
            println("${mutant?.id ?: "control"}: ${world.acceptedEdges.size} edges, ${world.counters["sends"]} sends")
            println("  ${outcome.sdm1.line()}\n  ${outcome.sdm2.line()}\n  ${outcome.sdm4.line()}")
            for (j in outcome.joins) println("  ${j.line()}")
            for ((permille, s) in outcome.thinned) println("  thinned to $permille per mille: ${s.line()}")
            outcome
        }

    @Test
    fun theStatisticsMoveOnTheirControls() {
        requireNative()
        val seed = PrivacySeeds.ALL[0]
        val result = EdgeControls(
            control = run(null, seed),
            open = run(EdgeLeaks.OPEN_FETCH_WINDOW, seed, thin = listOf(100, 30, 10, 3)) { listOf(it.jd7()) },
            tag = run(EdgeLeaks.CONVERSATION_TAG, seed) {
                listOf(it.jd1(), it.jd2(), it.jd3(), it.jd4(), it.jd5(), it.jd6(), it.jd7(), it.jd9())
            },
            pm2 = run(PrivacyMutants.PM2, seed),
        )
        PrivacyReport.line(result.line())
        assertTrue(result.line(), result.passed)
    }

    private companion object {
        const val SKIP = "set -Dghost.dm.native to the ghost-dm-host library: every privacy world runs the real stack"
    }
}

/**
 * What the controls must show, and the report line that says it. Each clause is a measurement of a
 * mutated world against the unmutated world of the same scale and seed; none compares a world with
 * itself, and S-DM1's comparison inside each world is that world's full view against its own LD.
 */
internal class EdgeControls(
    private val control: DmEdgeStatisticsTest.Outcome,
    private val open: DmEdgeStatisticsTest.Outcome,
    private val tag: DmEdgeStatisticsTest.Outcome,
    private val pm2: DmEdgeStatisticsTest.Outcome,
) {
    private val co = 0
    private val logistic = EdgeStatistics.LOGISTIC

    private companion object {
        /** JD7's message for a read outside every attempt window (the kill `OPEN_FETCH_WINDOW` names). */
        const val JD7_KILL = "not its own and not an open bundle fetch"
    }

    /** The control passes S-DM1 over a sample above its floor. */
    val controlPasses: Boolean get() = control.sdm1.passed

    /** The open window is flagged by the comparison — the co-occurrence attacker and the logistic one. */
    val openFlagged: Boolean get() = open.sdm1.tests[co].rejects && open.sdm1.tests[logistic].rejects && open.sdm1.floorMet

    /** … and JD7, its exact killer, fails on the same world with the reads outside every attempt window. */
    val openKilledByJd7: Boolean get() = open.joins.any { it.id == "JD7" && !it.passed && it.failureMessage().contains(JD7_KILL) }

    /** … and raises S-DM2's strongest LD attacker beyond the regression allowance over this scale's control. */
    val openRaisesSdm2: Boolean get() = open.sdm2.strongest - control.sdm2.strongest > EdgeStatistics.REGRESSION

    /** The tag is flagged by the exact half (shared byte windows across two clients' namespaces). */
    val tagFlaggedExactly: Boolean get() = (tag.sdm1.structure["byte windows"] ?: 0) > 0 && tag.sdm1.floorMet

    /** PM-2 is not an S-DM1 leak (its receipts are LD-category stores). */
    val pm2NotSdm1: Boolean get() = pm2.sdm1.flagged.isEmpty() && pm2.sdm1.structureClean && pm2.sdm1.floorMet

    val passed: Boolean get() = controlPasses && openFlagged && openKilledByJd7 && openRaisesSdm2 && tagFlaggedExactly && pm2NotSdm1

    private fun t(s: EdgeStatistics.Sdm1, i: Int): String =
        "${EdgeStatistics.MEMBERS[i]} diff ${"%+.4f".format(s.tests[i].difference)} p=${"%.3f".format(s.tests[i].p)}"

    private fun f(v: Double): String = "%.4f".format(v)

    fun line(): String {
        val openDelta = open.sdm2.strongest - control.sdm2.strongest
        val pm2Delta = pm2.sdm2.strongest - control.sdm2.strongest
        val tagJoinsFailed = tag.joins.filter { !it.passed }.map { it.id }
        return "dm S-DM1 controls: ${if (passed) "PASS" else "FAIL"} MEDIUM worlds (N=56, 2 days, seed 5eed0001, " +
            "n=${control.sdm1.pairs} pairs, ${control.sdm1.edges} conversations in the control), each against the same-scale control: " +
            "the control ${if (controlPasses) "passes" else "FAILS"} S-DM1 (${t(control.sdm1, co)}, ${t(control.sdm1, logistic)}; " +
            "${control.undecryptable} undecryptable blobs, the only thing PM-6's reflex acts on); " +
            "the fetch window left open is ${if (openFlagged) "flagged" else "NOT FLAGGED"} by the comparison " +
            "(${t(open.sdm1, co)}, ${t(open.sdm1, logistic)}; ${open.sdm1.outsideLd.values.sum()} events outside LD), " +
            "${if (openKilledByJd7) "fails" else "DOES NOT FAIL"} JD7 " +
            "(${open.joins.firstOrNull { it.id == "JD7" }?.violations?.size ?: 0} reads outside every attempt window), " +
            "measured, not required, with only a share of those reads kept in the full view: " +
            open.thinned.joinToString("; ") { (permille, s) ->
                "${permille / 10.0} % (${s.outsideLd.values.sum()} reads) " +
                    "${if (s.flagged.isEmpty()) "not flagged" else "flagged"} (${t(s, co)}, ${t(s, logistic)})"
            } + ", and " +
            "${if (openRaisesSdm2) "raises" else "DOES NOT RAISE"} S-DM2's strongest LD attacker's AUC over this scale's control from " +
            "${f(control.sdm2.strongest)} to ${f(open.sdm2.strongest)} (${"%+.4f".format(openDelta)}, allowance " +
            "${EdgeStatistics.REGRESSION}: its later reads that fall where a second or third attempt window could open are LD, L7-D6); " +
            "a conversation tag of ${EdgeLeaks.TAG_LENGTH} bytes at offset ${EdgeLeaks.TAG_OFFSET} of the envelope bytes is " +
            "${if (tagFlaggedExactly) "flagged" else "NOT FLAGGED"} by the exact half " +
            "(${tag.sdm1.structure["byte windows"]} shared byte windows), " +
            (if (tagJoinsFailed.isEmpty()) "by none of JD1-JD7 and JD9" else "BY ${tagJoinsFailed.joinToString("/")} TOO") +
            " and " +
            (
                if (tag.sdm1.flagged.isEmpty()) {
                    "not by the comparison, which cannot see it here (${t(tag.sdm1, logistic)}: LD's session co-occurrence " +
                        "already names every message's sender, §22.30); "
                } else {
                    "by the comparison too (${t(tag.sdm1, logistic)}); "
                }
            ) +
            "PM-2 ${if (pm2NotSdm1) "is not" else "IS"} an S-DM1 leak (${t(pm2.sdm1, logistic)}); measured, not required: it moves " +
            "S-DM2's strongest LD attacker's AUC by ${"%+.4f".format(pm2Delta)} " +
            (if (pm2Delta > EdgeStatistics.REGRESSION) "(beyond the allowance)" else "(inside the allowance: S-DM2 does not see it; JD6 and NI-DM1 do)") +
            " and S-DM4's within-inbox information from ${f(control.sdm4.within)} bits (null ${f(control.sdm4.withinNull)}, " +
            "p=${"%.3f".format(control.sdm4.withinP)}) to ${f(pm2.sdm4.within)} bits (null ${f(pm2.sdm4.withinNull)}, " +
            "p=${"%.3f".format(pm2.sdm4.withinP)})"
    }
}
