package org.ghost.messaging.entworld

import org.ghost.messaging.harness.DmHarness
import org.ghost.messaging.harness.DmKills
import org.ghost.messaging.harness.DmMutants
import org.ghost.messaging.harness.DmReport
import org.ghost.sync.harness.CallKind
import org.ghost.sync.harness.EventKind
import org.ghost.sync.harness.Fault
import org.ghost.sync.harness.FaultPlan
import org.ghost.sync.harness.JournalMode
import org.ghost.sync.harness.RunResult
import org.ghost.sync.harness.RunSpec
import org.ghost.sync.harness.Runner
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test

/**
 * **SCN-E** (Phase 9 design §15.3; §22.25): the offline recipient and its LOSE_KEYS variant on the
 * entitlement world ([ScnE]), under a **sampled** crash enumeration, and the two §15.7 mutants it
 * makes reachable — MC-14 and MC-15 — each killed fault-free and at crash points beside a clean run.
 *
 * **Why the enumeration is sampled, said once.** §15.3's method is every event; SCN-E's world is
 * about 640 000 events of bob and more of alice over 25 days, at about a minute a run on the owner's
 * workstation, and §22.22 item 7 names what classification (the Phase 7 harness's way of making an
 * every-event enumeration affordable) still lacks here: deterministic native randomness above all.
 * So SCN-E crashes at points it **samples**, stratified by the script's phases so that every phase
 * gets its share whatever its event density — the establishment, the offline span while bob's
 * registrations live, the lapse with its refused deposits, bob's return with its renewal and
 * registrations, and the rest; LOSE_KEYS's establishment, loss and healing — evenly spaced inside
 * each phase ([PR_PER_PHASE] per phase on a PR, [GATE_PER_PHASE] in the gate), for **each** client
 * armed in turn, plus "timeout after apply" at stores of the armed client, spread the same way. The
 * report's SCN-E lines say so in their own words (`…; sampled, not every event`), and
 * `dm-report-check.sh` requires those words and never holds these lines to the every-event rule of
 * the `dm crash classes:` lines. The points are a function of the recording run's event count and
 * its phase marks, so a run of the same code samples the same points.
 *
 * Every run carries every check [ScnE] makes, in every run, and its oracles at quiescence.
 */
class ScnETest {

    @Before
    fun native() {
        assumeTrue(DmHarness.SKIP_MESSAGE, DmHarness.nativeAvailable())
    }

    /** The offline recipient, sampled, with each client armed in turn. */
    @Test
    fun scnEOfflineRecipient() {
        for (armBob in listOf(true, false)) sample(ScnE.Variant.OFFLINE, armBob)
    }

    /** The LOSE_KEYS variant, sampled, with each client armed in turn. */
    @Test
    fun scnELoseKeys() {
        for (armBob in listOf(true, false)) sample(ScnE.Variant.LOSE_KEYS, armBob)
    }

    /** §15.7 MC-14: the healing rule re-arms nothing; SCN-E/LOSE_KEYS, bob (the owner who heals) armed. */
    @Test
    fun mc14RegistrationsNotReArmedIsDetected() = kill(DmMutants.MC14, armBob = true)

    /** §15.7 MC-15: a refused credential re-put on every `CAPABILITIES` hint; alice (the sender) armed. */
    @Test
    fun mc15RefusedCredentialReputOnEveryHintIsDetected() = kill(DmMutants.MC15, armBob = false)

    /**
     * The checks can fail. Two worlds that break one thing each, and fail for the reason they name:
     * bob returns but every redemption of his is lost (he never renews, so nothing he registers can
     * carry [ScnE.E_WAITING]); and bob returns a day after [ScnE.E_WAITING]'s deadline (it fails at
     * its deadline instead of being delivered). The healing check and the rule on refused stores
     * are shown able to fail by MC-14's and MC-15's kills.
     */
    @Test
    fun theChecksCanFail() {
        val controls = listOf(
            ScnE.Control.NO_RENEWAL_ON_RETURN to "six hours after his return bob holds no redeemed capability",
            ScnE.Control.RETURN_AFTER_EVERY_DEADLINE to "${ScnE.E_WAITING} the minute before bob returns is failed",
        )
        val failures = DmHarness.parallel(
            controls.map { (control, _) ->
                "control $control" to { runCatching { run(ScnE(ScnE.Variant.OFFLINE, armBob = true, control = control), RunSpec()) }.exceptionOrNull() }
            },
        )
        for ((pair, failure) in controls.zip(failures)) {
            val (control, expected) = pair
            val message = failure?.let(::deepMessage).orEmpty()
            assertTrue("control $control did not fail: its checks cannot see what it breaks", failure is AssertionError)
            assertTrue("control $control failed, but not for the reason it names.\n  expected: $expected\n  actual: $message", expected in message)
            println("SCN-E control $control: failed as it should: $message")
        }
    }

    // ------------------------------------------------------------------ the sampled enumeration

    private fun sample(variant: ScnE.Variant, armBob: Boolean) {
        val who = if (armBob) "bob" else "alice"
        val recording = ScnE(variant, armBob)
        val recorded = run(recording, RunSpec())
        val events = recorded.events
        recording.notes.forEach { println("${recording.name} ($who armed, recording run): $it") }
        val phases = strata(recording.phaseMarks, events)
        val perPhase = if (DmHarness.full) GATE_PER_PHASE else PR_PER_PHASE
        val timeoutsPerPhase = if (DmHarness.full) GATE_TIMEOUTS_PER_PHASE else PR_PER_PHASE
        val points = phases.flatMap { (from, to) -> spread(from, to, perPhase) }.distinct()
        val stores = recording.storeEvents.toList()
        check(stores.isNotEmpty()) { "${recording.name}: the armed client ($who) stored nothing" }
        val timeoutPoints = phases.flatMap { (from, to) -> stores.filter { it in (from + 1)..to }.let { pick(it, timeoutsPerPhase) } }.distinct()
            .ifEmpty { listOf(stores.first()) }

        val tasks = points.map { k -> "${recording.name} $who crash@$k" to { runChecked(ScnE(variant, armBob), RunSpec(crashAt = k)) to k } } +
            timeoutPoints.map { k -> "${recording.name} $who timeout@$k" to { runChecked(ScnE(variant, armBob), timeoutAt(k)) to -k } }
        val results = DmHarness.parallel(tasks)
        for ((pair, label) in results.zip(tasks.map { it.first })) {
            val (outcome, _) = pair
            assertTrue("$label: ${outcome.problem}", outcome.problem == null)
        }
        val line = "dm crash sample: ${recording.name} $who $events events, ${points.size} singles over ${phases.size} phases, " +
            "${timeoutPoints.size} timeouts over ${stores.size} stores; sampled, not every event"
        println(line)
        println("${recording.name} ($who armed): phases ${recording.phaseMarks}, crash points $points, timeout points $timeoutPoints")
        DmReport.line(line)
    }

    /** `[start, end)` event ranges of the script's phases, from the recording run's marks. */
    private fun strata(marks: Map<String, Long>, events: Long): List<Pair<Long, Long>> {
        val starts = marks.values.sorted()
        return starts.mapIndexed { i, from -> from to (starts.getOrNull(i + 1) ?: events) }.filter { it.second > it.first }
    }

    /** [n] points evenly inside `(from, to]`. */
    private fun spread(from: Long, to: Long, n: Int): List<Long> = (1..n).map { i -> from + maxOf(1L, (to - from) * i / (n + 1)) }

    /** [n] of [items], evenly (all of them when there are no more). */
    private fun pick(items: List<Long>, n: Int): List<Long> =
        if (items.size <= n) items else (1..n).map { i -> items[(items.size * i / (n + 1)).coerceAtMost(items.size - 1)] }

    private fun timeoutAt(k: Long): RunSpec = RunSpec(
        plan = { _ ->
            FaultPlan { e ->
                if (e.index == k && e.kind == EventKind.RELAY_AFTER_APPLY && e.call?.kind == CallKind.STORE) Fault.Network("timeout") else null
            }
        },
    )

    private class Outcome(val problem: String?)

    /** One run of the enumeration: it must pass and its fault must have fired. */
    private fun runChecked(s: ScnE, spec: RunSpec): Outcome {
        val result = run(s, spec)
        val problem = when {
            spec.crashAt != null && result.crashes != 1 -> "the crash planned at ${spec.crashAt} fired ${result.crashes} times"
            spec.plan != null && s.world.bus.networkFaults != 1 -> "the timeout planned at a store fired ${s.world.bus.networkFaults} times"
            else -> null
        }
        return Outcome(problem)
    }

    private fun run(s: ScnE, spec: RunSpec): RunResult = try {
        Runner(s, JournalMode.WAL, SEED).run(spec)
    } finally {
        runCatching { s.dm.close() }
    }

    // ------------------------------------------------------------------ the kills

    /**
     * S10b's kill rule (`DmMutantDetectionTest.detectFaultFreeAndUnderCrashes`) on the entitlement
     * world: the mutant is killed **fault-free** by the check its entry names, beside the clean
     * control, **and** at [CRASH_POINTS] crash points spread over the events both worlds reach, each
     * beside the unmutated scenario crashed at the same point, which must pass — and each mutated run
     * must really have crashed before it failed, so no point is the fault-free kill again.
     */
    private fun kill(mutation: DmMutants.Mutation, armBob: Boolean) {
        val variant = ScnE.Variant.LOSE_KEYS
        val clean = ScnE(variant, armBob)
        val cleanEvents = run(clean, RunSpec()).events

        val mutant = ScnE(variant, armBob, dmMutant = mutation)
        val faultFree = runCatching { run(mutant, RunSpec()) }.exceptionOrNull()
        assertTrue("${mutation.id} survived ${mutant.name}: the mutant is registered but nothing kills it", faultFree is AssertionError)
        val faultFreeMessage = deepMessage(faultFree!!)
        assertTrue(
            "${mutation.id} failed ${mutant.name}, but not for the reason its entry names.\n  expected: ${mutation.expect}\n  actual: $faultFreeMessage",
            mutation.expect in faultFreeMessage,
        )
        val mutantEvents = mutant.world.bus.count
        println("${mutation.id} killed fault-free by ${mutant.name} (clean passed, $cleanEvents events) at event $mutantEvents: $faultFreeMessage")

        val events = minOf(cleanEvents, mutantEvents)
        val points = (1..CRASH_POINTS).map { i -> maxOf(1L, events * i / (CRASH_POINTS + 1)) }.distinct()
        val tasks = points.flatMap { at ->
            listOf(
                "${clean.name} clean crash@$at" to {
                    val s = ScnE(variant, armBob)
                    val failure = runCatching { run(s, RunSpec(crashAt = at)) }.exceptionOrNull()
                    Triple(failure, s.world.bus.injected.size, at)
                },
                "${mutant.name} crash@$at" to {
                    val s = ScnE(variant, armBob, dmMutant = mutation)
                    val failure = runCatching { run(s, RunSpec(crashAt = at)) }.exceptionOrNull()
                    Triple(failure, s.world.bus.injected.size, at)
                },
            )
        }
        val outcomes = DmHarness.parallel(tasks)
        val kills = ArrayList<String>()
        for ((index, at) in points.withIndex()) {
            val (cleanFailure, cleanCrashes, _) = outcomes[2 * index]
            val (mutantFailure, mutantCrashes, _) = outcomes[2 * index + 1]
            assertTrue("the unmutated ${clean.name} fails at crash@$at, so a kill there proves nothing: ${cleanFailure?.let(::deepMessage)}", cleanFailure == null)
            assertEquals("the unmutated ${clean.name} did not crash at crash@$at", 1, cleanCrashes)
            assertTrue("${mutation.id} survived ${clean.name} crash@$at: the enumeration cannot see it there", mutantFailure is AssertionError)
            assertEquals("${mutation.id}'s run at crash@$at failed before its crash: that is the fault-free kill again", 1, mutantCrashes)
            val message = deepMessage(mutantFailure!!)
            assertTrue(
                "${mutation.id} failed ${clean.name} crash@$at, but not for a reason its entry names.\n  expected one of: ${mutation.expectUnderCrash}\n  actual: $message",
                mutation.expectUnderCrash.any { it in message },
            )
            println("${mutation.id} killed at ${clean.name} crash@$at of $events (clean passed): $message")
            kills += "crash@$at"
        }
        DmKills.record(
            mutation.id,
            "$faultFreeMessage | and under a crash at ${kills.joinToString(", ")} of $events events, each beside a clean run at the same point",
            "fault-free and at ${kills.size} of ${points.size} crash points, each beside a clean run",
        )
    }

    private fun deepMessage(failure: Throwable): String = generateSequence(failure) { it.cause }.mapNotNull { it.message }.joinToString(" | ")

    private companion object {
        const val SEED = 1L

        /** Crash points per phase of the script: on a PR (also its timeouts), and in the gate (`-Dghost.dm.crash=full`). */
        const val PR_PER_PHASE = 1
        const val GATE_PER_PHASE = 8

        /** Timeout-after-apply points per phase in the gate (a phase's stores, evenly, when it has more). */
        const val GATE_TIMEOUTS_PER_PHASE = 3

        /** S10b's number of crash points per kill. */
        const val CRASH_POINTS = 6
    }
}
