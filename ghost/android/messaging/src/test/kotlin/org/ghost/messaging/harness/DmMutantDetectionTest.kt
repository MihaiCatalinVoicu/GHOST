package org.ghost.messaging.harness

import org.ghost.crypto.bridge.DmEquivalence
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Every mutant of [DmMutants], killed by a named scenario (Phase 9 design §15.7; the discipline of
 * `MutantDetectionTest` in `:sync` and `t2_mutants.rs` in `:issuer`).
 *
 * > each detected against a same-scale control world
 *
 * Each case runs the **same** scenario twice: once clean — which is the control, and which must
 * pass, so a mutant cannot be "detected" by a world that was broken anyway — and once with the
 * mutation installed, which must fail. A failure that is not a [DmInvariantViolation] or an
 * [AssertionError] is not a detection either, and neither is one whose message is not the one the
 * scenario states: `Mutation.expect` is that message, and asserting it is what caught MC-5 being
 * killed by the `dm_message` replace guard rather than by the check its registry line named.
 *
 * MC-12 is killed in `DmPoisonTest`, which is where the native-crash loop lives, and MC-14 and MC-15
 * in `entworld.ScnETest`, on SCN-E's entitlement world (§22.25). Every kill, here and there, records
 * itself in [DmKills], and the report's `dm mutants:` lines are written from that record — not from
 * the registry — so an ignored kill lowers the count.
 */
class DmMutantDetectionTest {

    private fun requireNative() = assumeTrue(DmHarness.SKIP_MESSAGE, DmHarness.nativeAvailable())

    @Test
    fun mc1SplitSendTransactionIsDetectedOnlyByACrash() = detectUnderCrash(DmMutants.MC1, DmScenarios.scnA())

    @Test
    fun mc5D3OffIsDetected() = detect(DmMutants.MC5, DmSuiteCases.rp6ReEncryptionAfterAWronglyReportedFailure())

    @Test
    fun mc20BindingCoverageIsDetected() {
        // MC-20 (§21.4 point 1; §22.37): each of the four omissions, fault-free, by KC5b's replay
        // of its own field — each beside the clean KC5b, which refuses all four. One §15.7 id,
        // recorded once, and only when every omission is killed.
        val kills = DmMutants.MC20_OMISSIONS.map { detectFaultFree(it, DmSuiteCases.kc5bAGenuineBindingReplayed()) }
        DmKills.record(
            DmMutants.MC20.id,
            kills.joinToString(" | "),
            "fault-free, each of its ${kills.size} omissions by its own replay, each beside a clean run",
        )
    }

    @Test
    fun mc7D2bOffIsDetected() {
        // MC-7′, both halves (§15.7: "D2b not enforced, or written outside the RECV transaction";
        // §22.37). The first — the tuple never matches — fault-free by the CB replay and by RP4, whose
        // own property it breaks (the session bob reset comes back); the second — the tuple split
        // out of the RECV transaction, which no fault-free run can see — by RP5 at every crash
        // point of its split window, each beside a clean run. One §15.7 id, recorded once, and only
        // when both halves are killed.
        val first = detectFaultFree(DmMutants.MC7, DmSuiteCases.cbRejectedRequestStaysRejected())
        val byRp4 = detectFaultFree(
            DmMutants.MC7, DmSuiteCases.rp4FirstFlightOfAResetSession(), expect = "RP4: bob holds the session he reset again",
        )
        val (second, points) = detectAtEveryPointOfItsSplitWindow(
            DmMutants.MC7_SPLIT, DmSuiteCases.rp5PreKeyReplayAcrossARestart(),
        )
        DmKills.record(
            DmMutants.MC7.id,
            "$first | $byRp4 | its second half: $second",
            "fault-free by two cases (its first half) and, its second half, at $points of $points crash " +
                "points of its split window, each beside a clean run",
        )
    }

    @Test
    fun mc10ArrivalOrderDisplayIsDetected() = detect(DmMutants.MC10, DmScenarios.scnB())

    @Test
    fun mc16ResendBeyondTheBoundIsDetected() = detect(DmMutants.MC16, DmScenarios.scnG())

    /** S10b: the renewal of §21.3 point 2 keeps the lost device's out keys. */
    @Test
    fun mc18OutKeyFloorKeptAcrossARenewalIsDetected() =
        detectFaultFreeAndUnderCrashes(DmMutants.MC18, DmScenarios.scnI())

    /** S10b: SWEEP never deletes a `previous` session at its retire day. */
    @Test
    fun mc26PreviousNeverRetiredIsDetected() =
        detectFaultFreeAndUnderCrashes(DmMutants.MC26, DmScenarios.scnI())

    /** S10b: SWEEP erases a superseded generation 70 days early. */
    @Test
    fun mc28GenerationErasedEarlyIsDetected() =
        detectFaultFreeAndUnderCrashes(DmMutants.MC28, DmScenarios.scnH())

    /** S10b: SWEEP erases the out key a FAILED item of an earlier week still needs. */
    @Test
    fun mc33RetryWithoutTheAuthorWeekKeyIsDetected() =
        detectFaultFreeAndUnderCrashes(DmMutants.MC33, DmScenarios.scnGWeek())

    @Test
    fun me16ReadPathIgnoresExpiryIsDetected() =
        detect(DmMutants.ME16, DmSuiteCases.epExpiredRowsAreNotReadable())

    /** §22.27: SWEEP erases a recipient's in-keys before it ratchets them forward. */
    @Test
    fun mc21PairKeysErasedBeforeTheRatchetIsDetected() =
        detectFaultFreeAndWhereItActs(DmMutants.MC21, DmSuiteCases.rs2AClientOfflineSixtyDays(), DmSuiteCases.RS2_MARK)

    /** §22.27: RECV attempts `request → changed` for a request's second identity. */
    @Test
    fun mc24RequestToChangedAttemptedIsDetected() =
        detectFaultFreeAndWhereItActs(DmMutants.MC24, DmSuiteCases.kc12ARequestSendingTwoIdentities(), DmSuiteCases.KC12_MARK)

    /**
     * The registry is well formed, and the report's count is armed to be written from the kills.
     *
     * It is deliberately not "57 run, 57 detected". §15.7's set is 97 — 40 privacy, 33 correctness
     * and 24 ephemeral — and the slices so far register fifteen (§22.27). A gate that printed the
     * design's number while running fifteen would be the one failure a report-checked gate must not have, which is
     * why the check script pins this line to the number this suite actually runs — and why the line
     * itself is now written from [DmKills], so that removing a kill lowers it.
     */
    @Test
    fun theRegistryAndTheKillsAgree() {
        requireNative()
        val registered = DmMutants.all()
        assertTrue("the registry is empty", registered.isNotEmpty())
        for (mutant in registered) {
            assertTrue(
                "${mutant.id} has no rewrite, no decorator, no split, no trigger substitution and no native " +
                    "hook: it mutates nothing",
                mutant.rewrite != null || mutant.rewriteOn != null || mutant.decorate != null ||
                    mutant.defer != null || mutant.deferUpdate != null || mutant.hintKeeper ||
                    mutant.bindingOmit != DmEquivalence.BINDING_NONE,
            )
            assertTrue("${mutant.id} names no property", mutant.defeats.isNotBlank())
            assertTrue("${mutant.id} names no detecting case", mutant.detectedBy.isNotBlank())
            assertTrue("${mutant.id} names no expected failure", mutant.expect.isNotBlank())
        }
        DmKills.arm()
    }

    /**
     * Runs [scenario] clean and then mutated. The clean run is the control; the mutated run must
     * fail, and must fail for the reason the mutant's own registry entry states.
     */
    private fun detect(mutation: DmMutants.Mutation, scenario: DmScenario) {
        requireNative()
        DmCrashRunner(scenario).run(DmRunSpec())

        val failure = runCatching {
            DmCrashRunner(mutated(scenario, mutation)).run(DmRunSpec())
        }.exceptionOrNull()
        assertKilled(mutation, scenario.name, failure, rule = DmKills.FAULT_FREE)
    }

    /** [detect] without recording: the kill's message, for a mutant whose kill has more than one half. */
    private fun detectFaultFree(
        mutation: DmMutants.Mutation,
        scenario: DmScenario,
        expect: String = mutation.expect,
    ): String {
        requireNative()
        DmCrashRunner(scenario).run(DmRunSpec())
        val failure = runCatching {
            DmCrashRunner(mutated(scenario, mutation)).run(DmRunSpec())
        }.exceptionOrNull()
        assertKilled(mutation, scenario.name, failure, record = false, expect = expect)
        return deepMessage(requireNotNull(failure))
    }

    /**
     * A split mutant's kill at **every** crash point of its split window (§22.37): MC-1's rule, held
     * to what §22.27's review made of the window rule. The mutated world with no fault must pass (a
     * split is invisible without one, so a failure here would be some other defect); its recording
     * run reports the event indices inside its split windows ([DmEventBus.vulnerable], which since
     * §22.37 ends before the second transaction's post-commit event, the first at which the split
     * is no longer observable), and the scenario must split exactly one transaction in its armed
     * phase. Then **every** index of that window is a crash point, not the first that kills:
     * the mutated run must fail there for the reason the entry names, with its crash injected
     * **and rebooted** (a crash something absorbed is not a kill, §22.27 item 11(b)), and the
     * unmutated scenario crashed at the same index must pass. The two worlds differ before the
     * window by one event — the held-back statement raises its event in the second transaction,
     * not in the first — so "the same index" is where MC-1's rule put its control, inside or at the
     * end of the unsplit transaction.
     */
    private fun detectAtEveryPointOfItsSplitWindow(
        mutation: DmMutants.Mutation,
        scenario: DmScenario,
    ): Pair<String, Int> {
        requireNative()
        assertTrue("${mutation.id} is not declared as crash-only", mutation.needsACrash)
        DmCrashRunner(scenario).run(DmRunSpec())
        val mutant = mutated(scenario, mutation)
        // Invisible without a fault.
        DmCrashRunner(mutant).run(DmRunSpec())
        val vulnerable = DmCrashRunner(mutant).record().vulnerable
        val windows = ArrayList<MutableList<Long>>()
        for (at in vulnerable) {
            val last = windows.lastOrNull()
            if (last != null && last.last() + 1 == at) last += at else windows += mutableListOf(at)
        }
        assertEquals(
            "${mutation.id} split ${windows.size} transactions in ${scenario.name}'s armed phase " +
                "(windows $windows), expected exactly one",
            1, windows.size,
        )
        val points = windows.single().toList()
        val tasks: List<Pair<String, () -> Pair<Throwable?, DmArmedPhase?>>> = points.flatMap { at ->
            listOf(
                "${scenario.name} clean crash@$at" to {
                    val failure = runCatching { DmCrashRunner(scenario).run(DmRunSpec(crashAt = at)) }.exceptionOrNull()
                    failure to null
                },
                "${scenario.name}/${mutation.id} crash@$at" to {
                    var phase: DmArmedPhase? = null
                    val failure = runCatching {
                        DmCrashRunner(mutant).run(DmRunSpec(crashAt = at, onArmed = { phase = it }))
                    }.exceptionOrNull()
                    failure to phase
                },
            )
        }
        val outcomes = DmHarness.parallel(tasks)
        var first: String? = null
        for ((index, at) in points.withIndex()) {
            val (clean, _) = outcomes[2 * index]
            val (killed, phase) = outcomes[2 * index + 1]
            assertTrue(
                "the unmutated ${scenario.name} fails at crash@$at, so a kill there proves nothing: " +
                    clean?.let { deepMessage(it) },
                clean == null,
            )
            assertTrue(
                "${mutation.id} survived ${scenario.name} crash@$at, inside its split window $points",
                killed is AssertionError,
            )
            val armed = requireNotNull(phase) {
                "${mutation.id}'s run at crash@$at never ended its armed phase: ${killed?.let { deepMessage(it) }}"
            }
            assertEquals("${mutation.id}'s run at crash@$at: crashes injected", 1, armed.injected)
            assertEquals("${mutation.id}'s run at crash@$at: crashes that reached a reboot", 1, armed.reboots)
            val message = deepMessage(requireNotNull(killed))
            assertTrue(
                "${mutation.id} failed ${scenario.name} crash@$at, but not for the reason its entry names.\n" +
                    "  expected to contain: ${mutation.expect}\n  actual: $message",
                message.contains(mutation.expect),
            )
            println("${mutation.id} killed at ${scenario.name} crash@$at, in its split window $points (clean passed): $message")
            if (first == null) first = "${scenario.name} crash@$at: $message"
        }
        return requireNotNull(first) to points.size
    }

    /**
     * MC-1's kill, and the one control the whole crash enumeration was missing: a defect **no
     * fault-free run can see**.
     *
     * Three runs decide it.
     *  1. The mutated scenario with **no fault** must *pass*. A split transaction whose second half
     *     follows the first immediately is indistinguishable from one transaction, so a mutant that
     *     failed here would be some other defect and the rest would prove nothing.
     *  2. The mutated scenario crashed **inside the split window** must fail. The window is the
     *     event indices between the first commit and the second, which the executor reports through
     *     [DmEventBus.vulnerable]; the enumeration walks every k and therefore covers them, but a
     *     kill test that walked every k to find one would cost a gate run, so it crashes at the
     *     ones that can possibly matter and requires one of them to kill.
     *  3. The **clean** scenario crashed at that same k must pass. Without it "the mutant died at
     *     k" and "the scenario dies at k" are the same sentence.
     */
    private fun detectUnderCrash(mutation: DmMutants.Mutation, scenario: DmScenario) {
        requireNative()
        assertTrue("${mutation.id} is not declared as crash-only", mutation.needsACrash)
        val mutant = mutated(scenario, mutation)

        // 1: invisible without a fault.
        DmCrashRunner(mutant).run(DmRunSpec())

        // 2: fatal with one. The recording run of the mutated world reports its own split windows.
        val windows = DmCrashRunner(mutant).record().vulnerable
        assertTrue(
            "${mutation.id} never split a transaction: the mutation matched no statement",
            windows.isNotEmpty(),
        )
        var killedAt = -1L
        var failure: Throwable? = null
        for (at in windows) {
            failure = runCatching { DmCrashRunner(mutant).run(DmRunSpec(crashAt = at)) }
                .exceptionOrNull()
            if (failure != null) {
                killedAt = at
                break
            }
        }
        assertKilled(mutation, "${scenario.name} crash@$killedAt", failure, record = false)

        // 3: the same crash point on the unmutated world is green.
        DmCrashRunner(scenario).run(DmRunSpec(crashAt = killedAt))
        // Recorded only now, with the rule it was held to: the control at the same point passed.
        DmKills.record(
            mutation.id,
            deepMessage(requireNotNull(failure)),
            "invisible fault-free, killed under a crash in its split window, beside a clean run " +
                "at the same point",
        )
    }

    /**
     * The kill rule of every mutant S10b registers: detected **fault-free** by the check its entry
     * names, against the clean control — and then detected again **under crashes**, at crash
     * points spread over the scenario, each beside the unmutated scenario crashed at the same
     * point.
     *
     * Why the second half. A mutant killed only by a `finalCheck` is killed only in the one run of
     * an enumeration that injects nothing: every faulted run skips the final checks, because a
     * crash may have lost the step they assert. So "SCN-X detects it" would be a statement about
     * one run out of thousands, and whether the other runs could see the defect at all — through
     * the no-loss and liveness oracles, or the structural invariants — would be unmeasured. Here
     * it is measured, and the unmutated scenario at the same crash point is the control that makes
     * each kill a statement about the mutation and not about the crash point (MC-1's rule).
     *
     * The points are [CRASH_POINTS] indices spread evenly over the events **both** worlds raise —
     * the mutated world diverges from the clean one at the mutation's first effect and may raise
     * fewer events, and a point past its end would never fire and fail the run for a reason that
     * is the harness's. **Every** point must kill: a mutant that survived a crash point would be a
     * crash class in which the enumeration cannot see the defect, which is a finding to record and
     * not a kill to count.
     */
    private fun detectFaultFreeAndUnderCrashes(mutation: DmMutants.Mutation, scenario: DmScenario) {
        requireNative()
        assertTrue("${mutation.id} names no failure under a crash", mutation.expectUnderCrash.isNotEmpty())
        // Half 1: fault-free, against the clean control, with the entry's own final-check message.
        DmCrashRunner(scenario).run(DmRunSpec())
        val mutant = mutated(scenario, mutation)
        val faultFree = runCatching { DmCrashRunner(mutant).run(DmRunSpec()) }.exceptionOrNull()
        assertKilled(mutation, scenario.name, faultFree, record = false)
        val faultFreeMessage = deepMessage(requireNotNull(faultFree))
        println("${mutation.id} killed fault-free by ${scenario.name} (clean passed): $faultFreeMessage")

        // Half 2: at crash points both worlds reach.
        var mutantEvents = 0L
        runCatching { DmCrashRunner(mutant).run(DmRunSpec(onArmedEvents = { mutantEvents = it })) }
        assertTrue("${mutation.id}'s world raised no event", mutantEvents > 0)
        val events = minOf(DmCrashRunner(scenario).record().events, mutantEvents)
        val points = (1..CRASH_POINTS).map { i -> maxOf(1L, events * i / (CRASH_POINTS + 1)) }.distinct()
        val tasks = points.flatMap { at ->
            listOf(
                "${scenario.name} clean crash@$at" to {
                    runCatching { DmCrashRunner(scenario).run(DmRunSpec(crashAt = at)) }.exceptionOrNull()
                },
                "${scenario.name}/${mutation.id} crash@$at" to {
                    runCatching { DmCrashRunner(mutant).run(DmRunSpec(crashAt = at)) }.exceptionOrNull()
                },
            )
        }
        val outcomes = DmHarness.parallel(tasks)
        val kills = ArrayList<String>()
        for ((index, at) in points.withIndex()) {
            val clean = outcomes[2 * index]
            val mutated = outcomes[2 * index + 1]
            assertTrue(
                "the unmutated ${scenario.name} fails at crash@$at, so a kill there proves nothing: " +
                    clean?.let { deepMessage(it) },
                clean == null,
            )
            assertTrue(
                "${mutation.id} survived ${scenario.name} crash@$at: the enumeration cannot see it there",
                mutated is AssertionError,
            )
            val message = deepMessage(requireNotNull(mutated))
            assertTrue(
                "${mutation.id} failed ${scenario.name} crash@$at, but not for a reason its entry " +
                    "names.\n  expected one of: ${mutation.expectUnderCrash}\n  actual: $message",
                mutation.expectUnderCrash.any { message.contains(it) },
            )
            // The evidence, in the test's own output: which oracle killed it at which point.
            println("${mutation.id} killed at ${scenario.name} crash@$at of $events (clean passed): $message")
            kills += "crash@$at"
        }
        DmKills.record(
            mutation.id,
            "$faultFreeMessage | and under a crash at ${kills.joinToString(", ")} " +
                "of $events events, each beside a clean run at the same point",
            // The report prints this, so the rule a kill was held to is in the gate's own
            // evidence: a kill quietly moved back to the fault-free-only rule changes the line,
            // and `dm-report-check.sh` pins the line (S10b review).
            "fault-free and at ${kills.size} of ${points.size} crash points, each beside a clean run",
        )
    }

    /**
     * The kill rule of the suite cases of §22.27, as its review corrected it: S10b's — detected
     * **fault-free** by the check the entry names, beside the clean control, and at [CRASH_POINTS]
     * crash points each beside the unmutated scenario crashed at the same point — with every crash
     * point **inside the transaction the mutant first changes**.
     *
     * That transaction is measured, not guessed. The scenario writes a note, [mark], at the step
     * where the mutant can first change anything (from the bus's own count, so the note is an event
     * index); the rewriting executor records, for every transaction in which the mutation's rewrite
     * changed a statement, the span from that statement's event to the transaction's last event —
     * its post-commit event, or the statement it reached before it rolled back
     * ([DmEventBus.rewrittenSpans]); and the window is the first such span after the mark in the
     * mutated fault-free run. The points are spread over it, both ends included, and a window of
     * [CRASH_POINTS] events or fewer is crashed at every one of its events.
     *
     * Why not the window from the mark to the end of the run, which the first version used. The
     * review measured it: MC-21's only effect is the recipient's first SWEEP after the absence,
     * which committed some 900 events before the first of its six points, so every one of them was
     * the fault-free kill with an unrelated reboot after it; and MC-24's mark is the start of the
     * recipient's pass, so four of its six points fell in that pass's sweep, outcome and inbox
     * peek, before the rewritten read — the crash preceded the defect and the defect then ran
     * unfaulted, which is the statement about recovery this rule exists to avoid (SCN-E's review,
     * §22.25 item 14(e)). A point inside the changed transaction interrupts the defect itself: the
     * transaction rolls back (or, at its post-commit event, has committed and the caller never
     * hears), the node reboots, and the mutated step runs again from what the crash left.
     *
     * The prefix up to the window is the same in both worlds: the rewrites change no statement's
     * result before it (MC-21's changes the text of SWEEP's reads, whose result is unchanged while no
     * key is past its window; MC-24's the text of a read that finds no request until the second
     * identity writes), so the clean scenario crashed at the same index is at the same place until
     * the mutated statement, and inside its own copy of the changed transaction after it.
     */
    private fun detectFaultFreeAndWhereItActs(mutation: DmMutants.Mutation, scenario: DmScenario, mark: String) {
        requireNative()
        assertTrue("${mutation.id} names no failure under a crash", mutation.expectUnderCrash.isNotEmpty())
        // Half 1: fault-free, against the clean control, with the entry's own message.
        val cleanEvents = DmCrashRunner(scenario).run(DmRunSpec()).events
        val mutant = mutated(scenario, mutation)
        var armed: DmArmedPhase? = null
        val faultFree = runCatching {
            DmCrashRunner(mutant).run(DmRunSpec(onArmed = { armed = it }))
        }.exceptionOrNull()
        assertKilled(mutation, scenario.name, faultFree, record = false)
        val faultFreeMessage = deepMessage(requireNotNull(faultFree))
        val phase = requireNotNull(armed) { "${mutation.id}'s world never reached the end of its armed phase" }
        val markAt = requireNotNull(phase.notes[mark] as Long?) {
            "${mutation.id}'s world never reached the step ${scenario.name} marks ($mark)"
        }
        val window = requireNotNull(phase.rewrittenSpans.firstOrNull { it.first > markAt }) {
            "${mutation.id}'s rewrite changed no statement after ${scenario.name}'s mark at event $markAt"
        }
        assertTrue(
            "${mutation.id}'s window $window reaches past the clean run's $cleanEvents events",
            window.last <= cleanEvents,
        )
        println(
            "${mutation.id} killed fault-free by ${scenario.name} (clean passed, $cleanEvents events) at event " +
                "${phase.events}; mark at $markAt, the first transaction it changes spans events " +
                "${window.first}..${window.last}: $faultFreeMessage",
        )

        // Half 2: at crash points spread over the changed transaction, each beside the clean scenario.
        val width = window.last - window.first
        val points = if (width + 1 <= CRASH_POINTS) {
            window.toList()
        } else {
            (0 until CRASH_POINTS).map { i -> window.first + width * i / (CRASH_POINTS - 1) }.distinct()
        }
        val tasks: List<Pair<String, () -> Pair<Throwable?, DmArmedPhase?>>> = points.flatMap { at ->
            listOf(
                "${scenario.name} clean crash@$at" to {
                    val failure = runCatching { DmCrashRunner(scenario).run(DmRunSpec(crashAt = at)) }.exceptionOrNull()
                    failure to null
                },
                "${scenario.name}/${mutation.id} crash@$at" to {
                    var mutatedPhase: DmArmedPhase? = null
                    val failure = runCatching {
                        DmCrashRunner(mutant).run(DmRunSpec(crashAt = at, onArmed = { mutatedPhase = it }))
                    }.exceptionOrNull()
                    failure to mutatedPhase
                },
            )
        }
        val outcomes = DmHarness.parallel(tasks)
        val kills = ArrayList<String>()
        for ((index, at) in points.withIndex()) {
            val (clean, _) = outcomes[2 * index]
            val (mutated, mutatedPhase) = outcomes[2 * index + 1]
            // The clean run passing means its crash fired and rebooted: the runner refuses a run
            // whose planned crash never did (`theRequestedFaultFired`) or whose crash reached no
            // reboot.
            assertTrue(
                "the unmutated ${scenario.name} fails at crash@$at, so a kill there proves nothing: " +
                    clean?.let { deepMessage(it) },
                clean == null,
            )
            assertTrue(
                "${mutation.id} survived ${scenario.name} crash@$at: the enumeration cannot see it there",
                mutated is AssertionError,
            )
            // And the mutated run really **died** before the check that killed it: its crash was
            // injected and reached a reboot. Counting injections alone accepted a crash that
            // `DmActor.runPass` had absorbed into a pass's exception (the review's crash@526 of
            // MC-24): injected, never rebooted, and the kill was the fault-free kill again.
            val phaseAt = requireNotNull(mutatedPhase) { "${mutation.id}'s run at crash@$at never ended its armed phase" }
            assertEquals("${mutation.id}'s run at crash@$at: crashes injected", 1, phaseAt.injected)
            assertEquals("${mutation.id}'s run at crash@$at: crashes that reached a reboot", 1, phaseAt.reboots)
            val message = deepMessage(requireNotNull(mutated))
            assertTrue(
                "${mutation.id} failed ${scenario.name} crash@$at, but not for a reason its entry " +
                    "names.\n  expected one of: ${mutation.expectUnderCrash}\n  actual: $message",
                mutation.expectUnderCrash.any { message.contains(it) },
            )
            println(
                "${mutation.id} killed at ${scenario.name} crash@$at, inside the transaction it first changes " +
                    "(${window.first}..${window.last}; clean passed): $message",
            )
            kills += "crash@$at"
        }
        DmKills.record(
            mutation.id,
            "$faultFreeMessage | and under a crash at ${kills.joinToString(", ")}, inside the transaction " +
                "it first changes after ${scenario.name}'s mark (events ${window.first}..${window.last}), " +
                "each beside a clean run at the same point",
            "fault-free and at ${kills.size} of ${points.size} crash points inside the transaction it first " +
                "changes, each beside a clean run",
        )
    }

    /** One kill: an assertion failure, carrying the message the mutant's entry names, recorded. */
    private fun assertKilled(
        mutation: DmMutants.Mutation,
        where: String,
        failure: Throwable?,
        record: Boolean = true,
        rule: String = DmKills.FAULT_FREE,
        expect: String = mutation.expect,
    ) {
        assertTrue(
            "${mutation.id} survived $where: the mutant is registered but nothing kills it",
            failure is AssertionError,
        )
        val message = failure?.let { deepMessage(it) } ?: ""
        assertTrue(
            "${mutation.id} failed $where, but not for the reason its entry names.\n" +
                "  expected to contain: $expect\n" +
                "  actual: $message",
            message.contains(expect),
        )
        if (record) DmKills.record(mutation.id, message, rule)
    }

    private companion object {
        /** How many crash points the S10b kill rule spreads over a scenario. */
        const val CRASH_POINTS: Int = 6
    }

    /** Every message on the cause chain: `DmHarness.parallel` and JUnit both wrap. */
    private fun deepMessage(failure: Throwable): String =
        generateSequence(failure) { it.cause }.mapNotNull { it.message }.joinToString(" | ")

    /**
     * The same scenario with the mutation installed on every node of its world.
     *
     * The mutation is set on the world before `setup` builds the nodes, because a mutation that
     * arrived after the establishment would be a different world, not the same world with one
     * defect — and §15.7's "a same-scale control world" means the same world.
     */
    private fun mutated(scenario: DmScenario, mutation: DmMutants.Mutation): DmScenario = DmScenario(
        name = "${scenario.name}/${mutation.id}",
        setup = { world ->
            world.mutation = mutation
            scenario.setup(world)
        },
        steps = scenario.steps,
        finalChecks = scenario.finalChecks,
        alwaysChecks = scenario.alwaysChecks,
        doubles = false,
        tailRounds = scenario.tailRounds,
        liveness = scenario.liveness,
        nothingOwed = scenario.nothingOwed,
        expectedFailures = scenario.expectedFailures,
        noLoss = scenario.noLoss,
        declaredLoss = scenario.declaredLoss,
    )
}
