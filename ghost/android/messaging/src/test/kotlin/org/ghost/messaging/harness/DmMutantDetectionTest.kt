package org.ghost.messaging.harness

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
 * MC-12 is killed in `DmPoisonTest`, which is where the native-crash loop lives. Every kill, here
 * and there, records itself in [DmKills], and the report's `dm mutants:` lines are written from
 * that record — not from the registry — so an ignored kill lowers the count.
 */
class DmMutantDetectionTest {

    private fun requireNative() = assumeTrue(DmHarness.SKIP_MESSAGE, DmHarness.nativeAvailable())

    @Test
    fun mc1SplitSendTransactionIsDetectedOnlyByACrash() = detectUnderCrash(DmMutants.MC1, DmScenarios.scnA())

    @Test
    fun mc5D3OffIsDetected() = detect(DmMutants.MC5, DmSuiteCases.rp6ReEncryptionAfterAWronglyReportedFailure())

    @Test
    fun mc7D2bOffIsDetected() = detect(DmMutants.MC7, DmSuiteCases.cbRejectedRequestStaysRejected())

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

    /** S10b: SWEEP erases the out key a FAILED item of an earlier week still needs. */
    @Test
    fun mc33RetryWithoutTheAuthorWeekKeyIsDetected() =
        detectFaultFreeAndUnderCrashes(DmMutants.MC33, DmScenarios.scnGWeek())

    @Test
    fun me16ReadPathIgnoresExpiryIsDetected() =
        detect(DmMutants.ME16, DmSuiteCases.epExpiredRowsAreNotReadable())

    /**
     * The registry is well formed, and the report's count is armed to be written from the kills.
     *
     * It is deliberately not "57 run, 57 detected". §15.7's set is 97 — 40 privacy, 33 correctness
     * and 24 ephemeral — and S10 and S10b register ten. A gate that printed the design's number
     * while running ten would be the one failure a report-checked gate must not have, which is
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
                "${mutant.id} has no rewrite, no decorator and no split: it mutates nothing",
                mutant.rewrite != null || mutant.decorate != null || mutant.defer != null,
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
        assertKilled(mutation, scenario.name, failure)
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
        assertKilled(mutation, "${scenario.name} crash@$killedAt", failure)

        // 3: the same crash point on the unmutated world is green.
        DmCrashRunner(scenario).run(DmRunSpec(crashAt = killedAt))
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
        )
    }

    /** One kill: an assertion failure, carrying the message the mutant's entry names, recorded. */
    private fun assertKilled(
        mutation: DmMutants.Mutation,
        where: String,
        failure: Throwable?,
        record: Boolean = true,
    ) {
        assertTrue(
            "${mutation.id} survived $where: the mutant is registered but nothing kills it",
            failure is AssertionError,
        )
        val message = failure?.let { deepMessage(it) } ?: ""
        assertTrue(
            "${mutation.id} failed $where, but not for the reason its entry names.\n" +
                "  expected to contain: ${mutation.expect}\n" +
                "  actual: $message",
            message.contains(mutation.expect),
        )
        if (record) DmKills.record(mutation.id, message)
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
        livenessInTurn = scenario.livenessInTurn,
        noLoss = scenario.noLoss,
        declaredLoss = scenario.declaredLoss,
    )
}
