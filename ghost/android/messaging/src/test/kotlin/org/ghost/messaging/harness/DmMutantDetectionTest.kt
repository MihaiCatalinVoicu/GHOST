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

    @Test
    fun me16ReadPathIgnoresExpiryIsDetected() =
        detect(DmMutants.ME16, DmSuiteCases.epExpiredRowsAreNotReadable())

    /**
     * The registry is well formed, and the report's count is armed to be written from the kills.
     *
     * It is deliberately not "57 run, 57 detected". §15.7's set is 97 — 40 privacy, 33 correctness
     * and 24 ephemeral — and this slice registers seven. A gate that printed the design's number
     * while running seven would be the one failure a report-checked gate must not have, which is
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

    /** One kill: an assertion failure, carrying the message the mutant's entry names, recorded. */
    private fun assertKilled(mutation: DmMutants.Mutation, where: String, failure: Throwable?) {
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
        DmKills.record(mutation.id, message)
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
        noLoss = scenario.noLoss,
    )
}
