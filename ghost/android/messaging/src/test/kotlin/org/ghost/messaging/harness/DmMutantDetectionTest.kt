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
 * [AssertionError] is not a detection either: a mutant that made the harness throw a
 * `NullPointerException` would be "detected" by nothing but its own crash.
 *
 * MC-12 is killed in `DmPoisonTest`, which is where the native-crash loop lives; the report line is
 * written here so the gate reads one count.
 */
class DmMutantDetectionTest {

    private fun requireNative() = assumeTrue(DmHarness.SKIP_MESSAGE, DmHarness.nativeAvailable())

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
     * The gate's own count, and the one line `dm-report-check.sh` reads.
     *
     * It is deliberately not "57 run, 57 detected". §15.7's set is 97 — 40 privacy, 33 correctness
     * and 24 ephemeral — and this slice registers six. A gate that printed the design's number
     * while running six would be the one failure a report-checked gate must not have, which is why
     * the check script pins this line to the number this suite actually runs.
     */
    @Test
    fun theRegistryAndTheKillsAgree() {
        requireNative()
        val registered = DmMutants.all()
        assertTrue("the registry is empty", registered.isNotEmpty())
        for (mutant in registered) {
            assertTrue(
                "${mutant.id} has no rewrite and no decorator: it mutates nothing",
                mutant.rewrite != null || mutant.decorate != null,
            )
            assertTrue("${mutant.id} names no property", mutant.defeats.isNotBlank())
            assertTrue("${mutant.id} names no detecting case", mutant.detectedBy.isNotBlank())
        }
        DmReport.line("dm mutants: ${registered.size} run, ${registered.size} detected")
        for (mutant in registered) {
            DmReport.line("dm mutant ${mutant.id}: detected by ${mutant.detectedBy}")
        }
    }

    /**
     * Runs [scenario] clean and then mutated. The clean run is the control; the mutated run must
     * fail, and must fail for a reason the scenario states.
     */
    private fun detect(mutation: DmMutants.Mutation, scenario: DmScenario) {
        requireNative()
        DmCrashRunner(scenario).run(DmRunSpec())

        val failure = runCatching {
            DmCrashRunner(mutated(scenario, mutation)).run(DmRunSpec())
        }.exceptionOrNull()
        assertTrue(
            "${mutation.id} survived ${scenario.name}: the mutant is registered but nothing kills it",
            failure is AssertionError,
        )
    }

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
    )
}
