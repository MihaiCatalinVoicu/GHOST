package org.ghost.messaging.dmworld

import org.ghost.messaging.DmWorld
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.util.concurrent.ConcurrentHashMap

/**
 * Every privacy mutant of [PrivacyMutants], killed by the checks its entry names (Phase 9 design
 * §15.7: "each detected against a same-scale control world").
 *
 * For each killer the **control** — the same check on the same-scale world without the mutant — must
 * pass, and the mutated run must fail with a message containing the killer's `expect`. The controls
 * are computed once per JVM and shared, so the cost is one control per check plus one mutated world
 * per mutant and scale. Every kill is recorded in [PrivacyKills]; the report's lines are written from
 * that record, so an ignored kill lowers the count instead of leaving it standing (S10's `DmKills`
 * rule).
 */
class DmPrivacyMutantTest {

    private fun requireNative() {
        assumeTrue(SKIP, DmWorld.nativeAvailable())
        assumeTrue("-Dghost.dm.privacy=off: the privacy worlds are skipped", PrivacyScale.enabled)
    }

    @Test fun pm2AnAutomaticReceiptIsDetected() = kill(PrivacyMutants.PM2)

    @Test fun pm3APublicNamespaceIsDetected() = kill(PrivacyMutants.PM3)

    @Test fun pm4ABucketFromTheOlmLengthIsDetected() = kill(PrivacyMutants.PM4)

    @Test fun pm5ATtlRoundedToDaysIsDetected() = kill(PrivacyMutants.PM5)

    @Test fun pm6AResetOnAnUndecryptableBlobIsDetected() = kill(PrivacyMutants.PM6)

    @Test fun pm8ARevocationNamespaceIsDetected() = kill(PrivacyMutants.PM8)

    @Test fun pm13ACleartextRecipientIsDetected() = kill(PrivacyMutants.PM13)

    @Test fun pm19RetainedWeekKeysAreDetected() = kill(PrivacyMutants.PM19)

    @Test fun pm24AClientChosenRelaySetIsDetected() = kill(PrivacyMutants.PM24)

    @Test fun pm31UnboundedFetchAttemptsAreDetected() = kill(PrivacyMutants.PM31)

    @Test fun pm36RetainedRecognitionKeysAreDetected() = kill(PrivacyMutants.PM36)

    @Test fun pm39AProvisionalKeyPastItsAnchorBoundIsDetected() = kill(PrivacyMutants.PM39)

    /** The registry is well formed, and the report's lines are armed to be written from the kills. */
    @Test
    fun theRegistryAndTheKillsAgree() {
        requireNative()
        val all = PrivacyMutants.all()
        assertEquals("a mutant id twice", all.size, all.map { it.id }.toSet().size)
        for (mutant in all) {
            assertTrue("${mutant.id} names no killer", mutant.killers.isNotEmpty())
            assertTrue(
                "${mutant.id} mutates nothing",
                mutant.envelopes != null || mutant.crypto != null || mutant.rewrite != null ||
                    mutant.configure != null || mutant.afterWake != null || mutant.afterAdd != null,
            )
        }
        PrivacyKills.arm()
    }

    private fun kill(mutant: PrivacyMutant) {
        requireNative()
        val failures = ArrayList<String>()
        for (killer in mutant.killers) {
            val control = Controls.failure(killer.check)
            assertNull("the control of ${killer.check.label} fails without ${mutant.id}: $control", control)
            val failure = Mutated.failure(mutant, killer.check)
            // Counted once the mutated world has run to its end, whatever the check said.
            PrivacyKills.attempted(mutant.id, killer.check.label)
            if (failure == null) {
                failures += "${mutant.id} survived ${killer.check.label}"
            } else if (!failure.contains(killer.expect)) {
                failures += "${mutant.id} failed ${killer.check.label}, but not for the reason its entry names.\n" +
                    "  expected to contain: ${killer.expect}\n  actual: ${failure.take(2_000)}"
            } else if (killer.refuse != null && failure.contains(killer.refuse)) {
                // The check failed for the named reason and also because the mutated world did not
                // reach what the check needs (an NI-DM2 twin that stored nothing): not a kill.
                failures += "${mutant.id} failed ${killer.check.label}, but its world did not reach what the check " +
                    "needs.\n  must not contain: ${killer.refuse}\n  actual: ${failure.take(2_000)}"
            } else {
                PrivacyKills.record(mutant.id, killer.check.label, failure)
                // The killing failure, in the test's own output: what the check saw, not only that
                // it failed (§22.21).
                println("${mutant.id} killed by ${killer.check.label}: ${failure.take(1_500)}")
            }
        }
        assertTrue(failures.joinToString("\n"), failures.isEmpty())
    }

    /** The checks' outcomes on the unmutated worlds, once per JVM. */
    private object Controls {
        private val cache = ConcurrentHashMap<PrivacyCheck, Result<String?>>()

        fun failure(check: PrivacyCheck): String? =
            cache.computeIfAbsent(check) { runCatching { Checks.run(check, null) } }.getOrThrow()
    }

    /** The checks' outcomes on one mutant's worlds; one SMALL world serves every join of a mutant. */
    private object Mutated {
        fun failure(mutant: PrivacyMutant, check: PrivacyCheck): String? = Checks.run(check, mutant)
    }

    private companion object {
        const val SKIP = "set -Dghost.dm.native to the ghost-dm-host library: every privacy world runs the real stack"
    }
}

/** The worlds each [PrivacyCheck] runs on, and the failure message it produces (null: passed). */
internal object Checks {

    private val seed: Long = PrivacySeeds.ALL[0]

    /** One SMALL world per mutant (null: the control), with every join computed on it. */
    private val smallJoins = ConcurrentHashMap<String, Map<PrivacyCheck, JoinResult>>()

    fun run(check: PrivacyCheck, mutant: PrivacyMutant?): String? = when (check) {
        PrivacyCheck.JD1, PrivacyCheck.JD2, PrivacyCheck.JD4, PrivacyCheck.JD5, PrivacyCheck.JD6, PrivacyCheck.JD7,
        PrivacyCheck.JD9,
        -> {
            val result = small(mutant).getValue(check)
            if (result.passed) null else result.failureMessage()
        }
        PrivacyCheck.JD7_WITHHOLD -> withheld(mutant).let { if (it.passed) null else it.failureMessage() }
        PrivacyCheck.NI_DM1 -> NiDm1.run(seed, mutant).let { if (it.passed) null else it.line() }
        PrivacyCheck.NI_DM2 -> NiDm2.run(seed, mutant).let { if (it.passed) null else it.line() }
        PrivacyCheck.NI_DM3 -> NiDm3.run(seed, mutant).let { if (it.passed) null else it.line() }
        PrivacyCheck.S_DM3 -> PrivacyWorld(PrivacyWorldConfig.of(PrivacyScale.MEDIUM, seed, mutant)).use { world ->
            world.run()
            Sdm3.run(world, seed).let { if (it.passed) null else it.line() }
        }
        PrivacyCheck.T34 -> Seizure.seize(Seizure.config(seed, mutant)).let { if (it.passed) null else it.line() }
        PrivacyCheck.T34_ONE_REPLY -> Seizure.oneReply(seed, mutant).let { if (it.passed) null else it.line() }
    }

    private fun small(mutant: PrivacyMutant?): Map<PrivacyCheck, JoinResult> =
        smallJoins.computeIfAbsent(mutant?.id ?: "control") {
            PrivacyWorld(PrivacyWorldConfig.of(PrivacyScale.SMALL, seed, mutant)).use { world ->
                world.run()
                val joins = Joins(world)
                val out = mapOf(
                    PrivacyCheck.JD1 to joins.jd1(),
                    PrivacyCheck.JD2 to joins.jd2(),
                    PrivacyCheck.JD4 to joins.jd4(),
                    PrivacyCheck.JD5 to joins.jd5(),
                    PrivacyCheck.JD6 to joins.jd6(),
                    PrivacyCheck.JD7 to joins.jd7(),
                    PrivacyCheck.JD9 to joins.jd9(),
                )
                // PM-4 lives in R-B1's 16 KiB class, so a control world that drew no body there
                // could not tell a live JD4 from a dead one; PM-5 lives in the 1-hour bucket, so a
                // control whose users set no 5-minute or 1-hour timer could not tell a live JD5.
                if (mutant == null) {
                    val boundary = world.truth.bodyLengthOfBlob.values.count { it in 2_221..14_508 }
                    check(boundary > 0) { "the SMALL control drew no body in R-B1's 16 KiB class" }
                    val hourTexts = world.relay.events.count { e ->
                        e.op == ViewOp.STORE && e.ttlSeconds == 3_600L &&
                            e.cause?.messageRef?.let { Joins.hex(it) in world.userTexts } == true
                    }
                    check(hourTexts > 0) { "the SMALL control stored no user text in the 1-hour bucket" }
                }
                out
            }
        }

    /** One WITHHOLD_ALL_BUNDLES SMALL world per mutant (null: the control), for the JD7 variant. */
    private val withheldJoins = ConcurrentHashMap<String, JoinResult>()

    fun withheld(mutant: PrivacyMutant?): JoinResult =
        withheldJoins.computeIfAbsent(mutant?.id ?: "control") {
            PrivacyWorld(PrivacyWorldConfig.of(PrivacyScale.SMALL, seed, mutant, withholdAllBundles = true)).use { world ->
                world.run()
                Joins(world).jd7Withheld()
            }
        }
}

/**
 * The privacy kills a run performed, and the only source of the report's `dm privacy mutant` lines
 * (the `DmKills` rule of S10: a count written from the registry is a number no run measured).
 */
internal object PrivacyKills {

    /** `mutant id → (killer label → failure)`. */
    private val kills = ConcurrentHashMap<String, MutableMap<String, String>>()

    /** `mutant id → killer labels whose mutated world actually ran` (the "run" count). */
    private val attempts = ConcurrentHashMap<String, MutableSet<String>>()

    @Volatile
    private var armed = false

    fun attempted(id: String, check: String) {
        attempts.computeIfAbsent(id) { ConcurrentHashMap.newKeySet() } += check
    }

    fun record(id: String, check: String, failure: String) {
        kills.computeIfAbsent(id) { ConcurrentHashMap() }[check] = failure
    }

    @Synchronized
    fun arm() {
        if (armed) return
        armed = true
        Runtime.getRuntime().addShutdownHook(Thread { write() })
    }

    /**
     * A mutant counts as **run** only when a mutated world ran for every killer its entry names, and
     * as detected only when every one of them recorded a kill — both from what this JVM did, never
     * from the registry — so a mutant whose test was skipped or whose second check was quietly lost
     * lowers the numbers and prints NOT DETECTED.
     */
    private fun write() {
        val registered = PrivacyMutants.all()
        val ran = registered.filter { m -> m.killers.all { it.check.label in attempts[m.id].orEmpty() } }
        val detected = registered.filter { m ->
            val done = kills[m.id].orEmpty()
            m.killers.all { it.check.label in done }
        }
        PrivacyReport.line("dm privacy mutants: ${ran.size} run, ${detected.size} detected")
        for (m in registered) {
            val done = kills[m.id].orEmpty()
            if (m in detected) {
                PrivacyReport.line(
                    "dm privacy mutant ${m.id}: detected by ${m.killers.joinToString(", ") { it.check.label }}" +
                        (m.scope?.let { "; $it" } ?: ""),
                )
            } else {
                val missing = m.killers.filter { it.check.label !in done }.joinToString(", ") { it.check.label }
                PrivacyReport.line("dm privacy mutant ${m.id}: NOT DETECTED by $missing")
            }
        }
    }
}
