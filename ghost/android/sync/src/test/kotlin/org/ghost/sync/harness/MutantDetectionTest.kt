package org.ghost.sync.harness

import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.TtlBucket
import org.junit.AfterClass
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Negative fixtures (design §8.8): each of the thirteen mutant engines runs the scenario that must
 * expose it, and the harness must report the expected kind of failure. The same scenario with the
 * real engine passes (fault-free here; its full enumeration runs in [ExhaustiveScenarioTest]).
 */
class MutantDetectionTest {

    /** Runs [block]; returns the failure's full message chain, or fails the test if nothing was reported. */
    private fun detected(mutant: String, block: () -> Unit): String {
        try {
            block()
        } catch (e: Throwable) {
            val chain = generateSequence(e) { it.cause }.joinToString(" <- ") { "${it.javaClass.simpleName}: ${it.message}" }
            HarnessReport.add("$mutant DETECTED: ${chain.take(300)}")
            return chain
        }
        fail("$mutant was not detected")
        error("unreachable")
    }

    private fun faultFree(scenario: Scenario) {
        Runner(scenario, JournalMode.WAL).run(RunSpec())
    }

    private fun <S : Scenario> mutated(factory: () -> S, mutation: Mutation): () -> S = { factory().also { it.mutation = mutation } }

    private fun expect(chain: String, vararg keywords: String) {
        assertTrue("unexpected failure: $chain", keywords.any { chain.contains(it) })
    }

    @Test
    fun m1_cursorFirst() {
        faultFree(ScenarioB(PrivacyMode.STANDARD))
        val chain = detected("M1 CursorFirst") { Exhaustive.run("M1", mutated({ ScenarioB(PrivacyMode.STANDARD) }, Mutants.M1), JournalMode.WAL, doubles = false) }
        expect(chain, "IN-3")
    }

    @Test
    fun m2_quorumOnAck() {
        faultFree(ScenarioG())
        val chain = detected("M2 QuorumOnAck") { faultFree(mutated({ ScenarioG() }, Mutants.M2)()) }
        expect(chain, "verified operator(s) (OUT-4)")
    }

    @Test
    fun m3_reencryptOnRetry() {
        faultFree(ScenarioG())
        val chain = detected("M3 ReencryptOnRetry") { faultFree(mutated({ ScenarioG() }, Mutants.M3)()) }
        expect(chain, "OUT-3")
    }

    @Test
    fun m4_consumeOutsideTransaction() {
        faultFree(ScenarioB(PrivacyMode.STANDARD))
        val chain = detected("M4 ConsumeOutsideTx") { Exhaustive.run("M4", mutated({ ScenarioB(PrivacyMode.STANDARD) }, Mutants.M4), JournalMode.WAL, doubles = false) }
        expect(chain, "IN-1")
    }

    @Test
    fun m5_ackOnAnyResponse() {
        faultFree(ScenarioG())
        val chain = detected("M5 AckOnAnyResponse") { faultFree(mutated({ ScenarioG() }, Mutants.M5)()) }
        expect(chain, "acked ⇒ membership")
    }

    @Test
    fun m6_dedupByHashOnly() {
        faultFree(ScenarioCrossNamespace())
        val chain = detected("M6 DedupByHashOnly") { faultFree(mutated({ ScenarioCrossNamespace() }, Mutants.M6)()) }
        expect(chain, "IN-1")
    }

    @Test
    fun m7_emptyCursorStored() {
        faultFree(ScenarioLyingExpiry())
        val chain = detected("M7 EmptyCursorStored") { faultFree(mutated({ ScenarioLyingExpiry() }, Mutants.M7)()) }
        expect(chain, "oracle_consumed", "IN-2")
    }

    @Test
    fun m8_retainByFirstSeen() {
        faultFree(ScenarioLongTtl())
        val chain = detected("M8 RetainByFirstSeen") { faultFree(mutated({ ScenarioLongTtl() }, Mutants.M8)()) }
        expect(chain, "retention")
    }

    @Test
    fun m9_noGenerationGuard() {
        faultFree(ScenarioD())
        val chain = detected("M9 NoGenerationGuard") { faultFree(mutated({ ScenarioD() }, Mutants.M9)()) }
        expect(chain, "never refused that token", "wait for a capability")
    }

    @Test
    fun m10_failIgnoringCopies() {
        faultFree(ScenarioF(true, 40, TtlBucket.DAYS_7))
        val chain = detected("M10 FailIgnoringCopies") { faultFree(mutated({ ScenarioF(true, 40, TtlBucket.DAYS_7) }, Mutants.M10)()) }
        expect(chain, "failed-but-delivered")
    }

    @Test
    fun m11_noStoreWindow() {
        faultFree(ScenarioF(true, 40, TtlBucket.DAYS_7))
        val chain = detected("M11 NoStoreWindow") { faultFree(mutated({ ScenarioF(true, 40, TtlBucket.DAYS_7) }, Mutants.M11)()) }
        expect(chain, "store window", "oracle_consumed", "retention")
    }

    @Test
    fun m12_noLeaseNormalization() {
        val chain = detected("M12 NoLeaseNormalization") { Exhaustive.run("M12", mutated({ ScenarioA() }, Mutants.M12), JournalMode.WAL, doubles = false) }
        expect(chain, "no quiescence", "OUT-1", "OUT-4")
    }

    @Test
    fun m13_sharedTick() {
        PairIndependence.check(null)
        val chain = detected("M13 SharedTick") { PairIndependence.check(Mutants.M13) }
        expect(chain, "share")
    }

    companion object {
        @JvmStatic
        @AfterClass
        fun report() {
            HarnessReport.add("mutants: 13 run")
        }
    }
}
