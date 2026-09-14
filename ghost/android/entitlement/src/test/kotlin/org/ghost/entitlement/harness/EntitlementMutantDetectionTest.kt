package org.ghost.entitlement.harness

import org.ghost.sync.harness.HarnessReport
import org.ghost.sync.harness.JournalMode
import org.ghost.sync.harness.RunSpec
import org.ghost.sync.harness.Runner
import org.junit.AfterClass
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Negative fixtures of the `:entitlement` harness (Phase 8 design §13.5, the Phase 7
 * `MutantDetectionTest` pattern): each client mutant EM1–EM9 runs the world that must expose it, and
 * the harness must report the expected kind of failure (a trigger, a commit check, RED-2, MS-6, the
 * amount check); M3, M8 and M20 run the NI-K comparisons. The S9c review added four fixtures for what
 * the harness checks beyond them (MS-6 of issued and never-delivered invoices, the accounting of CREDIT
 * and INVITE tokens, the `request_id` in NI-1), and the restore-scan review one more (a credit sealed
 * into a listened drop is accounted in every run, not only by E-J's fault-free outcome check). The same
 * world with the real engine passes first (EM8's in hostile-issuer mode).
 */
class EntitlementMutantDetectionTest {

    /** Runs [block]; returns the failure's full message chain, or fails the test if nothing was reported. */
    private fun detected(mutant: EntMutant, block: () -> Unit): String {
        try {
            block()
        } catch (e: Throwable) {
            val chain = generateSequence(e) { it.cause }.joinToString(" <- ") { "${it.javaClass.simpleName}: ${it.message}" }
            HarnessReport.add("${mutant.name} DETECTED: ${chain.take(300)}")
            return chain
        }
        fail("${mutant.name} was not detected")
        error("unreachable")
    }

    private fun run(s: EntScenario) {
        Runner(s, JournalMode.WAL).run(RunSpec())
    }

    private fun <S : EntScenario> S.with(m: EntMutant): S = also { it.mutant = m }

    private fun expect(chain: String, vararg keywords: String) {
        assertTrue("unexpected failure: $chain", keywords.any { chain.contains(it) })
    }

    @Test
    fun em1_newSeedOnRetry() {
        run(ScenarioEB())
        expect(detected(EntMutants.EM1) { run(ScenarioEB().with(EntMutants.EM1)) }, "frozen once sent")
    }

    @Test
    fun em2_releaseReservation() {
        run(ScenarioEA())
        expect(detected(EntMutants.EM2) { run(ScenarioEA().with(EntMutants.EM2)) }, "ends only by deletion")
    }

    @Test
    fun em3_putOutsideTransaction() {
        run(ScenarioEA())
        expect(detected(EntMutants.EM3) { run(ScenarioEA().with(EntMutants.EM3)) }, "installed while its token is still held")
    }

    @Test
    fun em4_redeemOtherRelayOnTimeout() {
        run(ScenarioEM4())
        expect(detected(EntMutants.EM4) { run(ScenarioEM4().with(EntMutants.EM4)) }, "RED-2")
    }

    @Test
    fun em5_sendBeforeWriteAhead() {
        run(ScenarioEA(writes = false))
        expect(detected(EntMutants.EM5) { run(ScenarioEA(writes = false).with(EntMutants.EM5)) }, "MS-6")
    }

    @Test
    fun em6_wipeBeforeFinalize() {
        run(ScenarioEM6())
        expect(detected(EntMutants.EM6) { run(ScenarioEM6().with(EntMutants.EM6)) }, "MS-6")
    }

    @Test
    fun em7_layoutChangedAfterSend() {
        run(ScenarioEB())
        expect(detected(EntMutants.EM7) { run(ScenarioEB().with(EntMutants.EM7)) }, "frozen once sent")
    }

    @Test
    fun em8_trustIssuerAmount() {
        run(ScenarioEM8().with(EntMutants.HOSTILE_ISSUER))
        expect(detected(EntMutants.EM8) { run(ScenarioEM8().with(EntMutants.EM8)) }, "the issuer's amount was trusted")
    }

    @Test
    fun em9_claimAddressChangedOnRetry() {
        run(ScenarioEM9())
        expect(detected(EntMutants.EM9) { run(ScenarioEM9().with(EntMutants.EM9)) }, "keeps its address")
    }

    @Test
    fun m3_immediateEligible() {
        NiK.ni1(1, NiK.PROMPT, NiK.PROMPT_VARIED)
        expect(detected(EntMutants.M3) { for (seed in 1L..3L) NiK.ni1(seed, NiK.PROMPT, NiK.PROMPT_VARIED, EntMutants.M3) }, "NI-1")
    }

    @Test
    fun m8_variableCounts() {
        NiK.ni2(1, NiK.BASE, NiK.BUSY)
        expect(detected(EntMutants.M8) { NiK.ni2(1, NiK.BASE, NiK.BUSY, EntMutants.M8) }, "NI-2")
    }

    @Test
    fun m20_quietWhenWorkDue() {
        NiK.ni1(1, NiK.PROMPT, NiK.PROMPT_VARIED)
        expect(detected(EntMutants.M20) { for (seed in 1L..3L) NiK.ni1(seed, NiK.PROMPT, NiK.PROMPT_VARIED, EntMutants.M20) }, "NI-1")
    }

    @Test
    fun giveUpAfterLostSign() {
        run(ScenarioLostSign())
        expect(detected(EntMutants.GIVE_UP_AFTER_LOST_SIGN) { run(ScenarioLostSign().with(EntMutants.GIVE_UP_AFTER_LOST_SIGN)) }, "MS-6")
    }

    @Test
    fun noRequestInvoiceRetry() {
        run(ScenarioLostRequest())
        expect(detected(EntMutants.NO_REQUEST_INVOICE_RETRY) { run(ScenarioLostRequest().with(EntMutants.NO_REQUEST_INVOICE_RETRY)) }, "MS-6")
    }

    @Test
    fun loseCreditAndInviteTokens() {
        run(ScenarioEM6())
        expect(detected(EntMutants.LOSE_CREDIT_AND_INVITE_TOKENS) { run(ScenarioEM6().with(EntMutants.LOSE_CREDIT_AND_INVITE_TOKENS)) }, "token accounting")
    }

    @Test
    fun loseReceivedDropCredit() {
        run(ScenarioEJ())
        expect(detected(EntMutants.LOSE_RECEIVED_DROP_CREDIT) { run(ScenarioEJ().with(EntMutants.LOSE_RECEIVED_DROP_CREDIT)) }, "drop credit")
    }

    @Test
    fun requestIdFromIssuerState() {
        NiK.ni1(1, NiK.PROMPT, NiK.PROMPT_VARIED)
        expect(
            detected(EntMutants.REQUEST_ID_FROM_ISSUER_STATE) { for (seed in 1L..3L) NiK.ni1(seed, NiK.PROMPT, NiK.PROMPT_VARIED, EntMutants.REQUEST_ID_FROM_ISSUER_STATE) },
            "NI-1",
        )
    }

    companion object {
        @JvmStatic
        @AfterClass
        fun report() {
            HarnessReport.add(
                "entitlement mutants: 17 run (EM1-EM9, M3, M8, M20; review fixtures GiveUpAfterLostSign, NoRequestInvoiceRetry, " +
                    "LoseCreditAndInviteTokens, RequestIdFromIssuerState, LoseReceivedDropCredit)",
            )
        }
    }
}
