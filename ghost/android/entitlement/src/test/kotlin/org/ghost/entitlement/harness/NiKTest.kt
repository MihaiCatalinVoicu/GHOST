package org.ghost.entitlement.harness

import org.ghost.sync.harness.Harness
import org.ghost.sync.harness.HarnessReport
import org.junit.Test

/**
 * NI-K on the real Kotlin engine (Phase 8 design §13.4, §19.14): the production `QuietRunScheduler`
 * and `EntitlementEngine` satisfy R1 and R6 exactly in the NI-K worlds of [NiK], for every pinned seed.
 *  - NI-1 within one L-cell: another issuer seed and pool minors, answers after up to 30 s, the first
 *    `BlindSign` answered UNAVAILABLE instead of AWAITING_PAYMENT, the payment 30 minutes later:
 *    the relay-facing calls are identical (whole runs when the tokens activate alike);
 *  - NI-1 across cells: the first `RequestInvoice` answered UNAVAILABLE (the invoice a day later, the
 *    pack signed days later): identical before the earlier activation start;
 *  - NI-2: one more namespace, more writes and more inbound blobs: the issuer calls are identical.
 */
class NiKTest {

    private fun each(label: String, check: (Long) -> String) {
        val lines = Harness.parallel((1L..SEEDS).map { seed -> Pair("$label seed $seed") { check(seed) } })
        HarnessReport.add("NI-K $label: ${lines.size} seeds identical (${lines.joinToString("; ")})")
    }

    @Test
    fun ni1_issuerVariationsWithinOneLCellLeaveTheRelayViewIdentical() = each("NI-1 same L-cell") { seed -> NiK.ni1(seed, NiK.BASE, NiK.SAME_CELL) }

    @Test
    fun ni1_beforeTheEarlierActivationTheRelayViewIsIdentical() = each("NI-1 across L-cells") { seed -> NiK.ni1(seed, NiK.PROMPT, NiK.PROMPT_VARIED) }

    @Test
    fun ni2_namespacesAndRelayActivityLeaveTheIssuerViewIdentical() = each("NI-2") { seed -> NiK.ni2(seed, NiK.BASE, NiK.BUSY) }

    private companion object {
        const val SEEDS = 8L
    }
}
