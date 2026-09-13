package org.ghost.entitlement.harness

import org.ghost.entitlement.api.ActivationState
import org.ghost.sync.harness.JournalMode
import org.ghost.sync.harness.RunSpec
import org.ghost.sync.harness.Runner
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Every `:entitlement` scenario runs fault-free to quiescence with the real engine, the real sync
 * engine, the model issuer and the model redeem relays (design §13.2); the scenario's own outcome is
 * checked here, at its end. The crash enumeration of the same scenarios is [EntitlementExhaustiveTest].
 */
class EntitlementScenarioTest {

    private fun faultFree(s: EntScenario, check: (EntScenario) -> Unit) {
        s.outcome = check
        Runner(s, JournalMode.WAL).run(RunSpec())
    }

    private fun EntScenario.count(sql: String): Long {
        var n = 0L
        alice.c.jdbc.query(sql) { n = it.long(0) }
        return n
    }

    private fun EntScenario.calls(name: String): Int = ent.records.issuerLog.count { it.contains("|$name|") }

    @Test
    fun eA_aPackPaidInXmrFundsTheWritesOfItsFirstNeeds() = faultFree(ScenarioEA()) { s ->
        assertEquals(listOf("pack" to "finalized"), s.alice.purchaseStates())
        assertEquals("both relays of the namespace redeemed once", 2, s.ent.records.minted.size)
        assertEquals("5 weeks x 3 slots x 4 + 2 invites + 1 credit", 63, s.ent.records.issued.size)
        assertEquals(1, s.calls("blindSign"))
    }

    @Test
    fun eB_anUnderpaidInvoiceIsSignedAtTheNextPlannedAttemptAfterTheTopUp() = faultFree(ScenarioEB()) { s ->
        assertEquals(listOf("pack" to "finalized"), s.alice.purchaseStates())
        assertEquals("UNDERPAID, then SIGNED", 2, s.calls("blindSign"))
        assertEquals(2, s.ent.records.minted.size)
    }

    @Test
    fun eC_anUnpaidInvoiceExpiresAtThePlannedAttemptAfterTheGraceWindow() = faultFree(ScenarioECExpired()) { s ->
        assertEquals(listOf("pack" to "expired"), s.alice.purchaseStates())
        assertEquals(3, s.calls("blindSign"))
        assertTrue(s.ent.records.issued.isEmpty())
    }

    @Test
    fun eC_anInvoiceThatNeverTurnsFinalIsLostAfterFiveAttempts() = faultFree(ScenarioECLost()) { s ->
        assertEquals(listOf("pack" to "lost"), s.alice.purchaseStates())
        assertEquals("the J9 cap", 5, s.calls("blindSign"))
        assertEquals(1, s.calls("requestInvoice"))
    }

    @Test
    fun eD_aPackPaidWithTenCreditsSpendsThem() = faultFree(ScenarioED()) { s ->
        assertEquals(listOf("pack" to "finalized"), s.alice.purchaseStates())
        assertEquals(0L, s.count("SELECT count(*) FROM ent_token WHERE kind = 'credit'"))
        assertEquals("5 weeks x 3 slots x 4 + 2 invites, no credit", 62 + 10, s.ent.records.issued.size)
        assertEquals(2, s.ent.records.minted.size)
    }

    @Test
    fun eE_anActivatedInviteFundsTheFirstWritesWithItsTrial() = faultFree(ScenarioETrial()) { s ->
        assertTrue(s.alice.identity.exists)
        assertEquals(listOf("trial" to "finalized"), s.alice.purchaseStates())
        assertEquals(ActivationState.ACTIVE, s.alice.e().activationState())
        assertEquals(2, s.ent.records.minted.size)
    }

    @Test
    fun eE_aReplayedInviteWipesTheIdentity() = faultFree(ScenarioEWipe()) { s ->
        assertFalse(s.alice.identity.exists)
        assertEquals(listOf("trial" to "failed"), s.alice.purchaseStates())
        assertEquals(ActivationState.FAILED, s.alice.e().activationState())
        assertTrue(s.ent.records.issued.isEmpty())
    }

    @Test
    fun eF_exhaustedAndRejectedCapabilitiesAreRedeemedAgainAcrossTheWeekBoundary() = faultFree(ScenarioEF()) { s ->
        assertTrue("first redemptions, EXHAUSTED, REJECTED and renewals: ${s.ent.records.minted.size}", s.ent.records.minted.size >= 4)
        assertTrue("tokens of the next week were spent", s.ent.records.relayLog.size >= 4)
    }

    @Test
    fun eG_theDropIsWrittenAtItsMinuteAndAReceivedCreditIsRefreshed() = faultFree(ScenarioEG()) { s ->
        assertEquals(0L, s.count("SELECT count(*) FROM ent_drop_target"))
        assertEquals(1L, s.count("SELECT count(*) FROM ent_invite WHERE state = 'credited'"))
        assertEquals(listOf("refresh" to "finalized"), s.alice.purchaseStates())
        assertEquals("the refreshed credit (the own one went to the inviter)", 1L, s.count("SELECT count(*) FROM ent_token WHERE kind = 'credit'"))
        assertEquals(1, s.calls("refreshCredit"))
    }

    @Test
    fun eH_aClaimIsQueuedAndItsCreditsAreGone() = faultFree(ScenarioEH()) { s ->
        assertEquals(1L, s.count("SELECT count(*) FROM ent_claim WHERE state = 'queued'"))
        assertEquals(0L, s.count("SELECT count(*) FROM ent_token WHERE kind = 'credit'"))
        assertEquals(1L, s.count("SELECT count(*) FROM ent_payout_used"))
        assertEquals(1, s.calls("claimPayout"))
    }

    @Test
    fun eI_aWrongPeriodClosesTheFlowAndItsSuccessorIsInvoiced() = faultFree(ScenarioEI()) { s ->
        assertEquals(listOf("failed", "finalized"), s.alice.purchaseStates().map { it.second }.sorted())
        assertEquals(2, s.calls("requestInvoice"))
        assertEquals(1, s.ent.issuer.history.size)
    }
}
