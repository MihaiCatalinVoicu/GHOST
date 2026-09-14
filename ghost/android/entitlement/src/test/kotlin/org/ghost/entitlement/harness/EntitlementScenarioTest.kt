package org.ghost.entitlement.harness

import org.ghost.entitlement.api.ActivationState
import org.ghost.entitlement.engine.Grid
import org.ghost.entitlement.engine.Layouts
import org.ghost.network.EntitlementCrypto
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

    @Test
    fun eJ_aRestoredIdentityGetsTheCreditOfAPreRestoreInviteAndTheScanEnds() = faultFree(ScenarioEJ()) { s ->
        assertEquals(listOf("restore"), s.alice.identity.log)
        assertEquals(1, s.calls("refreshCredit"))
        assertEquals("the refresh flow finalized", listOf("finalized"), s.ent.records.ended.values.toList())
        assertTrue("GC deleted its terminal row a week later", s.alice.purchaseStates().isEmpty())
        assertEquals("the refreshed credit", 1L, s.count("SELECT count(*) FROM ent_token WHERE kind = 'credit'"))
        assertEquals("read capabilities of the 8 drops at the 3 slot relays", 24, s.ent.records.minted.size)
        assertEquals("the scan ended", 1L, s.count("SELECT count(*) FROM ent_state WHERE restore_scan_until_day IS NULL"))
        assertEquals(0L, s.count("SELECT count(*) FROM ent_invite WHERE state <> 'closed'"))
        assertEquals(0L, s.count("SELECT count(*) FROM sync_namespace WHERE consumer = 'identity' AND listening = 1"))
        assertEquals("new invites start after the scanned indices", 8L, s.count("SELECT next_invite_index FROM ent_state"))
    }

    @Test
    fun q29_aClientWhoseCapabilitiesAllLapsedRecoversInTheBackground() = faultFree(ScenarioLapsed()) { s ->
        assertEquals("no foreground ever ran", Long.MIN_VALUE, s.alice.c.foregroundUntil)
        assertEquals("A and B redeemed once each, in background sessions", 2, s.ent.records.minted.size)
        assertEquals(0L, s.count("SELECT count(*) FROM outbox_op WHERE released = 0"))
    }

    /**
     * Q30 (design §17, §19.23 point 5), harness seed 3819: a HIGH-mode invitee whose trial's activation
     * slot, with uncapped Geometric(1/2) extra days, fell after both trial weeks, so the trial was never
     * usable and the invitee had to buy a pack. With the cap, every trial token is eligible on a day of
     * the trial's last week at the latest (before 06:00 of its Sunday).
     */
    @Test
    fun q30_seed3819_aHighModeTrialIsEligibleWithinItsLastWeek() {
        val world = EntitlementSeededWorld(SEED_3819)
        world.outcome = { s ->
            val where = world.description.toString()
            assertTrue(where, "invitee=true mode=HIGH" in where)
            val trial = s.ent.records.issued.filter { it.value.kind == EntitlementCrypto.KIND_ACCESS && it.value.invoice == null }
            assertTrue("the trial finalized ($where)", trial.isNotEmpty())
            val base = trial.values.minOf { it.epoch }
            val lastDay = Grid.start(base + Layouts.TRIAL_WEEKS) - Grid.DAY
            for (n in trial.keys) {
                val eligible = checkNotNull(s.ent.records.eligibleOf[n]) { "a trial token was stored without its eligible minute" }
                assertTrue(
                    "a trial token of base week $base is eligible ${eligible - Grid.start(base)} s after start(base), past its last week's last day ($where)",
                    eligible < lastDay + 6 * Grid.HOUR,
                )
            }
        }
        // Odd seeds run in the DELETE journal mode (EntitlementSeededWorldsTest).
        Runner(world, JournalMode.DELETE, SEED_3819).run(RunSpec(plan = { w -> world.plan(w) }))
    }

    private companion object {
        const val SEED_3819 = 3819L
    }
}
