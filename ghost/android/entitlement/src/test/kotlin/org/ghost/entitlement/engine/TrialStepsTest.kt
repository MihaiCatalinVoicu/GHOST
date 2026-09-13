package org.ghost.entitlement.engine

import org.ghost.entitlement.T0
import org.ghost.entitlement.WEEK0
import org.ghost.entitlement.World
import org.ghost.entitlement.api.ActivationResult
import org.ghost.entitlement.api.ActivationState
import org.ghost.entitlement.store.InviteStore
import org.ghost.entitlement.store.PurchaseStore
import org.ghost.identity.Invite
import org.ghost.network.TorIssuerTransport
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.store.Time
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The activation sequence (design §8.3, §19.12, §19.20 point 6) and invite revocation (§8.6, §19.14):
 * the nonce, trial and drop target in one transaction; `RedeemInvite` only as a user call; it ends
 * either with an active identity holding its trial tokens or with no identity.
 */
class TrialStepsTest {

    @Test
    fun anInviteActivatesWithTrialTokensEligibleAtOnceAndADrawnDropTime(): Unit = World().use { w ->
        val text = w.inviteText()
        assertEquals(ActivationResult.PENDING, w.engine.activate(text))
        assertEquals(listOf("create"), w.identity.log)
        assertEquals(listOf("call"), w.userCalls.log)
        val call = w.issuer.named("redeemInvite").single()
        assertEquals(WEEK0.toString(), call.args[2])
        assertEquals("12", call.args[4])
        assertEquals(ActivationState.ACTIVE, w.engine.activationState())
        val access = w.tokenRows("access")
        assertEquals(12, access.size)
        assertTrue(access.all { it.eligibleMinute == Time.floorMinute(T0) })
        assertEquals(1L, w.count("SELECT count(*) FROM invite_nonces"))
        val invite = Invite.parseAndVerify(text, T0, { 739L }, Invite.InMemoryNonceStore())
        val target = checkNotNull(w.tx { w.ctx().invites.dropTarget(it) })
        assertEquals(InviteStore.WAITING, target.state)
        assertTrue(target.dropMinute >= Grid.start(WEEK0 + 3) && target.dropMinute < Grid.start(WEEK0 + 8))
        assertEquals(invite.expiryDay + 56, target.untilDay)
        assertEquals(listOf(0, 1, 2), target.dropSlots)
        assertEquals(PurchaseStore.FINALIZED, w.purchases().single().state)
    }

    @Test
    fun highModeTrialTokensWaitForAnActivationSlot(): Unit = World().use { w ->
        w.mode = PrivacyMode.HIGH
        w.random.uniformValue = 0.6
        w.engine.activate(w.inviteText())
        val thursday = Grid.start(WEEK0) + 3 * Grid.DAY
        assertTrue(w.tokenRows("access").all { it.eligibleMinute >= thursday })
    }

    @Test
    fun anInviteTheScheduleRefusesRecordsNothing(): Unit = World().use { w ->
        val text = w.inviteText()
        val unknown = World().use { v -> v.inviteText(seed = 78) }
        assertEquals(ActivationResult.REFUSED_TOKEN, w.engine.activate(unknown))
        assertEquals(0L, w.count("SELECT count(*) FROM invite_nonces"))
        assertTrue(w.purchases().isEmpty())
        assertFalse(w.identity.exists)
        assertEquals(ActivationState.NONE, w.engine.activationState())
        assertEquals(ActivationResult.REFUSED_MALFORMED, w.engine.activate("ghost://invite/zzz"))
        assertEquals(ActivationResult.PENDING, w.engine.activate(text))
    }

    @Test
    fun aReplayedInviteWipesTheIdentityAndFailsClosed(): Unit = World().use { w ->
        w.issuer.trialResult = TorIssuerTransport.TRIAL_REPLAYED
        val text = w.inviteText()
        w.engine.activate(text)
        assertEquals(listOf("create", "wipe"), w.identity.log)
        assertFalse(w.identity.exists)
        assertEquals(ActivationState.FAILED, w.engine.activationState())
        assertNull(w.tx { w.ctx().invites.dropTarget(it) })
        assertTrue(w.tokenRows("access").isEmpty())
        assertEquals("the nonce stays used", ActivationResult.REFUSED_REPLAYED, w.engine.activate(text))
    }

    @Test
    fun wrongPeriodRepreparesWithTheSameInviteToken(): Unit = World().use { w ->
        w.issuer.trialResult = TorIssuerTransport.TRIAL_WRONG_PERIOD
        w.engine.activate(w.inviteText())
        assertEquals(ActivationState.PENDING, w.engine.activationState())
        val rows = w.purchases()
        assertEquals(1, rows.count { it.state == PurchaseStore.FAILED })
        val fresh = rows.single { it.state == PurchaseStore.PREPARED }
        assertTrue(w.identity.exists)
        w.issuer.trialResult = TorIssuerTransport.TRIAL_OK
        w.engine.onForeground()
        val calls = w.issuer.named("redeemInvite")
        assertEquals(2, calls.size)
        assertEquals("same invite token", calls[0].args[0], calls[1].args[0])
        assertFalse("a new seed", calls[0].args[1] == calls[1].args[1])
        assertEquals(PurchaseStore.FINALIZED, checkNotNull(w.purchase(fresh.id())).state)
        assertEquals(ActivationState.ACTIVE, w.engine.activationState())
    }

    @Test
    fun aTransientFailureStaysPendingAndTheNextForegroundRetriesIdentically(): Unit = World().use { w ->
        w.issuer.failOnce = "transport"
        w.engine.activate(w.inviteText())
        assertEquals(ActivationState.PENDING, w.engine.activationState())
        w.engine.onForeground()
        val calls = w.issuer.named("redeemInvite")
        assertEquals(2, calls.size)
        assertEquals(calls[0].args, calls[1].args)
        assertEquals(ActivationState.ACTIVE, w.engine.activationState())
    }

    @Test
    fun aTrialNeedsATrustedClock(): Unit = World().use { w ->
        w.userCalls.trusted = false
        w.engine.activate(w.inviteText())
        assertTrue(w.issuer.calls.isEmpty())
        assertEquals(ActivationState.PENDING, w.engine.activationState())
        w.userCalls.trusted = true
        w.engine.onForeground()
        assertEquals(ActivationState.ACTIVE, w.engine.activationState())
    }

    @Test
    fun aPendingTrialWithoutIdentityResumesAtTheIdentityInANewProcess(): Unit = World().use { w ->
        w.userCalls.deferred = true
        w.engine.activate(w.inviteText())
        // The process ended after the activation transaction, before the identity was written.
        w.identity.exists = false
        w.identity.log.clear()
        w.userCalls.pending.clear()
        w.userCalls.deferred = false
        val restarted = EntitlementEngine(w.deps) { w.stores }
        assertEquals(ActivationState.PENDING, restarted.activationState())
        restarted.onForeground()
        assertEquals(listOf("create-resumed"), w.identity.log)
        assertEquals(1, w.issuer.named("redeemInvite").size)
        assertEquals(ActivationState.ACTIVE, restarted.activationState())
    }

    @Test
    fun aRevocationIsQuietRunWorkAndKeepsTheTokensAsSpares(): Unit = World().use { w ->
        w.identity.exists = true
        w.addTokens("invite", Grid.inviteEpoch(WEEK0), 1)
        assertTrue(w.engine.createInvite((Grid.day(T0) + 14).toInt()) != null)
        assertTrue(w.engine.revokeInvite(0))
        assertFalse("only once", w.engine.revokeInvite(0))
        assertEquals(InviteStore.CLOSED, checkNotNull(w.tx { w.ctx().invites.get(it, 0) }).state)
        assertTrue("never a foreground call", w.userCalls.log.isEmpty())
        assertEquals(ActivationState.ACTIVE, w.engine.activationState())
        w.random.uniformValue = 0.0
        w.quiet()
        assertEquals(1, w.issuer.named("redeemInvite").size)
        val thursday = Grid.start(WEEK0) + 3 * Grid.DAY
        val spares = w.tokenRows("access")
        assertEquals(12, spares.size)
        assertTrue("pack eligibility, not immediate", spares.all { it.eligibleMinute == thursday })
    }
}
