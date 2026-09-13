package org.ghost.entitlement.engine

import org.ghost.entitlement.T0
import org.ghost.entitlement.TestCrypto
import org.ghost.entitlement.WEEK0
import org.ghost.entitlement.World
import org.ghost.entitlement.api.PayWith
import org.ghost.entitlement.store.ClaimStore
import org.ghost.entitlement.store.InviteStore
import org.ghost.entitlement.store.TokenStore
import org.ghost.network.TorIssuerTransport
import org.ghost.sync.store.Time
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Payout claims (design §9.4, §19.22 point 2) and garbage collection and retention (§11.3, §11.4, §19.15). */
class ClaimAndGcTest {
    private val address = "5" + "b".repeat(94)

    @Test
    fun aClaimIsWrittenAheadAndQueuedInItsOwnQuietRun(): Unit = World().use { w ->
        assertNull("too few credits", w.engine.claimPayout(address))
        w.addTokens("credit", Grid.creditEpoch(WEEK0), 12)
        assertNull("an address the schedule refuses", w.engine.claimPayout("4" + "b".repeat(94)))
        val id = checkNotNull(w.engine.claimPayout(address)).toByteArray()
        assertNull("one open claim", w.engine.claimPayout(address))
        val claim = checkNotNull(w.tx { w.ctx().claims.get(it, id) })
        assertEquals(ClaimStore.PREPARED, claim.state)
        assertEquals(Time.ceilMinute(T0 + 12 * 3600), claim.nextDueMinute)
        assertTrue(w.tokenRows("credit").all { it.state == TokenStore.RESERVED && it.reservedFor == TokenStore.FOR_CLAIM })
        w.quiet()
        assertTrue(w.issuer.calls.isEmpty())
        w.clock.now = checkNotNull(claim.nextDueMinute)
        w.quiet()
        val call = w.issuer.named("claimPayout").single()
        assertEquals(12, call.args[1].split(",").size)
        assertEquals(address, call.args[2])
        val queued = checkNotNull(w.tx { w.ctx().claims.get(it, id) })
        assertEquals(ClaimStore.QUEUED, queued.state)
        assertNull(queued.payoutAddress)
        assertEquals(12 * (TestCrypto.PRICE / 10), queued.queuedAtomic)
        assertTrue(w.tokenRows("credit").isEmpty())
        assertEquals(1L, w.count("SELECT count(*) FROM ent_payout_used"))
        w.addTokens("credit", Grid.creditEpoch(WEEK0), 10)
        assertNull("a used address is refused", w.engine.claimPayout(address))
        val next = checkNotNull(w.engine.claimPayout("7" + "c".repeat(94))).toByteArray()
        val nextDue = checkNotNull(checkNotNull(w.tx { w.ctx().claims.get(it, next) }).nextDueMinute)
        assertTrue("at most one claim per week", nextDue >= (Grid.day(w.clock.now) + 7) * Grid.DAY)
    }

    @Test
    fun anAddressRejectedClaimReleasesItsCredits(): Unit = World().use { w ->
        w.addTokens("credit", Grid.creditEpoch(WEEK0), 10)
        val id = checkNotNull(w.engine.claimPayout(address)).toByteArray()
        w.issuer.claimResult = TorIssuerTransport.CLAIM_ADDRESS_REJECTED
        w.clock.now += Grid.DAY
        w.quiet()
        assertEquals(ClaimStore.FAILED, checkNotNull(w.tx { w.ctx().claims.get(it, id) }).state)
        assertEquals(10, w.tokenRows("credit").count { it.state == TokenStore.FRESH })
    }

    @Test
    fun spentCreditsOfAClaimAreDeletedAndTheOthersReleased(): Unit = World().use { w ->
        w.addTokens("credit", Grid.creditEpoch(WEEK0), 10)
        checkNotNull(w.engine.claimPayout(address))
        w.issuer.claimResult = TorIssuerTransport.CLAIM_CREDITS_SPENT
        w.issuer.claimMask = 0b11
        w.clock.now += Grid.DAY
        w.quiet()
        assertEquals(8, w.tokenRows("credit").size)
        assertTrue(w.tokenRows("credit").all { it.state == TokenStore.FRESH })
    }

    @Test
    fun gcDropsTokensOutOfTheirWindowAndTerminalRowsAfterAWeek(): Unit = World().use { w ->
        w.addAccess(WEEK0 - 1, 0, 1)
        w.addAccess(WEEK0, 0, 1)
        w.addTokens("invite", Grid.inviteEpoch(WEEK0) - 2, 1)
        w.addTokens("invite", Grid.inviteEpoch(WEEK0) - 1, 1)
        w.addTokens("credit", Grid.creditEpoch(WEEK0) - 5, 1)
        w.addTokens("credit", Grid.creditEpoch(WEEK0) - 4, 1)
        val id = checkNotNull(w.engine.startPurchase(PayWith.XMR))
        assertTrue(w.engine.cancel(id))
        w.ctx().gc.run(T0)
        assertEquals(listOf(WEEK0), w.tokenRows("access").map { it.epoch })
        assertEquals(listOf(Grid.inviteEpoch(WEEK0) - 1), w.tokenRows("invite").map { it.epoch })
        assertEquals(listOf(Grid.creditEpoch(WEEK0) - 4), w.tokenRows("credit").map { it.epoch })
        w.ctx().gc.run(T0 + 6 * Grid.DAY)
        assertNotNull(w.purchase(id.toByteArray()))
        w.ctx().gc.run(T0 + 7 * Grid.DAY)
        assertNull(w.purchase(id.toByteArray()))
    }

    @Test
    fun gcClosesInvitesAtTheirListeningEndAndForgetsThePaymentScreenAfterAnHour(): Unit = World().use { w ->
        w.identity.exists = true
        w.addTokens("invite", Grid.inviteEpoch(WEEK0), 1)
        val expiry = Grid.day(T0) + 14
        checkNotNull(w.engine.createInvite(expiry.toInt()))
        val ns = w.identity.root.inviteDropNamespace(0)
        val end = (expiry + 56) * Grid.DAY
        w.ctx().gc.run(end - Grid.DAY)
        assertEquals(InviteStore.CREATED, checkNotNull(w.tx { w.ctx().invites.get(it, 0) }).state)
        w.ctx().gc.run(end)
        assertEquals(InviteStore.CLOSED, checkNotNull(w.tx { w.ctx().invites.get(it, 0) }).state)
        assertEquals(0L, w.count("SELECT count(*) FROM sync_namespace WHERE namespace_id = ?1 AND listening = 1", listOf(ns)))
        w.ctx().gc.run(end)
        assertNull(w.tx { w.ctx().invites.get(it, 0) })

        val id = checkNotNull(w.engine.startPurchase(PayWith.XMR))
        w.engine.paymentScreenShown(id)
        assertEquals(Time.ceilMinute(T0), w.count("SELECT payment_shown_minute FROM ent_state"))
        w.ctx().gc.run(Time.ceilMinute(T0) + 59 * 60)
        assertEquals(Time.ceilMinute(T0), w.count("SELECT payment_shown_minute FROM ent_state"))
        w.ctx().gc.run(Time.ceilMinute(T0) + 60 * 60)
        assertEquals(1L, w.count("SELECT count(*) FROM ent_state WHERE payment_shown_minute IS NULL"))
    }
}
