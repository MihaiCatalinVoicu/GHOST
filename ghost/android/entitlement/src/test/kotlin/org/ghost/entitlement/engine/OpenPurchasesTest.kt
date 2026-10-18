package org.ghost.entitlement.engine

import org.ghost.entitlement.WEEK0
import org.ghost.entitlement.T0
import org.ghost.entitlement.World
import org.ghost.entitlement.api.PayWith
import org.ghost.entitlement.store.InviteStore
import org.ghost.network.TorIssuerTransport
import org.ghost.entitlement.store.PurchaseStore
import org.ghost.entitlement.api.PurchaseUiState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Phase 13 §3.6 (PM-U31's predicate test): `openPurchases`' UI state is NEVER the stored
 * `invoiced` alone — an invoiced pack inside its U[1 h, 6 h] delay is INVOICE_PENDING; READY
 * appears only when `paymentReady` holds; a shown purchase with an outstanding amount before its
 * deadline is UNDERPAID; terminal states map as §3.6 fixes.
 */
class OpenPurchasesTest {
    @Test
    fun theUiStateFollowsThePaymentReadyPredicateNeverTheStoredInvoiced(): Unit = World().use { w ->
        val id = checkNotNull(w.engine.startPurchase(PayWith.XMR)).toByteArray()
        // PREPARED at intent.
        assertEquals(listOf(PurchaseUiState.PREPARED), w.engine.openPurchases().map { it.state })

        w.quiet()
        assertEquals(PurchaseStore.INVOICED, checkNotNull(w.purchase(id)).state)
        // Inside the delay: INVOICE_PENDING, never READY (PM-U31: instructions cannot open early).
        assertEquals(listOf(PurchaseUiState.INVOICE_PENDING), w.engine.openPurchases().map { it.state })

        // Past the delay's far end: READY exactly when paymentReady holds.
        w.clock.now += 7 * 3600L
        assertEquals(listOf(PurchaseUiState.READY), w.engine.openPurchases().map { it.state })

        // A shown purchase with an outstanding amount before its deadline is UNDERPAID.
        w.tx { tx ->
            tx.sql.execUpdate(
                "UPDATE ent_purchase SET shown = 1, outstanding_atomic = 1 WHERE purchase_id = ?1",
                listOf(id),
            )
        }
        assertEquals(listOf(PurchaseUiState.UNDERPAID), w.engine.openPurchases().map { it.state })

        // The terminal end of the flow: FINALIZED after the sign, with the id and pay-with intact.
        w.tx { tx ->
            tx.sql.execUpdate(
                "UPDATE ent_purchase SET shown = 0, outstanding_atomic = NULL WHERE purchase_id = ?1",
                listOf(id),
            )
        }
        val p = checkNotNull(w.purchase(id))
        w.clock.now = maxOf(w.clock.now, p.nextDueMinute ?: w.clock.now)
        w.quiet()
        val done = w.engine.openPurchases().single()
        assertEquals(PurchaseUiState.FINALIZED, done.state)
        assertEquals(PayWith.XMR, done.payWith)
        assertTrue("the id crosses as a 16-byte local id", done.id.toByteArray().size == 16)
    }

    @Test
    fun expiredRowsSplitBySeenAndCancelledRowsMapAsDeclared(): Unit = World().use { w ->
        val id = checkNotNull(w.engine.startPurchase(PayWith.XMR)).toByteArray()
        w.quiet()
        // The issuer refuses the sign as expired: the pack expires past its payment window.
        w.issuer.signState = TorIssuerTransport.STATE_EXPIRED
        val p0 = checkNotNull(w.purchase(id))
        w.clock.now = maxOf(w.clock.now, p0.nextDueMinute ?: w.clock.now)
        w.quiet()
        assertEquals(PurchaseStore.EXPIRED, checkNotNull(w.purchase(id)).state)
        assertEquals(listOf(PurchaseUiState.EXPIRED_UNPAID), w.engine.openPurchases().map { it.state })
        w.tx { tx -> tx.sql.execUpdate("UPDATE ent_purchase SET shown = 1 WHERE purchase_id = ?1", listOf(id)) }
        assertEquals(listOf(PurchaseUiState.EXPIRED_SEEN), w.engine.openPurchases().map { it.state })
        // A second pack cancelled through the facade maps CANCELLED (direct state writes are
        // refused by the schema's transition trigger, which is what we want).
        val id2 = checkNotNull(w.engine.startPurchase(PayWith.XMR)).toByteArray()
        assertTrue(w.engine.cancel(org.ghost.entitlement.api.PurchaseId(id2)))
        val states = w.engine.openPurchases().map { it.state }.toSet()
        assertTrue(PurchaseUiState.EXPIRED_SEEN in states && PurchaseUiState.CANCELLED in states)
    }

    @Test
    fun invitesListIndexExpiryAndStateOnly(): Unit = World().use { w ->
        // ent_invite rows are issued (not activated) invites; the list is index/expiry/state only.
        w.identity.exists = true
        w.addTokens("invite", org.ghost.entitlement.engine.Grid.inviteEpoch(WEEK0), 1)
        val expiry = org.ghost.entitlement.engine.Grid.day(T0) + 14
        checkNotNull(w.engine.createInvite(expiryDay = expiry.toInt()))
        val invites = w.engine.invites()
        assertEquals(1, invites.size)
        assertEquals(0, invites[0].index)
        assertEquals(expiry, invites[0].expiryDay)
        assertEquals(InviteStore.CREATED, invites[0].state)
    }
}
