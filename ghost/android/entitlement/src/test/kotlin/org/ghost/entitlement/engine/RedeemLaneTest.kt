package org.ghost.entitlement.engine

import org.ghost.entitlement.T0
import org.ghost.entitlement.TestBytes
import org.ghost.entitlement.WEEK0
import org.ghost.entitlement.World
import org.ghost.entitlement.api.EntitlementFlag
import org.ghost.entitlement.store.TokenStore
import org.ghost.network.TorRelayTransport
import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.OperationId
import org.ghost.sync.api.OutboundBlob
import org.ghost.sync.api.RelayId
import org.ghost.sync.api.TtlBucket
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The redeem lane (design §11.6, §12.4): needs are fulfilled by installing the capability and
 * deleting the token in one transaction; a reserved token is retried only identically at its own
 * relay and namespace (R8); results per the §11.6 table.
 */
class RedeemLaneTest {
    private val ns = NamespaceId(TestBytes.of(32, 4242))

    /** A write-only namespace with one queued blob on [relays]: WRITE MISSING at each. */
    private fun World.writeNeed(relays: Set<RelayId>) = tx { t ->
        stores.namespaces.register(t, ns, Consumer.DM, relays, listen = false)
        stores.outbox.enqueue(t, OutboundBlob(OperationId(TestBytes.of(16, 1)), ns, TestBytes.of(1024, 2), TtlBucket.DAYS_7))
    }

    private fun World.capability(relay: RelayId): String? {
        var state: String? = null
        sql.query("SELECT state FROM relay_capability WHERE relay_id = ?1 AND namespace_id = ?2 AND kind = 'write'", listOf(relay.value, ns.toByteArray())) {
            state = it.string(0)
        }
        return state
    }

    @Test
    fun writeNeedsAreMetWithATokenOfEachRelaysSlotAndTheCapabilityInstalled(): Unit = World().use { w ->
        w.writeNeed(setOf(w.relayIds[0], w.relayIds[1]))
        val slot0 = w.addAccess(WEEK0, 0, 2).map { it.toList() }
        val slot1 = w.addAccess(WEEK0, 1, 2).map { it.toList() }
        w.laneStep()
        assertEquals(2, w.redeem.calls.size)
        val byRelay = w.redeem.calls.associateBy { it.relay }
        assertTrue(checkNotNull(byRelay[w.crypto.onions[0]]).token in slot0)
        assertTrue(checkNotNull(byRelay[w.crypto.onions[1]]).token in slot1)
        assertEquals("usable", w.capability(w.relayIds[0]))
        assertEquals("usable", w.capability(w.relayIds[1]))
        assertEquals("the redeemed tokens are gone", 2, w.tokenRows("access").size)
        assertTrue(w.tokenRows("access").all { it.state == TokenStore.FRESH })
        assertTrue(w.stores.capabilities.needed().isEmpty())
        w.laneStep()
        assertEquals("no need, no call", 2, w.redeem.calls.size)
    }

    @Test
    fun aReplayedTokenIsDeletedAndTheNextOneTried(): Unit = World().use { w ->
        w.writeNeed(setOf(w.relayIds[0], w.relayIds[1]))
        w.addAccess(WEEK0, 0, 2)
        w.redeem.result = TorRelayTransport.REDEEM_REPLAYED
        w.laneStep()
        assertEquals(1, w.tokenRows("access").size)
        assertEquals(1L, w.engine.counter(Counters.TOKENS_REPLAYED))
        w.redeem.result = TorRelayTransport.REDEEM_OK
        w.laneStep()
        assertTrue(w.tokenRows("access").isEmpty())
        assertEquals("usable", w.capability(w.relayIds[0]))
    }

    @Test
    fun anUnauthorizedTokenIsDeletedAndFlagged(): Unit = World().use { w ->
        w.writeNeed(setOf(w.relayIds[0], w.relayIds[1]))
        w.addAccess(WEEK0, 0, 1)
        w.redeem.fail = "unauthorized"
        w.laneStep()
        assertTrue(w.tokenRows("access").isEmpty())
        assertTrue(EntitlementFlag.REFUSED_BY_RELAY in w.engine.status().flags)
    }

    @Test
    fun aTransientFailureKeepsTheReservationForTheIdenticalRetry(): Unit = World().use { w ->
        w.writeNeed(setOf(w.relayIds[0], w.relayIds[1]))
        w.addAccess(WEEK0, 0, 2)
        w.redeem.failOnce = "timeout"
        w.laneStep()
        val reserved = w.tokenRows("access").single { it.state == TokenStore.RESERVED }
        assertEquals(w.relayIds[0].value, reserved.reservedRelay)
        w.laneStep()
        assertEquals(2, w.redeem.calls.size)
        assertEquals(w.redeem.calls[0].token, w.redeem.calls[1].token)
        assertEquals(w.redeem.calls[0].requestId, w.redeem.calls[1].requestId)
        assertEquals(w.redeem.calls[0].relay, w.redeem.calls[1].relay)
        assertEquals(1, w.tokenRows("access").size)
    }

    @Test
    fun wrongPeriodKeepsATokenThatIsEarlyAndDeletesOneThatIsLate(): Unit {
        World().use { w ->
            w.writeNeed(setOf(w.relayIds[0], w.relayIds[1]))
            w.addAccess(WEEK0, 0, 1)
            w.redeem.result = TorRelayTransport.REDEEM_WRONG_PERIOD
            w.redeem.relayPeriod = WEEK0 - 1
            w.laneStep()
            assertEquals(TokenStore.RESERVED, w.tokenRows("access").single().state)
        }
        World().use { w ->
            w.writeNeed(setOf(w.relayIds[0], w.relayIds[1]))
            w.addAccess(WEEK0, 0, 1)
            w.redeem.result = TorRelayTransport.REDEEM_WRONG_PERIOD
            w.redeem.relayPeriod = WEEK0 + 1
            w.laneStep()
            assertTrue(w.tokenRows("access").isEmpty())
        }
    }

    @Test
    fun aRelayInNoSlotIsNeverRedeemedAndRaisesNoNeed(): Unit = World().use { w ->
        w.writeNeed(setOf(w.relayIds[0], w.outsider))
        w.addAccess(WEEK0, 0, 1)
        w.random.prfValue = 0.0
        w.laneStep()
        assertEquals(listOf(w.crypto.onions[0]), w.redeem.calls.map { it.relay })
        assertTrue(w.engine.counter(Counters.NO_SLOT) >= 1)
        assertFalse(EntitlementFlag.ENTITLEMENT_NEEDED in w.engine.status().flags)
    }

    @Test
    fun aDueNeedWithoutAnEligibleTokenRaisesEntitlementNeededAfterItsDelay(): Unit = World().use { w ->
        w.writeNeed(setOf(w.relayIds[0], w.relayIds[1]))
        w.addAccess(WEEK0, 0, 1, eligibleMinute = T0 + 3600)
        w.random.prfValue = 0.5
        w.laneStep()
        assertTrue("not eligible yet", w.redeem.calls.isEmpty())
        assertFalse(EntitlementFlag.ENTITLEMENT_NEEDED in w.engine.status().flags)
        w.clock.now = T0 + 6 * 3600
        assertTrue(EntitlementFlag.ENTITLEMENT_NEEDED in w.engine.status().flags)
    }

    @Test
    fun nothingIsRedeemedWithoutATrustedClockOrNearAWeekBoundary(): Unit = World().use { w ->
        w.writeNeed(setOf(w.relayIds[0], w.relayIds[1]))
        w.addAccess(WEEK0, 0, 1, eligibleMinute = Grid.start(WEEK0) - Grid.DAY)
        w.laneStep(trusted = false)
        assertTrue(w.redeem.calls.isEmpty())
        w.clock.now = Grid.start(WEEK0) + 1800
        w.laneStep()
        assertTrue(w.redeem.calls.isEmpty())
        w.clock.now = Grid.start(WEEK0) + 3600
        w.laneStep()
        assertEquals(1, w.redeem.calls.size)
    }

    @Test
    fun anExpiringCapabilityIsRenewedWithANextWeekTokenInsideItsWindow(): Unit = World().use { w ->
        w.tx { t ->
            w.stores.namespaces.register(t, ns, Consumer.DM, setOf(w.relayIds[0]), listen = false)
            w.stores.capabilities.put(t, w.relayIds[0], ns, CapabilityKind.WRITE, TestBytes.of(98, 3), Grid.start(WEEK0 + 1) + 3600)
        }
        val next = w.addAccess(WEEK0 + 1, 0, 1).single().toList()
        w.addAccess(WEEK0, 0, 1)
        w.random.prfValue = 0.0
        w.clock.now = Grid.start(WEEK0 + 1) - 20 * 3600
        w.laneStep()
        assertEquals(next, w.redeem.calls.single().token)
    }

    @Test
    fun aListeningNamespaceIsReadByWriteAfterItsPrfDelay(): Unit = World().use { w ->
        w.tx { t -> w.stores.namespaces.register(t, ns, Consumer.DM, setOf(w.relayIds[0]), listen = true) }
        w.addAccess(WEEK0, 0, 1)
        w.random.prfValue = 0.5
        w.laneStep()
        assertTrue(w.redeem.calls.isEmpty())
        w.clock.now = T0 + 3 * 3600
        w.laneStep()
        assertEquals(1, w.redeem.calls.size)
        assertEquals("usable", w.capability(w.relayIds[0]))
    }

    @Test
    fun theLaneRunsUntilTheSessionCloses(): Unit = World().use { w ->
        w.writeNeed(setOf(w.relayIds[0], w.relayIds[1]))
        w.addAccess(WEEK0, 0, 1)
        val session = w.relaySession()
        var ticks = 0
        w.ctx().redeemLane.run(session) {
            ticks++
            if (ticks == 2) session.closed = true
        }
        assertEquals(2, ticks)
        assertEquals(1, w.redeem.calls.size)
    }
}
