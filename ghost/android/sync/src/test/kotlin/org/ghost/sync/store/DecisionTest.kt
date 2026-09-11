package org.ghost.sync.store

import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.OperationId
import org.ghost.sync.api.Outcome
import org.ghost.sync.api.RelayId
import org.ghost.sync.api.SyncChange
import org.ghost.sync.store.SyncWorld.Companion.DAY
import org.ghost.sync.store.SyncWorld.Companion.HOUR
import org.ghost.sync.store.SyncWorld.Companion.MINUTE
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Verification (§3.4, §11.2 #5), resolution, closure and the decision rules D1, D2, W, M3 (§3.5). */
class DecisionTest {

    private fun SyncWorld.ack(op: OperationId, relay: RelayId) {
        tx { outbox.lease(it, op, relay, now, 60) }
        tx { outbox.recordReceipt(it, op, relay, now + 7 * DAY, now) }
    }

    private fun SyncWorld.ambiguous(op: OperationId, relay: RelayId) {
        tx { outbox.lease(it, op, relay, now, 60) }
        tx { outbox.recordAmbiguous(it, op, relay, now) }
    }

    private fun SyncWorld.list(relay: RelayId, ns: NamespaceId, vararg seeds: Int) =
        tx { inbox.commitPage(it, relay, ns, seeds.map { s -> hashOf(s) }, ByteArray(0), now) }

    @Test
    fun listingVerifiesIdleOwnDeliveriesOfUndecidedOpsOnly(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.standardSet()
        val op = w.enqueue(1, ns)
        w.ack(op, relays[0])
        w.tx { w.outbox.lease(it, op, relays[1], w.now, 60) } // in flight: not promoted
        val page = w.list(relays[0], ns, 1)
        assertEquals(listOf(op), page.verified)
        assertEquals("verified", w.state(op, relays[0]))
        w.list(relays[1], ns, 1)
        assertEquals("pending", w.state(op, relays[1]))
        assertEquals(1L, w.delivery(op, relays[1], "inflight"))
        // A pending delivery without a copy on relay 2 is promoted too: inventory is truth.
        w.list(relays[2], ns, 1)
        assertEquals("verified", w.state(op, relays[2]))
        assertEquals("sent", w.outcome(op))
        // Decided: a later listing promotes nothing (the in-flight delivery ends later).
        w.tx { w.outbox.recordNotApplied(it, op, relays[1], w.now) }
        assertEquals(0, w.list(relays[1], ns, 1).verified.size)
        assertEquals("pending", w.state(op, relays[1]))
    }

    @Test
    fun listingVerificationReachesFailedClosedAndParkedDeliveries(): Unit = SyncWorld().use { w ->
        val relays = w.relays(1, 2, 3, 4)
        val ns = w.namespace(1, relays)
        relays.forEach { w.capability(it, ns) }
        val op = w.enqueue(1, ns)
        w.ambiguous(op, relays[0])
        w.raw("UPDATE outbox_delivery SET state = 'failed' WHERE relay_id = ?", relays[0])
        w.raw("UPDATE outbox_delivery SET state = 'closed' WHERE relay_id = ?", relays[1])
        w.raw("UPDATE outbox_delivery SET state = 'wait_capability' WHERE relay_id = ?", relays[2])
        w.list(relays[0], ns, 1)
        w.list(relays[1], ns, 1)
        assertEquals("verified", w.state(op, relays[0]))
        assertEquals("verified", w.state(op, relays[1]))
        assertEquals("sent", w.outcome(op))
        assertEquals("wait_capability", w.state(op, relays[2]))
    }

    @Test
    fun checkVerificationAndTwoStrikes(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.standardSet(listen = false)
        val op = w.enqueue(1, ns)
        w.ack(op, relays[0])
        // Not yet 60 s old.
        assertTrue(w.tx { w.outbox.ackedAwaitingVerification(it, relays[0], ns, w.now, 60, 64) }.isEmpty())
        w.clock.advance(MINUTE)
        val due = w.tx { w.outbox.ackedAwaitingVerification(it, relays[0], ns, w.now, 60, 64) }
        assertEquals(listOf(op), due.map { it.operationId })
        assertEquals(w.hashOf(1), due.single().hash)
        // Absent: strike 1, repair store due now.
        assertTrue(w.tx { w.outbox.recordAbsentAfterAck(it, op, relays[0], w.now) })
        assertEquals("pending", w.state(op, relays[0]))
        assertEquals(1L, w.delivery(op, relays[0], "strikes"))
        assertEquals(Time.floorMinute(w.now), w.delivery(op, relays[0], "next_attempt_minute"))
        w.ack(op, relays[0])
        w.clock.advance(MINUTE)
        assertTrue(w.tx { w.outbox.recordAbsentAfterAck(it, op, relays[0], w.now) })
        assertEquals("failed", w.state(op, relays[0]))
        assertEquals(2L, w.delivery(op, relays[0], "strikes"))
        // Present on another relay.
        w.ack(op, relays[1])
        w.clock.advance(MINUTE)
        assertTrue(w.tx { w.outbox.recordVerifiedAfterAck(it, op, relays[1], w.now) })
        assertEquals("verified", w.state(op, relays[1]))
        assertFalse(w.tx { w.outbox.recordVerifiedAfterAck(it, op, relays[1], w.now) })
    }

    @Test
    fun ackAgeUsesTheFallbackAndTheClockClamp(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.standardSet()
        val op = w.enqueue(1, ns)
        w.ack(op, relays[0])
        w.clock.advance(9 * MINUTE)
        assertTrue(w.tx { w.outbox.ackedAwaitingVerification(it, relays[0], ns, w.now, 600, 64) }.isEmpty())
        w.clock.advance(MINUTE)
        assertEquals(1, w.tx { w.outbox.ackedAwaitingVerification(it, relays[0], ns, w.now, 600, 64) }.size)
        w.clock.advance(-2 * HOUR)
        assertEquals(1, w.tx { w.outbox.ackedAwaitingVerification(it, relays[0], ns, w.now, 600, 64) }.size)
    }

    @Test
    fun quorumCountsDistinctOperatorsNotRelays(): Unit = SyncWorld().use { w ->
        val relays = w.relays(1, 1, 2)
        val ns = w.namespace(1, relays)
        relays.forEach { w.capability(it, ns) }
        val op = w.enqueue(1, ns)
        w.list(relays[0], ns, 1)
        w.list(relays[1], ns, 1)
        assertEquals("pending", w.outcome(op))
        w.hints.clear()
        w.list(relays[2], ns, 1)
        assertEquals("sent", w.outcome(op))
        assertEquals(listOf(setOf(SyncChange.OUTCOMES)), w.hints)
        assertFalse(w.hasPayload(op))
        val progress = w.stores.outbox.progress(op)!!
        assertEquals(2, progress.verifiedOperators)
        assertEquals(Outcome.SENT, progress.outcome)
    }

    @Test
    fun d2DecidesDegradedIndeterminateOrFailedOnlyWhenNothingCanProgress(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.standardSet()
        // degraded: one verified, the others refused.
        val a = w.enqueue(1, ns)
        w.list(relays[0], ns, 1)
        w.tx { w.outbox.failDelivery(it, a, relays[1], w.now) }
        assertEquals("pending", w.outcome(a))
        assertTrue(w.hasPayload(a))
        w.tx { w.outbox.failDelivery(it, a, relays[2], w.now) }
        assertEquals("degraded", w.outcome(a))
        assertFalse(w.hasPayload(a))
        // failed: no copy ever possible.
        val b = w.enqueue(2, ns)
        relays.forEach { r -> w.tx { w.outbox.failDelivery(it, b, r, w.now) } }
        assertEquals("failed", w.outcome(b))
        // indeterminate: an acked copy on a relay that then left the set.
        val c = w.enqueue(3, ns)
        w.ack(c, relays[0])
        w.tx { w.outbox.failDelivery(it, c, relays[1], w.now) }
        w.tx { w.outbox.failDelivery(it, c, relays[2], w.now) }
        assertEquals("pending", w.outcome(c))
        w.tx { w.stores.namespaces.setRelays(it, ns, setOf(relays[1], relays[2])) }
        assertEquals("indeterminate", w.outcome(c))
        assertFalse(w.hasPayload(c))
        // Decided once: D1/D2 never touch it again.
        assertFalse(w.tx { w.outbox.decide(it, c, w.now) })
    }

    @Test
    fun aResolvableCopyBlocksD2UntilCheckedOrNoLongerResolvable(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.standardSet()
        val op = w.enqueue(1, ns)
        w.ambiguous(op, relays[0])
        w.raw("UPDATE outbox_delivery SET state = 'failed' WHERE operation_id = ? AND relay_id = ?", op, relays[0])
        w.tx { w.outbox.failDelivery(it, op, relays[1], w.now) }
        w.tx { w.outbox.failDelivery(it, op, relays[2], w.now) }
        // Relay 0 may hold a copy that a check can still settle: undecided. No delivery can store any more: wiped.
        assertEquals("pending", w.outcome(op))
        assertFalse(w.hasPayload(op))
        assertEquals(listOf(op), w.tx { w.outbox.resolvable(it, relays[0], ns, w.now, 64) }.map { it.operationId })
        // A check proves it absent: the copy is forgotten, D2 decides FAILED.
        assertTrue(w.tx { w.outbox.clearUnackedCopy(it, op, relays[0], w.now) })
        assertEquals("failed", w.outcome(op))
    }

    @Test
    fun timeAloneEndsResolvabilityAndTheSweepDecidesIndeterminate(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.standardSet()
        val op = w.enqueue(1, ns)
        w.ambiguous(op, relays[0])
        w.raw("UPDATE outbox_delivery SET state = 'closed' WHERE operation_id = ? AND relay_id = ?", op, relays[0])
        w.tx { w.outbox.failDelivery(it, op, relays[1], w.now) }
        w.tx { w.outbox.failDelivery(it, op, relays[2], w.now) }
        assertEquals("pending", w.outcome(op))
        // copy_hour + ttl − σ = T0 + 4 d.
        w.clock.now = SyncWorld.T0 + 4 * DAY - 1
        assertEquals(0, w.tx { w.outbox.decideAll(it, w.now) })
        w.clock.now = SyncWorld.T0 + 4 * DAY
        assertTrue(w.tx { w.outbox.resolvable(it, relays[0], ns, w.now, 64) }.isEmpty())
        assertEquals(1, w.tx { w.outbox.decideAll(it, w.now) })
        assertEquals("indeterminate", w.outcome(op))
        val outcome = w.stores.outbox.outcomes(org.ghost.sync.api.Consumer.DM, 10).single()
        assertEquals(Outcome.INDETERMINATE, outcome.outcome)
        assertEquals(SyncWorld.T0 + 7 * DAY - RetentionPolicy.SKEW_SECONDS, outcome.resendNotAfterEpochSeconds)
    }

    @Test
    fun aResolvableCopyOnARetiredRelayDoesNotBlock(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.standardSet()
        val op = w.enqueue(1, ns)
        w.ambiguous(op, relays[0])
        w.tx { w.outbox.failDelivery(it, op, relays[1], w.now) }
        w.tx { w.outbox.failDelivery(it, op, relays[2], w.now) }
        assertEquals("pending", w.outcome(op))
        w.tx { w.stores.relayDirectory.retire(it, relays[0]) }
        assertEquals("indeterminate", w.outcome(op))
    }

    @Test
    fun m3ClosesOnTheCallerDeadline(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.standardSet()
        val op = w.enqueue(1, ns, deadline = w.now + 3 * HOUR)
        w.clock.now = SyncWorld.T0 + 3 * HOUR - 1
        assertEquals(0, w.tx { w.outbox.close(it, w.now) })
        w.clock.now = SyncWorld.T0 + 3 * HOUR
        assertEquals(3, w.tx { w.outbox.close(it, w.now) })
        relays.forEach { assertEquals("closed", w.state(op, it)) }
        assertEquals("failed", w.outcome(op))
    }

    @Test
    fun m3ClosesAnExpiredWindowOnlyWhenNothingIsResolvable(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.standardSet()
        val op = w.enqueue(1, ns)
        w.ack(op, relays[0])
        w.ambiguous(op, relays[1])
        // Relay 2 has no capability for a week: it stays parked, no copy.
        w.raw("UPDATE relay_capability SET state = 'rejected' WHERE relay_id = ?", relays[2])
        w.tx { w.outbox.parkWithoutCapability(it, w.now) }
        assertEquals("wait_capability", w.state(op, relays[2]))
        w.clock.now = SyncWorld.T0 + 7 * DAY
        // Window expired; relay 1's unacked copy is no longer resolvable (copy_hour + ttl − σ = T0 + 4 d < now) and
        // relay 0 is acked (never resolvable), so both open deliveries close.
        assertEquals(2, w.tx { w.outbox.close(it, w.now) })
        assertEquals("closed", w.state(op, relays[1]))
        assertEquals("closed", w.state(op, relays[2]))
        assertEquals("acked", w.state(op, relays[0]))
        assertEquals("pending", w.outcome(op))
    }

    @Test
    fun m3WaitsForAResolvableCopyOfALongTtlOp(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.standardSet()
        val op = w.enqueue(1, ns, org.ghost.sync.api.TtlBucket.DAYS_30)
        w.ambiguous(op, relays[0])
        w.clock.now = SyncWorld.T0 + 7 * DAY
        // relay 0's copy is still resolvable (T0 + 30 d − 3 d): nothing closes, and the pending delivery is offered
        // for a resolution check because its window is closed.
        assertEquals(0, w.tx { w.outbox.close(it, w.now) })
        assertEquals(listOf(op), w.tx { w.outbox.resolvable(it, relays[0], ns, w.now, 64) }.map { it.operationId })
        assertTrue(w.tx { w.outbox.dueStores(it, w.now, 32) }.isEmpty())
        // Found: verified, then the window stays closed and the others close.
        w.tx { w.outbox.recordFoundByCheck(it, op, relays[0], w.now) }
        assertEquals(2, w.tx { w.outbox.close(it, w.now) })
        assertEquals("degraded", w.outcome(op))
        assertNull(w.long("SELECT ciphertext FROM outbox_op"))
    }

    @Test
    fun absenceReopensTheWindowForAnOpWithASingleCopy(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.standardSet()
        val op = w.enqueue(1, ns, org.ghost.sync.api.TtlBucket.DAYS_30)
        w.ambiguous(op, relays[0])
        w.clock.now = SyncWorld.T0 + 8 * DAY
        assertTrue(w.tx { w.outbox.dueStores(it, w.now, 32) }.isEmpty())
        assertTrue(w.tx { w.outbox.clearUnackedCopy(it, op, relays[0], w.now) })
        assertEquals(3, w.tx { w.outbox.dueStores(it, w.now, 32) }.size)
    }

    @Test
    fun theWorkPairsAreThoseWithOpenOrResolvableDeliveries(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.standardSet()
        val op = w.enqueue(1, ns)
        assertEquals(3, w.tx { w.outbox.workPairs(it, w.now) }.size)
        w.ambiguous(op, relays[0])
        w.tx { w.outbox.failDelivery(it, op, relays[1], w.now) }
        w.raw("UPDATE outbox_delivery SET state = 'closed' WHERE relay_id = ?", relays[0])
        val pairs = w.tx { w.outbox.workPairs(it, w.now) }.map { it.relayId }.toSet()
        assertEquals(setOf(relays[0], relays[2]), pairs)
    }
}
