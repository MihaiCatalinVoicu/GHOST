package org.ghost.sync.store

import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.store.SyncWorld.Companion.DAY
import org.ghost.sync.store.SyncWorld.Companion.HOUR
import org.ghost.sync.store.SyncWorld.Companion.MINUTE
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** Planning, the write-ahead lease and every result transaction of a store attempt (design §3.3, §3.6, §3.7). */
class StoreAttemptTest {

    @Test
    fun planningHonoursEveryDueCondition(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.standardSet()
        val op = w.enqueue(1, ns)
        fun due() = w.tx { w.outbox.dueStores(it, w.now, 32) }.map { it.relayId }.toSet()
        assertEquals(relays.toSet(), due())
        // Pair filter.
        assertEquals(listOf(relays[1]), w.tx { w.outbox.dueStores(it, w.now, 32, relays[1], ns) }.map { it.relayId })
        // No usable write capability: rejected, expired, or only a read token.
        w.raw("UPDATE relay_capability SET state = 'rejected' WHERE relay_id = ?", relays[0])
        w.raw("UPDATE relay_capability SET expires_hour = ? WHERE relay_id = ?", Time.floorHour(w.now), relays[1])
        w.raw("UPDATE relay_capability SET kind = 'read' WHERE relay_id = ?", relays[2])
        assertEquals(emptySet<Any>(), due())
        w.raw("UPDATE relay_capability SET state = 'usable', expires_hour = NULL, kind = 'write'")
        // Retired relay.
        w.raw("UPDATE relay_directory SET state = 'retired', retired_day = 1 WHERE relay_id = ?", relays[2])
        assertEquals(setOf(relays[0], relays[1]), due())
        w.raw("UPDATE relay_directory SET state = 'active', retired_day = NULL")
        // Leased (in flight) or backing off.
        w.tx { assertNotNull(w.outbox.lease(it, op, relays[0], w.now, 300)) }
        assertEquals(setOf(relays[1], relays[2]), due())
        // The window: a copy hour H old closes it for every relay of the op.
        w.raw("UPDATE outbox_delivery SET inflight = 0, copy_hour = ? WHERE relay_id = ?", Time.floorHour(w.now) - RetentionPolicy.STORE_WINDOW_SECONDS, relays[0])
        assertEquals(emptySet<Any>(), due())
        // The lease re-checks the window: a stale plan cannot store past it (W-rule).
        assertNull(w.tx { w.outbox.lease(it, op, relays[1], w.now, 60) })
        // (A copy hour only changes through NULL: the trigger keeps the earliest hour otherwise.)
        w.raw("UPDATE outbox_delivery SET copy_hour = NULL WHERE relay_id = ?", relays[0])
        w.raw("UPDATE outbox_delivery SET copy_hour = ? WHERE relay_id = ?", Time.floorHour(w.now) - RetentionPolicy.STORE_WINDOW_SECONDS + HOUR, relays[0])
        assertEquals(setOf(relays[1], relays[2]), due())
    }

    @Test
    fun notBeforeAndDeadlineGatePlanningAndLease(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.standardSet()
        w.mode = PrivacyMode.HIGH
        w.random.sendDelayValue = 0.5 // 5 minutes
        val op = w.enqueue(1, ns, deadline = w.now + 2 * HOUR)
        assertTrue(w.tx { w.outbox.dueStores(it, w.now, 32) }.isEmpty())
        assertNull(w.tx { w.outbox.lease(it, op, relays[0], w.now, 60) })
        w.clock.advance(5 * MINUTE)
        assertEquals(3, w.tx { w.outbox.dueStores(it, w.now, 32) }.size)
        w.clock.now = SyncWorld.T0 + 2 * HOUR
        assertTrue(w.tx { w.outbox.dueStores(it, w.now, 32) }.isEmpty())
        assertNull(w.tx { w.outbox.lease(it, op, relays[0], w.now, 60) })
    }

    @Test
    fun aBackwardClockJumpDoesNotStrandDueTimes(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.standardSet()
        w.mode = PrivacyMode.HIGH
        w.random.sendDelayValue = 0.99
        val op = w.enqueue(1, ns)
        // Clock steps back by a day: not_before and next attempt are far in the "future" and treated as due.
        w.clock.advance(-DAY)
        assertEquals(3, w.tx { w.outbox.dueStores(it, w.now, 32) }.size)
        val lease = w.tx { w.outbox.lease(it, op, relays[0], w.now, HOUR) }
        assertNotNull(lease)
        assertEquals(Time.floorMinute(w.now) + HOUR, w.delivery(op, relays[0], "next_attempt_minute"))
        // A retry at most 61 minutes ahead is not due; beyond that it counts as due (§11.2 #4).
        w.tx { w.outbox.recordNotApplied(it, op, relays[0], w.now) }
        assertFalse(w.tx { w.outbox.dueStores(it, w.now, 32) }.any { it.relayId == relays[0] })
        w.raw("UPDATE outbox_delivery SET next_attempt_minute = ? WHERE relay_id = ?", Time.floorMinute(w.now) + 62 * MINUTE, relays[0])
        assertTrue(w.tx { w.outbox.dueStores(it, w.now, 32) }.any { it.relayId == relays[0] })
    }

    @Test
    fun leaseIsWriteAheadAndHappensOnce(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.standardSet()
        val op = w.enqueue(1, ns)
        w.clock.advance(25 * MINUTE + 7)
        val lease = w.tx { w.outbox.lease(it, op, relays[0], w.now, 90) }!!
        assertEquals(1L, w.delivery(op, relays[0], "inflight"))
        assertEquals(1L, w.delivery(op, relays[0], "attempts"))
        assertEquals(SyncWorld.T0, w.delivery(op, relays[0], "lease_hour"))
        assertEquals(Time.floorMinute(w.now) + 2 * MINUTE, w.delivery(op, relays[0], "next_attempt_minute"))
        assertNull(w.copyHour(op, relays[0]))
        assertArrayEquals(TestBytes.ciphertext(1), lease.ciphertext)
        assertEquals(w.hashOf(1), lease.hash)
        assertEquals(ns, lease.namespace)
        assertEquals(TestBytes.onion(1), lease.relay)
        assertEquals(CapabilityKind.WRITE, lease.capability.kind)
        assertEquals(1L, lease.capability.generation)
        assertFalse(lease.checkFirst)
        assertEquals("StoreLease(redacted)", lease.toString())
        assertNull(w.tx { w.outbox.lease(it, op, relays[0], w.now, 90) })
        assertThrows(IllegalArgumentException::class.java) { w.tx { w.outbox.lease(it, op, relays[1], w.now, 2 * HOUR) } }
    }

    @Test
    fun receiptAcksWithTheLeaseHourAsCopyHourAndRaisesTheOwnTombstone(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.standardSet()
        val op = w.enqueue(1, ns)
        val h = w.hashOf(1)
        w.tx { w.outbox.lease(it, op, relays[0], w.now, 60) }
        w.clock.advance(2 * HOUR + 30)
        val expiry = SyncWorld.T0 + 7 * DAY + HOUR
        w.hints.clear()
        assertEquals(ReceiptResult.ACKED, w.tx { w.outbox.recordReceipt(it, op, relays[0], expiry, w.now) })
        assertEquals("acked", w.state(op, relays[0]))
        assertEquals(0L, w.delivery(op, relays[0], "inflight"))
        assertEquals(SyncWorld.T0, w.copyHour(op, relays[0]))
        assertEquals(Time.floorMinute(w.now), w.delivery(op, relays[0], "ack_minute"))
        assertEquals(RetentionPolicy.expiryRetainDay(expiry), w.retainDay(ns, h))
        assertTrue(w.hints.isEmpty())
        // A later receipt with a longer expiry raises again; a shorter one never lowers it.
        w.tx { w.outbox.recordReceipt(it, op, relays[0], expiry + 30 * DAY, w.now) }
        assertEquals(RetentionPolicy.expiryRetainDay(expiry + 30 * DAY), w.retainDay(ns, h))
        w.tx { w.outbox.recordReceipt(it, op, relays[0], expiry, w.now) }
        assertEquals(RetentionPolicy.expiryRetainDay(expiry + 30 * DAY), w.retainDay(ns, h))
    }

    @Test
    fun ambiguousAndNotAppliedOutcomesDifferOnlyInTheCopyHour(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.standardSet()
        val op = w.enqueue(1, ns)
        w.tx { w.outbox.lease(it, op, relays[0], w.now, 60) }
        w.tx { w.outbox.lease(it, op, relays[1], w.now, 60) }
        assertTrue(w.tx { w.outbox.recordAmbiguous(it, op, relays[0], w.now) })
        assertTrue(w.tx { w.outbox.recordNotApplied(it, op, relays[1], w.now) })
        assertEquals(SyncWorld.T0, w.copyHour(op, relays[0]))
        assertNull(w.copyHour(op, relays[1]))
        assertEquals("pending", w.state(op, relays[0]))
        assertEquals("pending", w.state(op, relays[1]))
        // Without a lease nothing changes.
        assertFalse(w.tx { w.outbox.recordAmbiguous(it, op, relays[1], w.now) })
        assertNull(w.copyHour(op, relays[1]))
        // The earliest copy hour is kept by later attempts.
        w.clock.advance(3 * HOUR)
        val lease = w.tx { w.outbox.lease(it, op, relays[0], w.now, 60) }!!
        assertTrue(lease.checkFirst)
        assertEquals(SyncWorld.T0, lease.copyHour)
        assertTrue(lease.clearableIfAbsent)
        w.tx { w.outbox.recordAmbiguous(it, op, relays[0], w.now) }
        assertEquals(SyncWorld.T0, w.copyHour(op, relays[0]))
    }

    @Test
    fun lateReceiptOnAFailedDeliveryRecordsThePossibleCopy(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.standardSet()
        val op = w.enqueue(1, ns)
        w.tx { w.outbox.lease(it, op, relays[0], w.now, 60) }
        // The relay leaves the set while the call is in flight.
        w.tx { w.stores.namespaces.setRelays(it, ns, setOf(relays[1], relays[2])) }
        assertEquals("failed", w.state(op, relays[0]))
        assertEquals(1L, w.delivery(op, relays[0], "inflight"))
        assertEquals(ReceiptResult.LATE, w.tx { w.outbox.recordReceipt(it, op, relays[0], w.now + 7 * DAY, w.now) })
        assertEquals("failed", w.state(op, relays[0]))
        assertEquals(SyncWorld.T0, w.copyHour(op, relays[0]))
        assertEquals(0L, w.delivery(op, relays[0], "inflight"))
        assertEquals(ReceiptResult.NO_LEASE, w.tx { w.outbox.recordReceipt(it, op, relays[0], w.now + 7 * DAY, w.now) })
    }

    @Test
    fun checkBeforeRestoreFindsTheCopyOrProvesItAbsent(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.standardSet()
        val op = w.enqueue(1, ns)
        for (r in relays) {
            w.tx { w.outbox.lease(it, op, r, w.now, 60) }
            w.tx { w.outbox.recordAmbiguous(it, op, r, w.now) }
        }
        w.clock.advance(HOUR)
        // Relay 0: present → verified, copy hour kept.
        w.tx { w.outbox.lease(it, op, relays[0], w.now, 60) }
        assertTrue(w.tx { w.outbox.recordFoundByCheck(it, op, relays[0], w.now) })
        assertEquals("verified", w.state(op, relays[0]))
        assertEquals(SyncWorld.T0, w.copyHour(op, relays[0]))
        assertEquals(0L, w.delivery(op, relays[0], "inflight"))
        // Relay 1: absent while a copy of the earliest hour would still be live → forgotten; the store then acks
        // with the new lease hour as the copy hour.
        w.tx { w.outbox.lease(it, op, relays[1], w.now, 60) }
        assertTrue(w.tx { w.outbox.clearUnackedCopy(it, op, relays[1], w.now) })
        assertNull(w.copyHour(op, relays[1]))
        w.tx { w.outbox.recordReceipt(it, op, relays[1], w.now + 7 * DAY, w.now) }
        assertEquals(SyncWorld.T0 + HOUR, w.copyHour(op, relays[1]))
        // Relay 2: absent too late (now ≥ copy_hour + ttl − σ) → the copy hour stays.
        w.clock.now = SyncWorld.T0 + 4 * DAY
        w.raw("UPDATE outbox_delivery SET next_attempt_minute = 0 WHERE relay_id = ?", relays[2])
        val lease = w.tx { w.outbox.lease(it, op, relays[2], w.now, 60) }!!
        assertFalse(lease.clearableIfAbsent)
        assertFalse(w.tx { w.outbox.clearUnackedCopy(it, op, relays[2], w.now) })
        assertEquals(SyncWorld.T0, w.copyHour(op, relays[2]))
    }

    @Test
    fun anAckedCopyIsNeverForgotten(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.standardSet()
        val op = w.enqueue(1, ns)
        w.tx { w.outbox.lease(it, op, relays[0], w.now, 60) }
        w.tx { w.outbox.recordReceipt(it, op, relays[0], w.now + 7 * DAY, w.now) }
        w.clock.advance(2 * MINUTE)
        w.tx { w.outbox.recordAbsentAfterAck(it, op, relays[0], w.now) }
        assertEquals("pending", w.state(op, relays[0]))
        val lease = w.tx { w.outbox.lease(it, op, relays[0], w.now, 60) }!!
        assertTrue(lease.checkFirst)
        assertTrue(lease.acked)
        assertFalse(lease.clearableIfAbsent)
        assertFalse(w.tx { w.outbox.clearUnackedCopy(it, op, relays[0], w.now) })
        assertEquals(SyncWorld.T0, w.copyHour(op, relays[0]))
    }

    @Test
    fun leaseNormalizationTreatsLeftoverLeasesAsAmbiguous(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.standardSet()
        val op = w.enqueue(1, ns)
        w.tx { w.outbox.lease(it, op, relays[0], w.now, 60) }
        w.tx { w.outbox.lease(it, op, relays[1], w.now, 60) }
        // Process death: a new connection on the same file, then M1.
        w.reopen()
        assertEquals(2L, w.count("outbox_delivery", "inflight = 1"))
        assertEquals(2, w.tx { w.outbox.normalizeLeases(it, w.now) })
        assertEquals(0L, w.count("outbox_delivery", "inflight = 1"))
        assertEquals(SyncWorld.T0, w.copyHour(op, relays[0]))
        assertEquals(SyncWorld.T0, w.copyHour(op, relays[1]))
        assertNull(w.copyHour(op, relays[2]))
        assertEquals(0, w.tx { w.outbox.normalizeLeases(it, w.now) })
    }

    @Test
    fun rejectedOrLocalBugFailsTheDeliveryWithoutACopy(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.standardSet()
        val op = w.enqueue(1, ns)
        for (r in relays) {
            w.tx { w.outbox.lease(it, op, r, w.now, 60) }
            assertTrue(w.tx { w.outbox.failDelivery(it, op, r, w.now) })
        }
        relays.forEach { assertEquals("failed", w.state(op, it)) }
        assertEquals("failed", w.outcome(op))
        assertFalse(w.hasPayload(op))
    }
}
