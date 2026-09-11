package org.ghost.sync.store

import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.CapabilityNeed
import org.ghost.sync.api.SyncChange
import org.ghost.sync.store.SyncWorld.Companion.DAY
import org.ghost.sync.store.SyncWorld.Companion.HOUR
import org.ghost.sync.store.SyncWorld.Companion.MINUTE
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** Capability storage, use, the rejection race and parking (design §3.5 M2, §3.6, §3.8). */
class CapabilityTest {

    @Test
    fun putUpsertsWithANewGenerationAndAFlooredExpiry(): Unit = SyncWorld().use { w ->
        val relays = w.relays(1, 2)
        val ns = w.namespace(1, relays)
        w.hints.clear()
        w.capability(relays[0], ns, expiresAt = SyncWorld.T0 + 5 * HOUR + 1234)
        assertEquals(listOf(setOf(SyncChange.CAPABILITIES)), w.hints)
        assertEquals(1L, w.long("SELECT generation FROM relay_capability"))
        assertEquals(SyncWorld.T0 + 5 * HOUR, w.long("SELECT expires_hour FROM relay_capability"))
        w.raw("UPDATE relay_capability SET state = 'rejected'")
        w.capability(relays[0], ns, seed = 2)
        assertEquals(2L, w.long("SELECT generation FROM relay_capability"))
        assertEquals("usable", w.string("SELECT state FROM relay_capability"))
        assertNull(w.long("SELECT expires_hour FROM relay_capability"))
        assertArrayEquals(TestBytes.of(82, 2 * 17 + relays[0].value.toInt()), w.tx { w.caps.usable(it, relays[0], ns, CapabilityKind.WRITE, w.now) }!!.token)
        // Token length and unknown targets.
        assertThrows(IllegalArgumentException::class.java) {
            w.tx { w.stores.capabilities.put(it, relays[0], ns, CapabilityKind.READ, ByteArray(0), null) }
        }
        assertThrows(IllegalArgumentException::class.java) {
            w.tx { w.stores.capabilities.put(it, relays[0], ns, CapabilityKind.READ, ByteArray(513), null) }
        }
        val unknownNs = assertThrows(IllegalStateException::class.java) {
            w.tx { w.stores.capabilities.put(it, relays[0], TestBytes.namespace(9), CapabilityKind.READ, ByteArray(82), null) }
        }
        assertEquals("namespace is not registered", unknownNs.message)
    }

    @Test
    fun readingPrefersTheReadTokenAndFallsBackToWrite(): Unit = SyncWorld().use { w ->
        val relays = w.relays(1, 2)
        val ns = w.namespace(1, relays)
        assertNull(w.tx { w.caps.forReading(it, relays[0], ns, w.now) })
        w.capability(relays[0], ns, CapabilityKind.WRITE)
        assertEquals(CapabilityKind.WRITE, w.tx { w.caps.forReading(it, relays[0], ns, w.now) }!!.kind)
        w.capability(relays[0], ns, CapabilityKind.READ, expiresAt = w.now + 2 * HOUR)
        assertEquals(CapabilityKind.READ, w.tx { w.caps.forReading(it, relays[0], ns, w.now) }!!.kind)
        w.clock.advance(2 * HOUR)
        assertEquals(CapabilityKind.WRITE, w.tx { w.caps.forReading(it, relays[0], ns, w.now) }!!.kind)
    }

    @Test
    fun anExhaustedWriteTokenStillReadsAndChecks(): Unit = SyncWorld().use { w ->
        val relays = w.relays(1, 2)
        val ns = w.namespace(1, relays)
        w.capability(relays[0], ns, CapabilityKind.WRITE)
        // Quota is charged on store only: an exhausted write token still lists, gets and checks.
        w.raw("UPDATE relay_capability SET state = 'exhausted' WHERE relay_id = ? AND kind = 'write'", relays[0])
        assertEquals(CapabilityKind.WRITE, w.tx { w.caps.forReading(it, relays[0], ns, w.now) }!!.kind)
        assertEquals(CapabilityKind.WRITE, w.tx { w.caps.forChecking(it, relays[0], ns, w.now) }!!.kind)
        assertNull("but it never stores", w.tx { w.caps.usable(it, relays[0], ns, CapabilityKind.WRITE, w.now) })
        // Checks prefer the write token, reads the read token.
        w.capability(relays[0], ns, CapabilityKind.READ)
        assertEquals(CapabilityKind.READ, w.tx { w.caps.forReading(it, relays[0], ns, w.now) }!!.kind)
        assertEquals(CapabilityKind.WRITE, w.tx { w.caps.forChecking(it, relays[0], ns, w.now) }!!.kind)
        // A rejected write token reads nothing; checks fall back to the read token.
        w.raw("UPDATE relay_capability SET state = 'rejected' WHERE relay_id = ? AND kind = 'write'", relays[0])
        assertEquals(CapabilityKind.READ, w.tx { w.caps.forChecking(it, relays[0], ns, w.now) }!!.kind)
        w.raw("UPDATE relay_capability SET state = 'rejected' WHERE relay_id = ?", relays[0])
        assertNull(w.tx { w.caps.forReading(it, relays[0], ns, w.now) })
        assertNull(w.tx { w.caps.forChecking(it, relays[0], ns, w.now) })
    }

    @Test
    fun parkingWithoutAUsableWriteTokenAndReArmingOnPut(): Unit = SyncWorld().use { w ->
        val relays = w.relays(1, 2, 3)
        val ns = w.namespace(1, relays)
        w.capability(relays[0], ns)
        w.capability(relays[1], ns, expiresAt = w.now + HOUR)
        val op = w.enqueue(1, ns)
        assertEquals(1, w.tx { w.outbox.parkWithoutCapability(it, w.now) })
        assertEquals("wait_capability", w.state(op, relays[2]))
        w.clock.advance(HOUR)
        assertEquals(1, w.tx { w.outbox.parkWithoutCapability(it, w.now) })
        assertEquals("wait_capability", w.state(op, relays[1]))
        assertEquals("pending", w.state(op, relays[0]))
        // A read token does not re-arm; a write token does, due now.
        w.clock.advance(7 * MINUTE + 5)
        w.capability(relays[2], ns, CapabilityKind.READ)
        assertEquals("wait_capability", w.state(op, relays[2]))
        w.capability(relays[2], ns, CapabilityKind.WRITE)
        assertEquals("pending", w.state(op, relays[2]))
        assertEquals(Time.floorMinute(w.now), w.delivery(op, relays[2], "next_attempt_minute"))
        assertEquals("wait_capability", w.state(op, relays[1]))
        // A lease is never taken without a usable token, even if planning was stale.
        w.raw("UPDATE relay_capability SET state = 'exhausted' WHERE relay_id = ? AND kind = 'write'", relays[2])
        assertNull(w.tx { w.outbox.lease(it, op, relays[2], w.now, 60) })
    }

    @Test
    fun unauthorizedFromTheCurrentGenerationRejectsTheTokenAndParks(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.standardSet()
        val op = w.enqueue(1, ns)
        val lease = w.tx { w.outbox.lease(it, op, relays[0], w.now, 60) }!!
        w.hints.clear()
        val result = w.tx { w.outbox.parkForCapability(it, op, relays[0], ns, lease.capability.generation, exhausted = false, now = w.now) }
        assertEquals(ParkResult.PARKED, result)
        assertEquals("wait_capability", w.state(op, relays[0]))
        assertEquals(0L, w.delivery(op, relays[0], "inflight"))
        assertNull(w.copyHour(op, relays[0]))
        assertEquals("rejected", w.string("SELECT state FROM relay_capability WHERE relay_id = ? AND kind = 'write'", relays[0]))
        assertEquals(listOf(setOf(SyncChange.CAPABILITIES)), w.hints)
        assertTrue(CapabilityNeed(relays[0], ns, CapabilityKind.WRITE, CapabilityNeed.Reason.REJECTED) in w.stores.capabilities.needed())
    }

    @Test
    fun theRejectionRaceNeverMarksANewerToken(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.standardSet()
        val op = w.enqueue(1, ns)
        val lease = w.tx { w.outbox.lease(it, op, relays[0], w.now, 5 * MINUTE) }!!
        assertEquals(1L, lease.capability.generation)
        // Phase 8 installs generation 2 while the generation-1 call is in flight; that call then fails unauthorized.
        w.capability(relays[0], ns, seed = 5)
        val result = w.tx { w.outbox.parkForCapability(it, op, relays[0], ns, lease.capability.generation, exhausted = false, now = w.now) }
        assertEquals(ParkResult.NEWER_GENERATION, result)
        assertEquals("usable", w.string("SELECT state FROM relay_capability WHERE relay_id = ? AND kind = 'write'", relays[0]))
        assertEquals(2L, w.long("SELECT generation FROM relay_capability WHERE relay_id = ? AND kind = 'write'", relays[0]))
        assertEquals("pending", w.state(op, relays[0]))
        assertEquals(Time.floorMinute(w.now), w.delivery(op, relays[0], "next_attempt_minute"))
        // Due again at once with the new token.
        val again = w.tx { w.outbox.lease(it, op, relays[0], w.now, 60) }!!
        assertEquals(2L, again.capability.generation)
    }

    @Test
    fun aRefusedGenerationThatIsAlreadyMarkedStillParks(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.standardSet()
        val op1 = w.enqueue(1, ns)
        val op2 = w.enqueue(2, ns)
        val l1 = w.tx { w.outbox.lease(it, op1, relays[0], w.now, 60) }!!
        val l2 = w.tx { w.outbox.lease(it, op2, relays[0], w.now, 60) }!!
        w.tx { w.outbox.parkForCapability(it, op1, relays[0], ns, l1.capability.generation, exhausted = true, now = w.now) }
        assertEquals("exhausted", w.string("SELECT state FROM relay_capability WHERE relay_id = ? AND kind = 'write'", relays[0]))
        assertEquals(ParkResult.PARKED, w.tx { w.outbox.parkForCapability(it, op2, relays[0], ns, l2.capability.generation, exhausted = false, now = w.now) })
        assertEquals("exhausted", w.string("SELECT state FROM relay_capability WHERE relay_id = ? AND kind = 'write'", relays[0]))
        assertEquals("wait_capability", w.state(op2, relays[0]))
        assertTrue(CapabilityNeed(relays[0], ns, CapabilityKind.WRITE, CapabilityNeed.Reason.EXHAUSTED) in w.stores.capabilities.needed())
    }

    @Test
    fun quotaWithTheBlobPresentVerifiesInsteadOfParking(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.standardSet()
        val op = w.enqueue(1, ns)
        w.tx { w.outbox.lease(it, op, relays[0], w.now, 60) }
        w.tx { w.outbox.recordAmbiguous(it, op, relays[0], w.now) }
        w.clock.advance(2 * HOUR)
        w.tx { w.outbox.lease(it, op, relays[0], w.now, 60) }
        // store → quota; check([h]) with the same token → present.
        assertTrue(w.tx { w.outbox.recordFoundByCheck(it, op, relays[0], w.now) })
        assertEquals("verified", w.state(op, relays[0]))
        assertEquals("usable", w.string("SELECT state FROM relay_capability WHERE relay_id = ? AND kind = 'write'", relays[0]))
    }

    @Test
    fun neededReportsMissingRejectedExhaustedAndExpiring(): Unit = SyncWorld().use { w ->
        val relays = w.relays(1, 2, 3, 4)
        val listened = w.namespace(1, relays.take(3))
        val writeOnly = w.namespace(2, relays.take(3), listen = false)
        w.capability(relays[0], listened, CapabilityKind.READ, expiresAt = w.now + 23 * HOUR)
        w.capability(relays[1], listened, CapabilityKind.WRITE, expiresAt = w.now + 3 * DAY)
        w.capability(relays[0], writeOnly, CapabilityKind.WRITE)
        w.capability(relays[1], writeOnly, CapabilityKind.WRITE)
        w.raw("UPDATE relay_capability SET state = 'exhausted' WHERE relay_id = ? AND namespace_id = ?", relays[1], writeOnly)
        w.enqueue(1, writeOnly)
        val needs = w.stores.capabilities.needed().toSet()
        val expected = setOf(
            CapabilityNeed(relays[0], listened, CapabilityKind.READ, CapabilityNeed.Reason.EXPIRING),
            CapabilityNeed(relays[2], listened, CapabilityKind.READ, CapabilityNeed.Reason.MISSING),
            CapabilityNeed(relays[1], writeOnly, CapabilityKind.WRITE, CapabilityNeed.Reason.EXHAUSTED),
            CapabilityNeed(relays[2], writeOnly, CapabilityKind.WRITE, CapabilityNeed.Reason.MISSING),
        )
        assertEquals(expected, needs)
        // A retired relay needs nothing.
        w.tx { w.stores.relayDirectory.retire(it, relays[2]) }
        assertFalse(w.stores.capabilities.needed().any { it.relay == relays[2] })
        assertEquals(2, w.stores.counts().capabilityNeeds)
    }
}
