package org.ghost.sync.store

import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.Outcome
import org.ghost.sync.api.RelayEntry
import org.ghost.sync.api.SendDelay
import org.ghost.sync.api.SyncChange
import org.ghost.sync.store.SyncWorld.Companion.DAY
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** Relay-set changes, retirement, re-activation, cancel, release and outcome listing (design §3.9, §9). */
class TopologyTest {

    @Test
    fun setRelaysRepairsOnlyOpsThatStillHoldTheirPayloadAndAnOpenWindow(): Unit = SyncWorld().use { w ->
        val relays = w.relays(1, 2, 3, 4)
        val ns = w.namespace(1, relays.take(2))
        relays.forEach { w.capability(it, ns) }
        val open = w.enqueue(1, ns)
        val done = w.enqueue(2, ns)
        relays.take(2).forEach { r -> w.tx { w.outbox.failDelivery(it, done, r, w.now) } }
        assertFalse(w.hasPayload(done))
        val windowClosed = w.enqueue(3, ns, org.ghost.sync.api.TtlBucket.DAYS_30)
        w.tx { w.outbox.lease(it, windowClosed, relays[0], w.now, 60) }
        w.tx { w.outbox.recordAmbiguous(it, windowClosed, relays[0], w.now) }
        w.clock.advance(7 * DAY)
        w.hints.clear()
        // Adding relay 3 must not trip the insert trigger on the wiped op.
        w.tx { w.stores.namespaces.setRelays(it, ns, setOf(relays[0], relays[1], relays[2])) }
        assertEquals(listOf(setOf(SyncChange.TOPOLOGY)), w.hints)
        assertEquals("pending", w.state(open, relays[2]))
        assertEquals(Time.floorMinute(w.now), w.delivery(open, relays[2], "next_attempt_minute"))
        assertNull(w.state(done, relays[2]))
        assertNull(w.state(windowClosed, relays[2]))
        // Re-adding a relay that already has a delivery keeps it as it is.
        w.tx { w.stores.namespaces.setRelays(it, ns, setOf(relays[0], relays[2])) }
        assertEquals("failed", w.state(open, relays[1]))
        w.tx { w.stores.namespaces.setRelays(it, ns, setOf(relays[0], relays[1], relays[2])) }
        assertEquals("failed", w.state(open, relays[1]))
        // Unknown relays are refused before anything changes.
        val e = assertThrows(IllegalStateException::class.java) {
            w.tx { w.stores.namespaces.setRelays(it, ns, setOf(relays[0], org.ghost.sync.api.RelayId(999))) }
        }
        assertEquals("unknown relay", e.message)
    }

    @Test
    fun removingARelayFailsItsOpenDeliveriesAndKeepsTheirCopyHours(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.standardSet()
        val op = w.enqueue(1, ns)
        w.tx { w.outbox.lease(it, op, relays[0], w.now, 60) }
        w.tx { w.outbox.recordReceipt(it, op, relays[0], w.now + 7 * DAY, w.now) }
        w.tx { w.outbox.parkWithoutCapability(it, w.now) }
        w.raw("UPDATE relay_capability SET state = 'rejected' WHERE relay_id = ?", relays[1])
        w.tx { w.outbox.parkWithoutCapability(it, w.now) }
        assertEquals("wait_capability", w.state(op, relays[1]))
        w.tx { w.stores.namespaces.setRelays(it, ns, setOf(relays[2])) }
        assertEquals("failed", w.state(op, relays[0]))
        assertEquals("failed", w.state(op, relays[1]))
        assertEquals("pending", w.state(op, relays[2]))
        assertEquals(SyncWorld.T0, w.copyHour(op, relays[0]))
        assertEquals(0L, w.count("namespace_relay", "relay_id <> ?", relays[2]))
        // Cursors and capabilities of the removed pairs are kept.
        assertEquals(3L, w.count("relay_capability"))
    }

    @Test
    fun retireFailsDeliveriesInEveryNamespaceAndReAddReactivatesTheSameRow(): Unit = SyncWorld().use { w ->
        val relays = w.relays(1, 2, 3)
        val ns1 = w.namespace(1, relays)
        val ns2 = w.namespace(2, relays, listen = false)
        relays.forEach { w.capability(it, ns1); w.capability(it, ns2) }
        w.capability(relays[0], ns1, CapabilityKind.READ)
        val a = w.enqueue(1, ns1)
        val b = w.enqueue(2, ns2)
        w.tx { tx -> w.stores.cursorStore.put(tx, relays[0], ns1, ByteArray(8) { 7 }) }
        w.tx { w.stores.relayDirectory.retire(it, relays[0]) }
        assertEquals("failed", w.state(a, relays[0]))
        assertEquals("failed", w.state(b, relays[0]))
        assertEquals("retired", w.string("SELECT state FROM relay_directory WHERE relay_id = ?", relays[0]))
        assertEquals(Time.day(w.now), w.long("SELECT retired_day FROM relay_directory WHERE relay_id = ?", relays[0]))
        assertEquals(2, w.stores.relayDirectory.active().size)
        assertFalse(w.tx { w.directory.retire(it, relays[0], w.now) })
        // Retired relays are not read pairs; re-adding the same onion reactivates the row with cursor and tokens.
        assertFalse(w.tx { w.directory.readPairs(it, w.now) }.any { it.relayId == relays[0] })
        val again = w.tx {
            w.stores.relayDirectory.upsert(it, listOf(RelayEntry(TestBytes.onion(1), TestBytes.of(16, 501), RelayEntry.Source.MANIFEST)))
        }
        assertEquals(relays[0], again.values.single())
        assertEquals("active", w.string("SELECT state FROM relay_directory WHERE relay_id = ?", relays[0]))
        assertNull(w.long("SELECT retired_day FROM relay_directory WHERE relay_id = ?", relays[0]))
        assertEquals("manifest", w.string("SELECT source FROM relay_directory WHERE relay_id = ?", relays[0]))
        val pair = w.tx { w.directory.readPairs(it, w.now) }.single { it.relayId == relays[0] }
        assertEquals((1..8).map { 7.toByte() }, pair.cursor.toList())
        assertEquals(CapabilityKind.READ, pair.capability.kind)
        // The failed deliveries stay failed; only new ops get deliveries to it.
        assertEquals("failed", w.state(a, relays[0]))
        val c = w.enqueue(3, ns1)
        assertEquals("pending", w.state(c, relays[0]))
    }

    @Test
    fun cancelSucceedsOnlyWhileNoCopyCanExist(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.standardSet()
        val a = w.enqueue(1, ns)
        w.tx { w.outbox.lease(it, a, relays[0], w.now, 60) }
        w.tx { w.outbox.recordNotApplied(it, a, relays[0], w.now) }
        w.tx { w.outbox.parkWithoutCapability(it, w.now) }
        w.hints.clear()
        assertTrue(w.tx { w.stores.outbox.cancel(it, a) })
        assertEquals("failed", w.outcome(a))
        relays.forEach { assertEquals("failed", w.state(a, it)) }
        assertFalse(w.hasPayload(a))
        assertEquals(listOf(setOf(SyncChange.OUTCOMES)), w.hints)
        assertFalse(w.tx { w.stores.outbox.cancel(it, a) })
        // In flight, or a possible copy: refused.
        val b = w.enqueue(2, ns)
        w.tx { w.outbox.lease(it, b, relays[0], w.now, 60) }
        assertFalse(w.tx { w.stores.outbox.cancel(it, b) })
        w.tx { w.outbox.recordAmbiguous(it, b, relays[0], w.now) }
        assertFalse(w.tx { w.stores.outbox.cancel(it, b) })
        assertEquals("pending", w.state(b, relays[1]))
        assertFalse(w.tx { w.stores.outbox.cancel(it, TestBytes.op(77)) })
    }

    @Test
    fun releaseIsTrueExactlyOnceAndOnlyAfterTheOutcome(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.standardSet()
        val op = w.enqueue(1, ns)
        assertFalse(w.tx { w.stores.outbox.release(it, op) })
        relays.forEach { r -> w.tx { w.outbox.failDelivery(it, op, r, w.now) } }
        val listed = w.stores.outbox.outcomes(Consumer.DM, 10)
        assertEquals(listOf(op), listed.map { it.operationId })
        assertEquals(Outcome.FAILED, listed.single().outcome)
        assertNull(listed.single().resendNotAfterEpochSeconds)
        assertTrue(w.stores.outbox.outcomes(Consumer.CHANNEL, 10).isEmpty())
        assertTrue(w.tx { w.stores.outbox.release(it, op) })
        assertFalse(w.tx { w.stores.outbox.release(it, op) })
        assertTrue(w.stores.outbox.outcomes(Consumer.DM, 10).isEmpty())
        // A release rolled back with the consumer's transaction is offered again.
        val op2 = w.enqueue(2, ns)
        relays.forEach { r -> w.tx { w.outbox.failDelivery(it, op2, r, w.now) } }
        assertThrows(IllegalStateException::class.java) {
            w.tx { tx ->
                assertTrue(w.stores.outbox.release(tx, op2))
                throw IllegalStateException("consumer effect failed")
            }
        }
        assertEquals(listOf(op2), w.stores.outbox.outcomes(Consumer.DM, 10).map { it.operationId })
    }

    @Test
    fun progressCountsAcknowledgedAndVerifiedOperators(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.standardSet()
        val op = w.enqueue(1, ns)
        val p0 = w.stores.outbox.progress(op)!!
        assertEquals(0, p0.acknowledgedOperators)
        assertEquals(2, p0.requiredOperators)
        assertNull(p0.outcome)
        w.tx { w.outbox.lease(it, op, relays[0], w.now, 60) }
        w.tx { w.outbox.recordReceipt(it, op, relays[0], w.now + 7 * DAY, w.now) }
        val p1 = w.stores.outbox.progress(op)!!
        assertEquals(1, p1.acknowledgedOperators)
        assertEquals(0, p1.verifiedOperators)
        assertNull(w.stores.outbox.progress(TestBytes.op(99)))
        assertNotNull(p1.toString())
    }

    @Test
    fun registerReusesTheRowKeepsTheConsumerAndSetsModes(): Unit = SyncWorld().use { w ->
        val relays = w.relays(1, 2)
        val ns = w.namespace(1, relays)
        w.tx { w.stores.namespaces.register(it, ns, Consumer.DM, relays.toSet(), listen = false, sendDelay = SendDelay.ON) }
        assertEquals(0L, w.long("SELECT listening FROM sync_namespace"))
        assertEquals("on", w.string("SELECT send_delay FROM sync_namespace"))
        val e = assertThrows(IllegalStateException::class.java) {
            w.tx { w.stores.namespaces.register(it, ns, Consumer.CHANNEL, relays.toSet(), listen = true) }
        }
        assertEquals("namespace is registered for another consumer", e.message)
        w.tx { w.stores.namespaces.setListening(it, ns, true) }
        w.tx { w.stores.namespaces.setSendDelay(it, ns, SendDelay.OFF) }
        assertEquals(1L, w.long("SELECT listening FROM sync_namespace"))
        assertEquals("off", w.string("SELECT send_delay FROM sync_namespace"))
        val unknown = assertThrows(IllegalStateException::class.java) {
            w.tx { w.stores.namespaces.setListening(it, TestBytes.namespace(5), true) }
        }
        assertEquals("namespace is not registered", unknown.message)
        // Operator ids and addresses are never shown.
        assertEquals("RelayEntry(redacted)", w.stores.relayDirectory.active().first().toString())
        assertTrue(w.tx { w.directory.relays(it, activeOnly = false) }.size == 2)
        assertEquals(TestBytes.onion(1), w.tx { w.directory.address(it, relays[0]) })
    }
}
