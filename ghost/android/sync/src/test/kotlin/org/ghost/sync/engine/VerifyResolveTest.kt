package org.ghost.sync.engine

import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.StatusFlag
import org.ghost.sync.api.TtlBucket
import org.ghost.sync.engine.EngineWorld.Companion.HOUR
import org.ghost.sync.engine.EngineWorld.Companion.MINUTE
import org.ghost.sync.engine.EngineWorld.Companion.SECOND
import org.ghost.sync.api.OutboundBlob
import org.ghost.sync.port.TransportState
import org.ghost.sync.store.TestBytes
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Verification, resolution and maintenance on the work lane (design §3.4, §3.5, §3.7): an
 * acknowledged store the relay no longer shows is repaired, then failed at the second strike; a
 * possible copy on a parked delivery is resolved by a check; closure (M3) runs only with a trusted
 * clock.
 */
class VerifyResolveTest {

    @Test
    fun anAckAndDropRelayIsRepairedOnceThenFailedAtTheSecondStrike(): Unit = EngineWorld().use { w ->
        val (ns, relays) = w.standardSet(listen = false)
        val dropper = w.address(relays[0])
        val h = w.hashOf(1)
        // The relay acknowledges every store and has dropped the blob by the time anyone checks.
        w.net.during = { if (it.kind == TestRelays.Kind.CHECK && it.relay == dropper) w.net.drop(dropper, ns, h) }
        val (session, driver) = w.session()
        driver.runUntil(1 * SECOND)
        val op = w.enqueue(1, ns)
        session.expedite()
        driver.runUntil(30 * MINUTE)
        // The two honest relays were verified by check (write-only pairs check after 60 s): sent.
        assertEquals("verified", w.state(op, relays[1]))
        assertEquals("verified", w.state(op, relays[2]))
        assertEquals("sent", w.outcome(op))
        // The dropper: absent after ack → repair store → absent again → failed.
        assertEquals("failed", w.state(op, relays[0]))
        assertEquals(2L, w.long("SELECT strikes FROM outbox_delivery WHERE operation_id = ? AND relay_id = ?", op, relays[0]))
        assertEquals(2, w.net.callsOf(TestRelays.Kind.STORE).count { it.relay == dropper })
        assertTrue(StatusFlag.RELAY_SUSPECT in w.engine.status().flags)
        // Every check asked about the op's hash only, and at least 60 s after the receipt.
        val checks = w.net.callsOf(TestRelays.Kind.CHECK)
        assertTrue(checks.all { it.hashes == listOf(h) })
        val firstStore = w.net.callsOf(TestRelays.Kind.STORE).first { it.relay == dropper }.startMillis
        assertTrue(checks.first { it.relay == dropper }.startMillis >= firstStore + 60 * SECOND)
    }

    @Test
    fun aPossibleCopyOnAParkedDeliveryIsResolvedByACheck(): Unit = EngineWorld().use { w ->
        val (ns, relays) = w.standardSet(listen = false)
        w.capability(relays[0], ns, CapabilityKind.READ)
        val a = w.address(relays[0])
        // The first store to relay A lands, but its answer is lost.
        var lost = true
        w.net.failAfter = { if (it.kind == TestRelays.Kind.STORE && it.relay == a && lost) "timeout" else null }
        val (session, driver) = w.session()
        driver.runUntil(1 * SECOND)
        val op = w.enqueue(1, ns)
        session.expedite()
        driver.runUntil(2 * SECOND)
        lost = false
        assertNotNull(w.copyHour(op, relays[0]))
        // Then A's write token is refused: M2 parks the delivery, with its possible copy.
        w.raw("UPDATE relay_capability SET state = 'rejected' WHERE relay_id = ? AND kind = 'write'", relays[0])
        driver.runUntil(10 * MINUTE)
        // A check with the read token found the copy: verified, without another store.
        assertEquals("verified", w.state(op, relays[0]))
        assertEquals(1, w.net.callsOf(TestRelays.Kind.STORE).count { it.relay == a })
        assertTrue(w.net.callsOf(TestRelays.Kind.CHECK).any { it.relay == a })
        assertEquals("sent", w.outcome(op))
    }

    @Test
    fun closureWaitsForATrustedClock(): Unit = EngineWorld().use { w ->
        val (ns, relays) = w.standardSet(listen = false)
        w.transport.state = TransportState.UNAVAILABLE
        val (session, driver) = w.session()
        val op = TestBytes.op(1)
        w.tx { w.stores.outbox.enqueue(it, OutboundBlob(op, ns, TestBytes.ciphertext(1), TtlBucket.DAYS_7, w.clock.epochSeconds() + 3_600)) }
        driver.runUntil(3 * HOUR)
        // The caller's deadline has passed, but without READY in this process nothing is closed.
        assertEquals("pending", w.outcome(op))
        assertEquals(3L, w.count("outbox_delivery", "state = 'pending'"))
        assertTrue(w.transport.ensureCalls > 3)
        w.transport.state = TransportState.READY
        driver.runUntil(4 * HOUR)
        assertTrue(session.online)
        assertEquals("closed", w.state(op, relays[0]))
        assertEquals("failed", w.outcome(op))
        assertTrue("no store after the deadline", w.net.callsOf(TestRelays.Kind.STORE).isEmpty())
    }
}
