package org.ghost.sync.engine

import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.TransportStatus
import org.ghost.sync.engine.EngineWorld.Companion.MINUTE
import org.ghost.sync.engine.EngineWorld.Companion.SECOND
import org.ghost.sync.port.PairKey
import org.ghost.sync.port.TransportState
import org.ghost.sync.store.TestBytes
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** Session lifecycle over both lanes in virtual time (design §1.4, §3.5, §5.4). */
class SessionTest {

    @Test
    fun aForegroundSessionStartsWithM1ThenListsEveryPairOnItsOwnSchedule(): Unit = EngineWorld().use { w ->
        val (ns, relays) = w.standardSet()
        val (session, driver) = w.session()
        driver.runUntil(10 * MINUTE)
        assertTrue("M1 is the first item of the session", driver.started.first().second is WorkItem.Normalize)
        assertTrue(session.online)
        assertEquals(TransportStatus.READY, w.engine.status().transport)
        val schedule = PairSchedule(w.random, w.policy)
        for (relay in relays) {
            val pair = PairKey(relay, ns)
            val times = w.net.callsOf(TestRelays.Kind.LIST).filter { it.relay == w.address(relay) }.map { it.startMillis }
            val expected = (0L until 100L).map { schedule.time(pair, 0, it) }.filter { it <= 10 * MINUTE }
            assertEquals(expected, times)
            assertTrue(times.size in 13..40)
        }
        assertTrue(w.net.callsOf(TestRelays.Kind.LIST).all { it.limit == w.policy.listLimit && it.deadlineMillis == w.policy.listDeadlineMillis })
    }

    @Test
    fun anEnqueuedBlobIsStoredOnEveryRelayAndVerifiedByListingIntoSent(): Unit = EngineWorld().use { w ->
        val (ns, relays) = w.standardSet()
        val (session, driver) = w.session()
        driver.runUntil(1 * SECOND)
        val op = w.enqueue(1, ns)
        session.expedite()
        driver.runUntil(2 * MINUTE)
        for (r in relays) {
            assertTrue(w.net.holds(w.address(r), ns, w.hashOf(1)))
            assertEquals("verified", w.state(op, r))
        }
        assertEquals("sent", w.outcome(op))
        assertEquals(3, w.net.callsOf(TestRelays.Kind.STORE).size)
        // The own blob is never fetched back (its `done` row absorbs the listing).
        assertTrue(w.net.callsOf(TestRelays.Kind.GET).isEmpty())
        assertEquals(1, w.stores.outbox.outcomes(Consumer.DM, 10).size)
    }

    @Test
    fun inboundBlobsAreListedFetchedAndHandedOffOnce(): Unit = EngineWorld().use { w ->
        val relays = w.relays(1, 2)
        val ns = w.namespace(1, relays)
        relays.forEach { w.capability(it, ns, CapabilityKind.READ) }
        // The same blob on both relays and one only on each.
        val shared = TestBytes.ciphertext(100)
        relays.forEach { w.net.put(w.address(it), ns, shared) }
        val onlyA = w.inbound(relays[0], ns, 200, 1).single()
        val onlyB = w.inbound(relays[1], ns, 300, 1).single()
        val (_, driver) = w.session()
        driver.runUntil(3 * MINUTE)
        val blobs = w.stores.inbox.claim(Consumer.DM, 10)
        assertEquals(setOf(TestBytes.sha256(shared), onlyA, onlyB), blobs.map { it.hash }.toSet())
        assertEquals("dedup across relays: one fetch per hash", 3, w.net.callsOf(TestRelays.Kind.GET).size)
        blobs.forEach { b -> w.tx { assertTrue(w.stores.inbox.markConsumed(it, b.namespace, b.hash)) } }
        driver.runUntil(10 * MINUTE)
        assertTrue(w.stores.inbox.claim(Consumer.DM, 10).isEmpty())
        assertEquals(3, w.net.callsOf(TestRelays.Kind.GET).size)
    }

    @Test
    fun aBackgroundJobGivesEachPairOneEventWithinTheWindowThenEnds(): Unit = EngineWorld().use { w ->
        val (ns, relays) = w.standardSet()
        w.inbound(relays[0], ns, 500, 40)
        val (session, driver) = w.session(SessionKind.BACKGROUND)
        assertTrue(driver.runUntilFinished(10 * MINUTE))
        assertTrue(session.isFinished())
        val lists = w.net.callsOf(TestRelays.Kind.LIST)
        assertEquals("one event per read pair", 3, lists.size)
        assertTrue(lists.all { it.startMillis in 0 until w.policy.backgroundWindowMillis })
        // 32 fetches per pair event in the background (§11.2 #2); the other 8 wait for a later job.
        assertEquals(32, w.net.callsOf(TestRelays.Kind.GET).size)
        assertEquals(8L, w.count("inbox_blob", "state = 'listed'"))
        assertEquals(1, w.transport.ensureCalls)
        assertTrue("the last item is the final GC", driver.started.last().second.let { it is WorkItem.Gc && it.last })
    }

    @Test
    fun aBackgroundJobWithoutTransportMakesNoCallAndEnds(): Unit = EngineWorld().use { w ->
        w.standardSet()
        w.transport.state = TransportState.UNAVAILABLE
        val (_, driver) = w.session(SessionKind.BACKGROUND)
        assertTrue(driver.runUntilFinished(10 * MINUTE))
        assertTrue(w.net.calls.isEmpty())
        assertEquals(TransportStatus.UNAVAILABLE, w.engine.status().transport)
        assertFalse(w.engine.readyInProcess)
    }

    @Test
    fun theBackgroundRelayWorkBudgetBoundsCallTimePerRelay(): Unit = EngineWorld().use { w ->
        val relays = w.relays(1)
        val ns = w.namespace(1, relays)
        w.capability(relays[0], ns, CapabilityKind.READ)
        w.inbound(relays[0], ns, 500, 20)
        w.net.latency = { if (it.kind == TestRelays.Kind.GET) 20 * SECOND else 0 }
        val (_, driver) = w.session(SessionKind.BACKGROUND)
        assertTrue(driver.runUntilFinished(20 * MINUTE))
        val gets = w.net.callsOf(TestRelays.Kind.GET)
        // 90 s of call time per relay: four full 20 s gets, then one bounded by the 10 s left, then none.
        assertEquals(listOf(60_000, 60_000, 50_000, 30_000, 10_000), gets.map { it.deadlineMillis })
    }

    @Test
    fun transportFaultsTakeTheSessionOfflineUntilEnsureSucceeds(): Unit = EngineWorld().use { w ->
        val (ns, relays) = w.standardSet(listen = false)
        val (session, driver) = w.session()
        driver.runUntil(1 * SECOND)
        w.enqueue(1, ns)
        var failures = 1
        w.net.failBefore = { if (it.kind == TestRelays.Kind.STORE && failures-- > 0) "not_bootstrapped" else null }
        session.expedite()
        driver.runUntil(3 * SECOND)
        // not_bootstrapped: the holder bootstraps again at once, and the stores go on.
        assertEquals(2, w.transport.ensureCalls)
        assertTrue(session.online)
        driver.runUntil(2 * MINUTE)
        assertEquals(3, relays.count { w.net.holds(w.address(it), ns, w.hashOf(1)) })

        // tor_bootstrap: close and recreate the transport after 1 minute.
        w.enqueue(2, ns)
        failures = 1
        w.net.failBefore = { if (it.kind == TestRelays.Kind.STORE && failures-- > 0) "tor_bootstrap" else null }
        val before = w.transport.ensureCalls
        session.expedite()
        driver.runFor(1 * SECOND)
        assertFalse(session.online)
        assertEquals(1, w.transport.aborts)
        assertEquals(TransportStatus.UNAVAILABLE, w.engine.status().transport)
        driver.runFor(58 * SECOND)
        assertEquals(before, w.transport.ensureCalls)
        driver.runFor(2 * SECOND)
        assertEquals(before + 1, w.transport.ensureCalls)
        assertTrue(session.online)
    }

    @Test
    fun nativeMissingDisablesSyncForTheProcess(): Unit = EngineWorld().use { w ->
        val (ns, _) = w.standardSet(listen = false)
        val (session, driver) = w.session()
        driver.runUntil(1 * SECOND)
        w.enqueue(1, ns)
        w.net.failBefore = { "native_missing" }
        session.expedite()
        driver.runUntil(10 * MINUTE)
        assertFalse(session.online)
        assertTrue(w.engine.disabled)
        assertEquals(TransportStatus.NATIVE_MISSING, w.engine.status().transport)
        assertEquals("one store attempt, then nothing", 1, w.net.calls.size)
        session.stop()
        driver.runUntilFinished(11 * MINUTE)
        assertThrows(IllegalStateException::class.java) { w.engine.startSession(SessionKind.FOREGROUND) }
    }

    @Test
    fun stopDrainsInFlightCallsAndFinishes(): Unit = EngineWorld().use { w ->
        val (ns, relays) = w.standardSet()
        w.net.latency = { 10 * SECOND }
        val (session, driver) = w.session()
        driver.runUntil(1 * SECOND)
        val op = w.enqueue(1, ns)
        // The app goes to the background while the first store is in flight (an item runs whole in
        // virtual time, so the stop comes from inside the call).
        w.net.during = { if (it.kind == TestRelays.Kind.STORE) session.stop() }
        session.expedite()
        assertTrue(driver.runUntilFinished(2 * MINUTE))
        // The in-flight store recorded its receipt; no further call was made.
        assertEquals(1, w.net.callsOf(TestRelays.Kind.STORE).size)
        val stored = relays.filter { w.net.holds(w.address(it), ns, w.hashOf(1)) }
        assertEquals(1, stored.size)
        assertEquals("acked", w.state(op, stored.single()))
        assertEquals(0L, w.count("outbox_delivery", "inflight = 1"))
        // A new session may start once the previous one finished.
        w.engine.startSession(SessionKind.FOREGROUND)
    }

    @Test
    fun m1NormalizesLeasesLeftInFlightBeforeAnyCall(): Unit = EngineWorld().use { w ->
        val (ns, relays) = w.standardSet(listen = false)
        val op = w.enqueue(1, ns)
        // A previous process leased the store and died during the call (crash point C4/C5).
        w.tx { assertNotNull(w.stores.outboxStore.lease(it, op, relays[0], w.clock.epochSeconds(), 60)) }
        assertEquals(1L, w.count("outbox_delivery", "inflight = 1"))
        val (_, driver) = w.session()
        var deadLeaseAtFirstCall = -1L
        w.net.during = {
            if (deadLeaseAtFirstCall < 0) {
                deadLeaseAtFirstCall = w.long("SELECT inflight FROM outbox_delivery WHERE operation_id = ? AND relay_id = ?", op, relays[0])!!
            }
        }
        driver.runUntil(5 * MINUTE)
        assertEquals("M1 ran before the first relay call", 0L, deadLeaseAtFirstCall)
        assertTrue(driver.started.first().second is WorkItem.Normalize)
        // The possible copy was recorded, so the next attempt checked before storing again.
        assertEquals(TestRelays.Kind.CHECK, w.net.calls.first { it.relay == w.address(relays[0]) }.kind)
        assertEquals("verified", w.state(op, relays[1]))
    }

    @Test
    fun aBackwardWallClockJumpDoesNotStrandRetries(): Unit = EngineWorld().use { w ->
        val (ns, relays) = w.standardSet(listen = false)
        val (session, driver) = w.session()
        driver.runUntil(1 * SECOND)
        val op = w.enqueue(1, ns)
        w.net.failBefore = { if (it.kind == TestRelays.Kind.STORE) "transport" else null }
        session.expedite()
        driver.runUntil(2 * SECOND)
        assertEquals(3, w.net.callsOf(TestRelays.Kind.STORE).size)
        // The wall clock steps back a day: every retry time is now more than 61 min ahead (clamp, §11.2 #4).
        w.net.failBefore = { null }
        w.clock.wallOffsetSeconds = -86_400
        driver.runUntil(2 * MINUTE)
        assertEquals(6, w.net.callsOf(TestRelays.Kind.STORE).size)
        for (r in relays) assertEquals("acked", w.state(op, r))
    }

    @Test
    fun onlyOneSessionAtATime(): Unit = EngineWorld().use { w ->
        w.standardSet()
        w.session()
        assertThrows(IllegalStateException::class.java) { w.engine.startSession(SessionKind.BACKGROUND) }
    }
}
