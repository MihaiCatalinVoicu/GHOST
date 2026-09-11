package org.ghost.sync.engine

import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.OperationId
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.RelayId
import org.ghost.sync.api.SendDelay
import org.ghost.sync.engine.EngineWorld.Companion.MINUTE
import org.ghost.sync.engine.EngineWorld.Companion.SECOND
import org.ghost.sync.port.PairKey
import org.ghost.sync.store.Time
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * When stores go out (design §3.1 step 4, §6.1, §11.2 #15): STANDARD stores as soon as due (NFR-1),
 * HIGH delays each op by U[0, 10 min] once and stores only at the pair's events, and a namespace's
 * SendDelay overrides the delay (not the event binding, which follows the global mode).
 */
class SendDelayTest {

    private fun EngineWorld.set(sendDelay: SendDelay, listen: Boolean = true): Pair<NamespaceId, List<RelayId>> {
        val relays = relays(1, 2, 3)
        val ns = namespace(1, relays, listen = listen, sendDelay = sendDelay)
        relays.forEach { capability(it, ns) }
        return Pair(ns, relays)
    }

    private fun EngineWorld.notBefore(op: OperationId): Long = long("SELECT not_before_minute FROM outbox_op WHERE operation_id = ?", op)!!

    /** Monotonic time of a wall-clock second (the virtual clock starts at T0 with 0 ms). */
    private fun monotonicOf(epochSeconds: Long): Long = (epochSeconds - EngineWorld.T0) * 1_000

    @Test
    fun standardStoresAtOnceOnExpedite(): Unit = EngineWorld().use { w ->
        val (ns, _) = w.set(SendDelay.DEFAULT)
        val (session, driver) = w.session()
        driver.runUntil(10 * SECOND)
        val op = w.enqueue(1, ns)
        assertEquals(Time.floorMinute(w.clock.epochSeconds()), w.notBefore(op))
        session.expedite()
        driver.runUntil(11 * SECOND)
        assertEquals(3, w.net.callsOf(TestRelays.Kind.STORE).size)
        assertTrue(w.net.callsOf(TestRelays.Kind.STORE).all { it.startMillis == 10 * SECOND })
    }

    @Test
    fun highModeDelaysOnceAndStoresOnlyAtPairEventsAfterNotBefore(): Unit = EngineWorld().use { w ->
        w.mode = PrivacyMode.HIGH
        val (ns, relays) = w.set(SendDelay.DEFAULT)
        val (session, driver) = w.session()
        driver.runUntil(10 * SECOND)
        val op = w.enqueue(1, ns)
        val notBefore = w.notBefore(op)
        assertTrue(notBefore > w.clock.epochSeconds() && notBefore <= w.clock.epochSeconds() + 600 + 60)
        session.expedite() // a no-op in HIGH mode
        driver.runUntil(30 * MINUTE)
        val stores = w.net.callsOf(TestRelays.Kind.STORE)
        assertEquals(3, stores.size)
        val schedule = PairSchedule(w.random, w.policy)
        for (store in stores) {
            assertTrue("after not_before", store.startMillis >= monotonicOf(notBefore))
            val relay = relays.single { w.address(it) == store.relay }
            // The store is part of the pair's event bundle: it starts at one of the pair's event times.
            val events = (0L until 200L).map { schedule.time(PairKey(relay, ns), 0, it) }
            assertTrue("store at a pair event", store.startMillis in events)
            // ...the first event at or after not_before.
            assertEquals(events.first { it >= monotonicOf(notBefore) }, store.startMillis)
        }
        assertEquals("sent", w.outcome(op))
    }

    @Test
    fun aNamespaceOverrideTurnsTheDelayOnInStandardMode(): Unit = EngineWorld().use { w ->
        val (ns, _) = w.set(SendDelay.ON, listen = false)
        val (session, driver) = w.session()
        driver.runUntil(10 * SECOND)
        val op = w.enqueue(1, ns)
        val notBefore = w.notBefore(op)
        assertTrue(notBefore > w.clock.epochSeconds())
        session.expedite()
        driver.runUntil(20 * MINUTE)
        val stores = w.net.callsOf(TestRelays.Kind.STORE)
        assertEquals(3, stores.size)
        // STANDARD stores as soon as due: at the first pass after not_before (passes run every minute).
        for (s in stores) assertTrue(s.startMillis >= monotonicOf(notBefore) && s.startMillis < monotonicOf(notBefore) + MINUTE + SECOND)
    }

    @Test
    fun aNamespaceOverrideTurnsTheDelayOffInHighModeButStoresStillWaitForAPairEvent(): Unit = EngineWorld().use { w ->
        w.mode = PrivacyMode.HIGH
        val (ns, relays) = w.set(SendDelay.OFF)
        val (_, driver) = w.session()
        driver.runUntil(10 * SECOND)
        val op = w.enqueue(1, ns)
        val enqueuedAt = w.clock.millis
        assertEquals(Time.floorMinute(w.clock.epochSeconds()), w.notBefore(op))
        driver.runUntil(10 * MINUTE)
        val schedule = PairSchedule(w.random, w.policy)
        for (store in w.net.callsOf(TestRelays.Kind.STORE)) {
            val relay = relays.single { w.address(it) == store.relay }
            val next = (0L until 200L).map { schedule.time(PairKey(relay, ns), 0, it) }.first { it >= enqueuedAt }
            assertEquals("no request caused directly by the enqueue", next, store.startMillis)
        }
        assertEquals(3, w.net.callsOf(TestRelays.Kind.STORE).size)
    }
}
