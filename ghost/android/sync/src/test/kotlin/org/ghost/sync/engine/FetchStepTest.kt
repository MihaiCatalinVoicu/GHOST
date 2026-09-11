package org.ghost.sync.engine

import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.RelayId
import org.ghost.sync.api.StatusFlag
import org.ghost.sync.engine.EngineWorld.Companion.HOUR
import org.ghost.sync.engine.EngineWorld.Companion.MINUTE
import org.ghost.sync.port.FetchedBlob
import org.ghost.sync.port.PairKey
import org.ghost.sync.store.TestBytes
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The fetch step (design §4.2, §3.6 get column, §11.3): wrong bytes make the source bad and another
 * candidate serves the blob; `not_found` is retried once after an hour, then the row is unavailable;
 * `unauthorized` refuses the token; `rejected` pauses the pair's work but never its lists (T19).
 */
class FetchStepTest {

    private class Fixture(val w: EngineWorld, val session: Session, val ns: NamespaceId, val relays: List<RelayId>) {
        val ctx: WorkContext get() = session.workContext

        fun pair(i: Int) = PairKey(relays[i], ns)

        fun fetch(i: Int): Int = w.engine.steps.fetch.run(ctx, pair(i), 8)

        /** Records a listing of [hashes] by relay [i], as the list step would. */
        fun listed(i: Int, vararg hashes: org.ghost.sync.api.BlobHash) {
            w.tx { w.stores.inboxStore.commitPage(it, relays[i], ns, hashes.toList(), ByteArray(0), ByteArray(0), w.clock.epochSeconds()) }
        }
    }

    /** An online session with no event run yet: two relays with read tokens on a listening namespace. */
    private fun fixture(w: EngineWorld): Fixture {
        w.mode = PrivacyMode.HIGH
        val relays = w.relays(1, 2)
        val ns = w.namespace(1, relays)
        relays.forEach { w.capability(it, ns, CapabilityKind.READ) }
        val (session, driver) = w.session()
        driver.runUntil(0)
        check(session.online)
        return Fixture(w, session, ns, relays)
    }

    @Test
    fun wrongBytesMakeTheSourceBadAndAnotherCandidateServesTheBlob(): Unit = EngineWorld().use { w ->
        val f = fixture(w)
        val bytes = TestBytes.ciphertext(1)
        val h = f.w.net.put(w.address(f.relays[0]), f.ns, bytes)
        w.net.put(w.address(f.relays[1]), f.ns, bytes)
        f.listed(0, h)
        f.listed(1, h)
        // Relay 0 serves other bytes of a valid size (Rust would call it malformed_response; this checks the Kotlin re-check).
        w.net.getOverride = { if (it.relay == w.address(f.relays[0])) FetchedBlob(TestBytes.ciphertext(2), w.clock.epochSeconds() + 86_400) else null }
        assertEquals(0, f.fetch(0))
        assertEquals("bad", w.string("SELECT state FROM inbox_source WHERE relay_id = ?", f.relays[0]))
        assertEquals("listed", w.inboxState(f.ns, h))
        assertEquals(2, f.session.work.breaker.failures(f.relays[0]))
        // The row's fetch lease backs off (the lease is per row, not per source).
        assertEquals(0, f.fetch(1))
        w.clock.advance(2 * MINUTE)
        assertEquals(1, f.fetch(1))
        assertEquals("fetched", w.inboxState(f.ns, h))
        assertArrayEquals(bytes, w.stores.inbox.claim(Consumer.DM, 1).single().ciphertext)
    }

    @Test
    fun notFoundIsRetriedOnceAfterAnHourThenTheRowIsUnavailable(): Unit = EngineWorld().use { w ->
        val f = fixture(w)
        val h = TestBytes.hash(9)
        f.listed(0, h)
        assertEquals(0, f.fetch(0))
        assertEquals("not_found", w.string("SELECT state FROM inbox_source WHERE relay_id = ?", f.relays[0]))
        assertEquals(0, f.fetch(0))
        assertEquals("held for an hour", 1, w.net.callsOf(TestRelays.Kind.GET).size)
        w.clock.advance(HOUR + MINUTE)
        f.fetch(0)
        assertEquals(2, w.net.callsOf(TestRelays.Kind.GET).size)
        assertEquals("unavailable", w.inboxState(f.ns, h))
        assertEquals("not_found is not a relay failure", 0, f.session.work.breaker.failures(f.relays[0]))
    }

    @Test
    fun unauthorizedRefusesTheTokenAndStopsThePairsFetches(): Unit = EngineWorld().use { w ->
        val f = fixture(w)
        val hashes = (1..3).map { w.net.put(w.address(f.relays[0]), f.ns, TestBytes.ciphertext(it)) }
        f.listed(0, *hashes.toTypedArray())
        w.net.failBefore = { if (it.kind == TestRelays.Kind.GET) "unauthorized" else null }
        assertEquals(0, f.fetch(0))
        assertEquals(1, w.net.callsOf(TestRelays.Kind.GET).size)
        assertEquals("rejected", w.string("SELECT state FROM relay_capability WHERE relay_id = ? AND kind = 'read'", f.relays[0]))
    }

    @Test
    fun rejectedPausesThePairsWorkButNeverItsLists(): Unit = EngineWorld().use { w ->
        w.mode = PrivacyMode.HIGH
        val relay = w.relays(1).single()
        val ns = w.namespace(1, listOf(relay))
        w.capability(relay, ns, CapabilityKind.READ)
        w.inbound(relay, ns, 100, 3)
        w.net.failBefore = { if (it.kind == TestRelays.Kind.GET) "rejected" else null }
        val (session, driver) = w.session()
        driver.runUntil(30 * MINUTE)
        assertEquals("one get, then the pair's work is paused for 24 h", 1, w.net.callsOf(TestRelays.Kind.GET).size)
        assertTrue(w.engine.hasFlag(StatusFlag.RELAY_REJECTS))
        assertFalse(session.workContext.allows(PairKey(relay, ns)))
        val schedule = PairSchedule(w.random, w.policy)
        val events = (0L until 200L).map { schedule.time(PairKey(relay, ns), 0, it) }.takeWhile { it <= 30 * MINUTE }
        assertEquals("lists go on at every event", events, w.net.callsOf(TestRelays.Kind.LIST).map { it.startMillis })
    }
}
