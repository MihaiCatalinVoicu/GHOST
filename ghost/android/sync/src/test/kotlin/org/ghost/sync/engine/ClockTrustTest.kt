package org.ghost.sync.engine

import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.engine.EngineWorld.Companion.HOUR
import org.ghost.sync.engine.EngineWorld.Companion.MINUTE
import org.ghost.sync.engine.EngineWorld.Companion.SECOND
import org.ghost.sync.port.TransportState
import org.ghost.sync.store.RetentionPolicy
import org.ghost.sync.store.TestBytes
import org.ghost.sync.store.Time
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Clock trust per use (design §3.7 as corrected by §11.5, S9 finding #2): M3, the D1/D2/W sweep and
 * GC trust the wall clock only while the session is online and the wall clock has moved with the
 * monotonic clock (within 1 h) since the last READY; a step beyond that is not trusted until the
 * next READY.
 */
class ClockTrustTest {

    /** Records the clock trust of every maintenance pass. */
    private class Recorder : Maintenance() {
        val passes = ArrayList<Pair<Long, Boolean>>()

        override fun pass(ctx: EngineContext, trustedClock: Boolean): PassReport {
            passes += Pair(ctx.monotonic(), trustedClock)
            return super.pass(ctx, trustedClock)
        }
    }

    private fun EngineWorld.listeningPairs(): NamespaceId {
        val relays = relays(1, 2)
        val ns = namespace(1, relays)
        relays.forEach { capability(it, ns, CapabilityKind.READ) }
        return ns
    }

    /** A consumed blob's tombstone (only (namespace, hash, retain_until_day)). */
    private fun EngineWorld.tombstone(ns: NamespaceId, seed: Int, retainDay: Long) =
        raw("INSERT INTO inbox_blob(namespace_id, blob_hash, state, retain_until_day) VALUES (?, ?, 'done', ?)", ns, TestBytes.hash(seed), retainDay)

    private val today = Time.day(EngineWorld.T0)

    @Test
    fun garbageCollectionWaitsWhileTheSessionIsOfflineAfterAForwardClockStep() {
        val recorder = Recorder()
        EngineWorld(steps = Steps(maintenance = recorder)).use { w ->
            val ns = w.listeningPairs()
            // Due for deletion in two weeks of true time.
            w.tombstone(ns, 1, RetentionPolicy.ceil7(today + 14))
            val (session, driver) = w.session()
            driver.runUntil(1 * SECOND)
            assertTrue(session.online)
            // READY, then a transport fault: the session is offline and the transport stays unavailable.
            w.transport.state = TransportState.UNAVAILABLE
            w.net.failBefore = { if (it.kind == TestRelays.Kind.LIST) "tor_bootstrap" else null }
            driver.runUntil(2 * MINUTE)
            assertFalse(session.online)
            // The device date jumps 120 days forward; the hourly GC comes due twice while offline.
            w.clock.wallOffsetSeconds += 120 * DAY_SECONDS
            driver.runUntil(2 * HOUR + MINUTE)
            assertEquals("the tombstone outlives an untrusted clock", "done", w.inboxState(ns, TestBytes.hash(1)))
            assertTrue(recorder.passes.filter { it.first > 2 * MINUTE }.none { it.second })
        }
    }

    @Test
    fun aClockStepWhileReadyIsNotTrustedUntilTheNextReady() {
        val recorder = Recorder()
        EngineWorld(steps = Steps(maintenance = recorder)).use { w ->
            val ns = w.listeningPairs()
            val (session, driver) = w.session()
            driver.runUntil(1 * SECOND)
            assertTrue(recorder.passes.single().second)
            w.tombstone(ns, 1, RetentionPolicy.ceil7(today - 14)) // past its day for the true clock too
            w.tombstone(ns, 2, RetentionPolicy.ceil7(today + 14)) // due in two weeks of true time
            // The transport stays READY, but the wall clock steps 120 days away from the monotonic clock.
            w.clock.wallOffsetSeconds += 120 * DAY_SECONDS
            driver.runUntil(HOUR + MINUTE)
            assertTrue(session.online)
            assertEquals("done", w.inboxState(ns, TestBytes.hash(1)))
            assertEquals("done", w.inboxState(ns, TestBytes.hash(2)))
            assertTrue("no M3/M4 on a stepped clock", recorder.passes.filter { it.first > SECOND }.none { it.second })
            // Corrected again, the clock stays untrusted until the next READY.
            w.clock.wallOffsetSeconds -= 120 * DAY_SECONDS
            driver.runUntil(2 * HOUR + MINUTE)
            assertEquals("done", w.inboxState(ns, TestBytes.hash(1)))
            assertTrue(recorder.passes.filter { it.first > SECOND }.none { it.second })
            // The holder bootstraps again: the new READY re-anchors the clock, and GC and M3/M4 trust it.
            var failures = 1
            w.net.failBefore = { if (it.kind == TestRelays.Kind.LIST && failures-- > 0) "not_bootstrapped" else null }
            driver.runUntil(2 * HOUR + 3 * MINUTE)
            assertTrue(session.online)
            assertNull(w.inboxState(ns, TestBytes.hash(1)))
            assertEquals("done", w.inboxState(ns, TestBytes.hash(2)))
            assertTrue(recorder.passes.last().second)
        }
    }

    @Test
    fun smallStepsWithinAnHourStayTrusted() {
        val recorder = Recorder()
        EngineWorld(steps = Steps(maintenance = recorder)).use { w ->
            w.listeningPairs()
            val (_, driver) = w.session()
            driver.runUntil(1 * SECOND)
            w.clock.wallOffsetSeconds -= 50 * 60
            driver.runUntil(10 * MINUTE)
            w.clock.wallOffsetSeconds += 100 * 60
            driver.runUntil(20 * MINUTE)
            assertTrue(recorder.passes.size > 15)
            assertTrue(recorder.passes.all { it.second })
        }
    }

    private companion object {
        const val DAY_SECONDS: Long = 86_400
    }
}
