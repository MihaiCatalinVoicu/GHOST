package org.ghost.sync.engine

import org.ghost.sync.engine.EngineWorld.Companion.MINUTE
import org.ghost.sync.engine.EngineWorld.Companion.SECOND
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A background session always ends. Regression test for a bug the exit-gate harness found (seeded
 * world 8): when its remaining read events were consumed inside `take()` because the session budget
 * was spent, no item was left to complete, so nothing re-checked the end of the session; it never
 * finished and its job would only end when the OS stopped it. The second test covers the sibling
 * path (the transport lost mid-job), which already ended through the drain.
 */
class SessionEndTest {

    @Test
    fun aBackgroundSessionWhoseBudgetRunsOutBeforeItsPairEventsStillEnds(): Unit =
        EngineWorld(TrafficPolicy(backgroundSessionMillis = 12 * SECOND, backgroundWindowMillis = 90 * SECOND)).use { w ->
            val (ns, relays) = w.standardSet()
            w.inbound(relays[0], ns, 500, 4)
            val (session, driver) = w.session(SessionKind.BACKGROUND)
            assertTrue("the session ended", driver.runUntilFinished(10 * MINUTE))
            assertTrue(session.isFinished())
        }

    @Test
    fun aBackgroundSessionThatLosesItsTransportBeforeItsPairEventsStillEnds(): Unit = EngineWorld().use { w ->
        val (ns, relays) = w.standardSet()
        w.inbound(relays[0], ns, 500, 4)
        // The first list fails at the transport level: the session goes offline and drains; the other
        // pairs' events are consumed later without any item running.
        var first = true
        w.net.failBefore = { call -> if (call.kind == TestRelays.Kind.LIST && first) "tor_bootstrap".also { first = false } else null }
        val (session, driver) = w.session(SessionKind.BACKGROUND)
        assertTrue("the session ended", driver.runUntilFinished(10 * MINUTE))
        assertTrue(session.isFinished())
    }
}
