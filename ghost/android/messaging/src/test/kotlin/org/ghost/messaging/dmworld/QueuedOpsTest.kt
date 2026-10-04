package org.ghost.messaging.dmworld

import org.ghost.messaging.DmWorld
import org.ghost.messaging.api.Timer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Ops that wait for a relay round on production's triggers (design §22.39): what caused each, and
 * what becomes of one whose deadline passes first.
 *
 * The gate-scale nightlies of the privacy world failed from 2026-09-28 partly through the model
 * relay. A first flight queued for `EST-READY` and flushed by a pass between relay rounds waits for
 * the next round; when its messages expire meanwhile, SWEEP deletes their rows and never cancels the
 * ops (§10.6), and the model read each op's cause at the store — none left — so JD6 counted the
 * users' own TIMER_SETs as stores no action caused, and JD5 skipped them, R-T3 clause and all. And
 * the model stored an op whatever its deadline, where Phase 7's work lane closes it at its
 * `deadline_hour`: one went out 8 115 s late, which JD5's deadline half reported.
 *
 * Here both paths are taken on purpose. A writes to B and C to D, each with the timer set to five
 * minutes before the first text, both queued for `EST-READY`; each session ends a minute after
 * `EST-READY` flushes them, the messages expire at minute 5, and the next relay round of A comes at
 * minute 30 — before the ops' deadline (`author + 1 h`) — and of C at minute 90, after it. No plan
 * activation or job runs inside the window: the clients are activated by hand, so the only rounds
 * are the ones scheduled here.
 */
class QueuedOpsTest {

    @Test
    fun anOpWaitingForARoundKeepsItsCauseAndIsClosedAtItsDeadline() {
        assumeTrue("set -Dghost.dm.native: the privacy worlds run the real stack", DmWorld.nativeAvailable())
        assumeTrue("-Dghost.dm.privacy=off: the privacy worlds are skipped", PrivacyScale.enabled)
        val seed = PrivacySeeds.ALL[0]
        val start = DmWorld.WEEK_ORIGIN + 2_870 * DmWorld.WEEK + 2 * DmWorld.DAY
        // The plan's own activations and jobs come after the window (see the class note).
        val plan = Plan.scripted(activation = LongArray(4) { start + 3 * DmWorld.DAY }, edges = emptyList(), seed = seed)
        PrivacyWorld(PrivacyWorldConfig(seed = seed, clients = 4, days = 4, plan = plan)).use { world ->
            for (c in 0 until 4) world.schedule(start) { world.activate(c) }
            val t0 = start + DmWorld.HOUR
            for ((writer, peer) in listOf(0 to 1, 2 to 3)) {
                world.session(
                    writer, t0, 4,
                    mapOf(
                        0 to {
                            world.userAdd(writer, peer)
                            world.userSetTimer(writer, peer, Timer.MIN_5)
                            world.userSend(writer, peer, 12)
                        },
                    ),
                )
            }
            world.session(0, t0 + 30 * DmWorld.MINUTE, 1, emptyMap())
            world.session(2, t0 + 90 * DmWorld.MINUTE, 1, emptyMap())
            world.runUntil(t0 + 2 * DmWorld.HOUR)

            assertTrue("both TIMER_SETs waited for EST-READY's flush", world.timerChanges.size == 2 && world.timerChanges.all { it.queued })
            val inbox = { c: Int -> requireNotNull(world.truth.clients[c]?.inboxNamespace) }
            val storesOf = { from: Int, to: Int ->
                world.relay.events.filter { it.op == ViewOp.STORE && it.client == from && it.namespace.contentEquals(inbox(to)) }
            }
            // A's two ops: stored at minute 30, after SWEEP deleted their rows; JD6 maps both to the
            // user's actions by the cause recorded when they were enqueued.
            val a = storesOf(0, 1)
            assertTrue("A's TIMER_SET and text were stored", a.isNotEmpty())
            assertTrue("A's ops were stored at its next round", a.all { it.second == t0 + 30 * DmWorld.MINUTE })
            val joins = Joins(world)
            val jd6 = joins.jd6()
            assertTrue(jd6.failureMessage(), jd6.passed)
            // C's two ops: past their deadline at its next round, closed and never stored.
            assertTrue("C stored nothing into D's inbox: ${storesOf(2, 3).map { it.second - t0 }}", storesOf(2, 3).isEmpty())
            // JD5 sees A's TIMER_SET (it skipped a store without a cause) and finds on it exactly the
            // open defect NI-DM2 declares (§22.21 item 2): R-T3 on the pending path. When R-T3 is fixed,
            // this expectation goes with NiDm2.OPEN_DEFECTS.
            val jd5 = joins.jd5()
            assertEquals(
                listOf("a TIMER_SET from code 4 to 1 stored with TTL 3600, R-T3 says the larger bucket, 604800"),
                jd5.violations,
            )
            assertEquals("A's two ops were stored after the sweep deleted their rows", 2, world.relay.storesAfterSweep)
            assertEquals("C's two ops were closed at its next round, past their deadline", 2, world.relay.closedPastDeadline)
        }
    }
}
