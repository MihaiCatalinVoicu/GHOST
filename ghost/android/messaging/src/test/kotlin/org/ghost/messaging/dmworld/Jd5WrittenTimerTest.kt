package org.ghost.messaging.dmworld

import org.ghost.messaging.DmWorld
import org.ghost.messaging.api.Timer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * JD5 checks a text against the timer it was **written** under, not the one in force when it was
 * stored (design §22.39). The gate-scale nightlies of the privacy world failed from 2026-09-28 on two
 * kinds of JD5 violation; one was R-T3's declared defect (§22.21 item 2), the other this join's own:
 * a first text queued for `EST-READY`'s flush, with the users' timer change queued behind it, went out
 * after the change in the bucket of the timer its L0 carries — §10.1's — and the join, which took the
 * store second for the writing one, wanted the new timer's.
 *
 * Here that path is taken on purpose, on two clients: A writes to B and changes the timer from 7 d to
 * 30 d in the same second, before `EST-READY`, so both wait for the flush. The new bucket is the larger,
 * so R-T3's open defect on the pending path does not show; what is left is the join. It must pass, and
 * the first text must have gone out after the change in 7 d — the case the first version failed on.
 */
class Jd5WrittenTimerTest {

    @Test
    fun aTextQueuedAcrossATimerChangeIsCheckedAgainstTheTimerItWasWrittenUnder() {
        assumeTrue("set -Dghost.dm.native: the privacy worlds run the real stack", DmWorld.nativeAvailable())
        assumeTrue("-Dghost.dm.privacy=off: the privacy worlds are skipped", PrivacyScale.enabled)
        val seed = PrivacySeeds.ALL[0]
        val start = DmWorld.WEEK_ORIGIN + 2_870 * DmWorld.WEEK + 2 * DmWorld.DAY
        val plan = Plan.scripted(activation = LongArray(2) { start }, edges = emptyList(), seed = seed)
        PrivacyWorld(PrivacyWorldConfig(seed = seed, clients = 2, days = 1, plan = plan)).use { world ->
            val t0 = start + DmWorld.HOUR
            // The one-scan flow of §12.2, with the timer changed right after the first send.
            world.session(
                0, t0, 12,
                mapOf(
                    0 to {
                        world.userAdd(0, 1)
                        world.userSend(0, 1, 12)
                        world.userSetTimer(0, 1, Timer.DAYS_30)
                    },
                ),
            )
            world.schedule(t0) { world.pendingDecisions.getOrPut(1) { HashMap() }[0] = true }
            world.session(1, t0 + 2 * DmWorld.MINUTE, 10, emptyMap())
            // Later texts both ways, written under the new timer.
            world.session(1, t0 + DmWorld.HOUR, 3, mapOf(0 to { world.userSend(1, 0, 20) }))
            world.session(0, t0 + 2 * DmWorld.HOUR, 3, mapOf(0 to { world.userSend(0, 1, 20) }))
            world.runUntil(t0 + 6 * DmWorld.HOUR)

            val change = world.timerChanges.single()
            assertTrue("the TIMER_SET waited for EST-READY's flush", change.queued)
            val first = world.textWritten.entries.filter { world.userTexts[it.key]?.first == 0 }.minByOrNull { it.value.order }!!
            assertTrue("the first text was written before the change", first.value.order < change.order)
            val stores = world.relay.events.filter {
                it.op == ViewOp.STORE && it.cause?.messageRef?.let(Joins::hex) == first.key
            }
            assertTrue("the first text was stored", stores.isNotEmpty())
            for (store in stores) {
                assertTrue("the first text was stored after the change", store.second > change.at)
                assertEquals("the first text keeps the bucket of the timer it was written under", 604_800L, store.ttlSeconds)
            }
            val texts = world.userTexts.size
            assertTrue("A's first text, B's acceptance reply and the two later texts: $texts", texts >= 4)
            val jd5 = Joins(world).jd5()
            assertTrue(jd5.failureMessage(), jd5.passed)
        }
    }
}
