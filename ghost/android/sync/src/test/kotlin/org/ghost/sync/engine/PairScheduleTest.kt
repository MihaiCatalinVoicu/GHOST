package org.ghost.sync.engine

import org.ghost.sync.api.RelayId
import org.ghost.sync.port.PairKey
import org.ghost.sync.port.SchedulePurpose
import org.ghost.sync.store.TestBytes
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** Per-pair schedules with a keyed PRF (design §6.1, §11.2 #12) and the PRF streams (§1.6). */
class PairScheduleTest {
    private val key = ByteArray(32) { it.toByte() }
    private val policy = TrafficPolicy()

    private fun pair(relay: Long, ns: Int) = PairKey(RelayId(relay), TestBytes.namespace(ns))

    @Test
    fun theScheduleIsAPureFunctionOfKeyPairAndAnchor() {
        val a = PairSchedule(KeyedRandomSources(key), policy)
        val b = PairSchedule(KeyedRandomSources(key.copyOf()), policy)
        val p = pair(1, 1)
        val timesA = (0L until 50L).map { a.time(p, 1_000, it) }
        assertEquals(timesA, (0L until 50L).map { b.time(p, 1_000, it) })
        // Another anchor shifts every time by the same amount.
        assertEquals(timesA.map { it + 5_000 }, (0L until 50L).map { a.time(p, 6_000, it) })
        // Another key gives other times; another process key is fresh (SecureRandom).
        val other = PairSchedule(KeyedRandomSources(ByteArray(32) { 9 }), policy)
        assertNotEquals(timesA, (0L until 50L).map { other.time(p, 1_000, it) })
        assertNotEquals(timesA, (0L until 50L).map { PairSchedule(KeyedRandomSources(), policy).time(p, 1_000, it) })
    }

    @Test
    fun intervalsAreFixedWithUniformJitterOfPlusMinusHalf() {
        val s = PairSchedule(KeyedRandomSources(key), policy)
        var below = 0
        var above = 0
        for (ns in 1..20) {
            val p = pair(ns.toLong(), ns)
            val first = s.firstTime(p, 0)
            assertTrue(first in 0 until policy.intervalMillis)
            var t = first
            for (k in 0L until 200L) {
                val next = s.nextTime(p, k, t)
                val step = next - t
                assertTrue("step $step", step >= policy.intervalMillis / 2 && step < policy.intervalMillis * 3 / 2)
                if (step < policy.intervalMillis) below++ else above++
                t = next
            }
        }
        // Mean step T: both halves occur about equally often.
        assertTrue(below in 1_700..2_300 && above in 1_700..2_300)
    }

    @Test
    fun pairsHaveIndependentPhasesAndSteps() {
        val s = PairSchedule(KeyedRandomSources(key), policy)
        val pairs = (1..10).map { pair(it.toLong(), it) }
        val firsts = pairs.map { s.firstTime(it, 0) }
        assertEquals("no shared tick: every pair has its own phase", pairs.size, firsts.toSet().size)
        // A pair's times do not depend on which other pairs exist (they are never an input).
        val alone = PairSchedule(KeyedRandomSources(key), policy)
        assertEquals((0L until 30L).map { s.time(pairs[3], 0, it) }, (0L until 30L).map { alone.time(pairs[3], 0, it) })
        // The same relay with another namespace, and the same namespace on another relay, differ.
        assertNotEquals(s.firstTime(pair(1, 1), 0), s.firstTime(pair(1, 2), 0))
        assertNotEquals(s.firstTime(pair(1, 1), 0), s.firstTime(pair(2, 1), 0))
    }

    @Test
    fun backgroundOffsetsAreAKeyedPermutationWithinTheWindow() {
        val s = PairSchedule(KeyedRandomSources(key), policy)
        val pairs = (1..12).map { pair(it.toLong(), it) }
        val order0 = pairs.sortedBy { s.backgroundTime(it, 100, 0) }
        val order1 = pairs.sortedBy { s.backgroundTime(it, 100, 1) }
        for (p in pairs) assertTrue(s.backgroundTime(p, 100, 0) in 100 until 100 + policy.backgroundWindowMillis)
        assertNotEquals("each job orders pairs anew", order0, order1)
        assertEquals(order0, pairs.sortedBy { PairSchedule(KeyedRandomSources(key), policy).backgroundTime(it, 5, 0) })
    }

    @Test
    fun roundRobinGroupsBeyondTheCap() {
        val capped = TrafficPolicy(maxReadPairs = 4)
        val s = PairSchedule(KeyedRandomSources(key), capped)
        assertEquals(1, s.groupCount(0))
        assertEquals(1, s.groupCount(4))
        assertEquals(2, s.groupCount(5))
        assertEquals(3, s.groupCount(10))
        val pairs = (1..10).map { pair(it.toLong(), it) }
        val groups = s.groups(pairs)
        assertEquals(setOf(0, 1, 2), groups.values.toSet())
        val sizes = groups.values.groupingBy { it }.eachCount().values
        assertTrue("balanced groups, at most the cap each", sizes.all { it in 3..4 })
        assertEquals("deterministic", groups, PairSchedule(KeyedRandomSources(key), capped).groups(pairs.reversed()))
        // Within the cap every pair is its own group 0.
        assertEquals(setOf(0), s.groups(pairs.take(4)).values.toSet())
    }

    @Test
    fun keyedStreamsAreIndependentAndRedacted() {
        val r = KeyedRandomSources(key)
        val p = pair(1, 1)
        val before = (0L until 5L).map { r.schedule(p, SchedulePurpose.FOREGROUND_STEP, it) }
        val breakerBefore = r.readBreaker(RelayId(1), 0)
        val sendDelays = (0 until 5).map { r.sendDelay() }
        // Draws on the shared streams never shift a schedule or read-breaker value (T19).
        repeat(100) { r.selection() }
        assertEquals(before, (0L until 5L).map { r.schedule(p, SchedulePurpose.FOREGROUND_STEP, it) })
        assertEquals(breakerBefore, r.readBreaker(RelayId(1), 0), 0.0)
        // The send-delay stream is its own counter: selection draws do not shift it.
        val fresh = KeyedRandomSources(key)
        assertEquals(sendDelays, (0 until 5).map { fresh.sendDelay() })
        // Values are in [0, 1), purposes differ, and the key never shows.
        val all = before + sendDelays + listOf(breakerBefore) + (0 until 1_000).map { r.selection() }
        assertTrue(all.all { it >= 0.0 && it < 1.0 })
        assertNotEquals(r.schedule(p, SchedulePurpose.FOREGROUND_START, 0), r.schedule(p, SchedulePurpose.BACKGROUND_OFFSET, 0))
        assertEquals("KeyedRandomSources(redacted)", r.toString())
        assertFalse(r.toString().contains("00010203"))
        assertThrows(IllegalArgumentException::class.java) { KeyedRandomSources(ByteArray(16)) }
    }
}
