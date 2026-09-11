package org.ghost.sync.engine

import org.ghost.sync.api.RelayId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** Backoff and breaker arithmetic (design §3.7). */
class BackoffBreakerTest {

    @Test
    fun deliveryBackoffDoublesFromOneMinuteToOneHourWithJitterAndMinuteRounding() {
        // u = 0 gives the lower bound (half), u → 1 the upper bound (whole), rounded up to the minute.
        assertEquals(60L, Backoff.retrySeconds(1, 0.0)) // 30 s → 1 min
        assertEquals(60L, Backoff.retrySeconds(1, 0.999)) // 59.97 s → 1 min
        assertEquals(60L, Backoff.retrySeconds(2, 0.0)) // 60 s
        assertEquals(120L, Backoff.retrySeconds(2, 0.999))
        assertEquals(120L, Backoff.retrySeconds(3, 0.0)) // 240 × 0.5
        assertEquals(240L, Backoff.retrySeconds(3, 0.999))
        assertEquals(1_800L, Backoff.retrySeconds(7, 0.0)) // cap 3600 × 0.5
        assertEquals(3_600L, Backoff.retrySeconds(7, 0.999))
        for (n in 1..1_000) {
            for (u in listOf(0.0, 0.25, 0.5, 0.75, 0.999999)) {
                val b = Backoff.retrySeconds(n, u)
                assertEquals("minute granularity", 0L, b % 60)
                assertTrue("within [1 min, 1 h]", b in 60..3_600)
            }
        }
        // Monotonic in the attempt number for a fixed jitter.
        for (n in 1..20) assertTrue(Backoff.retrySeconds(n + 1, 0.3) >= Backoff.retrySeconds(n, 0.3))
        assertThrows(IllegalArgumentException::class.java) { Backoff.retrySeconds(0, 0.5) }
        assertThrows(IllegalArgumentException::class.java) { Backoff.retrySeconds(1, 1.0) }
    }

    @Test
    fun transportBackoffGoesFromOneToFifteenMinutes() {
        assertEquals(listOf(1L, 2L, 4L, 8L, 15L, 15L, 15L).map { it * 60_000 }, (1..7).map { Backoff.transportMillis(it) })
        assertEquals(15 * 60_000L, Backoff.transportMillis(Int.MAX_VALUE))
    }

    @Test
    fun breakerOpeningFormula() {
        // min(60 s × 2^(f−3), 30 min) × U[0.75, 1.25]
        assertEquals(45_000L, LaneBreaker.openMillis(3, 0.0))
        assertEquals(60_000L, LaneBreaker.openMillis(3, 0.5))
        assertEquals(120_000L, LaneBreaker.openMillis(4, 0.5))
        assertEquals(960_000L, LaneBreaker.openMillis(7, 0.5))
        assertEquals(1_800_000L, LaneBreaker.openMillis(8, 0.5)) // 60 × 32 s capped at 30 min
        assertEquals(1_800_000L, LaneBreaker.openMillis(100, 0.5))
        assertTrue(LaneBreaker.openMillis(100, 0.999) < 1_800_000L * 1.25)
        assertThrows(IllegalArgumentException::class.java) { LaneBreaker.openMillis(2, 0.5) }
    }

    @Test
    fun breakerOpensAtThreeFailuresPerRelayAndASuccessResetsIt() {
        val jitters = ArrayList<Pair<RelayId, Long>>()
        val breaker = LaneBreaker { relay, index -> jitters += Pair(relay, index); 0.5 }
        val a = RelayId(1)
        val b = RelayId(2)
        breaker.failure(a, 1, 0)
        breaker.failure(a, 1, 0)
        assertTrue(breaker.allows(a, 0))
        breaker.failure(a, 1, 1_000) // third failure: open for 60 s
        assertFalse(breaker.allows(a, 1_000))
        assertEquals(61_000L, breaker.openUntil(a, 1_000))
        assertTrue("breakers are per relay", breaker.allows(b, 1_000))
        assertTrue(breaker.allows(a, 61_000))
        // The trial call after the opening fails: 4 failures, 120 s.
        breaker.failure(a, 1, 61_000)
        assertEquals(181_000L, breaker.openUntil(a, 61_000))
        // A hostile answer weighs 2.
        breaker.failure(b, 2, 0)
        assertTrue(breaker.allows(b, 0))
        breaker.failure(b, 2, 0)
        assertFalse(breaker.allows(b, 0))
        assertEquals(4, breaker.failures(b))
        // Any success closes and resets.
        breaker.success(a)
        assertTrue(breaker.allows(a, 61_001))
        assertNull(breaker.openUntil(a, 61_001))
        assertEquals(0, breaker.failures(a))
        // The jitter is asked per relay with a per-relay opening index (the read lane's keyed stream).
        assertEquals(listOf(Pair(a, 0L), Pair(a, 1L), Pair(b, 0L)), jitters)
    }
}
