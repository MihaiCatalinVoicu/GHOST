package org.ghost.sync.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The update-run draw (Phase 14 design §7.3, §7.8): its own keyed domain (8), a pure function of
 * the key and the run index — the pattern of update runs depends on nothing else (P-D1) — and
 * never shared with the quiet-run or payment-hold streams (T19).
 */
class UpdateDrawTest {

    private val sources = KeyedRandomSources(ByteArray(32) { 7 })

    @Test
    fun theDrawIsDeterministicAndIndexDependent() {
        val again = KeyedRandomSources(ByteArray(32) { 7 })
        for (index in listOf(0L, 1L, 2L, 100L, 10_000L)) {
            assertEquals(sources.updateRun(index), again.updateRun(index), 0.0)
            assertEquals(sources.updateRun(index), sources.updateRun(index), 0.0)
        }
        val values = (0L..200L).map { sources.updateRun(it) }.toSet()
        assertNotEquals("200 draws give more than one value", 1, values.size)
        // About 1/24 of the draws are update runs.
        val draws = (0L..24_000L).count { sources.updateRun(it) < 1.0 / 24.0 }
        assertTrue(
            "about 1/24 of 24000 draws = 1000 +/- 30, got $draws",
            kotlin.math.abs(draws - 1000) <= 30,
        )
    }

    @Test
    fun theDrawIsItsOwnStream() {
        // Same key, same index, different domains: never the same value (a draw from one stream
        // must not be reachable through another).
        for (index in 0L..64L) {
            assertNotEquals(sources.updateRun(index), sources.quietRun(index), 0.0)
            assertNotEquals(sources.updateRun(index), sources.paymentHold(index), 0.0)
        }
        // A different key gives a different pattern.
        val other = KeyedRandomSources(ByteArray(32) { 8 })
        val mine = (0L..256L).map { sources.updateRun(it) < 1.0 / 24.0 }
        val theirs = (0L..256L).map { other.updateRun(it) < 1.0 / 24.0 }
        assertNotEquals(mine, theirs)
    }

    @Test
    fun theDrawNeverShiftsWhenOtherStreamsAdvance() {
        // Counters of the other streams advance; the indexed streams do not move (T19).
        val before = (0L..8L).map { sources.updateRun(it) }
        sources.sendDelay()
        sources.sendDelay()
        sources.selection()
        sources.requestId()
        val after = (0L..8L).map { sources.updateRun(it) }
        assertEquals(before, after)
    }
}
