package org.ghost.entitlement.engine

import org.ghost.entitlement.port.EntitlementRandom
import org.ghost.sync.store.Time
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The refresh time of a received credit (design §19.29, Q31 simplified): one draw 1–14 days after the
 * drop's listening ends, due as drawn while it lies inside the issuer's refresh window, the same draw
 * placed inside [listening end, cut] when it does not, and the credit dropped when the window closes
 * before the listening ends. [RefreshPlan.due] takes no read time: every read precedes the listening's
 * end. The exact values are pinned by `entitlement_policy.txt` (`PolicyVectorsTest`).
 */
class RefreshPlanTest {

    private class Fixed(private val u: Double) : EntitlementRandom {
        override fun bytes(size: Int): ByteArray = ByteArray(size)

        override fun uniform(): Double = u

        override fun prf(domain: Int, input: ByteArray): Double = u
    }

    private val listenUntilDay = Grid.day(Grid.start(2988))
    private val end = listenUntilDay * Grid.DAY
    private val draws = listOf(0.0, 0.25, 0.5, 0.75, 0.85, 0.9, 0.9999999)

    @Test
    fun theTimeIsOneDrawOneToFourteenDaysAfterTheListening() {
        assertEquals(end + Grid.DAY, RefreshPlan.time(listenUntilDay, Fixed(0.0)))
        assertEquals(Time.ceilMinute(end + Grid.DAY + (0.5 * 13 * Grid.DAY).toLong()), RefreshPlan.time(listenUntilDay, Fixed(0.5)))
        assertEquals(end + 14 * Grid.DAY, RefreshPlan.time(listenUntilDay, Fixed(0.9999999)))
    }

    @Test
    fun aTimeInsideTheRefreshWindowIsDueAsDrawn() {
        // Epoch 229 is refreshed until start(3003) − 2 d, weeks after the draw window.
        for (u in draws) {
            val at = RefreshPlan.time(listenUntilDay, Fixed(u))
            assertEquals(at, RefreshPlan.due(at, listenUntilDay, 229))
        }
    }

    @Test
    fun aTimeAfterTheCutIsPlacedInsideTheWindowByItsDraw() {
        // Epoch 228 is refreshed until start(2990) − 2 d, 12 days after the listening ends.
        val cut = RefreshPlan.cut(228)
        assertEquals(Grid.start(2990) - 2 * Grid.DAY, cut)
        var placed = 0
        for (u in draws) {
            val at = RefreshPlan.time(listenUntilDay, Fixed(u))
            val due = checkNotNull(RefreshPlan.due(at, listenUntilDay, 228))
            assertTrue("inside [listening end, cut]", due in end..cut)
            if (at <= cut) assertEquals(at, due) else placed++
        }
        assertTrue("the fixture places some draws", placed > 0)
    }

    @Test
    fun aCutBeforeTheListeningEndsDropsTheCredit() {
        // Epoch 227 is refreshed until start(2977) − 2 d, before the listening ends at start(2988).
        assertTrue(RefreshPlan.cut(227) < end)
        for (u in draws) assertNull(RefreshPlan.due(RefreshPlan.time(listenUntilDay, Fixed(u)), listenUntilDay, 227))
    }
}
