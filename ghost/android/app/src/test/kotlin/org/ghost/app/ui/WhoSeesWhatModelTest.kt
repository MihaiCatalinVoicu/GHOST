package org.ghost.app.ui

import org.ghost.ui.feature.settings.WhoSeesWhatModel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Phase 13 §8.2: the "Cine vede ce" table's shape — one row per actor of plan §4 plus §8.2's
 * additions, every cell backed by a string resource id, the GOAL status constant present. The
 * strings themselves are gate-checked (G-U12 twins, G-U8 triggers); here the structure.
 */
class WhoSeesWhatModelTest {
    @Test
    fun theTableHasEveryActorAndOnlyConstants() {
        val m = WhoSeesWhatModel()
        // plan §4's eight actors plus §8.2's five additions.
        assertEquals(13, m.rows.size)
        assertEquals(m.rows.distinctBy { it.actor }.size, m.rows.size)
        for (row in m.rows) {
            assertTrue("actor id is a resource", row.actor != 0)
            assertTrue("sees id is a resource", row.sees != 0)
            assertTrue("goal id is a resource", row.goal != 0)
        }
        assertTrue(m.goalStatus != 0)
    }
}
