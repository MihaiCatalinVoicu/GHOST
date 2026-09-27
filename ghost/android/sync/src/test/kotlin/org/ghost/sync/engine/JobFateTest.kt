package org.ghost.sync.engine

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * [JobFate], the periodic job's decision (design §5.4; Phase 8 design §11.6): a job ends at once while
 * the foreground is wanted or another activity runs, whatever its draw; a quiet draw is a quiet run
 * only while a participant is installed; every other job is a background relay session. The runtime
 * tests (`SyncRuntimeTest`, `SessionParticipantTest`) show `SyncRuntime.runJob` acting on it; the Phase 9
 * privacy world calls the same function for its jobs (Phase 9 design §22.36, item 12).
 */
class JobFateTest {

    @Test
    fun theFateOfEveryJobIsTheTable() {
        for (quiet in listOf(true, false)) for (participant in listOf(true, false)) {
            assertEquals("occupied, quiet=$quiet, participant=$participant", JobFate.RETURN, JobFate.of(occupied = true, quietDraw = quiet, participant = participant))
        }
        assertEquals(JobFate.QUIET_RUN, JobFate.of(occupied = false, quietDraw = true, participant = true))
        assertEquals("no participant: no quiet run", JobFate.BACKGROUND_SESSION, JobFate.of(occupied = false, quietDraw = true, participant = false))
        assertEquals(JobFate.BACKGROUND_SESSION, JobFate.of(occupied = false, quietDraw = false, participant = true))
        assertEquals(JobFate.BACKGROUND_SESSION, JobFate.of(occupied = false, quietDraw = false, participant = false))
    }
}
