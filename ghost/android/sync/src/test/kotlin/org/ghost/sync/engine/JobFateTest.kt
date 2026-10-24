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

    /**
     * The update draw (Phase 14 design §7.3) and its precedence: RETURN first, the quiet run
     * before the update run (a quiet draw is never also an update run — the update draw is taken
     * among the jobs that are not quiet), the update run only while an updater is installed, and
     * a background relay session otherwise. The old three-argument decision is the same function
     * with no updater: no behavior of the existing worlds changes until they pass one (Q39).
     */
    @Test
    fun theUpdateDrawDecidesOnlyAmongTheNonQuietJobs() {
        for (occupied in listOf(true, false)) for (quiet in listOf(true, false)) {
            for (update in listOf(true, false)) for (updater in listOf(true, false)) {
                val fate = JobFate.of(occupied, quiet, update, participant = true, updater = updater)
                val expected = when {
                    occupied -> JobFate.RETURN
                    quiet -> JobFate.QUIET_RUN
                    update && updater -> JobFate.UPDATE_RUN
                    else -> JobFate.BACKGROUND_SESSION
                }
                assertEquals("occupied=$occupied quiet=$quiet update=$update updater=$updater", expected, fate)
            }
        }
        // The quiet run wins over the update run: the update draw is taken only among the
        // non-quiet jobs (1 / (7/8 × 1/24), not 1/24 of every job).
        assertEquals(
            JobFate.QUIET_RUN,
            JobFate.of(occupied = false, quietDraw = true, updateDraw = true, participant = true, updater = true),
        )
        // Without an updater installed the draw means nothing.
        assertEquals(
            JobFate.BACKGROUND_SESSION,
            JobFate.of(occupied = false, quietDraw = false, updateDraw = true, participant = true, updater = false),
        )
        // The three-argument decision is the no-updater decision.
        assertEquals(
            JobFate.of(occupied = false, quietDraw = true, participant = true),
            JobFate.of(occupied = false, quietDraw = true, updateDraw = true, participant = true, updater = false),
        )
    }
}
