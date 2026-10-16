package org.ghost.messaging.engine

/**
 * §11.1's checkpoint debt for the media key erasures that run **outside** SWEEP —
 * `VIEW-ONCE-OPEN`, the view-once sender cleanups of `MEDIA-OUTCOME` and `MEDIA-DEADLINE`:
 * the same §10.7 rule the DM sweeper keeps for its own deletions (`Sweeper.checkpointDue`,
 * `ChannelSweepStep.checkpointDue`). A media checkpoint that answers busy — or fails on a
 * full disk — leaves the erased key's pre-image pages in the `-wal`; the caller records the
 * debt here and SWEEP re-asks the pragma at its next pass, **even when that pass deletes
 * nothing**: an idle sweep with a standing media debt still truncates.
 *
 * Shared, not per-component: one busy pragma is one debt, whichever key erasure asked last.
 * In memory on purpose, exactly like `Sweeper.checkpointDue` — the state it describes does
 * not survive the process, and R-K1's open checkpoint is what covers the restart.
 */
internal class MediaCheckpointState {
    /** True while a media key-erasing checkpoint is owed a re-ask (§10.7's `checkpoint_due`). */
    @Volatile
    var due: Boolean = false
        private set

    /** Records one media checkpoint's answer: `!truncated` keeps the debt (the sweeper's shape). */
    fun record(truncated: Boolean) {
        due = !truncated
    }

    /** A successful pragma pays every component's debt at once; the sweep's re-ask clears this. */
    fun clearedBySweep() {
        due = false
    }
}
