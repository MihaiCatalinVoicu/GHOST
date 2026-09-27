package org.ghost.sync.engine

/**
 * **What one periodic job does** (design §5.4; Phase 8 design §11.6): the decision the Android
 * runtime's `SyncRuntime.runJob` makes once the job has taken its quiet draw, as a pure function.
 *
 * It is one function so that a model of the runtime's schedule makes the runtime's decision instead of
 * a copy of it: the Phase 9 privacy world, whose DM actor gets a relay session start at a background
 * session and none at a quiet run, calls it for every job it runs (Phase 9 design §22.36, item 12: the
 * world's copy of this decision was the same kind of drift that phase review MD-2 found in its triggers).
 *
 * What the runtime does after the decision stays the runtime's: a job whose database does not open for
 * the background, or whose engine is disabled, ends at once whatever its fate, and so does a
 * [BACKGROUND_SESSION] while the payment screen holds relay sessions off (Phase 8 design §19.11).
 */
enum class JobFate {
    /** The job ends at once: the foreground is wanted (the app is visible), another activity runs, or sync is wiped or halted. */
    RETURN,

    /** A quiet run: the transport READY for the participant's one issuer call and no relay session; then the consumer tail. */
    QUIET_RUN,

    /** A background relay session; then the consumer tail. */
    BACKGROUND_SESSION,
    ;

    companion object {
        /**
         * The fate of a job: [occupied] when the foreground is wanted, another activity runs, or sync is
         * wiped or halted; [quietDraw], the job's [QuietRunScheduler.quiet] draw, which every job takes
         * whatever becomes of it; [participant], whether a session participant is installed — a run is
         * quiet only for one (Phase 8 design §11.6).
         */
        fun of(occupied: Boolean, quietDraw: Boolean, participant: Boolean): JobFate = when {
            occupied -> RETURN
            quietDraw && participant -> QUIET_RUN
            else -> BACKGROUND_SESSION
        }
    }
}
