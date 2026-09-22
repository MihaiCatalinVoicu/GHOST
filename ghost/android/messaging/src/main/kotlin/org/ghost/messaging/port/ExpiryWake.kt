package org.ghost.messaging.port

/**
 * The two **wakes** the sweep schedule of Phase 9 design §10.7 needs beside the passes that
 * already happen: the in-process timer (trigger 1) and the one inexact alarm (trigger 5).
 *
 * > **Sweeps run** at: (1) the actor's in-process timer (§21.9), which includes the next
 * > `delete_at_minute`, while the process lives (lag ≤ 1 min); (2) every database open; (3) the
 * > start of every foreground session and every `ConsumerTail` run; (4) every read query filters
 * > …; (5) **one inexact alarm**.
 *
 * Triggers 2, 3 and 4 need no port: the database open and the consumer tail are calls the actor
 * already receives, and the read filter is in the DAOs. These two do, because both are platform
 * facilities `:messaging` may not reach (`AlarmManager` is Android's, and a timer thread is the
 * app's to own and to stop).
 *
 * **One method, and null means cancel.** §10.7 gives the alarm a single pending intent with one
 * fixed request code and no extras, so "schedule" and "reschedule" are the same operation — a
 * second `setAndAllowWhileIdle` with the same request code replaces the first — and "nothing is
 * pending" is the cancel §10.7 requires ("cancelled when nothing is pending and at wipe"). A
 * two-method port would let a caller schedule without ever cancelling, which is the state a rooted
 * examiner reads an expiry minute out of (L7-D7).
 *
 * **The value is a wall-clock minute, not a delay.** The alarm runs on `ELAPSED_REALTIME_WAKEUP`
 * and the timer on a monotonic clock, and both conversions belong to the implementation that owns
 * that clock (§21.10 point 7: `SystemClock.elapsedRealtime() + (next − now)`). What the engine
 * knows is the minute a row becomes due, which is what it passes.
 */
fun interface ExpiryWake {

    /**
     * Wake the DM actor at [wallMinute] (unix seconds on the minute grid), or cancel every
     * outstanding wake when it is null.
     *
     * A minute already in the past is a wake as soon as possible; implementations do not have to
     * special-case it, because the pass that follows is idempotent (SWEEP deletes by time).
     */
    fun wakeAt(wallMinute: Long?)

    companion object {
        /** The port a world with no platform behind it wires: nothing is scheduled, nothing leaks. */
        val NONE: ExpiryWake = ExpiryWake { }
    }
}
