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
 * **The value is a delay, not a wall-clock minute** (corrected by the S9 review). §21.10 point 7
 * writes the alarm as `SystemClock.elapsedRealtime() + (next − now)`, and the subtraction is the
 * engine's half, not the implementation's: the `now` of that expression is **`now_e`**, the expiry
 * clock of R-T7 (`max(floor_minute(wall), dm_self.expiry_clock_minute)`), which only the side
 * holding the database knows. While the port carried the absolute minute, each implementation
 * subtracted its own `clock.now` — so on a device whose clock had been stepped back a day, a row
 * due in an hour was scheduled for 25 hours' time and survived a day past its deadline, which is
 * precisely what R-T7 and §10.9 point 4 ("a clock stepped back one day does not delay deletion")
 * forbid. What stays with the implementation is the conversion to *its own* clock: elapsed
 * realtime for the alarm, the scheduler's own for the timer. Neither needs a wall clock at all,
 * and neither has one any more.
 */
fun interface ExpiryWake {

    /**
     * Wake the DM actor in [delaySeconds] seconds, or cancel every outstanding wake when it is
     * null.
     *
     * The value is never negative: a deadline already past is a zero delay, which is a wake as
     * soon as the platform will run it. The pass that follows is idempotent (SWEEP deletes by
     * time), so an early or a repeated wake costs nothing.
     */
    fun wakeIn(delaySeconds: Long?)

    companion object {
        /** The port a world with no platform behind it wires: nothing is scheduled, nothing leaks. */
        val NONE: ExpiryWake = ExpiryWake { }
    }
}
