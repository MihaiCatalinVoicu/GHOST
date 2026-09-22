package org.ghost.messaging.engine

import org.ghost.messaging.port.DmClock
import org.ghost.messaging.port.ExpiryWake
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit

/**
 * **The actor's in-process expiry timer** — trigger 1 of Phase 9 design §10.7, and the one §21.9
 * rule 1 sets to "min(next `delete_at_minute`, …)".
 *
 * > (1) the actor's in-process timer (§21.9), which includes the next `delete_at_minute`, while
 * > the process lives (lag ≤ 1 min)
 *
 * It is the trigger that makes the lag a **minute** rather than a Doze window: while the process
 * is alive nothing has to wait for `AlarmManager` at all. [org.ghost.messaging.android.ExpiryAlarm]
 * is the other half, for a process that is not alive, and the two are wired together behind one
 * [ExpiryWake] by [both] — they take the same minute and mean the same thing, and a device that
 * has both simply sweeps at whichever fires first.
 *
 * **One pending wake at a time.** A second [wakeAt] cancels the first, exactly as a second
 * `setAndAllowWhileIdle` with the same request code replaces the first alarm; null cancels and
 * schedules nothing, which is §10.7's "cancelled when nothing is pending and at wipe".
 *
 * **The firing thread does no work.** It calls [wake], which the wiring binds to
 * `DmActor.onTimeTrigger()` — a post, not a call — so the pass runs on the actor thread and §7.9's
 * value-state rule holds. The pass then ends by calling [wakeAt] again with the next minute, which
 * is why this class must tolerate being re-entered from another thread while a task is running,
 * and why every mutation is inside one lock.
 *
 * **No busy loop is possible**, and that is a property of [Sweeper.nextWakeMinute] rather than of
 * this class: every deadline it considers is strictly **greater** than the expiry clock it
 * compares against, so a wake is never scheduled for a minute the sweep that just ran had already
 * passed.
 */
internal class ExpiryTimer(
    private val clock: DmClock,
    private val wake: () -> Unit,
    /**
     * The seam a test replaces: schedule [wake] after a delay in seconds, and hand back something
     * that cancels it. The default is a daemon single-thread scheduler, which is what `:app` gets.
     */
    private val scheduler: (Long, () -> Unit) -> Cancellable = defaultScheduler(),
) : ExpiryWake, AutoCloseable {

    /** What [scheduler] hands back: the one pending wake, cancellable and idempotent. */
    fun interface Cancellable {
        fun cancel()
    }

    private val lock = Any()

    private var pending: Cancellable? = null

    override fun wakeAt(wallMinute: Long?) {
        synchronized(lock) {
            pending?.cancel()
            pending = null
            if (wallMinute == null) return
            // Clamped at zero: a minute already past is a wake as soon as the scheduler will run
            // it, and the sweep that follows is idempotent (§7.2).
            val delay = maxOf(0L, wallMinute - clock.nowEpochSeconds())
            pending = scheduler(delay) {
                synchronized(lock) { pending = null }
                wake()
            }
        }
    }

    /** Stops the scheduler; the process is going away or the identity was wiped (§13.7). */
    override fun close() {
        synchronized(lock) {
            pending?.cancel()
            pending = null
        }
        (scheduler as? OwnedScheduler)?.shutdown()
    }

    /** A scheduler this object owns and must shut down with itself. */
    private interface OwnedScheduler {
        fun shutdown()
    }

    companion object {
        /** The thread the wake fires on. It posts to the actor and does nothing else (§13.7). */
        const val THREAD_NAME: String = "ghost-dm-expiry"

        private fun defaultScheduler(): (Long, () -> Unit) -> Cancellable {
            val executor: ScheduledExecutorService =
                Executors.newSingleThreadScheduledExecutor { runnable ->
                    Thread(runnable, THREAD_NAME).apply { isDaemon = true }
                }
            return object : (Long, () -> Unit) -> Cancellable, OwnedScheduler {
                override fun invoke(delaySeconds: Long, task: () -> Unit): Cancellable {
                    val future = executor.schedule(task, delaySeconds, TimeUnit.SECONDS)
                    return Cancellable { future.cancel(false) }
                }

                override fun shutdown() {
                    executor.shutdownNow()
                }
            }
        }

        /**
         * The two wakes of §10.7 behind one port: the in-process timer, for the lag of a minute
         * while the process lives, and the inexact alarm, for when it does not.
         *
         * Both are given the same minute and both read null as a cancel, so a device that sweeps
         * at the timer finds nothing left when the alarm follows — which is the whole of the
         * design's "a sweep is idempotent, it deletes by time".
         */
        fun both(first: ExpiryWake, second: ExpiryWake): ExpiryWake = ExpiryWake { minute ->
            first.wakeAt(minute)
            second.wakeAt(minute)
        }
    }
}
