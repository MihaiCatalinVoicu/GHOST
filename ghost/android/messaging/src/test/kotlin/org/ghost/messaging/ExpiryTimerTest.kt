package org.ghost.messaging

import org.ghost.messaging.engine.ExpiryTimer
import org.ghost.messaging.port.ExpiryWake
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * The in-process half of §10.7's sweep schedule (trigger 1, §21.9 rule 1): one pending wake at a
 * time, the delay passed straight through to the scheduler, null as the cancel, and a firing
 * thread that hands the work on rather than doing it.
 *
 * **The delay arrives already measured**, against `now_e` and not the wall clock (R-T7,
 * `Sweeper.nextWake`). This class holds no clock at all since the S9 review, which is the point:
 * while it subtracted `clock.now` itself, a device whose clock had been stepped back a day
 * scheduled a row due in an hour for 25 hours' time.
 *
 * The real scheduler is a daemon single-thread executor and is exercised once at the end; every
 * other case drives the seam by hand, because a test that slept for the delay would be measuring
 * the JDK.
 */
class ExpiryTimerTest {

    /** The seam: what was scheduled, and whether it was cancelled. */
    private class FakeScheduler : (Long, () -> Unit) -> ExpiryTimer.Cancellable {
        val delays = ArrayList<Long>()
        var cancels: Int = 0
        var task: (() -> Unit)? = null

        override fun invoke(delaySeconds: Long, task: () -> Unit): ExpiryTimer.Cancellable {
            delays += delaySeconds
            this.task = task
            return ExpiryTimer.Cancellable {
                cancels += 1
                this.task = null
            }
        }

        fun fire() {
            val pending = checkNotNull(task) { "nothing is scheduled" }
            task = null
            pending()
        }
    }

    @Test
    fun theDelayIsHandedToTheSchedulerUnchanged() {
        val scheduler = FakeScheduler()
        val timer = ExpiryTimer(wake = {}, scheduler = scheduler)
        timer.wakeIn(900)
        assertEquals(listOf(900L), scheduler.delays)
    }

    /** A delay already past is a wake as soon as the scheduler will run it, never a negative one. */
    @Test
    fun aMinuteAlreadyPastIsScheduledAtOnce() {
        val scheduler = FakeScheduler()
        val timer = ExpiryTimer(wake = {}, scheduler = scheduler)
        timer.wakeIn(-600)
        assertEquals(listOf(0L), scheduler.delays)
    }

    /**
     * One pending wake at a time: the second replaces the first, exactly as a second
     * `setAndAllowWhileIdle` with the same request code replaces the first alarm. Otherwise every
     * pass would leave a wake behind and an idle device would sweep once per pass it ever ran.
     */
    @Test
    fun asecondWakeReplacesTheFirst() {
        val scheduler = FakeScheduler()
        val timer = ExpiryTimer(wake = {}, scheduler = scheduler)
        timer.wakeIn(900)
        timer.wakeIn(60)
        assertEquals(listOf(900L, 60L), scheduler.delays)
        assertEquals("the first was cancelled", 1, scheduler.cancels)
    }

    /** §10.7: "cancelled when nothing is pending and at wipe" — and nothing is scheduled instead. */
    @Test
    fun nullCancelsAndSchedulesNothing() {
        val scheduler = FakeScheduler()
        val timer = ExpiryTimer(wake = {}, scheduler = scheduler)
        timer.wakeIn(900)
        timer.wakeIn(null)
        assertEquals(1, scheduler.cancels)
        assertEquals("no second schedule", listOf(900L), scheduler.delays)
        assertNull(scheduler.task)
        timer.close()
        assertEquals("closing an already-cancelled timer cancels nothing twice", 1, scheduler.cancels)
    }

    /**
     * The pass the wake starts ends by asking for the **next** wake, from the actor thread, while
     * this thread is still inside the fired task. That re-entry must schedule rather than be
     * swallowed — otherwise a device sweeps once and then never again while the process lives.
     */
    @Test
    fun aWakeThatSchedulesTheNextOneFromInsideItselfIsNotSwallowed() {
        val scheduler = FakeScheduler()
        var timer: ExpiryTimer? = null
        timer = ExpiryTimer(
            wake = { timer?.wakeIn(120) },
            scheduler = scheduler,
        )
        timer.wakeIn(60)
        scheduler.fire()
        assertEquals(listOf(60L, 120L), scheduler.delays)
        assertEquals("the fired wake was not cancelled, it completed", 0, scheduler.cancels)
    }

    /** The default scheduler really runs the task, on its own daemon thread, off the caller's. */
    @Test
    fun theDefaultSchedulerFiresOnItsOwnThread() {
        val fired = CountDownLatch(1)
        var thread: String? = null
        val timer = ExpiryTimer(wake = { thread = Thread.currentThread().name; fired.countDown() })
        timer.use {
            it.wakeIn(0)
            assertTrue("the wake fired", fired.await(5, TimeUnit.SECONDS))
        }
        assertEquals(ExpiryTimer.THREAD_NAME, thread)
    }

    /** §10.7's two triggers behind one port: both are given the same delay, and both see null. */
    @Test
    fun theTwoWakesAreDrivenTogether() {
        val first = ArrayList<Long?>()
        val second = ArrayList<Long?>()
        val both = ExpiryTimer.both(ExpiryWake { first += it }, ExpiryWake { second += it })
        both.wakeIn(2_520L)
        both.wakeIn(null)
        assertEquals(listOf<Long?>(2_520L, null), first)
        assertEquals(first, second)
    }
}
