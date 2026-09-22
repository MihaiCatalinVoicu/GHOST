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
 * time, the delay computed against the wall clock, null as the cancel, and a firing thread that
 * hands the work on rather than doing it.
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

    private val clock = MovableClock(1_800_000_000L)

    @Test
    fun theDelayIsTheDistanceToTheDueMinuteOnTheWallClock() {
        val scheduler = FakeScheduler()
        val timer = ExpiryTimer(clock, wake = {}, scheduler = scheduler)
        timer.wakeAt(clock.now + 900)
        assertEquals(listOf(900L), scheduler.delays)
    }

    /** A minute already past is a wake as soon as the scheduler will run it, never a negative delay. */
    @Test
    fun aMinuteAlreadyPastIsScheduledAtOnce() {
        val scheduler = FakeScheduler()
        val timer = ExpiryTimer(clock, wake = {}, scheduler = scheduler)
        timer.wakeAt(clock.now - 600)
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
        val timer = ExpiryTimer(clock, wake = {}, scheduler = scheduler)
        timer.wakeAt(clock.now + 900)
        timer.wakeAt(clock.now + 60)
        assertEquals(listOf(900L, 60L), scheduler.delays)
        assertEquals("the first was cancelled", 1, scheduler.cancels)
    }

    /** §10.7: "cancelled when nothing is pending and at wipe" — and nothing is scheduled instead. */
    @Test
    fun nullCancelsAndSchedulesNothing() {
        val scheduler = FakeScheduler()
        val timer = ExpiryTimer(clock, wake = {}, scheduler = scheduler)
        timer.wakeAt(clock.now + 900)
        timer.wakeAt(null)
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
            clock,
            wake = { timer?.wakeAt(clock.now + 120) },
            scheduler = scheduler,
        )
        timer.wakeAt(clock.now + 60)
        scheduler.fire()
        assertEquals(listOf(60L, 120L), scheduler.delays)
        assertEquals("the fired wake was not cancelled, it completed", 0, scheduler.cancels)
    }

    /** The default scheduler really runs the task, on its own daemon thread, off the caller's. */
    @Test
    fun theDefaultSchedulerFiresOnItsOwnThread() {
        val fired = CountDownLatch(1)
        var thread: String? = null
        val timer = ExpiryTimer(clock, wake = { thread = Thread.currentThread().name; fired.countDown() })
        timer.use {
            it.wakeAt(clock.now)
            assertTrue("the wake fired", fired.await(5, TimeUnit.SECONDS))
        }
        assertEquals(ExpiryTimer.THREAD_NAME, thread)
    }

    /** §10.7's two triggers behind one port: both are given the same minute, and both see null. */
    @Test
    fun theTwoWakesAreDrivenTogether() {
        val first = ArrayList<Long?>()
        val second = ArrayList<Long?>()
        val both = ExpiryTimer.both(ExpiryWake { first += it }, ExpiryWake { second += it })
        both.wakeAt(42 * 60L)
        both.wakeAt(null)
        assertEquals(listOf<Long?>(2_520L, null), first)
        assertEquals(first, second)
    }
}
