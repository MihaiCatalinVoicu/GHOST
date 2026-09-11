package org.ghost.sync.engine

import org.ghost.sync.port.SyncClock
import java.util.concurrent.ThreadFactory
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.Condition
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/** The two lanes of a session (design §1.4). */
internal enum class Lane { READ, WORK }

/** One unit of lane work. [run] executes outside the scheduler lock and outside any transaction. */
internal abstract class LaneItem(val lane: Lane) {
    abstract fun run()
}

/**
 * The deterministic scheduler abstraction shared by production and tests (design §1.4, §8.2). A
 * source decides which item a lane runs next; runners only ask and report back:
 *
 *  - production: [ThreadedLaneRunner] runs [threads] plain threads per lane against real time;
 *  - tests: a deterministic driver runs one item at a time in virtual time, holding each item's
 *    completion until the virtual time its calls took, so lanes and read workers overlap exactly as
 *    they would on threads.
 *
 * Contract: [take], [wakeAt] and [complete] are called with [lock] held, by any thread; [take]
 * marks the returned item started and [complete] must follow for every item returned; a [take] at
 * or after [wakeAt] makes progress (returns an item or changes state). Code that changes the
 * source from outside a runner signals [changed] under [lock].
 */
internal interface LaneSource {
    val lock: ReentrantLock
    val changed: Condition

    /** Threads a runner gives [lane]; the source itself bounds how many items run at once. */
    fun threads(lane: Lane): Int

    /** The next item [lane] should run at monotonic time [now], or null. */
    fun take(lane: Lane, now: Long): LaneItem?

    /** Earliest monotonic time a [take] for [lane] can make progress, or null until [changed] is signalled. */
    fun wakeAt(lane: Lane, now: Long): Long?

    /** [item] ended at monotonic time [now]. */
    fun complete(item: LaneItem, now: Long)

    /** No item will ever be returned again and none is running. */
    val finished: Boolean
}

/**
 * Runs a [LaneSource] on plain threads (no coroutines, design §5.4): [LaneSource.threads] per lane,
 * each looping take → run → complete and sleeping on [LaneSource.changed] until the source's next
 * wake time. Nothing is caught: if an item throws, the runner stops every thread (the `finally`
 * marks it failed) and the throwable reaches the thread's uncaught-exception handler, which on
 * Android ends the process (design §11.2 #11); leases left in flight are normalized by M1 in the
 * next session.
 */
internal class ThreadedLaneRunner(
    private val source: LaneSource,
    private val clock: SyncClock,
    private val threadFactory: ThreadFactory,
) {
    private val threads = ArrayList<Thread>()
    private var failed = false
    private var started = false

    fun start() {
        source.lock.withLock {
            check(!started) { "runner already started" }
            started = true
        }
        for (lane in Lane.entries) {
            repeat(source.threads(lane)) { threads += threadFactory.newThread { loop(lane) } }
        }
        threads.forEach { it.start() }
    }

    /** True once every thread has ended within [timeoutMillis]. */
    fun awaitStopped(timeoutMillis: Long): Boolean {
        val end = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
        for (t in threads) {
            val left = TimeUnit.NANOSECONDS.toMillis(end - System.nanoTime())
            if (left <= 0) return threads.none { it.isAlive }
            t.join(left)
        }
        return threads.none { it.isAlive }
    }

    /** True if an item ended with a throwable and the runner stopped. */
    val hasFailed: Boolean get() = source.lock.withLock { failed }

    private fun loop(lane: Lane) {
        while (true) {
            val item = next(lane) ?: return
            var completed = false
            try {
                item.run()
                completed = true
            } finally {
                source.lock.withLock {
                    if (completed) source.complete(item, clock.monotonicMillis()) else failed = true
                    source.changed.signalAll()
                }
            }
        }
    }

    private fun next(lane: Lane): LaneItem? = source.lock.withLock {
        var item: LaneItem? = null
        while (item == null && !failed && !source.finished) {
            val now = clock.monotonicMillis()
            item = source.take(lane, now)
            if (item == null) {
                val wake = source.wakeAt(lane, now)
                if (wake == null) {
                    source.changed.await()
                } else {
                    source.changed.await(maxOf(1L, wake - now), TimeUnit.MILLISECONDS)
                }
            }
        }
        // Wake the other threads so they see the end too.
        if (item == null) source.changed.signalAll()
        item
    }

    override fun toString(): String = "ThreadedLaneRunner"
}
