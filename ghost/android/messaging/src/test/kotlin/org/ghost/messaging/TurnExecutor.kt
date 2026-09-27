package org.ghost.messaging

import java.util.concurrent.AbstractExecutorService
import java.util.concurrent.CancellationException
import java.util.concurrent.ExecutionException
import java.util.concurrent.Future
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit

/**
 * The DM actor's turns in a world that runs in virtual time (`DmActor`'s `turns`; the privacy worlds
 * and the entitlement world, phase review MD-2 and MD-3, design §22.36).
 *
 * On a device the actor is one thread: a trigger — a relay session start, the alarm, the actor timer,
 * the consumer tail, a listener hint — **posts** a turn and returns, and the turns run one at a time,
 * in the order they were posted. Here each posted turn runs on the thread that posted it, before
 * `execute` returns, so a world that calls the production entry points (`DmActor.onTimeTrigger`,
 * `onChange`, `consumerTail`) has the pass done when the call returns and stays deterministic. A turn
 * posted **from inside** a turn — a pass whose commit hints the listener, which posts the next pass —
 * is queued and runs after the turn in progress has ended, exactly where it would run behind the one
 * thread: never in the middle of another turn.
 *
 * **What a turn throws is not lost.** The actor posts its passes and drops the future (a pass that
 * threw has ended, and the work is owed again at the next trigger, §22.15's closing note), which on a
 * device is right and in a harness would hide an engine exception behind a green run. Every failed turn
 * is handed to [failed] after it ran: the privacy world keeps it and fails the world, the entitlement
 * world records an `Exception` as the actor thread would swallow it and rethrows an `Error` (an
 * injected crash), which ends the "process" there — and then the turns still queued go with it.
 *
 * A turn that waits for a turn queued behind it would wait for ever on one thread; on this executor
 * the wait is refused at once ([Turn.get]) instead of hanging the world.
 */
internal class TurnExecutor(private val failed: (Throwable) -> Unit) : AbstractExecutorService() {

    private val queue = ArrayDeque<Runnable>()
    private var running = false
    private var shut = false

    /** Turns run so far (diagnostics). */
    var turns: Long = 0
        private set

    override fun execute(command: Runnable) {
        if (shut) throw RejectedExecutionException("the DM actor is stopped")
        queue.addLast(command)
        if (!running) drain()
    }

    /**
     * Runs [block] as a thread that is **not** the actor — the thread that committed a listener
     * hint, which on a device posts and returns — with every turn it posts queued behind it: they run
     * in order once [block] has returned, so a wake the actor coalesces (`DmActor.onChange`'s flag)
     * is coalesced here as it is behind the one thread. Called from inside a turn it is that turn's
     * own code, and what it posts queues behind the turn anyway.
     */
    fun posting(block: () -> Unit) {
        if (running) {
            block()
            return
        }
        running = true
        try {
            block()
        } finally {
            running = false
        }
        drain()
    }

    private fun drain() {
        running = true
        try {
            while (true) {
                val next = queue.removeFirstOrNull() ?: break
                turns++
                // A future holds what its turn threw; a bare runnable throws it here.
                val failure = try {
                    next.run()
                    failureOf(next)
                } catch (t: Throwable) {
                    t
                }
                failure?.let(failed)
            }
        } catch (t: Throwable) {
            // [failed] rethrew: the process this world models has ended, and its queue with it.
            queue.clear()
            throw t
        } finally {
            running = false
        }
    }

    override fun <T> newTaskFor(callable: java.util.concurrent.Callable<T>): java.util.concurrent.RunnableFuture<T> =
        Turn(java.util.concurrent.FutureTask(callable))

    override fun <T> newTaskFor(runnable: Runnable, value: T): java.util.concurrent.RunnableFuture<T> =
        Turn(java.util.concurrent.FutureTask(runnable, value))

    /** A turn's future, whose wait before the turn ran is a deadlock on one thread and is refused. */
    private class Turn<T>(private val task: java.util.concurrent.FutureTask<T>) : java.util.concurrent.RunnableFuture<T> by task {
        override fun get(): T {
            check(task.isDone) { "a DM actor turn waited for a turn queued behind it: one thread would deadlock here" }
            return task.get()
        }

        override fun get(timeout: Long, unit: TimeUnit): T = get()
    }

    private fun failureOf(turn: Runnable): Throwable? {
        val future = turn as? Future<*> ?: return null
        if (!future.isDone) return null
        return try {
            future.get()
            null
        } catch (e: ExecutionException) {
            e.cause ?: e
        } catch (e: CancellationException) {
            null
        }
    }

    override fun shutdown() {
        shut = true
    }

    override fun shutdownNow(): MutableList<Runnable> {
        shut = true
        val left = queue.toMutableList()
        queue.clear()
        return left
    }

    override fun isShutdown(): Boolean = shut

    override fun isTerminated(): Boolean = shut && !running

    override fun awaitTermination(timeout: Long, unit: TimeUnit): Boolean = isTerminated

    override fun toString(): String = "TurnExecutor"
}
