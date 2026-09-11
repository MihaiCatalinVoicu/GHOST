package org.ghost.sync.android

import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.SyncCounts
import org.ghost.sync.api.SyncDatabase
import org.ghost.sync.api.SyncStatus
import org.ghost.sync.api.TransportStatus
import org.ghost.sync.engine.SessionKind
import org.ghost.sync.engine.Session
import org.ghost.sync.engine.Steps
import org.ghost.sync.engine.SyncEngine
import org.ghost.sync.engine.ThreadedLaneRunner
import org.ghost.sync.engine.TrafficPolicy
import org.ghost.sync.port.RandomSources
import org.ghost.sync.port.SyncClock
import org.ghost.sync.port.TransportPort
import org.ghost.sync.store.SyncStores
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ThreadFactory
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * One background job's hand-off to JobScheduler (design §5.4): [finish] reports the end at most
 * once (`jobFinished(params, false)`); after [stop] (onStopJob) nothing is reported.
 */
internal class JobTicket(private val onFinished: () -> Unit) {
    private val state = AtomicInteger(OPEN)

    val stopped: Boolean get() = state.get() == STOPPED

    fun finish() {
        if (state.compareAndSet(OPEN, DONE)) onFinished()
    }

    fun stop() {
        state.compareAndSet(OPEN, STOPPED)
    }

    override fun toString(): String = "JobTicket"

    private companion object {
        const val OPEN = 0
        const val DONE = 1
        const val STOPPED = 2
    }
}

/**
 * The process-wide sync runtime (design §1.4, §5.4): the database and engine, the one transport,
 * and **at most one session**, FOREGROUND or BACKGROUND, each run on plain lane threads by a
 * [ThreadedLaneRunner]. Every decision runs on one runtime thread, in the order the commands were
 * posted; nothing on it waits for a network call.
 *
 *  - The foreground is wanted while the app is visible ([setForeground]). A background session
 *    running then stops taking items, finishes its calls in flight, and the foreground session
 *    starts. A job that arrives while the foreground is wanted returns at once.
 *  - A job opens the database for [DatabaseOpener.Purpose.BACKGROUND]; null (an auth-bound key,
 *    Q6) ends it with no network I/O.
 *  - When the app is hidden, the foreground session stops taking items; the transport is closed as
 *    soon as its calls in flight have finished (design §11.3, no timer). A session that is still
 *    bootstrapping is aborted at once instead.
 *  - Every session's end closes the transport, so the next session builds new circuits, and a
 *    job's end is always reported to JobScheduler, after the transport is closed.
 *  - [wipe] stops everything and drops the engine; no session starts again until [resume].
 *
 * Nothing here is persisted (T20). A throwable from a lane item is not caught: it reaches the
 * thread's uncaught-exception handler, which on Android ends the process (design §11.2 #11).
 */
internal class SyncRuntime(
    private val opener: DatabaseOpener,
    private val transport: TransportPort,
    private val clock: SyncClock,
    private val random: RandomSources,
    private val policy: TrafficPolicy,
    private val threads: ThreadFactory,
    private val steps: Steps = Steps.DEFAULT,
) {
    private class Run(val kind: SessionKind, val session: Session, val ticket: JobTicket?) {
        lateinit var runner: ThreadedLaneRunner
        var stopping = false
    }

    /** Global privacy mode, read by the stores and the engine at each use (default STANDARD, §11.1). */
    @Volatile
    var privacyMode: PrivacyMode = PrivacyMode.STANDARD

    private val commands = LinkedBlockingQueue<() -> Unit>()

    // Runtime-thread state.
    private var wantForeground = false
    private var wiped = false
    private var halted = false
    private var openedWith: SqlExecutor? = null

    @Volatile
    private var engine: SyncEngine? = null

    /** The public sync API over the open database (Phases 9–11), or null while none is open. */
    @Volatile
    var stores: SyncStores? = null
        private set

    private val idleLock = ReentrantLock()
    private val idleChanged = idleLock.newCondition()

    @Volatile
    private var running: Run? = null

    init {
        threads.newThread(::loop).start()
    }

    private fun loop() {
        while (true) {
            val command = commands.take()
            command()
        }
    }

    /** Runs [command] on the runtime thread after every command posted before it. */
    fun post(command: () -> Unit) {
        commands.put(command)
    }

    /** The app became visible (true) or hidden (false). */
    fun setForeground(visible: Boolean) = post {
        wantForeground = visible
        reconcile()
    }

    /** The database became usable (key created, unlocked): lifts a [wipe] and re-evaluates. */
    fun resume() = post {
        wiped = false
        reconcile()
    }

    /** Local data is being wiped: stop the session at once and drop the engine. */
    fun wipe() = post {
        wiped = true
        running?.let { stop(it, abortNow = true) }
        engine = null
        stores = null
        openedWith = null
    }

    /** A JobScheduler job started; [onFinished] is called once when it ends (never after [stopJob]). */
    fun startJob(onFinished: () -> Unit): JobTicket {
        val ticket = JobTicket(onFinished)
        post { runJob(ticket) }
        return ticket
    }

    /**
     * onStopJob: the transport is aborted at once from the caller's thread, so calls in flight end
     * with `closed` (an ambiguous result the next session resolves); then the session stops.
     */
    fun stopJob(ticket: JobTicket) {
        ticket.stop()
        if (running?.ticket === ticket) transport.abort()
        post { running?.takeIf { it.ticket === ticket }?.let { stop(it, abortNow = true) } }
    }

    /** STANDARD foreground only (the session checks): a pass for due stores now; never a read event. */
    fun expedite() {
        running?.takeIf { it.kind == SessionKind.FOREGROUND }?.session?.expedite()
    }

    /** Counts and enums only; opens its own transaction when a database is open. */
    fun status(): SyncStatus =
        engine?.status() ?: SyncStatus(TransportStatus.OFF, privacyMode, emptySet(), SyncCounts.EMPTY)

    /** Kind of the session running now, if any. */
    val activeKind: SessionKind? get() = running?.kind

    /** Waits until every command posted before this call has run; false at the timeout. */
    fun awaitCommands(timeoutMillis: Long): Boolean {
        val drained = CountDownLatch(1)
        post { drained.countDown() }
        return drained.await(timeoutMillis, TimeUnit.MILLISECONDS)
    }

    /**
     * Waits until the commands posted before this call have run and no session runs (the wipe flow
     * waits here before closing the database); false at the timeout, e.g. while the app is visible
     * and its foreground session keeps running.
     */
    fun awaitIdle(timeoutMillis: Long): Boolean {
        val end = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
        if (!awaitCommands(timeoutMillis)) return false
        return idleLock.withLock {
            while (running != null) {
                val left = end - System.nanoTime()
                if (left <= 0) return@withLock false
                idleChanged.awaitNanos(left)
            }
            true
        }
    }

    // ------------------------------------------------------------------ runtime thread

    private fun runJob(ticket: JobTicket) {
        if (ticket.stopped) return
        if (wantForeground || running != null || wiped || halted) {
            ticket.finish()
            return
        }
        val e = engineFor(DatabaseOpener.Purpose.BACKGROUND)
        if (e == null || e.disabled) {
            ticket.finish()
            return
        }
        start(e, SessionKind.BACKGROUND, ticket)
    }

    private fun reconcile() {
        val run = running
        if (run != null) {
            val handover = run.kind == SessionKind.BACKGROUND && wantForeground
            val hidden = run.kind == SessionKind.FOREGROUND && !wantForeground
            // Calls in flight finish first; a session still bootstrapping has none, so it is aborted.
            if (handover || hidden) stop(run, abortNow = !run.session.online)
            return
        }
        if (!wantForeground || wiped || halted) return
        val e = engineFor(DatabaseOpener.Purpose.FOREGROUND) ?: return
        if (e.disabled) return
        start(e, SessionKind.FOREGROUND, null)
    }

    private fun stop(run: Run, abortNow: Boolean) {
        if (!run.stopping) {
            run.stopping = true
            run.session.stop()
        }
        if (abortNow) transport.abort()
    }

    /** The engine over the database [opener] gives for [purpose]; a new database gets a new engine. */
    private fun engineFor(purpose: DatabaseOpener.Purpose): SyncEngine? {
        val sql = opener.open(purpose) ?: return null
        engine?.let { if (openedWith === sql) return it }
        val database = SyncDatabase(sql)
        val newStores = SyncStores(database, clock, random) { privacyMode }
        val newEngine = SyncEngine(newStores, transport, clock, random, policy, steps) { privacyMode }
        openedWith = sql
        stores = newStores
        engine = newEngine
        return newEngine
    }

    private fun start(e: SyncEngine, kind: SessionKind, ticket: JobTicket?) {
        val run = Run(kind, e.startSession(kind), ticket)
        setRunning(run)
        val lanes = LaneThreads(run)
        run.runner = ThreadedLaneRunner(run.session, clock, lanes)
        run.runner.start()
        lanes.seal()
    }

    /** Every lane thread of [run] has ended: the session is finished (or its runner failed). */
    private fun ended(run: Run) {
        if (running !== run) return
        setRunning(null)
        transport.abort()
        if (!run.session.engine.disabled) run.session.engine.setTransportStatus(TransportStatus.OFF)
        // A runner that failed left its session unfinished; the process is ending (§11.2 #11).
        if (run.runner.hasFailed) halted = true
        run.ticket?.finish()
        reconcile()
    }

    private fun setRunning(run: Run?) = idleLock.withLock {
        running = run
        idleChanged.signalAll()
    }

    /** Makes the lane threads of [run] and posts [ended] once all of them have ended. */
    private inner class LaneThreads(private val run: Run) : ThreadFactory {
        private val made = AtomicInteger()
        private val exited = AtomicInteger()
        private val reported = AtomicBoolean()

        @Volatile
        private var sealed = false

        override fun newThread(r: Runnable): Thread {
            made.incrementAndGet()
            return threads.newThread {
                try {
                    r.run()
                } finally {
                    exited.incrementAndGet()
                    reportIfDone()
                }
            }
        }

        /** Called once the runner has made and started all its threads. */
        fun seal() {
            sealed = true
            reportIfDone()
        }

        private fun reportIfDone() {
            if (sealed && exited.get() == made.get() && reported.compareAndSet(false, true)) post { ended(run) }
        }
    }

    override fun toString(): String = "SyncRuntime"
}
