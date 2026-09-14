package org.ghost.sync.android

import org.ghost.network.NetworkException
import org.ghost.network.TorIssuerTransport
import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.ParticipantSession
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.SessionParticipant
import org.ghost.sync.api.SyncCounts
import org.ghost.sync.api.SyncDatabase
import org.ghost.sync.api.SyncStatus
import org.ghost.sync.api.TransportStatus
import org.ghost.sync.engine.QuietRunScheduler
import org.ghost.sync.engine.RedeemHold
import org.ghost.sync.engine.Session
import org.ghost.sync.engine.SessionKind
import org.ghost.sync.engine.Steps
import org.ghost.sync.engine.SyncEngine
import org.ghost.sync.engine.ThreadedLaneRunner
import org.ghost.sync.engine.TrafficPolicy
import org.ghost.sync.port.EntitlementCalls
import org.ghost.sync.port.LeasePort
import org.ghost.sync.port.RandomSources
import org.ghost.sync.port.SyncClock
import org.ghost.sync.port.TransportLease
import org.ghost.sync.port.TransportPort
import org.ghost.sync.port.TransportState
import org.ghost.sync.store.SyncStores
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ThreadFactory
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock
import org.ghost.sync.api.SessionKind as ParticipantKind

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

/** Leases of a runtime without participant access: every lease is closed from the start. */
internal object ClosedLeases : LeasePort {
    override fun openLease(): TransportLease = Closed

    private object Closed : TransportLease {
        override val closed: Boolean = true

        override fun awaitReady(deadlineMonotonicMillis: Long): Boolean = false

        override fun close() = Unit

        override fun <T> use(block: (EntitlementCalls) -> T): T = throw NetworkException("closed")

        override fun newFlow(): ByteArray = TorIssuerTransport.newFlow()

        override fun endFlow(flow: ByteArray) = Unit

        override fun toString(): String = "TransportLease(closed)"
    }
}

/**
 * The process-wide sync runtime (design §1.4, §5.4): the database and engine, the one transport,
 * and **at most one activity** that owns the transport: a relay session (FOREGROUND or BACKGROUND,
 * each run on plain lane threads by a [ThreadedLaneRunner]), a quiet run, or standalone user issuer
 * calls. Every decision runs on one runtime thread, in the order the commands were posted; nothing
 * on it waits for a network call.
 *
 *  - The foreground is wanted while the app is visible ([setForeground]). A background session
 *    running then stops taking items, finishes its calls in flight, and the foreground session
 *    starts. A job that arrives while the foreground is wanted returns at once.
 *  - A job opens the database for [DatabaseOpener.Purpose.BACKGROUND]; null (an auth-bound key,
 *    Q6) ends it with no network I/O.
 *  - When the app is hidden, the foreground session stops taking items; the transport is closed as
 *    soon as its calls in flight have finished (design §11.3, no timer). A session that is still
 *    bootstrapping is aborted at once instead.
 *  - Every activity's end closes the transport, so the next one builds new circuits, and a job's
 *    end is always reported to JobScheduler, after the transport is closed.
 *  - [wipe] stops everything and drops the engine; no session starts again until [resume].
 *
 * The session participant (Phase 8 design §11.6, §12.2, §19.11, §19.14; ADR-23):
 *  - Quiet runs: every job draws [QuietRunScheduler.quiet] for its index in this process, whatever
 *    becomes of the job; a quiet job, while a participant is installed, makes the transport READY,
 *    calls [SessionParticipant.onQuietRun] on its own thread, and ends (lease closed, transport
 *    aborted, job finished) when the participant returns or at the deadline, whichever comes
 *    first. It starts no relay session. Foreground sessions are never quiet; a foreground wanted
 *    during a quiet run ends it at once.
 *  - Relay sessions: once the session's transport is READY the participant gets
 *    [SessionParticipant.onRelaySession] on its own thread, with a lease that closes when the
 *    session stops. Neither callback thread is a lane thread: the session never waits for it.
 *  - The redeem hold (§17 Q29, §19.23 point 5; [RedeemHold]): a background session that started,
 *    with a participant installed, while a write need was pending stays the activity after its lanes
 *    have ended (transport READY, lease open) until the participant reports a redeem-lane step, the
 *    job's deadline, or a stop (a foreground wanted, the payment screen, onStopJob, a wipe). It is
 *    decided by the count of pending write needs at the session's start alone and never touches the
 *    lanes, so the read lane is that of the session without it (T19); a session whose transport
 *    failed is not held.
 *  - User issuer calls ([runUserIssuerCall]) are foreground actions (§8.3, §12.2: declared L3
 *    samples) and run only while the app is visible: on the foreground session's transport, or,
 *    when no relay session may run (the payment hold), on a transport made READY for them. A call
 *    posted while a session stops waits for its end. While the app is hidden a call gets a closed
 *    session, so no issuer call happens during a background session or a quiet run (P-7, T23).
 *  - Nothing relay-visible waits for a user call (R1: the issuer's answer time would set it):
 *    hiding the app closes the calls that made the transport READY for themselves, and so does a
 *    foreground session that may start (the payment hold ended); those calls fail `closed`.
 *  - The payment screen ([paymentScreenShown]) closes a running relay session at once; none starts
 *    while it is shown and for [QuietRunScheduler.paymentHoldMillis] after it was hidden (hiding
 *    the app hides it). A new process gets the hold back from [restorePaymentHold]. Quiet runs and
 *    user issuer calls are not relay sessions and are unaffected.
 *
 * No activity waits for a participant's callback or a user call to return; [awaitIdle], where the wipe
 * flow waits before closing the database, does (they use the database after their session closed).
 *
 * Nothing here is persisted (T20); the moment the payment screen was last visible is persisted by
 * the entitlement engine, which owns it. A throwable from a lane item or a participant callback is not
 * caught: it reaches the thread's uncaught-exception handler, which on Android ends the process
 * (design §11.2 #11).
 */
internal class SyncRuntime(
    private val opener: DatabaseOpener,
    private val transport: TransportPort,
    private val clock: SyncClock,
    private val random: RandomSources,
    private val policy: TrafficPolicy,
    private val threads: ThreadFactory,
    private val steps: Steps = Steps.DEFAULT,
    private val leases: LeasePort = ClosedLeases,
) {
    private class Run(val kind: SessionKind, val session: Session, val ticket: JobTicket?, val lease: TransportLease, val hold: RedeemHold) {
        lateinit var runner: ThreadedLaneRunner
        var stopping = false

        /** Its lanes have ended and its redeem hold keeps it the activity (written on the runtime thread; Q29). */
        @Volatile
        var holding = false

        /** Counted down when the run has ended (its hold's watchdog stops then). */
        val done = CountDownLatch(1)

        /** Leases of user issuer calls on this session's transport (runtime thread). */
        val userLeases = ArrayList<TransportLease>()
    }

    /** A quiet run: the transport READY for the participant alone. */
    private class Quiet(val engine: SyncEngine, val ticket: JobTicket, val lease: TransportLease, val deadline: Long) {
        /** The participant returned, or was never called. */
        val done = CountDownLatch(1)
    }

    /** User issuer calls while no session runs; they make the transport READY themselves. */
    private class UserRun(val engine: SyncEngine) {
        val leases = ArrayList<TransportLease>()
    }

    private class UserCall(val block: (ParticipantSession) -> Unit, val deadline: Long)

    /** Global privacy mode, read by the stores and the engine at each use (default STANDARD, §11.1). */
    @Volatile
    var privacyMode: PrivacyMode = PrivacyMode.STANDARD

    private val commands = LinkedBlockingQueue<() -> Unit>()
    private val schedule = QuietRunScheduler(random, clock)

    // Runtime-thread state.
    private var wantForeground = false
    private var wiped = false
    private var halted = false
    private var openedWith: SqlExecutor? = null
    private var jobIndex = 0L
    private var paymentScreen = false
    private var holdUntil = Long.MIN_VALUE
    private var holds = 0L
    private var wakeAt: Long? = null
    private val pendingUserCalls = ArrayList<UserCall>()

    @Volatile
    private var participant: SessionParticipant? = null

    @Volatile
    private var engine: SyncEngine? = null

    /** The public sync API over the open database (Phases 9–11), or null while none is open. */
    @Volatile
    var stores: SyncStores? = null
        private set

    private val idleLock = ReentrantLock()
    private val idleChanged = idleLock.newCondition()

    /** Participant and user-call threads still running (guarded by [idleLock]); they use the database. */
    private var callbackThreads = 0

    @Volatile
    private var running: Run? = null

    @Volatile
    private var quiet: Quiet? = null

    @Volatile
    private var userRun: UserRun? = null

    init {
        threads.newThread(::loop).start()
    }

    private fun loop() {
        while (true) {
            val wake = wakeAt
            val command = if (wake == null) commands.take() else commands.poll(maxOf(1L, wake - clock.monotonicMillis()), TimeUnit.MILLISECONDS)
            if (command != null) {
                command()
            } else {
                // A payment hold may have ended: a visible app gets its session.
                wakeAt = null
                reconcile()
            }
        }
    }

    /** Runs [command] on the runtime thread after every command posted before it. */
    fun post(command: () -> Unit) {
        commands.put(command)
    }

    /** The app became visible (true) or hidden (false); hiding the app hides the payment screen. */
    fun setForeground(visible: Boolean) = post {
        wantForeground = visible
        if (!visible) hidePaymentScreen()
        reconcile()
    }

    /** The database became usable (key created, unlocked): lifts a [wipe] and re-evaluates. */
    fun resume() = post {
        wiped = false
        reconcile()
    }

    /** Local data is being wiped: stop every activity at once and drop the engine. */
    fun wipe() = post {
        wiped = true
        running?.let { stop(it, abortNow = true) }
        quiet?.let { closeQuiet(it) }
        userRun?.let { closeUserRun(it) }
        engine = null
        stores = null
        openedWith = null
        dispatchUserCalls()
    }

    /** A JobScheduler job started; [onFinished] is called once when it ends (never after [stopJob]). */
    fun startJob(onFinished: () -> Unit): JobTicket {
        val ticket = JobTicket(onFinished)
        post { runJob(ticket) }
        return ticket
    }

    /**
     * onStopJob: the transport is aborted at once from the caller's thread, so calls in flight end
     * with `closed` (an ambiguous result the next session resolves); then the session or quiet run
     * stops.
     */
    fun stopJob(ticket: JobTicket) {
        ticket.stop()
        running?.takeIf { it.ticket === ticket }?.let {
            it.lease.close()
            transport.abort()
        }
        quiet?.takeIf { it.ticket === ticket }?.let {
            it.lease.close()
            transport.abort()
        }
        post {
            running?.takeIf { it.ticket === ticket }?.let { stop(it, abortNow = true) }
            quiet?.takeIf { it.ticket === ticket }?.let { quietEnded(it) }
        }
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

    /** A quiet run is in progress. */
    val quietRunning: Boolean get() = quiet != null

    /** A background session's lanes have ended and its redeem hold keeps it open (Q29). */
    val redeemHeld: Boolean get() = running?.holding == true

    /** The one session participant; it takes effect from the next session, quiet run or user call. */
    fun setParticipant(p: SessionParticipant?) {
        participant = p
    }

    /** Runs [block] exactly once on its own thread with a USER_ISSUER_CALL session (see the class doc). */
    fun runUserIssuerCall(block: (ParticipantSession) -> Unit) {
        val call = UserCall(block, clock.monotonicMillis() + userCallMillis)
        post { startUserCall(call) }
    }

    /** The payment screen is shown: a running relay session is closed at once (§19.11). */
    fun paymentScreenShown() = post {
        paymentScreen = true
        reconcile()
    }

    /** The payment screen was hidden: relay sessions stay held for a drawn hold. */
    fun paymentScreenHidden() = post {
        hidePaymentScreen()
        reconcile()
    }

    /**
     * An earlier process last showed the payment screen at [lastShownEpochSeconds] (wall clock):
     * relay sessions are held as if it had been hidden then, for a fresh draw of the hold, so never
     * longer than the longest hold from now; a running relay session is closed at once.
     */
    fun restorePaymentHold(lastShownEpochSeconds: Long) {
        require(lastShownEpochSeconds >= 0) { "moment out of range" }
        post { applyPaymentHold(lastShownEpochSeconds) }
    }

    private fun applyPaymentHold(lastShownEpochSeconds: Long) {
        val elapsedMillis = maxOf(0L, clock.epochSeconds() - lastShownEpochSeconds) * 1_000L
        val left = schedule.paymentHoldMillis(holds++) - elapsedMillis
        if (left > 0) {
            holdUntil = maxOf(holdUntil, clock.monotonicMillis() + left)
            wakeAt = holdUntil
        }
        reconcile()
    }

    /** Waits until every command posted before this call has run; false at the timeout. */
    fun awaitCommands(timeoutMillis: Long): Boolean {
        val drained = CountDownLatch(1)
        post { drained.countDown() }
        return drained.await(timeoutMillis, TimeUnit.MILLISECONDS)
    }

    /**
     * [restorePaymentHold] with the moment read by [lastShown] on the runtime thread, in this command's
     * turn: reading it may open the database (a Keystore unwrap, the key derivation, a migration), which
     * stays off the caller's (main) thread, and the hold is in place for every command posted after this
     * call, as with [restorePaymentHold]. Null, or a moment before the epoch, holds nothing.
     */
    fun restorePaymentHoldFrom(lastShown: () -> Long?) = post {
        lastShown()?.takeIf { it >= 0 }?.let(::applyPaymentHold)
    }

    /**
     * Runs [block] once, on its own thread, after every command posted before this call, with the
     * database open for the foreground ([stores] set) as a user call opens it: the entitlement engine's
     * foreground work (a pending onboarding trial retries at the foreground, Phase 8 design §8.3) needs
     * the stores, which at a cold start no session has opened yet, and none opens while the payment hold
     * keeps relay sessions off. It starts no session. Nothing runs after a [wipe], or when no database can
     * be opened. [awaitIdle] waits for the thread.
     */
    fun runWhenStoresOpen(block: () -> Unit) = post {
        if (wiped || halted) return@post
        val e = engineFor(DatabaseOpener.Purpose.FOREGROUND) ?: return@post
        if (e.disabled) return@post
        startCallbackThread(block)
    }

    /**
     * Waits until the commands posted before this call have run, no activity runs and no participant
     * or user-call thread is still running (the wipe flow waits here before closing the database:
     * those threads use it after their session closed, an engine transaction after a call failed
     * `closed`, say); false at the timeout, e.g. while the app is visible and its foreground session
     * keeps running, or while a participant has not returned from its callback.
     */
    fun awaitIdle(timeoutMillis: Long): Boolean = await(timeoutMillis) { busy() || callbackThreads > 0 }

    /**
     * Waits until the commands posted before this call have run and no activity runs; participant and
     * user-call threads may still run (no activity waits for them). False at the timeout.
     */
    fun awaitNoActivity(timeoutMillis: Long): Boolean = await(timeoutMillis) { busy() }

    private fun await(timeoutMillis: Long, waiting: () -> Boolean): Boolean {
        val end = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
        if (!awaitCommands(timeoutMillis)) return false
        return idleLock.withLock {
            while (waiting()) {
                val left = end - System.nanoTime()
                if (left <= 0) return@withLock false
                idleChanged.awaitNanos(left)
            }
            true
        }
    }

    // ------------------------------------------------------------------ runtime thread

    private fun busy(): Boolean = running != null || quiet != null || userRun != null

    /**
     * Starts [body] on a thread of its own that [awaitIdle] waits for: a participant's callback or a
     * user call, which may use the database after its activity has ended (no activity waits for it).
     * Counted before the start, so an [awaitIdle] posted after this command sees it; a thread that
     * cannot start throws on the runtime thread, which ends the process (design §11.2 #11).
     */
    private fun startCallbackThread(body: () -> Unit) {
        idleLock.withLock { callbackThreads++ }
        threads.newThread {
            try {
                body()
            } finally {
                callbackEnded()
            }
        }.start()
    }

    private fun callbackEnded() = idleLock.withLock {
        callbackThreads--
        idleChanged.signalAll()
    }

    private fun runJob(ticket: JobTicket) {
        // Every job draws, whatever becomes of it: the n-th job of the process gets the n-th draw.
        val quietDraw = schedule.quiet(jobIndex++)
        if (ticket.stopped) return
        if (wantForeground || busy() || wiped || halted) {
            ticket.finish()
            return
        }
        val e = engineFor(DatabaseOpener.Purpose.BACKGROUND)
        if (e == null || e.disabled) {
            ticket.finish()
            return
        }
        val p = participant
        if (quietDraw && p != null) {
            startQuiet(e, ticket, p)
            return
        }
        if (relayHeld()) {
            ticket.finish()
            return
        }
        start(e, SessionKind.BACKGROUND, ticket)
    }

    private fun reconcile() {
        reconcileActivity()
        dispatchUserCalls()
    }

    private fun reconcileActivity() {
        val run = running
        if (run != null) {
            if (relayHeld()) {
                // The payment screen closes a running relay session at once (§19.11).
                stop(run, abortNow = true)
                return
            }
            val handover = run.kind == SessionKind.BACKGROUND && wantForeground
            val hidden = run.kind == SessionKind.FOREGROUND && !wantForeground
            // Calls in flight finish first; a session still bootstrapping has none, so it is aborted.
            if (handover || hidden) stop(run, abortNow = !run.session.online)
            return
        }
        val q = quiet
        if (q != null) {
            // Foreground sessions are never quiet, and never wait for one: the quiet run ends now.
            if (!wantForeground) return
            closeQuiet(q)
        }
        val due = wantForeground && !wiped && !halted && !relayHeld()
        // User calls on a transport of their own are foreground actions, and no session start waits
        // for an issuer's answer (R1): hiding the app closes them, and so does a foreground session due now.
        userRun?.let { if (!wantForeground || due) closeUserRun(it) }
        if (!due) return
        val e = engineFor(DatabaseOpener.Purpose.FOREGROUND) ?: return
        if (e.disabled) return
        start(e, SessionKind.FOREGROUND, null)
    }

    /**
     * Relay sessions are held off (§19.11): the payment screen is shown, or was hidden less than its
     * hold ago (the runtime thread then wakes at the hold's end).
     */
    private fun relayHeld(): Boolean {
        if (paymentScreen) return true
        if (clock.monotonicMillis() < holdUntil) {
            wakeAt = holdUntil
            return true
        }
        return false
    }

    private fun hidePaymentScreen() {
        if (!paymentScreen) return
        paymentScreen = false
        holdUntil = maxOf(holdUntil, clock.monotonicMillis() + schedule.paymentHoldMillis(holds++))
        wakeAt = holdUntil
    }

    private fun stop(run: Run, abortNow: Boolean) {
        if (!run.stopping) {
            run.stopping = true
            // The participant and user calls start nothing more on this session's transport.
            closeLeases(run)
            run.session.stop()
        }
        if (abortNow) transport.abort()
        // A held run has no lane left to end it: it ends through ended() now.
        if (run.holding) post { ended(run) }
    }

    private fun closeLeases(run: Run) {
        run.lease.close()
        run.userLeases.forEach { it.close() }
        run.userLeases.clear()
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
        val p = participant
        // The one input of the redeem hold (Q29), read before the session starts.
        val writeNeeds = if (kind == SessionKind.BACKGROUND && p != null) RedeemHold.pendingWriteNeeds(e.stores) else 0
        val session = e.startSession(kind)
        val hold = if (kind == SessionKind.BACKGROUND) RedeemHold.background(writeNeeds, session.startedAt + policy.backgroundSessionMillis) else RedeemHold.none()
        val run = Run(kind, session, ticket, leases.openLease(), hold)
        setActivity { running = run }
        val lanes = LaneThreads(run)
        run.runner = ThreadedLaneRunner(run.session, clock, lanes)
        run.runner.start()
        lanes.seal()
        p?.let { startRelayParticipant(it, e, run) }
    }

    /** The participant's thread of a relay session: it waits for READY, then runs until it returns. */
    private fun startRelayParticipant(p: SessionParticipant, e: SyncEngine, run: Run) {
        val foreground = run.kind == SessionKind.FOREGROUND
        val deadline = if (foreground) Long.MAX_VALUE else run.session.startedAt + policy.backgroundSessionMillis
        val kind = if (foreground) ParticipantKind.FOREGROUND else ParticipantKind.BACKGROUND
        val session = schedule.session(kind, run.lease, deadline, e::clockTrusted, { e.stores.database.inTransaction }) {
            // The lane's first step ends a hold (Q29); later steps change nothing.
            if (run.hold.stepDone() && run.hold.armed) post { if (running === run && run.holding) ended(run) }
        }
        startCallbackThread { if (run.lease.awaitReady(deadline)) p.onRelaySession(session) }
    }

    /**
     * Every lane thread of [run] has ended: the session is finished (or its runner failed). The run
     * ends, unless its redeem hold keeps it; this runs again when the hold ends.
     */
    private fun ended(run: Run) {
        if (running !== run) return
        if (held(run)) return
        run.done.countDown()
        closeLeases(run)
        // Closed before the runtime reads as idle: an idle runtime holds no transport.
        transport.abort()
        setActivity { running = null }
        if (!run.session.engine.disabled) run.session.engine.setTransportStatus(TransportStatus.OFF)
        // A runner that failed left its session unfinished; the process is ending (§11.2 #11).
        if (run.runner.hasFailed) halted = true
        run.ticket?.finish()
        reconcile()
    }

    /**
     * The redeem hold (Q29, [RedeemHold]): true while [run], whose lanes have ended, stays the
     * activity for its participant's first redeem-lane step. Never for a run that is stopping, whose
     * runner failed or whose transport went offline. A watchdog ends the hold at its deadline.
     */
    private fun held(run: Run): Boolean {
        if (run.stopping || run.runner.hasFailed || !run.session.online || !run.hold.holds(clock.monotonicMillis())) return false
        if (!run.holding) {
            run.holding = true
            watchHold(run)
        }
        return true
    }

    /** Ends [run]'s hold at its deadline, on the sync clock (elapsed realtime): re-read every second. */
    private fun watchHold(run: Run) {
        threads.newThread {
            while (true) {
                val left = run.hold.deadlineMonotonicMillis - clock.monotonicMillis()
                if (left <= 0) {
                    post { ended(run) }
                    break
                }
                if (run.done.await(minOf(left, WATCHDOG_STEP_MILLIS), TimeUnit.MILLISECONDS)) break
            }
        }.start()
    }

    private fun setActivity(change: () -> Unit) = idleLock.withLock {
        change()
        idleChanged.signalAll()
    }

    // ------------------------------------------------------------------ quiet runs

    private fun startQuiet(e: SyncEngine, ticket: JobTicket, p: SessionParticipant) {
        val startedAt = clock.monotonicMillis()
        val q = Quiet(e, ticket, leases.openLease(), startedAt + policy.backgroundSessionMillis)
        setActivity { quiet = q }
        val session = schedule.session(ParticipantKind.QUIET, q.lease, q.deadline, e::clockTrusted, { e.stores.database.inTransaction })
        startCallbackThread {
            try {
                if (!q.lease.closed) {
                    e.setTransportStatus(TransportStatus.STARTING)
                    val state = transport.ensureReady(minOf(startedAt + policy.bootstrapMillis, q.deadline - policy.deadlineReserveMillis))
                    if (!q.lease.closed) {
                        noteTransport(e, state)
                        if (state == TransportState.READY) p.onQuietRun(session)
                    }
                }
            } finally {
                q.done.countDown()
                post { quietEnded(q) }
            }
        }
        // At the deadline the run ends whether or not the participant has returned. The deadline is
        // on the sync clock (elapsed realtime, which runs on in deep sleep): re-read it every second.
        threads.newThread {
            while (true) {
                val left = q.deadline - clock.monotonicMillis()
                if (left <= 0) {
                    post { quietEnded(q) }
                    break
                }
                if (q.done.await(minOf(left, WATCHDOG_STEP_MILLIS), TimeUnit.MILLISECONDS)) break
            }
        }.start()
    }

    /** The transport state a quiet run or a standalone user call reached, as the session would record it. */
    private fun noteTransport(e: SyncEngine, state: TransportState) {
        when (state) {
            TransportState.READY -> e.markReady()
            TransportState.UNAVAILABLE -> e.setTransportStatus(TransportStatus.UNAVAILABLE)
            TransportState.BRIDGE_CONFIG -> e.setTransportStatus(TransportStatus.BRIDGE_CONFIG)
            TransportState.FAILED -> e.setTransportStatus(TransportStatus.TRANSPORT_FAILED)
        }
    }

    private fun quietEnded(q: Quiet) {
        if (quiet !== q) {
            abortIfUnowned()
            return
        }
        closeQuiet(q)
        reconcile()
    }

    private fun closeQuiet(q: Quiet) {
        q.lease.close()
        transport.abort()
        setActivity { quiet = null }
        if (!q.engine.disabled) q.engine.setTransportStatus(TransportStatus.OFF)
        q.ticket.finish()
    }

    /**
     * A late end of an activity that was already closed (its thread was still making the transport
     * READY): a transport made after the close must not outlive it. Only when no activity owns the
     * transport now; one that does closes it at its own end.
     */
    private fun abortIfUnowned() {
        if (!busy()) transport.abort()
    }

    // ------------------------------------------------------------------ user issuer calls

    private val userCallMillis: Long get() = policy.bootstrapMillis + TorIssuerTransport.MAX_SIGNING_DEADLINE_MILLIS

    private fun startUserCall(call: UserCall) {
        val run = running
        when {
            // A foreground action: while the app is hidden none runs, so none meets a background
            // session or a quiet run (P-7, T23).
            wiped || halted || !wantForeground -> runUserCall(call, null, ClosedLeases.openLease(), ensure = false) {}
            run != null && run.kind == SessionKind.FOREGROUND && !run.stopping -> {
                val lease = leases.openLease()
                run.userLeases += lease
                runUserCall(call, run.session.engine, lease, ensure = false) {
                    lease.close()
                    run.userLeases.remove(lease)
                }
            }
            // A stopping session (handed over to the foreground, or closed by the payment screen) ends first.
            run != null || quiet != null -> pendingUserCalls += call
            else -> {
                val e = userRun?.engine ?: engineFor(DatabaseOpener.Purpose.FOREGROUND)
                if (e == null || e.disabled) {
                    runUserCall(call, null, ClosedLeases.openLease(), ensure = false) {}
                    return
                }
                val u = userRun ?: UserRun(e).also { setActivity { userRun = it } }
                val lease = leases.openLease()
                u.leases += lease
                runUserCall(call, e, lease, ensure = true) { userCallEnded(u, lease) }
            }
        }
    }

    /** Pending user calls are decided again at every change: a hidden app closes them, a foreground session takes them. */
    private fun dispatchUserCalls() {
        if (pendingUserCalls.isEmpty()) return
        val calls = pendingUserCalls.toList()
        pendingUserCalls.clear()
        calls.forEach(::startUserCall)
    }

    /**
     * [call]'s thread: READY (made by the call itself when [ensure], else awaited), then the block,
     * exactly once; [onEnd] runs on the runtime thread afterwards.
     */
    private fun runUserCall(call: UserCall, e: SyncEngine?, lease: TransportLease, ensure: Boolean, onEnd: () -> Unit) {
        val session = schedule.session(
            ParticipantKind.USER_ISSUER_CALL, lease, call.deadline,
            { e?.clockTrusted() == true }, { e?.stores?.database?.inTransaction == true },
        )
        startCallbackThread {
            try {
                if (e != null && !lease.closed) {
                    val readyBy = minOf(call.deadline, clock.monotonicMillis() + policy.bootstrapMillis)
                    if (ensure) {
                        val state = transport.ensureReady(readyBy)
                        if (!lease.closed) noteTransport(e, state)
                    }
                    lease.awaitReady(readyBy)
                }
                call.block(session)
            } finally {
                post(onEnd)
            }
        }
    }

    private fun userCallEnded(u: UserRun, lease: TransportLease) {
        lease.close()
        if (userRun !== u) {
            abortIfUnowned()
            return
        }
        u.leases.remove(lease)
        if (u.leases.isNotEmpty()) return
        closeUserRun(u)
        reconcile()
    }

    private fun closeUserRun(u: UserRun) {
        u.leases.forEach { it.close() }
        u.leases.clear()
        transport.abort()
        setActivity { userRun = null }
        if (!u.engine.disabled) u.engine.setTransportStatus(TransportStatus.OFF)
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

    private companion object {
        /** Longest wait of the quiet-run watchdog between two reads of the sync clock. */
        const val WATCHDOG_STEP_MILLIS = 1_000L
    }
}
