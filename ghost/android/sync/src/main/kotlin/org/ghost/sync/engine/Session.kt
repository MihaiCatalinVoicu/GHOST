package org.ghost.sync.engine

import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.TransportStatus
import org.ghost.sync.port.PairKey
import org.ghost.sync.port.TransportState
import org.ghost.sync.store.ReadPair
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.locks.Condition
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/** Design §1.4: a session runs while the app is visible, or for one background job. */
internal enum class SessionKind { FOREGROUND, BACKGROUND }

/**
 * Read pairs and write-only work pairs read in one transaction. [sequence] orders snapshots by the
 * order of their transactions, so a slower refresh never overwrites a newer one.
 */
internal class PairSnapshot(val sequence: Long, val read: List<ReadPair>, val write: List<PairKey>) {
    override fun toString(): String = "PairSnapshot(read=${read.size}, write=${write.size})"
}

/**
 * Time budget of a session (design §3.7): a background session has 8 minutes; each call's deadline
 * is `min(policy, remaining − 5 s)` and no call is made with less than [TrafficPolicy.minCallMillis].
 * The foreground has no session budget.
 */
internal class SessionBudget(private val start: Long, private val total: Long?, private val policy: TrafficPolicy) {
    fun remaining(now: Long): Long = if (total == null) Long.MAX_VALUE else start + total - now

    /** Deadline in ms for a call limited to [limitMillis], or null when too little time is left. */
    fun deadline(now: Long, limitMillis: Long): Int? {
        val room = if (total == null) limitMillis else minOf(limitMillis, remaining(now) - policy.deadlineReserveMillis)
        return if (room >= policy.minCallMillis) minOf(room, TrafficPolicy.MAX_DEADLINE_MILLIS.toLong()).toInt() else null
    }

    fun hasTime(now: Long): Boolean = deadline(now, policy.minCallMillis.toLong()) != null

    override fun toString(): String = "SessionBudget"
}

/**
 * One sync session (design §1.4, §5.4): M1, then the transport, then two lanes over the same
 * database until the session stops (foreground) or its work is done (background). It is the
 * [LaneSource] of its runner: [ThreadedLaneRunner] in production, a deterministic driver in tests.
 *
 * Session start: M1 (always first), EnsureTransport; on READY the pair snapshot, a maintenance pass
 * and (foreground) GC; then read-pair events on the read lane and write-pair events, passes every
 * minute and GC every hour on the work lane. A transport-level failure takes the session offline:
 * no call is made until EnsureTransport succeeds again (foreground, with the 1 → 15 min backoff);
 * a background session then drains and ends. A background session ends after every pair's one event,
 * the drained work lane and a final GC.
 *
 * Lock order: the session lock may be taken before the database lock (never the reverse: no
 * transaction calls into the session). [ReadItem.run] and [WorkItem.run] run without the lock.
 */
internal class Session(val engine: SyncEngine, val kind: SessionKind, val job: Long) : LaneSource {
    override val lock: ReentrantLock = ReentrantLock()
    override val changed: Condition = lock.newCondition()

    private val policy = engine.policy

    /** Monotonic start (the anchor of background offsets). */
    val startedAt: Long = engine.clock.monotonicMillis()

    val budget = SessionBudget(startedAt, if (kind == SessionKind.BACKGROUND) policy.backgroundSessionMillis else null, policy)
    val schedule: PairSchedule = engine.steps.schedule(engine.random, policy)
    val workContext: WorkContext = WorkContext(engine, this)
    val read = ReadLane(this, schedule)
    val work = WorkLane(this, schedule)

    @Volatile
    var online: Boolean = false
        private set

    @Volatile
    private var stopping = false

    @Volatile
    private var finishedFlag = false

    private var running = 0
    private var ensurePending = false
    private val snapshots = AtomicLong()
    private var appliedSnapshot = 0L
    private var finalGc = FinalGc.NOT_POSTED

    private enum class FinalGc { NOT_POSTED, POSTED, DONE }

    override val finished: Boolean get() = finishedFlag

    fun isFinished(): Boolean = finishedFlag

    /** Queues M1; called once by [SyncEngine.startSession]. */
    fun start() = lock.withLock {
        work.post(WorkItem.Normalize(this), now())
        changed.signalAll()
    }

    /**
     * Stops accepting items; calls in flight finish and record their results, then the session is
     * finished (foreground → background handover, app backgrounded, onStopJob after the abort).
     */
    fun stop() = lock.withLock {
        stopping = true
        work.clear()
        read.dropAll()
        maybeFinish(now())
        changed.signalAll()
    }

    /** STANDARD foreground only: a pass for due stores now (never a read event, design §5.4). */
    fun expedite() = lock.withLock {
        if (kind != SessionKind.FOREGROUND || engine.privacyMode() != PrivacyMode.STANDARD) return@withLock
        val now = now()
        if (!online || stopping || work.queuedBy<WorkItem.Pass>(now)) return@withLock
        work.post(WorkItem.Pass(this), now)
        changed.signalAll()
    }

    /** The session may make calls at monotonic time [now]: online, not stopping, budget left. */
    fun canUseNetwork(now: Long): Boolean = online && !stopping && budget.hasTime(now)

    private fun now(): Long = engine.clock.monotonicMillis()

    // ------------------------------------------------------------------ LaneSource

    override fun threads(lane: Lane): Int = if (lane == Lane.READ) policy.readWorkers + 1 else 1

    override fun take(lane: Lane, now: Long): LaneItem? {
        if (finishedFlag || stopping) return null
        val item = if (lane == Lane.READ) read.take(now) else work.take(now)
        if (item != null) {
            running++
        } else if (finishChanged(now)) {
            // A take can end the session's work without any item completing (events consumed while
            // the budget is spent or the transport is gone, networked items dropped): re-check the
            // end here, and wake the other lane's runner if it posted the final GC or finished.
            changed.signalAll()
        }
        return item
    }

    /** Runs [maybeFinish]; true if it posted the final GC or finished the session. */
    private fun finishChanged(now: Long): Boolean {
        val gc = finalGc
        val done = finishedFlag
        maybeFinish(now)
        return finalGc != gc || finishedFlag != done
    }

    override fun wakeAt(lane: Lane, now: Long): Long? {
        if (finishedFlag || stopping) return null
        return if (lane == Lane.READ) read.wakeAt(now) else work.wakeAt(now)
    }

    override fun complete(item: LaneItem, now: Long) {
        running--
        when (item) {
            is ReadItem -> read.complete(item, now)
            is WorkItem -> {
                work.complete()
                completeWork(item, now)
            }
            else -> throw IllegalStateException("unknown lane item")
        }
        maybeFinish(now)
    }

    private fun completeWork(item: WorkItem, now: Long) {
        if (stopping) return
        when (item) {
            is WorkItem.Normalize -> postEnsure(now)
            is WorkItem.EnsureTransport -> transportResult(item, now)
            is WorkItem.Pass -> {
                item.snapshot?.let { applySnapshot(it, now) }
                if (item.storesAtCap) {
                    work.post(WorkItem.Pass(this), now)
                } else if (kind == SessionKind.FOREGROUND && !work.queuedBy<WorkItem.Pass>(Long.MAX_VALUE)) {
                    work.post(WorkItem.Pass(this), now + policy.passIntervalMillis)
                }
            }
            is WorkItem.Gc -> if (item.last) finalGc = FinalGc.DONE else work.post(WorkItem.Gc(this, last = false), now + policy.gcIntervalMillis)
            is WorkItem.PairWork -> Unit
        }
    }

    private fun postEnsure(at: Long) {
        if (ensurePending || stopping) return
        ensurePending = true
        work.post(WorkItem.EnsureTransport(this), at)
    }

    private fun transportResult(item: WorkItem.EnsureTransport, now: Long) {
        ensurePending = false
        when (item.state) {
            TransportState.READY -> {
                online = true
                item.snapshot?.let { applySnapshot(it, now) }
                work.post(WorkItem.Pass(this), now)
                if (kind == SessionKind.FOREGROUND) work.post(WorkItem.Gc(this, last = false), now)
            }
            TransportState.UNAVAILABLE -> {
                engine.setTransportStatus(TransportStatus.UNAVAILABLE)
                retryOrDrain(now)
            }
            TransportState.BRIDGE_CONFIG -> {
                engine.setTransportStatus(TransportStatus.BRIDGE_CONFIG)
                drainIfBackground()
            }
            TransportState.FAILED, null -> {
                engine.setTransportStatus(TransportStatus.TRANSPORT_FAILED)
                drainIfBackground()
            }
        }
    }

    /** Foreground: EnsureTransport again after the in-memory backoff; background: no more network. */
    private fun retryOrDrain(now: Long) {
        if (kind == SessionKind.FOREGROUND) {
            engine.transportFailures++
            val delay = Backoff.transportMillis(engine.transportFailures)
            postEnsure(now + delay)
        } else {
            drainIfBackground()
        }
    }

    private fun drainIfBackground() {
        if (kind != SessionKind.BACKGROUND) return
        read.dropAll()
        work.dropNetworked()
    }

    // ------------------------------------------------------------------ transport faults (design §3.6)

    /** A transport-level failure seen by a lane item (no lock held). */
    fun fault(failure: CallResult.Failed) = lock.withLock {
        faultLocked(failure, now())
        changed.signalAll()
    }

    fun faultLocked(failure: CallResult.Failed, now: Long) {
        check(failure.errorClass.transportLevel) { "not a transport failure" }
        if (!online) return
        online = false
        when (failure.errorClass) {
            // Closed under the call (an abort); a foreground session reconnects on a fresh transport.
            ErrorClass.ABORT -> {
                engine.setTransportStatus(TransportStatus.UNAVAILABLE)
                if (kind == SessionKind.FOREGROUND) postEnsure(now) else drainIfBackground()
            }
            // The holder bootstraps the same transport again.
            ErrorClass.NEEDS_BOOTSTRAP -> postEnsure(now)
            // Close and recreate, with the 1 → 15 min backoff.
            ErrorClass.NEW_TRANSPORT -> {
                engine.transport.abort()
                engine.setTransportStatus(TransportStatus.UNAVAILABLE)
                retryOrDrain(now)
            }
            ErrorClass.LOCAL_FATAL -> {
                if (failure.category == ErrorPolicy.NATIVE_MISSING) engine.disable() else engine.setTransportStatus(TransportStatus.TRANSPORT_FAILED)
                drainIfBackground()
            }
            ErrorClass.CONFIG -> {
                engine.setTransportStatus(TransportStatus.BRIDGE_CONFIG)
                drainIfBackground()
            }
            else -> throw IllegalStateException("not a transport failure")
        }
    }

    // ------------------------------------------------------------------ pairs

    /** Deadline for [org.ghost.sync.port.TransportPort.ensureReady]. */
    fun bootstrapDeadline(): Long {
        val now = now()
        val bound = now + policy.bootstrapMillis
        return if (kind == SessionKind.BACKGROUND) minOf(bound, now + budget.remaining(now) - policy.deadlineReserveMillis) else bound
    }

    /** Reads the read pairs and the write-only work pairs (with a token that can check) in one transaction. */
    fun loadSnapshot(): PairSnapshot = engine.stores.database.transaction { tx ->
        val now = engine.clock.epochSeconds()
        val stores = engine.stores
        val readPairs = stores.directoryStore.readPairs(tx, now)
        val readKeys = readPairs.mapTo(HashSet()) { PairKey(it.relayId, it.namespace) }
        val writePairs = stores.outboxStore.workPairs(tx, now)
            .map { PairKey(it.relayId, it.namespace) }
            .filter { it !in readKeys && stores.capabilityStore.forChecking(tx, it.relayId, it.namespace, now) != null }
        // Numbered inside the transaction: transactions are serialized, so numbers follow read order.
        PairSnapshot(snapshots.incrementAndGet(), readPairs, writePairs)
    }

    private fun applySnapshot(snapshot: PairSnapshot, now: Long) {
        if (snapshot.sequence <= appliedSnapshot) return
        appliedSnapshot = snapshot.sequence
        read.setPairs(snapshot.read, now)
        work.setWritePairs(snapshot.write, now)
    }

    /**
     * After a capability or topology change (engine hint, on the committing thread, outside any
     * transaction and without the lock): reload and apply the pairs, so the read lane's snapshot
     * (tokens, generations, pair set) follows without the read lane reading the database itself.
     */
    fun refreshPairs() {
        if (!online || stopping) return
        val snapshot = loadSnapshot()
        lock.withLock {
            if (online && !stopping) applySnapshot(snapshot, now())
            changed.signalAll()
        }
    }

    // ------------------------------------------------------------------ end

    private fun maybeFinish(now: Long) {
        if (finishedFlag) return
        if (stopping) {
            if (running == 0) finishedFlag = true
            return
        }
        if (kind != SessionKind.BACKGROUND || running > 0 || ensurePending || !work.idle || !read.allConsumed) return
        when (finalGc) {
            FinalGc.NOT_POSTED ->
                if (online && engine.readyInProcess) {
                    finalGc = FinalGc.POSTED
                    work.post(WorkItem.Gc(this, last = true), now)
                } else {
                    finishedFlag = true
                }
            FinalGc.POSTED -> Unit
            FinalGc.DONE -> finishedFlag = true
        }
    }

    override fun toString(): String = "Session($kind)"
}
