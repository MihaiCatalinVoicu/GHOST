package org.ghost.sync.engine

import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.RelayId
import org.ghost.sync.api.TransportStatus
import org.ghost.sync.port.PairKey
import org.ghost.sync.port.TransportState
import java.util.PriorityQueue
import java.util.TreeMap

/** One item of the work lane. [networked] items are dropped while the session cannot make calls. */
internal sealed class WorkItem(protected val session: Session, val networked: Boolean) : LaneItem(Lane.WORK) {

    /** M1, the first item of every session (design §3.5). */
    class Normalize(session: Session) : WorkItem(session, networked = false) {
        override fun run() {
            session.engine.steps.maintenance.normalize(session.workContext)
        }

        override fun toString(): String = "Normalize"
    }

    /** Creates or bootstraps the transport; on READY also loads the pair snapshot. */
    class EnsureTransport(session: Session) : WorkItem(session, networked = false) {
        var state: TransportState? = null
            private set
        var snapshot: PairSnapshot? = null
            private set

        override fun run() {
            session.engine.setTransportStatus(TransportStatus.STARTING)
            state = session.engine.transport.ensureReady(session.bootstrapDeadline())
            if (state == TransportState.READY) {
                session.engine.markReady()
                snapshot = session.loadSnapshot()
            }
        }

        override fun toString(): String = "EnsureTransport"
    }

    /**
     * Maintenance pass (M2, and M3/M4 with a trusted clock), a refresh of the pair snapshot and, in
     * STANDARD mode, the due stores (at most [TrafficPolicy.storesPerPass]).
     */
    class Pass(session: Session) : WorkItem(session, networked = false) {
        var snapshot: PairSnapshot? = null
            private set
        var storesAtCap = false
            private set

        override fun run() {
            val ctx = session.workContext
            val online = ctx.active
            ctx.steps.maintenance.pass(ctx, trustedClock = online && ctx.engine.readyInProcess)
            if (online) {
                snapshot = session.loadSnapshot()
                if (ctx.mode() == PrivacyMode.STANDARD) {
                    storesAtCap = ctx.steps.store.round(ctx, null, ctx.policy.storesPerPass) >= ctx.policy.storesPerPass
                }
            }
        }

        override fun toString(): String = "Pass"
    }

    /**
     * The work bundle of one pair event (design §6.1): fetches for a read pair (8 per event in the
     * foreground, 32 in a background job), one verification/resolution check, and in HIGH mode the
     * pair's due stores (at most [TrafficPolicy.storesPerPairEvent]).
     */
    class PairWork(session: Session, val pair: PairKey, val readPair: Boolean) : WorkItem(session, networked = true) {
        override fun run() {
            val ctx = session.workContext
            if (readPair) {
                val limit = if (ctx.kind == SessionKind.FOREGROUND) ctx.policy.foregroundFetchesPerEvent else ctx.policy.backgroundFetchesPerEvent
                ctx.steps.fetch.run(ctx, pair, limit)
            }
            CheckRound.run(ctx, pair)
            if (ctx.mode() == PrivacyMode.HIGH) ctx.steps.store.round(ctx, pair, ctx.policy.storesPerPairEvent)
        }

        override fun toString(): String = "PairWork(read=$readPair)"
    }

    /** Garbage collection; [last] marks a background session's final pass. */
    class Gc(session: Session, val last: Boolean) : WorkItem(session, networked = false) {
        override fun run() {
            session.engine.steps.gc.run(session.workContext)
        }

        override fun toString(): String = "Gc(last=$last)"
    }
}

/**
 * The work lane of a session (design §1.4): one worker running maintenance, the transport, pair
 * event bundles, store passes and GC in time order. Write-only pairs with outstanding work have
 * their own [PairSchedule] events here (they never list). The work-lane [breaker], pauses and the
 * background per-relay budget live here and never reach the read lane (T19).
 *
 * All methods run with the session lock held, except [recordCall] and [relayBudgetLeft], which only
 * the work worker calls.
 */
internal class WorkLane(private val session: Session, private val schedule: PairSchedule) {
    private val engine = session.engine
    private val policy = engine.policy
    val breaker = LaneBreaker { _, _ -> engine.random.selection() }

    private class Entry(val at: Long, val seq: Long, val item: WorkItem)

    private class WritePair(var time: Long) {
        var index = 0L
        var done = false
    }

    private val queue = PriorityQueue<Entry>(compareBy<Entry>({ it.at }, { it.seq }))
    private var seq = 0L
    private var busy = false
    private val writePairs = TreeMap<PairKey, WritePair>(PairSchedule.PAIR_ORDER)
    private val relayMillis = HashMap<Long, Long>()

    fun post(item: WorkItem, at: Long) {
        queue.add(Entry(at, seq++, item))
    }

    fun postPairWork(pair: PairKey, readPair: Boolean, at: Long) = post(WorkItem.PairWork(session, pair, readPair), at)

    /** True if an item of type [T] is queued for monotonic time [at] or earlier. */
    inline fun <reified T : WorkItem> queuedBy(at: Long): Boolean = queuedItems(at).any { it is T }

    /** Items queued for monotonic time [at] or earlier. */
    fun queuedItems(at: Long): List<WorkItem> = queue.filter { it.at <= at }.map { it.item }

    /** Nothing queued, running or scheduled. */
    val idle: Boolean get() = !busy && queue.isEmpty() && writePairs.values.all { it.done }

    fun take(now: Long): WorkItem? {
        if (busy) return null
        fireWritePairs(now)
        while (true) {
            val head = queue.peek() ?: return null
            if (head.at > now) return null
            queue.poll()
            if (head.item.networked && !session.canUseNetwork(now)) continue
            busy = true
            return head.item
        }
    }

    fun wakeAt(now: Long): Long? {
        if (busy) return null
        var best = queue.peek()?.at
        for (w in writePairs.values) {
            if (w.done) continue
            best = if (best == null) w.time else minOf(best, w.time)
        }
        return best?.let { maxOf(it, now) }
    }

    fun complete() {
        busy = false
    }

    /** Drops every queued networked item and scheduled write-pair event (background, no more network). */
    fun dropNetworked() {
        queue.removeAll { it.item.networked }
        writePairs.values.forEach { it.done = true }
    }

    /** Drops every queued item (the session stops). */
    fun clear() {
        queue.clear()
        writePairs.values.forEach { it.done = true }
    }

    // ------------------------------------------------------------------ write-only pairs

    /**
     * Applies the write pairs of a snapshot at monotonic time [now]: new pairs start their schedule
     * (foreground) or get their keyed offset in the job's window (background); gone pairs stop.
     */
    fun setWritePairs(keys: List<PairKey>, now: Long) {
        writePairs.keys.retainAll(keys.toSet())
        for (key in keys) {
            if (writePairs.containsKey(key)) continue
            val time = if (session.kind == SessionKind.FOREGROUND) {
                schedule.firstTime(key, now)
            } else {
                schedule.backgroundTime(key, session.startedAt, session.job)
            }
            writePairs[key] = WritePair(time)
        }
    }

    private fun fireWritePairs(now: Long) {
        for ((key, w) in writePairs) {
            while (!w.done && w.time <= now) {
                if (session.canUseNetwork(now)) post(WorkItem.PairWork(session, key, readPair = false), w.time)
                if (session.kind == SessionKind.BACKGROUND) {
                    w.done = true
                } else {
                    w.time = schedule.nextTime(key, w.index, w.time)
                    w.index++
                }
            }
        }
    }

    // ------------------------------------------------------------------ background per-relay budget

    fun recordCall(relay: RelayId, elapsedMillis: Long) {
        if (session.kind != SessionKind.BACKGROUND) return
        relayMillis[relay.value] = (relayMillis[relay.value] ?: 0L) + maxOf(0L, elapsedMillis)
    }

    /** Remaining work-lane call time for [relay] in this session (unlimited in the foreground). */
    fun relayBudgetLeft(relay: RelayId): Long =
        if (session.kind != SessionKind.BACKGROUND) Long.MAX_VALUE else policy.backgroundRelayWorkMillis - (relayMillis[relay.value] ?: 0L)

    override fun toString(): String = "WorkLane(queued=${queue.size})"
}
