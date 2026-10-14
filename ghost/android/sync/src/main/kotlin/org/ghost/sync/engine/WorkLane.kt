package org.ghost.sync.engine

import org.ghost.sync.api.Consumer
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
     * STANDARD mode, the due stores — at most [TrafficPolicy.storesPerPass] non-media stores, then
     * at most [TrafficPolicy.mediaStoresPerPass] media stores (Phase 11 design §5.5) — and the due
     * key registrations (at most [TrafficPolicy.registrationsPerPass], Phase 9 design §13.3 item 5).
     */
    class Pass(session: Session) : WorkItem(session, networked = false) {
        var snapshot: PairSnapshot? = null
            private set
        var storesAtCap = false
            private set

        override fun run() {
            val ctx = session.workContext
            val online = ctx.active
            ctx.steps.maintenance.pass(ctx, trustedClock = online && ctx.engine.clockTrusted())
            if (online) {
                snapshot = session.loadSnapshot()
                if (ctx.mode() == PrivacyMode.STANDARD) {
                    // Registrations first: there are at most eight of them and they are what keeps
                    // the owner reachable, so a large store backlog never starves them.
                    ctx.steps.registration.round(ctx, null, ctx.policy.registrationsPerPass)
                    // The media stores are a separate round, taken after the pass's non-media stores:
                    // a media burst never crowds a pass's DM work out, nor waits behind a later one.
                    val nonMedia = ctx.steps.store.round(ctx, null, ctx.policy.storesPerPass)
                    val media = ctx.steps.store.round(ctx, null, ctx.policy.mediaStoresPerPass, media = true)
                    // The at-cap repost (Session.completeWork) also applies to media, so a media
                    // backlog keeps passes coming while other queued work interleaves between them.
                    storesAtCap = nonMedia >= ctx.policy.storesPerPass || media >= ctx.policy.mediaStoresPerPass
                }
            }
        }

        override fun toString(): String = "Pass"
    }

    /**
     * The work bundle of one pair event (design §6.1): fetches for a read pair (8 per event in the
     * foreground, 32 in a background job; a media pair's event fetches at most
     * [TrafficPolicy.mediaForegroundFetchesPerEvent] or [TrafficPolicy.mediaBackgroundFetchesPerEvent]
     * blobs, in slices of [TrafficPolicy.mediaFetchesPerItem], each further slice a new item behind
     * the non-media items already queued — Phase 11 design §5.5), one verification/resolution check,
     * and in HIGH mode the pair's due stores (at most [TrafficPolicy.storesPerPairEvent] non-media,
     * then [TrafficPolicy.mediaStoresPerPairEvent] media) and key registrations (Phase 9 design
     * §13.3 item 5).
     *
     * [fetchesDone] counts the media fetches of this item's event already delivered by earlier
     * slices of the same event, and [fetchesOnly] marks such a continuation: it exists only to
     * carry the next fetch slice, so it runs the fetch and nothing else — §5.5's
     * `mediaStoresPerPairEvent = 8` is an event's bound, and a continuation is not a new event
     * (the review's F1: without the flag one event delivered 24 media stores). The event body
     * (check, HIGH stores, registrations) runs on the event's first item only.
     */
    class PairWork(
        session: Session,
        val pair: PairKey,
        val readPair: Boolean,
        val fetchesDone: Int = 0,
        val fetchesOnly: Boolean = false,
    ) : WorkItem(session, networked = true) {
        /** Fetches this item delivered (set by [run], read by [Session.completeWork]). */
        var fetched = 0
            private set

        /** True when a full slice was delivered and the event's media budget is not spent: [Session] reposts the rest. */
        var continueFetches = false
            private set

        override fun run() {
            val ctx = session.workContext
            val media = ctx.db.transaction { tx ->
                ctx.stores.directoryStore.namespace(tx, pair.namespace)?.consumer == Consumer.MEDIA
            }
            if (readPair) {
                if (media) {
                    val budget = if (ctx.kind == SessionKind.FOREGROUND) {
                        ctx.policy.mediaForegroundFetchesPerEvent
                    } else {
                        ctx.policy.mediaBackgroundFetchesPerEvent
                    }
                    val slice = minOf(ctx.policy.mediaFetchesPerItem, budget - fetchesDone)
                    if (slice > 0) {
                        fetched = ctx.steps.fetch.run(ctx, pair, slice)
                        // A full slice means more of the bundle may be due: the rest resumes as a new
                        // item behind the non-media items already queued (Session.completeWork).
                        continueFetches = fetched >= slice && fetchesDone + fetched < budget
                    }
                } else {
                    val limit = if (ctx.kind == SessionKind.FOREGROUND) ctx.policy.foregroundFetchesPerEvent else ctx.policy.backgroundFetchesPerEvent
                    ctx.steps.fetch.run(ctx, pair, limit)
                }
            }
            if (fetchesOnly) return
            CheckRound.run(ctx, pair, media)
            if (ctx.mode() == PrivacyMode.HIGH) {
                ctx.steps.registration.round(ctx, pair, ctx.policy.registrationsPerPass)
                ctx.steps.store.round(ctx, pair, ctx.policy.storesPerPairEvent)
                ctx.steps.store.round(ctx, pair, ctx.policy.mediaStoresPerPairEvent, media = true)
            }
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

    /**
     * Per-relay work-lane call time of this session. [relayMillis] is the total,
     * [mediaRelayMillis] the media share's part of it: media work may use at most
     * [TrafficPolicy.mediaBackgroundRelayWorkMillis] of the relay's
     * [TrafficPolicy.backgroundRelayWorkMillis], and what media has spent comes out of the total,
     * so the rest stays for DM, bundle and channel work of that relay (Phase 11 design §5.5).
     */
    private val relayMillis = HashMap<Long, Long>()
    private val mediaRelayMillis = HashMap<Long, Long>()

    fun recordCall(relay: RelayId, elapsedMillis: Long, media: Boolean) {
        if (session.kind != SessionKind.BACKGROUND) return
        relayMillis[relay.value] = (relayMillis[relay.value] ?: 0L) + maxOf(0L, elapsedMillis)
        if (media) mediaRelayMillis[relay.value] = (mediaRelayMillis[relay.value] ?: 0L) + maxOf(0L, elapsedMillis)
    }

    /** Remaining work-lane call time for [relay] in this session (unlimited in the foreground). */
    fun relayBudgetLeft(relay: RelayId, media: Boolean): Long =
        if (session.kind != SessionKind.BACKGROUND) {
            Long.MAX_VALUE
        } else {
            val total = policy.backgroundRelayWorkMillis - (relayMillis[relay.value] ?: 0L)
            if (media) minOf(policy.mediaBackgroundRelayWorkMillis - (mediaRelayMillis[relay.value] ?: 0L), total) else total
        }

    /** Media call time a relay has spent in this session (tests). */
    fun mediaRelaySpent(relay: RelayId): Long = mediaRelayMillis[relay.value] ?: 0L

    override fun toString(): String = "WorkLane(queued=${queue.size})"
}
