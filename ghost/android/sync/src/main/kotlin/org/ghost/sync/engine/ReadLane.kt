package org.ghost.sync.engine

import org.ghost.network.OnionAddress
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.port.PairKey
import org.ghost.sync.store.CapabilityToken
import org.ghost.sync.store.PageCommit
import org.ghost.sync.store.ReadPair
import java.util.TreeMap

/**
 * One list request of the read lane: the first page of a pair event, or a further page of a
 * STANDARD event. Everything it sends comes from the lane's in-memory snapshot taken at dispatch.
 */
internal class ReadItem(
    private val readLane: ReadLane,
    val pair: PairKey,
    val relay: OnionAddress,
    val token: CapabilityToken,
    cursor: ByteArray,
    val limit: Int,
    val deadlineMillis: Int,
    /** 1 for an event's first page. */
    val page: Int,
    /** Pages the event may read (1 in HIGH mode, up to 4 in STANDARD). */
    val pagesAllowed: Int,
    /** Scheduled time of the event (monotonic ms). */
    val scheduledMillis: Long,
    /** Dispatch time (monotonic ms). */
    val startMillis: Long,
) : LaneItem(Lane.READ) {
    private val sent: ByteArray = cursor.copyOf()

    /** The cursor this request sends (empty = from the beginning). */
    val cursor: ByteArray get() = sent.copyOf()

    val continuation: Boolean get() = page > 1

    var outcome: PageOutcome? = null
        private set

    override fun run() {
        outcome = readLane.listStep.page(readLane.context, this)
    }

    override fun toString(): String = "ReadItem(page=$page)"
}

/**
 * The read lane of a session (design §1.4, §4.1, §6.1, §11.2 #12, #13).
 *
 *  - Every read pair has its own [PairSchedule]; events are dispatched by scheduled time to at most
 *    [TrafficPolicy.readWorkers] event workers, one event per pair at a time. In the foreground an
 *    event that cannot start within [TrafficPolicy.lateToleranceMillis] of its time is skipped, not
 *    delayed, and its index is consumed; in a background job each pair's one event waits for a
 *    worker, in the keyed offset order.
 *  - An event's first page is the only request whose timing T19 constrains. Further STANDARD pages
 *    (only while pages are full and the cursor advances) run on a separate continuation worker and
 *    must end before the pair's next event, so inbound volume never occupies an event worker or
 *    delays any event. A further page still queued when its pair's next event is due is dropped;
 *    only a running one makes its pair busy (§11.5 #5). Their outcomes do not feed the breaker.
 *  - The read-lane [breaker] counts first-page outcomes only; pauses of the read lane come from list
 *    outcomes only. Nothing the work lane does changes this lane's state, and the lane never reads
 *    the database before sending (snapshot of cursor, token and generation).
 *  - When an event ends (listed, failed, held or skipped) its work bundle (fetches, checks, HIGH
 *    stores) is queued on the work lane.
 *
 * All methods run with the session lock held, except [ReadItem.run].
 */
internal class ReadLane(private val session: Session, private val schedule: PairSchedule) {
    private val engine = session.engine
    private val policy = engine.policy
    val context: EngineContext = EngineContext(engine)
    val listStep: ListStep get() = engine.steps.list
    val breaker = LaneBreaker { relay, index -> engine.random.readBreaker(relay, index) }

    private class PairState(val key: PairKey, var relay: OnionAddress, var token: CapabilityToken, var cursor: ByteArray, var time: Long) {
        var index = 0L
        var group = 0
        var busy = false
        var done = false

        /** Generation the relay refused (`unauthorized`); listing resumes with a newer one. */
        var refusedGeneration: Long? = null
    }

    private class Continuation(val key: PairKey, val page: Int, val pagesAllowed: Int)

    private val pairs = TreeMap<PairKey, PairState>(PairSchedule.PAIR_ORDER)
    private var groups = 1
    private var eventsRunning = 0
    private var continuationRunning = false
    private val continuations = ArrayDeque<Continuation>()
    private var loaded = false

    /** Foreground events skipped because they could not start in time (tests and status). */
    var skippedLate = 0L
        private set

    // ------------------------------------------------------------------ pair set

    /**
     * Applies a snapshot of the read pairs at monotonic time [now]. New pairs start their schedule
     * at [now] (foreground) or get their keyed offset in the job's window (background); existing
     * pairs keep their schedule and their cursor (the lane owns it) and take the stored token.
     */
    fun setPairs(snapshot: List<ReadPair>, now: Long) {
        loaded = true
        val incoming = LinkedHashMap<PairKey, ReadPair>()
        snapshot.forEach { incoming[PairKey(it.relayId, it.namespace)] = it }
        pairs.keys.retainAll(incoming.keys)
        for ((key, rp) in incoming) {
            val existing = pairs[key]
            if (existing == null) {
                val time = if (session.kind == SessionKind.FOREGROUND) {
                    schedule.firstTime(key, now)
                } else {
                    schedule.backgroundTime(key, session.startedAt, session.job)
                }
                pairs[key] = PairState(key, rp.relay, rp.capability, rp.cursor, time)
            } else {
                existing.relay = rp.relay
                existing.token = rp.capability
            }
        }
        regroup()
    }

    private fun regroup() {
        val assignment = schedule.groups(pairs.keys)
        groups = schedule.groupCount(pairs.size)
        for (p in pairs.values) {
            p.group = assignment.getValue(p.key)
            if (session.kind == SessionKind.FOREGROUND) {
                while (!acting(p)) step(p)
            } else if (Math.floorMod(session.job, groups.toLong()) != p.group.toLong()) {
                p.done = true
            }
        }
    }

    private fun acting(p: PairState): Boolean = Math.floorMod(p.index, groups.toLong()) == p.group.toLong()

    private fun step(p: PairState) {
        p.time = schedule.nextTime(p.key, p.index, p.time)
        p.index++
    }

    /** Consumes the pair's current event: the next acting index (foreground) or done (background). */
    private fun consume(p: PairState) {
        if (session.kind == SessionKind.BACKGROUND) {
            p.done = true
            return
        }
        do {
            step(p)
        } while (!acting(p))
    }

    /** Every pair's event is consumed and nothing runs (background end). */
    val allConsumed: Boolean
        get() = eventsRunning == 0 && !continuationRunning && continuations.isEmpty() && pairs.values.all { it.done && !it.busy }

    /** Background, no more network: every remaining event is dropped. */
    fun dropAll() {
        // A pair waiting only for its further page is free again; a pair whose request runs stays busy until it completes.
        continuations.forEach { c -> pairs[c.key]?.busy = false }
        continuations.clear()
        pairs.values.forEach { it.done = true }
    }

    // ------------------------------------------------------------------ dispatch

    fun take(now: Long): ReadItem? {
        if (!loaded) return null
        dropDueContinuations(now)
        takeContinuation(now)?.let { return it }
        while (true) {
            val p = nextActionable(now) ?: return null
            when {
                !session.canUseNetwork(now) -> consume(p)
                late(p, now) -> {
                    consume(p)
                    skippedLate++
                    bundle(p.key, now)
                }
                !listAllowed(p, now) -> {
                    consume(p)
                    bundle(p.key, now)
                }
                else -> dispatch(p, now)?.let { return it }
            }
        }
    }

    fun wakeAt(now: Long): Long? {
        if (!loaded) return null
        var best: Long? = null
        if (!continuationRunning && continuations.isNotEmpty()) best = now
        for (p in pairs.values) {
            if (p.done) continue
            val at = maxOf(now, p.time)
            val t = when {
                !blocked(p, at) -> p.time
                session.kind == SessionKind.FOREGROUND -> p.time + policy.lateToleranceMillis + 1
                else -> continue
            }
            best = if (best == null) t else minOf(best, t)
        }
        return best
    }

    private fun nextActionable(now: Long): PairState? {
        var best: PairState? = null
        for (p in pairs.values) {
            if (p.done || p.time > now || blocked(p, now)) continue
            if (best == null || p.time < best.time) best = p
        }
        return best
    }

    /** The event is due for a list but must wait for its pair or a worker (within the tolerance). */
    private fun blocked(p: PairState, now: Long): Boolean =
        session.canUseNetwork(now) && !late(p, now) && listAllowed(p, now) && (p.busy || eventsRunning >= policy.readWorkers)

    private fun late(p: PairState, now: Long): Boolean =
        session.kind == SessionKind.FOREGROUND && now > p.time + policy.lateToleranceMillis

    private fun listAllowed(p: PairState, now: Long): Boolean {
        val refused = p.refusedGeneration
        if (refused != null && p.token.generation <= refused) return false
        return !engine.readPaused(p.key, now) && breaker.allows(p.key.relayId, now)
    }

    private fun dispatch(p: PairState, now: Long): ReadItem? {
        val deadline = session.budget.deadline(now, policy.listDeadlineMillis.toLong())
        if (deadline == null) {
            consume(p)
            return null
        }
        val pages = if (engine.privacyMode() == PrivacyMode.HIGH) policy.highPagesPerEvent else policy.standardPagesPerEvent
        val item = ReadItem(this, p.key, p.relay, p.token, p.cursor, policy.listLimit, deadline, 1, pages, p.time, now)
        consume(p)
        p.busy = true
        eventsRunning++
        return item
    }

    /**
     * A further page still waiting in the queue never holds its pair past the pair's next event
     * (design §11.5 #5): once that event is due, the page is dropped and the pair's work bundle is
     * queued, so inbound volume on another pair, whose further page may run up to its own deadline,
     * never delays or skips this pair's first page (T19). Only a running further page makes its pair
     * busy.
     */
    private fun dropDueContinuations(now: Long) {
        if (session.kind != SessionKind.FOREGROUND || continuations.isEmpty()) return
        val due = continuations.filter { c -> pairs[c.key]?.let { p -> !p.done && p.time <= now } ?: false }
        if (due.isEmpty()) return
        continuations.removeAll(due)
        for (c in due) bundle(c.key, now)
    }

    private fun takeContinuation(now: Long): ReadItem? {
        if (continuationRunning) return null
        while (continuations.isNotEmpty()) {
            val c = continuations.removeFirst()
            val p = pairs[c.key] ?: continue
            // A further page must end before the pair's next event; with less time than a call it is dropped.
            val untilNext = if (session.kind == SessionKind.FOREGROUND && !p.done) p.time - now else Long.MAX_VALUE
            val deadline = session.budget.deadline(now, minOf(policy.listDeadlineMillis.toLong(), untilNext))
            if (!session.canUseNetwork(now) || deadline == null) {
                bundle(p.key, now)
                continue
            }
            continuationRunning = true
            p.busy = true
            return ReadItem(this, p.key, p.relay, p.token, p.cursor, policy.listLimit, deadline, c.page, c.pagesAllowed, now, now)
        }
        return null
    }

    // ------------------------------------------------------------------ completion

    fun complete(item: ReadItem, now: Long) {
        if (item.continuation) continuationRunning = false else eventsRunning--
        val p = pairs[item.pair] ?: return // the pair left the session while listing
        p.busy = false
        when (val outcome = item.outcome ?: return) {
            is PageOutcome.Committed -> {
                // The cursor stored after the commit: the next one, the kept one, or the stored one
                // reloaded when it was no longer the one this request sent (design §11.5 #3).
                outcome.commit.cursor?.let { p.cursor = it }
                if (!item.continuation) breaker.success(p.key.relayId)
                when (outcome.commit.disposition) {
                    PageCommit.Disposition.ACCEPTED ->
                        if (!outcome.commit.staleCursor && continues(item, outcome)) {
                            // Queued, not running: the pair stays free, and its next event drops the page (§11.5 #5).
                            continuations.addLast(Continuation(p.key, item.page + 1, item.pagesAllowed))
                        } else {
                            bundle(p.key, now)
                        }
                    PageCommit.Disposition.DROPPED_BACKLOG -> bundle(p.key, now)
                    // The pair stopped being a read pair; the topology hint's refresh removes it.
                    PageCommit.Disposition.DROPPED_NOT_LISTENED -> Unit
                }
            }
            is PageOutcome.Failed -> {
                val disposition = ErrorPolicy.read(outcome.failure.errorClass, isGet = false)
                disposition.flag?.let { engine.flag(it) }
                if (!item.continuation && disposition.breakerWeight > 0) breaker.failure(p.key.relayId, disposition.breakerWeight, now)
                when (disposition.action) {
                    ReadAction.STOP -> {
                        session.faultLocked(outcome.failure, now)
                        return
                    }
                    ReadAction.SUSPEND -> p.refusedGeneration = item.token.generation
                    ReadAction.PAUSE -> engine.pauseRead(p.key, now + SyncEngine.PAUSE_MILLIS)
                    ReadAction.SKIP, ReadAction.HOSTILE, ReadAction.NOT_FOUND -> Unit
                }
                bundle(p.key, now)
            }
        }
    }

    /** STANDARD: a further page only while the page was full and its non-empty cursor differs from the one sent. */
    private fun continues(item: ReadItem, outcome: PageOutcome.Committed): Boolean {
        if (item.page >= item.pagesAllowed || outcome.hashes < item.limit) return false
        val next = outcome.nextCursor
        return next.isNotEmpty() && !next.contentEquals(item.cursor)
    }

    private fun bundle(pair: PairKey, now: Long) {
        if (session.canUseNetwork(now)) session.work.postPairWork(pair, readPair = true, at = now)
    }

    override fun toString(): String = "ReadLane(pairs=${pairs.size})"
}
