package org.ghost.sync.harness

import org.ghost.sync.engine.Lane
import org.ghost.sync.engine.LaneItem
import org.ghost.sync.engine.Session
import java.util.PriorityQueue
import kotlin.concurrent.withLock

/**
 * Deterministic driver of a world (design §1.4, §8.2): every client's session lanes, the pending
 * completions of their items and the world's timeline of actions (user actions, other clients'
 * writes, session starts and stops, consumer drains), all in virtual time, one at a time.
 *
 * An item starts at the time its lane asks for; its calls advance the clock by their latency; its
 * completion is held until that later time, so read workers, the work lane and other clients
 * overlap exactly as on threads (the clock steps back to the next start between items, as in the
 * engine's own driver). Ties: completions, then timeline actions, then read, then work; clients in
 * creation order. Nothing is caught here: an injected crash leaves [runUntil] and reaches the
 * scenario runner.
 */
internal class HarnessDriver(private val world: World) {
    private class Pending(val at: Long, val seq: Long, val client: Client, val session: Session, val item: LaneItem)

    private class Timed(val at: Long, val seq: Long, val label: String, val sessionOf: Client?, val process: Client?, val run: () -> Unit)

    private val pending = PriorityQueue<Pending>(compareBy<Pending>({ it.at }, { it.seq }))
    private val timeline = PriorityQueue<Timed>(compareBy<Timed>({ it.at }, { it.seq }))
    private var seq = 0L
    private var idle = 0

    /** Time of the last step (the clock may be ahead of it while an item's latency runs). */
    var time: Long = 0
        private set

    /** Timeline actions run and unarmed clients' item starts and completions (classification key). */
    var worldActions: Long = 0
        private set

    /** Id of the lane item running now (relay calls must happen inside one). */
    var currentItemId: Long? = null
        private set
    var currentItem: LaneItem? = null
        private set
    var currentClient: Client? = null
        private set
    private var itemIds = 0L

    /** Items started, with client and start time (T19 tests read it) when [recordStarts]. */
    var recordStarts = false
    val started = ArrayList<Triple<Client, Long, LaneItem>>()

    /** Runs before every lane item (consumer interleavings between items, design §8.5). */
    var beforeItem: ((Client, LaneItem) -> Unit)? = null

    /** Called when a client's session finished. */
    var onSessionFinished: ((Client, Session) -> Unit)? = null

    fun schedule(at: Long, label: String, run: () -> Unit) {
        timeline.add(Timed(at, seq++, label, null, null, run))
    }

    /** An action of [client]'s process (a consumer thread): it dies with the process. */
    fun scheduleProcess(at: Long, client: Client, label: String, run: () -> Unit) {
        timeline.add(Timed(at, seq++, label, null, client, run))
    }

    /** A session start of [client] (used to find the next session after a crash). */
    fun scheduleSession(at: Long, client: Client, label: String, run: () -> Unit) {
        timeline.add(Timed(at, seq++, label, client, null, run))
    }

    /** Earliest scheduled session start of [client] at or after [from], or null. */
    fun nextSessionStart(client: Client, from: Long): Long? =
        timeline.filter { it.sessionOf === client && it.at >= from }.minOfOrNull { it.at }

    fun hasTimeline(): Boolean = timeline.isNotEmpty()

    fun dropClient(client: Client) {
        pending.removeIf { it.client === client }
        timeline.removeIf { it.process === client }
    }

    /** True while some client runs a session or holds pending completions. */
    val busy: Boolean get() = pending.isNotEmpty() || world.clients.any { it.session != null }

    /** Runs every step at or before [limit]; the clock ends at max(clock, limit). */
    fun runUntil(limit: Long) {
        while (step(limit)) {
            // one step per iteration
        }
        if (limit > time) time = limit
        if (world.clock.millis < time) world.clock.millis = time
    }

    /** Runs until no session is running and nothing is pending, or [limit]; returns true if idle. */
    fun runUntilIdle(limit: Long): Boolean {
        while (busy && step(limit)) {
            // one step per iteration
        }
        if (world.clock.millis < time) world.clock.millis = time
        return !busy
    }

    private fun step(limit: Long): Boolean {
        var bestAt = Long.MAX_VALUE
        var bestKind = -1
        var bestClient: Client? = null
        var bestLane: Lane? = null
        pending.peek()?.let {
            bestAt = maxOf(it.at, time)
            bestKind = 0
        }
        timeline.peek()?.let {
            val at = maxOf(it.at, time)
            if (at < bestAt) {
                bestAt = at
                bestKind = 1
            }
        }
        for (c in world.clients) {
            val s = c.session ?: continue
            for (lane in LANES) {
                val wake = s.lock.withLock { if (s.finished) null else s.wakeAt(lane, time) } ?: continue
                val at = maxOf(wake, time)
                if (at < bestAt) {
                    bestAt = at
                    bestKind = 2
                    bestClient = c
                    bestLane = lane
                }
            }
        }
        if (bestKind < 0 || bestAt > limit) return false
        time = bestAt
        world.clock.millis = bestAt
        when (bestKind) {
            0 -> {
                val p = pending.poll()
                if (!p.client.spec.armed) worldActions++
                p.session.lock.withLock { p.session.complete(p.item, bestAt) }
                idle = 0
                settle()
            }
            1 -> {
                val t = timeline.poll()
                worldActions++
                t.run()
                idle = 0
                settle()
            }
            else -> {
                val c = bestClient!!
                val s = c.session!!
                val item = s.lock.withLock { s.take(bestLane!!, bestAt) }
                if (item == null) {
                    idle++
                    check(idle < 100_000) { "a lane keeps waking without progress" }
                    settle()
                    return true
                }
                idle = 0
                if (!c.spec.armed) worldActions++
                if (recordStarts) started += Triple(c, bestAt, item)
                beforeItem?.invoke(c, item)
                currentItemId = ++itemIds
                currentItem = item
                currentClient = c
                try {
                    item.run()
                } finally {
                    currentItemId = null
                    currentItem = null
                    currentClient = null
                }
                pending.add(Pending(world.clock.millis, seq++, c, s, item))
            }
        }
        return true
    }

    /** Clears finished sessions (a stop with nothing running finishes at once). */
    private fun settle() {
        for (c in world.clients) {
            val s = c.session ?: continue
            if (s.lock.withLock { s.finished } && pending.none { it.session === s }) {
                c.session = null
                onSessionFinished?.invoke(c, s)
            }
        }
    }

    override fun toString(): String = "HarnessDriver(t=$time)"

    companion object {
        private val LANES = listOf(Lane.READ, Lane.WORK)
    }
}
