package org.ghost.sync.engine

import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.RelayId
import org.ghost.sync.engine.EngineWorld.Companion.MINUTE
import org.ghost.sync.engine.EngineWorld.Companion.SECOND
import org.ghost.sync.port.PairKey
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Read-lane dispatch (design §1.4, §11.2 #12): k = 4 event workers, one event per pair at a time,
 * late events skipped not delayed, round-robin beyond the pair cap, and further STANDARD pages on
 * their own worker, bounded by the pair's next event.
 */
class ReadLaneTest {

    /** [namespaces] listening namespaces over [relays] relays with read tokens: namespaces × relays read pairs. */
    private fun EngineWorld.pairs(relays: Int, namespaces: Int): List<PairKey> {
        val ids = relays(*IntArray(relays) { it + 1 })
        val out = ArrayList<PairKey>()
        for (n in 1..namespaces) {
            val ns = namespace(n, ids)
            ids.forEach { capability(it, ns, CapabilityKind.READ) }
            ids.forEach { out += PairKey(it, ns) }
        }
        return out
    }

    private fun maxOverlap(intervals: List<LongRange>): Int {
        val edges = intervals.flatMap { listOf(Pair(it.first, 1), Pair(it.last, -1)) }.sortedWith(compareBy({ it.first }, { it.second }))
        var now = 0
        var best = 0
        for ((_, d) in edges) {
            now += d
            best = maxOf(best, now)
        }
        return best
    }

    private fun DeterministicDriver.readItems(): List<ReadItem> = started.map { it.second }.filterIsInstance<ReadItem>()

    @Test
    fun atMostFourEventsRunAtOnceAndEachPairRunsOneAtATime(): Unit = EngineWorld().use { w ->
        w.mode = PrivacyMode.HIGH
        w.pairs(relays = 4, namespaces = 3) // 12 pairs
        w.net.latency = { if (it.kind == TestRelays.Kind.LIST) 12 * SECOND else 0 }
        val (session, driver) = w.session()
        driver.runUntil(30 * MINUTE)
        val lists = w.net.callsOf(TestRelays.Kind.LIST)
        assertTrue(lists.size > 300)
        val intervals = lists.map { it.startMillis until it.startMillis + 12 * SECOND }
        assertEquals("k = 4 event workers, saturated", 4, maxOverlap(intervals))
        for ((_, calls) in lists.groupBy { Pair(it.relay, it.namespace) }) {
            val sorted = calls.sortedBy { it.startMillis }
            for (i in 1 until sorted.size) assertTrue("serialized per pair", sorted[i].startMillis >= sorted[i - 1].startMillis + 12 * SECOND)
        }
        // Saturated: some events could not start within 2 s and were skipped, never delayed further.
        assertTrue(session.read.skippedLate > 0)
        for (item in driver.readItems()) {
            val delay = item.startMillis - item.scheduledMillis
            assertTrue("started $delay ms late", delay in 0..w.policy.lateToleranceMillis)
        }
    }

    @Test
    fun anIdleLaneStartsEveryEventExactlyOnTime(): Unit = EngineWorld().use { w ->
        w.mode = PrivacyMode.HIGH
        val pairs = w.pairs(relays = 2, namespaces = 2)
        w.net.latency = { if (it.kind == TestRelays.Kind.LIST) 1 * SECOND else 0 }
        val (session, driver) = w.session()
        driver.runUntil(20 * MINUTE)
        val schedule = PairSchedule(w.random, w.policy)
        for (p in pairs) {
            val times = w.net.callsOf(TestRelays.Kind.LIST).filter { it.namespace == p.namespace && it.relay == w.address(p.relayId) }.map { it.startMillis }
            assertEquals((0L until 200L).map { schedule.time(p, 0, it) }.takeWhile { it <= 20 * MINUTE }, times)
        }
        assertEquals(0L, session.read.skippedLate)
    }

    @Test
    fun beyondTheCapPairsShareEventsRoundRobin(): Unit = EngineWorld(TrafficPolicy(maxReadPairs = 4)).use { w ->
        w.mode = PrivacyMode.HIGH
        val pairs = w.pairs(relays = 5, namespaces = 2) // 10 pairs → 3 groups
        val (_, driver) = w.session()
        driver.runUntil(60 * MINUTE)
        val schedule = PairSchedule(w.random, w.policy)
        val groups = schedule.groups(pairs)
        val lists = w.net.callsOf(TestRelays.Kind.LIST)
        for (p in pairs) {
            val times = lists.filter { it.namespace == p.namespace && it.relay == w.address(p.relayId) }.map { it.startMillis }
            val acting = (0L until 1_000L).filter { it % 3 == groups.getValue(p).toLong() }.map { schedule.time(p, 0, it) }.takeWhile { it <= 60 * MINUTE }
            assertEquals("pair lists exactly at its acting indices", acting, times)
            // One event per T × 3 on average: about 40 in an hour.
            assertTrue(times.size in 30..50)
        }
    }

    @Test
    fun furtherStandardPagesRunOnTheirOwnWorkerAndEndBeforeThePairsNextEvent(): Unit = EngineWorld(TrafficPolicy(listLimit = 4)).use { w ->
        val pairs = w.pairs(relays = 4, namespaces = 2) // 8 pairs
        pairs.forEachIndexed { i, p -> w.inbound(p.relayId, p.namespace, 10_000 * (i + 1), 40) }
        w.net.latency = { if (it.kind == TestRelays.Kind.LIST) 6 * SECOND else 0 }
        val (_, driver) = w.session()
        driver.runUntil(15 * MINUTE)
        val items = driver.readItems()
        val continuations = items.filter { it.continuation }
        assertTrue(continuations.isNotEmpty())
        // Event workers carry first pages only; at most one further page runs at a time.
        assertTrue(maxOverlap(items.filter { !it.continuation }.map { it.startMillis until it.startMillis + 6 * SECOND }) <= 4)
        assertEquals(1, maxOverlap(continuations.map { it.startMillis until it.startMillis + minOf(6 * SECOND, it.deadlineMillis.toLong()) }))
        // A further page's deadline ends before the pair's next event.
        val schedule = PairSchedule(w.random, w.policy)
        for (c in continuations) {
            val next = (0L until 1_000L).map { schedule.time(c.pair, 0, it) }.first { it > c.startMillis }
            assertTrue(c.startMillis + c.deadlineMillis <= next)
        }
        // First pages still start at their scheduled times (within the tolerance, never later).
        for (item in items.filter { !it.continuation }) assertTrue(item.startMillis - item.scheduledMillis in 0..w.policy.lateToleranceMillis)
    }

    @Test
    fun listFailuresOpenTheReadBreakerOfThatRelayOnly(): Unit = EngineWorld().use { w ->
        w.mode = PrivacyMode.HIGH
        val relays = w.relays(1, 2)
        val ns = w.namespace(1, relays)
        relays.forEach { w.capability(it, ns, CapabilityKind.READ) }
        val bad = w.address(relays[0])
        w.net.failBefore = { if (it.kind == TestRelays.Kind.LIST && it.relay == bad) "timeout" else null }
        val (session, driver) = w.session()
        driver.runUntil(30 * MINUTE)
        val badLists = w.net.callsOf(TestRelays.Kind.LIST).filter { it.relay == bad }.size
        val goodLists = w.net.callsOf(TestRelays.Kind.LIST).filter { it.relay != bad }.size
        assertTrue("the failing relay is held by its breaker", badLists < goodLists / 3)
        assertEquals("every failure counted, none reset", badLists, session.read.breaker.failures(relays[0]))
        assertEquals(0, session.read.breaker.failures(relays[1]))
    }

    @Test
    fun unauthorizedSuspendsThePairUntilANewGeneration(): Unit = EngineWorld().use { w ->
        w.mode = PrivacyMode.HIGH
        val relay = w.relays(1).single()
        val ns: NamespaceId = w.namespace(1, listOf(relay))
        w.capability(relay, ns, CapabilityKind.READ)
        var refuse = true
        w.net.failBefore = { if (it.kind == TestRelays.Kind.LIST && refuse) "unauthorized" else null }
        val (_, driver) = w.session()
        driver.runUntil(10 * MINUTE)
        assertEquals("one refused request, then no listing", 1, w.net.callsOf(TestRelays.Kind.LIST).size)
        assertEquals("rejected", w.string("SELECT state FROM relay_capability WHERE relay_id = ?", relay))
        // Phase 8 installs a new generation: the hint refreshes the snapshot and listing resumes.
        refuse = false
        w.capability(relay, ns, CapabilityKind.READ, seed = 2)
        driver.runUntil(20 * MINUTE)
        assertTrue(w.net.callsOf(TestRelays.Kind.LIST).size > 10)
        val relayId: RelayId = relay
        assertEquals(2L, w.long("SELECT generation FROM relay_capability WHERE relay_id = ?", relayId))
    }
}
