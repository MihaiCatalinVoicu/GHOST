package org.ghost.sync.engine

import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.RelayId
import org.ghost.sync.engine.EngineWorld.Companion.MINUTE
import org.ghost.sync.engine.EngineWorld.Companion.SECOND
import org.ghost.sync.port.ListPage
import org.ghost.sync.port.PairKey
import org.ghost.sync.store.RetentionPolicy
import org.ghost.sync.store.StoreLimits
import org.ghost.sync.store.TestBytes
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The list step and its page bounds against the in-test relay (design §4.1, §4.4): sticky tail,
 * empty page with a cursor, pages per event by mode, hostile cursors, and backlog drop without any
 * change of the request schedule. The test policy uses LIST_LIMIT = 4 (design §8.3).
 */
class ListStepTest {
    private val policy = TrafficPolicy(listLimit = 4)

    /** One listening namespace on one relay with a read token: exactly one read pair. */
    private fun EngineWorld.onePair(): Pair<NamespaceId, RelayId> {
        val relay = relays(1).single()
        val ns = namespace(1, listOf(relay))
        capability(relay, ns, CapabilityKind.READ)
        return Pair(ns, relay)
    }

    private fun EngineWorld.lists(): List<TestRelays.Call> = net.callsOf(TestRelays.Kind.LIST)

    /** First-page start times of the pair's events by its own schedule, up to [until]. */
    private fun EngineWorld.eventTimes(relay: RelayId, ns: NamespaceId, until: Long): List<Long> {
        val schedule = PairSchedule(random, policy)
        return (0L until 1_000L).map { schedule.time(PairKey(relay, ns), 0, it) }.takeWhile { it <= until }
    }

    @Test
    fun theStickyTailKeepsTheLastCursorWhenTheRelayIsCaughtUp(): Unit = EngineWorld(policy).use { w ->
        val (ns, relay) = w.onePair()
        w.inbound(relay, ns, 100, 6)
        val (_, driver) = w.session()
        val events = w.eventTimes(relay, ns, 3 * MINUTE)
        driver.runUntil(events[0])
        // Event 1 (STANDARD): a full page with a cursor, then a further page that reaches the end.
        assertEquals(listOf(0L, 4L), w.lists().map { TestRelays.seqOf(it.cursor) })
        assertEquals("only a non-empty cursor is stored", 4L, w.cursor(relay, ns))
        driver.runUntil(events[1])
        // Event 2 re-lists the tail after the stored cursor (fewer than LIST_LIMIT, absorbed by dedup).
        assertEquals(4L, TestRelays.seqOf(w.lists()[2].cursor))
        assertEquals(4L, w.cursor(relay, ns))
        assertEquals(6L, w.count("inbox_blob"))
        // New blobs after the tail are found from the kept cursor.
        w.inbound(relay, ns, 200, 1)
        driver.runUntil(events[2])
        assertEquals(4L, TestRelays.seqOf(w.lists()[3].cursor))
        assertEquals(7L, w.count("inbox_blob"))
    }

    @Test
    fun anEmptyPageWithACursorIsCommittedAndTheNextEventUsesIt(): Unit = EngineWorld(policy).use { w ->
        val (ns, relay) = w.onePair()
        var answers = 0
        // The real relay does this after skipping more than MAX_LIST_SCAN expired entries.
        w.net.listOverride = { if (answers++ == 0) ListPage(emptyList(), TestRelays.cursorOf(1_100)) else null }
        val (_, driver) = w.session()
        val events = w.eventTimes(relay, ns, 3 * MINUTE)
        driver.runUntil(events[0])
        assertEquals("an empty page is not full: no further page", 1, w.lists().size)
        assertEquals(1_100L, w.cursor(relay, ns))
        driver.runUntil(events[1])
        assertEquals(1_100L, TestRelays.seqOf(w.lists()[1].cursor))
    }

    @Test
    fun standardReadsUpToFourPagesPerEventWhileFullAndAdvancing(): Unit = EngineWorld(policy).use { w ->
        val (ns, relay) = w.onePair()
        w.inbound(relay, ns, 100, 30)
        val (_, driver) = w.session()
        val events = w.eventTimes(relay, ns, 5 * MINUTE)
        driver.runUntil(events[0])
        assertEquals(listOf(0L, 4L, 8L, 12L), w.lists().map { TestRelays.seqOf(it.cursor) })
        assertEquals(16L, w.cursor(relay, ns))
        driver.runUntil(events[1])
        // Event 2: 14 left → pages of 4, 4, 4 (the third ends with a cursor) and a fourth of 2.
        assertEquals(listOf(16L, 20L, 24L, 28L), w.lists().drop(4).map { TestRelays.seqOf(it.cursor) })
        assertEquals(28L, w.cursor(relay, ns))
        assertEquals(30L, w.count("inbox_blob"))
        // Every first page started exactly at its event; further pages only after a full page.
        val firstPages = driver.started.map { it.second }.filterIsInstance<ReadItem>().filter { !it.continuation }
        assertEquals(events.take(2), firstPages.map { it.startMillis })
    }

    @Test
    fun highModeReadsExactlyOnePagePerEvent(): Unit = EngineWorld(policy).use { w ->
        w.mode = PrivacyMode.HIGH
        val (ns, relay) = w.onePair()
        w.inbound(relay, ns, 100, 30)
        val (_, driver) = w.session()
        val events = w.eventTimes(relay, ns, 5 * MINUTE)
        driver.runUntil(5 * MINUTE)
        assertEquals(events, w.lists().map { it.startMillis })
        assertEquals(events.indices.map { minOf(4L * it, 28L) }, w.lists().map { TestRelays.seqOf(it.cursor) })
    }

    @Test
    fun hostileCursorsCostAtMostTheEventsPageBound(): Unit = EngineWorld(policy).use { w ->
        val (ns, relay) = w.onePair()
        // A full page of garbage and a fresh cursor on every request, forever.
        var counter = 0L
        w.net.listOverride = { ListPage((0 until 4).map { TestBytes.hash(10_000 + (counter * 4 + it).toInt()) }, TestRelays.cursorOf(++counter)) }
        val (_, driver) = w.session()
        val events = w.eventTimes(relay, ns, 10 * MINUTE)
        driver.runUntil(10 * MINUTE)
        assertEquals("exactly four requests per event", events.size * 4, w.lists().size)
        // A full page whose cursor equals the one sent is not followed.
        w.net.listOverride = { call -> ListPage((0 until 4).map { TestBytes.hash(20_000 + it) }, call.cursor.takeIf { it.isNotEmpty() } ?: TestRelays.cursorOf(1)) }
        val before = w.lists().size
        driver.runUntil(20 * MINUTE)
        val more = w.eventTimes(relay, ns, 20 * MINUTE).size - events.size
        assertEquals(more, w.lists().size - before)
        // A non-empty cursor with an empty page, forever: one request per event.
        w.net.listOverride = { ListPage(emptyList(), TestRelays.cursorOf(99)) }
        val before2 = w.lists().size
        driver.runUntil(30 * MINUTE)
        assertEquals(w.eventTimes(relay, ns, 30 * MINUTE).size - events.size - more, w.lists().size - before2)
    }

    @Test
    fun overTheBacklogCapThePageIsDroppedButTheScheduleIsUnchanged(): Unit = EngineWorld(policy).use { w ->
        val (ns, relay) = w.onePair()
        w.inbound(relay, ns, 100, 3)
        // BACKLOG_CAP listed rows attributed to this relay already (a flooding relay's earlier pages).
        val retain = RetentionPolicy.listedRetainDay(w.clock.epochSeconds())
        w.sql.transaction {
            for (i in 0 until StoreLimits.BACKLOG_CAP) {
                val h = TestBytes.hash(50_000 + i).toByteArray()
                w.raw("INSERT INTO inbox_blob(namespace_id, blob_hash, state, retain_until_day) VALUES (?, ?, 'listed', ?)", ns, h, retain)
                w.raw("INSERT INTO inbox_source(namespace_id, blob_hash, relay_id, state) VALUES (?, ?, ?, 'candidate')", ns, h, relay)
            }
        }
        w.net.latency = { if (it.kind == TestRelays.Kind.GET) 1 * SECOND else 0 }
        val (_, driver) = w.session()
        val events = w.eventTimes(relay, ns, 3 * MINUTE)
        driver.runUntil(3 * MINUTE)
        // The request is still sent at every event; its page is discarded and the cursor stays.
        assertEquals(events, w.lists().filter { it.cursor.isEmpty() }.map { it.startMillis })
        assertEquals(events.size, w.lists().size)
        assertNull(w.cursor(relay, ns))
        assertNull("the relay's real blobs were not recorded", w.inboxState(ns, w.hashOf(100)))
        assertEquals(StoreLimits.BACKLOG_CAP.toLong(), w.count("inbox_blob"))
        // The work lane still spends the pair's fetch slots on the backlog (8 per event).
        assertEquals(8 * events.size, w.net.callsOf(TestRelays.Kind.GET).size)
    }
}
