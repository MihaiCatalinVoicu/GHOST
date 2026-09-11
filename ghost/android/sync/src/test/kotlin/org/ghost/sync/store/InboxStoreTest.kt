package org.ghost.sync.store

import org.ghost.sync.api.BlobHash
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.InboundBlob
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.RelayId
import org.ghost.sync.api.SyncChange
import org.ghost.sync.store.SyncWorld.Companion.DAY
import org.ghost.sync.store.SyncWorld.Companion.HOUR
import org.ghost.sync.store.SyncWorld.Companion.MINUTE
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** List commit, fetch, hand-off (design §4, §11.2 #1–#3, §11.3). */
class InboxStoreTest {

    /** A listening namespace over two relays of distinct operators, with read tokens. */
    private fun SyncWorld.inboxSet(): Pair<NamespaceId, List<RelayId>> {
        val relays = relays(1, 2)
        val ns = namespace(1, relays)
        relays.forEach { capability(it, ns, org.ghost.sync.api.CapabilityKind.READ) }
        return Pair(ns, relays)
    }

    private fun cursor(b: Int) = ByteArray(8) { b.toByte() }

    private fun SyncWorld.page(relay: RelayId, ns: NamespaceId, hashes: List<BlobHash>, next: ByteArray = ByteArray(0)) =
        tx { inbox.commitPage(it, relay, ns, hashes, next, now) }

    private fun SyncWorld.fetch(relay: RelayId, ns: NamespaceId, seed: Int, expiry: Long = now + 7 * DAY) {
        val h = hashOf(seed)
        assertTrue(tx { inbox.leaseFetch(it, ns, h, now, 60) })
        assertTrue(tx { inbox.recordFetched(it, ns, h, TestBytes.ciphertext(seed), expiry) })
    }

    @Test
    fun aPageCommitsRowsSourcesAndOnlyANonEmptyCursor(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.inboxSet()
        val hashes = listOf(w.hashOf(1), w.hashOf(2), w.hashOf(1))
        val first = w.page(relays[0], ns, hashes, cursor(1))
        assertEquals(PageCommit.Disposition.ACCEPTED, first.disposition)
        assertEquals(2, first.listedRows)
        assertTrue(first.cursorStored)
        assertEquals(2L, w.count("inbox_blob", "state = 'listed'"))
        assertEquals(RetentionPolicy.ceil7(Time.day(w.now) + 111), w.retainDay(ns, w.hashOf(1)))
        assertEquals("candidate", w.sourceState(ns, w.hashOf(1), relays[0]))
        assertArrayEquals(cursor(1), w.tx { w.cursors.cursor(it, relays[0], ns) })
        // Sticky tail: an empty next cursor keeps the stored one.
        w.clock.advance(20 * DAY)
        val tail = w.page(relays[0], ns, listOf(w.hashOf(2)))
        assertFalse(tail.cursorStored)
        assertArrayEquals(cursor(1), w.tx { w.cursors.cursor(it, relays[0], ns) })
        // A re-listing refreshes the retention day (never lowers it) and a second relay adds its source.
        assertEquals(RetentionPolicy.ceil7(Time.day(w.now) + 111), w.retainDay(ns, w.hashOf(2)))
        w.page(relays[1], ns, listOf(w.hashOf(2)), cursor(9))
        assertEquals(2L, w.count("inbox_source", "blob_hash = ?", w.hashOf(2)))
        assertArrayEquals(cursor(9), w.tx { w.cursors.cursor(it, relays[1], ns) })
        // A non-empty cursor with an empty page is committed too.
        w.page(relays[1], ns, emptyList(), cursor(10))
        assertArrayEquals(cursor(10), w.tx { w.cursors.cursor(it, relays[1], ns) })
        assertThrows(IllegalArgumentException::class.java) { w.page(relays[1], ns, emptyList(), ByteArray(7)) }
    }

    @Test
    fun ownAndConsumedHashesAreAbsorbed(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.inboxSet()
        relays.forEach { w.capability(it, ns) }
        w.enqueue(5, ns)
        val own = w.hashOf(5)
        val page = w.page(relays[0], ns, listOf(own))
        assertEquals(0, page.listedRows)
        assertEquals("done", w.inboxState(ns, own))
        assertEquals(0L, w.count("inbox_source"))
        assertEquals(1, page.verified.size)
    }

    @Test
    fun pagesOfAPairThatIsNoLongerListenedAreDropped(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.inboxSet()
        w.tx { w.stores.namespaces.setListening(it, ns, false) }
        val dropped = w.page(relays[0], ns, listOf(w.hashOf(1)), cursor(1))
        assertEquals(PageCommit.Disposition.DROPPED_NOT_LISTENED, dropped.disposition)
        w.tx { w.stores.namespaces.setListening(it, ns, true) }
        w.tx { w.stores.namespaces.setRelays(it, ns, setOf(relays[1])) }
        assertEquals(PageCommit.Disposition.DROPPED_NOT_LISTENED, w.page(relays[0], ns, listOf(w.hashOf(1)), cursor(1)).disposition)
        assertEquals(0L, w.count("inbox_blob"))
        assertEquals(0L, w.count("relay_cursor"))
    }

    @Test
    fun backlogCapDropsThePageAndKeepsTheCursor(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.inboxSet()
        val batch = (0 until StoreLimits.BACKLOG_CAP - 1).map { BlobHash(TestBytes.of(32, 100_000 + it)) }
        w.tx { tx ->
            batch.chunked(128).forEach { w.inbox.commitPage(tx, relays[0], ns, it, ByteArray(0), w.now) }
        }
        assertEquals(StoreLimits.BACKLOG_CAP - 1, w.tx { w.inbox.backlog(it, relays[0], ns) })
        assertEquals(PageCommit.Disposition.ACCEPTED, w.page(relays[0], ns, listOf(w.hashOf(1)), cursor(1)).disposition)
        assertEquals(StoreLimits.BACKLOG_CAP, w.tx { w.inbox.backlog(it, relays[0], ns) })
        val over = w.page(relays[0], ns, listOf(w.hashOf(2)), cursor(2))
        assertEquals(PageCommit.Disposition.DROPPED_BACKLOG, over.disposition)
        assertNull(w.inboxState(ns, w.hashOf(2)))
        assertArrayEquals(cursor(1), w.tx { w.cursors.cursor(it, relays[0], ns) })
        // Another relay of the set is unaffected; rows that became unavailable still count for their relay.
        assertEquals(PageCommit.Disposition.ACCEPTED, w.page(relays[1], ns, listOf(w.hashOf(2))).disposition)
        w.raw("UPDATE inbox_source SET state = 'bad' WHERE relay_id = ?", relays[0])
        w.raw("UPDATE inbox_blob SET state = 'unavailable' WHERE state = 'listed' AND blob_hash <> ?", w.hashOf(2))
        assertEquals(StoreLimits.BACKLOG_CAP, w.tx { w.inbox.backlog(it, relays[0], ns) })
        assertEquals(PageCommit.Disposition.DROPPED_BACKLOG, w.page(relays[0], ns, listOf(w.hashOf(3))).disposition)
    }

    @Test
    fun fetchLeaseSuccessAndHandOffOrder(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.inboxSet()
        w.page(relays[0], ns, listOf(w.hashOf(1), w.hashOf(2)))
        val due = w.tx { w.inbox.dueFetches(it, relays[0], ns, w.now, 8) }
        assertEquals(setOf(w.hashOf(1), w.hashOf(2)), due.toSet())
        assertTrue(w.tx { w.inbox.dueFetches(it, relays[1], ns, w.now, 8) }.isEmpty())
        assertTrue(w.tx { w.inbox.leaseFetch(it, ns, w.hashOf(2), w.now, 90) })
        assertFalse(w.tx { w.inbox.leaseFetch(it, ns, w.hashOf(2), w.now, 90) })
        assertEquals(1L, w.long("SELECT fetch_attempts FROM inbox_blob WHERE blob_hash = ?", w.hashOf(2)))
        assertEquals(Time.floorMinute(w.now) + 2 * MINUTE, w.long("SELECT next_fetch_minute FROM inbox_blob WHERE blob_hash = ?", w.hashOf(2)))
        assertEquals(listOf(w.hashOf(1)), w.tx { w.inbox.dueFetches(it, relays[0], ns, w.now, 8) })
        w.hints.clear()
        val expiry = w.now + 7 * DAY + 5 * HOUR
        assertTrue(w.tx { w.inbox.recordFetched(it, ns, w.hashOf(2), TestBytes.ciphertext(2), expiry) })
        assertEquals(listOf(setOf(SyncChange.INBOX)), w.hints)
        assertEquals("fetched", w.inboxState(ns, w.hashOf(2)))
        assertEquals(RetentionPolicy.ceil7(Time.day(expiry) + 24), w.retainDay(ns, w.hashOf(2)))
        assertEquals(0L, w.long("SELECT fetch_attempts FROM inbox_blob WHERE blob_hash = ?", w.hashOf(2)))
        assertEquals(0L, w.count("inbox_source", "blob_hash = ?", w.hashOf(2)))
        assertFalse(w.tx { w.inbox.recordFetched(it, ns, w.hashOf(2), TestBytes.ciphertext(2), expiry) })
        assertThrows(IllegalArgumentException::class.java) {
            w.tx { w.inbox.recordFetched(it, ns, w.hashOf(1), TestBytes.ciphertext(2), expiry) }
        }
        w.fetch(relays[0], ns, 1)
        // Claim returns local arrival order (fetch order), not hash order.
        val claimed = w.stores.inbox.claim(Consumer.DM, 10)
        assertEquals(listOf(w.hashOf(2), w.hashOf(1)), claimed.map(InboundBlob::hash))
        assertArrayEquals(TestBytes.ciphertext(2), claimed[0].ciphertext)
        assertTrue(w.stores.inbox.claim(Consumer.CHANNEL, 10).isEmpty())
    }

    @Test
    fun notFoundIsRetriedOnceAfterAnHourThenTheRowBecomesUnavailableUntilListedAgain(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.inboxSet()
        val h = w.hashOf(1)
        w.page(relays[0], ns, listOf(h))
        assertTrue(w.tx { w.inbox.leaseFetch(it, ns, h, w.now, 60) })
        assertEquals(NotFoundResult.RETRY_LATER, w.tx { w.inbox.recordNotFound(it, relays[0], ns, h, w.now) })
        assertEquals("not_found", w.sourceState(ns, h, relays[0]))
        assertEquals("listed", w.inboxState(ns, h))
        assertEquals(Time.floorMinute(w.now) + HOUR, w.long("SELECT next_fetch_minute FROM inbox_blob"))
        w.clock.advance(59 * MINUTE)
        assertTrue(w.tx { w.inbox.dueFetches(it, relays[0], ns, w.now, 8) }.isEmpty())
        w.clock.advance(MINUTE)
        assertEquals(listOf(h), w.tx { w.inbox.dueFetches(it, relays[0], ns, w.now, 8) })
        assertTrue(w.tx { w.inbox.leaseFetch(it, ns, h, w.now, 60) })
        assertEquals(NotFoundResult.UNAVAILABLE, w.tx { w.inbox.recordNotFound(it, relays[0], ns, h, w.now) })
        assertEquals("bad", w.sourceState(ns, h, relays[0]))
        assertEquals("unavailable", w.inboxState(ns, h))
        assertTrue(w.tx { w.inbox.dueFetches(it, relays[0], ns, w.now + HOUR, 8) }.isEmpty())
        // The same relay listing it again changes nothing; another relay does.
        w.page(relays[0], ns, listOf(h))
        assertEquals("unavailable", w.inboxState(ns, h))
        w.page(relays[1], ns, listOf(h))
        assertEquals("listed", w.inboxState(ns, h))
        assertEquals(listOf(h), w.tx { w.inbox.dueFetches(it, relays[1], ns, w.now + HOUR, 8) })
    }

    @Test
    fun aFetchRetryFarInTheFutureAfterABackwardClockJumpIsDue(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.inboxSet()
        val h = w.hashOf(1)
        w.page(relays[0], ns, listOf(h))
        assertTrue(w.tx { w.inbox.leaseFetch(it, ns, h, w.now, HOUR) })
        assertTrue(w.tx { w.inbox.dueFetches(it, relays[0], ns, w.now, 8) }.isEmpty())
        assertFalse(w.tx { w.inbox.leaseFetch(it, ns, h, w.now, 60) })
        // The clock steps back two hours: the stored retry lies more than 61 minutes ahead and counts as due.
        w.clock.advance(-2 * HOUR)
        assertEquals(listOf(h), w.tx { w.inbox.dueFetches(it, relays[0], ns, w.now, 8) })
        assertTrue(w.tx { w.inbox.leaseFetch(it, ns, h, w.now, 60) })
        assertEquals(2L, w.long("SELECT fetch_attempts FROM inbox_blob"))
    }

    @Test
    fun aNotFoundSourceWaitsWhileAnotherCandidateRemains(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.inboxSet()
        val h = w.hashOf(1)
        w.page(relays[0], ns, listOf(h))
        w.page(relays[1], ns, listOf(h))
        assertTrue(w.tx { w.inbox.leaseFetch(it, ns, h, w.now, 0) })
        assertEquals(NotFoundResult.RETRY_LATER, w.tx { w.inbox.recordNotFound(it, relays[0], ns, h, w.now) })
        // The other candidate is not held back by an hour.
        assertEquals(Time.floorMinute(w.now), w.long("SELECT next_fetch_minute FROM inbox_blob"))
        assertTrue(w.tx { w.inbox.dueFetches(it, relays[0], ns, w.now, 8) }.isEmpty())
        assertEquals(listOf(h), w.tx { w.inbox.dueFetches(it, relays[1], ns, w.now, 8) })
        // A malformed answer from the last candidate: the not_found source is retried after the hour.
        assertTrue(w.tx { w.inbox.leaseFetch(it, ns, h, w.now, 0) })
        assertFalse(w.tx { w.inbox.recordBadSource(it, relays[1], ns, h, w.now) })
        assertEquals("bad", w.sourceState(ns, h, relays[1]))
        assertEquals("listed", w.inboxState(ns, h))
        assertTrue(w.tx { w.inbox.dueFetches(it, relays[0], ns, w.now + 59 * MINUTE, 8) }.isEmpty())
        assertEquals(listOf(h), w.tx { w.inbox.dueFetches(it, relays[0], ns, w.now + HOUR, 8) })
        assertEquals(NotFoundResult.IGNORED, w.tx { w.inbox.recordNotFound(it, relays[1], ns, h, w.now) })
    }

    @Test
    fun fetchedCapCountsOnlyDueNonSuspectRows(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.inboxSet()
        val cap = StoreLimits.FETCHED_CAP
        val hashes = (0 until cap).map { BlobHash(TestBytes.of(32, 50_000 + it)) }
        w.page(relays[0], ns, hashes.take(128))
        w.page(relays[0], ns, hashes.drop(128))
        w.page(relays[0], ns, listOf(w.hashOf(1)))
        // Mark all cap rows fetched directly (bytes need not match here: the store checks only on its own path).
        w.raw(
            "UPDATE inbox_blob SET state = 'fetched', ciphertext = zeroblob(1024), fetch_seq = rowid_seq, retain_until_day = 7 " +
                "FROM (SELECT blob_hash AS h, row_number() OVER (ORDER BY blob_hash) AS rowid_seq FROM inbox_blob WHERE blob_hash <> ?) " +
                "WHERE inbox_blob.blob_hash = h",
            w.hashOf(1),
        )
        assertEquals(cap, w.tx { w.inbox.fetchedLoad(it, ns, w.now) })
        assertTrue(w.tx { w.inbox.dueFetches(it, relays[0], ns, w.now, 8) }.isEmpty())
        // A deferred row and a suspect (offers >= 3) row stop counting.
        w.tx { w.stores.inbox.defer(it, ns, hashes[0], 3600) }
        w.raw("UPDATE inbox_blob SET offers = 3, offer_after_minute = ? WHERE blob_hash = ?", Time.floorMinute(w.now) + HOUR, hashes[1])
        assertEquals(cap - 2, w.tx { w.inbox.fetchedLoad(it, ns, w.now) })
        assertEquals(listOf(w.hashOf(1)), w.tx { w.inbox.dueFetches(it, relays[0], ns, w.now, 8) })
    }

    @Test
    fun claimIsolatesAPoisonBlobAndTheInnocentsAreConsumed(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.inboxSet()
        val seeds = (1..32).toList()
        w.page(relays[0], ns, seeds.map { w.hashOf(it) })
        seeds.forEach { w.fetch(relays[0], ns, it) }
        val poison = w.hashOf(1)
        // A consumer that dies (process crash) whenever it touches the poison blob, consuming in order until then.
        fun consumerRun(): Int {
            var consumed = 0
            for (b in w.stores.inbox.claim(Consumer.DM, 32)) {
                if (b.hash == poison) return consumed
                assertTrue(w.tx { w.stores.inbox.markConsumed(it, b.namespace, b.hash) })
                consumed++
            }
            return consumed
        }
        assertEquals(0, consumerRun()) // poison first in arrival order: nothing consumed
        assertEquals(0, consumerRun())
        // Every row has now been offered twice: each claim returns one suspect alone.
        var runs = 0
        while (w.count("inbox_blob", "state = 'fetched'") > 1 && runs < 100) {
            consumerRun()
            runs++
        }
        assertEquals(1L, w.count("inbox_blob", "state = 'fetched'"))
        assertEquals("fetched", w.inboxState(ns, poison))
        assertEquals(31L, w.count("inbox_blob", "state = 'done'"))
        assertEquals(3L, w.long("SELECT offers FROM inbox_blob WHERE blob_hash = ?", poison))
        assertEquals(Time.floorMinute(w.now) + HOUR, w.long("SELECT offer_after_minute FROM inbox_blob WHERE blob_hash = ?", poison))
        assertTrue(w.stores.inbox.claim(Consumer.DM, 32).isEmpty())
        val counts = w.stores.counts()
        assertEquals(1, counts.consumerPoisoned)
        assertEquals(1, counts.fetchedUnconsumed)
        // Never dropped: offered again after the backoff, alone.
        w.clock.advance(HOUR)
        assertEquals(listOf(poison), w.stores.inbox.claim(Consumer.DM, 32).map { it.hash })
    }

    @Test
    fun claimBackoffGrowsToADayAndAFarFutureValueIsDue(): Unit = SyncWorld().use { w ->
        assertEquals(listOf(1L, 2L, 4L, 8L, 16L, 24L, 24L).map { it * HOUR }, (3..9).map { InboxStore.offerBackoffSeconds(it) })
        val (ns, relays) = w.inboxSet()
        w.page(relays[0], ns, listOf(w.hashOf(1)))
        w.fetch(relays[0], ns, 1)
        w.raw("UPDATE inbox_blob SET offers = 5, offer_after_minute = ?", Time.floorMinute(w.now) + 24 * HOUR)
        assertTrue(w.stores.inbox.claim(Consumer.DM, 1).isEmpty())
        // After a backward clock jump the stored backoff lies more than 24 h ahead: treated as due.
        w.clock.advance(-2 * MINUTE)
        assertEquals(1, w.stores.inbox.claim(Consumer.DM, 1).size)
        assertEquals(Time.floorMinute(w.now) + 8 * HOUR, w.long("SELECT offer_after_minute FROM inbox_blob"))
    }

    @Test
    fun markConsumedIsTrueExactlyOnceAndLeavesABareTombstone(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.inboxSet()
        w.page(relays[0], ns, listOf(w.hashOf(1)))
        w.fetch(relays[0], ns, 1)
        w.stores.inbox.claim(Consumer.DM, 1)
        assertTrue(w.tx { w.stores.inbox.markConsumed(it, ns, w.hashOf(1)) })
        assertFalse(w.tx { w.stores.inbox.markConsumed(it, ns, w.hashOf(1)) })
        assertEquals("done", w.inboxState(ns, w.hashOf(1)))
        assertEquals(
            1L,
            w.long(
                "SELECT ciphertext IS NULL AND fetch_seq IS NULL AND fetch_attempts = 0 AND next_fetch_minute = 0 " +
                    "AND offers = 0 AND offer_after_minute = 0 FROM inbox_blob",
            ),
        )
        assertFalse(w.tx { w.stores.inbox.markConsumed(it, ns, w.hashOf(9)) })
        // A consume rolled back with the consumer's transaction is offered again.
        w.page(relays[0], ns, listOf(w.hashOf(2)))
        w.fetch(relays[0], ns, 2)
        assertThrows(IllegalStateException::class.java) {
            w.tx { tx ->
                assertTrue(w.stores.inbox.markConsumed(tx, ns, w.hashOf(2)))
                throw IllegalStateException("consumer failed")
            }
        }
        assertEquals(listOf(w.hashOf(2)), w.stores.inbox.claim(Consumer.DM, 5).map { it.hash })
    }

    @Test
    fun deferResetsOffersWithinSevenDays(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.inboxSet()
        w.page(relays[0], ns, listOf(w.hashOf(1)))
        w.fetch(relays[0], ns, 1)
        w.stores.inbox.claim(Consumer.DM, 1)
        w.stores.inbox.claim(Consumer.DM, 1)
        w.clock.advance(17)
        assertTrue(w.tx { w.stores.inbox.defer(it, ns, w.hashOf(1), 7 * 86_400) })
        assertEquals(0L, w.long("SELECT offers FROM inbox_blob"))
        assertEquals(Time.floorMinute(w.now) + 7 * DAY, w.long("SELECT offer_after_minute FROM inbox_blob"))
        assertTrue(w.stores.inbox.claim(Consumer.DM, 1).isEmpty())
        w.clock.advance(7 * DAY)
        assertEquals(1, w.stores.inbox.claim(Consumer.DM, 1).size)
        assertThrows(IllegalArgumentException::class.java) { w.tx { w.stores.inbox.defer(it, ns, w.hashOf(1), 7 * 86_400 + 1) } }
        assertThrows(IllegalArgumentException::class.java) { w.tx { w.stores.inbox.defer(it, ns, w.hashOf(1), 0) } }
        assertFalse(w.tx { w.stores.inbox.defer(it, ns, w.hashOf(5), 60) })
        // A deferral that lies more than 7 days ahead (backward clock jump) is due.
        w.tx { w.stores.inbox.defer(it, ns, w.hashOf(1), 7 * 86_400) }
        w.clock.advance(-2 * MINUTE)
        assertEquals(1, w.stores.inbox.claim(Consumer.DM, 1).size)
    }
}
