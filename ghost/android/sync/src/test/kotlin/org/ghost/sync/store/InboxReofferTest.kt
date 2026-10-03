package org.ghost.sync.store

import org.ghost.sync.api.BlobHash
import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.RelayId
import org.ghost.sync.api.SyncChange
import org.ghost.sync.store.SyncWorld.Companion.DAY
import org.ghost.sync.store.SyncWorld.Companion.HOUR
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `Inbox.defer` for a channel's unopenable blobs and `Inbox.reofferDeferred` (Phase 10 design §7.5
 * items 5 and 6, §19.1, §6.3.2): a blob of epoch e + 1 that the member cannot open yet is deferred
 * with a backoff of up to six hours, does not throttle the fetching of what it can open, and is
 * made due **at once** — in its arrival order — when the settle, the join or the switch that makes
 * it openable commits, instead of waiting out the backoff. The call writes the re-offer time of
 * local rows and nothing else.
 */
class InboxReofferTest {

    private fun SyncWorld.channelSet(): Pair<NamespaceId, List<RelayId>> {
        val relays = relays(1, 2)
        val ns = namespace(1, relays, consumer = Consumer.CHANNEL)
        relays.forEach { capability(it, ns, CapabilityKind.READ) }
        return Pair(ns, relays)
    }

    private fun SyncWorld.listAndFetch(relay: RelayId, ns: NamespaceId, seed: Int, expiry: Long = now + 7 * DAY) {
        val h = hashOf(seed)
        tx { inbox.commitPage(it, relay, ns, listOf(h), ByteArray(0), ByteArray(0), now) }
        assertTrue(tx { inbox.leaseFetch(it, ns, h, now, 60) })
        assertTrue(tx { inbox.recordFetched(it, ns, h, TestBytes.ciphertext(seed), expiry) })
    }

    private fun SyncWorld.peekSeeds(consumer: Consumer = Consumer.CHANNEL): List<Int> =
        stores.inbox.peek(consumer, 64).map { blob -> (1..40).first { hashOf(it) == blob.hash } }

    private fun SyncWorld.reoffer(ns: NamespaceId): Int = tx { stores.inbox.reofferDeferred(it, ns) }

    private fun SyncWorld.offerAfter(seed: Int): Long = long("SELECT offer_after_minute FROM inbox_blob WHERE blob_hash = ?", hashOf(seed))!!

    private fun SyncWorld.offers(seed: Int): Long = long("SELECT offers FROM inbox_blob WHERE blob_hash = ?", hashOf(seed))!!

    @Test
    fun aDeferredRowIsMadeDueAtOnceAndKeepsItsPlaceInArrivalOrder(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.channelSet()
        for (seed in 1..4) w.listAndFetch(relays[0], ns, seed)
        // The consumer sets two blobs aside, one for a minute and one for the longest backoff of §6.3.2.
        assertTrue(w.tx { w.stores.inbox.defer(it, ns, w.hashOf(2), 60) })
        assertTrue(w.tx { w.stores.inbox.defer(it, ns, w.hashOf(3), 6 * 3600) })
        assertEquals("a deferred blob is not offered", listOf(1, 4), w.peekSeeds())
        assertEquals(Time.floorMinute(w.now) + 6 * HOUR, w.offerAfter(3))
        w.hints.clear()
        assertEquals(2, w.reoffer(ns))
        assertEquals("the next peek returns them in the order they arrived", listOf(1, 2, 3, 4), w.peekSeeds())
        assertEquals(0L, w.offerAfter(2))
        assertEquals(0L, w.offerAfter(3))
        assertEquals("a deferral reset the counter and the re-offer leaves it", 0L, w.offers(3))
        // A consumer hint follows (a blob became available to claim), exactly one, and none for an empty call.
        assertEquals(listOf<Set<SyncChange>>(setOf(SyncChange.INBOX)), w.hints.toList())
        w.hints.clear()
        assertEquals(0, w.reoffer(ns))
        assertTrue(w.hints.isEmpty())
        // The re-offered row is claimed like any other, with the offer rules of claim.
        val claimed = w.stores.inbox.claimOne(Consumer.CHANNEL, ns, w.hashOf(3))
        assertNotNull(claimed)
        assertEquals(1, claimed!!.offers)
        assertArrayEquals(TestBytes.ciphertext(3), claimed.ciphertext)
    }

    /** A row backed off by the poison guard (offered three times, never consumed nor deferred) is not a deferred row. */
    @Test
    fun aRowOnThePoisonBackoffKeepsItsBackoff(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.channelSet()
        w.listAndFetch(relays[0], ns, 1)
        w.listAndFetch(relays[0], ns, 2)
        repeat(3) { assertNotNull(w.stores.inbox.claimOne(Consumer.CHANNEL, ns, w.hashOf(1))) }
        assertEquals(3L, w.offers(1))
        val backoff = w.offerAfter(1)
        assertEquals(Time.floorMinute(w.now) + HOUR, backoff)
        assertTrue(w.tx { w.stores.inbox.defer(it, ns, w.hashOf(2), 3600) })
        assertEquals("only the deferred row", 1, w.reoffer(ns))
        assertEquals("the poisoned row keeps its backoff and its counter", backoff, w.offerAfter(1))
        assertEquals(3L, w.offers(1))
        assertEquals(listOf(2), w.peekSeeds())
        w.clock.advance(HOUR)
        assertEquals(listOf(1, 2), w.peekSeeds())
        // A row offered twice and then deferred is a deferred row again: the deferral reset its counter.
        repeat(2) { w.stores.inbox.claimOne(Consumer.CHANNEL, ns, w.hashOf(2)) }
        assertEquals(2L, w.offers(2))
        assertTrue(w.tx { w.stores.inbox.defer(it, ns, w.hashOf(2), 3600) })
        assertEquals(0L, w.offers(2))
        assertEquals(1, w.reoffer(ns))
    }

    @Test
    fun onlyTheNamedNamespacesFetchedAndNotYetDueRowsAreTouched(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.channelSet()
        val other = w.namespace(2, relays, consumer = Consumer.CHANNEL)
        relays.forEach { w.capability(it, other, CapabilityKind.READ) }
        w.listAndFetch(relays[0], ns, 1)
        w.listAndFetch(relays[0], other, 2)
        w.listAndFetch(relays[0], ns, 3)
        w.listAndFetch(relays[0], ns, 4)
        assertTrue(w.tx { w.stores.inbox.defer(it, ns, w.hashOf(1), 600) })
        assertTrue(w.tx { w.stores.inbox.defer(it, other, w.hashOf(2), 600) })
        // A deferral that has run out is a due row, not a deferred one: it is left as it is.
        assertTrue(w.tx { w.stores.inbox.defer(it, ns, w.hashOf(3), 60) })
        val lapsed = w.offerAfter(3)
        w.clock.advance(2 * 60)
        // A row that is not fetched is no concern of the call, whatever its columns say.
        w.tx { w.inbox.commitPage(it, relays[1], ns, listOf(w.hashOf(5)), ByteArray(0), ByteArray(0), w.now) }
        w.raw("UPDATE inbox_blob SET offer_after_minute = ? WHERE blob_hash = ?", Time.floorMinute(w.now) + HOUR, w.hashOf(5))
        assertEquals(1, w.reoffer(ns))
        assertEquals(0L, w.offerAfter(1))
        assertEquals("another namespace's deferred row stays deferred", Time.floorMinute(w.now - 2 * 60) + 600, w.offerAfter(2))
        assertEquals("a lapsed deferral is untouched", lapsed, w.offerAfter(3))
        assertEquals("a listed row is untouched", Time.floorMinute(w.now) + HOUR, w.offerAfter(5))
        assertEquals("listed", w.inboxState(ns, w.hashOf(5)))
        assertEquals(1, w.reoffer(other))
        assertEquals(0L, w.offerAfter(2))
        // Nothing but the re-offer time moved: the rows are still fetched, with their ciphertext, hand-off number and retention.
        for (seed in listOf(1, 2, 3, 4)) assertEquals("fetched", w.string("SELECT state FROM inbox_blob WHERE blob_hash = ?", w.hashOf(seed)))
        assertEquals(4L, w.count("inbox_blob", "state = 'fetched' AND ciphertext IS NOT NULL AND fetch_seq IS NOT NULL"))
    }

    @Test
    fun aDeferralThatLiesFarAheadAfterABackwardClockJumpIsDueAndLeftAlone(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.channelSet()
        w.listAndFetch(relays[0], ns, 1)
        assertTrue(w.tx { w.stores.inbox.defer(it, ns, w.hashOf(1), 7 * 86_400) })
        w.clock.advance(-2 * 60)
        assertEquals("treated as due by the clamp already", listOf(1), w.peekSeeds())
        // It is offered once on the strength of the clamp, so the row now carries a counter of 1 beside a
        // re-offer time that still lies ahead: the one state in which `offers` and a future time meet.
        assertNotNull(w.stores.inbox.claimOne(Consumer.CHANNEL, ns, w.hashOf(1)))
        assertEquals(1L, w.offers(1))
        // The call still resets the time (it lies ahead of now): harmless, the row was due, and now it is
        // plainly due. It leaves the counter alone (Phase 10 review of S1a, mutant R-F4: a reset of the
        // counter would let a row that fails be offered again from the start).
        assertEquals(1, w.reoffer(ns))
        assertEquals(0L, w.offerAfter(1))
        assertEquals("the offer counter is not the call's to reset", 1L, w.offers(1))
        assertEquals(listOf(1), w.peekSeeds())
    }

    /**
     * Design §7.5 item 5 for a channel: a deferred row does not count against `FETCHED_CAP`, so a
     * member that cannot open the blobs of epoch e + 1 yet keeps fetching the rest; once the settle
     * re-offers them they count again, and the fetch pauses at the cap as it always does.
     */
    @Test
    fun aDeferredChannelBlobDoesNotCountAgainstTheFetchedCapUntilItIsReoffered(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.channelSet()
        val cap = StoreLimits.FETCHED_CAP
        val hashes = (0 until cap).map { BlobHash(TestBytes.of(32, 50_000 + it)) }
        w.tx { w.inbox.commitPage(it, relays[0], ns, hashes.take(128), ByteArray(0), ByteArray(0), w.now) }
        w.tx { w.inbox.commitPage(it, relays[0], ns, hashes.drop(128), ByteArray(0), ByteArray(0), w.now) }
        w.tx { w.inbox.commitPage(it, relays[0], ns, listOf(w.hashOf(1)), ByteArray(0), ByteArray(0), w.now) }
        // Mark all cap rows fetched directly (bytes need not match here: the store checks only on its own path).
        w.raw(
            "UPDATE inbox_blob SET state = 'fetched', ciphertext = zeroblob(1024), fetch_seq = rowid_seq, retain_until_day = 7, relay_expiry_hour = ? " +
                "FROM (SELECT blob_hash AS h, row_number() OVER (ORDER BY blob_hash) AS rowid_seq FROM inbox_blob WHERE blob_hash <> ?) " +
                "WHERE inbox_blob.blob_hash = h",
            Time.floorHour(w.now + 7 * DAY), w.hashOf(1),
        )
        assertEquals(cap, w.tx { w.inbox.fetchedLoad(it, ns, w.now) })
        assertTrue("at the cap nothing more is fetched", w.tx { w.inbox.dueFetches(it, relays[0], ns, w.now, 8) }.isEmpty())
        // The consumer cannot open three blobs yet and defers them (60 s, an hour, the longest backoff).
        for ((i, seconds) in listOf(60, 3600, 6 * 3600).withIndex()) {
            assertTrue(w.tx { w.stores.inbox.defer(it, ns, hashes[i], seconds) })
        }
        assertEquals(cap - 3, w.tx { w.inbox.fetchedLoad(it, ns, w.now) })
        assertEquals("the room the deferred blobs left is used", listOf(w.hashOf(1)), w.tx { w.inbox.dueFetches(it, relays[0], ns, w.now, 8) })
        // The settle makes them openable and re-offers them: they count again, and the fetch waits.
        assertEquals(3, w.reoffer(ns))
        assertEquals(cap, w.tx { w.inbox.fetchedLoad(it, ns, w.now) })
        assertTrue(w.tx { w.inbox.dueFetches(it, relays[0], ns, w.now, 8) }.isEmpty())
        assertNull("the listed row was never fetched", w.string("SELECT ciphertext FROM inbox_blob WHERE blob_hash = ? AND state = 'listed'", w.hashOf(1)))
    }

    @Test
    fun theCallNeedsAnActiveTransaction(): Unit = SyncWorld().use { w ->
        val (ns, _) = w.channelSet()
        var leaked: org.ghost.sync.api.SyncTransaction? = null
        w.tx { leaked = it }
        org.junit.Assert.assertThrows(IllegalStateException::class.java) { w.stores.inbox.reofferDeferred(checkNotNull(leaked), ns) }
    }
}
