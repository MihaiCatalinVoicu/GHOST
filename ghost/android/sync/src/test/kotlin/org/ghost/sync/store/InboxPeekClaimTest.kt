package org.ghost.sync.store

import org.ghost.sync.api.BlobHash
import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.OutboundBlob
import org.ghost.sync.api.RelayId
import org.ghost.sync.api.TtlBucket
import org.ghost.sync.store.SyncWorld.Companion.DAY
import org.ghost.sync.store.SyncWorld.Companion.HOUR
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The Phase 9 inbox additions (design §13.3 items 2 and 10): the relay expiry and offer count a
 * claimed blob carries, `peek` as a read that changes nothing, `claimOne` for the row the consumer
 * ordered first, and `forgetConsumed` for a bundle namespace.
 */
class InboxPeekClaimTest {

    private fun SyncWorld.inboxSet(consumer: Consumer = Consumer.DM): Pair<NamespaceId, List<RelayId>> {
        val relays = relays(1, 2)
        val ns = namespace(1, relays, consumer = consumer)
        relays.forEach { capability(it, ns, CapabilityKind.READ) }
        return Pair(ns, relays)
    }

    private fun SyncWorld.listAndFetch(relay: RelayId, ns: NamespaceId, seed: Int, expiry: Long) {
        val h = hashOf(seed)
        tx { inbox.commitPage(it, relay, ns, listOf(h), ByteArray(0), ByteArray(0), now) }
        assertTrue(tx { inbox.leaseFetch(it, ns, h, now, 60) })
        assertTrue(tx { inbox.recordFetched(it, ns, h, TestBytes.ciphertext(seed), expiry) })
    }

    private fun SyncWorld.relayExpiry(ns: NamespaceId, hash: BlobHash): Long? =
        long("SELECT relay_expiry_hour FROM inbox_blob WHERE namespace_id = ? AND blob_hash = ?", ns, hash)

    @Test
    fun aClaimCarriesTheFlooredRelayExpiryAndTheCommittedOfferCount(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.inboxSet()
        val expiry = w.now + HOUR + 137
        w.listAndFetch(relays[0], ns, 1, expiry)
        assertEquals(Time.floorHour(expiry), w.relayExpiry(ns, w.hashOf(1)))

        val first = w.stores.inbox.claim(Consumer.DM, 4).single()
        assertEquals(Time.floorHour(expiry), first.relayExpiryHour)
        assertEquals("the counter commits before the hand-off", 1, first.offers)
        assertEquals(2, w.stores.inbox.claim(Consumer.DM, 4).single().offers)

        // Consuming drops the relay expiry in the same statement as the ciphertext (§13.3 item 2).
        assertTrue(w.tx { w.stores.inbox.markConsumed(it, ns, w.hashOf(1)) })
        assertNull(w.relayExpiry(ns, w.hashOf(1)))
    }

    @Test
    fun peekChangesNothingAndClaimOneTakesTheRowTheConsumerChose(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.inboxSet()
        for (seed in 1..3) w.listAndFetch(relays[0], ns, seed, w.now + 7 * DAY)

        val peeked = w.stores.inbox.peek(Consumer.DM, 8)
        assertEquals(3, peeked.size)
        assertEquals((1..3).map { w.hashOf(it) }, peeked.map { it.hash })
        assertArrayEquals(TestBytes.ciphertext(2), peeked[1].ciphertext)
        assertEquals(Time.floorHour(w.now + 7 * DAY), peeked[0].relayExpiryHour)
        assertEquals("peek commits no offer", 0L, w.long("SELECT sum(offers) FROM inbox_blob"))
        assertEquals("peek is idempotent", 3, w.stores.inbox.peek(Consumer.DM, 8).size)
        assertEquals("peek respects its limit", 2, w.stores.inbox.peek(Consumer.DM, 2).size)
        assertThrows(IllegalArgumentException::class.java) { w.stores.inbox.peek(Consumer.DM, 0) }

        // The consumer orders the batch itself and claims the row it wants first.
        val chosen = peeked[2]
        val claimed = w.stores.inbox.claimOne(Consumer.DM, chosen.namespace, chosen.hash)
        assertNotNull(claimed)
        assertEquals(chosen.hash, claimed!!.hash)
        assertEquals(1, claimed.offers)
        assertArrayEquals(TestBytes.ciphertext(3), claimed.ciphertext)
        assertEquals(1L, w.long("SELECT sum(offers) FROM inbox_blob"))
        // The other rows are untouched and still peekable.
        assertEquals(3, w.stores.inbox.peek(Consumer.DM, 8).size)

        // Consumed, in another consumer's namespace, or unknown: all null.
        assertTrue(w.tx { w.stores.inbox.markConsumed(it, ns, chosen.hash) })
        assertNull(w.stores.inbox.claimOne(Consumer.DM, ns, chosen.hash))
        assertNull(w.stores.inbox.claimOne(Consumer.CHANNEL, ns, w.hashOf(1)))
        assertNull(w.stores.inbox.claimOne(Consumer.DM, ns, w.hashOf(9)))
    }

    /**
     * A fetched row always carries the relay expiry its consumer bounds the message's life by
     * (design §10.3): migration 4 gives one to every row fetched before schema v4, and a row whose
     * expiry is unknown is never handed out — 0 is a legal expiry hour, so no sentinel could tell
     * the two apart.
     */
    @Test
    fun aFetchedRowWithNoRelayExpiryIsNeverOffered(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.inboxSet()
        for (seed in 1..2) w.listAndFetch(relays[0], ns, seed, w.now + 7 * DAY)
        assertEquals(
            1,
            w.sql.execUpdate(
                "UPDATE inbox_blob SET relay_expiry_hour = NULL WHERE namespace_id = ? AND blob_hash = ?",
                listOf(ns.toByteArray(), w.hashOf(1).toByteArray()),
            ),
        )
        assertNull(w.relayExpiry(ns, w.hashOf(1)))
        assertEquals(listOf(w.hashOf(2)), w.stores.inbox.peek(Consumer.DM, 8).map { it.hash })
        assertEquals(listOf(w.hashOf(2)), w.stores.inbox.claim(Consumer.DM, 8).map { it.hash })
        assertNull(w.stores.inbox.claimOne(Consumer.DM, ns, w.hashOf(1)))
        assertEquals("the row was not offered", 0L, w.long("SELECT offers FROM inbox_blob WHERE blob_hash = ?", w.hashOf(1)))
    }

    @Test
    fun peekAndClaimOneFollowTheOfferBackoff(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.inboxSet()
        w.listAndFetch(relays[0], ns, 1, w.now + 7 * DAY)
        val hash = w.hashOf(1)
        // Three offers back the row off for an hour: peek stops showing it and claimOne refuses.
        repeat(3) { assertNotNull(w.stores.inbox.claimOne(Consumer.DM, ns, hash)) }
        assertEquals(3L, w.long("SELECT offers FROM inbox_blob"))
        assertTrue(w.stores.inbox.peek(Consumer.DM, 8).isEmpty())
        assertNull(w.stores.inbox.claimOne(Consumer.DM, ns, hash))
        w.clock.advance(HOUR)
        assertEquals(1, w.stores.inbox.peek(Consumer.DM, 8).size)
        assertNotNull(w.stores.inbox.claimOne(Consumer.DM, ns, hash))
        // A deferral hides the row from both calls until it is due again.
        assertTrue(w.tx { w.stores.inbox.defer(it, ns, hash, 600) })
        assertTrue(w.stores.inbox.peek(Consumer.DM, 8).isEmpty())
        assertNull(w.stores.inbox.claimOne(Consumer.DM, ns, hash))
        w.clock.advance(600)
        assertEquals(1, w.stores.inbox.peek(Consumer.DM, 8).size)
    }

    @Test
    fun forgetConsumedClearsABundleNamespaceAndRefusesEveryOther(): Unit = SyncWorld().use { w ->
        val (bundle, relays) = w.inboxSet(Consumer.PREKEYS)
        for (seed in 1..2) w.listAndFetch(relays[0], bundle, seed, w.now + 7 * DAY)
        for (seed in 1..2) {
            assertNotNull(w.stores.inbox.claimOne(Consumer.PREKEYS, bundle, w.hashOf(seed)))
            assertTrue(w.tx { w.stores.inbox.markConsumed(it, bundle, w.hashOf(seed)) })
        }
        assertEquals(2L, w.count("inbox_blob", "state = 'done'"))

        // A re-established contact must see the bundles it consumed earlier (§21.7 point 2).
        assertEquals(2, w.tx { w.stores.inbox.forgetConsumed(it, bundle) })
        assertEquals(0L, w.count("inbox_blob"))
        w.listAndFetch(relays[0], bundle, 1, w.now + 7 * DAY)
        assertEquals(1, w.stores.inbox.peek(Consumer.PREKEYS, 8).size)

        // Own blobs keep their tombstone: nothing of ours is ever fetched back.
        w.capability(relays[0], bundle)
        w.capability(relays[1], bundle)
        w.tx { tx -> w.stores.outbox.enqueue(tx, OutboundBlob(TestBytes.op(7), bundle, TestBytes.ciphertext(7), TtlBucket.DAYS_7)) }
        assertEquals(1L, w.count("inbox_blob", "state = 'done'"))
        assertEquals(0, w.tx { w.stores.inbox.forgetConsumed(it, bundle) })
        assertEquals(1L, w.count("inbox_blob", "state = 'done'"))

        // Every other consumer keeps its exactly-once tombstones.
        val dm = w.namespace(2, relays, consumer = Consumer.DM)
        assertThrows(IllegalStateException::class.java) { w.tx { w.stores.inbox.forgetConsumed(it, dm) } }
        assertThrows(IllegalStateException::class.java) { w.tx { w.stores.inbox.forgetConsumed(it, TestBytes.namespace(99)) } }
    }
}
