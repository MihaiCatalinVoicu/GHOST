package org.ghost.sync.store

import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.RelayId
import org.ghost.sync.api.TtlBucket
import org.ghost.sync.store.SyncWorld.Companion.DAY
import org.ghost.sync.store.SyncWorld.Companion.HOUR
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Retention (design §2.3, §11.2 #6–#8) and garbage collection (§11.2 #19). */
class GcRetentionTest {

    private fun SyncWorld.gcPass(): GcReport {
        val report = tx { gc.pass(it, now) }
        gc.checkpoint(sql)
        return report
    }

    private fun SyncWorld.inboxSet(): Pair<NamespaceId, List<RelayId>> {
        val relays = relays(1, 2)
        val ns = namespace(1, relays)
        relays.forEach { capability(it, ns) }
        return Pair(ns, relays)
    }

    @Test
    fun ceil7RoundsUpToAWeekBoundary() {
        assertEquals(0L, RetentionPolicy.ceil7(0))
        assertEquals(7L, RetentionPolicy.ceil7(1))
        assertEquals(7L, RetentionPolicy.ceil7(7))
        assertEquals(14L, RetentionPolicy.ceil7(8))
        assertEquals(RetentionPolicy.ceil7(20_833 + 111), RetentionPolicy.listedRetainDay(20_833 * DAY + 5))
        assertEquals(RetentionPolicy.ceil7(20_833 + 30 + 8), RetentionPolicy.ownRetainDay(20_833 * DAY + 5, 30 * DAY))
        assertEquals(RetentionPolicy.ceil7(20_900 + 24), RetentionPolicy.expiryRetainDay(20_900 * DAY + 86_399))
    }

    @Test
    fun everyRetentionDayWrittenIsAWeekBoundary(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.inboxSet()
        w.clock.advance(3 * DAY + 5 * HOUR)
        w.enqueue(1, ns, TtlBucket.DAY_1)
        w.tx { w.inbox.commitPage(it, relays[0], ns, listOf(w.hashOf(2), w.hashOf(3)), ByteArray(0), ByteArray(0), w.now) }
        w.tx { w.inbox.leaseFetch(it, ns, w.hashOf(2), w.now, 0) }
        w.tx { w.inbox.recordFetched(it, ns, w.hashOf(2), TestBytes.ciphertext(2), w.now + 3 * DAY + 17) }
        val op = TestBytes.op(1)
        w.tx { w.outbox.lease(it, op, relays[0], w.now, 60) }
        w.tx { w.outbox.recordReceipt(it, op, relays[0], w.now + DAY + 3 * HOUR, w.now) }
        var rows = 0
        w.sql.query("SELECT retain_until_day FROM inbox_blob") {
            assertEquals(0L, it.long(0) % 7)
            rows++
        }
        assertEquals(3, rows)
    }

    @Test
    fun everyReceiptRaisesTheOwnTombstonePastTheRelayExpiry(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.inboxSet()
        val op = w.enqueue(1, ns, TtlBucket.DAY_1)
        val h = w.hashOf(1)
        val atEnqueue = RetentionPolicy.ceil7(Time.day(w.now) + 1 + 8)
        assertEquals(atEnqueue, w.retainDay(ns, h))
        // A repair store five days later extends the membership: the tombstone follows the latest receipt.
        w.tx { w.outbox.lease(it, op, relays[0], w.now, 60) }
        w.tx { w.outbox.recordReceipt(it, op, relays[0], w.now + DAY, w.now) }
        w.clock.advance(5 * DAY)
        w.tx { w.outbox.recordAbsentAfterAck(it, op, relays[0], w.now) }
        w.tx { w.outbox.lease(it, op, relays[0], w.now, 60) }
        val lateExpiry = w.now + DAY + HOUR
        w.tx { w.outbox.recordReceipt(it, op, relays[0], lateExpiry, w.now) }
        assertEquals(RetentionPolicy.expiryRetainDay(lateExpiry), w.retainDay(ns, h))
        assertTrue(w.retainDay(ns, h)!! > atEnqueue)
        assertTrue(w.retainDay(ns, h)!! * DAY >= lateExpiry + RetentionPolicy.TAIL_DAYS * DAY - DAY)
    }

    @Test
    fun ownTombstonesAreKeptWhileTheOpExistsAndSetAtItsDeletion(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.inboxSet()
        val op = w.enqueue(1, ns, TtlBucket.DAY_1)
        val h = w.hashOf(1)
        relays.forEach { r -> w.tx { w.outbox.failDelivery(it, op, r, w.now) } }
        assertEquals("failed", w.outcome(op))
        // Far past the enqueue-time retention, the unreleased op still pins its tombstone.
        w.clock.advance(60 * DAY)
        assertEquals(0, w.gcPass().total)
        assertEquals("done", w.inboxState(ns, h))
        // After release, GC deletes the op and sets the tombstone to today + TTL + 8.
        assertTrue(w.tx { w.stores.outbox.release(it, op) })
        val report = w.gcPass()
        assertEquals(1, report.operations)
        assertEquals(0L, w.count("outbox_op"))
        assertEquals(0L, w.count("outbox_delivery"))
        assertEquals(RetentionPolicy.ownRetainDay(w.now, DAY), w.retainDay(ns, h))
        // Deleted strictly after its day.
        w.clock.now = RetentionPolicy.ownRetainDay(w.now, DAY) * DAY + DAY - 1
        assertEquals(0, w.gcPass().tombstones)
        w.clock.advance(1)
        assertEquals(1, w.gcPass().tombstones)
        assertNull(w.inboxState(ns, h))
    }

    @Test
    fun receivedTombstonesListedRowsAndFetchedRows(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.inboxSet()
        w.tx { w.inbox.commitPage(it, relays[0], ns, listOf(w.hashOf(1), w.hashOf(2), w.hashOf(3)), ByteArray(0), ByteArray(0), w.now) }
        for (seed in listOf(1, 2)) {
            w.tx { w.inbox.leaseFetch(it, ns, w.hashOf(seed), w.now, 0) }
            w.tx { w.inbox.recordFetched(it, ns, w.hashOf(seed), TestBytes.ciphertext(seed), w.now + 7 * DAY) }
        }
        w.stores.inbox.claim(Consumer.DM, 10)
        assertTrue(w.tx { w.stores.inbox.markConsumed(it, ns, w.hashOf(1)) })
        val doneDay = RetentionPolicy.expiryRetainDay(w.now + 7 * DAY)
        val listedDay = RetentionPolicy.listedRetainDay(w.now)
        assertEquals(doneDay, w.retainDay(ns, w.hashOf(1)))
        assertEquals(listedDay, w.retainDay(ns, w.hashOf(3)))
        // Past the received tombstone's day: only the tombstone goes.
        w.clock.now = (doneDay + 1) * DAY
        val first = w.gcPass()
        assertEquals(1, first.tombstones)
        assertEquals(0, first.listedRows)
        assertNull(w.inboxState(ns, w.hashOf(1)))
        // Past the listing retention: the never-fetched row goes; the fetched, unconsumed row is never collected.
        w.clock.now = (listedDay + 1) * DAY
        val second = w.gcPass()
        assertEquals(1, second.listedRows)
        assertNull(w.inboxState(ns, w.hashOf(3)))
        assertEquals("fetched", w.inboxState(ns, w.hashOf(2)))
        assertEquals(1, w.stores.counts().expiredUnconsumed)
        w.clock.advance(1000 * DAY)
        w.gcPass()
        assertEquals("fetched", w.inboxState(ns, w.hashOf(2)))
    }

    @Test
    fun gcDeletesAtMostOneBatchOfInboxRowsPerPass(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.inboxSet()
        val hashes = (0 until 600).map { org.ghost.sync.api.BlobHash(TestBytes.of(32, 70_000 + it)) }
        w.tx { tx -> hashes.chunked(128).forEach { w.inbox.commitPage(tx, relays[0], ns, it, ByteArray(0), ByteArray(0), w.now) } }
        w.clock.now = (RetentionPolicy.listedRetainDay(w.now) + 1) * DAY
        assertEquals(RetentionPolicy.GC_BATCH, w.gcPass().listedRows)
        assertEquals(100, w.gcPass().listedRows)
        assertEquals(0L, w.count("inbox_source"))
    }

    @Test
    fun capabilitiesAndRetiredRelaysAreCollected(): Unit = SyncWorld().use { w ->
        val relays = w.relays(1, 2, 3)
        val ns = w.namespace(1, relays)
        w.capability(relays[0], ns, CapabilityKind.READ, expiresAt = w.now + 2 * HOUR)
        w.capability(relays[1], ns, CapabilityKind.READ)
        w.clock.now = SyncWorld.T0 + 2 * HOUR + DAY - 1
        assertEquals(0, w.gcPass().capabilities)
        w.clock.advance(1)
        assertEquals(1, w.gcPass().capabilities)
        // A retired relay still in a set, or with deliveries, is kept; once unreferenced it goes after 111 days.
        w.tx { w.stores.relayDirectory.retire(it, relays[2]) }
        val retiredDay = Time.day(w.now)
        w.clock.now = (retiredDay + RetentionPolicy.RETIRED_RELAY_DAYS) * DAY
        assertEquals(0, w.gcPass().relays)
        w.tx { w.stores.namespaces.setRelays(it, ns, setOf(relays[0], relays[1])) }
        w.clock.now = (retiredDay + RetentionPolicy.RETIRED_RELAY_DAYS) * DAY - 1
        assertEquals(0, w.gcPass().relays)
        w.clock.advance(1)
        assertEquals(1, w.gcPass().relays)
        assertEquals(2L, w.count("relay_directory"))
    }

    @Test
    fun namespaceRemoveKeepsTombstonesAndReRegisteringReusesThem(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.inboxSet()
        w.capability(relays[0], ns, CapabilityKind.READ)
        w.tx { w.inbox.commitPage(it, relays[0], ns, listOf(w.hashOf(1), w.hashOf(2)), ByteArray(0), ByteArray(8) { 1 }, w.now) }
        w.tx { w.inbox.leaseFetch(it, ns, w.hashOf(1), w.now, 0) }
        w.tx { w.inbox.recordFetched(it, ns, w.hashOf(1), TestBytes.ciphertext(1), w.now + 7 * DAY) }
        val op = w.enqueue(3, ns)
        // Refused while ops or fetched rows exist.
        assertFalse(w.tx { w.stores.namespaces.remove(it, ns) })
        relays.forEach { r -> w.tx { w.outbox.failDelivery(it, op, r, w.now) } }
        w.tx { w.stores.outbox.release(it, op) }
        w.gcPass()
        assertFalse(w.tx { w.stores.namespaces.remove(it, ns) })
        w.stores.inbox.claim(Consumer.DM, 10)
        w.tx { w.stores.inbox.markConsumed(it, ns, w.hashOf(1)) }
        w.hints.clear()
        assertTrue(w.tx { w.stores.namespaces.remove(it, ns) })
        assertEquals(0L, w.long("SELECT listening FROM sync_namespace"))
        assertEquals(0L, w.count("namespace_relay"))
        assertEquals(0L, w.count("relay_cursor"))
        assertEquals(0L, w.count("relay_capability"))
        assertNull(w.inboxState(ns, w.hashOf(2)))
        assertEquals("done", w.inboxState(ns, w.hashOf(1)))
        assertEquals("done", w.inboxState(ns, w.hashOf(3)))
        assertFalse(w.tx { w.stores.namespaces.remove(it, TestBytes.namespace(42)) })
        // Re-registered before GC: the row is reused and a relisting of the consumed hash is absorbed.
        w.tx { w.stores.namespaces.register(it, ns, Consumer.DM, relays.toSet(), listen = true) }
        w.capability(relays[0], ns, CapabilityKind.READ)
        val page = w.tx { w.inbox.commitPage(it, relays[0], ns, listOf(w.hashOf(1)), ByteArray(0), ByteArray(0), w.now) }
        assertEquals(0, page.listedRows)
        assertEquals("done", w.inboxState(ns, w.hashOf(1)))
        // Removed again; after the tombstones' days, GC deletes them and then the namespace row.
        assertTrue(w.tx { w.stores.namespaces.remove(it, ns) })
        w.clock.advance(400 * DAY)
        val report = w.gcPass()
        assertEquals(2, report.tombstones)
        assertEquals(1, report.namespaces)
        assertEquals(0L, w.count("sync_namespace"))
    }

    @Test
    fun removingANamespaceWithoutRowsDeletesItAtOnce(): Unit = SyncWorld().use { w ->
        val relays = w.relays(1, 2)
        val ns = w.namespace(1, relays, listen = false)
        w.capability(relays[0], ns)
        assertTrue(w.tx { w.stores.namespaces.remove(it, ns) })
        assertEquals(0L, w.count("sync_namespace"))
        assertEquals(2L, w.count("relay_directory"))
    }

    @Test
    fun aWriteOnlyNamespaceInUseIsNeverCollected(): Unit = SyncWorld().use { w ->
        val relays = w.relays(1, 2)
        w.namespace(1, relays, listen = false)
        w.clock.advance(500 * DAY)
        assertEquals(0, w.gcPass().namespaces)
        assertEquals(1L, w.count("sync_namespace"))
    }
}
