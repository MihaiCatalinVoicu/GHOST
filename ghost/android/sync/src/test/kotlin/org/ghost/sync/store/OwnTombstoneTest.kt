package org.ghost.sync.store

import org.ghost.sync.api.Consumer
import org.ghost.sync.api.SendDelay
import org.ghost.sync.api.TtlBucket
import org.ghost.sync.store.SyncWorld.Companion.DAY
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Own tombstones on a listening 0 → 1 transition (S9 finding #1, IN-2 "the consumer never sees its
 * own blobs"): a namespace that was write-only when its ops were enqueued gets an own `done` row for
 * every op it still has, in the transaction that turns listening on, with the enqueue rule
 * `ceil7(today + TTL + 8)`; later receipts raise it as for any own row.
 */
class OwnTombstoneTest {

    @Test
    fun setListeningWritesAnOwnTombstoneForEveryOpOfTheNamespace(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.standardSet(listen = false)
        w.enqueue(1, ns, TtlBucket.DAYS_7)
        w.enqueue(2, ns, TtlBucket.DAYS_30)
        assertEquals(0L, w.count("inbox_blob"))
        w.clock.advance(2 * DAY)
        w.tx { w.stores.namespaces.setListening(it, ns, true) }
        assertEquals("done", w.inboxState(ns, w.hashOf(1)))
        assertEquals("done", w.inboxState(ns, w.hashOf(2)))
        assertEquals(RetentionPolicy.ownRetainDay(w.now, TtlBucket.DAYS_7.seconds.toLong()), w.retainDay(ns, w.hashOf(1)))
        assertEquals(RetentionPolicy.ownRetainDay(w.now, TtlBucket.DAYS_30.seconds.toLong()), w.retainDay(ns, w.hashOf(2)))

        // A relay listing our own hash adds no listed row and no source: the blob is never fetched back.
        val page = w.tx { w.inbox.commitPage(it, relays[0], ns, listOf(w.hashOf(1), w.hashOf(3)), ByteArray(0), ByteArray(0), w.now) }
        assertEquals(1, page.listedRows)
        assertEquals("done", w.inboxState(ns, w.hashOf(1)))
        assertNull(w.sourceState(ns, w.hashOf(1), relays[0]))

        // A later receipt raises the row, as for an op enqueued while listening.
        val op = TestBytes.op(1)
        w.tx { w.outbox.lease(it, op, relays[1], w.now, 60) }
        w.tx { w.outbox.recordReceipt(it, op, relays[1], w.now + 7 * DAY, w.now) }
        assertEquals(RetentionPolicy.expiryRetainDay(w.now + 7 * DAY), w.retainDay(ns, w.hashOf(1)))

        // Listening off and on again keeps the rows and does not raise them.
        val before = w.retainDay(ns, w.hashOf(2))
        w.tx { w.stores.namespaces.setListening(it, ns, false) }
        w.clock.advance(3 * DAY)
        w.tx { w.stores.namespaces.setListening(it, ns, true) }
        assertEquals("done", w.inboxState(ns, w.hashOf(2)))
        assertEquals(RetentionPolicy.ownRetainDay(w.now, TtlBucket.DAYS_30.seconds.toLong()), w.retainDay(ns, w.hashOf(2)))
        assertEquals(true, w.retainDay(ns, w.hashOf(2))!! >= before!!)
    }

    @Test
    fun registeringAKnownWriteOnlyNamespaceAsListeningWritesTheOwnTombstones(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.standardSet(listen = false)
        w.enqueue(1, ns, TtlBucket.DAY_1)
        w.tx { w.stores.namespaces.register(it, ns, Consumer.DM, relays.toSet(), listen = true, sendDelay = SendDelay.DEFAULT) }
        assertEquals("done", w.inboxState(ns, w.hashOf(1)))
        assertEquals(RetentionPolicy.ownRetainDay(w.now, TtlBucket.DAY_1.seconds.toLong()), w.retainDay(ns, w.hashOf(1)))
        // Re-registering while already listening changes nothing.
        w.clock.advance(14 * DAY)
        val retained = w.retainDay(ns, w.hashOf(1))
        w.tx { w.stores.namespaces.register(it, ns, Consumer.DM, relays.toSet(), listen = true, sendDelay = SendDelay.DEFAULT) }
        assertEquals(retained, w.retainDay(ns, w.hashOf(1)))
        assertEquals(1L, w.count("inbox_blob"))
    }

    @Test
    fun aWriteOnlyNamespaceStillKeepsNoInboxRow(): Unit = SyncWorld().use { w ->
        val (ns, _) = w.standardSet(listen = false)
        w.enqueue(1, ns)
        w.tx { w.stores.namespaces.setListening(it, ns, false) }
        assertEquals(0L, w.count("inbox_blob"))
    }
}
