package org.ghost.sync.engine

import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.CapabilitySource
import org.ghost.sync.api.Consumer
import org.ghost.sync.engine.EngineWorld.Companion.MINUTE
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `Inbox.held` (Phase 10 design §6.4 CO-3's "held blobs", the input of a commit trial settle):
 * the fetched rows a consumer set aside — deferred by its own choice or backed off by the poison
 * guard — read-only, in hash order, bounded. Due rows and consumed rows are not held; a row
 * `reofferDeferred` made due is not held either.
 */
class InboxHeldTest {

    @Test
    fun heldRowsAreExactlyTheDeferredOnesInHashOrder() = EngineWorld().use { w ->
        val relay = w.relays(1).single()
        val ns = w.namespace(1, listOf(relay), consumer = Consumer.CHANNEL, capabilitySource = CapabilitySource.LOCAL)
        w.capability(relay, ns, CapabilityKind.READ)
        w.inbound(relay, ns, 0, 6)
        val (_, driver) = w.session()
        val deferred = LinkedHashSet<List<Byte>>()
        val consumed = LinkedHashSet<List<Byte>>()
        var toggle = false
        driver.beforeItem = {
            // Claim whatever is due; defer every other blob, consume the rest, until nothing moves.
            for (blob in w.stores.inbox.claim(Consumer.CHANNEL, 4)) {
                toggle = !toggle
                w.tx {
                    if (toggle) {
                        w.stores.inbox.defer(it, blob.namespace, blob.hash, 6 * 3600)
                        deferred += blob.hash.toByteArray().toList()
                    } else {
                        w.stores.inbox.markConsumed(it, blob.namespace, blob.hash)
                        consumed += blob.hash.toByteArray().toList()
                    }
                }
            }
        }
        driver.runUntil(10 * MINUTE)
        assertTrue("some blobs were deferred", deferred.isNotEmpty())
        assertTrue("some blobs were consumed", consumed.isNotEmpty())
        val now = w.clock.epochSeconds()
        val held = w.stores.inbox.held(ns, now, 32)
        assertEquals("exactly the deferred rows, no consumed, no listed", deferred, held.map { it.hash.toByteArray().toList() }.toSet())
        val order = held.map { it.hash.toByteArray().toList() }
        assertEquals("hash order", order.sortedBy { it.joinToString("") { b -> "%02x".format(b) } }, order)
        // The bound is honoured.
        assertEquals(1, w.stores.inbox.held(ns, now, 1).size)
        // A row made due again is not held; it is peeked instead.
        w.tx { w.stores.inbox.reofferDeferred(it, ns) }
        assertTrue(w.stores.inbox.held(ns, now, 32).isEmpty())
        assertEquals(deferred.size, w.stores.inbox.peek(Consumer.CHANNEL, 32).size)
    }
}
