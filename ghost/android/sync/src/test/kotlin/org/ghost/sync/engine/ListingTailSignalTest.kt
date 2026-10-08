package org.ghost.sync.engine

import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.engine.EngineWorld.Companion.MINUTE
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The listing-pass signal (design §6.3.1 (a), §6.4 CO-4 (ii); finding F-S4-1 of §19.37, built in
 * S5a): `Inbox.listingTails` reports, per relay, when this process last listed a namespace to that
 * relay's tail. Only a page that ended the pass at the tail counts — a dropped page (BACKLOG_CAP)
 * is not a completed pass, and a pass cut short by the page budget is not at the tail.
 */
class ListingTailSignalTest {

    @Test
    fun anEmptyNamespaceIsListedToTheTailOfEveryRelayAtOnce() = EngineWorld().use { w ->
        val relays = w.relays(1, 2)
        val a: NamespaceId = w.namespace(1, relays)
        val b: NamespaceId = w.namespace(2, relays)
        for (ns in listOf(a, b)) relays.forEach { w.capability(it, ns, CapabilityKind.READ) }
        val (_, driver) = w.session()
        driver.runUntil(10 * MINUTE)
        for (ns in listOf(a, b)) {
            val tails = w.stores.inbox.listingTails(ns)
            assertEquals("both relays completed a pass over $ns", relays.toSet(), tails.keys)
            tails.values.forEach { at -> assertTrue("recorded inside the run", at in 1..10 * MINUTE) }
        }
    }

    @Test
    fun aFullPagesPassIsRecordedWhenItsTailPageEndsIt() = EngineWorld(TrafficPolicy(listLimit = 4)).use { w ->
        val relay = w.relays(1).single()
        val ns: NamespaceId = w.namespace(1, listOf(relay))
        w.capability(relay, ns, CapabilityKind.READ)
        w.inbound(relay, ns, 0, 10)
        val (_, driver) = w.session()
        driver.runUntil(10 * MINUTE)
        val tails = w.stores.inbox.listingTails(ns)
        assertEquals(setOf(relay), tails.keys)
        // The tail page is the pass's last list call; the record is its completion, at or after it.
        val last = w.net.callsOf(TestRelays.Kind.LIST).filter { it.relay == w.address(relay) }.maxOf { it.startMillis }
        assertTrue("recorded when the tail page completed, not at the full first page", tails.getValue(relay) >= last)
    }

    @Test
    fun aPassThatNeverReachesTheTailIsNotRecorded() = EngineWorld(
        TrafficPolicy(listLimit = 4, backlogCap = 8),
    ).use { w ->
        val relay = w.relays(1).single()
        val ns: NamespaceId = w.namespace(1, listOf(relay))
        w.capability(relay, ns, CapabilityKind.READ)
        w.inbound(relay, ns, 0, 100)
        // The listed rows never fetch (not_found): they stay listed/unavailable and pin the relay's
        // backlog at its cap, so every page from the second on is dropped — no pass completes.
        w.net.failBefore = { if (it.kind == TestRelays.Kind.GET) "not_found" else null }
        val (_, driver) = w.session()
        driver.runUntil(20 * MINUTE)
        assertTrue(
            "dropped pages ran, none at the tail",
            w.net.callsOf(TestRelays.Kind.LIST).isNotEmpty(),
        )
        assertTrue("no completed pass", w.stores.inbox.listingTails(ns).isEmpty())
    }
}
