package org.ghost.sync.engine

import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.CapabilitySource
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.KeyKind
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.engine.EngineWorld.Companion.MINUTE
import org.ghost.sync.store.Time
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The `:sync` half of T40 for the Phase 10 additions (design §7.5, §7.7, §7.8: "anything else, because a
 * blob arrived: never"; "no new request kind, field or timing"). Marking a namespace funded or not and
 * making the consumer's deferred blobs due again are local acts. A session that is poked with them at
 * every few lane items makes **exactly the relay calls of the session that is not** — same kinds, same
 * relays, same namespaces, same start times, same limits, cursors, hashes, capabilities and
 * ciphertexts — in STANDARD and in HIGH mode, with stores in flight, a registration of a funded
 * namespace due and blobs arriving.
 *
 * The consumer's own transactions (claim, defer, consume) run alike in both worlds and are not part
 * of the difference, and the funded namespace stays funded in both (its flag decides which capability
 * serves its registrations, which is a change of behaviour by design and tested where it is made):
 * what differs is only the poking — a second namespace's flag set and cleared, the funded one's set
 * again, and `reofferDeferred` called on the channel.
 */
class ChannelSyncNoTrafficTest {

    /** Every relay call, in order, as text: nothing a relay could see is left out. */
    private fun log(w: EngineWorld): List<String> = w.net.calls.mapIndexed { i, c ->
        "$i|${c.kind}|${c.relay}|${c.namespace.toByteArray().contentHashCode()}|${c.startMillis}|${c.limit}|" +
            "${c.cursor.contentHashCode()}|${c.hashes.map { it.toByteArray().contentHashCode() }}|${c.capability.contentHashCode()}|" +
            "${c.ciphertext?.contentHashCode()}|${c.deadlineMillis}"
    }

    private fun run(mode: PrivacyMode, poke: Boolean): Pair<List<String>, Int> = EngineWorld().use { w ->
        w.mode = mode
        val relays = w.relays(1, 2, 3)
        val ns = w.namespace(1, relays, consumer = Consumer.CHANNEL, capabilitySource = CapabilitySource.LOCAL)
        // Another channel the run never writes or reads (write-only, no capability), whose flag is poked.
        val other = w.namespace(9, relays.take(2), listen = false, consumer = Consumer.CHANNEL, capabilitySource = CapabilitySource.LOCAL)
        val week = Time.week(w.clock.epochSeconds())
        val expiry = Time.WEEK_ORIGIN + Time.WEEK * (week + 1) + Time.HOUR
        w.fund(ns)
        relays.forEach {
            w.capability(it, ns, CapabilityKind.READ, seed = 1, expiresAt = expiry)
            w.capability(it, ns, CapabilityKind.WRITE, seed = 1, expiresAt = expiry)
            w.capability(it, ns, CapabilityKind.REGISTER, seed = 2, expiresAt = expiry)
        }
        // A funder with registrations pending on every relay, posts to store and blobs to fetch.
        for (relay in relays) for (period in listOf(week, week + 1)) w.registration(relay, ns, period, KeyKind.DEPOSIT)
        for (seed in 1..3) w.enqueue(seed, ns)
        for ((i, relay) in relays.withIndex()) w.inbound(relay, ns, 100 + 10 * i, 6)
        val (session, driver) = w.session()
        var items = 0
        var reoffered = 0
        driver.beforeItem = {
            items++
            // The consumer, alike in both worlds: set aside every other blob it is offered and consume the rest.
            if (items % 6 == 0) {
                for (blob in w.stores.inbox.claim(Consumer.CHANNEL, 4)) {
                    w.tx {
                        if (blob.hash.toByteArray()[0].toInt() % 2 == 0) w.stores.inbox.defer(it, blob.namespace, blob.hash, 6 * 3600)
                        else w.stores.inbox.markConsumed(it, blob.namespace, blob.hash)
                    }
                }
            }
            if (poke) {
                if (items % 5 == 0) reoffered += w.tx { w.stores.inbox.reofferDeferred(it, ns) }
                if (items % 7 == 0) w.fund(other, funded = (items / 7) % 2 == 1)
                if (items % 9 == 0) w.fund(ns, funded = true)
            }
        }
        driver.runUntil(20 * MINUTE)
        check(session.online)
        Pair(log(w), reoffered)
    }

    @Test
    fun pokingWithFundingAndReofferAddsNoRelayCallInStandardMode() {
        val quiet = run(PrivacyMode.STANDARD, poke = false)
        val poked = run(PrivacyMode.STANDARD, poke = true)
        assertTrue("the world must make calls of every kind", quiet.first.size > 100)
        assertEquals(quiet.first, poked.first)
        assertTrue("some deferred blob was made due again", poked.second > 0)
    }

    @Test
    fun pokingWithFundingAndReofferAddsNoRelayCallInHighMode() {
        val quiet = run(PrivacyMode.HIGH, poke = false)
        val poked = run(PrivacyMode.HIGH, poke = true)
        assertTrue(quiet.first.size > 50)
        assertEquals(quiet.first, poked.first)
        assertTrue(poked.second > 0)
    }

    @Test
    fun theRunsContainEveryKindOfCallThePokingCouldHaveMultiplied() {
        for (mode in PrivacyMode.entries) {
            val (calls, _) = run(mode, poke = true)
            for (kind in TestRelays.Kind.entries) {
                assertTrue("no $kind call in the $mode run", calls.any { it.split("|")[1] == kind.toString() })
            }
        }
    }
}
