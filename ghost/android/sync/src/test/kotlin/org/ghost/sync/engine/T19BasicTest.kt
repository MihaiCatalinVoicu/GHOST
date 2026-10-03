package org.ghost.sync.engine

import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.engine.EngineWorld.Companion.MINUTE
import org.ghost.sync.engine.EngineWorld.Companion.SECOND
import org.ghost.sync.store.Time
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest

/**
 * T19, basic check (design §7.2, §8.6, §11.2 #12, #13): with the keys, the read pairs, the capability
 * states and the list-latency trace fixed, the read schedule is identical with and without activity.
 * Run (a) is idle; run (b) has enqueues, inbound blobs, consumer transactions between lane items,
 * non-zero work-lane latency and 100 % work-lane failures. STANDARD: every event's first list request
 * (start time, pair, limit) is identical; HIGH: the whole list sequence is. The exit-gate suite (step
 * S6) repeats this with seeded worlds and the model relay.
 *
 * Work-lane failures use relay-level categories only: a transport-level failure (the transport is
 * gone) and a refused capability change the premise (transport and capability state), not activity.
 */
class T19BasicTest {

    private class Observed(
        val requests: List<Triple<Long, String, Int>>,
        val stores: Int,
        val gets: Int,
        val checks: Int,
        val registrations: Int,
        val continuations: Int,
        /** Start time of every registration call, in order: the work lane's registration schedule. */
        val registrationStarts: List<Long> = emptyList(),
    )

    private val workFailures = listOf("timeout", "transport", "internal", "relay_unavailable", "malformed_response", "not_stored", "rejected", "not_found", "invalid_argument")

    /** A deterministic value in [0, n) from the call's pair and start time (the fixed list-latency trace). */
    private fun keyed(call: TestRelays.Call, n: Int, salt: String): Int {
        val d = MessageDigest.getInstance("SHA-256").digest("$salt|${call.relay}|${call.namespace.toByteArray().contentToString()}|${call.startMillis}".toByteArray())
        return Math.floorMod(((d[0].toInt() and 0xff) shl 8) or (d[1].toInt() and 0xff), n)
    }

    /**
     * [funded] (Phase 10 design §7.5): the write-only namespace is a funder's, so its key registrations
     * are served by a registration capability on the spare relay instead of a write capability, and
     * nothing else differs. The property is that the read schedule is the same either way.
     */
    private fun run(mode: PrivacyMode, activity: Boolean, funded: Boolean = false): Observed = EngineWorld(TrafficPolicy(listLimit = 4)).use { w ->
        w.mode = mode
        val relays = w.relays(1, 2, 3, 4)
        // The capabilities declare the expiry of a redeemed week, in both runs alike: a key
        // registration is due only against a capability whose week is known (Phase 9 §13.3 item 5).
        val week = Time.week(w.clock.epochSeconds())
        val capabilityExpiry = Time.WEEK_ORIGIN + Time.WEEK * (week + 1) + Time.HOUR
        // 8 read pairs over 4 event workers (read via write tokens), plus a write-only namespace.
        val listened: List<NamespaceId> =
            (1..2).map { n -> w.namespace(n, relays).also { ns -> relays.forEach { w.capability(it, ns, expiresAt = capabilityExpiry) } } }
        // A channel namespace in both runs (only a channel can be funded, Phase 10 review of S1a), of source
        // REDEEM so that, unfunded, its registrations are served by a write capability as in Phase 9.
        val writeOnly = w.namespace(3, relays, listen = false, consumer = Consumer.CHANNEL)
            .also { ns -> relays.forEach { w.capability(it, ns, expiresAt = capabilityExpiry) } }
        // A relay in no namespace's set, as the owner keeps one after a slot change (§21.1 point 3):
        // it adds no read pair, and run (b) gives it key registrations of its own.
        val spare = w.relays(5).single()
        if (funded) {
            w.fund(writeOnly)
            w.capability(spare, writeOnly, CapabilityKind.REGISTER, expiresAt = capabilityExpiry)
        } else {
            w.capability(spare, writeOnly, expiresAt = capabilityExpiry)
        }
        val firstList = HashSet<Pair<String, String>>()
        w.net.latency = { call ->
            when (call.kind) {
                TestRelays.Kind.LIST -> {
                    // Fixed trace: 0.5–9.5 s by (pair, start time), plus a rendezvous cost on the pair's first list.
                    val rendezvous = if (firstList.add(Pair(call.relay.toString(), call.namespace.toByteArray().contentToString()))) 3 * SECOND else 0
                    500L + keyed(call, 9_000, "latency") + rendezvous
                }
                else -> 5 * SECOND
            }
        }
        var rotation = 0
        w.net.failBefore = { call ->
            when {
                call.kind == TestRelays.Kind.LIST -> if (keyed(call, 10, "fail") == 0) "timeout" else null
                activity -> workFailures[rotation++ % workFailures.size]
                else -> null
            }
        }
        val (session, driver) = w.session()
        if (activity) {
            // Key registrations are work-lane work too (Phase 9 design §13.3 item 5): the read lane
            // must not see them either.
            for (period in listOf(week, week + 1)) w.registration(spare, writeOnly, period)
            check(w.tx { w.stores.registrationStore.due(it, w.clock.epochSeconds(), 16, null, null) }.size == 2) { "registrations are not due" }
            relays.forEachIndexed { i, r -> listened.forEach { ns -> w.inbound(r, ns, 1_000 * (i + 1) + ns.hashCode() % 7, 7) } }
            var items = 0
            var seed = 1
            driver.beforeItem = {
                items++
                // Enqueues and consumer transactions between lane items, on every kind of namespace.
                if (items % 5 == 0 && seed <= 20) {
                    w.enqueue(seed, if (seed % 3 == 0) writeOnly else listened[seed % 2])
                    session.expedite()
                    seed++
                }
                if (items % 7 == 0) {
                    for (b in w.stores.inbox.claim(Consumer.DM, 4)) w.tx { w.stores.inbox.markConsumed(it, b.namespace, b.hash) }
                    for (consumer in listOf(Consumer.DM, Consumer.CHANNEL)) {
                        for (o in w.stores.outbox.outcomes(consumer, 4)) w.tx { w.stores.outbox.release(it, o.operationId) }
                    }
                }
            }
        }
        driver.runUntil(20 * MINUTE)
        val requests = if (mode == PrivacyMode.HIGH) {
            w.net.callsOf(TestRelays.Kind.LIST).map { Triple(it.startMillis, "${it.relay}|${it.namespace.toByteArray().contentToString()}", it.limit) }
        } else {
            driver.started.map { it.second }.filterIsInstance<ReadItem>().filter { !it.continuation }.map {
                Triple(it.startMillis, "${it.relay}|${it.pair.namespace.toByteArray().contentToString()}", it.limit)
            }
        }
        Observed(
            requests,
            w.net.callsOf(TestRelays.Kind.STORE).size,
            w.net.callsOf(TestRelays.Kind.GET).size,
            w.net.callsOf(TestRelays.Kind.CHECK).size,
            w.net.callsOf(TestRelays.Kind.REGISTER).size,
            driver.started.map { it.second }.filterIsInstance<ReadItem>().count { it.continuation },
            w.net.callsOf(TestRelays.Kind.REGISTER).map { it.startMillis },
        )
    }

    @Test
    fun standardModeFirstPagesAreIdenticalWithAndWithoutActivity() {
        val idle = run(PrivacyMode.STANDARD, activity = false)
        val busy = run(PrivacyMode.STANDARD, activity = true)
        assertTrue(idle.requests.size > 200)
        assertEquals(idle.requests, busy.requests)
        // The busy run really was busy, and every one of its work-lane calls failed.
        assertEquals(0, idle.stores + idle.gets + idle.checks + idle.registrations)
        assertTrue(busy.stores >= 8)
        assertTrue(busy.gets > 0)
        assertTrue("key registrations ran on the work lane", busy.registrations > 0)
        assertTrue("inbound volume made further pages", busy.continuations > 0)
    }

    @Test
    fun highModeListSequencesAreIdenticalWithAndWithoutActivity() {
        val idle = run(PrivacyMode.HIGH, activity = false)
        val busy = run(PrivacyMode.HIGH, activity = true)
        assertTrue(idle.requests.size > 200)
        assertEquals(idle.requests, busy.requests)
        assertEquals(0, busy.continuations)
        assertTrue(busy.stores > 0 && busy.gets > 0)
        assertTrue("key registrations ran at the pair's events", busy.registrations > 0)
    }

    /**
     * Phase 10 design §7.5, §7.8 ("no new request kind, field or timing"): a namespace whose
     * registrations are served by a funder's registration capability reads and registers on exactly the
     * schedule of one served by a write capability — every first list request in STANDARD, the whole
     * list sequence in HIGH, and the start of every registration call.
     */
    @Test
    fun aFundedNamespaceChangesNeitherTheReadScheduleNorTheRegistrationTimes() {
        for (mode in PrivacyMode.entries) {
            val plain = run(mode, activity = true)
            val funded = run(mode, activity = true, funded = true)
            assertTrue(mode.toString(), plain.requests.size > 200)
            assertEquals(mode.toString(), plain.requests, funded.requests)
            assertEquals(mode.toString(), plain.registrationStarts, funded.registrationStarts)
            assertTrue("key registrations ran on the funded namespace too ($mode)", funded.registrations > 0)
            assertEquals(mode.toString(), plain.stores, funded.stores)
            assertEquals(mode.toString(), plain.gets, funded.gets)
            assertEquals(mode.toString(), plain.continuations, funded.continuations)
        }
    }

    @Test
    fun addingOrRemovingAnotherPairLeavesAPairsEventsUnchanged() {
        fun listTimes(extraPairs: Int): List<Long> = EngineWorld().use { w ->
            w.mode = PrivacyMode.HIGH
            val relays = w.relays(1, 2)
            val ns = w.namespace(1, relays)
            relays.forEach { w.capability(it, ns) }
            for (n in 0 until extraPairs) {
                val other = w.namespace(10 + n, listOf(relays[1]))
                w.capability(relays[1], other)
            }
            w.net.latency = { if (it.kind == TestRelays.Kind.LIST) 2 * SECOND else 0 }
            val (_, driver) = w.session()
            driver.runUntil(30 * MINUTE)
            w.net.callsOf(TestRelays.Kind.LIST).filter { it.namespace == ns && it.relay == w.address(relays[0]) }.map { it.startMillis }
        }
        val base = listTimes(0)
        assertTrue(base.size > 40)
        assertEquals(base, listTimes(1))
        assertEquals(base, listTimes(2))
    }
}
