package org.ghost.sync.harness

import org.ghost.network.NetworkException
import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.OperationId
import org.ghost.sync.api.OutboundBlob
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.TtlBucket
import org.ghost.sync.engine.ErrorPolicy
import org.ghost.sync.engine.Session
import org.ghost.sync.engine.SyncEngine
import org.ghost.sync.harness.World.Companion.MINUTE
import org.ghost.sync.harness.World.Companion.SECOND
import org.ghost.sync.port.WakeScheduler
import org.ghost.sync.store.SyncStores
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.security.MessageDigest
import java.util.Base64

/**
 * Pair independence (T19 last clause, design §6.1): with three read pairs of one client on one
 * relay, no two pairs' first list requests share a start time. Mutant M13 (one schedule for all
 * pairs) fails it.
 */
internal object PairIndependence {
    fun check(mutation: Mutation?) {
        val s = object : Scenario("pairs") {
            override fun build(w: World) {
                val a = w.relay("A", 1)
                val b = w.relay("B", 2)
                val c = subject(w, "julia")
                for (i in 1..3) {
                    val ns = c.namespace("n$i", listOf(a, b), listen = true)
                    c.capability(a, ns, CapabilityKind.READ)
                    c.capability(b, ns, CapabilityKind.READ)
                }
                w.foreground(c, 0, 10 * MINUTE)
                w.endMillis = 10 * MINUTE
            }

            override fun finalChecks(w: World) {
                val byPair = w.subject.port.calls.filter { it.kind == CallKind.LIST && it.page == 1 }
                    .groupBy { "${it.relay}|${it.namespace.toByteArray().hex()}" }.mapValues { e -> e.value.map { it.startMillis }.toSet() }
                check(byPair.size == 6) { "expected six read pairs, saw ${byPair.size}" }
                val keys = byPair.keys.toList()
                for (i in keys.indices) for (j in i + 1 until keys.size) {
                    val shared = byPair.getValue(keys[i]) intersect byPair.getValue(keys[j])
                    if (shared.isNotEmpty()) violation("two read pairs share ${shared.size} list start time(s): the pairs share a tick (T19)")
                }
            }
        }
        s.mutation = mutation
        Runner(s, JournalMode.WAL).run(RunSpec())
    }
}

/**
 * The T19 worlds (design §7.2, §8.6, §11.2 #12, #13), shared by [PrivacyHarnessTest] and the T19
 * mutants of `MutantDetectionTest` (M15–M17).
 */
internal object T19Worlds {

    class ListRequest(val start: Long, val pair: String, val limit: Int) {
        override fun equals(other: Any?) = other is ListRequest && other.start == start && other.pair == pair && other.limit == limit
        override fun hashCode() = (start.hashCode() * 31 + pair.hashCode()) * 31 + limit
        override fun toString() = "($start, $pair, $limit)"
    }

    private val workFailures = listOf(
        "timeout", "transport", "internal", "relay_unavailable", "malformed_response", "not_stored", "rejected", "not_found", "invalid_argument",
    )

    private fun keyed(vararg parts: Any): Int {
        val d = MessageDigest.getInstance("SHA-256").digest(parts.joinToString("|").toByteArray())
        return ((d[0].toInt() and 0xff) shl 8) or (d[1].toInt() and 0xff)
    }

    /**
     * Runs the idle and the busy world with [mutation]'s steps (null: the real engine) and reports a
     * T19 violation when STANDARD first list requests, or the whole HIGH list sequence, differ.
     */
    fun compare(mode: PrivacyMode, mutation: Mutation?) {
        val steps = mutation?.steps ?: org.ghost.sync.engine.Steps.DEFAULT
        val (idle, _, w1) = run(mode, busy = false, steps)
        val (busy, _, w2) = run(mode, busy = true, steps)
        try {
            if (idle.size <= 200) violation("T19 world: too few list requests (${idle.size})")
            if (idle != busy) {
                val first = idle.indices.firstOrNull { it >= busy.size || idle[it] != busy[it] }
                violation("T19: list requests differ with activity (${idle.size} idle, ${busy.size} busy, first difference at $first)")
            }
        } finally {
            w1.close()
            w2.close()
        }
    }

    /**
     * One T19 world: 8 read pairs over 4 event workers (4 relays × 2 listening namespaces, read
     * through write tokens) and a write-only namespace; seeded latency with rendezvous setup per pair
     * per transport; a keyed 10 % of lists time out (a fixed trace of pair and start time). The busy
     * run adds 20 enqueues, 50 inbound blobs, a consumer transaction before every lane item and
     * 100 % failures of every work-lane call (relay-level categories only).
     */
    fun run(
        mode: PrivacyMode,
        busy: Boolean,
        steps: org.ghost.sync.engine.Steps = org.ghost.sync.engine.Steps.DEFAULT,
    ): Triple<List<ListRequest>, List<HarnessRelayPort.Call>, World> {
        val w = World("T19", 19, JournalMode.WAL)
        val relays = (1..4).map { w.relay("R$it", it) }
        val c = w.client(ClientSpec("kim", armed = false, mode = mode, steps = steps))
        val listened = (1..2).map { i -> c.namespace("n$i", relays, listen = true).also { ns -> relays.forEach { r -> c.capability(r, ns) } } }
        val writeOnly = c.namespace("w", relays, listen = false).also { ns -> relays.forEach { r -> c.capability(r, ns) } }
        var rotation = 0
        w.relayHook = { _, kind, info ->
            when {
                kind != EventKind.RELAY_BEFORE_SEND -> null
                info.kind == CallKind.LIST -> if (keyed("fail", info.relay, info.namespace, w.clock.millis) % 10 == 0) "timeout" else null
                busy -> workFailures[rotation++ % workFailures.size]
                else -> null
            }
        }
        if (busy) {
            for (i in 1..20) w.at(i * 37 * SECOND, "enqueue $i") { c.enqueue("op$i", if (i % 3 == 0) writeOnly else listened[i % 2]) }
            for (i in 1..50) w.at(i * 13 * SECOND, "inbound $i") { w.otherWrite(relays[i % 4], listened[i % 2], "in$i") }
            w.driver.beforeItem = { client, _ -> if (client === c) client.oracle.step() }
        }
        w.foreground(c, 0, 20 * MINUTE)
        w.driver.runUntil(20 * MINUTE)
        val lists = c.port.calls.filter { it.kind == CallKind.LIST && (mode == PrivacyMode.HIGH || it.page == 1) }
            .map { ListRequest(it.startMillis, "${it.relay}|${it.namespace.toByteArray().hex()}", it.limit) }
        return Triple(lists, c.port.calls.toList(), w)
    }
}

class PrivacyHarnessTest {

    // ------------------------------------------------------------------ T19 exact (design §7.2, §8.6, §11.2 #12, #13)

    private fun t19(mode: PrivacyMode, busy: Boolean) = T19Worlds.run(mode, busy)

    @Test
    fun t19StandardFirstPagesAreIdenticalWithAndWithoutActivity() {
        val (idle, idleCalls, w1) = t19(PrivacyMode.STANDARD, busy = false)
        val (busy, busyCalls, w2) = t19(PrivacyMode.STANDARD, busy = true)
        try {
            assertTrue("too few list requests: ${idle.size}", idle.size > 200)
            assertEquals(idle, busy)
            assertEquals(0, idleCalls.count { it.kind != CallKind.LIST })
            assertTrue("the busy run stored", busyCalls.count { it.kind == CallKind.STORE } >= 8)
            assertTrue("the busy run fetched", busyCalls.count { it.kind == CallKind.GET } > 0)
            assertTrue("inbound volume made further pages", busyCalls.any { it.kind == CallKind.LIST && (it.page ?: 1) > 1 })
        } finally {
            w1.close()
            w2.close()
        }
    }

    @Test
    fun t19HighModeListSequencesAreIdenticalAndStoresFallOnPairEvents() {
        val (idle, _, w1) = t19(PrivacyMode.HIGH, busy = false)
        val (busy, busyCalls, w2) = t19(PrivacyMode.HIGH, busy = true)
        try {
            assertTrue(idle.size > 200)
            assertEquals(idle, busy)
            assertTrue(busyCalls.none { it.kind == CallKind.LIST && it.page != 1 })
            val stores = busyCalls.filter { it.kind == CallKind.STORE || it.kind == CallKind.CHECK }
            assertTrue("the busy run stored", stores.any { it.kind == CallKind.STORE })
            // HIGH mode: no request is caused by a local event; stores and checks run only in a pair's event bundle.
            for (call in stores) assertTrue("a ${call.kind} outside a pair event: ${call.item}", call.item.startsWith("PairWork"))
            // ... and never before the op's not_before (sampled once at enqueue).
            val c = w2.clients.single()
            for (call in busyCalls.filter { it.kind == CallKind.STORE }) {
                var notBefore = Long.MAX_VALUE
                c.jdbc.query("SELECT min(not_before_minute) FROM outbox_op WHERE namespace_id = ?1", listOf(call.namespace.toByteArray())) {
                    if (!it.isNull(0)) notBefore = it.long(0)
                }
                assertTrue("a store before not_before", World.T0 + call.startMillis / 1000 + 60 >= notBefore)
            }
        } finally {
            w1.close()
            w2.close()
        }
    }

    @Test
    fun t19AddingOrRemovingAnotherPairLeavesAPairsEventsUnchanged() {
        fun times(extra: Int): List<Long> = World("T19-pairs", 7, JournalMode.WAL).use { w ->
            val a = w.relay("A", 1)
            val b = w.relay("B", 2)
            val c = w.client(ClientSpec("lee", armed = false, mode = PrivacyMode.HIGH))
            val ns = c.namespace("p", listOf(a, b), listen = true)
            c.capability(a, ns)
            c.capability(b, ns)
            for (n in 0 until extra) c.namespace("x$n", listOf(b), listen = true).also { c.capability(b, it) }
            w.foreground(c, 0, 30 * MINUTE)
            w.driver.runUntil(30 * MINUTE)
            c.port.calls.filter { it.kind == CallKind.LIST && it.relay == "A" && it.namespace == ns }.map { it.startMillis }
        }
        val base = times(0)
        assertTrue(base.size > 40)
        assertEquals(base, times(1))
        assertEquals(base, times(2))
    }

    @Test
    fun t19PairsHaveIndependentPhases() = PairIndependence.check(null)

    @Test
    fun wakeSchedulerIsUnreachableFromEnqueueAndConsume() {
        // Nothing the stores or the engine hold can reach the periodic job: enqueue and consume never wake anything.
        for (type in listOf(SyncStores::class.java, SyncEngine::class.java, Session::class.java)) {
            for (f in type.declaredFields) assertFalse("${type.simpleName}.${f.name}", WakeScheduler::class.java.isAssignableFrom(f.type))
            for (k in type.declaredConstructors) assertFalse(k.parameterTypes.any { WakeScheduler::class.java.isAssignableFrom(it) })
        }
    }

    // ------------------------------------------------------------------ T3 canaries (design §8.6)

    @Test
    fun t3CanariesNeverAppearInMessagesOrPublicStrings() {
        World("T3", 3, JournalMode.WAL).use { w ->
            val relays = (1..3).map { w.relay("R$it", it) }
            val c = w.client(ClientSpec("mia", armed = false))
            val ns = c.namespace("canary-ns", relays, listen = true)
            val tokens = relays.map { c.capability(it, ns) }
            val categories = ErrorPolicy.CATEGORIES.keys.toList() + "no_such_category"
            var n = 0
            w.relayHook = { _, kind, _ -> if (kind == EventKind.RELAY_BEFORE_SEND || kind == EventKind.RELAY_AFTER_APPLY) categories[n++ % categories.size] else null }
            val ops = (1..4).map { c.enqueue("canary-op$it", ns) }
            for (i in 1..6) w.otherWrite(relays[i % 3], ns, "canary-in$i")
            w.foreground(c, 0, 10 * MINUTE)
            val strings = ArrayList<String>()
            w.driver.runUntil(10 * MINUTE)
            w.relayHook = null
            w.jobs(c, 11 * MINUTE, 41 * MINUTE)
            w.driver.runUntil(45 * MINUTE)
            // Public strings after every category was injected at every call.
            strings += c.engine.status().toString()
            strings += c.stores.counts().toString()
            strings += c.stores.capabilities.needed().map { it.toString() }
            strings += Consumer.entries.flatMap { k -> c.stores.outbox.outcomes(k, 100).map { it.toString() } }
            strings += Consumer.entries.flatMap { k -> c.stores.inbox.claim(k, 100).map { it.toString() } }
            strings += ops.map { c.stores.outbox.progress(it.operationId).toString() }
            strings += listOf(ns.toString(), ops[0].operationId.toString(), c.stores.relayDirectory.active().toString(), c.stores.toString())
            // Messages of every exception the public API throws for these canaries.
            val thrown = ArrayList<Throwable>()
            fun capture(block: () -> Unit) {
                try {
                    block()
                } catch (e: Exception) {
                    thrown += e
                }
            }
            capture { c.tx { c.stores.outbox.enqueue(it, OutboundBlob(ops[0].operationId, ns, w.bytes("other bytes"), TtlBucket.DAYS_7)) } }
            capture { c.tx { c.stores.outbox.enqueue(it, OutboundBlob(OperationId(ByteArray(16) { 7 }), ns, ops[1].ciphertext, TtlBucket.DAYS_7)) } }
            capture { c.tx { c.stores.outbox.enqueue(it, OutboundBlob(ops[2].operationId, NamespaceId(ByteArray(32) { 9 }), ops[2].ciphertext, TtlBucket.DAYS_7)) } }
            capture { OutboundBlob(ops[0].operationId, ns, ops[0].ciphertext.copyOf(100), TtlBucket.DAYS_7) }
            capture { c.tx { c.stores.capabilities.put(it, c.id(relays[0]), NamespaceId(ByteArray(32) { 5 }), CapabilityKind.WRITE, tokens[0], null) } }
            capture { c.tx { c.stores.capabilities.put(it, c.id(relays[0]), ns, CapabilityKind.WRITE, ByteArray(600) { 1 }, null) } }
            capture { c.tx { c.stores.inbox.defer(it, ns, ops[0].hash, 0) } }
            capture { NamespaceId(ns.toByteArray().copyOf(31)) }
            capture { throw NetworkException(categories[3]) }
            assertTrue("the API calls threw", thrown.size >= 7)
            for (t in thrown) generateSequence(t) { it.cause }.forEach { strings += "${it.javaClass.name}: ${it.message}" }
            val canaries = ArrayList<ByteArray>()
            canaries += ns.toByteArray()
            canaries += tokens
            ops.forEach { canaries += it.operationId.toByteArray(); canaries += it.ciphertext.copyOf(48); canaries += it.hash.toByteArray() }
            val needles = ArrayList<String>()
            for (b in canaries) {
                needles += b.hex()
                needles += b.hex().uppercase()
                needles += Base64.getEncoder().encodeToString(b).take(24)
                needles += Base64.getUrlEncoder().withoutPadding().encodeToString(b).take(24)
                needles += String(b, Charsets.ISO_8859_1).take(12)
            }
            relays.forEach { needles += it.address.host.take(20) }
            needles += "[B@"
            for (s in strings) for (needle in needles) {
                if (needle.length >= 8 && s.contains(needle)) fail("a canary reached a public string or message: ${s.take(120)}")
            }
            assertTrue(strings.size > 10)
        }
    }

    @Test
    fun theOperationIdCanaryCatchesAnIdInAnyArgument() {
        World("T1-canary", 1, JournalMode.WAL).use { w ->
            val a = w.relay("A", 1)
            val c = w.client(ClientSpec("noa", armed = false))
            val ns = c.namespace("n", listOf(a, w.relay("B", 2)), listen = false)
            val op = c.enqueue("op", ns)
            val leaky = op.ciphertext.copyOf().also { System.arraycopy(op.operationId.toByteArray(), 0, it, 100, 16) }
            // The check runs before anything else in every port call; a lane item is required too.
            try {
                c.port.store(a.address, ns, ByteArray(82), leaky, TtlBucket.DAYS_7.seconds, 1000)
                fail("a call outside a lane item or with an op id was accepted")
            } catch (e: InvariantViolation) {
                assertTrue(e.message!!.contains("lane item") || e.message!!.contains("operation id"))
            }
            assertEquals(-1, HarnessRelayPort.indexOf(op.ciphertext, op.operationId.toByteArray()))
            assertEquals(100, HarnessRelayPort.indexOf(leaky, op.operationId.toByteArray()))
        }
    }
}
