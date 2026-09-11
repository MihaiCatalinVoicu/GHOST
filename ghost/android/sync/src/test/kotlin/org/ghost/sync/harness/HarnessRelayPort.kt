package org.ghost.sync.harness

import org.ghost.network.NetworkException
import org.ghost.network.OnionAddress
import org.ghost.sync.api.BlobHash
import org.ghost.sync.api.Buckets
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.port.FetchedBlob
import org.ghost.sync.port.ListPage
import org.ghost.sync.port.RelayPort
import org.ghost.sync.port.StoreReceipt
import org.ghost.sync.store.RetentionPolicy
import java.nio.ByteBuffer
import java.security.MessageDigest

/**
 * The client's relay port in the harness (design §8.2 FaultyRelayPort over the model relays). It
 * stands where `TorRelayPort` → Rust would be, so it also does what the Rust client does around a
 * call: the T21 capability-scope guard (`invalid_argument` before any I/O), argument checks
 * (`IllegalArgumentException`, like the Kotlin `require`s), and validation of every answer
 * (`malformed_response`, `not_stored`), with the device clock.
 *
 * Each call has three events on the client's bus: before-send, after-apply (the relay applied it;
 * the response has not arrived) and after-response. At each the plan may crash the process, fail
 * the call with a category, or run an interleaving callback (outside any transaction). Latency
 * comes from the world's seeded model and advances the virtual clock. The port records what the
 * invariants need (inventory shown to the client, ambiguous store attempts, unanswered stores)
 * and asserts on the spot: calls happen only inside a lane item; no argument ever contains an
 * operation id (T1); every stored ciphertext is the frozen payload of one of the client's ops (OUT-3).
 */
internal class HarnessRelayPort(private val client: Client) : RelayPort {
    private val world: World get() = client.world

    /**
     * Phase of the store call in flight (0 none, 1 sending, 2 reached the relay, 3 lost on the way):
     * what a crash now leaves in the records (classification key).
     */
    var storePhase: Int = 0
        private set

    /** Relay calls made by this port (tests read them; nothing here is sent anywhere). */
    val calls = ArrayList<Call>()

    class Call(
        val kind: CallKind,
        val relay: String,
        val namespace: NamespaceId,
        val startMillis: Long,
        val limit: Int,
        val itemId: Long,
        /** Page number of the read-lane item making a list call (1 = an event's first page). */
        val page: Int?,
        /** The lane item making the call (its toString: item kind only). */
        val item: String,
        /** Hashes the call names (a store's blob; get and check hashes). */
        val hashes: List<BlobHash> = emptyList(),
    ) {
        /** How the call ended, filled in by the port (for failure messages). */
        var result: String = "?"
        override fun toString(): String = "Call($kind@$relay)"
    }

    private fun fail(category: String): Nothing = throw NetworkException(category)

    /** A relay's own refusal of a token (the truth behind a capability marked rejected or exhausted). */
    private fun <T> answer(node: RelayNode, token: ByteArray, reply: ModelRelay.Reply<T>): T = when (reply) {
        is ModelRelay.Reply.Ok -> reply.value
        is ModelRelay.Reply.Err -> {
            if (reply.category == "unauthorized" || reply.category == "quota") world.records.refused(node.name, ModelRelay.sha256(token), reply.category)
            fail(reply.category)
        }
    }

    /** Runs a planned fault or interleaving at [kind]; returns a category to throw, if any. */
    private fun event(kind: EventKind, info: CallInfo, node: RelayNode, token: ByteArray): String? {
        val planned = when (val f = client.bus.event(kind, info)) {
            null -> null
            is Fault.Network -> f.category
            is Fault.Interleave -> {
                f.action()
                null
            }
            is Fault.Crash -> error("crash faults are thrown by the bus")
        }
        val category = planned ?: world.relayHook?.invoke(client, kind, info)
        // An injected refusal stands for the relay refusing this token.
        if (category == "unauthorized" || category == "quota") world.records.refused(node.name, ModelRelay.sha256(token), category)
        return category
    }

    private fun opIdCanary(vararg args: ByteArray) {
        for (op in world.ops.values) {
            if (op.client !== client) continue
            val id = op.operationId.toByteArray()
            for (a in args) if (indexOf(a, id) >= 0) violation("an operation id reached the relay port (T1)")
        }
    }

    private fun scopeGuard(capability: ByteArray, ns: NamespaceId, write: Boolean) {
        val header = ModelRelay.header(capability) ?: fail("invalid_argument")
        if (header.namespace != ns) fail("invalid_argument")
        if (write && header.kind != ModelRelay.KIND_WRITE) fail("invalid_argument")
    }

    private fun begin(kind: CallKind, relay: OnionAddress, ns: NamespaceId, limit: Int, deadlineMillis: Int, hashes: List<BlobHash>): Pair<RelayNode, CallInfo> {
        require(deadlineMillis in 1..60_000) { "deadline out of range" }
        val item = world.driver.currentItemId ?: violation("a relay call outside any lane item")
        val node = world.node(relay)
        val call = Call(kind, node.name, ns, world.clock.millis, limit, item, (world.driver.currentItem as? org.ghost.sync.engine.ReadItem)?.page, world.driver.currentItem.toString(), hashes)
        calls += call
        val key = listOf<Any>(client.name, node.name, item, kind)
        world.records.callsPerItem[key] = (world.records.callsPerItem[key] ?: 0) + 1
        world.pruneRelays()
        return Pair(node, CallInfo(kind, node.name, ns.toByteArray().hex(), hashes.map { it.toByteArray().hex() }))
    }

    /** Latency of the call; true if the request reached the relay before the deadline. */
    private fun travel(node: RelayNode, ns: NamespaceId, kind: CallKind, deadlineMillis: Int): Boolean {
        val laneClass = if (kind == CallKind.LIST) "list" else "work"
        val first = client.transport.circuits.add("$laneClass|${node.name}|${ns.toByteArray().hex()}")
        var latency = world.latency.of(client.name, node.name, ns, kind, world.clock.millis, first)
        if (node.hostile == Hostile.STALL) latency = 60_000
        if (latency > deadlineMillis) {
            // The request goes out; the answer does not come back within the deadline.
            world.clock.advance(deadlineMillis.toLong())
            return latency / 2 <= deadlineMillis
        }
        world.clock.advance(latency)
        return true
    }

    private fun reachability(node: RelayNode) {
        if (client.offline()) fail("transport")
        if (!node.reachable) fail(node.unreachableCategory)
    }

    // ------------------------------------------------------------------ store

    override fun store(relay: OnionAddress, ns: NamespaceId, capability: ByteArray, ciphertext: ByteArray, ttlSeconds: Int, deadlineMillis: Int): StoreReceipt {
        val hash = ModelRelay.sha256(ciphertext)
        val (node, info) = begin(CallKind.STORE, relay, ns, 0, deadlineMillis, listOf(hash))
        opIdCanary(ns.toByteArray(), capability, ciphertext)
        if (ciphertext.size !in Buckets.SIZES) fail("not_bucket_sized")
        scopeGuard(capability, ns, write = true)
        if (world.ops.values.none { it.client === client && it.namespace == ns && it.hash == hash }) {
            violation("a store sent bytes that are no op's frozen payload (OUT-3: a second ciphertext)")
        }
        val generation = client.transport.generation
        val call = calls.last()
        var arrived = false
        storePhase = 1
        try {
            event(EventKind.RELAY_BEFORE_SEND, info, node, capability)?.let { fail(it) }
            reachability(node)
            arrived = travel(node, ns, CallKind.STORE, deadlineMillis)
            storePhase = if (arrived) 2 else 3
            // The request reached the relay: from here a copy may exist (OUT-4's "reached after-apply").
            if (arrived) world.records.ambiguous(ns, hash)
            val reply: ModelRelay.Reply<ModelRelay.Receipt>? = if (arrived) applyStore(node, ns, capability, ciphertext, ttlSeconds, hash) else null
            event(EventKind.RELAY_AFTER_APPLY, info, node, capability)?.let { fail(it) }
            if (!arrived || node.hostile == Hostile.STALL) fail("timeout")
            if (client.transport.generation != generation) fail("closed")
            val receipt = if (reply == null) fail("timeout") else answer(node, capability, reply)
            // Rust validate_store, with the device clock.
            val now = world.clock.epochSeconds()
            if (receipt.hash != hash) fail("malformed_response")
            if (receipt.expiry > now + MAX_TTL + RetentionPolicy.SKEW_SECONDS) fail("malformed_response")
            if (receipt.expiry + RetentionPolicy.SKEW_SECONDS < now + ttlSeconds) fail("not_stored")
            event(EventKind.RELAY_AFTER_RESPONSE, info, node, capability)?.let { fail(it) }
            call.result = "receipt@${world.clock.millis}"
            return StoreReceipt(receipt.hash, receipt.expiry)
        } catch (e: Throwable) {
            call.result = "${(e as? NetworkException)?.category ?: e.javaClass.simpleName}@${world.clock.millis} arrived=$arrived"
            // A definite refusal or a failure before the request left changes nothing; anything else
            // (a crash, a timeout, a closed transport, a bad answer) leaves the attempt ambiguous.
            val category = (e as? NetworkException)?.category
            val definite = category in DEFINITE_NOT_APPLIED
            if (!definite) world.records.ambiguous(ns, hash)
            if (arrived && !definite) world.records.unanswered(node.name, ns, hash)
            throw e
        } finally {
            storePhase = 0
        }
    }

    private fun applyStore(node: RelayNode, ns: NamespaceId, capability: ByteArray, ciphertext: ByteArray, ttl: Int, hash: BlobHash): ModelRelay.Reply<ModelRelay.Receipt> {
        if (node.hostile == Hostile.MALFORMED_STORE && node.malformedOnce.add(hash)) {
            node.hostileCalls++
            return ModelRelay.Reply.Err("malformed_response")
        }
        val reply = node.model.store(ns, ciphertext, capability, ttl.toLong(), world.relayNow(node))
        if (node.hostile == Hostile.ACK_AND_DROP && reply is ModelRelay.Reply.Ok) {
            // It answers with a receipt, but keeps nothing (whether or not the answer arrives).
            node.model.drop(ns, hash)
            world.records.dropped(node.name, ns, hash)
        }
        return reply
    }

    // ------------------------------------------------------------------ get

    override fun get(relay: OnionAddress, ns: NamespaceId, capability: ByteArray, hash: BlobHash, deadlineMillis: Int): FetchedBlob {
        val (node, info) = begin(CallKind.GET, relay, ns, 0, deadlineMillis, listOf(hash))
        opIdCanary(ns.toByteArray(), capability, hash.toByteArray())
        scopeGuard(capability, ns, write = false)
        event(EventKind.RELAY_BEFORE_SEND, info, node, capability)?.let { fail(it) }
        reachability(node)
        val arrived = travel(node, ns, CallKind.GET, deadlineMillis)
        event(EventKind.RELAY_AFTER_APPLY, info, node, capability)?.let { fail(it) }
        if (!arrived || node.hostile == Hostile.STALL) fail("timeout")
        val served = answer(node, capability, node.model.get(hash, capability, world.relayNow(node)))
        var data = served.data
        var expiry = served.expiry
        when (node.hostile) {
            Hostile.LIST_BUT_NOT_FOUND -> {
                node.hostileCalls++
                fail("not_found")
            }
            Hostile.WITHHOLD -> if (withheld(hash)) fail("not_found")
            Hostile.WRONG_BYTES -> {
                node.hostileCalls++
                data = data.copyOf().also { it[0] = (it[0].toInt() xor 0x5a).toByte() }
            }
            Hostile.SHORT_EXPIRY -> expiry = world.relayNow(node) + 3_600
            else -> Unit
        }
        // Rust validate_get.
        val now = world.clock.epochSeconds()
        if (data.size !in Buckets.SIZES || ModelRelay.sha256(data) != hash) fail("malformed_response")
        if (expiry > now + MAX_TTL + RetentionPolicy.SKEW_SECONDS) fail("malformed_response")
        event(EventKind.RELAY_AFTER_RESPONSE, info, node, capability)?.let { fail(it) }
        return FetchedBlob(data, expiry)
    }

    // ------------------------------------------------------------------ list

    override fun list(relay: OnionAddress, ns: NamespaceId, capability: ByteArray, cursor: ByteArray, limit: Int, deadlineMillis: Int): ListPage {
        val (node, info) = begin(CallKind.LIST, relay, ns, limit, deadlineMillis, emptyList())
        opIdCanary(ns.toByteArray(), capability, cursor)
        require(limit in 1..ModelRelay.MAX_BATCH) { "limit out of range" }
        if (cursor.isNotEmpty() && cursor.size != 8) fail("invalid_argument")
        scopeGuard(capability, ns, write = false)
        event(EventKind.RELAY_BEFORE_SEND, info, node, capability)?.let { fail(it) }
        reachability(node)
        val arrived = travel(node, ns, CallKind.LIST, deadlineMillis)
        event(EventKind.RELAY_AFTER_APPLY, info, node, capability)?.let { fail(it) }
        if (!arrived || node.hostile == Hostile.STALL) fail("timeout")
        val page = hostileList(node, ns, capability, cursor, limit)
        // Rust validate_list.
        if (page.hashes.size > limit || (page.next.isNotEmpty() && page.next.size != 8)) fail("malformed_response")
        event(EventKind.RELAY_AFTER_RESPONSE, info, node, capability)?.let { fail(it) }
        recordInventory(node, ns, page.hashes)
        return ListPage(page.hashes, page.next)
    }

    private fun hostileList(node: RelayNode, ns: NamespaceId, capability: ByteArray, cursor: ByteArray, limit: Int): ModelRelay.Page {
        val now = world.relayNow(node)
        fun honest(c: ByteArray): ModelRelay.Page = answer(node, capability, node.model.list(ns, capability, c, limit, now))
        return when (node.hostile) {
            Hostile.REWIND -> {
                node.hostileCalls++
                if (node.hostileCalls % 2 == 0L) honest(ByteArray(0)) else honest(cursor)
            }
            Hostile.REPEATS -> {
                val p = honest(cursor)
                ModelRelay.Page(p.hashes.flatMap { listOf(it, it) }.take(limit), p.next)
            }
            Hostile.EMPTY_PAGE_CURSOR -> {
                node.hostileCalls++
                ModelRelay.Page(emptyList(), ModelRelay.cursorOf(node.hostileCalls))
            }
            Hostile.WITHHOLD -> {
                val p = honest(cursor)
                ModelRelay.Page(p.hashes.filterNot { withheld(it) }, p.next)
            }
            Hostile.FLOOD -> {
                node.hostileCalls++
                val base = node.hostileCalls * limit
                ModelRelay.Page((0 until limit).map { garbage(node, base + it) }, ModelRelay.cursorOf(base))
            }
            else -> honest(cursor)
        }
    }

    private fun garbage(node: RelayNode, i: Long): BlobHash =
        BlobHash(MessageDigest.getInstance("SHA-256").digest("garbage|${node.name}|$i".toByteArray()))

    private fun withheld(hash: BlobHash): Boolean = hash.toByteArray()[0].toInt() and 1 == 0

    // ------------------------------------------------------------------ check

    override fun check(relay: OnionAddress, ns: NamespaceId, capability: ByteArray, hashes: List<BlobHash>, deadlineMillis: Int): Set<BlobHash> {
        require(hashes.size in 1..ModelRelay.MAX_BATCH) { "check batch out of range" }
        require(hashes.toSet().size == hashes.size) { "check hashes must be distinct" }
        val (node, info) = begin(CallKind.CHECK, relay, ns, hashes.size, deadlineMillis, hashes)
        opIdCanary(ns.toByteArray(), capability, *hashes.map { it.toByteArray() }.toTypedArray())
        scopeGuard(capability, ns, write = false)
        event(EventKind.RELAY_BEFORE_SEND, info, node, capability)?.let { fail(it) }
        reachability(node)
        val arrived = travel(node, ns, CallKind.CHECK, deadlineMillis)
        event(EventKind.RELAY_AFTER_APPLY, info, node, capability)?.let { fail(it) }
        if (!arrived || node.hostile == Hostile.STALL) fail("timeout")
        var held = answer(node, capability, node.model.check(hashes, capability, world.relayNow(node)))
        if (node.hostile == Hostile.WITHHOLD) held = held.filterNot { withheld(it) }
        // Rust validate_check: a subset of the request, no repeats.
        if (held.size > hashes.size || held.any { it !in hashes } || held.toSet().size != held.size) fail("malformed_response")
        event(EventKind.RELAY_AFTER_RESPONSE, info, node, capability)?.let { fail(it) }
        recordInventory(node, ns, held)
        for (h in hashes) {
            if (h !in held && world.ops.values.any { it.client === client && it.namespace == ns && it.hash == h }) world.records.absent(node.name, ns, h)
        }
        calls.last().result = "held=${held.size}/${hashes.size}@${world.clock.millis}"
        return held.toSet()
    }

    /** What the relay showed that it really holds (a hostile relay's false claims are not inventory). */
    private fun recordInventory(node: RelayNode, ns: NamespaceId, hashes: List<BlobHash>) {
        val now = world.relayNow(node)
        hashes.filter { node.model.live(ns, it, now) }.forEach { world.records.inventory(client.name, node.name, ns, it) }
    }

    override fun toString(): String = "HarnessRelayPort(${client.name})"

    companion object {
        const val MAX_TTL: Long = 7_776_000

        /** Categories that prove a store was not applied (design §3.6 copy effect "none"). */
        val DEFINITE_NOT_APPLIED: Set<String?> = setOf(
            "transport", "unauthorized", "quota", "rejected", "invalid_argument", "not_bucket_sized", "not_onion",
            "not_bootstrapped", "tor_bootstrap", "tor_bootstrap_timeout", "tor_setup", "runtime", "bridge_config", "native_missing",
        )

        fun indexOf(haystack: ByteArray, needle: ByteArray): Int {
            if (needle.isEmpty() || haystack.size < needle.size) return -1
            outer@ for (i in 0..haystack.size - needle.size) {
                for (j in needle.indices) if (haystack[i + j] != needle[j]) continue@outer
                return i
            }
            return -1
        }

        fun seqOf(cursor: ByteArray): Long = ByteBuffer.wrap(cursor).long
    }
}
