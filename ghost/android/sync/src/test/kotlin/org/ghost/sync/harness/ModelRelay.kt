package org.ghost.sync.harness

import org.ghost.sync.api.BlobHash
import org.ghost.sync.api.Buckets
import org.ghost.sync.api.NamespaceId
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.TreeMap
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Model of one relay (design §8.7): exactly the rules pinned by
 * `protocol/test-vectors/relay_semantics.txt`, which [ModelRelayConformanceTest] replays against it
 * (the Rust relay replays the same file), so the model cannot drift from the relay.
 *
 * Rules: expiry = now + ttl rounded up to the hour; a store over a live membership whose expiry +
 * 1 h reaches the wanted expiry is a free no-op; a live but shorter membership is extended (charged,
 * same sequence); an expired one, pruned or not, is renewed (charged, new sequence); quota is
 * charged per token before anything changes; get/check take the namespace from the capability;
 * write grants read; list walks index entries (live and expired-unpruned) after the cursor, at
 * most 1024 per call, returns the live ones, and its cursor is the last examined sequence or empty
 * at the end of the index; an emptied namespace restarts from the hour seed `(now / 3600) << 32`.
 *
 * Times are the relay's unix seconds. Categories are the client's (`rejected`, `unauthorized`,
 * `quota`, `not_found`). The model also keeps a history the harness invariants read: every
 * membership ever held, charges and state-changing stores per (namespace, hash).
 */
internal class ModelRelay(val name: String, key: ByteArray, var maxTtlSeconds: Long = MAX_TTL) {

    sealed class Reply<out T> {
        class Ok<T>(val value: T) : Reply<T>()
        class Err(val category: String) : Reply<Nothing>() {
            override fun toString(): String = "Err($category)"
        }
    }

    class Receipt(val hash: BlobHash, val expiry: Long)

    class Served(val data: ByteArray, val expiry: Long)

    class Page(val hashes: List<BlobHash>, val next: ByteArray)

    class Member(val hash: BlobHash, var expiry: Long, val seq: Long, val createdAt: Long)

    class Header(val kind: Int, val namespace: NamespaceId, val quota: Long, val expiry: Long)

    private class Space {
        val members = HashMap<BlobHash, Member>()
        val index = TreeMap<Long, BlobHash>()
        var nextSeq: Long? = null
    }

    private var macKey: ByteArray = key.copyOf()
    private val spaces = HashMap<NamespaceId, Space>()
    private val content = HashMap<BlobHash, ByteArray>()

    /** Quota ledger: SHA-256 of the token → (bytes used, capability expiry). */
    private val ledger = HashMap<BlobHash, Pair<Long, Long>>()

    /** Every (namespace, hash) that ever had a membership here. */
    val everHeld = HashSet<Pair<NamespaceId, BlobHash>>()

    /** Charged stores per (namespace, hash). */
    val charges = HashMap<Pair<NamespaceId, BlobHash>, Int>()

    /** Relay times of stores that created, renewed or extended a membership, per (namespace, hash). */
    val changingStores = HashMap<Pair<NamespaceId, BlobHash>, MutableList<Long>>()

    /** Count of state changes (stores that changed something, prunes that removed something, drops). */
    var mutations: Long = 0
        private set

    // ------------------------------------------------------------------ capabilities

    fun mint(kind: Int, namespace: NamespaceId, quota: Long, expiry: Long): ByteArray {
        require(kind == KIND_READ || kind == KIND_WRITE) { "capability kind out of range" }
        val body = ByteBuffer.allocate(BODY_BYTES).put(VERSION).put(kind.toByte()).put(namespace.toByteArray())
            .putLong(quota).putLong(expiry).array()
        return body + mac(body)
    }

    /** Key rotation (FR-5.7): every outstanding capability stops verifying. */
    fun rotateKey(newKey: ByteArray) {
        macKey = newKey.copyOf()
    }

    private fun mac(body: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(macKey, "HmacSHA256")) }.doFinal(body)

    /** The relay's current MAC key (the `:entitlement` harness mints redeemed v2 capabilities with it). */
    fun key(): ByteArray = macKey.copyOf()

    /** Verifies [token] for [required] on [namespace]; null = refused (`unauthorized`). */
    private fun verify(token: ByteArray, required: Int, namespace: NamespaceId, now: Long): Header? {
        val bodyBytes = bodyBytes(token) ?: return null
        val body = token.copyOfRange(0, bodyBytes)
        if (!MessageDigest.isEqual(mac(body), token.copyOfRange(bodyBytes, token.size))) return null
        val cap = header(token) ?: return null
        if (cap.expiry <= now) return null
        val scope = cap.namespace == namespace && (cap.kind == required || (cap.kind == KIND_WRITE && required == KIND_READ))
        return if (scope) cap else null
    }

    private fun verifyAny(token: ByteArray, now: Long): Header? {
        val h = header(token) ?: return null
        return verify(token, h.kind, h.namespace, now)
    }

    // ------------------------------------------------------------------ operations

    fun store(namespace: NamespaceId, data: ByteArray, token: ByteArray, ttlSeconds: Long, now: Long): Reply<Receipt> {
        if (ttlSeconds <= 0 || ttlSeconds > maxTtlSeconds) return Reply.Err("rejected")
        if (data.size !in Buckets.SIZES) return Reply.Err("rejected")
        val cap = verify(token, KIND_WRITE, namespace, now) ?: return Reply.Err("unauthorized")
        val hash = sha256(data)
        val wanted = ceilHour(now + ttlSeconds)
        val space = spaces.getOrPut(namespace) { Space() }
        val existing = space.members[hash]
        if (existing != null && existing.expiry > now && existing.expiry + HOUR >= wanted) {
            return Reply.Ok(Receipt(hash, existing.expiry))
        }
        val scope = sha256(token)
        val (used, _) = ledger[scope] ?: Pair(0L, cap.expiry)
        if (used + data.size > cap.quota) return Reply.Err("quota")
        ledger[scope] = Pair(used + data.size, cap.expiry)
        val key = Pair(namespace, hash)
        charges[key] = (charges[key] ?: 0) + 1
        changingStores.getOrPut(key) { ArrayList() } += now
        mutations++
        if (existing != null && existing.expiry > now) {
            existing.expiry = wanted
        } else {
            if (existing != null) removeMembership(namespace, space, existing)
            val seq = space.nextSeq ?: seed(now)
            space.nextSeq = seq + 1
            space.members[hash] = Member(hash, wanted, seq, now)
            space.index[seq] = hash
            content[hash] = data.copyOf()
            everHeld += key
        }
        return Reply.Ok(Receipt(hash, wanted))
    }

    fun get(hash: BlobHash, token: ByteArray, now: Long): Reply<Served> {
        val cap = verifyAny(token, now) ?: return Reply.Err("unauthorized")
        val m = spaces[cap.namespace]?.members?.get(hash)
        if (m == null || m.expiry <= now) return Reply.Err("not_found")
        return Reply.Ok(Served(content.getValue(hash).copyOf(), m.expiry))
    }

    fun check(hashes: List<BlobHash>, token: ByteArray, now: Long): Reply<List<BlobHash>> {
        if (hashes.size > MAX_BATCH) return Reply.Err("rejected")
        val cap = verifyAny(token, now) ?: return Reply.Err("unauthorized")
        val members = spaces[cap.namespace]?.members
        return Reply.Ok(hashes.filter { h -> members?.get(h)?.let { it.expiry > now } == true })
    }

    fun list(namespace: NamespaceId, token: ByteArray, cursor: ByteArray, limit: Int, now: Long): Reply<Page> {
        if (limit <= 0 || limit > MAX_BATCH) return Reply.Err("rejected")
        verify(token, KIND_READ, namespace, now) ?: return Reply.Err("unauthorized")
        val start = when (cursor.size) {
            0 -> 0L
            8 -> ByteBuffer.wrap(cursor).long + 1
            else -> return Reply.Err("rejected")
        }
        val space = spaces[namespace] ?: return Reply.Ok(Page(emptyList(), ByteArray(0)))
        val hashes = ArrayList<BlobHash>()
        var last: Long? = null
        var exhausted = true
        var scanned = 0
        for ((seq, hash) in space.index.tailMap(start, true)) {
            if (hashes.size == limit || scanned == MAX_LIST_SCAN) {
                exhausted = false
                break
            }
            scanned++
            last = seq
            if ((space.members[hash]?.expiry ?: 0L) > now) hashes += hash
        }
        val next = if (exhausted || last == null) ByteArray(0) else cursorOf(last)
        return Reply.Ok(Page(hashes, next))
    }

    /** One sweep: removes every membership with expiry <= now; returns how many. */
    fun prune(now: Long): Int {
        var removed = 0
        for ((ns, space) in spaces) {
            val doomed = space.members.values.filter { it.expiry <= now }
            for (m in doomed) {
                removeMembership(ns, space, m)
                removed++
            }
        }
        ledger.entries.removeIf { it.value.second <= now }
        if (removed > 0) mutations++
        return removed
    }

    private fun removeMembership(namespace: NamespaceId, space: Space, m: Member) {
        space.members.remove(m.hash)
        space.index.remove(m.seq)
        if (space.index.isEmpty()) space.nextSeq = null
        check(namespace in spaces) { "unknown namespace" }
    }

    // ------------------------------------------------------------------ hostile helpers and introspection

    /** An ack-and-drop relay forgets a membership it acknowledged. */
    fun drop(namespace: NamespaceId, hash: BlobHash) {
        val space = spaces[namespace] ?: return
        val m = space.members[hash] ?: return
        removeMembership(namespace, space, m)
        mutations++
    }

    /** Another client's write straight into the relay (no capability, no quota; design §8.1). */
    fun inject(namespace: NamespaceId, data: ByteArray, ttlSeconds: Long, now: Long): BlobHash {
        val token = mint(KIND_WRITE, namespace, Long.MAX_VALUE / 4, now + 400L * 86_400)
        val reply = store(namespace, data, token, ttlSeconds, now)
        check(reply is Reply.Ok) { "injected store refused: $reply" }
        return reply.value.hash
    }

    fun member(namespace: NamespaceId, hash: BlobHash): Member? = spaces[namespace]?.members?.get(hash)

    fun live(namespace: NamespaceId, hash: BlobHash, now: Long): Boolean = (member(namespace, hash)?.expiry ?: 0L) > now

    /** Live memberships of [namespace] at [now]. */
    fun liveMembers(namespace: NamespaceId, now: Long): List<Member> =
        spaces[namespace]?.members?.values?.filter { it.expiry > now }.orEmpty()

    fun namespaces(): Set<NamespaceId> = spaces.keys.toSet()

    /** Digest of the whole state (memberships, index, sequences, ledger), for crash-point classification checks. */
    fun digest(): String {
        val md = MessageDigest.getInstance("SHA-256")
        for (ns in spaces.keys.sortedBy { it.toByteArray().hex() }) {
            val s = spaces.getValue(ns)
            md.update(ns.toByteArray())
            md.update(ByteBuffer.allocate(8).putLong(s.nextSeq ?: -1).array())
            for ((seq, h) in s.index) {
                val m = s.members.getValue(h)
                md.update(ByteBuffer.allocate(16).putLong(seq).putLong(m.expiry).array())
                md.update(h.toByteArray())
            }
        }
        for (k in ledger.keys.sortedBy { it.toByteArray().hex() }) {
            md.update(k.toByteArray())
            md.update(ByteBuffer.allocate(8).putLong(ledger.getValue(k).first).array())
        }
        return md.digest().hex()
    }

    override fun toString(): String = "ModelRelay($name)"

    companion object {
        const val KIND_READ = 1
        const val KIND_WRITE = 2
        const val VERSION: Byte = 1
        const val BODY_BYTES = 1 + 1 + 32 + 8 + 8
        const val TOKEN_BYTES = BODY_BYTES + 32

        /**
         * Capability v2 (Phase 8 design §10.3, X9): the v1 header plus a 16-byte serial, so a
         * redeemed capability is 98 bytes and its MAC covers bytes 0..66. The header fields sit
         * where v1 has them (`ghost_relay_api::capability_header` parses both).
         */
        const val VERSION_2: Byte = 2
        const val BODY_V2_BYTES = BODY_BYTES + 16
        const val TOKEN_V2_BYTES = BODY_V2_BYTES + 32

        /** The MAC-covered body length of a v1 or v2 capability, or null for anything else. */
        fun bodyBytes(token: ByteArray): Int? = when {
            token.size == TOKEN_BYTES && token[0] == VERSION -> BODY_BYTES
            token.size == TOKEN_V2_BYTES && token[0] == VERSION_2 -> BODY_V2_BYTES
            else -> null
        }
        const val MAX_BATCH = 256
        const val MAX_LIST_SCAN = 1024
        const val HOUR = 3_600L
        const val MAX_TTL = 7_776_000L

        fun ceilHour(t: Long): Long = -Math.floorDiv(-t, HOUR) * HOUR

        fun seed(now: Long): Long = (now / HOUR) shl 32

        fun cursorOf(seq: Long): ByteArray = ByteBuffer.allocate(8).putLong(seq).array()

        fun seqOf(cursor: ByteArray): Long = ByteBuffer.wrap(cursor).long

        fun sha256(bytes: ByteArray): BlobHash = BlobHash(MessageDigest.getInstance("SHA-256").digest(bytes))

        /** The public header of a v1 or v2 token (ghost_relay_api::capability_header), or null. */
        fun header(token: ByteArray): Header? {
            if (bodyBytes(token) == null) return null
            val kind = token[1].toInt()
            if (kind != KIND_READ && kind != KIND_WRITE) return null
            val b = ByteBuffer.wrap(token)
            return Header(kind, NamespaceId(token.copyOfRange(2, 34)), b.getLong(34), b.getLong(42))
        }
    }
}
