package org.ghost.sync.engine

import org.ghost.network.NetworkException
import org.ghost.network.OnionAddress
import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import org.ghost.sync.api.BlobHash
import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.EnqueueResult
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.OperationId
import org.ghost.sync.api.OutboundBlob
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.RelayEntry
import org.ghost.sync.api.RelayId
import org.ghost.sync.api.SendDelay
import org.ghost.sync.api.SyncDatabase
import org.ghost.sync.api.SyncTransaction
import org.ghost.sync.api.TtlBucket
import org.ghost.sync.port.FetchedBlob
import org.ghost.sync.port.ListPage
import org.ghost.sync.port.RelayPort
import org.ghost.sync.port.StoreReceipt
import org.ghost.sync.port.SyncClock
import org.ghost.sync.port.TransportPort
import org.ghost.sync.port.TransportState
import org.ghost.sync.store.SyncStores
import org.ghost.sync.store.TestBytes
import java.io.File
import java.nio.ByteBuffer
import java.nio.file.Files
import java.util.PriorityQueue
import kotlin.concurrent.withLock

/**
 * Virtual time for deterministic runs: a monotonic millisecond counter and a wall clock derived
 * from it (plus [wallOffsetSeconds] for clock jumps).
 */
class VirtualClock(private val startEpochSeconds: Long) : SyncClock {
    @Volatile
    var millis: Long = 0

    @Volatile
    var wallOffsetSeconds: Long = 0

    override fun epochSeconds(): Long = startEpochSeconds + Math.floorDiv(millis, 1000L) + wallOffsetSeconds

    override fun monotonicMillis(): Long = millis

    fun advance(ms: Long) {
        millis += ms
    }
}

/**
 * A small in-test relay network (not the exit-gate model relay of step S6): memberships per
 * (relay, namespace) with sequence numbers, lists by sequence with 8-byte big-endian cursors (the
 * test decodes them; the engine never does), and an empty next cursor when the namespace is
 * exhausted. Calls advance the virtual clock by [latency] and may fail with a category before or
 * after the relay applies them. Every call is recorded with its start time.
 */
internal class TestRelays(private val clock: VirtualClock) : RelayPort {
    enum class Kind { STORE, GET, LIST, CHECK }

    class Call(
        val kind: Kind,
        val relay: OnionAddress,
        val namespace: NamespaceId,
        val startMillis: Long,
        val limit: Int,
        cursor: ByteArray,
        val hashes: List<BlobHash>,
        val deadlineMillis: Int,
        capability: ByteArray,
        val ciphertext: ByteArray?,
    ) {
        val cursor: ByteArray = cursor.copyOf()
        val capability: ByteArray = capability.copyOf()

        override fun toString(): String = "Call($kind)"
    }

    private class Member(val bytes: ByteArray, var expiry: Long, var seq: Long)

    private class Space {
        val members = LinkedHashMap<BlobHash, Member>()
        var nextSeq = 1L
    }

    private val spaces = HashMap<Pair<OnionAddress, NamespaceId>, Space>()
    val calls = ArrayList<Call>()

    /** Virtual duration of a call, in ms; beyond the call's deadline it ends as `timeout` at the deadline. */
    var latency: (Call) -> Long = { 0L }

    /** A category thrown after the latency, before the relay applies the call. */
    var failBefore: (Call) -> String? = { null }

    /** A category thrown after the relay applied the call (e.g. a store applied, then a timeout). */
    var failAfter: (Call) -> String? = { null }

    /** Replaces a list answer (hostile relays); null keeps the honest answer. */
    var listOverride: (Call) -> ListPage? = { null }

    /** Replaces a get answer (hostile relays); null keeps the honest answer. */
    var getOverride: (Call) -> FetchedBlob? = { null }

    /** Replaces a store receipt's hash (hostile relays); null keeps the true hash. */
    var receiptHashOverride: (Call) -> BlobHash? = { null }

    /** Called during a call after the latency (e.g. a capability put racing the call). */
    var during: (Call) -> Unit = {}

    /** A Kotlin argument error thrown instead of the call (a port `require`). */
    var argumentError: (Call) -> Boolean = { false }

    private fun space(relay: OnionAddress, ns: NamespaceId): Space = spaces.getOrPut(Pair(relay, ns)) { Space() }

    private fun now(): Long = clock.epochSeconds()

    /** Another client's write: stores [bytes] on [relay] without a recorded call. */
    fun put(relay: OnionAddress, ns: NamespaceId, bytes: ByteArray, ttlSeconds: Long = 604_800): BlobHash {
        val hash = TestBytes.sha256(bytes)
        apply(relay, ns, hash, bytes, ttlSeconds)
        return hash
    }

    fun holds(relay: OnionAddress, ns: NamespaceId, hash: BlobHash): Boolean =
        spaces[Pair(relay, ns)]?.members?.get(hash)?.let { it.expiry > now() } ?: false

    /** Removes a membership (an ack-and-drop relay). */
    fun drop(relay: OnionAddress, ns: NamespaceId, hash: BlobHash) {
        spaces[Pair(relay, ns)]?.members?.remove(hash)
    }

    fun memberships(relay: OnionAddress, ns: NamespaceId): Int = spaces[Pair(relay, ns)]?.members?.size ?: 0

    fun callsOf(kind: Kind): List<Call> = calls.filter { it.kind == kind }

    private fun apply(relay: OnionAddress, ns: NamespaceId, hash: BlobHash, bytes: ByteArray, ttlSeconds: Long): Member {
        val s = space(relay, ns)
        val expiry = ceilHour(now() + ttlSeconds)
        val existing = s.members[hash]
        return when {
            existing == null -> Member(bytes, expiry, s.nextSeq++).also { s.members[hash] = it }
            existing.expiry <= now() -> existing.also {
                it.expiry = expiry
                it.seq = s.nextSeq++
            }
            existing.expiry < expiry -> existing.also { it.expiry = expiry }
            else -> existing
        }
    }

    private fun begin(call: Call) {
        calls += call
        // The native deadline bounds every call: a slower answer is a timeout at the deadline.
        val took = latency(call)
        if (took > call.deadlineMillis) {
            clock.advance(call.deadlineMillis.toLong())
            throw NetworkException("timeout")
        }
        clock.advance(took)
        during(call)
        if (argumentError(call)) throw IllegalArgumentException("argument out of range")
        failBefore(call)?.let { throw NetworkException(it) }
    }

    private fun end(call: Call) {
        failAfter(call)?.let { throw NetworkException(it) }
    }

    override fun store(relay: OnionAddress, ns: NamespaceId, capability: ByteArray, ciphertext: ByteArray, ttlSeconds: Int, deadlineMillis: Int): StoreReceipt {
        val hash = TestBytes.sha256(ciphertext)
        val call = Call(Kind.STORE, relay, ns, clock.millis, 0, ByteArray(0), listOf(hash), deadlineMillis, capability, ciphertext.copyOf())
        begin(call)
        val member = apply(relay, ns, hash, ciphertext.copyOf(), ttlSeconds.toLong())
        end(call)
        return StoreReceipt(receiptHashOverride(call) ?: hash, member.expiry)
    }

    override fun get(relay: OnionAddress, ns: NamespaceId, capability: ByteArray, hash: BlobHash, deadlineMillis: Int): FetchedBlob {
        val call = Call(Kind.GET, relay, ns, clock.millis, 0, ByteArray(0), listOf(hash), deadlineMillis, capability, null)
        begin(call)
        getOverride(call)?.let { return it }
        val member = spaces[Pair(relay, ns)]?.members?.get(hash)?.takeIf { it.expiry > now() } ?: throw NetworkException("not_found")
        end(call)
        return FetchedBlob(member.bytes, member.expiry)
    }

    override fun list(relay: OnionAddress, ns: NamespaceId, capability: ByteArray, cursor: ByteArray, limit: Int, deadlineMillis: Int): ListPage {
        val call = Call(Kind.LIST, relay, ns, clock.millis, limit, cursor, emptyList(), deadlineMillis, capability, null)
        begin(call)
        listOverride(call)?.let { return it }
        val after = if (cursor.isEmpty()) 0L else ByteBuffer.wrap(cursor).long
        val live = (spaces[Pair(relay, ns)]?.members ?: emptyMap<BlobHash, Member>()).entries
            .filter { it.value.seq > after && it.value.expiry > now() }
            .sortedBy { it.value.seq }
        val page = live.take(limit)
        val next = if (live.size > limit) cursorOf(page.last().value.seq) else ByteArray(0)
        end(call)
        return ListPage(page.map { it.key }, next)
    }

    override fun check(relay: OnionAddress, ns: NamespaceId, capability: ByteArray, hashes: List<BlobHash>, deadlineMillis: Int): Set<BlobHash> {
        require(hashes.size == hashes.toSet().size) { "check hashes must be distinct" }
        val call = Call(Kind.CHECK, relay, ns, clock.millis, 0, ByteArray(0), hashes, deadlineMillis, capability, null)
        begin(call)
        val held = hashes.filter { holds(relay, ns, it) }.toSet()
        end(call)
        return held
    }

    companion object {
        fun cursorOf(seq: Long): ByteArray = ByteBuffer.allocate(8).putLong(seq).array()

        fun seqOf(cursor: ByteArray): Long = if (cursor.isEmpty()) 0L else ByteBuffer.wrap(cursor).long

        private fun ceilHour(seconds: Long): Long = -Math.floorDiv(-seconds, 3600L) * 3600L
    }
}

/** Transport with a settable state; counts calls. */
internal class TestTransport(override val relays: RelayPort) : TransportPort {
    var state: TransportState = TransportState.READY
    var ensureCalls = 0
    var aborts = 0

    override fun ensureReady(deadlineMonotonicMillis: Long): TransportState {
        ensureCalls++
        return state
    }

    override fun abort() {
        aborts++
    }
}

/**
 * Runs a [LaneSource] one item at a time in virtual time (design §1.4, §8.2). An item starts at the
 * virtual time the source asks for; its calls advance the clock by their latency; its completion is
 * held until that later time, so read workers and the work lane overlap exactly as on threads. Ties
 * are ordered completion, read, work. [beforeItem] lets a test interleave its own transactions
 * between items (no hook in production code).
 */
internal class DeterministicDriver(private val clock: VirtualClock, private val source: LaneSource) {
    private class Pending(val at: Long, val seq: Long, val item: LaneItem)

    private val pending = PriorityQueue<Pending>(compareBy<Pending>({ it.at }, { it.seq }))
    private var seq = 0L
    private var idleTakes = 0

    /** Virtual time of the last event. */
    var time: Long = clock.millis
        private set

    var beforeItem: (LaneItem) -> Unit = {}

    /** Items started, in order, with their start time. */
    val started = ArrayList<Pair<Long, LaneItem>>()

    /** Runs every event up to and including monotonic time [limit]; the clock ends at [limit]. */
    fun runUntil(limit: Long) {
        while (step(limit)) {
            // one event per iteration
        }
        if (limit > time) time = limit
        clock.millis = time
    }

    /** Runs until the source is finished (or [limit]); returns whether it finished. */
    fun runUntilFinished(limit: Long): Boolean {
        while (!source.lock.withLock { source.finished } && step(limit)) {
            // one event per iteration
        }
        clock.millis = time
        return source.lock.withLock { source.finished }
    }

    fun runFor(ms: Long) = runUntil(time + ms)

    private fun step(limit: Long): Boolean {
        val completion = pending.peek()?.at
        val (read, work) = source.lock.withLock {
            Pair(source.wakeAt(Lane.READ, time)?.let { maxOf(it, time) }, source.wakeAt(Lane.WORK, time)?.let { maxOf(it, time) })
        }
        var best = Long.MAX_VALUE
        var which = -1
        val candidates = listOf(completion, read, work)
        for (i in candidates.indices) {
            val c = candidates[i] ?: continue
            if (c < best) {
                best = c
                which = i
            }
        }
        if (which < 0) return false
        val t = best
        if (t > limit) return false
        time = t
        clock.millis = t
        if (which == 0) {
            val p = checkNotNull(pending.poll())
            source.lock.withLock { source.complete(p.item, t) }
            idleTakes = 0
            return true
        }
        val lane = if (which == 1) Lane.READ else Lane.WORK
        val item = source.lock.withLock { source.take(lane, t) }
        if (item == null) {
            idleTakes++
            check(idleTakes < 100_000) { "the source keeps waking without progress" }
            return true
        }
        idleTakes = 0
        started += Pair(t, item)
        beforeItem(item)
        item.run()
        pending.add(Pending(clock.millis, seq++, item))
        return true
    }
}

/**
 * A migrated database in a temporary file, the stores, the engine with a [TestRelays] network, a
 * [VirtualClock] and a fixed schedule key, plus setup and inspection helpers.
 */
internal class EngineWorld(
    val policy: TrafficPolicy = TrafficPolicy(),
    key: ByteArray = ByteArray(32) { (it * 7 + 3).toByte() },
    steps: Steps = Steps.DEFAULT,
) : AutoCloseable {
    private val dir: File = Files.createTempDirectory("ghost-engine-test").toFile()
    val sql: JdbcSqlExecutor = JdbcSqlExecutor(File(dir, "sync.db").absolutePath).also {
        MigrationRunner(it).migrate()
        MigrationRunner(it).verifyIntegrity()
    }
    val clock = VirtualClock(T0)
    val random = KeyedRandomSources(key)
    var mode: PrivacyMode = PrivacyMode.STANDARD
    val db = SyncDatabase(sql)
    val stores = SyncStores(db, clock, random) { mode }
    val net = TestRelays(clock)
    val transport = TestTransport(net)
    val engine = SyncEngine(stores, transport, clock, random, policy, steps) { mode }
    private val addresses = HashMap<Long, OnionAddress>()
    private var relaySeed = 1

    fun <T> tx(block: (SyncTransaction) -> T): T = db.transaction(block)

    /** Starts a session and a driver over it. */
    fun session(kind: SessionKind = SessionKind.FOREGROUND): Pair<Session, DeterministicDriver> {
        val s = engine.startSession(kind)
        return Pair(s, DeterministicDriver(clock, s))
    }

    fun relays(vararg operators: Int): List<RelayId> {
        val entries = operators.mapIndexed { i, operator ->
            RelayEntry(TestBytes.onion(relaySeed + i), TestBytes.of(16, 500 + operator), RelayEntry.Source.CONFIG)
        }
        relaySeed += operators.size
        val ids = tx { stores.relayDirectory.upsert(it, entries) }
        return entries.map { e -> ids.getValue(e.address).also { addresses[it.value] = e.address } }
    }

    fun address(relay: RelayId): OnionAddress = addresses.getValue(relay.value)

    fun namespace(seed: Int, relays: Collection<RelayId>, listen: Boolean = true, sendDelay: SendDelay = SendDelay.DEFAULT): NamespaceId {
        val ns = TestBytes.namespace(seed)
        tx { stores.namespaces.register(it, ns, Consumer.DM, relays.toSet(), listen, sendDelay) }
        return ns
    }

    fun capability(relay: RelayId, ns: NamespaceId, kind: CapabilityKind = CapabilityKind.WRITE, seed: Int = 1) =
        tx { stores.capabilities.put(it, relay, ns, kind, TestBytes.of(82, seed * 17 + relay.value.toInt()), null) }

    /** Three relays of operators 1, 2, 3, a namespace over them and write tokens on each. */
    fun standardSet(listen: Boolean = true, seed: Int = 1): Pair<NamespaceId, List<RelayId>> {
        val relays = relays(1, 2, 3)
        val ns = namespace(seed, relays, listen)
        relays.forEach { capability(it, ns) }
        return Pair(ns, relays)
    }

    fun enqueue(seed: Int, ns: NamespaceId, ttl: TtlBucket = TtlBucket.DAYS_7): OperationId {
        val op = TestBytes.op(seed)
        val result = tx { stores.outbox.enqueue(it, OutboundBlob(op, ns, TestBytes.ciphertext(seed), ttl)) }
        check(result == EnqueueResult.Enqueued)
        return op
    }

    fun hashOf(seed: Int): BlobHash = TestBytes.sha256(TestBytes.ciphertext(seed))

    /** Another client writes [count] blobs to [relay] in [ns]; returns their hashes. */
    fun inbound(relay: RelayId, ns: NamespaceId, firstSeed: Int, count: Int): List<BlobHash> =
        (firstSeed until firstSeed + count).map { net.put(address(relay), ns, TestBytes.ciphertext(it)) }

    // ------------------------------------------------------------------ inspection

    fun long(query: String, vararg args: Any?): Long? {
        var out: Long? = null
        sql.query(query, args.map(::bindable)) { out = if (it.isNull(0)) null else it.long(0) }
        return out
    }

    fun string(query: String, vararg args: Any?): String? {
        var out: String? = null
        sql.query(query, args.map(::bindable)) { out = if (it.isNull(0)) null else it.string(0) }
        return out
    }

    fun raw(statement: String, vararg args: Any?): Int = sql.execUpdate(statement, args.map(::bindable))

    private fun bindable(a: Any?): Any? = when (a) {
        is OperationId -> a.toByteArray()
        is NamespaceId -> a.toByteArray()
        is BlobHash -> a.toByteArray()
        is RelayId -> a.value
        else -> a
    }

    fun state(op: OperationId, relay: RelayId): String? =
        string("SELECT state FROM outbox_delivery WHERE operation_id = ? AND relay_id = ?", op, relay)

    fun copyHour(op: OperationId, relay: RelayId): Long? =
        long("SELECT copy_hour FROM outbox_delivery WHERE operation_id = ? AND relay_id = ?", op, relay)

    fun outcome(op: OperationId): String? = string("SELECT outcome FROM outbox_op WHERE operation_id = ?", op)

    fun inboxState(ns: NamespaceId, hash: BlobHash): String? =
        string("SELECT state FROM inbox_blob WHERE namespace_id = ? AND blob_hash = ?", ns, hash)

    fun cursor(relay: RelayId, ns: NamespaceId): Long? {
        var out: ByteArray? = null
        sql.query("SELECT cursor FROM relay_cursor WHERE relay_id = ? AND namespace_id = ?", listOf(relay.value, ns.toByteArray())) { out = it.blob(0) }
        return out?.let { TestRelays.seqOf(it) }
    }

    fun count(table: String, where: String = "1", vararg args: Any?): Long = long("SELECT count(*) FROM $table WHERE $where", *args) ?: 0L

    override fun close() {
        sql.close()
        dir.deleteRecursively()
    }

    companion object {
        /** A whole hour; not a day boundary. */
        const val T0: Long = 1_800_000_000L
        const val SECOND = 1_000L
        const val MINUTE = 60_000L
        const val HOUR = 3_600_000L
    }
}
