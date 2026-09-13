package org.ghost.sync.harness

import org.ghost.network.OnionAddress
import org.ghost.sync.api.BlobHash
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.OperationId
import org.ghost.sync.api.TtlBucket
import org.ghost.sync.store.TestBytes
import java.io.File
import java.nio.ByteBuffer
import java.nio.file.Files
import java.security.MessageDigest

/** Journal modes every suite runs in (design §8.1). */
internal enum class JournalMode { DELETE, WAL }

/**
 * Hostile relay behaviours (design §8.5), applied by the harness port on top of the honest model.
 * The invariants are asserted against the honest relays; the hostile one is bounded instead.
 */
internal enum class Hostile {
    /** Every other list answers from the beginning of the namespace, whatever the cursor. */
    REWIND,

    /** Every listed hash is repeated (up to the limit). */
    REPEATS,

    /** Lists answer an empty page with a fresh non-empty cursor, forever. */
    EMPTY_PAGE_CURSOR,

    /** Never lists (or serves) hashes whose first byte is even. */
    WITHHOLD,

    /** Lists honestly; every get answers not_found. */
    LIST_BUT_NOT_FOUND,

    /** Gets serve other bytes (the Rust client answers malformed_response). */
    WRONG_BYTES,

    /** Every list page is `limit` garbage hashes with an advancing cursor. */
    FLOOD,

    /** Every call stalls for 60 s (the deadline answers timeout). */
    STALL,

    /** Stores are acknowledged, then the membership is dropped. */
    ACK_AND_DROP,

    /** Gets declare an expiry one hour ahead (a lie the client cannot detect). */
    SHORT_EXPIRY,

    /** The first store of each hash answers malformed_response without storing (mutant M5). */
    MALFORMED_STORE,
}

/** One relay of the world: the model, its operator, and what the harness does around it. */
internal class RelayNode(
    val index: Int,
    val name: String,
    val address: OnionAddress,
    val operatorId: ByteArray,
    val model: ModelRelay,
    var hostile: Hostile?,
    /** The relay's clock minus true time, seconds (within σ for honest relays). */
    var skewSeconds: Long,
) {
    /** When false every call fails before reaching the relay with [unreachableCategory]. */
    var reachable: Boolean = true
    var unreachableCategory: String = "transport"

    /** Hostile-mode state (counters), part of the world state. */
    var hostileCalls: Long = 0
    val malformedOnce = HashSet<BlobHash>()

    val honest: Boolean get() = hostile == null

    override fun toString(): String = "RelayNode($name)"
}

/** An outbound operation the scenario intends (the oracle table says whether its enqueue committed). */
internal class OpRecord(
    val label: String,
    val client: Client,
    val operationId: OperationId,
    val namespace: NamespaceId,
    val ciphertext: ByteArray,
    val ttl: TtlBucket,
    val deadlineEpochSeconds: Long?,
) {
    val hash: BlobHash = ModelRelay.sha256(ciphertext)

    override fun toString(): String = "Op($label)"
}

/**
 * Harness bookkeeping the invariants read (design §8.4). Every change bumps [version], which is
 * part of the crash-point classification key.
 */
internal class Records {
    var version: Long = 0
        private set

    /** (client, relay, namespace, hash) the relay showed to that client in a list page or check answer. */
    val inventory = HashSet<List<Any>>()

    /**
     * (namespace, hash) with a store attempt that reached a relay (applied or not) or ended
     * ambiguous (a timeout, a closed transport, a bad answer, a crash with the lease in flight).
     */
    val ambiguous = HashSet<Pair<NamespaceId, BlobHash>>()

    /** (relay, namespace, hash) → store calls that reached the relay without a receipt reaching the engine. */
    val unanswered = HashMap<List<Any>, Int>()

    /** (relay, namespace, hash) → check answers that did not show an own op's hash. */
    val absent = HashMap<List<Any>, Int>()

    fun absent(relay: String, ns: NamespaceId, hash: BlobHash) {
        val k = listOf<Any>(relay, ns, hash)
        absent[k] = (absent[k] ?: 0) + 1
        version++
    }

    /** (relay, namespace, hash) → memberships an ack-and-drop relay dropped after a receipt. */
    val drops = HashMap<List<Any>, Int>()

    /** (relay, token hash, category) for every `unauthorized` or `quota` answer a relay gave. */
    val refused = HashSet<List<Any>>()

    fun refused(relay: String, tokenHash: BlobHash, category: String) {
        if (refused.add(listOf(relay, tokenHash, category))) version++
    }

    /** Relay calls per (client, relay, driver item id, kind), for the hostile bounds. */
    val callsPerItem = HashMap<List<Any>, Int>()

    fun inventory(client: String, relay: String, ns: NamespaceId, hash: BlobHash) {
        if (inventory.add(listOf(client, relay, ns, hash))) version++
    }

    fun ambiguous(ns: NamespaceId, hash: BlobHash) {
        if (ambiguous.add(Pair(ns, hash))) version++
    }

    fun unanswered(relay: String, ns: NamespaceId, hash: BlobHash) {
        val k = listOf<Any>(relay, ns, hash)
        unanswered[k] = (unanswered[k] ?: 0) + 1
        version++
    }

    fun dropped(relay: String, ns: NamespaceId, hash: BlobHash) {
        val k = listOf<Any>(relay, ns, hash)
        drops[k] = (drops[k] ?: 0) + 1
        version++
    }

    fun digest(): String {
        val md = MessageDigest.getInstance("SHA-256")
        md.update(inventory.map { it.joinToString("|") }.sorted().joinToString("\n").toByteArray())
        md.update(ambiguous.map { "${it.first.toByteArray().hex()}|${it.second.toByteArray().hex()}" }.sorted().joinToString("\n").toByteArray())
        md.update(unanswered.entries.map { "${it.key}=${it.value}" }.sorted().joinToString("\n").toByteArray())
        md.update(drops.entries.map { "${it.key}=${it.value}" }.sorted().joinToString("\n").toByteArray())
        md.update(refused.map { it.joinToString("|") }.sorted().joinToString("\n").toByteArray())
        md.update(absent.entries.map { "${it.key}=${it.value}" }.sorted().joinToString("\n").toByteArray())
        return md.digest().hex()
    }
}

/**
 * Seeded latency (design §8.2, §11.2 #12): a keyed value per (client, pair, kind, start time), so
 * a list's latency is a fixed trace of its pair and start time, plus a rendezvous setup cost on the
 * first call per pair per transport, counted separately for list and work calls (a work-lane call
 * never warms a list's circuit in the model, so the list trace stays fixed, T19 premise).
 */
internal class LatencyModel(private val seed: Long) {
    var listBaseMillis: Long = 300
    var listSpreadMillis: Long = 2_700
    var workBaseMillis: Long = 300
    var workSpreadMillis: Long = 4_700
    var rendezvousMillis: Long = 3_000
    var bootstrapMillis: Long = 4_000

    fun of(client: String, relay: String, ns: NamespaceId, kind: CallKind, startMillis: Long, firstOnCircuit: Boolean): Long {
        val md = MessageDigest.getInstance("SHA-256")
        md.update(ByteBuffer.allocate(16).putLong(seed).putLong(startMillis).array())
        md.update("$client|$relay|$kind".toByteArray())
        md.update(ns.toByteArray())
        val u = (ByteBuffer.wrap(md.digest()).long ushr 11) * (1.0 / (1L shl 53))
        val (base, spread) = if (kind == CallKind.LIST) Pair(listBaseMillis, listSpreadMillis) else Pair(workBaseMillis, workSpreadMillis)
        return base + (u * spread).toLong() + if (firstOnCircuit) rendezvousMillis else 0L
    }
}

/**
 * The world a scenario runs in (design §8.1): the model relays, the clock, the clients (each a
 * database file that survives crashes), "other clients" writing straight into relays, and the
 * driver that runs everything in virtual time. One armed client (the subject) carries the event
 * bus: its events are enumerated and faulted.
 */
internal class World(val name: String, val seed: Long, val journal: JournalMode) : AutoCloseable {
    val dir: File = Files.createTempDirectory(baseDir(), "ghost-harness").toFile()
    val clock = TestClock(T0)
    val bus = EventBus()
    val records = Records()
    val latency = LatencyModel(seed)
    val driver = HarnessDriver(this)
    val relays = ArrayList<RelayNode>()
    val clients = ArrayList<Client>()
    val ops = LinkedHashMap<String, OpRecord>()

    /** Byte arrays other clients wrote, by label, so scenarios can refer to them. */
    val otherBlobs = LinkedHashMap<String, Pair<NamespaceId, BlobHash>>()

    /**
     * Scenario hook at every relay event of every client (outside any transaction), after the
     * fault plan: it may act (a capability put racing the call, a topology change, an offline
     * window) and may return a category to fail the call with. Hooks that change state the future
     * depends on bump [scriptState] (classification key).
     */
    var relayHook: ((Client, EventKind, CallInfo) -> String?)? = null
    var scriptState: Long = 0

    /** Ignore the retention-safety check (worlds with a relay that lies about expiry). */
    var retentionCheck: Boolean = true

    /** Scripted end of the scenario; the quiescence tail starts here. */
    var endMillis: Long = 0

    /** Messages of findings the harness tolerates by design (for the report), never failures. */
    val notes = ArrayList<String>()

    // ------------------------------------------------------------------ extension points
    // The `:entitlement` harness (Phase 8 design §11.9) adds the real entitlement engine to this
    // world through these; the defaults are the Phase 7 behaviour.

    /** Runs at the end of every boot of a client (per-process components of an extension). */
    var onBoot: ((Client) -> Unit)? = null

    /** Runs when a client's sync session starts (an extension's session participant). */
    var onSessionStart: ((Client, org.ghost.sync.engine.Session) -> Unit)? = null

    /** One periodic job of a client: a background session unless one runs (an extension may make it a quiet run). */
    var runJob: (Client) -> Unit = { c -> if (c.session == null) c.startSession(org.ghost.sync.engine.SessionKind.BACKGROUND) }

    /** State changes of an extension's models (part of the crash-point classification key). */
    var extraMutations: () -> Long = { 0L }

    /** Lines describing an extension's models (part of the crash digest). */
    var extraState: () -> List<String> = { emptyList() }

    /** Listened namespaces another consumer than the oracle drains (IN-1 is the extension's check there). */
    var in1Exempt: (Client, NamespaceId) -> Boolean = { _, _ -> false }

    fun relayNow(node: RelayNode): Long = clock.trueEpochSeconds() + node.skewSeconds

    fun relay(name: String, operator: Int, maxTtl: Long = ModelRelay.MAX_TTL, hostile: Hostile? = null, skewSeconds: Long = 0): RelayNode {
        val index = relays.size
        val key = MessageDigest.getInstance("SHA-256").digest("relay-key|$seed|$name".toByteArray())
        val node = RelayNode(index, name, TestBytes.onion(10_000 + index), TestBytes.of(16, 700 + operator), ModelRelay(name, key, maxTtl), hostile, skewSeconds)
        check(relays.none { it.address == node.address }) { "duplicate onion" }
        relays += node
        if (hostile == Hostile.SHORT_EXPIRY) retentionCheck = false
        return node
    }

    fun node(address: OnionAddress): RelayNode = relays.firstOrNull { it.address == address } ?: error("unknown relay")

    fun client(spec: ClientSpec): Client {
        check(clients.none { it.name == spec.name }) { "duplicate client" }
        val c = Client(this, clients.size, spec)
        clients += c
        c.boot()
        return c
    }

    val subject: Client get() = clients.firstOrNull { it.spec.armed } ?: error("no armed client")

    /** Schedules [action] at true time [atMillis] (a world action of the driver). */
    fun at(atMillis: Long, label: String, action: () -> Unit) = driver.schedule(atMillis, label, action)

    /** Deterministic bytes of one bucket for a label. */
    fun bytes(label: String, size: Int = 1024): ByteArray {
        val out = ByteArray(size)
        var pos = 0
        var counter = 0
        while (pos < size) {
            val block = MessageDigest.getInstance("SHA-256").digest("$seed|$label|$counter".toByteArray())
            val n = minOf(block.size, size - pos)
            System.arraycopy(block, 0, out, pos, n)
            pos += n
            counter++
        }
        return out
    }

    /** Another client writes [label]'s bytes into [node] for [ns] now (straight into the model, design §8.1). */
    fun otherWrite(node: RelayNode, ns: NamespaceId, label: String, ttl: TtlBucket = TtlBucket.DAYS_7, size: Int = 1024): BlobHash {
        val data = bytes("other|$label", size)
        val h = node.model.inject(ns, data, ttl.seconds.toLong(), relayNow(node))
        otherBlobs[label] = Pair(ns, h)
        return h
    }

    /** Sum of every relay's state changes and hostile counters (classification key). */
    fun relayMutations(): Long = relays.sumOf { it.model.mutations + it.hostileCalls } + extraMutations()

    /** Model relays prune once per hour of true time, lazily before a call (the relay's periodic sweep). */
    private var lastPruneHour = Long.MIN_VALUE

    fun pruneRelays() {
        val hour = Math.floorDiv(clock.trueEpochSeconds(), 3600L)
        if (hour == lastPruneHour) return
        lastPruneHour = hour
        relays.forEach { it.model.prune(relayNow(it)) }
    }

    override fun close() {
        clients.forEach { it.close() }
        dir.deleteRecursively()
    }

    override fun toString(): String = "World($name, seed=$seed, $journal)"

    companion object {
        /** A whole hour; not a day boundary. */
        const val T0: Long = 1_800_000_000L
        const val SECOND = 1_000L
        const val MINUTE = 60_000L
        const val HOUR = 3_600_000L
        const val DAY = 86_400_000L

        /**
         * Where world databases live: `ghost.sync.harness.dir` when set, else a tmpfs (/dev/shm) when
         * the machine has one, else the temp directory. The crash model is process death, not power
         * loss (design §8.1), so a memory-backed file system changes timing only.
         */
        fun baseDir(): java.nio.file.Path {
            val configured = System.getProperty("ghost.sync.harness.dir")
            val dir = when {
                !configured.isNullOrBlank() -> File(configured)
                File("/dev/shm").let { it.isDirectory && it.canWrite() } -> File("/dev/shm/ghost-sync-harness")
                else -> File(System.getProperty("java.io.tmpdir"))
            }
            dir.mkdirs()
            return dir.toPath()
        }
    }
}
