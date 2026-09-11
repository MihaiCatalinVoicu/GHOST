package org.ghost.sync.harness

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
import org.ghost.sync.api.SyncChange
import org.ghost.sync.api.SyncDatabase
import org.ghost.sync.api.SyncTransaction
import org.ghost.sync.api.TtlBucket
import org.ghost.sync.engine.KeyedRandomSources
import org.ghost.sync.engine.Session
import org.ghost.sync.engine.SessionKind
import org.ghost.sync.engine.Steps
import org.ghost.sync.engine.SyncEngine
import org.ghost.sync.engine.TrafficPolicy
import org.ghost.sync.port.RelayPort
import org.ghost.sync.port.TransportPort
import org.ghost.sync.port.TransportState
import org.ghost.sync.store.RetentionPolicy
import org.ghost.sync.store.SyncStores
import java.io.File
import java.security.MessageDigest

/** How the oracle consumer behaves (design §8.2). */
internal class ConsumerPolicy(
    /** Consumers do nothing while this returns true (S-H: paused longer than a TTL). */
    val paused: (World) -> Boolean = { false },
    /** Defer a blob once, for this many seconds, when this returns true for its hash (S-C). */
    val deferOnce: (BlobHash) -> Boolean = { false },
    val deferSeconds: Int = 60,
    /** Mutant M4: markConsumed commits in its own transaction, the consumer's effect in a second one. */
    val consumeOutsideTransaction: Boolean = false,
)

internal class ClientSpec(
    val name: String,
    val armed: Boolean,
    val mode: PrivacyMode = PrivacyMode.STANDARD,
    val policy: TrafficPolicy = Harness.POLICY,
    val steps: Steps = Steps.DEFAULT,
    val consumer: ConsumerPolicy = ConsumerPolicy(),
    /** Offline windows of true time [from, to) in ms: no network, ensureReady answers UNAVAILABLE. */
    val offline: List<LongRange> = emptyList(),
    /** Statement rewriting for SQL-level mutants (design §8.8). */
    val rewrite: ((String, List<Any?>) -> Pair<String, List<Any?>>)? = null,
)

/**
 * The transport fake (design §8.2): offline windows, an Arti clock check (ensureReady answers
 * UNAVAILABLE while the device clock is off by more than σ), scripted bootstrap failures, and a
 * generation that changes on [abort] (a fresh transport: new circuits, so rendezvous costs return).
 */
internal class FakeTransport(private val client: Client, override val relays: RelayPort) : TransportPort {
    var generation: Int = 0
        private set

    /** Pair circuits already set up in this generation, per lane class ("list"/"work"). */
    val circuits = HashSet<String>()

    var aborts: Int = 0
        private set
    private var bootstrapped = false

    override fun ensureReady(deadlineMonotonicMillis: Long): TransportState {
        val world = client.world
        client.bus.event(EventKind.TRANSPORT_ENSURE)
        if (client.offline()) return TransportState.UNAVAILABLE
        if (Math.abs(world.clock.deviceOffsetSeconds) > RetentionPolicy.SKEW_SECONDS) return TransportState.UNAVAILABLE
        client.bootstrapScript.removeFirstOrNull()?.let { return it }
        if (!bootstrapped) {
            val cost = world.latency.bootstrapMillis
            if (world.clock.millis + cost > deadlineMonotonicMillis) return TransportState.UNAVAILABLE
            world.clock.advance(cost)
            bootstrapped = true
        }
        return TransportState.READY
    }

    override fun abort() {
        generation++
        aborts++
        circuits.clear()
        bootstrapped = false
    }

    override fun toString(): String = "FakeTransport"
}

/**
 * One client device: a database file that survives crashes, and everything that does not (the
 * executor stack, stores, engine, session, transport, random key), rebuilt by [boot]. Reboot after
 * a crash = close the connection without committing, then a new `JdbcSqlExecutor(samePath)`,
 * `migrate()`, `verifyIntegrity()` and a new engine (design §8.1).
 */
internal class Client(val world: World, val index: Int, val spec: ClientSpec) : AutoCloseable {
    val name: String get() = spec.name
    val dbFile = File(world.dir, "${spec.name}.db")
    val bus: EventBus = if (spec.armed) world.bus else EventBus()
    var boots: Int = 0
        private set

    lateinit var jdbc: JdbcSqlExecutor
        private set
    lateinit var sql: FaultySqlExecutor
        private set
    lateinit var db: SyncDatabase
        private set
    lateinit var stores: SyncStores
        private set
    internal lateinit var engine: SyncEngine
        private set
    lateinit var transport: FakeTransport
        private set
    lateinit var port: HarnessRelayPort
        private set

    internal var session: Session? = null
    var mode: PrivacyMode = spec.mode
    val oracle = OracleConsumer(this)
    private var open = false

    /** Relay ids of this client's directory, by node index. */
    val relayIds = HashMap<Int, RelayId>()

    /** Namespaces this client registered, by label. */
    val namespaces = LinkedHashMap<String, NamespaceId>()
    val listening = HashSet<NamespaceId>()

    /** Consumers of this client's namespaces (the oracle only polls these). */
    val consumers = LinkedHashSet<Consumer>()

    /** Foreground window end (true ms); a crash before it restarts the foreground at once. */
    var foregroundUntil: Long = Long.MIN_VALUE

    /** A foreground start waits for the running background session to drain (design §1.4). */
    var foregroundPending: Boolean = false

    /** Offline windows added by the script while running (true ms). */
    val offlineWindows = ArrayList<LongRange>()

    fun offline(): Boolean = spec.offline.any { world.clock.millis in it } || offlineWindows.any { world.clock.millis in it }

    /** The next ensureReady calls answer these states (bootstrap failures of the network, not the process). */
    val bootstrapScript = ArrayDeque<TransportState>()

    fun boot() {
        check(!open) { "client already running" }
        boots++
        if (!dbFile.exists()) Templates.copy(world.journal, dbFile)
        jdbc = JdbcSqlExecutor(dbFile.absolutePath)
        jdbc.query("PRAGMA journal_mode = ${world.journal.name}") { }
        MigrationRunner(jdbc).migrate()
        MigrationRunner(jdbc).verifyIntegrity()
        OracleConsumer.createTables(jdbc)
        sql = FaultySqlExecutor(jdbc, bus)
        spec.rewrite?.let { sql.rewrite = it }
        sql.onUpdate += { s, args, changed -> Invariants.retentionWatch(this, s, args, changed) }
        sql.onCommit += { if (Harness.checkEveryCommit) Invariants.truth(this, "commit") }
        db = SyncDatabase(sql)
        val key = MessageDigest.getInstance("SHA-256").digest("schedule-key|${world.seed}|$name|$boots".toByteArray())
        val random = KeyedRandomSources(key)
        stores = SyncStores(db, world.clock, random) { mode }
        port = HarnessRelayPort(this)
        transport = FakeTransport(this, port)
        engine = SyncEngine(stores, transport, world.clock, random, spec.policy, spec.steps) { mode }
        stores.inbox.setListener { changes ->
            if (SyncChange.INBOX in changes || SyncChange.OUTCOMES in changes) oracle.requestDrain()
        }
        open = true
    }

    /** Process death: the connection closes without committing and every in-memory object is dropped. */
    fun kill() {
        session = null
        world.driver.dropClient(this)
        oracle.forget()
        if (open) jdbc.close()
        open = false
    }

    fun startSession(kind: SessionKind): Session {
        check(session == null) { "session already running" }
        val s = engine.startSession(kind)
        session = s
        return s
    }

    // ------------------------------------------------------------------ setup helpers (unarmed or scripted)

    fun <T> tx(block: (SyncTransaction) -> T): T = db.transaction(block)

    /** Adds relays to this client's directory (their ids are local handles). */
    fun directory(vararg nodes: RelayNode) {
        val entries = nodes.map { RelayEntry(it.address, it.operatorId, RelayEntry.Source.CONFIG) }
        val ids = tx { stores.relayDirectory.upsert(it, entries) }
        nodes.forEach { relayIds[it.index] = ids.getValue(it.address) }
    }

    fun id(node: RelayNode): RelayId = relayIds[node.index] ?: error("relay not in ${name}'s directory")

    fun namespace(label: String, nodes: List<RelayNode>, listen: Boolean, consumer: Consumer = Consumer.DM, sendDelay: SendDelay = SendDelay.DEFAULT): NamespaceId {
        consumers += consumer
        val ns = namespaces.getOrPut(label) { NamespaceId(MessageDigest.getInstance("SHA-256").digest("ns|${world.seed}|$label".toByteArray())) }
        nodes.filter { it.index !in relayIds }.forEach { directory(it) }
        tx { stores.namespaces.register(it, ns, consumer, nodes.map { n -> id(n) }.toSet(), listen, sendDelay) }
        if (listen) listening += ns else listening -= ns
        return ns
    }

    /** A token minted by [node] for [ns], installed through the public API. Returns the token. */
    fun capability(
        node: RelayNode,
        ns: NamespaceId,
        kind: CapabilityKind = CapabilityKind.WRITE,
        quota: Long = 64L * 1024 * 1024,
        validSeconds: Long = 200L * 86_400,
        declaredExpiry: Boolean = true,
    ): ByteArray {
        val expiry = world.relayNow(node) + validSeconds
        val token = node.model.mint(if (kind == CapabilityKind.READ) ModelRelay.KIND_READ else ModelRelay.KIND_WRITE, ns, quota, expiry)
        tx { stores.capabilities.put(it, id(node), ns, kind, token, if (declaredExpiry) expiry else null) }
        return token
    }

    /** Registers [label] as an op of this client and enqueues it through the oracle (one transaction). */
    fun enqueue(label: String, ns: NamespaceId, ttl: TtlBucket = TtlBucket.DAYS_7, size: Int = 1024, deadlineInSeconds: Long? = null): OpRecord {
        val op = world.ops.getOrPut(label) {
            val id = OperationId(MessageDigest.getInstance("SHA-256").digest("op|${world.seed}|$label".toByteArray()).copyOf(16))
            val deadline = deadlineInSeconds?.let { world.clock.epochSeconds() + it }
            OpRecord(label, this, id, ns, world.bytes("op|$label", size), ttl, deadline)
        }
        oracle.enqueue(op)
        return op
    }

    override fun close() {
        if (open) jdbc.close()
        open = false
    }

    override fun toString(): String = "Client($name)"
}

/**
 * A freshly migrated database per journal mode, made once per JVM and copied into every new world
 * (a new client's first boot); every boot still runs migrate() and verifyIntegrity() on it.
 */
internal object Templates {
    private val files = HashMap<JournalMode, File>()

    @Synchronized
    fun copy(mode: JournalMode, target: File) {
        val template = files.getOrPut(mode) {
            val dir = java.nio.file.Files.createTempDirectory(World.baseDir(), "ghost-template").toFile()
            dir.deleteOnExit()
            val file = File(dir, "template-${mode.name}.db")
            JdbcSqlExecutor(file.absolutePath).use { j ->
                j.query("PRAGMA journal_mode = ${mode.name}") { }
                MigrationRunner(j).migrate()
                MigrationRunner(j).verifyIntegrity()
                OracleConsumer.createTables(j)
            }
            file.deleteOnExit()
            file
        }
        java.nio.file.Files.copy(template.toPath(), target.toPath())
    }
}

/**
 * Oracle consumer (design §8.2): three tables with primary keys, written in the same transaction as
 * `enqueue`, `release` (when it returns true) and `markConsumed` (when it returns true), so a
 * duplicate fails at the event that caused it, and a lost effect shows as a missing row.
 */
internal class OracleConsumer(private val client: Client) {
    private var drainScheduled = false
    private val deferred = HashSet<BlobHash>()

    /** Queue of claimed blobs not yet handled (step-wise consumption between events, S-C). */
    private val claimed = ArrayDeque<org.ghost.sync.api.InboundBlob>()

    fun enqueue(op: OpRecord): EnqueueResult = client.tx { tx ->
        val blob = OutboundBlob(op.operationId, op.namespace, op.ciphertext, op.ttl, op.deadlineEpochSeconds)
        val r = client.stores.outbox.enqueue(tx, blob)
        if (r == EnqueueResult.Enqueued) {
            tx.sql.execUpdate(
                "INSERT INTO oracle_enqueued(operation_id, namespace_id, blob_hash) VALUES (?1, ?2, ?3)",
                listOf(op.operationId.toByteArray(), op.namespace.toByteArray(), op.hash.toByteArray()),
            )
        }
        r
    }

    /** A hint arrived: drain at the current time, as a consumer thread would. */
    fun requestDrain() {
        if (drainScheduled) return
        drainScheduled = true
        drainAt(client.world.clock.millis)
    }

    /** Schedules a drain at [at] (after a reboot: at the next session start). */
    fun drainAt(at: Long) {
        drainScheduled = true
        client.world.driver.scheduleProcess(at, client, "drain:${client.name}") {
            drainScheduled = false
            drain()
        }
    }

    fun forget() {
        drainScheduled = false
        claimed.clear()
    }

    /** Releases every decided outcome and consumes every claimable blob. Returns the transactions run. */
    fun drain(): Int {
        if (client.spec.consumer.paused(client.world)) return 0
        var actions = 0
        while (true) {
            val did = step()
            if (!did) break
            actions++
        }
        return actions
    }

    /**
     * One consumer action: handle one claimed blob, else release one outcome, else claim a batch.
     * Returns false when there is nothing to do.
     */
    fun step(): Boolean {
        if (client.spec.consumer.paused(client.world)) return false
        claimed.removeFirstOrNull()?.let { b ->
            consume(b)
            return true
        }
        for (consumer in client.consumers) {
            val outcome = client.stores.outbox.outcomes(consumer, 1).firstOrNull() ?: continue
            client.tx { tx ->
                if (client.stores.outbox.release(tx, outcome.operationId)) {
                    tx.sql.execUpdate(
                        "INSERT INTO oracle_outcome(operation_id, outcome) VALUES (?1, ?2)",
                        listOf(outcome.operationId.toByteArray(), outcome.outcome.name),
                    )
                }
            }
            return true
        }
        for (consumer in client.consumers) {
            val blobs = client.stores.inbox.claim(consumer, 8)
            if (blobs.isNotEmpty()) {
                claimed.addAll(blobs)
                return true
            }
        }
        return false
    }

    private fun consume(b: org.ghost.sync.api.InboundBlob) {
        val policy = client.spec.consumer
        if (policy.deferOnce(b.hash) && deferred.add(b.hash)) {
            client.tx { tx -> client.stores.inbox.defer(tx, b.namespace, b.hash, policy.deferSeconds) }
            return
        }
        check(ModelRelay.sha256(b.ciphertext) == b.hash) { "claimed blob does not match its hash" }
        val insert = "INSERT INTO oracle_consumed(namespace_id, blob_hash) VALUES (?1, ?2)"
        val args = listOf<Any?>(b.namespace.toByteArray(), b.hash.toByteArray())
        if (policy.consumeOutsideTransaction) {
            val consumed = client.tx { tx -> client.stores.inbox.markConsumed(tx, b.namespace, b.hash) }
            if (consumed) client.tx { tx -> tx.sql.execUpdate(insert, args) }
        } else {
            client.tx { tx -> if (client.stores.inbox.markConsumed(tx, b.namespace, b.hash)) tx.sql.execUpdate(insert, args) }
        }
    }

    companion object {
        fun createTables(jdbc: JdbcSqlExecutor) {
            jdbc.exec(
                "CREATE TABLE IF NOT EXISTS oracle_enqueued (operation_id BLOB PRIMARY KEY NOT NULL, " +
                    "namespace_id BLOB NOT NULL, blob_hash BLOB NOT NULL) WITHOUT ROWID",
            )
            jdbc.exec("CREATE TABLE IF NOT EXISTS oracle_outcome (operation_id BLOB PRIMARY KEY NOT NULL, outcome TEXT NOT NULL) WITHOUT ROWID")
            jdbc.exec(
                "CREATE TABLE IF NOT EXISTS oracle_consumed (namespace_id BLOB NOT NULL, blob_hash BLOB NOT NULL, " +
                    "PRIMARY KEY (namespace_id, blob_hash)) WITHOUT ROWID",
            )
        }
    }
}
