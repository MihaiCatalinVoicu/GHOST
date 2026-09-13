package org.ghost.sync.store

import org.ghost.network.OnionAddress
import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import org.ghost.storage.SqlExecutor
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
import org.ghost.sync.port.PairKey
import org.ghost.sync.port.RandomSources
import org.ghost.sync.port.SchedulePurpose
import org.ghost.sync.port.SyncClock
import java.io.File
import java.nio.file.Files
import java.security.MessageDigest

/** Settable wall clock for store tests. */
class ManualClock(var now: Long) : SyncClock {
    override fun epochSeconds(): Long = now

    override fun monotonicMillis(): Long = now * 1000

    fun advance(seconds: Long) {
        now += seconds
    }
}

/** Random streams with fixed, test-chosen values. */
class FixedRandom(var sendDelayValue: Double = 0.5, var selectionValue: Double = 0.5) : RandomSources {
    var sendDelayDraws = 0

    override fun schedule(pair: PairKey, purpose: SchedulePurpose, index: Long): Double = 0.5

    override fun readBreaker(relay: RelayId, index: Long): Double = 0.5

    override fun sendDelay(): Double {
        sendDelayDraws++
        return sendDelayValue
    }

    override fun selection(): Double = selectionValue

    override fun quietRun(index: Long): Double = 0.5

    override fun paymentHold(index: Long): Double = 0.5
}

object TestBytes {
    /** Deterministic bytes, distinct for every seed: SHA-256 blocks of "seed:counter". */
    fun of(size: Int, seed: Int): ByteArray {
        val out = ByteArray(size)
        var pos = 0
        var counter = 0
        while (pos < size) {
            val block = MessageDigest.getInstance("SHA-256").digest("$seed:$counter".toByteArray(Charsets.US_ASCII))
            val n = minOf(block.size, size - pos)
            System.arraycopy(block, 0, out, pos, n)
            pos += n
            counter++
        }
        return out
    }

    fun ciphertext(seed: Int, size: Int = 1024): ByteArray = of(size, 900_000 + seed)

    fun sha256(bytes: ByteArray): BlobHash = BlobHash(MessageDigest.getInstance("SHA-256").digest(bytes))

    fun namespace(seed: Int): NamespaceId = NamespaceId(of(32, 1000 + seed))

    fun op(seed: Int): OperationId = OperationId(of(16, 2000 + seed))

    fun hash(seed: Int): BlobHash = BlobHash(of(32, 3000 + seed))

    /** A valid v3 onion address (checksum and version byte as Tor defines them; SHA3-256 from the JDK). */
    fun onion(seed: Int, port: Int = 443): OnionAddress {
        val publicKey = ByteArray(32) { (seed * 13 + it * 5 + 1).toByte() }
        val md = MessageDigest.getInstance("SHA3-256")
        md.update(".onion checksum".toByteArray(Charsets.US_ASCII))
        md.update(publicKey)
        md.update(3.toByte())
        val checksum = md.digest()
        val raw = publicKey + byteArrayOf(checksum[0], checksum[1], 3)
        return OnionAddress.parse(base32(raw) + ".onion:" + port)
    }

    private fun base32(bytes: ByteArray): String {
        val alphabet = "abcdefghijklmnopqrstuvwxyz234567"
        val out = StringBuilder()
        var buffer = 0
        var bits = 0
        for (b in bytes) {
            buffer = (buffer shl 8) or (b.toInt() and 0xff)
            bits += 8
            while (bits >= 5) {
                bits -= 5
                out.append(alphabet[(buffer shr bits) and 31])
            }
        }
        if (bits > 0) out.append(alphabet[(buffer shl (5 - bits)) and 31])
        return out.toString()
    }
}

/**
 * A migrated v2 database in a temporary file, the stores over it, a manual clock and fixed random
 * streams. [reopen] closes the connection and opens a new one on the same file (process restart).
 */
internal class SyncWorld(start: Long = T0) : AutoCloseable {
    private val dir: File = Files.createTempDirectory("ghost-sync-test").toFile()
    val file = File(dir, "sync.db")
    var sql: JdbcSqlExecutor = open()
        private set
    val clock = ManualClock(start)
    val random = FixedRandom()
    var mode: PrivacyMode = PrivacyMode.STANDARD
    var db: SyncDatabase = SyncDatabase(sql)
        private set
    var stores: SyncStores = SyncStores(db, clock, random) { mode }
        private set
    val hints = ArrayList<Set<SyncChange>>()

    init {
        stores.inbox.setListener { hints += it }
    }

    private fun open(): JdbcSqlExecutor = JdbcSqlExecutor(file.absolutePath).also {
        MigrationRunner(it).migrate()
        MigrationRunner(it).verifyIntegrity()
    }

    fun reopen() {
        sql.close()
        sql = open()
        db = SyncDatabase(sql)
        stores = SyncStores(db, clock, random) { mode }
        stores.inbox.setListener { hints += it }
    }

    val now: Long get() = clock.now
    val outbox: OutboxStore get() = stores.outboxStore
    val inbox: InboxStore get() = stores.inboxStore
    val directory: DirectoryStore get() = stores.directoryStore
    val caps: CapabilityStore get() = stores.capabilityStore
    val cursors: CursorStore get() = stores.cursorStore
    val gc: Gc get() = stores.gc

    fun <T> tx(block: (SyncTransaction) -> T): T = db.transaction(block)

    /** Adds relays whose operators are the given numbers; returns their ids in order. */
    fun relays(vararg operators: Int, firstSeed: Int = relaySeed): List<RelayId> {
        val entries = operators.mapIndexed { i, operator ->
            RelayEntry(TestBytes.onion(firstSeed + i), TestBytes.of(16, 500 + operator), RelayEntry.Source.CONFIG)
        }
        relaySeed = firstSeed + operators.size
        val ids = tx { stores.relayDirectory.upsert(it, entries) }
        return entries.map { ids.getValue(it.address) }
    }

    private var relaySeed = 1

    fun namespace(
        seed: Int,
        relays: Collection<RelayId>,
        listen: Boolean = true,
        consumer: Consumer = Consumer.DM,
        sendDelay: SendDelay = SendDelay.DEFAULT,
    ): NamespaceId {
        val ns = TestBytes.namespace(seed)
        tx { stores.namespaces.register(it, ns, consumer, relays.toSet(), listen, sendDelay) }
        return ns
    }

    fun capability(relay: RelayId, ns: NamespaceId, kind: CapabilityKind = CapabilityKind.WRITE, expiresAt: Long? = null, seed: Int = 1) =
        tx { stores.capabilities.put(it, relay, ns, kind, TestBytes.of(82, seed * 17 + relay.value.toInt()), expiresAt) }

    /** Relays of operators 1, 2, 3, a listening namespace over them and write tokens on each. */
    fun standardSet(listen: Boolean = true, seed: Int = 1): Pair<NamespaceId, List<RelayId>> {
        val relays = relays(1, 2, 3)
        val ns = namespace(seed, relays, listen)
        relays.forEach { capability(it, ns) }
        return Pair(ns, relays)
    }

    fun blob(seed: Int, ns: NamespaceId, ttl: TtlBucket = TtlBucket.DAYS_7, size: Int = 1024, deadline: Long? = null) =
        OutboundBlob(TestBytes.op(seed), ns, TestBytes.ciphertext(seed, size), ttl, deadline)

    fun enqueue(seed: Int, ns: NamespaceId, ttl: TtlBucket = TtlBucket.DAYS_7, deadline: Long? = null): OperationId {
        val result = tx { stores.outbox.enqueue(it, blob(seed, ns, ttl, deadline = deadline)) }
        check(result == EnqueueResult.Enqueued)
        return TestBytes.op(seed)
    }

    fun hashOf(seed: Int, size: Int = 1024): BlobHash = TestBytes.sha256(TestBytes.ciphertext(seed, size))

    // ------------------------------------------------------------------ inspection

    fun long(query: String, vararg args: Any?): Long? = rawSingle(query, args.toList()) { if (it.isNull(0)) null else it.long(0) }

    fun string(query: String, vararg args: Any?): String? = rawSingle(query, args.toList()) { if (it.isNull(0)) null else it.string(0) }

    private fun <T> rawSingle(query: String, args: List<Any?>, map: (SqlExecutor.Row) -> T?): T? {
        var out: T? = null
        sql.query(query, args.map(::bindable)) { out = map(it) }
        return out
    }

    private fun bindable(a: Any?): Any? = when (a) {
        is OperationId -> a.toByteArray()
        is NamespaceId -> a.toByteArray()
        is BlobHash -> a.toByteArray()
        is RelayId -> a.value
        else -> a
    }

    fun count(table: String, where: String = "1", vararg args: Any?): Long = long("SELECT count(*) FROM $table WHERE $where", *args)!!

    fun delivery(op: OperationId, relay: RelayId, column: String = "state"): Any? =
        rawSingle("SELECT $column FROM outbox_delivery WHERE operation_id = ? AND relay_id = ?", listOf(op.toByteArray(), relay.value)) {
            if (it.isNull(0)) null else if (column == "state") it.string(0) else it.long(0)
        }

    fun state(op: OperationId, relay: RelayId): String? = delivery(op, relay) as String?

    fun copyHour(op: OperationId, relay: RelayId): Long? = delivery(op, relay, "copy_hour") as Long?

    fun outcome(op: OperationId): String? = string("SELECT outcome FROM outbox_op WHERE operation_id = ?", op)

    fun hasPayload(op: OperationId): Boolean = long("SELECT ciphertext IS NOT NULL FROM outbox_op WHERE operation_id = ?", op) == 1L

    fun inboxState(ns: NamespaceId, hash: BlobHash): String? =
        string("SELECT state FROM inbox_blob WHERE namespace_id = ? AND blob_hash = ?", ns, hash)

    fun retainDay(ns: NamespaceId, hash: BlobHash): Long? =
        long("SELECT retain_until_day FROM inbox_blob WHERE namespace_id = ? AND blob_hash = ?", ns, hash)

    fun sourceState(ns: NamespaceId, hash: BlobHash, relay: RelayId): String? =
        string("SELECT state FROM inbox_source WHERE namespace_id = ? AND blob_hash = ? AND relay_id = ?", ns, hash, relay)

    /** Writes directly, for setting up states the stores reach only through several steps. */
    fun raw(statement: String, vararg args: Any?): Int = sql.execUpdate(statement, args.toList().map(::bindable))

    override fun close() {
        sql.close()
        dir.deleteRecursively()
    }

    companion object {
        /** A whole hour (and minute); not a day boundary. */
        const val T0: Long = 1_800_000_000L
        const val MINUTE = 60L
        const val HOUR = 3600L
        const val DAY = 86_400L
    }
}
