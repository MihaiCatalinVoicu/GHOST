package org.ghost.messaging.channel

import org.ghost.crypto.bridge.MlsNative
import org.ghost.messaging.DmWorld
import org.ghost.messaging.FakeKeyWrapper
import org.ghost.messaging.FixedRandomSources
import org.ghost.messaging.MovableClock
import org.ghost.messaging.OwnerWorld
import org.ghost.messaging.SequentialRandom
import org.ghost.messaging.api.ChannelId
import org.ghost.messaging.channel.engine.ChannelActor
import org.ghost.messaging.channel.engine.ChannelContexts
import org.ghost.messaging.channel.engine.ChannelCounters
import org.ghost.messaging.channel.engine.ChannelEngine
import org.ghost.messaging.channel.engine.ChannelEnv
import org.ghost.messaging.channel.engine.ChannelLocalKeys
import org.ghost.messaging.channel.engine.ChannelSyncPorts
import org.ghost.messaging.channel.store.ChannelStore
import org.ghost.messaging.channel.store.ChannelStores
import org.ghost.messaging.port.ChannelSeeds
import org.ghost.messaging.port.EsSlot
import org.ghost.messaging.port.EsSlots
import org.ghost.messaging.store.ContentCipher
import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.RelayEntry
import org.ghost.sync.api.SyncDatabase
import org.ghost.sync.store.SyncStores
import java.security.MessageDigest

/**
 * The channel world of slice S4 (Phase 10 design §12.1, scaled to what S4 builds): 2 … 6 clients, each a real
 * `:messaging` channel engine over its own migrated v7 database and its own `:sync` stores, the **real** OpenMLS through
 * `MlsNative` loading `ghost-dm-host`, and a model relay ([ModelChannelRelay]) between them.
 *
 * **What is real and what is a model.** Everything inside `:messaging` and `:crypto-bridge` is the production code: the
 * engine, its steps, the stores, the facade, the native library. The transport is the model relay — it reads the ops
 * the engine enqueued through `Outbox.enqueue`, keeps them for their TTL, serves them to whichever client listens on
 * the namespace and writes back the delivery rows and the outcome the Phase 7 engine would have written (the recipe
 * `ModelDmRelay` uses, F9 §15.1): re-driving Phase 7 here would re-prove it.
 *
 * **Time** is virtual and common to the world ([advance]); the native side reads days only from the arguments it is
 * given (§3.6). **Determinism** of the native draws is not assumed: every assertion is about states, counts and
 * displayed posts, never about bytes the native side drew.
 *
 * The user actions run inline on the caller's thread ([InlineActor]): a world drives every pass itself.
 */
internal class ChannelWorld(
    val startSeconds: Long = DmWorld.WEEK_ORIGIN + 2_870 * DmWorld.WEEK + 2 * DmWorld.DAY,
    val slotCount: Int = 4,
    val operators: Int = 2,
    /** The relay; a world restored from a snapshot passes a copy of the snapshot's ([ModelChannelRelay.copy]). */
    val relay: ModelChannelRelay = ModelChannelRelay(),
) : AutoCloseable {

    val clients = ArrayList<ChannelClient>()
    var now: Long = startSeconds
        private set

    /**
     * A new client, named; its database in memory, or in the file [path] (which the client then owns and closes: what a
     * crash enumeration freezes, [ChannelWorld.restore]), or over the executor [sql] the caller owns.
     */
    fun client(name: String, sql: SqlExecutor? = null, boot: Int = 0, path: String? = null): ChannelClient {
        val client = ChannelClient(this, name, sql, boot, path)
        clients.removeAll { it.name == name }
        clients += client
        return client
    }

    fun advance(seconds: Long) {
        now += seconds
        for (c in clients) {
            c.clock.now = now
            c.clock.monotonic += seconds * 1_000
        }
    }

    /** One relay round. */
    fun pump(): Int = relay.pump(clients, now)

    /**
     * Relay rounds and hint-triggered passes of every client until nothing moves, at most [rounds] rounds: the
     * outcomes come back, the blobs are received, the settles that are due run. Returns the number of rounds that moved
     * something.
     */
    fun quiesce(rounds: Int = 12): Int {
        var moving = 0
        repeat(rounds) {
            val moved = pump()
            for (c in clients) c.hintPass()
            if (moved == 0 && relay.pendingOps(clients) == 0) return moving
            moving++
        }
        return moving
    }

    /**
     * The admission path of a committer (CO-8): a relay session start schedules the pass `U[0, 5 min]` later, and the
     * first time-triggered pass after it runs it.
     */
    fun admissionPass(committer: ChannelClient) {
        committer.sessionStart()
        advance(6 * DmWorld.MINUTE)
        committer.timePass()
    }

    /** Past the settle window of CO-4 (20 minutes), with a time-triggered pass of every client. */
    fun pastSettleWindow() {
        advance(21 * DmWorld.MINUTE)
        for (c in clients) c.timePass()
    }

    override fun close() {
        for (c in clients) c.close()
    }

    companion object {
        /** A fresh executor over a copy of [snapshot] (the snapshot itself stays untouched for the next run). */
        fun restore(snapshot: java.io.File): JdbcSqlExecutor {
            val copy = java.io.File(snapshot.parentFile, snapshot.nameWithoutExtension + "-" + System.nanoTime() + ".db")
            snapshot.copyTo(copy)
            return JdbcSqlExecutor(copy.absolutePath)
        }

        /** True when `ghost-dm-host` is loaded (`-Dghost.dm.native`): the channel worlds need the real OpenMLS. */
        fun nativeAvailable(): Boolean {
            val path = System.getProperty(MlsNative.HOST_LIBRARY_PROPERTY)
            return !path.isNullOrEmpty() && MlsNative.isAvailable()
        }

        fun sha256(text: String): ByteArray = MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.UTF_8))

        fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }
    }
}

/** The user actions on the caller's thread: the world is single-threaded on purpose. */
internal object InlineActor : ChannelActor {
    override fun <T> call(body: () -> T): T = body()
}

/**
 * One client of a [ChannelWorld]: a migrated database, `:sync` stores over it, the relay directory and the week's slot
 * table, a channel engine with fixed local keys (the content key and the seen key `dm_self` would hold) and pseudonym
 * seeds derived from its name — so a client rebuilt over the same database after a crash ([reboot]) is the same user.
 */
internal class ChannelClient(
    val world: ChannelWorld,
    val name: String,
    sql: SqlExecutor? = null,
    /** 0 at the first boot; a reboot draws from its own stream so it never reuses an id the first boot committed. */
    val boot: Int = 0,
    /** A database file the client opens and owns (closed by [close], so the file can then be copied whole). */
    path: String? = null,
) : AutoCloseable {

    private val ownExecutor: JdbcSqlExecutor? =
        if (sql == null) JdbcSqlExecutor(path ?: ":memory:").also { MigrationRunner(it).migrate() } else null
    val sql: SqlExecutor = sql ?: requireNotNull(ownExecutor)
    val database = SyncDatabase(this.sql)
    val clock = MovableClock(world.now)
    val stores = SyncStores(database, clock, FixedRandomSources()) { PrivacyMode.STANDARD }
    val random = SequentialRandom(0, "channel-$name" + if (boot > 0) "-b$boot" else "")

    var slots: List<EsSlot>
    private val esSlots = EsSlots { slots }

    private val contentKey: ByteArray = ChannelWorld.sha256("content:$name")
    private val seen: ByteArray = ChannelWorld.sha256("seen:$name")
    val content = ContentCipher(contentKey)

    /** False makes the local keys unavailable, as a locked identity would (`CRYPTO_UNAVAILABLE`). */
    var unlocked = true

    val keys = object : ChannelLocalKeys {
        override fun content(): ContentCipher? = if (unlocked) content else null

        override fun seenKey(): ByteArray? = if (unlocked) seen.copyOf() else null
    }

    /** `ps` for a channel: what `:identity` derives from the root (here from the client's name, so a reboot keeps it). */
    val seeds = ChannelSeeds { channelId -> ChannelWorld.sha256("seed:$name:" + ChannelWorld.hex(channelId)) }

    val channelStores = ChannelStores()
    val counters = ChannelCounters()
    val contexts = ChannelContexts(database, channelStores, FakeKeyWrapper(), random, seeds)
    val env: ChannelEnv
    val engine: ChannelEngine

    init {
        val relayIds = database.transaction { tx ->
            stores.relayDirectory.upsert(
                tx,
                (0 until world.slotCount).map { i ->
                    RelayEntry(OwnerWorld.onion(i), OwnerWorld.operatorId(i % world.operators), RelayEntry.Source.CONFIG)
                },
            )
        }
        slots = (0 until world.slotCount).map { i ->
            EsSlot(i, relayIds.getValue(OwnerWorld.onion(i)), OwnerWorld.operatorId(i % world.operators))
        }
        env = ChannelEnv(database, channelStores, contexts, keys, clock, random, esSlots, counters)
        engine = ChannelEngine(
            env,
            ChannelSyncPorts(stores.namespaces, stores.capabilities, stores.registrations, stores.outbox, stores.inbox, stores.funding),
            InlineActor,
        )
    }

    // ---------------------------------------------------------------------------------------------- passes

    /** A pass a listener hint would run: outcomes, receive, settle, pending posts; nothing time-triggered. */
    fun hintPass() = engine.runPass(timeTriggered = false, deadlineMonotonicMillis = null, sessionStart = false)

    /** A time-triggered pass that is no relay session start (the alarm, the timer, a database open). */
    fun timePass() = engine.runPass(timeTriggered = true, deadlineMonotonicMillis = null, sessionStart = false)

    /** A relay session start: a time-triggered pass that also schedules the committer's pass (CO-8). */
    fun sessionStart() = engine.runPass(timeTriggered = true, deadlineMonotonicMillis = null, sessionStart = true)

    // ---------------------------------------------------------------------------------------------- reads

    fun channel(id: ChannelId): ChannelStore.ChannelRow? =
        database.transaction { tx -> channelStores.channels.channel(tx.sql, id.toByteArray()) }

    /** The texts of the posts the channel shows, newest first, as the UI would read them (the expiry filter applied). */
    fun displayed(id: ChannelId): List<String> = database.transaction { tx ->
        channelStores.posts.page(tx.sql, id.toByteArray(), clock.now, 500).map { row ->
            val text = content.open(row.bodyEnv, org.ghost.messaging.channel.engine.ChannelAd.postBody(row.opId))
                ?: error("a post body that does not open")
            String(text, Charsets.UTF_8)
        }
    }

    fun count(table: String, where: String = "1 = 1", vararg args: Any?): Long {
        var n = 0L
        sql.query("SELECT count(*) FROM $table WHERE $where", args.toList()) { n = it.long(0) }
        return n
    }

    /** The integrity checks §12.4 runs after every reboot. */
    fun integrity(): List<String> {
        val problems = ArrayList<String>()
        sql.query("PRAGMA integrity_check") { if (it.string(0) != "ok") problems += "integrity: ${it.string(0)}" }
        sql.query("PRAGMA foreign_key_check") { problems += "foreign key: ${it.string(0)}" }
        sql.query(
            "SELECT channel_id, count(*) FROM ch_generation WHERE state = 'current' GROUP BY channel_id HAVING count(*) > 1",
        ) { problems += "two current generations" }
        sql.query(
            "SELECT channel_id, epoch, count(*) FROM ch_candidate WHERE own = 0 GROUP BY channel_id, epoch HAVING count(*) > 8",
        ) { problems += "more than 8 candidates" }
        // every queued post has an op or a pending row
        sql.query(
            "SELECT op_id FROM ch_post p WHERE p.state = 'queued' AND NOT EXISTS (SELECT 1 FROM ch_outbound_op o WHERE o.ref = p.op_id) " +
                "AND NOT EXISTS (SELECT 1 FROM ch_pending_post q WHERE q.op_id = p.op_id)",
        ) { problems += "a queued post with neither an op nor a pending row" }
        // a joining channel holds its join state, an active one none
        sql.query(
            "SELECT 1 FROM ch_channel c WHERE c.state = 'joining' AND NOT EXISTS (SELECT 1 FROM ch_join j WHERE j.channel_id = c.channel_id)",
        ) { problems += "a joining channel without its join state" }
        sql.query(
            "SELECT 1 FROM ch_channel c WHERE c.state = 'active' AND EXISTS (SELECT 1 FROM ch_join j WHERE j.channel_id = c.channel_id)",
        ) { problems += "an active channel that kept its join state" }
        return problems
    }

    /** What a crash leaves of the client: the native context's memory (the process died). */
    fun die() {
        contexts.close()
    }

    override fun close() {
        contexts.close()
        ownExecutor?.close()
    }

    override fun toString(): String = "ChannelClient($name)"
}

/** The error a crash world throws at its armed event: an `Error`, so no typed catch of the engine can swallow it. */
internal class SimulatedCrash(val at: Int) : Error("simulated crash at event $at")

/**
 * The crash executor of the channel worlds (the F7 §8.3 method; §12.4 "`FaultySqlExecutor` at every statement, pre- and
 * post-commit"): every `exec`, `execUpdate` and `query` is an event **before** it runs, a transaction adds a pre-commit
 * event inside its block and a post-commit event after it, and the armed event throws [SimulatedCrash] — which rolls
 * back the open transaction exactly as a process death mid-transaction does.
 */
internal class CrashingSqlExecutor(val delegate: JdbcSqlExecutor) : SqlExecutor {
    var count: Int = 0
        private set

    /** The event to crash at, counted from the next one ([count] + 1 … ); null runs everything. */
    var armAt: Int? = null

    /** When set, every event's statement (its first words) is recorded: a trace two runs can be compared by. */
    var trace: MutableList<String>? = null

    /** Counting starts over (the window the enumeration measures). */
    fun reset() {
        count = 0
        armAt = null
    }

    private fun event(label: String = "commit") {
        trace?.add(label.trim().take(60).replace(Regex("\\s+"), " "))
        count++
        if (armAt == count) {
            armAt = null
            throw SimulatedCrash(count)
        }
    }

    override fun exec(sql: String, args: List<Any?>) {
        event(sql)
        delegate.exec(sql, args)
    }

    override fun execUpdate(sql: String, args: List<Any?>): Int {
        event(sql)
        return delegate.execUpdate(sql, args)
    }

    override fun query(sql: String, args: List<Any?>, onRow: (SqlExecutor.Row) -> Unit) {
        event(sql)
        delegate.query(sql, args, onRow)
    }

    override fun <T> transaction(block: () -> T): T {
        val nested = delegate.inTransaction
        val result = delegate.transaction {
            val r = block()
            if (!nested) event()
            r
        }
        if (!nested) event()
        return result
    }

    override val inTransaction: Boolean get() = delegate.inTransaction

    override var userVersion: Int
        get() = delegate.userVersion
        set(value) {
            delegate.userVersion = value
        }
}
