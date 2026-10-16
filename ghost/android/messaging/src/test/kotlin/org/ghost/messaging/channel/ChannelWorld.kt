package org.ghost.messaging.channel

import org.ghost.crypto.bridge.MlsNative
import org.ghost.messaging.DmWorld
import org.ghost.messaging.FakeKeyWrapper
import org.ghost.messaging.FixedRandomSources
import org.ghost.messaging.MovableClock
import org.ghost.messaging.OwnerWorld
import org.ghost.messaging.RecordingCheckpoint
import org.ghost.messaging.SequentialRandom
import org.ghost.messaging.api.ChannelId
import org.ghost.messaging.channel.engine.ChannelActor
import org.ghost.messaging.channel.engine.ChannelContexts
import org.ghost.messaging.channel.engine.ChannelCounters
import org.ghost.messaging.channel.engine.ChannelEngine
import org.ghost.messaging.channel.engine.ChannelEnv
import org.ghost.messaging.channel.engine.ChannelLocalKeys
import org.ghost.messaging.channel.engine.ChannelReceiveStep
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
 * The channel world of Phase 10's test plan (design §12.1): each client a real `:messaging` channel engine
 * over its own migrated v7 database and its own `:sync` stores, the **real** OpenMLS through `MlsNative`
 * loading `ghost-dm-host`, and a model relay ([ModelChannelRelay]) between them. S4 built it at 2 … 6
 * clients; slice S10 scales it to SCN-M20's 20 (§12.5) — nothing here bounds the client count, and a
 * [seedName] lets a restored stack (a new device holding the same seed) live beside the lost one.
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
     * Every KeyPackage ref the world saw published, by channel (hex channel id → hex refs): the
     * joiner's `ch_join` row is deleted when its join completes, so JC-1/JC-2's KeyPackage
     * material is recorded at the accept ([recordKeyPackage], the review of S11, §19.52 FIX 2/3 —
     * the ref is the KeyPackage's stored hash, the value JC-1's convention hashes).
     */
    private val keyPackageRefs = LinkedHashMap<String, LinkedHashSet<String>>()

    /** Records [client]'s just-published KeyPackage ref for [id] (its `ch_join` row lives until the join completes). */
    fun recordKeyPackage(client: ChannelClient, id: ChannelId) {
        client.sql.query("SELECT kp_ref FROM ch_join WHERE channel_id = ?", listOf(id.toByteArray())) {
            keyPackageRefs.getOrPut(ModelChannelRelay.hex(id.toByteArray())) { LinkedHashSet() } +=
                ModelChannelRelay.hex(it.blob(0))
        }
    }

    /** Every KeyPackage ref recorded for [id] ([recordKeyPackage]). */
    fun keyPackageRefsOf(id: ChannelId): List<ByteArray> =
        keyPackageRefs[ModelChannelRelay.hex(id.toByteArray())]?.map { ModelChannelRelay.unhex(it) } ?: emptyList()

    /**
     * A new client, named; its database in memory, or in the file [path] (which the client then owns and closes: what a
     * crash enumeration freezes, [ChannelWorld.restore]), or over the executor [sql] the caller owns.
     *
     * [seedName] overrides the name the client's **secrets** derive from (content and seen keys, the pseudonym
     * seeds, the DM identity): the new stack of a device swap (SCN-M20's restore, §12.5) is a different device —
     * its own random stream and relay name — holding the same seed, so it re-derives the removed device's
     * pseudonym and accepts the return invite as a restore (F-S7-2's row-holding flow). Null derives from [name].
     */
    fun client(
        name: String,
        sql: SqlExecutor? = null,
        boot: Int = 0,
        path: String? = null,
        /** The receive step's peek window: a narrower one puts the client's passes under pressure (§19.38). */
        peekLimit: Int = ChannelReceiveStep.PEEK_LIMIT,
        seedName: String? = null,
        /**
         * The privacy mode of the client's `:sync` stores (S11's HIGH-mode debt, §19.10): HIGH
         * delays each store by U[0, 10 min] at the enqueue (`outbox_op.not_before_minute`) and the
         * relay honours it ([ModelChannelRelay.delayedStores]); the default keeps every world of
         * S4 … S10 byte for byte (STANDARD).
         */
        privacyMode: PrivacyMode = PrivacyMode.STANDARD,
    ): ChannelClient {
        val client = ChannelClient(this, name, sql, boot, path, peekLimit, seedName, privacyMode)
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
     *
     * HIGH mode's send delays (§19.10): an op whose `not_before_minute` lies ahead waits at the
     * outbox ([ModelChannelRelay.delayedStores]); when nothing else moves and ops are still
     * pending, the world advances past the delay (at most 10 min) and takes another round —
     * what production's next pair event does at its own minute.
     */
    fun quiesce(rounds: Int = 12): Int {
        var moving = 0
        var waited = false
        repeat(rounds) {
            val moved = pump()
            for (c in clients) c.hintPass()
            if (moved == 0 && relay.pendingOps(clients) == 0) return moving
            if (moved == 0 && !waited) {
                waited = true
                advance(11 * DmWorld.MINUTE)
            }
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

    /**
     * Past the settle window of CO-4 (20 minutes), with one relay round and a time-triggered pass of
     * every client: the round is a completed listing pass over every relay of the set **after** the
     * window opened, which is CO-4 (ii)'s condition — without it the passes would find (i) held and
     * (ii) not, and settle nothing.
     */
    fun pastSettleWindow() {
        advance(21 * DmWorld.MINUTE)
        pump()
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

        /** Lowercase hex, table-driven (the per-byte format-based hex was a measured hot spot of the crash enumeration). */
        fun hex(bytes: ByteArray): String {
            val digits = "0123456789abcdef"
            val out = CharArray(bytes.size * 2)
            for (i in bytes.indices) {
                val b = bytes[i].toInt() and 0xff
                out[2 * i] = digits[b shr 4]
                out[2 * i + 1] = digits[b and 0x0f]
            }
            return String(out)
        }
    }
}

/** The user actions on the caller's thread: the world is single-threaded on purpose. */
internal object InlineActor : ChannelActor {
    override fun <T> call(body: () -> T): T = body()
}

/**
 * The inbox port of a world's client: everything delegates to the real `:sync` inbox but
 * [listingTails], which the world's relay feeds — a [ModelChannelRelay] round serves a client
 * everything the relay holds, which is one completed listing pass over every relay of the set,
 * the CO-4 (ii) signal (F-S4-1) the production read lane records. In-memory like the production
 * store: a client rebuilt over its database after a crash forgets every pass.
 */
internal class WorldInbox(private val delegate: org.ghost.sync.api.Inbox) : org.ghost.sync.api.Inbox {
    private val tails = HashMap<org.ghost.sync.api.RelayId, HashMap<List<Byte>, Long>>()

    /** Records a completed pass over [namespaces] at monotonic [atMillis] for every [relay]. */
    fun markPassed(namespaces: Collection<org.ghost.sync.api.NamespaceId>, relays: Collection<org.ghost.sync.api.RelayId>, atMillis: Long) {
        for (ns in namespaces) {
            val key = ns.toByteArray().toList()
            for (relay in relays) tails.getOrPut(relay) { HashMap() }[key] = atMillis
        }
    }

    override fun listingTails(namespace: org.ghost.sync.api.NamespaceId): Map<org.ghost.sync.api.RelayId, Long> {
        val key = namespace.toByteArray().toList()
        return tails.mapNotNull { (relay, byNs) -> byNs[key]?.let { relay to it } }.toMap()
    }

    override fun claim(consumer: org.ghost.sync.api.Consumer, limit: Int): List<org.ghost.sync.api.InboundBlob> = delegate.claim(consumer, limit)

    override fun peek(consumer: org.ghost.sync.api.Consumer, limit: Int): List<org.ghost.sync.api.PeekedBlob> = delegate.peek(consumer, limit)

    override fun claimOne(
        consumer: org.ghost.sync.api.Consumer,
        namespace: org.ghost.sync.api.NamespaceId,
        hash: org.ghost.sync.api.BlobHash,
    ): org.ghost.sync.api.InboundBlob? = delegate.claimOne(consumer, namespace, hash)

    override fun markConsumed(tx: org.ghost.sync.api.SyncTransaction, namespace: org.ghost.sync.api.NamespaceId, hash: org.ghost.sync.api.BlobHash): Boolean =
        delegate.markConsumed(tx, namespace, hash)

    override fun defer(tx: org.ghost.sync.api.SyncTransaction, namespace: org.ghost.sync.api.NamespaceId, hash: org.ghost.sync.api.BlobHash, seconds: Int): Boolean =
        delegate.defer(tx, namespace, hash, seconds)

    override fun reofferDeferred(tx: org.ghost.sync.api.SyncTransaction, namespace: org.ghost.sync.api.NamespaceId): Int =
        delegate.reofferDeferred(tx, namespace)

    override fun held(namespace: org.ghost.sync.api.NamespaceId, now: Long, limit: Int): List<org.ghost.sync.api.InboundBlob> =
        delegate.held(namespace, now, limit)

    override fun forgetConsumed(tx: org.ghost.sync.api.SyncTransaction, namespace: org.ghost.sync.api.NamespaceId): Int =
        delegate.forgetConsumed(tx, namespace)

    override fun setListener(listener: org.ghost.sync.api.SyncListener?) = delegate.setListener(listener)

    override fun toString(): String = "WorldInbox"
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
    peekLimit: Int = ChannelReceiveStep.PEEK_LIMIT,
    /**
     * The name the secret material derives from (null: [name]): a restored stack passes the lost device's
     * name here, so its pseudonym, content/seen keys and DM identity re-derive — while its random stream
     * stays its own (a new device never reuses another's draws).
     */
    seedName: String? = null,
    /** See [ChannelWorld.client]: HIGH mode's send delays at the enqueue (S11, §19.10). */
    privacyMode: PrivacyMode = PrivacyMode.STANDARD,
) : AutoCloseable {

    private val seedOf: String = seedName ?: name

    private val ownExecutor: JdbcSqlExecutor? =
        if (sql == null) JdbcSqlExecutor(path ?: ":memory:").also { MigrationRunner(it).migrate() } else null
    val sql: SqlExecutor = sql ?: requireNotNull(ownExecutor)

    /**
     * The file this client's database lives in (null when the caller passed an executor): what a
     * consistent snapshot reads through a fresh connection ([ChannelM20.snapshotOpenDb]) — a
     * `VACUUM INTO` on the live connection itself is refused (its cached prepared statements read
     * as statements in progress).
     */
    val dbPath: String? = if (sql == null) (path ?: ":memory:").takeIf { it != ":memory:" } else null
    val database = SyncDatabase(this.sql)
    val clock = MovableClock(world.now)
    val stores = SyncStores(database, clock, FixedRandomSources()) { privacyMode }
    val random = SequentialRandom(0, "channel-$name" + if (boot > 0) "-b$boot" else "")

    var slots: List<EsSlot>
    private val esSlots = EsSlots { slots }

    private val contentKey: ByteArray = ChannelWorld.sha256("content:$seedOf")
    private val seen: ByteArray = ChannelWorld.sha256("seen:$seedOf")
    val content = ContentCipher(contentKey)

    /** False makes the local keys unavailable, as a locked identity would (`CRYPTO_UNAVAILABLE`). */
    var unlocked = true

    val keys = object : ChannelLocalKeys {
        override fun content(): ContentCipher? = if (unlocked) content else null

        override fun seenKey(): ByteArray? = if (unlocked) seen.copyOf() else null
    }

    /** `ps` for a channel: what `:identity` derives from the root (here from the client's seed name, so a
     *  restore stack re-derives the lost device's pseudonym and a reboot keeps it). */
    val seeds = ChannelSeeds { channelId -> ChannelWorld.sha256("seed:$seedOf:" + ChannelWorld.hex(channelId)) }

    /**
     * The DM context §6.9's `revealSeal` signs with: the world's stand-in for the DM stack's
     * context, opened lazily over an identity derived from the client's name (so every client's
     * card and identity key differ and a reboot keeps them). Null-handle while locked, like the
     * DM context's. The MESSAGING branch is per-client too, like production's (`m` of each
     * identity): since slice S13b the channel self-update schedule keys its slot PRF by
     * `K_sched = HKDF(m, "ghost/v1/dm/channel-schedule")` (§6.4 CO-9, owner decision Q-F5-6), and
     * a branch shared by every client would give all of one channel's members the same slot.
     */
    private var dmHandle: Long? = null
    private var dmScheduleKey: ByteArray? = null
    private val dmContext = object : org.ghost.messaging.port.DmContext {
        override fun handleOrNull(): Long? = if (unlocked) openDm()?.first else null
        override fun stateKeyWrapped(): ByteArray? = null
        override fun channelScheduleKey(): ByteArray? =
            if (unlocked) openDm()?.second?.copyOf() else null
    }

    private fun openDm(): Pair<Long, ByteArray>? {
        dmHandle?.let { return it to dmScheduleKey!! }
        val opened = org.ghost.crypto.bridge.DmSessions.openContext(
            ChannelWorld.sha256("dm-branch:$seedOf"),
            // The identity persists across reboots and restores, like the pseudonym seed (a reboot
            // changes the random streams, never the identity): a revealed card must verify as the same
            // identity after the device crashed and came back.
            ChannelWorld.sha256("identity:$seedOf"),
            ChannelWorld.sha256("dm-state:$seedOf"),
        ) ?: return null
        dmHandle = opened.handle
        dmScheduleKey = opened.channelScheduleKey
        return opened.handle to opened.channelScheduleKey
    }

    /** The own contact card v2 (through the DM context): what a reveal of this client carries, and what a recipient's offer compares against. */
    fun ownCard(): ByteArray? {
        val h = openDm()?.first ?: return null
        return org.ghost.crypto.bridge.DmSessions.ownCard(h, 0)?.card
    }

    /** The (card, source) pairs the contact offer of §6.9 received (a copy each; the engine zeroes its own). */
    val offeredCards = ArrayList<Pair<ByteArray, org.ghost.messaging.store.ContactStore.Source>>()

    /**
     * What the world's contact offer answers — the stand-in for the DM layer's availability at
     * the offer (§19.48 FIX 3): `NOT_ACTIVATED`/`CRYPTO_UNAVAILABLE` stand for a locked or wiped
     * DM library, which the receive counts `REVEAL_OFFER_FAILED`.
     */
    var offerOutcome: org.ghost.messaging.engine.ContactSteps.AddResult = org.ghost.messaging.engine.ContactSteps.AddResult.ADDED

    val channelStores = ChannelStores()
    val counters = ChannelCounters()
    val contexts = ChannelContexts(database, channelStores, FakeKeyWrapper(), random, seeds)
    val inbox = WorldInbox(stores.inbox)
    val env: ChannelEnv
    /** The sweep's checkpoint port (§8.2): a test may make it busy or fail it to watch the debt retry (§10.7). */
    lateinit var checkpoint: RecordingCheckpoint

    val engine: ChannelEngine

    init {
        world.relay.onListed = { client, namespaces ->
            client.inbox.markPassed(namespaces, client.slots.map { it.relay }, client.clock.monotonic)
        }
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
        env = ChannelEnv(
            database, channelStores, contexts, keys, clock, random, esSlots, counters,
            dmContext = dmContext,
            contactOffer = { card, source ->
                offeredCards.add(card.copyOf() to source)
                offerOutcome
            },
        )
        val checkpoint = RecordingCheckpoint { org.ghost.storage.Checkpoint.truncate(this.sql) { } }
        this.checkpoint = checkpoint
        engine = ChannelEngine(
            env,
            ChannelSyncPorts(stores.namespaces, stores.capabilities, stores.registrations, stores.outbox, inbox, stores.funding),
            InlineActor,
            checkpoint = checkpoint,
            peekLimit = peekLimit,
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
        // Slice S7 (§6.7): an active channel may keep a rejoin row (the resync is a user action on
        // an active channel); a join or a restore's row on an active channel is still residue.
        sql.query(
            "SELECT 1 FROM ch_channel c WHERE c.state = 'active' AND EXISTS " +
                "(SELECT 1 FROM ch_join j WHERE j.channel_id = c.channel_id AND j.type != 'rejoin')",
        ) { problems += "an active channel that kept its join state" }
        return problems
    }

    /** What a crash leaves of the client: the native context's memory (the process died). */
    fun die() {
        contexts.close()
        dmHandle?.let { org.ghost.crypto.bridge.DmSessions.closeContext(it) }
        dmHandle = null
    }

    override fun close() {
        contexts.close()
        dmHandle?.let { org.ghost.crypto.bridge.DmSessions.closeContext(it) }
        dmHandle = null
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
