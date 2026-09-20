package org.ghost.messaging

import org.ghost.crypto.bridge.DmNative
import org.ghost.crypto.bridge.DmSessions
import org.ghost.messaging.engine.ContactKeeper
import org.ghost.messaging.engine.ContactMaterial
import org.ghost.messaging.engine.ContactSteps
import org.ghost.messaging.engine.DmActor
import org.ghost.messaging.engine.DmCounters
import org.ghost.messaging.engine.DmSyncPorts
import org.ghost.messaging.engine.EstablishmentSteps
import org.ghost.messaging.engine.MessagingEngine
import org.ghost.messaging.engine.OutcomeStep
import org.ghost.messaging.engine.OwnerSteps
import org.ghost.messaging.engine.PairKeySteps
import org.ghost.messaging.engine.PeekOrder
import org.ghost.messaging.engine.ReceiveStep
import org.ghost.messaging.engine.RecognitionKeys
import org.ghost.messaging.engine.RelaySetResolver
import org.ghost.messaging.engine.SelfContexts
import org.ghost.messaging.engine.SendStep
import org.ghost.messaging.engine.SessionSlots
import org.ghost.messaging.port.DmContext
import org.ghost.messaging.port.EsSlot
import org.ghost.messaging.port.EsSlots
import org.ghost.messaging.port.NativeDmCrypto
import org.ghost.messaging.port.NativeDmEnvelopes
import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.RelayEntry
import org.ghost.sync.api.SyncDatabase
import org.ghost.sync.store.SyncStores
import java.security.MessageDigest

/**
 * Two devices, the **real** DM cryptography, a real migrated v5 database each, and a delivery
 * model between them (Phase 9 design §15.1).
 *
 * > The seal, codec and PQ layer are in the same native library, so every DM world runs the
 * > production cryptography.
 *
 * **Why the crypto is real here and faked in [OwnerWorld].** The owner steps are about
 * transactions, guards and idempotence; a deterministic fake of a derivation proves exactly that.
 * Sending and receiving are about whether the **other side** can open what this side sealed — a
 * wrong wrap binding, a wrong direction byte, a wrong transcript input or a wrong mode all
 * compile, and all fail only as "the peer sees nothing". So this world runs `ghost-dm-host`
 * through the same closed surface the device uses, and skips where the library is absent, exactly
 * as `DmSessionsNativeTest` and `DmEnvelopeNativeTest` do.
 *
 * **What the delivery model is, and what it is not.** [deliver] moves each device's enqueued
 * blobs into the inbox of whichever device listens on that namespace, as a relay would, and
 * nothing more: it is the **envelope** path, not the Phase 7 engine. The outbox's own lanes,
 * leases, quorum and outcome machinery are Phase 7's and are proved by `sync-exit-gate`; the
 * `DmWorld` of §15.1 that drives the real engine against a `ModelRelay` is slice S10's. What this
 * world proves is what S7 owns: that A's envelope opens on B, in the mode §6.8 chose, and that
 * `RECV`'s twelve steps do what §7.4 says with the rows in front of them.
 */
class DmWorld(
    slotCount: Int = 4,
    operators: Int = 2,
    startSeconds: Long = WEEK_ORIGIN + 2_870 * WEEK + 2 * DAY,
) : AutoCloseable {

    /** The two devices. Distinct MESSAGING branches, so distinct identities and cards. */
    val alice: DmDevice = DmDevice(0x41, slotCount, operators, startSeconds)
    val bob: DmDevice = DmDevice(0x51, slotCount, operators, startSeconds)

    private var sequence = 1L

    /** Moves the virtual clock of both devices. */
    fun advanceTo(seconds: Long) {
        alice.clock.now = seconds
        bob.clock.now = seconds
        alice.clock.monotonic += 1_000
        bob.clock.monotonic += 1_000
    }

    /**
     * One relay round: every enqueued blob of each device lands in the inbox of whichever device
     * **listens** on its namespace.
     *
     * A device's own bundle namespace is registered `listen = false` (§5.1), so a bundle reaches
     * only the contact that registered it listening during `EST-START`; a DM reaches only the
     * inbox that owns the namespace. Nothing is delivered twice: the source row is marked so a
     * second [deliver] is a no-op, which is what makes a replay test have to ask for one.
     */
    fun deliver(): Int = deliverTo(bob) + deliverTo(alice)

    /**
     * One direction only: what the **other** device has enqueued lands in [to]'s inbox.
     *
     * `NoReflexTest` needs it. Two worlds that are to differ only in what arrived at B must run
     * A's establishment identically — and A's establishment needs B's bundle — so "deliver" has to
     * be splittable by recipient rather than by round.
     */
    fun deliverTo(to: DmDevice): Int = deliverFrom(if (to === bob) alice else bob, to)

    /**
     * Re-serves a blob that was already delivered, as a relay that lies about expiry or serves a
     * copy twice would (§7.6's four replay cases). The recipient must consume it and show nothing.
     */
    fun redeliver(from: DmDevice, to: DmDevice, namespace: ByteArray, ciphertext: ByteArray) {
        insert(to, namespace, ciphertext, from.clock.now)
    }

    /** The `operation_id`s already moved, so a second [deliver] is a no-op. */
    private val delivered = HashSet<List<Byte>>()

    private fun deliverFrom(from: DmDevice, to: DmDevice): Int {
        val blobs = ArrayList<Triple<ByteArray, ByteArray, ByteArray>>()
        from.sql.query(
            "SELECT operation_id, namespace_id, ciphertext FROM outbox_op ORDER BY rowid",
        ) { blobs += Triple(it.blob(0), it.blob(1), it.blob(2)) }
        var moved = 0
        for ((operationId, namespace, ciphertext) in blobs) {
            // The listening check comes **first**: a relay keeps a stored blob for its whole TTL,
            // so a namespace that starts listening later still lists what is already there. That
            // is exactly how `EST-START` finds a bundle the contact published before the scan, and
            // marking such a blob delivered here would model a relay that forgets it.
            if (!listens(to, namespace)) continue
            if (!delivered.add(operationId.toList())) continue
            insert(to, namespace, ciphertext, from.clock.now)
            moved += 1
        }
        return moved
    }

    private fun listens(device: DmDevice, namespace: ByteArray): Boolean {
        var found = false
        device.sql.query(
            "SELECT 1 FROM sync_namespace WHERE namespace_id = ? AND listening = 1",
            listOf(namespace),
        ) { found = true }
        return found
    }

    private fun insert(device: DmDevice, namespace: ByteArray, ciphertext: ByteArray, now: Long) {
        val hash = MessageDigest.getInstance("SHA-256").digest(ciphertext)
        var exists = false
        device.sql.query(
            "SELECT 1 FROM inbox_blob WHERE namespace_id = ? AND blob_hash = ?",
            listOf(namespace, hash),
        ) { exists = true }
        if (exists) return
        val retainUntilDay = ceil7(Math.floorDiv(now, DAY) + 24)
        // The Phase 7 schema makes a fetch a **two-step** transition and the model follows it: an
        // inbox row starts `listed` (`inbox_blob_insert`), moves to `fetched` with its ciphertext
        // (`inbox_blob_state`), and only a `fetched` row may carry a relay expiry (the two v4
        // triggers of §13.6 step 2). Writing the end state directly would be a model that the
        // real engine could not reach.
        device.sql.exec(
            "INSERT INTO inbox_blob(namespace_id, blob_hash, state, ciphertext, fetch_seq, " +
                "fetch_attempts, next_fetch_minute, offers, offer_after_minute, retain_until_day) " +
                "VALUES (?, ?, 'listed', NULL, NULL, 0, 0, 0, 0, ?)",
            listOf(namespace, hash, retainUntilDay),
        )
        device.sql.exec(
            "UPDATE inbox_blob SET state = 'fetched', ciphertext = ?, fetch_seq = ?, " +
                "relay_expiry_hour = ? WHERE namespace_id = ? AND blob_hash = ?",
            listOf(ciphertext, sequence++, ceilHour(now + 30 * DAY), namespace, hash),
        )
    }

    override fun close() {
        alice.close()
        bob.close()
    }

    companion object {
        /** Monday 1970-01-05 00:00 UTC, the Phase 8 grid origin. */
        const val WEEK_ORIGIN: Long = 345_600L
        const val MINUTE: Long = 60L
        const val HOUR: Long = 3_600L
        const val DAY: Long = 86_400L
        const val WEEK: Long = 604_800L

        /** True when `ghost-dm-host` is on the classpath (§2.7, §15.1). */
        fun nativeAvailable(): Boolean {
            val path = System.getProperty(DmNative.HOST_LIBRARY_PROPERTY)
            return !path.isNullOrEmpty() && DmNative.isAvailable()
        }

        fun ceilHour(seconds: Long): Long = -Math.floorDiv(-seconds, HOUR) * HOUR

        fun ceil7(day: Long): Long = -Math.floorDiv(-day, 7L) * 7L
    }
}

/** One device of a [DmWorld]: its own database, its own DM context, its own engine. */
class DmDevice(
    branch: Int,
    slotCount: Int,
    operators: Int,
    startSeconds: Long,
) : AutoCloseable {

    val sql: JdbcSqlExecutor = JdbcSqlExecutor().also { MigrationRunner(it).migrate() }
    val database: SyncDatabase = SyncDatabase(sql)
    val clock = MovableClock(startSeconds)
    val stores: SyncStores = SyncStores(database, clock, FixedRandomSources()) { PrivacyMode.STANDARD }
    val random = SequentialRandom(branch)
    val wrapper = FakeKeyWrapper()

    /** The real DM context: one per device, opened on this device's own MESSAGING branch. */
    private val handle: Long? = if (DmWorld.nativeAvailable()) {
        DmSessions.openContext(
            messagingBranch = ByteArray(32) { branch.toByte() },
            identitySeed = ByteArray(32) { (branch + 1).toByte() },
            sessionStateKey = ByteArray(32) { (branch + 2).toByte() },
        )
    } else {
        null
    }

    private val stateKey: ByteArray = FakeKeyWrapper.PREFIX + ByteArray(32) { (branch + 2).toByte() }

    private val context = object : DmContext {
        override fun handleOrNull(): Long? = handle

        override fun stateKeyWrapped(): ByteArray? = if (handle != null) stateKey else null
    }

    val crypto = NativeDmCrypto(context)
    val envelopes = NativeDmEnvelopes(context)

    var slots: List<EsSlot>
    private val esSlots = EsSlots { slots }

    internal val contexts = SelfContexts(database, crypto, wrapper)
    internal val material = ContactMaterial(crypto, contexts)
    internal val counters = DmCounters()
    private val relayResolver = RelaySetResolver(esSlots)
    private val dmSync = DmSyncPorts(
        stores.namespaces,
        stores.capabilities,
        stores.registrations,
        stores.outbox,
        stores.inbox,
    )

    internal val steps: OwnerSteps
    internal val contactSteps = ContactSteps(database, crypto, random, contexts)
    internal val sendStep = SendStep(
        database, dmSync, envelopes, material, relayResolver, clock, random, contexts,
    )
    internal val establishment = EstablishmentSteps(
        database, dmSync, envelopes, material, relayResolver, clock, contexts,
    )
    internal val recognition = RecognitionKeys(envelopes)
    internal val receiveStep = ReceiveStep(
        database, dmSync, envelopes, crypto, material, recognition, SessionSlots(), clock, random,
        contexts, counters,
    )
    internal val peekOrder = PeekOrder(database, dmSync, envelopes, recognition, clock, contexts)
    internal val engine: MessagingEngine
    internal val outcomeStep: OutcomeStep
    internal val actor: DmActor

    init {
        val relayIds = database.transaction { tx ->
            stores.relayDirectory.upsert(
                tx,
                (0 until slotCount).map { i ->
                    RelayEntry(
                        OwnerWorld.onion(i),
                        OwnerWorld.operatorId(i % operators),
                        RelayEntry.Source.CONFIG,
                    )
                },
            )
        }
        val ordered = (0 until slotCount).map { i -> relayIds.getValue(OwnerWorld.onion(i)) }
        slots = (0 until slotCount).map { i ->
            EsSlot(i, ordered[i], OwnerWorld.operatorId(i % operators))
        }
        steps = OwnerSteps(
            database = database,
            sync = OwnerSteps.SyncPorts(
                stores.namespaces, stores.capabilities, stores.registrations, stores.outbox,
            ),
            crypto = crypto,
            clock = clock,
            random = random,
            keyWrapper = wrapper,
            esSlots = esSlots,
        )
        engine = MessagingEngine(
            database, steps, contactSteps, sendStep, establishment, counters, clock, contexts,
        )
        outcomeStep = OutcomeStep(database, dmSync, sendStep, clock)
        actor = DmActor(
            database = database,
            sync = dmSync,
            establishment = establishment,
            sendStep = sendStep,
            receiveStep = receiveStep,
            outcomeStep = outcomeStep,
            pairKeys = PairKeySteps(database, envelopes, clock),
            contactKeeper = ContactKeeper(database, dmSync, material, relayResolver, clock, contexts),
            ownerMaintenance = { engine.runOwnerMaintenance() },
            peekOrder = peekOrder,
            material = material,
            clock = clock,
            contexts = contexts,
        )
        // The world drives the pass directly, so the facade must not post to the actor's thread
        // and wait for it: every test here is single-threaded on purpose, and `DmActorTest` is
        // where the threading contract of §13.7 is checked on its own.
    }

    /** The owner's own card, as the other device would scan it. */
    fun card(): ByteArray = requireNotNull(engine.myCard()) { "myCard" }.card

    /** A time-triggered pass (§21.9 rule 1): the owner steps, establishment and the inbox. */
    fun timeTriggeredPass() {
        actor.runPass(timeTriggered = true, deadlineMonotonicMillis = null)
    }

    /** A hint-triggered pass: outcomes, bundles and the inbox, and nothing time-triggered. */
    fun hintPass() {
        actor.runPass(timeTriggered = false, deadlineMonotonicMillis = null)
    }

    /** Every relay-visible effect this device has produced so far, as a comparable list. */
    fun relayVisible(): List<String> {
        val out = ArrayList<String>()
        sql.query(
            "SELECT hex(namespace_id), ttl_seconds, deadline_hour, length(ciphertext) " +
                "FROM outbox_op ORDER BY rowid",
        ) { out += "store ${it.string(0)} ${it.long(1)} ${it.long(2)} ${it.long(3)}" }
        sql.query(
            "SELECT hex(namespace_id), consumer, listening, capability_source FROM sync_namespace " +
                "ORDER BY namespace_id",
        ) { out += "ns ${it.string(0)} ${it.string(1)} ${it.long(2)} ${it.string(3)}" }
        sql.query(
            "SELECT relay_id, hex(namespace_id), kind, state, generation FROM relay_capability " +
                "ORDER BY relay_id, namespace_id, kind",
        ) {
            out += "cap ${it.long(0)} ${it.string(1)} ${it.string(2)} ${it.string(3)} ${it.long(4)}"
        }
        sql.query(
            "SELECT relay_id, hex(namespace_id), period_id, kind, state FROM relay_key_registration " +
                "ORDER BY relay_id, namespace_id, period_id, kind",
        ) {
            out += "reg ${it.long(0)} ${it.string(1)} ${it.long(2)} ${it.string(3)} ${it.string(4)}"
        }
        return out
    }

    override fun close() {
        handle?.let { DmSessions.closeContext(it) }
        actor.close()
        sql.close()
    }
}
