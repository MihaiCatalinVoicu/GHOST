package org.ghost.messaging

import org.ghost.crypto.bridge.DmNative
import org.ghost.crypto.bridge.DmSessions
import org.ghost.messaging.engine.BundleStep
import org.ghost.messaging.engine.ContactKeeper
import org.ghost.messaging.engine.ContactMaterial
import org.ghost.messaging.engine.ContactSteps
import org.ghost.messaging.engine.DisplayStep
import org.ghost.messaging.engine.DmActor
import org.ghost.messaging.engine.DmCounters
import org.ghost.messaging.engine.DmSyncPorts
import org.ghost.messaging.engine.EstablishmentSteps
import org.ghost.messaging.engine.ExpirySchedule
import org.ghost.messaging.engine.HeldReplay
import org.ghost.messaging.engine.KeyDecision
import org.ghost.messaging.engine.MessagingEngine
import org.ghost.messaging.engine.OutcomeStep
import org.ghost.messaging.engine.OwnerSteps
import org.ghost.messaging.engine.PairKeySteps
import org.ghost.messaging.engine.PeekOrder
import org.ghost.messaging.engine.ReceiveStep
import org.ghost.messaging.engine.RecognitionKeys
import org.ghost.messaging.engine.RelaySetResolver
import org.ghost.messaging.engine.ScheduledSteps
import org.ghost.messaging.engine.SelfContexts
import org.ghost.messaging.engine.SendStep
import org.ghost.messaging.engine.SessionSlots
import org.ghost.messaging.engine.Sweeper
import org.ghost.messaging.engine.UnreadNotices
import org.ghost.messaging.port.DmContext
import org.ghost.messaging.port.EsSlot
import org.ghost.messaging.port.EsSlots
import org.ghost.messaging.port.NativeDmCrypto
import org.ghost.messaging.port.NativeDmEnvelopes
import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import org.ghost.storage.SqlExecutor
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
    /**
     * When set, each device's database is a **file** under this directory, in WAL mode, instead of
     * the in-memory default.
     *
     * The T25 physical scan of §10.9 point 2 needs it: "the raw `.db` and `-wal` bytes contain
     * neither the plaintext canary, nor the `body_env` bytes, … nor the `message_id`", and an
     * in-memory database has no bytes to scan and no write-ahead log to truncate. Every other world
     * stays in memory, because a file costs a temporary directory per test and proves nothing the
     * in-memory one does not.
     */
    private val databaseDirectory: java.io.File? = null,
    /**
     * Wraps each device's `DmEnvelopes` port, by MESSAGING branch (slice S13): the PQ-C worlds
     * record what the engine sealed and encoded (the ground truth of PQ3, PQ4 and PQ6) and plant
     * their control mutant on this seam. Null keeps every world of S6–S12 byte for byte as it was.
     */
    private val decorate: ((Int, org.ghost.messaging.port.DmEnvelopes) -> org.ghost.messaging.port.DmEnvelopes)? =
        null,
) : AutoCloseable {

    /** The two devices. Distinct MESSAGING branches, so distinct identities and cards. */
    val alice: DmDevice = DmDevice(
        0x41, slotCount, operators, startSeconds, path = pathFor(0x41),
        decorateEnvelopes = decorate?.let { d -> { e: org.ghost.messaging.port.DmEnvelopes -> d(0x41, e) } },
    )
    val bob: DmDevice = DmDevice(
        0x51, slotCount, operators, startSeconds, path = pathFor(0x51),
        decorateEnvelopes = decorate?.let { d -> { e: org.ghost.messaging.port.DmEnvelopes -> d(0x51, e) } },
    )

    private fun pathFor(branch: Int): String? =
        databaseDirectory?.let { java.io.File(it, "dm-$branch.db").absolutePath }

    private val extra = ArrayList<DmDevice>()

    private var sequence = 1L

    /**
     * How far ahead of the store the model relay puts `InboundBlob.relayExpiryHour` — the **E** of
     * §10.3, which caps an unread message's deadline at `min(E, consume + bucket + 1 h)`.
     *
     * The default is the 30-day store-and-forward horizon, which is above every bucket, so the
     * second term wins and the world behaves like an honest relay serving a fresh blob. A test
     * lowers it to model a relay **lying short** (C-11: "a relay lying short can only make deletion
     * earlier, a denial of service it could cause by withholding anyway") and raises it to model
     * one lying long, which the second term clamps.
     */
    var relayExpirySeconds: Long = 30 * DAY

    /**
     * A device that holds [of]'s **`ghost1` Ed25519 seed** under a different MESSAGING branch: a
     * contact whose Olm identity changed (§8.3).
     *
     * That is the only shape a key change can take. §8.3's classification needs a signature valid
     * under the contact's **pinned** Ed25519 key over a *different* Olm identity, and §3.4 says
     * where such a signature comes from: "the holder of that Ed25519 secret signed another Olm
     * identity — the contact itself (including a modified client), a derivation-version change, or
     * a seed thief". This is that device. Anything that does not hold the Ed25519 secret produces
     * a **forgery**, which `openIntro` refuses before any of this code sees it.
     *
     * Its card carries the same `identity_pk` and a different `card_secret` (which is a MESSAGING
     * derivation), so the old device's inbox is not this one's — which is exactly what makes the
     * change one-directional until the user re-adds a card, and is R-20's declared behaviour.
     */
    /**
     * The **same identity on a fresh database**: a restore from the seed (§8.6).
     *
     * Every derivation survives — the `ghost1` key, the Olm identity, `card_secret_0`, `X_0`, `P_0`
     * and every credential — and nothing else does: contacts, cards, sessions, pair keys, the
     * lost device's generations, `dm_seen`, held rows, messages and scheduled controls are all
     * regenerated or gone, which is §8.6's own table.
     */
    fun restored(of: DmDevice): DmDevice {
        val device = DmDevice(
            branch = of.branch,
            slotCount = of.slotCount,
            operators = of.operators,
            startSeconds = of.clock.now,
            identityBranch = of.identityBranch,
            decorateEnvelopes = decorate?.let { d ->
                { e: org.ghost.messaging.port.DmEnvelopes -> d(of.branch, e) }
            },
        )
        extra += device
        return device
    }

    fun reincarnation(of: DmDevice, branch: Int): DmDevice {
        val device = DmDevice(
            branch = branch,
            slotCount = of.slotCount,
            operators = of.operators,
            startSeconds = of.clock.now,
            identityBranch = of.identityBranch,
        )
        extra += device
        return device
    }

    /** Moves the virtual clock of every device of the world. */
    fun advanceTo(seconds: Long) {
        for (device in devices()) {
            device.clock.now = seconds
            device.clock.monotonic += 1_000
        }
    }

    private fun devices(): List<DmDevice> = listOf(alice, bob) + extra

    /**
     * One relay round: every enqueued blob of each device lands in the inbox of whichever device
     * **listens** on its namespace.
     *
     * A device's own bundle namespace is registered `listen = false` (§5.1), so a bundle reaches
     * only the contact that registered it listening during `EST-START`; a DM reaches only the
     * inbox that owns the namespace. Nothing is delivered twice: the source row is marked so a
     * second [deliver] is a no-op, which is what makes a replay test have to ask for one.
     */
    fun deliver(): Int {
        var moved = 0
        for (to in devices()) for (from in devices()) if (from !== to) moved += deliverFrom(from, to)
        return moved
    }

    /**
     * One direction between any two devices of the world, for a three-device key-change flow.
     *
     * [again] serves a blob the recipient **already consumed once**, which is what a relay does
     * after `EST-START` forgets a bundle namespace's tombstones (§21.7 point 2: "a bundle consumed
     * during an earlier establishment must be fetchable again after a reset, a key change or a
     * re-added contact"). The relay never forgot the blob; this world's bookkeeping did, and that
     * is the only reason the flag exists. The recipient's own `inbox_blob` uniqueness still
     * refuses it while its tombstone lives, so a caller cannot use this to fake a replay — the
     * replay path is [redeliver], which inserts under a fresh model row.
     */
    fun deliverBetween(from: DmDevice, to: DmDevice, again: Boolean = false): Int =
        deliverFrom(from, to, again)

    /**
     * One direction only: what the **other** device has enqueued lands in [to]'s inbox.
     *
     * `NoReflexTest` needs it. Two worlds that are to differ only in what arrived at B must run
     * A's establishment identically — and A's establishment needs B's bundle — so "deliver" has to
     * be splittable by recipient rather than by round.
     */
    fun deliverTo(to: DmDevice): Int = deliverFrom(if (to === bob) alice else bob, to)

    /**
     * Loses everything [from] has enqueued so far on its way to [to]: a relay that dropped the
     * blobs (slice S13 review — a PQ-C offer whose message never arrives). Nothing is inserted,
     * and a later [deliver] does not bring them back. Returns how many were lost.
     */
    fun lose(from: DmDevice, to: DmDevice): Int {
        var lost = 0
        from.sql.query("SELECT operation_id, namespace_id FROM outbox_op ORDER BY rowid") {
            if (listens(to, it.blob(1)) && delivered.add(it.blob(0).toList() to to)) lost += 1
        }
        return lost
    }

    /**
     * Re-serves a blob that was already delivered, as a relay that lies about expiry or serves a
     * copy twice would (§7.6's four replay cases). The recipient must consume it and show nothing.
     */
    fun redeliver(from: DmDevice, to: DmDevice, namespace: ByteArray, ciphertext: ByteArray) {
        insert(to, namespace, ciphertext, from.clock.now)
    }

    /**
     * The `(operation_id, recipient)` pairs already moved, so a second [deliver] is a no-op.
     *
     * The recipient is part of the key because a world with three devices has two of them holding
     * the same `ghost1` identity — and, after [restored], two holding the **same** MESSAGING
     * branch, hence the same random stream and the same operation ids. An op keyed by its id alone
     * would then be "delivered" to whichever of them the loop reached first.
     */
    private val delivered = HashSet<Pair<List<Byte>, DmDevice>>()

    private fun deliverFrom(from: DmDevice, to: DmDevice, again: Boolean = false): Int {
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
            val fresh = delivered.add(operationId.toList() to to)
            if (!fresh && !again) continue
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
            listOf(ciphertext, sequence++, ceilHour(now + relayExpirySeconds), namespace, hash),
        )
    }

    override fun close() {
        for (device in devices()) device.close()
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
    /** The MESSAGING branch: the card, the namespaces, the read secrets and the Olm identity. */
    internal val branch: Int,
    internal val slotCount: Int,
    internal val operators: Int,
    startSeconds: Long,
    /**
     * The `ghost1` Ed25519 seed's branch, separate from [branch] so a world can build the one
     * device §8.3 calls a key change: the **same** identity key under a different Olm identity
     * (`DmWorld.reincarnation`). On every ordinary device it is `branch + 1`.
     */
    internal val identityBranch: Int = branch + 1,
    /** A file path for the T25 physical scan, or null for the in-memory default (see [DmWorld]). */
    private val path: String? = null,
    /**
     * S10's crash harness: an executor, a clock and a boot index the caller owns (§15.3).
     *
     * A reboot is "drop the uncommitted connection, reopen the same file, migrate,
     * `verifyIntegrity`, R-K1, **build a new client**", and the new client has to be a real
     * `DmDevice` over the *same* database file, the *same* virtual clock and a *different* random
     * stream. None of that is expressible while the device opens its own connection in its own
     * initialiser, so the harness supplies all three and this constructor uses them instead.
     *
     * When it is null nothing changes: the device opens, migrates and owns its own connection, and
     * every world of S6–S9 keeps the byte streams it had (the boot index leaves stream 0 alone).
     */
    val harness: HarnessOverride? = null,
    /**
     * S11's privacy worlds: explicit key material, because a world of 120 or 600 devices cannot
     * name its devices by one byte. When null, every derivation below keeps the one-byte `branch`
     * pattern every world of S6–S10 was built on, byte for byte.
     */
    val seeds: DeviceSeeds? = null,
    /**
     * Wraps the `DmEnvelopes` port of a device built without a [harness] (slice S13's PQ-C worlds;
     * see `DmWorld`'s `decorate`). A harness brings its own decorator, which wins.
     */
    decorateEnvelopes: ((org.ghost.messaging.port.DmEnvelopes) -> org.ghost.messaging.port.DmEnvelopes)? = null,
) : AutoCloseable {

    /**
     * The seeds of one device of a large world (Phase 9 design §15.6): the MESSAGING branch, the
     * `ghost1` Ed25519 seed, the `session_state_key` and the name of the Kotlin random stream. The
     * privacy world derives all four from its seed and the client's index, so two clients never
     * share one and a seed pair names one world.
     */
    class DeviceSeeds(
        val messagingBranch: ByteArray,
        val identitySeed: ByteArray,
        val sessionStateKey: ByteArray,
        val randomStream: String,
    ) {
        init {
            require(messagingBranch.size == 32 && identitySeed.size == 32 && sessionStateKey.size == 32)
        }
    }

    /** The three things the S10 crash harness owns instead of the device (see [harness]). */
    class HarnessOverride(
        val sql: SqlExecutor,
        val clock: MovableClock,
        /** 0 for the first boot; later boots draw from their own random stream. */
        val bootIndex: Int,
        /**
         * Wraps the device's `DmEnvelopes` port before anything is wired to it.
         *
         * Two things of §15.1 and §15.7 need it and nothing else can give it: the
         * `SimulatedNativeCrash` "thrown from the `DmNative` port during RECV", and the envelope
         * mutants, which §15.7 requires to live "only in `src/test`" — so they cannot be a flag on
         * the production port.
         */
        val decorate: ((org.ghost.messaging.port.DmEnvelopes) -> org.ghost.messaging.port.DmEnvelopes)? = null,
        /**
         * Wraps the device's `DmCrypto` port (S11): the ground-truth recorder of the privacy world
         * reads every own card and every contact card's derivations through it, and the privacy
         * mutant PM-3 (a namespace derived from public identity material) lives on this seam.
         */
        val decorateCrypto: ((org.ghost.messaging.port.DmCrypto) -> org.ghost.messaging.port.DmCrypto)? = null,
    )

    /** Null when [harness] supplied the executor: the harness closes what it opened. */
    private val ownExecutor: JdbcSqlExecutor? = if (harness != null) {
        null
    } else {
        JdbcSqlExecutor(path ?: ":memory:").also {
            MigrationRunner(it).migrate()
            // A `-wal` file exists only in WAL mode, and it is what §10.9 point 3 scans and what
            // `checkpointTruncate()` truncates. `GhostDatabase.finishOpen` does this on device.
            if (path != null) it.query("PRAGMA journal_mode = WAL") { }
        }
    }

    val sql: SqlExecutor = harness?.sql ?: requireNotNull(ownExecutor)

    /** The database file and its write-ahead log, for the physical scan (null in memory). */
    val databaseFile: java.io.File? get() = path?.let { java.io.File(it) }

    val walFile: java.io.File? get() = path?.let { java.io.File("$it-wal") }
    val database: SyncDatabase = SyncDatabase(sql)
    val clock: MovableClock = harness?.clock ?: MovableClock(startSeconds)
    val stores: SyncStores = SyncStores(database, clock, FixedRandomSources()) { PrivacyMode.STANDARD }
    // One stream per device: see `SequentialRandom`. Two devices sharing a stream produced a
    // `message_id` on one that was the 16-byte prefix of a `seen_key` on the other, which the T25
    // physical scan reads as a message surviving its own deletion.
    //
    // A reboot adds its boot index to the stream for the same reason: the process that comes back
    // draws fresh entropy on a device, and a stream restarted at counter 0 would hand the second
    // boot the ids the first one already committed.
    val random = SequentialRandom(
        branch,
        (seeds?.randomStream ?: "device-$branch-$identityBranch") +
            (harness?.bootIndex?.takeIf { it > 0 }?.let { "-b$it" } ?: ""),
    )
    val wrapper = FakeKeyWrapper()

    /** The real DM context: one per device, opened on this device's own MESSAGING branch. */
    private val handle: Long? = if (DmWorld.nativeAvailable()) {
        DmSessions.openContext(
            messagingBranch = seeds?.messagingBranch ?: ByteArray(32) { branch.toByte() },
            identitySeed = seeds?.identitySeed ?: ByteArray(32) { identityBranch.toByte() },
            sessionStateKey = seeds?.sessionStateKey ?: ByteArray(32) { (branch + 2).toByte() },
        )
    } else {
        null
    }

    private val stateKey: ByteArray =
        FakeKeyWrapper.PREFIX + (seeds?.sessionStateKey ?: ByteArray(32) { (branch + 2).toByte() })

    private val context = object : DmContext {
        override fun handleOrNull(): Long? = handle

        override fun stateKeyWrapped(): ByteArray? = if (handle != null) stateKey else null
    }

    val crypto: org.ghost.messaging.port.DmCrypto =
        NativeDmCrypto(context).let { harness?.decorateCrypto?.invoke(it) ?: it }
    val envelopes: org.ghost.messaging.port.DmEnvelopes =
        NativeDmEnvelopes(context).let {
            harness?.decorate?.invoke(it) ?: decorateEnvelopes?.invoke(it) ?: it
        }

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
    internal val sendStep = SendStep(
        database, dmSync, envelopes, material, relayResolver, clock, random, contexts,
        counters = counters,
    )
    internal val establishment = EstablishmentSteps(
        database, dmSync, envelopes, material, relayResolver, clock, contexts,
    )
    internal val bundleStep = BundleStep(envelopes, material, clock, contexts)
    internal val contactSteps = ContactSteps(database, crypto, random, contexts, establishment)
    internal val recognition = RecognitionKeys(envelopes)
    internal val receiveStep = ReceiveStep(
        database, dmSync, envelopes, crypto, material, recognition, SessionSlots(), clock, random,
        contexts, counters,
    )
    internal val peekOrder = PeekOrder(database, dmSync, envelopes, recognition, clock, contexts)
    internal val keyDecision = KeyDecision(database, crypto, contexts)
    internal val heldReplay = HeldReplay(database, envelopes, receiveStep, clock, contexts, counters)
    internal val scheduledSteps = ScheduledSteps(
        database, crypto, sendStep, establishment, clock, random, contexts,
    )
    internal val pairKeys = PairKeySteps(envelopes)
    internal val displayStep = DisplayStep(database, clock)

    /**
     * The `-wal` truncation of §10.7, wired to the **real** `Checkpoint.truncate` over this
     * device's executor — not to a stub. Mutants ME-10 ("checkpoint result ignored") and ME-11
     * ("no checkpoint") live on the other side of this line, and a world that faked it would prove
     * nothing about either.
     */
    val checkpoints = RecordingCheckpoint { org.ghost.storage.Checkpoint.truncate(sql) }

    /** Every wake the actor asked for (§10.7 triggers 1 and 5); null is a cancel. */
    val wakes = RecordingWake()

    /** Every unread count the notification port was given (§10.6, §10.7 Q19). */
    val notifications = RecordingNotifications()

    /** Every batch of ids SWEEP handed the media port inside its own transaction (§10.6). */
    val media = RecordingMedia()

    internal val sweeper = Sweeper(
        database = database,
        namespaces = stores.namespaces,
        envelopes = envelopes,
        pairKeys = pairKeys,
        checkpoint = checkpoints,
        clock = clock,
        contexts = contexts,
        media = media,
    )
    internal val notices = UnreadNotices { sweeper.unreadCount() }
    internal val schedule = ExpirySchedule(sweeper, wakes, notices)
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
            database, steps, contactSteps, sendStep, establishment, keyDecision, heldReplay,
            scheduledSteps, displayStep, schedule, counters, clock, contexts, recognition,
        )
        outcomeStep = OutcomeStep(database, dmSync, sendStep, clock)
        actor = DmActor(
            database = database,
            sync = dmSync,
            establishment = establishment,
            bundleStep = bundleStep,
            sendStep = sendStep,
            receiveStep = receiveStep,
            outcomeStep = outcomeStep,
            heldReplay = heldReplay,
            scheduledSteps = scheduledSteps,
            contactKeeper = ContactKeeper(database, dmSync, material, relayResolver, clock, contexts),
            sweeper = sweeper,
            schedule = schedule,
            ownerMaintenance = { engine.runOwnerMaintenance() },
            // §21.12 point 2's resume, wired to the **step** and not to the facade: the actor
            // calls it from inside a pass, and a facade call would post to the actor's own thread.
            // `restored = true` is the side that is safe in both cases; see `DmActor`.
            resumeActivation = {
                steps.activate(restored = true)
                contexts.invalidate()
                recognition.clear()
            },
            peekOrder = peekOrder,
            material = material,
            clock = clock,
            contexts = contexts,
        )
        // The world drives the pass directly, so the facade must not post to the actor's thread
        // and wait for it: every test here is single-threaded on purpose, and `DmActorTest` is
        // where the threading contract of §13.7 is checked on its own.
        engine.setNotificationPort(notifications)
    }

    /** The owner's own card, as the other device would scan it. */
    fun card(): ByteArray = requireNotNull(engine.myCard()) { "myCard" }.card

    /**
     * A **second** DM context over this device's secrets — its MESSAGING branch, `ghost1` seed and
     * `session_state_key` — which is what an adversary holding a dump of the device can call (the
     * PQ3 healing world, slice S13). It shares nothing with the device's own context but those
     * inputs, so nothing the device does afterwards reaches it. The caller closes it.
     */
    fun openLeakedContext(): Long? = if (DmWorld.nativeAvailable()) {
        DmSessions.openContext(
            messagingBranch = seeds?.messagingBranch ?: ByteArray(32) { branch.toByte() },
            identitySeed = seeds?.identitySeed ?: ByteArray(32) { identityBranch.toByte() },
            sessionStateKey = seeds?.sessionStateKey ?: ByteArray(32) { (branch + 2).toByte() },
        )
    } else {
        null
    }

    /** A time-triggered pass (§21.9 rule 1): the owner steps, establishment and the inbox. */
    fun timeTriggeredPass() {
        actor.runPass(timeTriggered = true, deadlineMonotonicMillis = null)
    }

    /** A hint-triggered pass: outcomes, bundles and the inbox, and nothing time-triggered. */
    fun hintPass() {
        actor.runPass(timeTriggered = false, deadlineMonotonicMillis = null)
    }

    /**
     * Every relay-visible effect this device has produced so far, as a comparable list.
     *
     * The projection has to cover **every** call gate G-DM2 restricts, or the behavioural half of
     * T28 is narrower than the static half it is supposed to back up. Three were missing and are
     * here now:
     *  - `namespace_relay`, which `Namespaces.setRelays` writes and nothing else read — a reflex
     *    that repointed a namespace's relay set on receipt of a blob was invisible, and that is
     *    not "wider than the wire", it is narrower than it;
     *  - `sync_namespace.send_delay`, which `Namespaces.setSendDelay` moves (the ADR-15 delay that
     *    keeps a store from naming the moment the user pressed send);
     *  - `outbox_op.outcome` and `outbox_delivery`, because `Outbox.cancel` does not delete an op:
     *    it fails the deliveries and sets the outcome.
     */
    fun relayVisible(): List<String> {
        val out = ArrayList<String>()
        sql.query(
            "SELECT hex(namespace_id), ttl_seconds, deadline_hour, length(ciphertext), outcome " +
                "FROM outbox_op ORDER BY rowid",
        ) {
            out += "store ${it.string(0)} ${it.long(1)} ${it.long(2)} ${it.long(3)} ${it.string(4)}"
        }
        sql.query(
            "SELECT hex(operation_id), relay_id, state FROM outbox_delivery " +
                "ORDER BY operation_id, relay_id",
        ) { out += "del ${it.string(0)} ${it.long(1)} ${it.string(2)}" }
        sql.query(
            "SELECT hex(namespace_id), consumer, listening, capability_source, send_delay " +
                "FROM sync_namespace ORDER BY namespace_id",
        ) {
            out += "ns ${it.string(0)} ${it.string(1)} ${it.long(2)} ${it.string(3)} ${it.string(4)}"
        }
        sql.query(
            "SELECT hex(namespace_id), relay_id FROM namespace_relay " +
                "ORDER BY namespace_id, relay_id",
        ) { out += "nsrelay ${it.string(0)} ${it.long(1)}" }
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
        ownExecutor?.close()
    }
}
