package org.ghost.messaging.media

import org.ghost.crypto.bridge.DmCards
import org.ghost.crypto.bridge.DmContent
import org.ghost.media.send.GhostTranscoder
import org.ghost.media.send.ImageStripper
import org.ghost.media.send.JpegCanonicalizer
import org.ghost.media.send.MediaFeeder
import org.ghost.media.send.MediaPreparer
import org.ghost.media.send.MediaSealerFactory
import org.ghost.media.send.PrepFailure
import org.ghost.media.send.SealedFragmentGroup
import org.ghost.media.send.SealedObject
import org.ghost.media.send.SealingChannel
import org.ghost.media.send.StreamSealer
import org.ghost.media.send.VideoExport
import org.ghost.media.send.VideoSource
import org.ghost.media.store.CiphertextFileSystem
import org.ghost.media.store.CiphertextFiles
import org.ghost.media.store.MediaBlobs
import org.ghost.media.store.MediaFragments
import org.ghost.media.store.MediaLimits
import org.ghost.media.store.MediaObjects
import org.ghost.media.store.MediaReconcile
import org.ghost.media.store.NameSource
import org.ghost.media.store.NioCiphertextFileSystem
import org.ghost.media.store.PreparingFiles
import org.ghost.media.store.ReconcileReport
import org.ghost.messaging.FakeDmCrypto
import org.ghost.messaging.FakeKeyWrapper
import org.ghost.messaging.FixedRandomSources
import org.ghost.messaging.MovableClock
import org.ghost.messaging.OwnerWorld
import org.ghost.messaging.SequentialRandom
import org.ghost.messaging.engine.ContactMaterial
import org.ghost.messaging.engine.DmSyncPorts
import org.ghost.messaging.engine.DmTime
import org.ghost.messaging.engine.MediaOpIds
import org.ghost.messaging.engine.MediaOrphanSteps
import org.ghost.messaging.engine.MediaReceiveSteps
import org.ghost.messaging.engine.MediaSteps
import org.ghost.messaging.engine.OutcomeStep
import org.ghost.messaging.port.MediaReaders.Chunked
import org.ghost.messaging.port.MediaReaders.Opened
import org.ghost.messaging.port.MediaReaders.Validated
import org.ghost.messaging.engine.OwnerSteps
import org.ghost.messaging.engine.RelaySetResolver
import org.ghost.messaging.engine.SelfContexts
import org.ghost.messaging.engine.SendStep
import org.ghost.messaging.port.DmContext
import org.ghost.messaging.port.DmEnvelopes
import org.ghost.messaging.port.NativeDmEnvelopes
import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.EnqueueResult
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.Outcome
import org.ghost.sync.api.Outbox
import org.ghost.sync.api.OutboxProgress
import org.ghost.sync.api.OutboundBlob
import org.ghost.sync.api.OutboundOutcome
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.SyncDatabase
import org.ghost.sync.store.SyncStores
import org.ghost.sync.api.SyncTransaction
import org.ghost.sync.api.TtlBucket
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicInteger

/**
 * `MediaWorld` (Phase 11 design §15.1): the sender pipeline's world — a real migrated v8 database
 * (file-backed, so a "reboot" reopens it), a real ciphertext directory behind a crash-injecting
 * file system, the real stores, `MediaSteps`, `MediaFeeder`, `MediaPreparer` and the real
 * `SealingChannel` (so the `tfdt` insertion, the chunking and the file protocol run on real
 * bytes), with deterministic fakes at the seams: the sandbox stripper and image decoder
 * (committed S0 goldens; the decoder records its requests, which is what proves the zero-click
 * rules), the video export (a committed golden canonical fMP4) and the sealer/reader pair
 * (contract-faithful JVM stand-ins over one manifest wire; the host build's
 * `testSealBeginWithKey` re-derivation is §15.6's relay fidelity, S9's concern — this world's
 * oracles are structural).
 *
 * The outbox is [ScriptedOutbox]; media deposits into `M_0` are [depositMedia]. The world is driven
 * single-threaded (the actor's seriality is the test's). A crash run: drive the scripted body,
 * [close], reopen with `MediaWorld(path, dir, relay)`, [reconcile], [assertSendInvariants],
 * resume or finish.
 */
internal class MediaWorld(
    val dbPath: String,
    val dir: File,
    val relay: ScriptedOutbox = ScriptedOutbox(),
    /**
     * S9: the privacy world gives every client its own salted identity ([SaltedCrypto]); every
     * other world keeps the shared default.
     */
    cryptoFactory: () -> org.ghost.messaging.port.DmCrypto = { FakeDmCrypto() },
    /** S9: the privacy world namespaces each client's sealer object ids (JM3's no-shared-key rule). */
    sealerClientIndex: Int = 0,
    /**
     * S9: the privacy world's devices share one readers registry — the stand-in judges a wire by
     * the object's own record (production: the native reader derives from `key_env`), so sharing
     * mirrors production across devices. Single-device worlds keep their own.
     */
    sharedReaders: FakeReaders? = null,
) : AutoCloseable {

    val sql: JdbcSqlExecutor = JdbcSqlExecutor(dbPath).also {
        MigrationRunner(it).migrate()
        // The device's journal mode (GhostDatabase sets WAL; the JDBC executor carries the rest
        // of the production pragmas on open): S8's EP-M suite scans the raw `.db`/`-wal` bytes.
        it.query("PRAGMA journal_mode = WAL") { }
    }
    val database: SyncDatabase = SyncDatabase(sql)
    val clock = MovableClock()
    val stores: SyncStores = SyncStores(database, clock, FixedRandomSources()) { PrivacyMode.STANDARD }
    val crypto = cryptoFactory()
    val random = SequentialRandom()
    val wrapper = FakeKeyWrapper()
    val contexts: SelfContexts by lazy { SelfContexts(database, crypto, wrapper) }

    /** The crash-injecting file system behind [files], for the scenario suites. */
    val crashFs = CrashableFileSystem(NioCiphertextFileSystem())
    val files: CiphertextFiles = CiphertextFiles(
        File(dir, "m"), crashFs, WorldNames(), MediaLimits.FREE_FLOOR_BYTES,
    ).also { it.open() }
    val preparing = PreparingFiles()
    val fragments = MediaFragments()
    val objects = MediaObjects(fragments)
    val blobs = MediaBlobs(fragments)
    private val reconcile = MediaReconcile(files, blobs, fragments)

    /** S6's reader seam: the registry the [FakeSealerFactory] records into and [FakeReaders] judges by. */
    val readers: FakeReaders = sharedReaders ?: FakeReaders()

    /** S6's decode seam: records every request (the zero-click oracle); can be told to fail. */
    val decoder = FakeDecoder()

    /** Every checkpoint the recipient steps asked for, in order (§11.1's caller). */
    val checkpointLog = ArrayList<Boolean>()

    private val sync = DmSyncPorts(
        stores.namespaces, stores.capabilities, stores.registrations, relay, stores.inbox,
    )

    /** The sync ports the recipient steps claim the scripted inbox through (tests that build their own steps). */
    val syncPorts: DmSyncPorts get() = sync

    /** The envelope seam: the owner world's closed-context shape, with a canned kind-5 encode.
     * Internal (not private) so a test can build the production `Sweeper` over this world. */
    internal val envelopes: DmEnvelopes =
        object : DmEnvelopes by NativeDmEnvelopes(object : DmContext {
            override fun handleOrNull(): Long? = null
            override fun stateKeyWrapped(): ByteArray? = null
            override fun channelScheduleKey(): ByteArray? = null
        }) {
            override fun encodeContent(
                kind: DmContent.Kind,
                messageId: ByteArray,
                authorMinute: Long,
                minuteIndex: Int,
                timerCode: Int,
                timerVersion: Long,
                quoteRef: ByteArray?,
                body: ByteArray,
                contactId: ByteArray,
                offerRootGen: Int,
                offerEnv: ByteArray,
                revocation: ByteArray,
                sessionReset: Boolean,
                pqKey: DmContent.PqKeyCandidate?,
                pqKeyFirst: Boolean,
            ): DmContent.Encoded = DmContent.Encoded.Ok(ByteArray(64) { 0x05 }, 4_096)
        }

    private val material: ContactMaterial by lazy { ContactMaterial(crypto, contexts) }
    private val slots: List<EsSlotLike>

    private val ownerSteps: OwnerSteps

    init {
        clock.now = NOW
        val relayIds = database.transaction { tx ->
            stores.relayDirectory.upsert(
                tx,
                (0 until 2).map { i ->
                    RelayEntryLike(OwnerWorld.onion(i), OwnerWorld.operatorId(i % 2), SourceLike.CONFIG)
                },
            )
        }
        slots = (0 until 2).map { i ->
            EsSlotLike(i, relayIds.getValue(OwnerWorld.onion(i)), OwnerWorld.operatorId(i % 2))
        }
        ownerSteps = OwnerSteps(
            database = database,
            sync = OwnerSteps.SyncPorts(stores.namespaces, stores.capabilities, stores.registrations, relay),
            crypto = crypto,
            clock = clock,
            random = random,
            keyWrapper = wrapper,
            esSlots = EsSlotsLike { slots },
        )
    }

    /** The steps under test. */
    val steps: MediaSteps = MediaSteps(
        database = database,
        sync = sync,
        crypto = crypto,
        envelopes = envelopes,
        material = material,
        relays = RelaySetResolver(EsSlotsLike { slots }),
        sendStep = SendStep(database, sync, envelopes, material, RelaySetResolver(EsSlotsLike { slots }), clock, random, contexts),
        feeder = MediaFeeder(files, objects, fragments, blobs, relay, MediaOpIds.sha256()),
        opIds = MediaOpIds.sha256(),
        clock = clock,
        random = random,
        contexts = contexts,
        mediaOrphans = MediaOrphanSteps(crypto, clock),
        // The FAILED-descriptor cleanup's after-commit half (§11.1, §13.5); the lambdas run at
        // deadline time, after the whole world exists.
        checkpoint = { realCheckpoint() },
        onSenderCopyErased = { receiveSteps.reconcile() },
    )

    /**
     * The sealer factory the world's [preparer] uses, exposed so the privacy world can script
     * classes 1…10 on its next object ([FakeSealerFactory.forceClass], S9).
     */
    val sealerFactory: FakeSealerFactory = FakeSealerFactory(readers, sealerClientIndex)

    /** The preparation pipeline over the fake ports. */
    val preparer: MediaPreparer = MediaPreparer(
        FakeStripper, FakeVideoExport, sealerFactory, JpegCanonicalizer { it.copyOf() },
        files, preparing,
    )

    /**
     * The recipient pipeline under test (slice S6): the real steps over the world's stores, files
     * and scripted inbox, with the fake reader/decoder seams and a recording checkpoint.
     */
    val receiveSteps: MediaReceiveSteps = MediaReceiveSteps(
        database = database,
        sync = sync,
        files = files,
        readers = readers,
        preparing = { preparing.snapshot() },
        checkpoint = { realCheckpoint() },
        contexts = contexts,
        clock = clock,
    )

    /**
     * F9's OUTCOME step over the world (slice S8): drives the descriptor outcomes whose terminal
     * ones trigger §6.4's view-once sender cleanup, with the world's recording checkpoint and the
     * recipient reconcile as the after-commit hooks.
     */
    val outcomeStep: OutcomeStep = OutcomeStep(
        database = database,
        sync = sync,
        sendStep = SendStep(database, sync, envelopes, material, RelaySetResolver(EsSlotsLike { slots }), clock, random, contexts),
        clock = clock,
        contexts = contexts,
        mediaOrphans = MediaOrphanSteps(crypto, clock),
        checkpoint = { realCheckpoint() },
        onSenderCopyErased = { receiveSteps.reconcile() },
    )

    /**
     * The §11.1 checkpoint over the world's executor — what the production wiring hands every
     * media component, and what the EP-M physical scans need to be real: the recording stub in
     * [checkpointLog] never truncates the log.
     */
    fun realCheckpoint(): Boolean {
        checkpointLog += true
        return org.ghost.storage.Checkpoint.truncate(sql)
    }

    /** The raw database file and its write-ahead log, for the EP-M byte scans. */
    fun dbFiles(): List<File> = listOf(File(dbPath), File("$dbPath-wal")).filter { it.isFile }

    /** The own media namespace `M_0`, registered `Consumer.MEDIA` at [activate]. */
    val m0: ByteArray by lazy { crypto.ownCard(0)!!.mediaNamespace }

    /**
     * What Phase 7 would hand `MEDIA-INGEST`: a fetched blob in `M_0`. Returns the blob's hash
     * (the identity every later row names).
     */
    fun depositMedia(bytes: ByteArray, relayExpirySeconds: Long = NOW + 7 * 86_400): ByteArray {
        require(bytes.size == MediaLimits.FRAGMENT_BYTES) { "a relay blob is exactly 64 KiB" }
        val hash = digest(bytes)
        val retain = -Math.floorDiv(-MediaLimits.day(relayExpirySeconds), 7) * 7
        // The trigger keeps relay_expiry_hour off INSERTs: listed first, then the recordFetched
        // shape (state + ciphertext + seq + retention + expiry in one UPDATE).
        database.transaction { tx ->
            tx.sql.exec(
                "INSERT INTO inbox_blob(namespace_id, blob_hash, state, retain_until_day) VALUES (?, ?, 'listed', ?)",
                listOf(m0, hash, retain),
            )
            tx.sql.exec(
                "UPDATE inbox_blob SET state = 'fetched', ciphertext = ?, " +
                    "fetch_seq = (SELECT COALESCE(MAX(fetch_seq), 0) + 1 FROM inbox_blob), " +
                    "retain_until_day = ?, relay_expiry_hour = ? " +
                    "WHERE namespace_id = ? AND blob_hash = ? AND state = 'listed'",
                listOf(bytes, retain, relayExpirySeconds - relayExpirySeconds % 3_600, m0, hash),
            )
        }
        return hash
    }

    /**
     * What RECV's kind-5 branch commits for a descriptor from a contact (§7.2): the kind-5 message
     * row (the caption) and the `awaiting` object, in one transaction. The D28 request rule —
     * calling this not at all — is the caller's, exactly as in `ReceiveStep`, and is proved at the
     * real RECV in `DmMediaReceiveTest`.
     */
    fun receiveDescriptor(
        contactId: ByteArray,
        descriptor: org.ghost.media.store.MediaDescriptor,
        keyEnv: ByteArray,
        relayExpiryHour: Long = NOW + 86_400,
        caption: String = "media",
        // S9: the privacy world runs the recipient countdown (EP-M's sweep erases the keys at
        // expiry — the seizure check). Default keeps every pre-S9 test's off-timer shape.
        timerCode: Int = 0,
        unreadDeadlineMinute: Long? = null,
    ): ByteArray {
        val messageId = random.bytes(16)
        // The S8 rule's order: the context resolves before the transaction.
        val self = contexts.get()!!
        val bodyEnv = self.content.seal(random.bytes(12), messageId, caption.toByteArray())
        database.transaction { tx ->
            var conversationId = ByteArray(0)
            tx.sql.query(
                "SELECT conversation_id FROM dm_conversation WHERE contact_id = ?",
                listOf(contactId),
            ) { conversationId = it.blob(0) }
            check(conversationId.isNotEmpty()) { "addContact first" }
            org.ghost.messaging.store.MessageStore().insertIncomingIfAbsent(
                tx = tx,
                messageId = messageId,
                conversationId = conversationId,
                kind = DmContent.Kind.MEDIA.wire,
                authorMinute = DmTime.floorMinute(clock.now),
                sortMinute = DmTime.floorMinute(clock.now),
                minuteIndex = 0,
                timerCode = timerCode,
                bodyEnv = bodyEnv,
                unreadDeadlineMinute = unreadDeadlineMinute,
            )
            objects.onDescriptor(
                tx = tx,
                messageId = messageId,
                contactId = contactId,
                descriptor = descriptor,
                keyEnv = keyEnv,
                incompleteAfterHour = relayExpiryHour,
            )
        }
        return messageId
    }

    /** ACTIVATE (idempotent per fresh database; a rebooted world must not call it again). */
    fun activate() {
        check(ownerSteps.activate(restored = false) == OwnerSteps.Result.DONE) { "ACTIVATE" }
    }

    /** A contact whose `M_c` the commit can derive and register; returns `M_c`. */
    fun addContact(contactId: ByteArray): ByteArray {
        val self = contexts.get()!!
        val card = crypto.ownCard(0)!!.card
        val cardEnv = self.content.seal(random.bytes(12), contactId, card)
        sql.exec(
            "INSERT INTO dm_contact(contact_id, identity_pk, card_env, card_index, trust_state, " +
                "source, establishment) VALUES (?, ?, ?, 0, 'unverified', 'link', 'card_only')",
            listOf(contactId, ByteArray(32) { 0x22 }, cardEnv),
        )
        sql.exec(
            "INSERT INTO dm_conversation(conversation_id, contact_id) VALUES (?, ?)",
            listOf(ByteArray(16) { 0x23 }, contactId),
        )
        val derived = crypto.deriveCard(card, 0) as DmCards.DeriveResult.Ok
        val ns = derived.values.mediaNamespace.copyOf()
        derived.values.clearSecrets()
        return ns
    }

    /** One reconcile pass (the maintenance a reboot runs). */
    fun reconcile(): ReconcileReport {
        val report = reconcile.run(database) { preparing.snapshot() }
        files.syncDirectory()
        return report
    }

    override fun close() {
        sql.close()
    }

    /** §15.3's SCN-MA invariants, checked after every reboot and at the end. */
    fun assertSendInvariants() {
        // 1. Every blob row names a whole file whose bytes hash to the row.
        database.transaction { tx ->
            val rows = ArrayList<Pair<ByteArray, ByteArray>>()
            tx.sql.query("SELECT blob_hash, file_name FROM media_blob") { r ->
                rows += r.blob(0) to r.blob(1)
            }
            for ((hash, name) in rows) {
                val bytes = files.read(name)
                check(bytes.size == MediaLimits.FRAGMENT_BYTES) { "a file is not whole" }
                check(MessageDigest.isEqual(digest(bytes), hash)) { "a file does not match its row's hash" }
            }
        }
        // 2. Every file is named by a row or reserved in `preparing` (no stray bytes).
        val named = database.transaction { tx ->
            val out = HashSet<String>()
            tx.sql.query("SELECT file_name FROM media_blob") { r -> out += hexOf(r.blob(0)) }
            out
        }
        for (listed in files.list()) {
            val finalName = CiphertextFiles.finalNameOfTemp(listed) ?: listed
            check(named.contains(finalName) || preparing.snapshot().contains(finalName)) {
                "a stray file survives: $listed"
            }
        }
        // 3. No key_env without every fragment of the object's class bound.
        database.transaction { tx ->
            val objects = ArrayList<Triple<ByteArray, Int, ByteArray?>>()
            tx.sql.query("SELECT object_id, class_code, key_env FROM media_object WHERE role = 'out'") { r ->
                objects += Triple(r.blob(0), r.long(1).toInt(), if (r.isNull(2)) null else r.blob(2))
            }
            for ((objectId, classCode, keyEnv) in objects) {
                val bound = tx.sql.let { s ->
                    var n = 0L
                    s.query(
                        "SELECT count(*) FROM media_fragment WHERE object_id = ? AND state = 'bound'",
                        listOf(objectId),
                    ) { r -> n = r.long(0) }
                    n
                }
                if (keyEnv != null) {
                    check(bound == MediaLimits.CLASSES[classCode] + 1L) {
                        "a keyed object without every fragment bound"
                    }
                }
            }
        }
    }

    companion object {
        /** The world's fixed clock second (Monday of week 2870 + 2 days, hour-aligned). */
        const val NOW: Long = 345_600L + 2_870L * 604_800L + 2 * 86_400L
    }
}

// The slot/relay types under their production names (kept as aliases so the world's construction
// reads exactly like the wiring's).
private typealias EsSlotLike = org.ghost.messaging.port.EsSlot
private typealias EsSlotsLike = org.ghost.messaging.port.EsSlots
private typealias RelayEntryLike = org.ghost.sync.api.RelayEntry
private typealias SourceLike = org.ghost.sync.api.RelayEntry.Source

internal fun digest(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

/** The store's `hex` is module-internal; this world keeps its own. */
internal fun hexOf(bytes: ByteArray): String {
    val digits = "0123456789abcdef"
    val out = StringBuilder(bytes.size * 2)
    for (b in bytes) out.append(digits[(b.toInt() shr 4) and 0xF]).append(digits[b.toInt() and 0xF])
    return out.toString()
}

private class WorldNames : NameSource {
    private val n = AtomicInteger(0)
    override fun next16(): ByteArray {
        val v = n.getAndIncrement()
        return ByteArray(16) { if (it < 4) (v ushr (8 * it)).toByte() else 0 }
    }
}

/** A crash-injecting file system: set [crashBeforeNext] and the next call dies mid-flight. */
internal class CrashableFileSystem(private val real: CiphertextFileSystem) : CiphertextFileSystem {
    @Volatile
    var crashBeforeNext = false

    /** When set, the call whose index in [trace] (1-based) equals this value dies mid-flight. */
    @Volatile
    var crashAtCall = -1
    val trace = ArrayList<String>()

    /** When set, [freeSpace] answers this instead of the disk's (the §7.5 floor's test seam). */
    @Volatile
    var freeSpaceBytes: Long? = null

    private fun maybeCrash() {
        if (crashBeforeNext) {
            crashBeforeNext = false
            throw java.io.IOException("crash point")
        }
        if (crashAtCall >= 0 && trace.size == crashAtCall) {
            throw java.io.IOException("crash point $crashAtCall")
        }
    }

    override fun makeDirectory(directory: File) = real.makeDirectory(directory)
    override fun list(directory: File): List<String> = real.list(directory)
    override fun exists(file: File): Boolean = real.exists(file)
    override fun read(file: File): ByteArray = real.read(file)
    override fun writeNew(file: File, bytes: ByteArray) {
        trace += "writeNew"
        maybeCrash()
        real.writeNew(file, bytes)
        maybeCrash()
    }
    override fun setTimes(file: File, lastModifiedMillis: Long, lastAccessMillis: Long) =
        real.setTimes(file, lastModifiedMillis, lastAccessMillis)
    override fun times(file: File) = real.times(file)
    override fun force(file: File) {
        trace += "force"
        maybeCrash()
        real.force(file)
        maybeCrash()
    }
    override fun rename(from: File, to: File) {
        trace += "rename"
        maybeCrash()
        real.rename(from, to)
        maybeCrash()
    }
    override fun delete(file: File): Boolean {
        trace += "delete"
        maybeCrash()
        return real.delete(file)
    }
    override fun syncDirectory(directory: File) = real.syncDirectory(directory)
    override fun freeSpace(directory: File): Long = freeSpaceBytes ?: real.freeSpace(directory)
}

/** The sandbox seam: the committed golden canonical JPEG (object and preview alike). */
internal object FakeStripper : ImageStripper {
    override fun strip(source: ByteArray, preview: Boolean, maxBytes: Int): ImageStripper.StripResult =
        ImageStripper.StripResult.Ok(Goldens.jpeg, 512, 336)
}

/** The video seam: the committed golden canonical fMP4 through the caller's real channel. */
internal object FakeVideoExport : VideoExport {
    override fun calibrate(): PrepFailure? = null

    override fun export(
        source: VideoSource,
        displayLandscape: Boolean,
        sourceDurationUs: Long,
        maxFps: Float,
        maxClass: Int,
        channel: SealingChannel,
        cancelled: () -> Boolean,
    ): GhostTranscoder.Outcome {
        val bytes = Goldens.video
        var at = 0
        while (at < bytes.size) {
            val end = minOf(bytes.size, at + 262_144)
            channel.write(java.nio.ByteBuffer.wrap(bytes, at, end - at))
            at = end
        }
        channel.close()
        return GhostTranscoder.Outcome.Ok(ByteArray(0), 1_280, 720)
    }
}

/**
 * The sealer seam: deterministic bytes unique per object (a second object must not collide on
 * a blob hash), hashes over the bytes themselves (self-consistent with the file oracles), and —
 * since S6 — the recording half of the reader seam: [finish] writes the manifest in
 * [FakeReaders]' wire and registers the object, so [FakeReaders] can judge a later open, bind or
 * verify the way the real reader judges AEAD (its own record, per object, never by arrival order).
 *
 * [forceClass] (S9): the media privacy world's scripted objects of classes 1…10 — the sealer pads
 * with zero-content chunk groups to the class's fragment count. Null keeps every existing world's
 * class-0 shape.
 */
internal class FakeSealerFactory(
    private val readers: FakeReaders,
    /** The privacy world gives every client a distinct id space so objects never collide across devices. */
    private val clientIndex: Int = 0,
) : MediaSealerFactory {
    private var n = 0

    /** The next begin seals to exactly this class (the world's scripted classes, §15.4). */
    var forceClass: Int? = null

    override fun begin(
        destId: ByteArray,
        kind: org.ghost.crypto.bridge.MediaCrypto.Kind,
        viewOnce: Boolean,
        maxClass: Int,
    ): MediaSealerFactory.Begun {
        val v = (clientIndex shl 16) or n++
        val objectId = ByteArray(16) { if (it < 4) (v ushr (8 * it)).toByte() else it.toByte() }
        // The stand-in's K_f (ADR-44 point 1's per-object key): digest-seeded from the factory's
        // unique (client, ordinal), carried per object so JM3's (K_f, object_id) clause runs over
        // the truth (the S9 review's finding 3 — the old clause keyed the wrapped keyEnv and never
        // fired; a deterministic-K_f sealer puts one K_f on many object ids and fires the clause).
        // The real K_f's relay-side fidelity is the gate follow-up (F-S9-1's declared layer).
        val kf = digest(
            "ghost-media-world kf".toByteArray() +
                byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte()),
        )
        return MediaSealerFactory.Begun.Ok(FakeSealer(objectId, kind, viewOnce, readers, forceClass, kf), objectId)
    }
}

/**
 * Emits exactly the four chunks (16 fragments, class 0) every object of this world seals: the
 * content's chunks, then zero padding groups — what the real sealer's class rounding does. The
 * manifest carries the real fragment hashes in [FakeReaders]' wire, so a bind or verify against
 * it exercises the same hash-and-authenticate order the native reader has. With [forceClass] the
 * padding targets that class's fragment count instead (S9's scripted objects).
 */
private class FakeSealer(
    private val objectId: ByteArray,
    private val kind: org.ghost.crypto.bridge.MediaCrypto.Kind,
    private val viewOnce: Boolean,
    private val readers: FakeReaders,
    private val forceClass: Int? = null,
    /** The stand-in's per-object K_f (see [FakeSealerFactory.begin]); carried to the truth for JM3. */
    private val kf: ByteArray = ByteArray(0),
) : StreamSealer {
    private var consumed = 0L
    private var next = 0
    private val groups = ArrayList<SealedFragmentGroup>()

    /** The class this sealer targets: [forceClass] or 0. */
    private val targetClass: Int get() = forceClass ?: 0

    /** The chunk groups the target class needs: ceil(fragments / 4); class 0 = 16 fragments = 4. */
    private val targetGroups: Int get() = (MediaLimits.CLASSES[targetClass] + 3) / 4

    override fun append(plaintext: ByteArray): List<SealedFragmentGroup> {
        consumed += plaintext.size
        val completed = (consumed / MediaLimits.CHUNK_PLAINTEXT).toInt()
        val out = ArrayList<SealedFragmentGroup>()
        while (next < completed) {
            val group = group(next++)
            groups += group
            out += group
        }
        return out
    }

    override fun finish(preview: ByteArray): SealedObject {
        val tail = consumed % MediaLimits.CHUNK_PLAINTEXT != 0L
        val finishGroups = ArrayList<SealedFragmentGroup>()
        if (tail || next == 0) {
            val group = group(next++)
            groups += group
            finishGroups += group
        }
        while (next < targetGroups) {
            val group = group(next++)
            groups += group
            finishGroups += group
        }
        val hashes = groups.flatMap { it.hashes }
        val keyEnv = FakeReaders.fakeKeyEnvOf(objectId)
        val manifest = FakeReaders.manifestBytes(
            objectId = objectId,
            kindCode = if (kind == org.ghost.crypto.bridge.MediaCrypto.Kind.IMAGE) 1 else 2,
            viewOnce = viewOnce,
            classCode = targetClass,
            contentLen = consumed,
            width = 1_280,
            height = 720,
            durationMs = 0,
            preview = preview,
            hashes = hashes,
        )
        readers.register(
            FakeReaders.Recorded(
                objectId = objectId,
                keyEnv = keyEnv,
                kf = kf.copyOf(),
                chunks = groups.map { it.fragments },
                kind = kind,
                viewOnce = viewOnce,
                classCode = targetClass,
                contentLen = consumed,
                width = 1_280,
                height = 720,
                durationMs = 0,
                preview = preview,
            ),
        )
        return SealedObject(
            classCode = targetClass,
            contentLen = consumed,
            width = 1_280,
            height = 720,
            durationMs = 0,
            keyEnv = keyEnv,
            manifestBlob = manifest,
            manifestHash = digest(manifest),
            preview = preview,
            finishGroups = finishGroups,
        )
    }

    override fun abort() = Unit

    private fun group(index: Int): SealedFragmentGroup {
        val seed = objectId[0].toInt() and 0xFF
        val fragments = List(4) { k -> syntheticFragment(objectId, index, k) }
        return SealedFragmentGroup(index, fragments, fragments.map { digest(it) })
    }
}

/**
 * The deterministic per-(object, chunk, fragment) 64 KiB blob the sealer emits and the model
 * relay re-derives a stored blob from (§15.1's recipe rule: the relay holds (object, ordinal)
 * and re-derives bytes on get). Every blob's bytes are seeded by a digest of (object, chunk,
 * fragment) — an arithmetic pattern (`objectId[i]*31 + chunk*7 + fragment*13 + i%251`) collided
 * for in-range (chunk, fragment) pairs at class ≥ 8 (7·31 + 13·3 = 256 ≡ 0, duplicate blob
 * hashes, ROW_EXISTS at commit — the privacy world's first class-7 send caught it, F-S9-1).
 * Test-only: the gate fidelity of re-sealing through the host build's `testSealBeginWithKey`
 * (real K_f, real AEAD) is the gate's follow-up.
 */
internal fun syntheticFragment(objectId: ByteArray, chunk: Int, fragment: Int): ByteArray {
    val seed = digest(
        objectId + byteArrayOf((chunk ushr 8).toByte(), chunk.toByte(), fragment.toByte()),
    )
    return ByteArray(MediaLimits.FRAGMENT_BYTES) { i -> (seed[i % seed.size].toInt() + (i % 251)).toByte() }
}

/**
 * The reader seam (S6): a contract-faithful judge over [Recorded] objects. `open` checks the
 * manifest's hash, wire and descriptor agreement, then the key envelope against the object's own
 * record; `chunk` (validate) enforces the manifest's per-ordinal hashes first and the object's own
 * sealed bytes second — the AEAD order — so a hash-squatting object (a manifest naming another
 * sender's hashes, whose rows therefore bind the honest files) fails on the second check while the
 * honest object verifies from the same files (§7.2's "ownership is decided by authentication").
 */
internal class FakeReaders : org.ghost.messaging.port.MediaReaders {

    class Recorded(
        val objectId: ByteArray,
        val keyEnv: ByteArray,
        /**
         * The stand-in's raw K_f for the object (the sealer's own; null where a test builds a
         * record by hand — JM3's K_f clause skips those, they never enter the privacy truth).
         */
        val kf: ByteArray? = null,
        /** The sealed chunks: chunk → its four fragments, in order. */
        val chunks: List<List<ByteArray>>,
        val kind: org.ghost.crypto.bridge.MediaCrypto.Kind,
        val viewOnce: Boolean,
        val classCode: Int,
        val contentLen: Long,
        val width: Int,
        val height: Int,
        val durationMs: Long,
        val preview: ByteArray,
    )

    val registry = LinkedHashMap<String, Recorded>()

    private var nextHandle = 1L

    private class OpenState(
        val record: Recorded,
        val manifestHashes: List<ByteArray>,
        val readable: Boolean,
        var nextIndex: Int = 0,
    )

    private val open = HashMap<Long, OpenState>()

    fun register(record: Recorded) {
        registry[hexOf(record.objectId)] = record
    }

    override fun open(spec: org.ghost.messaging.port.MediaReaders.OpenSpec): Opened {
        if (digest(spec.manifestBlob).zip(spec.manifestHash).any { (a, b) -> a != b } ||
            spec.manifestBlob.size != MediaLimits.FRAGMENT_BYTES
        ) {
            return Opened.HashMismatch
        }
        val parsed = parseManifest(spec.manifestBlob) ?: return Opened.NonCanonical
        if (!parsed.objectId.contentEquals(spec.objectId)) return Opened.NonCanonical
        val specKind = if (spec.kind == org.ghost.crypto.bridge.MediaCrypto.Kind.IMAGE) 1 else 2
        if (parsed.kindCode != specKind || parsed.viewOnce != spec.viewOnce || parsed.classCode != spec.classCode) {
            return Opened.NonCanonical
        }
        val record = registry[hexOf(parsed.objectId)] ?: return Opened.CommitMismatch
        if (!record.keyEnv.zip(spec.keyEnv).all { (a, b) -> a == b }) return Opened.StateCorrupt
        val handle = nextHandle++
        open[handle] = OpenState(record, parsed.hashes, spec.readable)
        return Opened.Ok(
            reader = handle,
            kind = record.kind,
            viewOnce = record.viewOnce,
            classCode = record.classCode,
            contentLen = record.contentLen,
            width = record.width,
            height = record.height,
            durationMs = record.durationMs,
            preview = parsed.preview,
            hashes = parsed.hashes,
        )
    }

    override fun chunk(
        reader: Long,
        index: Int,
        fragments: ByteArray,
        validate: Boolean,
    ): Chunked {
        val state = open[reader] ?: return Chunked.Unavailable
        if (!validate && !state.readable) return Chunked.Sequence
        if (index < 0 || index >= state.record.chunks.size) return Chunked.IndexRange
        if (state.nextIndex != index) return Chunked.Sequence
        if (fragments.size != 4 * MediaLimits.FRAGMENT_BYTES) return Chunked.NonCanonical
        val sealed = state.record.chunks[index]
        for (k in 0 until 4) {
            val frag = fragments.copyOfRange(k * MediaLimits.FRAGMENT_BYTES, (k + 1) * MediaLimits.FRAGMENT_BYTES)
            val named = state.manifestHashes[index * 4 + k]
            if (!digest(frag).zip(named).all { (a, b) -> a == b }) return Chunked.HashMismatch
            if (!frag.zip(sealed[k]).all { (a, b) -> a == b }) return Chunked.NotOpen
        }
        state.nextIndex += 1
        return Chunked.Ok(if (validate) ByteArray(0) else fragments.copyOf())
    }

    override fun finish(reader: Long): Validated {
        val state = open[reader] ?: return Validated.Unavailable
        return if (state.nextIndex == state.record.chunks.size) Validated.Ok else Validated.NonCanonical
    }

    override fun close(reader: Long) {
        open.remove(reader)
    }

    /** How many native readers are open right now: the R4 leak oracle. */
    fun openCount(): Int = open.size

    class ParsedManifest(
        val objectId: ByteArray,
        val kindCode: Int,
        val viewOnce: Boolean,
        val classCode: Int,
        val preview: ByteArray,
        val hashes: List<ByteArray>,
    )

    companion object {
        private val MAGIC = byteArrayOf('G'.code.toByte(), 'F'.code.toByte(), 'M'.code.toByte(), 1)

        /** The fake envelope: a deterministic 60-byte function of the object, distinguishable per object. */
        fun fakeKeyEnvOf(objectId: ByteArray): ByteArray {
            val d = digest("fake-key-env".toByteArray() + objectId)
            return (d + d).copyOf(60)
        }

        /**
         * The fake manifest wire (65536 bytes): the fields a bind needs, then the fragment
         * hashes. Everything past the object id is masked with a per-object keystream (S9): the
         * blob stands in for the sealed manifest, and production's blob is AEAD ciphertext —
         * two objects with the same canned preview must not present identical bytes (the
         * privacy world's JM3 window check caught the plaintext wire leaking them, F-S9-3).
         */
        fun manifestBytes(
            objectId: ByteArray,
            kindCode: Int,
            viewOnce: Boolean,
            classCode: Int,
            contentLen: Long,
            width: Int,
            height: Int,
            durationMs: Long,
            preview: ByteArray,
            hashes: List<ByteArray>,
        ): ByteArray {
            val out = ByteArray(MediaLimits.FRAGMENT_BYTES)
            MAGIC.copyInto(out, 0)
            objectId.copyInto(out, 4)
            out[20] = kindCode.toByte()
            out[21] = (if (viewOnce) 1 else 0).toByte()
            out[22] = classCode.toByte()
            var at = 24
            for (shift in 56 downTo 0 step 8) out[at++] = (contentLen ushr shift).toByte()
            out[32] = (width ushr 8).toByte(); out[33] = width.toByte()
            out[34] = (height ushr 8).toByte(); out[35] = height.toByte()
            out[36] = (durationMs ushr 24).toByte(); out[37] = (durationMs ushr 16).toByte()
            out[38] = (durationMs ushr 8).toByte(); out[39] = durationMs.toByte()
            out[40] = (preview.size ushr 8).toByte(); out[41] = preview.size.toByte()
            preview.copyInto(out, 42)
            at = 42 + preview.size
            for (hash in hashes) {
                hash.copyInto(out, at)
                at += 32
            }
            val mask = manifestMask(objectId)
            for (i in 20 until out.size) out[i] = (out[i].toInt() xor mask[i].toInt()).toByte()
            return out
        }

        /** The per-object keystream: digest-chained, so every object's mask is its own. */
        private fun manifestMask(objectId: ByteArray): ByteArray {
            val out = ByteArray(MediaLimits.FRAGMENT_BYTES)
            var at = 0
            var ctr = 0
            while (at < out.size) {
                val block = digest("fake-manifest-mask".toByteArray() + objectId + byteArrayOf(ctr++.toByte()))
                block.copyInto(out, at)
                at += block.size
            }
            return out
        }

        fun parseManifest(bytes: ByteArray): ParsedManifest? {
            if (bytes.size != MediaLimits.FRAGMENT_BYTES) return null
            if (!bytes.copyOfRange(0, 4).contentEquals(MAGIC)) return null
            val objectId = bytes.copyOfRange(4, 20)
            val mask = manifestMask(objectId)
            val plain = ByteArray(bytes.size) { i ->
                if (i < 20) bytes[i] else (bytes[i].toInt() xor mask[i].toInt()).toByte()
            }
            val previewLen = ((plain[40].toInt() and 0xFF) shl 8) or (plain[41].toInt() and 0xFF)
            val hashesStart = 42 + previewLen
            val hashes = ArrayList<ByteArray>()
            var at = hashesStart
            while (at + 32 <= plain.size && !(plain[at].toInt() == 0 && plain.copyOfRange(at, at + 32).all { it.toInt() == 0 })) {
                hashes += plain.copyOfRange(at, at + 32)
                at += 32
            }
            if (hashes.isEmpty()) return null
            return ParsedManifest(
                objectId = objectId,
                kindCode = plain[20].toInt(),
                viewOnce = plain[21].toInt() == 1,
                classCode = plain[22].toInt(),
                preview = plain.copyOfRange(42, hashesStart),
                hashes = hashes,
            )
        }
    }
}

/** The decode seam (S6): records every request — the zero-click oracle — and serves canned pixels. */
internal class FakeDecoder : org.ghost.media.send.ImageDecoder {
    /** (jpeg size, maxW, maxH) per request; the bytes themselves stay unnamed. */
    val requests = ArrayList<Triple<Int, Int, Int>>()

    /** Fail the next this many requests, then serve again (CS-M8's two-strikes). */
    var failuresLeft: Int = 0

    /** The canned answer's geometry. */
    var cannedWidth: Int = 320
    var cannedHeight: Int = 200

    override fun decode(jpeg: ByteArray, maxW: Int, maxH: Int): org.ghost.media.send.ImageDecoder.Decoded? {
        requests += Triple(jpeg.size, maxW, maxH)
        if (failuresLeft > 0) {
            failuresLeft -= 1
            return null
        }
        return org.ghost.media.send.ImageDecoder.Decoded(
            ByteArray(cannedWidth * cannedHeight * 4) { 0x5A }, cannedWidth, cannedHeight,
        )
    }
}

/** The committed goldens the fakes serve. */
internal object Goldens {
    private const val DIR = "../../protocol/test-vectors/media-goldens/media3-1.11.1/api35-emulator"
    val jpeg: ByteArray by lazy { File(DIR, "strip_orient1.jpg").canonicalFile.readBytes() }
    val video: ByteArray by lazy { File(DIR, "quad_land.fmp4").canonicalFile.readBytes() }
}

/**
 * The scripted relay (Phase 7's outbox port): enqueues are recorded by op id (deterministic, so a
 * repeated feed answers [EnqueueResult.AlreadyEnqueued]); [outcomes] drains the scripted
 * decisions; [release] is exactly-once per process, and after a reboot the media stores' guarded
 * transitions make a re-application a no-op — the release-first contract of §6.4.
 */
internal class ScriptedOutbox : Outbox {
    class Scripted(val operationId: org.ghost.sync.api.OperationId, val outcome: Outcome, val resendNotAfter: Long?)

    private val enqueued = LinkedHashMap<String, NamespaceId>()
    private val released = HashSet<String>()
    private val script = ArrayDeque<Scripted>()

    /** The descriptor (and any other DM) outcomes, drained by `OutcomeStep` (slice S8). */
    private val dmScript = ArrayDeque<Scripted>()

    /** The outcomes drained so far, by op id: release() decides the row before releasing it
     * (outbox_op_release refuses a release while the outcome is 'pending'). */
    private val decided = HashMap<String, Outcome>()

    /** What the relay holds, for the oracles: op id → namespace. */
    val held: Map<String, NamespaceId> get() = enqueued

    /** The (namespace, ciphertext-hash) pairs the relay holds: Phase 7's uniqueness key. */
    private val byBytes = HashSet<String>()

    fun script(operationId: org.ghost.sync.api.OperationId, outcome: Outcome, resendNotAfter: Long? = null) {
        script += Scripted(operationId, outcome, resendNotAfter)
    }

    /** A DM-consumer outcome (the descriptor's op): drained by `outcomes(Consumer.DM)`. */
    fun scriptDm(operationId: org.ghost.sync.api.OperationId, outcome: Outcome, resendNotAfter: Long? = null) {
        dmScript += Scripted(operationId, outcome, resendNotAfter)
    }

    /** The deterministic op id the steps will derive for (object, ordinal, generation, resend). */
    fun opIdOf(objectId: ByteArray, ordinal: Int, gen: Int = 0, resend: Int = 0) =
        org.ghost.sync.api.OperationId(MediaOpIds.sha256().of(objectId, ordinal, gen, resend))

    override fun enqueue(tx: SyncTransaction, blob: OutboundBlob): EnqueueResult {
        val key = hexOf(blob.operationId.toByteArray())
        // Phase 7's rule (outbox_op UNIQUE (namespace_id, blob_hash), D2's frozen bytes): the
        // same ciphertext bytes are one operation in a namespace, whatever op id names them.
        // F-S5-19: the design's per-retry-generation op ids collide with this for a retried
        // ordinal's identical bytes — recorded for the owner; the world mirrors the store.
        val bytesKey = hexOf(blob.namespace.toByteArray()) + ":" +
            hexOf(java.security.MessageDigest.getInstance("SHA-256").digest(blob.ciphertext))
        if (!byBytes.add(bytesKey)) return EnqueueResult.AlreadyEnqueued
        if (enqueued.put(key, blob.namespace) != null) return EnqueueResult.AlreadyEnqueued
        // F-S5-16: a real outbox_op row, so MEDIA_ORPHAN_OP_BLOCKERS is live in the world — an op
        // the relay still holds (released = 0) must block the M_c orphan rule, as production's join
        // does (the memory-only shape made the clause vacuous and the orphan fired early).
        tx.sql.exec(
            "INSERT INTO outbox_op(operation_id, namespace_id, blob_hash, ciphertext, ttl_seconds, " +
                "not_before_minute, deadline_hour, required_operators, outcome, released) " +
                "VALUES (?, ?, ?, ?, ?, 0, ?, 2, 'pending', 0)",
            listOf(
                blob.operationId.toByteArray(),
                blob.namespace.toByteArray(),
                java.security.MessageDigest.getInstance("SHA-256").digest(blob.ciphertext),
                blob.ciphertext,
                blob.ttl.seconds.toLong(),
                blob.deadlineEpochSeconds ?: 0L,
            ),
        )
        return EnqueueResult.Enqueued
    }

    override fun cancel(tx: SyncTransaction, operationId: org.ghost.sync.api.OperationId): Boolean = false

    override fun progress(operationId: org.ghost.sync.api.OperationId): OutboxProgress? = null

    override fun outcomes(consumer: Consumer, limit: Int): List<OutboundOutcome> {
        val source = when (consumer) {
            Consumer.MEDIA -> script
            Consumer.DM -> dmScript
            else -> return emptyList()
        }
        val out = ArrayList<OutboundOutcome>()
        repeat(minOf(limit, source.size)) {
            val s = source.removeFirst()
            decided[hexOf(s.operationId.toByteArray())] = s.outcome
            out += OutboundOutcome(
                s.operationId,
                enqueued[hexOf(s.operationId.toByteArray())] ?: NamespaceId(ByteArray(32)),
                s.outcome,
                s.resendNotAfter,
                TtlBucket.DAYS_7,
            )
        }
        return out
    }

    override fun release(tx: SyncTransaction, operationId: org.ghost.sync.api.OperationId): Boolean {
        val key = hexOf(operationId.toByteArray())
        // Exactly-once first: a re-delivered outcome's release is a no-op without touching the
        // row (its outcome is already decided; the schema's trigger would abort the UPDATE).
        if (key in released) return false
        val op = operationId.toByteArray()
        // The outcome is decided before the release, as the schema's trigger requires.
        decided[key]?.let {
            tx.sql.exec(
                "UPDATE outbox_op SET outcome = ? WHERE operation_id = ?",
                listOf(it.name.lowercase(), op),
            )
        }
        tx.sql.exec("UPDATE outbox_op SET released = 1 WHERE operation_id = ?", listOf(op))
        return released.add(key)
    }
}
