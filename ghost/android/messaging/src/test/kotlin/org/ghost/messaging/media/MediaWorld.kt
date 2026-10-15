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
import org.ghost.messaging.engine.MediaOpIds
import org.ghost.messaging.engine.MediaOrphanSteps
import org.ghost.messaging.engine.MediaSteps
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
 * bytes), with deterministic fakes at the three Android-only seams: the sandbox stripper (a
 * committed S0 golden), the video export (a committed golden canonical fMP4) and the sealer (a
 * JVM stand-in, contract-faithful; the host build's `testSealBeginWithKey` re-derivation is
 * §15.6's relay fidelity, S9's concern — this world's oracles are structural).
 *
 * The outbox is [ScriptedOutbox], the relay's decided outcomes scripted; it survives a reboot
 * like the external relay would. The world is driven single-threaded (the actor's seriality is
 * the test's). A crash run: drive the scripted body, [close], reopen with
 * `MediaWorld(path, dir, relay)`, [reconcile], [assertSendInvariants], resume or finish.
 */
internal class MediaWorld(
    val dbPath: String,
    val dir: File,
    val relay: ScriptedOutbox = ScriptedOutbox(),
) : AutoCloseable {

    val sql: JdbcSqlExecutor = JdbcSqlExecutor(dbPath).also { MigrationRunner(it).migrate() }
    val database: SyncDatabase = SyncDatabase(sql)
    val clock = MovableClock()
    val stores: SyncStores = SyncStores(database, clock, FixedRandomSources()) { PrivacyMode.STANDARD }
    val crypto = FakeDmCrypto()
    val random = SequentialRandom()
    val wrapper = FakeKeyWrapper()
    val contexts: SelfContexts by lazy { SelfContexts(database, crypto, wrapper) }

    /** The crash-injecting file system behind [files], for the scenario suites. */
    val crashFs = CrashableFileSystem(NioCiphertextFileSystem())
    val files: CiphertextFiles = CiphertextFiles(
        File(dir, "m"), crashFs, WorldNames(), 0L,
    ).also { it.open() }
    val preparing = PreparingFiles()
    val fragments = MediaFragments()
    val objects = MediaObjects(fragments)
    val blobs = MediaBlobs(fragments)
    private val reconcile = MediaReconcile(files, blobs, fragments)

    private val sync = DmSyncPorts(
        stores.namespaces, stores.capabilities, stores.registrations, relay, stores.inbox,
    )

    /** The envelope seam: the owner world's closed-context shape, with a canned kind-5 encode. */
    private val envelopes: DmEnvelopes =
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
    )

    /** The preparation pipeline over the fake ports. */
    val preparer: MediaPreparer = MediaPreparer(
        FakeStripper, FakeVideoExport, FakeSealerFactory, JpegCanonicalizer { it.copyOf() },
        files, preparing,
    )

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

private fun digest(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

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
    override fun freeSpace(directory: File): Long = real.freeSpace(directory)
}

/** The sandbox seam: the committed golden canonical JPEG (object and preview alike). */
private object FakeStripper : ImageStripper {
    override fun strip(source: ByteArray, preview: Boolean, maxBytes: Int): ImageStripper.StripResult =
        ImageStripper.StripResult.Ok(Goldens.jpeg, 512, 336)
}

/** The video seam: the committed golden canonical fMP4 through the caller's real channel. */
private object FakeVideoExport : VideoExport {
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

/** The sealer seam: deterministic bytes unique per object (a second object must not collide on
 * a blob hash), hashes over the bytes themselves (self-consistent with the file oracles). */
private object FakeSealerFactory : MediaSealerFactory {
    private var n = 0

    override fun begin(
        destId: ByteArray,
        kind: org.ghost.crypto.bridge.MediaCrypto.Kind,
        viewOnce: Boolean,
        maxClass: Int,
    ): MediaSealerFactory.Begun {
        val v = n++
        val objectId = ByteArray(16) { if (it < 4) (v ushr (8 * it)).toByte() else it.toByte() }
        return MediaSealerFactory.Begun.Ok(FakeSealer(objectId), objectId)
    }
}

/**
 * Emits exactly the four chunks (16 fragments, class 0) every object of this world seals: the
 * content's chunks, then zero padding groups — what the real sealer's class rounding does.
 */
private class FakeSealer(private val objectId: ByteArray) : StreamSealer {
    private var consumed = 0L
    private var next = 0

    override fun append(plaintext: ByteArray): List<SealedFragmentGroup> {
        consumed += plaintext.size
        val completed = (consumed / MediaLimits.CHUNK_PLAINTEXT).toInt()
        val out = ArrayList<SealedFragmentGroup>()
        while (next < completed) out += group(next++)
        return out
    }

    override fun finish(preview: ByteArray): SealedObject {
        val tail = consumed % MediaLimits.CHUNK_PLAINTEXT != 0L
        val finishGroups = ArrayList<SealedFragmentGroup>()
        if (tail || next == 0) finishGroups += group(next++)
        while (next < 4) finishGroups += group(next++)
        val manifest = ByteArray(MediaLimits.FRAGMENT_BYTES) { (0x4D xor objectId[0].toInt()).toByte() }
        return SealedObject(
            classCode = 0,
            contentLen = consumed,
            width = 1_280,
            height = 720,
            durationMs = 0,
            keyEnv = ByteArray(60) { 0x4B },
            manifestBlob = manifest,
            manifestHash = digest(manifest),
            preview = preview,
            finishGroups = finishGroups,
        )
    }

    override fun abort() = Unit

    private fun group(index: Int): SealedFragmentGroup {
        val seed = objectId[0].toInt() and 0xFF
        val fragments = List(4) { k ->
            ByteArray(MediaLimits.FRAGMENT_BYTES) { i ->
                ((seed + index * 7 + k * 13 + (i % 251)) and 0xFF).toByte()
            }
        }
        return SealedFragmentGroup(index, fragments, fragments.map { digest(it) })
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

    /** What the relay holds, for the oracles: op id → namespace. */
    val held: Map<String, NamespaceId> get() = enqueued

    fun script(operationId: org.ghost.sync.api.OperationId, outcome: Outcome, resendNotAfter: Long? = null) {
        script += Scripted(operationId, outcome, resendNotAfter)
    }

    /** The deterministic op id the steps will derive for (object, ordinal, generation, resend). */
    fun opIdOf(objectId: ByteArray, ordinal: Int, gen: Int = 0, resend: Int = 0) =
        org.ghost.sync.api.OperationId(MediaOpIds.sha256().of(objectId, ordinal, gen, resend))

    override fun enqueue(tx: SyncTransaction, blob: OutboundBlob): EnqueueResult {
        val key = hexOf(blob.operationId.toByteArray())
        return if (enqueued.put(key, blob.namespace) == null) EnqueueResult.Enqueued
        else EnqueueResult.AlreadyEnqueued
    }

    override fun cancel(tx: SyncTransaction, operationId: org.ghost.sync.api.OperationId): Boolean = false

    override fun progress(operationId: org.ghost.sync.api.OperationId): OutboxProgress? = null

    override fun outcomes(consumer: Consumer, limit: Int): List<OutboundOutcome> {
        if (consumer != Consumer.MEDIA) return emptyList()
        val out = ArrayList<OutboundOutcome>()
        repeat(minOf(limit, script.size)) {
            val s = script.removeFirst()
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

    override fun release(tx: SyncTransaction, operationId: org.ghost.sync.api.OperationId): Boolean =
        released.add(hexOf(operationId.toByteArray()))
}
