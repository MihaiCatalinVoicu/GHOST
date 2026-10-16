package org.ghost.messaging.engine

import org.ghost.media.send.PrepFailure
import org.ghost.media.store.MediaObjects
import org.ghost.media.store.RetryResult
import org.ghost.messaging.api.MediaSendResult
import org.ghost.messaging.api.PreparationId
import org.ghost.messaging.api.PreparationView
import org.ghost.messaging.api.SendResult
import org.ghost.messaging.port.DmRandom
import org.ghost.messaging.store.ContactStore
import org.ghost.sync.api.SyncDatabase
import java.util.concurrent.ExecutorService

/**
 * The facade's media half (Phase 11 design §6.5), holding what the [MessagingEngine] cannot own:
 * the [Preparations] registry (S0-23), the media worker of §13.7 (`ghost-media-prep`, one thread —
 * sandbox calls, Transformer, sealing; no transaction), and the bridge that runs a finished
 * preparation into `MEDIA-COMMIT` on the DM actor and then releases the reserved file names.
 *
 * Everything here is local: the change listener the facade fires is the engine's own; nothing a
 * preparation does reaches a relay except through the `MEDIA-FEED` the actor runs after a commit.
 */
internal class MediaEngineSupport(
    private val database: SyncDatabase,
    private val steps: MediaSteps,
    private val receiveSteps: MediaReceiveSteps,
    private val preparations: org.ghost.media.send.Preparations,
    private val pipeline: MediaPipelinePorts,
    private val worker: ExecutorService,
    private val random: DmRandom,
    private val contexts: SelfContexts,
    private val actorCall: (() -> Unit) -> Unit,
) {
    private val objects = MediaObjects(org.ghost.media.store.MediaFragments())
    private val contacts = ContactStore()

    /**
     * §7.4/§9.3's zero-click gates, both default-deny: no conversation named, or the app in the
     * background (a process started for the background job never saw ON_START). `onLock` clears
     * both and the preview cache (§13.7) — wired in slice S6's `MessagingWiring.onHidden`/lock path
     * with the foreground signal of §6.5.
     */
    @Volatile
    private var onScreenContact: ByteArray? = null

    @Volatile
    private var foreground: Boolean = false

    /** The decoded-preview RAM cache of §10.5 (≤ 16 MiB, erased on eviction). */
    private val previewCache = PreviewCache()

    /** §6.5's `setConversationOnScreen`: the UI's statement of which conversation is visible. */
    fun onScreen(contact: ByteArray?) {
        onScreenContact = contact?.copyOf()
    }

    /** The foreground half of the on-screen signal (§6.5; GhostApp's ON_START/ON_STOP). */
    fun onForeground(visible: Boolean) {
        foreground = visible
    }

    /** §13.7's lock/wipe half: the signal and the cache go; the sandbox instances die with the unbind. */
    fun onLocked() {
        foreground = false
        onScreenContact = null
        previewCache.clear()
    }

    /** §6.5's `mediaState`: kind, class, state and held/F progress; no times. */
    fun mediaState(messageId: ByteArray): org.ghost.messaging.api.MediaStateView? {
        // The no-arg expiry clock opens a transaction of its own: read it before ours.
        val nowE = steps.nowE()
        return database.transaction { tx ->
            val obj = objects.byMessage(tx.sql, messageId, nowE)
            if (obj != null) {
                var bound = 0L
                tx.sql.query(
                    "SELECT count(*) FROM media_fragment WHERE object_id = ? AND state = 'bound' AND ordinal >= 0",
                    listOf(obj.objectId),
                ) { r -> bound = r.long(0) }
                org.ghost.messaging.api.MediaStateView(
                    state = obj.state,
                    kind = obj.kind,
                    classCode = obj.classCode,
                    heldFragments = bound.toInt(),
                    totalFragments = org.ghost.media.store.MediaLimits.CLASSES[obj.classCode],
                )
            } else {
                // No object: a live kind-5 message is one received in a request (D28) — NOT_KEPT.
                var kind = 0L
                tx.sql.query(
                    "SELECT kind FROM dm_message WHERE message_id = ? " +
                        "AND (delete_at_minute IS NULL OR delete_at_minute > ?)",
                    listOf(messageId, DmTime.floorMinute(nowE)),
                ) { r -> kind = r.long(0) }
                if (kind == org.ghost.crypto.bridge.DmContent.Kind.MEDIA.wire.toLong()) {
                    org.ghost.messaging.api.MediaStateView.NOT_KEPT
                } else {
                    null
                }
            }
        }
    }

    /**
     * §6.5's `mediaPreview`: decoded pixels from the RAM cache or the sandbox — null unless §7.4
     * allows (§9.3's zero-click rules). Runs off the actor: the gates read on the actor, the
     * sandbox bind/decode blocks this caller (never the DM actor), and the failure counting writes
     * on the actor.
     */
    fun preview(messageId: ByteArray): org.ghost.messaging.api.MediaPreview? {
        if (!foreground) return null
        val onScreen = onScreenContact ?: return null
        val nowE = steps.nowE()

        // The gates, on the actor: the object of the message, verified, of the named contact,
        // and a contact the zero-click rules allow (a request has no object at all — D28).
        val gateHolder = arrayOfNulls<PreviewGate>(1)
        actorCall {
            gateHolder[0] = database.transaction { tx ->
                val obj = objects.byMessage(tx.sql, messageId, nowE) ?: return@transaction null
                val contact = contacts.contact(tx.sql, obj.destId) ?: return@transaction null
                val allowed = when (contact.trust) {
                    ContactStore.Trust.UNVERIFIED,
                    ContactStore.Trust.VERIFIED,
                    ContactStore.Trust.CHANGED,
                    -> true
                    ContactStore.Trust.REQUEST,
                    ContactStore.Trust.BLOCKED,
                    ContactStore.Trust.REVOKED,
                    -> false
                }
                if (!allowed || !onScreen.contentEquals(obj.destId)) return@transaction null
                if (obj.state != org.ghost.media.store.ObjectState.VERIFIED) return@transaction null
                PreviewGate(obj.objectId)
            }
        }
        val gate = gateHolder[0] ?: return null

        previewCache.get(gate.objectId)?.let { return it }

        // The manifest's preview: open the reader (its VERIFY pass already authenticated the
        // manifest, so these bytes are canonical by construction), take the preview, close.
        val opened = openPreviewReader(gate.objectId, nowE) ?: return null
        try {
            val previewBytes = opened.preview
            if (previewBytes.isEmpty()) return null // view-once carries none (ADR-44 point 5)
            val decoded = pipeline.decoder.decode(
                previewBytes,
                org.ghost.media.send.MediaSendLimits.PREVIEW_LONG_EDGE,
                org.ghost.media.send.MediaSendLimits.PREVIEW_LONG_EDGE,
            ) ?: run {
                previewBytes.fill(0)
                previewDecodeFailed(gate.objectId)
                return null
            }
            val w = decoded.width
            val h = decoded.height
            val expected = w * h * 4
            if (w <= 0 || h <= 0 || w > org.ghost.media.send.MediaSendLimits.PREVIEW_LONG_EDGE ||
                h > org.ghost.media.send.MediaSendLimits.PREVIEW_LONG_EDGE || decoded.pixels.size != expected
            ) {
                // §9.2: an out-of-range answer is a failure, never parsed further.
                decoded.pixels.fill(0)
                previewBytes.fill(0)
                previewDecodeFailed(gate.objectId)
                return null
            }
            previewBytes.fill(0)
            val view = org.ghost.messaging.api.MediaPreview(w, h, decoded.pixels)
            previewCache.put(gate.objectId, view)
            return view
        } finally {
            readersCloseQuietly(opened.reader)
        }
    }

    /** What the gate read yields: the object id alone; nothing else crosses the actor boundary. */
    private class PreviewGate(val objectId: ByteArray)

    /** One decode failure towards the two-strikes rule (CS-M8, §9.2). */
    private fun previewDecodeFailed(objectId: ByteArray) {
        actorCall {
            try {
                val nowE = steps.nowE()
                val count = database.transaction { tx -> objects.recordDecodeFailure(tx, objectId) }
                if (count >= org.ghost.media.store.MediaLimits.MAX_DECODE_FAILURES) {
                    database.transaction { tx -> objects.markUndecodable(tx, objectId) }
                }
            } catch (e: org.ghost.media.store.MediaStoreException) {
                // A third failure or a state that moved: the object is already undecodable or gone.
                Unit
            }
        }
    }

    /** The reader over a verified object, opened readable for the preview bytes; null on any refusal. */
    private fun openPreviewReader(objectId: ByteArray, nowE: Long): org.ghost.messaging.port.MediaReaders.Opened.Ok? {
        // The object's row again (off-actor reads stay transactional and short; this is the worker).
        val obj = database.transaction { tx -> objects.byId(tx.sql, objectId, nowE) } ?: return null
        val keyEnv = obj.keyEnv ?: return null
        val manifestRow = database.transaction { tx ->
            org.ghost.media.store.MediaBlobs(org.ghost.media.store.MediaFragments())
                .byHash(tx.sql, obj.manifestHash)
        } ?: return null
        val manifest = try {
            pipeline.files.read(manifestRow.fileName)
        } catch (e: java.io.IOException) {
            return null
        }
        if (manifest.size != org.ghost.media.store.MediaLimits.FRAGMENT_BYTES) return null
        return when (
            val opened = pipeline.readers.open(
                org.ghost.messaging.port.MediaReaders.OpenSpec(
                    keyEnv = keyEnv,
                    role = org.ghost.crypto.bridge.MediaCrypto.Role.IN,
                    destId = obj.destId,
                    objectId = obj.objectId,
                    manifestHash = obj.manifestHash,
                    manifestBlob = manifest,
                    kind = if (obj.kind == org.ghost.media.store.MediaKind.IMAGE) {
                        org.ghost.crypto.bridge.MediaCrypto.Kind.IMAGE
                    } else {
                        org.ghost.crypto.bridge.MediaCrypto.Kind.VIDEO
                    },
                    viewOnce = obj.viewOnce,
                    classCode = obj.classCode,
                    readable = true,
                ),
            )
        ) {
            is org.ghost.messaging.port.MediaReaders.Opened.Ok -> opened
            else -> null
        }
    }

    private fun readersCloseQuietly(reader: Long) {
        // No catch-all: the native close is typed inside `MediaCrypto.closeReader`, and a defect
        // there must surface, not vanish (sync-no-catch-all; F-S5-4's lesson).
        pipeline.readers.close(reader)
    }

    /** §6.6's free-space check the engine's pre-checks read (the store's typed answer). */
    fun freeSpace(): Long = pipeline.files.freeSpace()

    /** The registry's concurrent bound (§6.5): false → `LIMIT_REACHED`. */
    fun begin(preparation: PreparationId): Boolean = preparations.begin(preparation.id)

    /** The worker-side runs, called inside [startPreparation]'s lambda. */
    fun prepareImage(source: ByteArray, destId: ByteArray, viewOnce: Boolean) =
        preparer.prepareImage(source, destId, viewOnce)

    fun prepareVideo(
        source: org.ghost.media.send.VideoSource,
        destId: ByteArray,
        viewOnce: Boolean,
        maxClass: Int,
    ) = preparer.prepareVideo(source, destId, viewOnce, maxClass)

    /** The actor-side steps, for the pass hooks (`DmActor` runs them on its thread). */
    fun stepsForPass(): MediaSteps = steps

    /** The recipient half's actor-side steps, for the same pass hooks. */
    fun receiveStepsForPass(): MediaReceiveSteps = receiveSteps

    /** The sealer factory over the DM context's handle (§3.7); built here so the handle never
     * leaves the module that owns the context. */
    private val sealers: org.ghost.media.send.MediaSealerFactory =
        object : org.ghost.media.send.MediaSealerFactory {
            override fun begin(
                destId: ByteArray,
                kind: org.ghost.crypto.bridge.MediaCrypto.Kind,
                viewOnce: Boolean,
                maxClass: Int,
            ): org.ghost.media.send.MediaSealerFactory.Begun =
                steps.beginMediaSealer(destId, kind, viewOnce, maxClass)
        }

    /** M9 `jpegCanonicalize` as the preparer's port (§8.2's own-copy check). */
    private val canonicalizer = org.ghost.media.send.JpegCanonicalizer { bytes ->
        when (val c = org.ghost.crypto.bridge.MediaCrypto.jpegCanonicalize(bytes)) {
            is org.ghost.crypto.bridge.MediaCrypto.Canonical.Ok -> c.bytes
            else -> null
        }
    }

    /** The preparer the worker runs: the device ports plus the crypto-bound pieces above. */
    internal val preparer: org.ghost.media.send.MediaPreparer = org.ghost.media.send.MediaPreparer(
        pipeline.stripper, pipeline.video, sealers, canonicalizer, pipeline.files, pipeline.preparing,
    )

    /** §13.7's worker thread name. */
    companion object {
        const val WORKER_THREAD: String = "ghost-media-prep"
    }

    /** The engine's pre-checks ran and the registry has the id: run the preparation off-actor. */
    fun startPreparation(
        preparation: PreparationId,
        run: () -> org.ghost.media.send.MediaPreparer.Prepared,
        caption: ByteArray,
        contactId: ByteArray,
    ) {
        worker.submit {
            try {
                val prepared = run()
                // The context is resolved on the actor, in the S8 rule's order (before the
                // commit's transaction, which the actor's seriality makes sound).
                var committed: ByteArray? = null
                var failure: PrepFailure? = null
                actorCall {
                    val self = contexts.get()
                    if (self == null) {
                        failure = PrepFailure.Cancelled
                        return@actorCall
                    }
                    when (val result = steps.commit(self, request(prepared, caption, contactId))) {
                        is MediaSteps.CommitResult.Committed -> {
                            steps.feed()
                            committed = result.messageId
                        }
                        // A commit-time refusal is a race the pre-checks could not see (the slot
                        // table, the disk). PrepFailure has no value for NO_REPLICAS; the refusal
                        // is cancellation-shaped and counted (§22.8 F-S5-8's reading).
                        is MediaSteps.CommitResult.Refused ->
                            failure = when (result.outcome) {
                                SendStep.Outcome.STORAGE_FULL -> PrepFailure.StorageFull
                                else -> PrepFailure.Cancelled
                            }
                        MediaSteps.CommitResult.NoReplicas -> failure = PrepFailure.Cancelled
                        MediaSteps.CommitResult.Unavailable -> failure = PrepFailure.Cancelled
                    }
                }
                prepared.releaseNames()
                val messageId = committed
                if (messageId != null) {
                    preparations.committed(preparation.id, messageId)
                } else {
                    preparations.failed(preparation.id, failure ?: PrepFailure.Cancelled)
                }
            } catch (e: org.ghost.media.send.MediaPreparer.Refused) {
                preparations.failed(preparation.id, e.failure)
            } catch (e: Throwable) {
                // A defect of the pipeline (a store refusal, an unexpected throw): the preparation
                // is cancelled; its orphans reconcile; the actor's crash fidelity is untouched
                // because this is the worker thread, not the actor's.
                preparations.failed(preparation.id, PrepFailure.Cancelled)
            }
        }
    }

    private fun request(
        prepared: org.ghost.media.send.MediaPreparer.Prepared,
        caption: ByteArray,
        contactId: ByteArray,
    ): MediaSteps.CommitRequest {
        val sealed = prepared.sealed
        return MediaSteps.CommitRequest(
            contactId = contactId,
            kind = if (prepared.kind == org.ghost.crypto.bridge.MediaCrypto.Kind.IMAGE) {
                org.ghost.media.store.MediaKind.IMAGE
            } else {
                org.ghost.media.store.MediaKind.VIDEO
            },
            viewOnce = prepared.viewOnce,
            classCode = sealed.classCode,
            objectId = prepared.objectId,
            manifestHash = sealed.manifestHash,
            caption = caption,
            keyEnv = sealed.keyEnv,
            manifestBlob = sealed.manifestBlob,
            manifestFile = sealed.manifestFile,
            fragmentHashes = sealed.fragmentHashes,
            fragmentFiles = sealed.fragmentFiles,
        )
    }

    /** §6.5's `preparationState`: the registry's answer, mapped; null after the final read. */
    fun preparationState(preparation: PreparationId): PreparationView? =
        when (val state = preparations.state(preparation.id)) {
            null -> null
            is org.ghost.media.send.Preparations.State.Preparing ->
                PreparationView.Preparing(state.progress)
            is org.ghost.media.send.Preparations.State.Committed ->
                PreparationView.Committed(org.ghost.messaging.api.MessageId(state.messageId))
            is org.ghost.media.send.Preparations.State.Failed ->
                PreparationView.Failed(state.failure)
        }

    /** §6.5's `retryMedia`: the object of the message must be a failed upload, before the deadline. */
    fun retryMedia(messageId: ByteArray): SendResult {
        val nowE = steps.nowE()
        val objectId = database.transaction { tx ->
            objects.byMessage(tx.sql, messageId, nowE)?.takeIf {
                it.role == org.ghost.media.store.MediaRole.OUT
            }?.objectId
        } ?: return SendResult.UNKNOWN
        // F-S5-15: the re-feed runs AFTER the retry transaction, in the READY shape (same pass,
        // not the same transaction) — SyncDatabase is not reentrant, and the nested feed() threw
        // out of the facade on every retry (the store-level suites bypass the facade, which is
        // why it stayed green until the review).
        return when (val result = database.transaction { tx -> objects.retryUpload(tx, objectId, nowE) }) {
            RetryResult.RETRIED -> {
                steps.feed()
                SendResult.QUEUED
            }
            RetryResult.DEADLINE_PASSED -> SendResult.DEADLINE_PASSED
            RetryResult.NOT_RETRYABLE -> SendResult.NOT_RETRYABLE
            RetryResult.RETRIES_EXHAUSTED,
            RetryResult.NOT_FAILED,
            -> SendResult.UNKNOWN
            RetryResult.NO_SUCH_OBJECT -> SendResult.UNKNOWN
        }
    }

    /** A fresh local preparation id (S0-23: random, local, no row before the commit). */
    fun newPreparationId(): PreparationId =
        PreparationId(random.bytes(8).joinToString("") { "%02x".format(it) })

    fun close() {
        worker.shutdown()
    }

    /**
     * The decoded-preview RAM cache (§10.5, CS-M6): at most [budgetBytes] of pixels, the oldest
     * entries evicted first and **erased before they are dropped** (§10.5's hygiene; a ByteArray
     * has no `recycle`, so the erasure is the rule itself).
     */
    private class PreviewCache(private val budgetBytes: Int = MAX_PREVIEW_CACHE_BYTES) {
        private val lock = Any()
        private val byObject = LinkedHashMap<String, org.ghost.messaging.api.MediaPreview>()
        private var bytes: Int = 0

        fun get(objectId: ByteArray): org.ghost.messaging.api.MediaPreview? = synchronized(lock) {
            byObject[hexOf(objectId)]
        }

        fun put(objectId: ByteArray, preview: org.ghost.messaging.api.MediaPreview) = synchronized(lock) {
            val key = hexOf(objectId)
            val size = preview.pixels.size
            if (size > budgetBytes) return@synchronized // never fits: don't cache
            byObject.remove(key)?.let { bytes -= it.pixels.size }
            while (bytes + size > budgetBytes && byObject.isNotEmpty()) {
                val oldest = byObject.entries.iterator().next()
                oldest.value.pixels.fill(0)
                byObject.remove(oldest.key)
                bytes -= oldest.value.pixels.size
            }
            byObject[key] = preview
            bytes += size
        }

        fun clear() = synchronized(lock) {
            for (preview in byObject.values) preview.pixels.fill(0)
            byObject.clear()
            bytes = 0
        }

        private fun hexOf(bytes: ByteArray): String =
            bytes.joinToString("") { "%02x".format(it) }

        companion object {
            /** §10.5/CS-M6: previews in RAM ≤ 16 MiB. */
            const val MAX_PREVIEW_CACHE_BYTES: Int = 16 * 1024 * 1024
        }
    }
}
