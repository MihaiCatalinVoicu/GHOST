package org.ghost.messaging.engine

import org.ghost.media.send.PrepFailure
import org.ghost.media.store.MediaObject
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
    /** `Checkpoint.truncate` over the database's executor (§10.7); the corrupt-after-verified path's. */
    private val checkpoint: org.ghost.messaging.port.DmCheckpoint,
    /**
     * §11.1's debt for `openViewOnce`'s checkpoint (the S8 review's R1): a busy or failed
     * pragma is recorded here and SWEEP re-asks it, exactly like `Sweeper.checkpointDue`.
     * Defaulted per instance where no sweep shares the state; `MessagingRuntime` wires one.
     */
    private val mediaCheckpoint: MediaCheckpointState = MediaCheckpointState(),
) {
    private val objects = MediaObjects(org.ghost.media.store.MediaFragments())
    private val contacts = ContactStore()
    private val fragments = org.ghost.media.store.MediaFragments()
    private val blobs = org.ghost.media.store.MediaBlobs(fragments)

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
        // §13.7's playback half: every open handle's reader goes (the native `ctxClose` would
        // kill the context anyway; closing here also marks the handles, so a late read from a
        // still-releasing player ends in the typed `Closed`, never a call on a stale context).
        val open: List<ReaderPlayable>
        synchronized(openHandles) { open = openHandles.toList() }
        for (handle in open) handle.close()
    }

    /** §10.5's trim half: the preview cache goes when the UI hides (TRIM_MEMORY_UI_HIDDEN). */
    fun onTrimMemory() {
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
     * on the actor. The gate is held across the decode: the flags are re-read when the sandbox
     * answer returns and the result is dropped (pixels erased, never cached) if ON_STOP or an
     * on-screen change landed mid-decode (T46's shape).
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
            var decodeReturned = false
            val decoded = try {
                pipeline.decoder.decode(
                    previewBytes,
                    org.ghost.media.send.MediaSendLimits.PREVIEW_LONG_EDGE,
                    org.ghost.media.send.MediaSendLimits.PREVIEW_LONG_EDGE,
                ).also { decodeReturned = it != null }
            } finally {
                // The manifest's preview bytes are plaintext media: whatever leaves this
                // block — a null answer or a sandbox defect that throws (rather than
                // answering null) — must not leave them live (F-S7 review, LOW).
                if (!decodeReturned) previewBytes.fill(0)
            } ?: run {
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
            // Hold the zero-click gate across the blocking sandbox decode: the flags were read
            // at entry, and ON_STOP can land while the decode runs — a decode entered in the
            // foreground completes in the background unless the result is re-checked. §9.3's
            // "nothing is decoded in the background" must hold of the answer too: re-read the
            // signal, and drop the result if it changed, erasing the pixels. A dropped answer
            // is not a sandbox failure — nothing counts towards the two-strikes rule.
            val after = onScreenContact
            if (!foreground || after == null || !onScreen.contentEquals(after)) {
                decoded.pixels.fill(0)
                previewBytes.fill(0)
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

    /**
     * §6.5/§10.2's `openMedia` (slice S7): a handle over a `verified` object, or the sender's
     * own `out` object in `uploading`, `uploaded` or `failed` (§7.4's readable states). Null
     * for anything else — no object, a request's `NOT_KEPT`, an unreadable state, a view-once
     * object (S8's `openViewOnce` is that surface) or a key already erased. Deliberately not
     * onActor: the gates run on the actor, the reader's native open and the chunk reads run
     * on the caller's and Media3's threads, exactly as `preview` keeps the sandbox decode off
     * the actor.
     */
    fun openMedia(messageId: ByteArray): org.ghost.messaging.api.MediaHandle? {
        val nowE = steps.nowE()
        val holder = arrayOfNulls<MediaObject>(1)
        actorCall {
            holder[0] = database.transaction { tx -> objects.byMessage(tx.sql, messageId, nowE) }
        }
        val obj = holder[0] ?: return null
        val readable = obj.state == org.ghost.media.store.ObjectState.VERIFIED ||
            (
                obj.role == org.ghost.media.store.MediaRole.OUT && (
                    obj.state == org.ghost.media.store.ObjectState.UPLOADING ||
                        obj.state == org.ghost.media.store.ObjectState.UPLOADED ||
                        obj.state == org.ghost.media.store.ObjectState.FAILED
                    )
                )
        if (!readable || obj.viewOnce || obj.keyEnv == null) return null
        val opened = openReader(obj, nowE) ?: return null
        val playable = ReaderPlayable(obj, opened)
        synchronized(openHandles) { openHandles += playable }
        return org.ghost.messaging.api.MediaHandle(
            kind = obj.kind,
            classCode = opened.classCode,
            width = opened.width,
            height = opened.height,
            durationMs = opened.durationMs,
            contentLength = opened.contentLen,
            playable = playable,
        )
    }

    /** Every playback handle the process holds open; the lock walks and closes it (§13.7). */
    private val openHandles = java.util.Collections.synchronizedSet(HashSet<ReaderPlayable>())

    /**
     * §6.5/§11.2's `openViewOnce` (slice S8): the one display of a verified view-once object.
     * The key moves into the native reader first (§11.2's order — the row loses the key only
     * after the reader holds it); the row half (`viewing`, `key_env = NULL`) commits on the
     * actor; the §11.1 checkpoint runs after the commit and **before the handle returns** —
     * a checkpoint that stays busy (or fails on a full disk) records the debt in the shared
     * [MediaCheckpointState] and the handle returns anyway, L9-M10's declared lag, re-asked
     * by SWEEP at its next pass (§10.7's `checkpoint_due` shape, the S8 review's R1); and the
     * handle's close is
     * `VIEW-ONCE-CLOSE`. Null for anything but a verified, never-opened view-once object —
     * a second open while `viewing` or after `viewed` refuses, which is CS-M5's "at most one
     * display per device" together with the crash semantics (a crash after the commit loses
     * the object; the key existed only in native memory).
     */
    fun openViewOnce(messageId: ByteArray): org.ghost.messaging.api.MediaHandle? {
        val nowE = steps.nowE()
        val holder = arrayOfNulls<MediaObject>(1)
        actorCall { holder[0] = database.transaction { tx -> objects.byMessage(tx.sql, messageId, nowE) } }
        val obj = holder[0] ?: return null
        if (!obj.viewOnce || obj.state != org.ghost.media.store.ObjectState.VERIFIED || obj.keyEnv == null) {
            return null
        }
        // The reader holds K_f before the row gives it up; on any refusal here nothing was
        // shown and the object stays `verified` with its key — the open can be tried again.
        val opened = openReader(obj, nowE) ?: return null
        var moved = false
        try {
            actorCall { database.transaction { tx -> objects.openViewOnce(tx, obj.objectId) } }
            moved = true
        } catch (e: org.ghost.media.store.MediaStoreException) {
            // A racing transition (the object went viewing, viewed or was swept): no display.
        } catch (e: org.ghost.storage.StorageFullException) {
            // §21.12 point 1's shape: the commit was refused and rolled back — the row still
            // names the key, nothing was shown, and the open can be tried again later.
        } finally {
            // The reader now holds the only copy of K_f: when the row move did not commit —
            // a typed refusal above or a defect on the way out — the freshly opened native
            // reader must die here, never leak (the S8 review's R4). No catch-all: a defect
            // still surfaces, with the reader closed.
            if (!moved) readersCloseQuietly(opened.reader)
        }
        if (!moved) return null
        // §11.2/T45: the checkpoint follows the key erasure and precedes the handle (MC-M19).
        // A busy answer (or a full disk) does not lose the erasure: the debt is recorded and
        // SWEEP re-asks the pragma at its next pass (§10.7's shape, the S8 review's R1).
        mediaCheckpoint.record(checkpoint.truncate())
        val playable = ReaderPlayable(obj, opened, viewOnceClose = true)
        synchronized(openHandles) { openHandles += playable }
        return org.ghost.messaging.api.MediaHandle(
            kind = obj.kind,
            classCode = opened.classCode,
            width = opened.width,
            height = opened.height,
            durationMs = opened.durationMs,
            contentLength = opened.contentLen,
            playable = playable,
        )
    }

    /**
     * §11.2's start rule: rows a dead process left `viewing` (its reader died with the process,
     * the key was already erased and checkpointed before the handle was returned) become `viewed`
     * and lose their fragment rows and unshared blobs; the files go with the reconcile. Runs once,
     * on the actor's first media pass, before any handle can exist in this process — a row that is
     * legitimately `viewing` here means a crash (or this engine never opened it), never a live view.
     * More crashed rows than one batch ([VIEW_ONCE_START_BATCH]) all clear in this one pass, in
     * bounded rounds (the S8 review's R2) — the cap never left the rest waiting for a next start.
     */
    fun closeInterruptedViews() {
        val nowE = steps.nowE()
        var closedAny = false
        // The batch bounds one transaction, not the pass: a device that died with more than
        // [VIEW_ONCE_START_BATCH] views open drains them all in this one start, in bounded
        // rounds — none of these rows can be a live view (a live process's own opens are its,
        // and a row this process opened is not `viewing` here), so running the batch again
        // until it comes back short is §11.2's rule, not a race. The reconcile runs once, after.
        var rounds = 0
        do {
            var closedThisRound = false
            database.transaction { tx ->
                for (objectId in objects.viewing(tx.sql, nowE, VIEW_ONCE_START_BATCH)) {
                    objects.closeViewOnce(tx, objectId)
                    closedThisRound = true
                }
            }
            closedAny = closedAny || closedThisRound
            rounds++
        } while (closedThisRound && rounds < VIEW_ONCE_START_MAX_ROUNDS)
        if (closedAny) receiveSteps.reconcile()
    }

    /** §10.5's "when an object is deleted": its decoded preview is erased, not just uncounted. */
    fun evictPreviews(objectIds: List<ByteArray>) {
        for (objectId in objectIds) previewCache.evict(objectId)
    }

    /** The EP-M (6) oracle: whether the preview cache holds an entry of [objectId]. */
    internal fun previewCacheHolds(objectId: ByteArray): Boolean = previewCache.holds(objectId)

    /**
     * `VIEW-ONCE-CLOSE`'s row half (§11.2): the reader is already closed by the handle; the row
     * becomes `viewed` and its fragments and unshared blobs go, on the actor; the reconcile
     * follows the commit. The guarded store move tolerates the object being already viewed or
     * swept — the reader is closed either way, which is the invariant.
     */
    private fun closeViewing(objectId: ByteArray) {
        actorCall {
            try {
                database.transaction { tx -> objects.closeViewOnce(tx, objectId) }
            } catch (e: org.ghost.media.store.MediaStoreException) {
                // Viewed already, or swept with its message while the handle was open: nothing
                // to close. The reader is zeroised by the handle regardless.
            }
            receiveSteps.reconcile()
        }
        previewCache.evict(objectId)
    }

    /**
     * §13.5's "reconcile after the cleanup": `OUTCOME`/`MEDIA-DEADLINE` erased a view-once sender's
     * copy inside its transaction and ran the §11.1 checkpoint itself; the reconcile of the
     * dereferenced files runs here, on the actor, after that commit.
     */
    fun reconcileAfterSenderCopyErased() {
        receiveSteps.reconcile()
    }

    /**
     * The [org.ghost.media.play.MediaPlayable] over one open reader (§10.2): chunk reads fetch
     * the four fragment files from the ciphertext store, hand them to the reader's random-access
     * `READ`, erase the assembled ciphertext after every call, and map the reader's refusals —
     * a hash or tag failure (`HASH_MISMATCH`, `NOT_OPEN`, `NON_CANONICAL`) records the object
     * `verified → corrupt` (§7.3) before the player sees the typed error; `SEQUENCE`/`INDEX_RANGE`
     * are defects that surface; `Unavailable` is the lock's typed `Closed`.
     */
    private inner class ReaderPlayable(
        private val obj: MediaObject,
        private val opened: org.ghost.messaging.port.MediaReaders.Opened.Ok,
        /** View-once handles run `VIEW-ONCE-CLOSE`'s row half and the reconcile at close (§11.2). */
        private val viewOnceClose: Boolean = false,
    ) : org.ghost.media.play.MediaPlayable {

        @Volatile
        private var closed: Boolean = false

        override val contentLength: Long get() = opened.contentLen

        override fun readChunk(index: Int): ByteArray {
            if (closed) throw org.ghost.media.play.MediaPlayException.Closed()
            val fragmentCount = opened.hashes.size
            if (index < 0 || index * FRAGMENTS_PER_CHUNK >= fragmentCount) {
                throw org.ghost.media.play.MediaPlayException.Defect("chunk $index outside $fragmentCount fragments")
            }
            val assembled = ByteArray(FRAGMENTS_PER_CHUNK * FRAGMENT_BYTES)
            try {
                val nowE = steps.nowE()
                for (k in 0 until FRAGMENTS_PER_CHUNK) {
                    val ordinal = index * FRAGMENTS_PER_CHUNK + k
                    if (ordinal >= fragmentCount) {
                        throw org.ghost.media.play.MediaPlayException.Defect("fragment $ordinal missing of $fragmentCount")
                    }
                    val blob = database.transaction { tx -> fragments.fragment(tx.sql, obj.objectId, ordinal, nowE) }
                        ?: throw org.ghost.media.play.MediaPlayException.Defect("fragment $ordinal has no row")
                    val file = database.transaction { tx -> blobs.byHash(tx.sql, blob.blobHash) }
                        ?: throw org.ghost.media.play.MediaPlayException.Defect("fragment $ordinal names no blob")
                    val bytes = try {
                        pipeline.files.read(file.fileName)
                    } catch (e: org.ghost.media.store.CiphertextFilesException) {
                        // A file of the store that cannot be read whole (missing, wrong length):
                        // the object cannot survive a read — record it, like a hash failure.
                        corrupt(obj.objectId)
                        throw org.ghost.media.play.MediaPlayException.Corrupt(e)
                    }
                    System.arraycopy(bytes, 0, assembled, k * FRAGMENT_BYTES, FRAGMENT_BYTES)
                }
                return when (
                    val chunked = pipeline.readers.chunk(
                        opened.reader, index, assembled, validate = false,
                    )
                ) {
                    is org.ghost.messaging.port.MediaReaders.Chunked.Ok -> chunked.content
                    org.ghost.messaging.port.MediaReaders.Chunked.HashMismatch,
                    org.ghost.messaging.port.MediaReaders.Chunked.NotOpen,
                    org.ghost.messaging.port.MediaReaders.Chunked.NonCanonical,
                    -> {
                        corrupt(obj.objectId)
                        throw org.ghost.media.play.MediaPlayException.Corrupt()
                    }
                    org.ghost.messaging.port.MediaReaders.Chunked.Sequence,
                    org.ghost.messaging.port.MediaReaders.Chunked.IndexRange,
                    -> throw org.ghost.media.play.MediaPlayException.Defect("reader refused chunk $index: $chunked")
                    org.ghost.messaging.port.MediaReaders.Chunked.Unavailable -> {
                        closed = true
                        throw org.ghost.media.play.MediaPlayException.Closed()
                    }
                }
            } finally {
                assembled.fill(0)
            }
        }

        override fun close() {
            if (closed) return
            closed = true
            synchronized(openHandles) { openHandles.remove(this) }
            pipeline.readers.close(opened.reader)
            // §11.2: a view-once handle's close is VIEW-ONCE-CLOSE — the UI closing it, the lock,
            // and a wipe all end here (a crash ends at the next process start instead, via
            // closeInterruptedViews).
            if (viewOnceClose) closeViewing(obj.objectId)
        }
    }

    /**
     * §7.3's `verified → corrupt` from a read (the corrupt-after-verified half §15.8 item 3
     * names): the object releases its references and erases its key in one transaction, the
     * count and the checkpoint follow — on the actor, so the checkpoint cannot interleave a
     * pass's transaction (the same shape `MediaReceiveSteps` keeps).
     */
    private fun corrupt(objectId: ByteArray) {
        actorCall {
            try {
                database.transaction { tx -> objects.markCorrupt(tx, objectId) }
            } catch (e: org.ghost.media.store.MediaStoreException) {
                // Already corrupt, incomplete or gone — a racing record won; nothing to add.
                return@actorCall
            }
            receiveSteps.stats.addCorrupt()
            checkpoint.truncate()
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
        return openReader(obj, nowE)
    }

    /**
     * Opens the native reader over [obj]'s manifest, attested readable (§13.2 M5): the manifest
     * blob from the ciphertext store, `key_env` unwrapped inside Rust. The preview path (S6) and
     * the playback path (S7) share this; a refusal answers null and the caller surfaces nothing.
     */
    private fun openReader(obj: MediaObject, nowE: Long): org.ghost.messaging.port.MediaReaders.Opened.Ok? {
        val keyEnv = obj.keyEnv ?: return null
        val manifestRow = database.transaction { tx -> blobs.byHash(tx.sql, obj.manifestHash) }
            ?: return null
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
                    role = if (obj.role == org.ghost.media.store.MediaRole.OUT) {
                        org.ghost.crypto.bridge.MediaCrypto.Role.OUT
                    } else {
                        org.ghost.crypto.bridge.MediaCrypto.Role.IN
                    },
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

        /** [org.ghost.media.store.MediaLimits.FRAGMENT_BYTES]: one fragment file's bytes. */
        const val FRAGMENT_BYTES: Int = 65_536

        /** Four fragments per chunk (§13.2 M2). */
        const val FRAGMENTS_PER_CHUNK: Int = 4

        /** §11.2's start pass closes every `viewing` row a dead process left behind, in batches. */
        const val VIEW_ONCE_START_BATCH: Int = 32

        /** How many such batches the one start pass runs: 1 024 crashed views, bounded work. */
        const val VIEW_ONCE_START_MAX_ROUNDS: Int = 32
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
            byObject.remove(key)?.let {
                // The replaced entry is erased, not just uncounted — the same hygiene as the
                // eviction loop below (F-S7 review, LOW; latent: the same object id is re-put
                // only after a trim or a state change, but the erase is the rule itself).
                it.pixels.fill(0)
                bytes -= it.pixels.size
            }
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

        /** §10.5's object-deleted rule: the entry's pixels are erased, not just uncounted. */
        fun evict(objectId: ByteArray) = synchronized(lock) {
            byObject.remove(hexOf(objectId))?.let {
                it.pixels.fill(0)
                bytes -= it.pixels.size
            }
        }

        /** The EP-M (6) oracle. */
        fun holds(objectId: ByteArray): Boolean = synchronized(lock) { byObject.containsKey(hexOf(objectId)) }

        private fun hexOf(bytes: ByteArray): String =
            bytes.joinToString("") { "%02x".format(it) }

        companion object {
            /** §10.5/CS-M6: previews in RAM ≤ 16 MiB. */
            const val MAX_PREVIEW_CACHE_BYTES: Int = 16 * 1024 * 1024
        }
    }
}
