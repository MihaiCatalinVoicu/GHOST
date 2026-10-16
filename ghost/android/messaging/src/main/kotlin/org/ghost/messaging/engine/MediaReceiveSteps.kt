package org.ghost.messaging.engine

import org.ghost.media.store.CiphertextFiles
import org.ghost.media.store.MediaBlobs
import org.ghost.media.store.MediaFragments
import org.ghost.media.store.MediaLimits
import org.ghost.media.store.MediaObject
import org.ghost.media.store.MediaObjects
import org.ghost.media.store.MediaReconcile
import org.ghost.media.store.ObjectState
import org.ghost.media.store.WriteResult
import org.ghost.messaging.port.DmCheckpoint
import org.ghost.messaging.port.DmClock
import org.ghost.messaging.port.MediaReaders
import org.ghost.storage.StorageFullException
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.SyncDatabase
import org.ghost.sync.api.SyncTransaction

/**
 * The recipient half of the media state machines (Phase 11 design §7.2–§7.5, §13.5): **MEDIA-INGEST**,
 * **MEDIA-BIND**, **MEDIA-VERIFY** and **MEDIA-GC**, driven by the actor's media pass exactly as
 * the sender half (`MediaSteps`) is — one thread, every write inside a transaction, file writes
 * before the transaction that references them and file deletions after the commit that
 * dereferences them, by the reconcile.
 *
 *  - `MEDIA-INGEST` (§7.2): claim `Consumer.MEDIA` blobs; a blob that is not exactly 65 536 bytes,
 *    a hash the store already has, or a write below the free-space floor is **consumed without a
 *    file**, counted — the receive side never refuses for space and never changes what is fetched
 *    (T28, §7.5). Otherwise the file is written (forced, directory synced) and one transaction
 *    consumes the blob, inserts the row with its retention day and binds every `expected` fragment
 *    row naming the hash; an object whose last `expected` row bound becomes `complete`; the pool
 *    cap is enforced in the same transaction ([MediaBlobs.evictOverCap], never a stop).
 *  - `MEDIA-BIND` (§7.2): an `awaiting` object whose manifest hash has a blob gets the manifest
 *    read, hash-checked and opened through the reader (which unwraps `key_env` under its binding,
 *    checks the commitment and compares kind/flags/class/object id with the descriptor); one
 *    transaction inserts one fragment row per manifest hash — `bound` where the blob is already
 *    stored, `expected` otherwise, whatever object else names the same hash (D25: ownership is
 *    decided by authentication, never by arrival order) — and moves the object to `fetching`. A
 *    manifest that does not open or disagrees makes the object `corrupt` (counted).
 *  - `MEDIA-VERIFY` (§7.3): a `complete` object is walked chunk by chunk through the reader in
 *    validate mode — authenticated, pad-checked, canonically walked, nothing exposed — and one
 *    transaction records `verified` or `corrupt`; a `corrupt` object releases its references and
 *    erases its key, and the caller checkpoints (§11.1).
 *  - `MEDIA-GC` (§7.5): objects past `incomplete_after_hour` are declared `incomplete` (the same
 *    release), pooled blobs past their retention day and unnamed sealed blobs are collected; the
 *    checkpoint follows any key erasure, the reconcile any row deletion.
 *
 * **Thread shape (§13.7's reading).** The design names a separate media actor; this slice runs
 * these steps on the DM actor, as S5 already runs the sender steps — the invariant that matters,
 * media rows only inside transactions with the DM actor the only other writer, holds because
 * SQLite serialises the two writers and the DM actor's media writes are the `MediaSteps` above.
 * The `preparing` snapshot the reconcile takes is thread-safe ([org.ghost.media.store.PreparingFiles]).
 * Recorded for the review in §22.9.
 *
 * **Crash shape.** Ingest writes the file before its transaction; a crash between leaves an orphan
 * file (the reconcile deletes it) and an unconsumed row (re-offered) — nothing is lost, nothing
 * written twice. Bind and verify do their native work outside a transaction and record the outcome
 * in one; a crash mid-walk leaves the object `awaiting`/`complete` and the pass simply runs again.
 * Nothing here logs or touches the network.
 */
internal class MediaReceiveSteps(
    private val database: SyncDatabase,
    private val sync: DmSyncPorts,
    private val files: CiphertextFiles,
    private val readers: MediaReaders,
    private val preparing: () -> Set<String>,
    private val checkpoint: DmCheckpoint,
    private val contexts: SelfContexts,
    private val clock: DmClock,
    /** The pool cap (§7.5): the production default; tests shrink it to make eviction observable. */
    private val poolCapBytes: Long = MediaLimits.POOL_CAP_BYTES,
) {
    private val fragments = MediaFragments()
    private val objects = MediaObjects(fragments)
    private val blobs = MediaBlobs(fragments)
    private val reconcile = MediaReconcile(files, blobs, fragments)
    private val expiry = ExpiryClock(database, clock)

    /** The local counters §7.2/§7.5 mark "counted" at: nothing here is relay-visible, all of it is test-observable. */
    class Stats {
        @Volatile var wrongSizeDrops: Int = 0; private set
        @Volatile var duplicateConsumes: Int = 0; private set
        @Volatile var belowFloorConsumes: Int = 0; private set
        @Volatile var writeFailures: Int = 0; private set
        @Volatile var bound: Int = 0; private set
        @Volatile var verified: Int = 0; private set
        @Volatile var corrupted: Int = 0; private set
        @Volatile var declaredIncomplete: Int = 0; private set
        @Volatile var evicted: Int = 0; private set

        fun addWrongSize() { wrongSizeDrops++ }
        fun addDuplicate() { duplicateConsumes++ }
        fun addBelowFloor() { belowFloorConsumes++ }
        fun addWriteFailure() { writeFailures++ }
        fun addBound() { bound++ }
        fun addVerified() { verified++ }
        fun addCorrupt() { corrupted++ }
        fun addIncomplete() { declaredIncomplete++ }
        fun addEvicted(n: Int) { evicted += n }

        override fun toString(): String =
            "Stats(bound=$bound, verified=$verified, corrupt=$corrupted, incomplete=$declaredIncomplete)"
    }

    val stats = Stats()

    /** The expiry clock the media stores read under, for callers outside a pass (R-T7). */
    fun nowE(): Long = expiry.nowSeconds()

    /**
     * `MEDIA-INGEST` (§7.2): claim up to [limit] blobs Phase 7 fetched into `M_0` and move each into
     * the ciphertext store. Returns after [limit] blobs or the claim batch, whichever first; a
     * storage-full transaction defers the blob like F9's RECV path and stops the batch (the next
     * pass claims it again).
     */
    fun ingest(limit: Int = INGEST_BATCH) {
        val nowE = expiry.nowSeconds()
        val claimed = sync.inbox.claim(Consumer.MEDIA, limit)
        var evicted = 0
        var needReconcile = false
        for (blob in claimed) {
            val bytes = blob.ciphertext
            if (bytes.size != MediaLimits.FRAGMENT_BYTES) {
                consumeOnly(blob.namespace, blob.hash)
                stats.addWrongSize()
                continue
            }
            if (blobs.existsIn(database, blob.hash)) {
                consumeOnly(blob.namespace, blob.hash)
                stats.addDuplicate()
                continue
            }
            val name = files.newName()
            when (val written = writeFloorSafe(name, bytes)) {
                null -> {
                    // The write itself failed (not the floor — that is [WriteResult.BelowFloor]):
                    // defer the blob like F9's RECV path (§21.12 point 1) so its offer counter
                    // resets, and stop the batch. The next pass claims it again.
                    deferQuietly(blob.namespace, blob.hash)
                    needReconcile = true
                    break
                }
                WriteResult.BelowFloor -> {
                    // §7.5: below the free-space floor the blob is consumed without a file,
                    // counted — what is fetched never follows local state.
                    consumeOnly(blob.namespace, blob.hash)
                    stats.addBelowFloor()
                    continue
                }
                is WriteResult.Written -> {
                    try {
                        database.transaction { tx ->
                            if (!sync.inbox.markConsumed(tx, blob.namespace, blob.hash)) return@transaction
                            val waiting = blobs.ingest(
                                tx, blob.hash.toByteArray(), name,
                                MediaBlobs.retentionDay(blob.relayExpiryHour, nowE),
                            )
                            for (objectId in waiting) completeIfReady(tx, objectId)
                            val evictedNow = blobs.evictOverCap(tx, poolCapBytes)
                            if (evictedNow > 0) {
                                evicted += evictedNow
                                needReconcile = true
                            }
                        }
                    } catch (e: StorageFullException) {
                        // The file is an orphan the reconcile will take; defer the blob like F9's
                        // RECV path (§21.12 point 1) so its offer counter resets, and stop the batch.
                        deferQuietly(blob.namespace, blob.hash)
                        needReconcile = true
                        break
                    }
                }
            }
        }
        stats.addEvicted(evicted)
        if (needReconcile) reconcile()
    }

    /**
     * `MEDIA-BIND` (§7.2): every `awaiting` object whose manifest hash has a stored blob meets its
     * manifest — opened through the reader outside the transaction, recorded inside it.
     */
    fun bind(limit: Int = BIND_BATCH) {
        val nowE = expiry.nowSeconds()
        val candidates = database.transaction { tx ->
            objects.pendingDownloads(tx.sql, nowE, limit)
                .mapNotNull { objects.byId(tx.sql, it, nowE) }
                .filter { it.state == ObjectState.AWAITING }
        }
        for (obj in candidates) bindOne(obj, nowE)
    }

    /**
     * `MEDIA-VERIFY` (§7.3): every `complete` object gets the full validation pass before any
     * exposure; the walk runs outside the transaction, the verdict inside it.
     */
    fun verify(limit: Int = VERIFY_BATCH) {
        val nowE = expiry.nowSeconds()
        val candidates = database.transaction { tx ->
            objects.toVerify(tx.sql, nowE, limit)
                .mapNotNull { objects.byId(tx.sql, it, nowE) }
                .filter { it.state == ObjectState.COMPLETE }
        }
        for (obj in candidates) verifyOne(obj, nowE)
    }

    /**
     * `MEDIA-GC` (§7.5): declared losses, expired pooled blobs and unnamed sealed garbage. Runs on
     * the time-triggered pass; a process that was not running applies it at start.
     */
    fun gc(limit: Int = GC_BATCH) {
        val nowE = expiry.nowSeconds()
        var keysErased = false
        var rowsDeleted = false
        database.transaction { tx ->
            for (objectId in objects.incompleteDue(tx.sql, nowE, limit)) {
                objects.markIncomplete(tx, objectId)
                stats.addIncomplete()
                keysErased = true
                rowsDeleted = true
            }
            if (blobs.collectExpired(tx, nowE, limit) > 0) rowsDeleted = true
            if (blobs.collectUnnamedSealed(tx) > 0) rowsDeleted = true
        }
        if (keysErased) checkpoint.truncate()
        if (rowsDeleted) reconcile()
    }

    /** One reconcile pass (the maintenance that follows any commit that dereferenced files). */
    fun reconcile() {
        reconcile.run(database, preparing)
        files.syncDirectory()
    }

    // ---------------------------------------------------------------- internals

    /** Bind one `awaiting` object to its manifest, or declare it `corrupt` (§7.2). */
    private fun bindOne(obj: MediaObject, nowE: Long) {
        val row = blobs.byHashIn(database, obj.manifestHash) ?: return
        val manifest = try {
            files.read(row.fileName)
        } catch (e: org.ghost.media.store.CiphertextFilesException) {
            return // the reconcile names the loss; the object stays awaiting for now
        }
        if (manifest.size != MediaLimits.FRAGMENT_BYTES) {
            corrupt(obj.objectId, nowE)
            return
        }
        val keyEnv = obj.keyEnv ?: run { corrupt(obj.objectId, nowE); return }
        val opened = readers.open(
            MediaReaders.OpenSpec(
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
                readable = false,
            ),
        )
        when (opened) {
            is MediaReaders.Opened.Ok -> {
                readers.close(opened.reader)
                try {
                    database.transaction { tx ->
                        fragments.insertIncoming(tx, obj.objectId, obj.classCode, obj.manifestHash, opened.hashes)
                        objects.markFetching(tx, obj.objectId)
                        // The descriptor can arrive last (§7.2): every row inserted above may
                        // already be bound, and then the last `expected` row bound here.
                        completeIfReady(tx, obj.objectId)
                    }
                    stats.addBound()
                } catch (e: org.ghost.media.store.MediaStoreException) {
                    // A guarded refusal (a duplicate bind racing us on the actor's own thread is
                    // impossible; this is a store defect): declare the loss rather than wedge the pass.
                    corrupt(obj.objectId, nowE)
                }
            }
            MediaReaders.Opened.HashMismatch,
            MediaReaders.Opened.CommitMismatch,
            MediaReaders.Opened.NotOpen,
            MediaReaders.Opened.NonCanonical,
            MediaReaders.Opened.StateCorrupt,
            -> corrupt(obj.objectId, nowE)
            MediaReaders.Opened.Limited,
            MediaReaders.Opened.Unavailable,
            -> Unit // transient: the next pass tries the object again
        }
    }

    /** The full validation pass over one `complete` object (§7.3). */
    private fun verifyOne(obj: MediaObject, nowE: Long) {
        val keyEnv = obj.keyEnv ?: run { corrupt(obj.objectId, nowE); return }
        val manifestRow = blobs.byHashIn(database, obj.manifestHash)
        val filesByOrdinal = blobs.filesIn(database, obj.objectId, nowE)
        if (manifestRow == null) {
            corrupt(obj.objectId, nowE)
            return
        }
        val manifest = try {
            files.read(manifestRow.fileName)
        } catch (e: org.ghost.media.store.CiphertextFilesException) {
            corrupt(obj.objectId, nowE)
            return
        }
        if (manifest.size != MediaLimits.FRAGMENT_BYTES) {
            corrupt(obj.objectId, nowE)
            return
        }
        val opened = readers.open(
            MediaReaders.OpenSpec(
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
                readable = false,
            ),
        )
        if (opened !is MediaReaders.Opened.Ok) {
            when (opened) {
                MediaReaders.Opened.Limited,
                MediaReaders.Opened.Unavailable,
                -> return // transient: retry next pass
                else -> {
                    corrupt(obj.objectId, nowE)
                    return
                }
            }
        }
        var verdict: MediaReaders.Validated? = null
        var broke = false
        try {
            val fragmentsPerChunk = 4
            val chunks = MediaLimits.CLASSES[obj.classCode] / fragmentsPerChunk
            for (index in 0 until chunks) {
                val chunkBytes = try {
                    chunkOf(filesByOrdinal, index * fragmentsPerChunk, fragmentsPerChunk)
                } catch (e: org.ghost.media.store.CiphertextFilesException) {
                    broke = true
                    break
                }
                if (chunkBytes == null) {
                    broke = true
                    break
                }
                when (val chunked = readers.chunk(opened.reader, index, chunkBytes, validate = true)) {
                    is MediaReaders.Chunked.Ok -> Unit
                    else -> {
                        broke = true
                        break
                    }
                }
            }
            if (!broke) verdict = readers.finish(opened.reader)
        } finally {
            readers.close(opened.reader)
        }
        val ok = !broke && verdict is MediaReaders.Validated.Ok
        database.transaction { tx ->
            if (ok) {
                objects.markVerified(tx, obj.objectId)
            } else {
                objects.markCorrupt(tx, obj.objectId)
            }
        }
        if (ok) {
            stats.addVerified()
        } else {
            stats.addCorrupt()
            checkpoint.truncate()
        }
    }

    /** Concatenate the four fragment files of chunk [firstOrdinal] — null when one is missing. */
    private fun chunkOf(filesByOrdinal: Map<Int, ByteArray>, firstOrdinal: Int, count: Int): ByteArray? {
        val out = java.io.ByteArrayOutputStream(count * MediaLimits.FRAGMENT_BYTES)
        for (i in 0 until count) {
            val name = filesByOrdinal[firstOrdinal + i] ?: return null
            out.write(files.read(name))
        }
        return out.toByteArray()
    }

    /** Consume a claimed blob without writing anything (§7.2's counted drops). */
    private fun consumeOnly(namespace: org.ghost.sync.api.NamespaceId, hash: org.ghost.sync.api.BlobHash) {
        try {
            database.transaction { tx -> sync.inbox.markConsumed(tx, namespace, hash) }
        } catch (e: StorageFullException) {
            deferQuietly(namespace, hash)
        }
    }

    private fun deferQuietly(namespace: org.ghost.sync.api.NamespaceId, hash: org.ghost.sync.api.BlobHash) {
        try {
            database.transaction { tx -> sync.inbox.defer(tx, namespace, hash, STORAGE_FULL_DEFER_SECONDS) }
        } catch (e: StorageFullException) {
            // Both transactions failed on a full disk: the blob keeps its offer counter, and the
            // pass moves on — the next pass claims it again (a defer is a courtesy, not a latch).
        }
    }

    /**
     * The manifest bind's completeness half (§7.2): when the last `expected` row of an object bound,
     * the object becomes `complete` — [MediaObjects.markComplete]'s guard refuses unless every row
     * of the class is `bound`, so a too-early call is impossible by construction.
     */
    private fun completeIfReady(tx: SyncTransaction, objectId: ByteArray) {
        if (fragments.expectedCount(tx.sql, objectId) == 0) {
            objects.markComplete(tx, objectId)
        }
    }

    /** Move an object to `corrupt`: its key is erased and its references released in the transaction. */
    private fun corrupt(objectId: ByteArray, nowE: Long) {
        database.transaction { tx -> objects.markCorrupt(tx, objectId) }
        stats.addCorrupt()
        checkpoint.truncate()
    }

    /** The write with the §7.5 floor; null when the write itself failed (counted as a write failure). */
    private fun writeFloorSafe(name: ByteArray, bytes: ByteArray): WriteResult? =
        try {
            files.write(name, bytes, enforceFloor = true)
        } catch (e: org.ghost.media.store.CiphertextFilesException) {
            stats.addWriteFailure()
            null
        } catch (e: java.io.IOException) {
            stats.addWriteFailure()
            null
        }

    // Small store wrappers that open their own read transaction, so the step code above reads
    // exactly like the pass it runs in (the stores are transaction-scoped everywhere else).
    private fun MediaBlobs.existsIn(database: SyncDatabase, hash: org.ghost.sync.api.BlobHash): Boolean =
        database.transaction { tx -> exists(tx.sql, hash.toByteArray()) }

    private fun MediaBlobs.byHashIn(database: SyncDatabase, hash: ByteArray): org.ghost.media.store.MediaBlob? =
        database.transaction { tx -> byHash(tx.sql, hash) }

    private fun MediaBlobs.filesIn(
        database: SyncDatabase,
        objectId: ByteArray,
        nowE: Long,
    ): Map<Int, ByteArray> = database.transaction { tx ->
        files(tx.sql, objectId, nowE).associate { it.ordinal to it.fileName }
    }

    companion object {
        private const val INGEST_BATCH: Int = 32
        private const val BIND_BATCH: Int = 32
        private const val VERIFY_BATCH: Int = 8
        private const val GC_BATCH: Int = 64
        private const val STORAGE_FULL_DEFER_SECONDS: Int = 60
    }
}
