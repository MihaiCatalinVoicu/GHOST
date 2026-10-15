package org.ghost.media.store

import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.SyncTransaction

/**
 * The fragment-side rows of the media schema (Phase 11 design §13.6): `media_fragment` (which blob is at which ordinal of
 * which object, and how far its upload went) and `media_outbound_op` (which Phase 7 operation carried it).
 *
 * **Every read carries the expiry filter of §10.7 point 4 as the media tables have it** (a row dies with its message:
 * `dm_message.delete_at_minute IS NULL OR > :now_e`, and an incoming object past its `incomplete_after_hour` is declared
 * loss, so its fragments are gone to a reader before `MEDIA-GC` deletes them), and each is registered in `:storage`'s
 * `MediaDaoQueries`, which runs it against a world that still holds the expired rows and one that does not and requires
 * the two to be indistinguishable (mutant ME-16). The few reads that must **see** expired rows because a bound is counted
 * over them are `MediaBoundQueries`.
 *
 * **Every write goes through the caller's [SyncTransaction]** (the transactions of §13.5 are each one
 * `SyncDatabase.transaction`; a store opens none), and there is no `REPLACE` and no upsert anywhere (gate G-DM4): a row that
 * may exist is checked first, and the `*_no_replace` guards of the schema are the backstop.
 */
class MediaFragments {

    // ---------------------------------------------------------------- reads (expiry-filtered)

    /** The fragments of a live object, manifest first (ordinal -1), then 0, 1, ... An incoming object past its deadline has none to a reader. */
    fun fragments(sql: SqlExecutor, objectId: ByteArray, nowE: Long): List<MediaFragment> {
        val out = ArrayList<MediaFragment>()
        sql.query(FRAGMENTS_OF, listOf(Fields.objectId(objectId), nowE, nowE)) { out += readFragment(objectId, it) }
        return out
    }

    /** One fragment of a live object, if it is there. */
    fun fragment(sql: SqlExecutor, objectId: ByteArray, ordinal: Int, nowE: Long): MediaFragment? {
        var out: MediaFragment? = null
        sql.query(FRAGMENT, listOf(Fields.objectId(objectId), Fields.ordinal(ordinal).toLong(), nowE, nowE)) { out = readFragment(objectId, it) }
        return out
    }

    /** The ordinals of an outgoing object that no operation carries yet, manifest first then the lowest (`MEDIA-FEED`, §6.4). */
    fun unsent(sql: SqlExecutor, objectId: ByteArray, nowE: Long, limit: Int): List<MediaFragment> {
        val out = ArrayList<MediaFragment>()
        sql.query(UNSENT, listOf(Fields.objectId(objectId), nowE, limit.toLong())) { out += readFragment(objectId, it) }
        return out
    }

    /** The operation behind a Phase 7 outcome, if its object is still there: an op whose row is gone is released and ignored (§6.4 `MEDIA-OUTCOME`). */
    fun op(sql: SqlExecutor, operationId: ByteArray, nowE: Long): MediaOp? {
        var out: MediaOp? = null
        sql.query(OP_BY_ID, listOf(Fields.bytes("media_outbound_op.operation_id", operationId, 16), nowE)) {
            out = MediaOp(operationId, it.blob(0), it.long(1).toInt(), it.long(2).toInt(), it.long(3).toInt())
        }
        return out
    }

    // ---------------------------------------------------------------- reads (bounds: they count every row, the expired ones too)

    /** Open ordinals of one object: `MEDIA-FEED` keeps at most [MediaLimits.OPEN_PER_OBJECT]. Counts every row, as the operations in flight are real whether or not the message has expired. */
    fun openCount(sql: SqlExecutor, objectId: ByteArray): Int =
        sql.queryCount(OPEN_OF_OBJECT, listOf(Fields.objectId(objectId)))

    /** Open ordinals of the device: at most [MediaLimits.OPEN_PER_DEVICE]. */
    fun openCountOfDevice(sql: SqlExecutor): Int = sql.queryCount(OPEN_OF_DEVICE, emptyList())

    /** The ordinals of an object still waiting for their blob (`expected`): completeness is "none left" (§7.2). */
    fun expectedCount(sql: SqlExecutor, objectId: ByteArray): Int =
        sql.queryCount(EXPECTED_OF_OBJECT, listOf(Fields.objectId(objectId)))

    /** All the fragment rows of an object, `expected` and `bound` (completeness is "F + 1 bound rows", §7.2). */
    fun boundCount(sql: SqlExecutor, objectId: ByteArray): Int =
        sql.queryCount(BOUND_OF_OBJECT, listOf(Fields.objectId(objectId)))

    /** The upload state of one ordinal, whatever the age of its object (a bound: the feeder and the resend rule read the row as it is). */
    fun uploadStateOf(sql: SqlExecutor, objectId: ByteArray, ordinal: Int): UploadState? {
        var out: UploadState? = null
        sql.query(UPLOAD_STATE_OF, listOf(Fields.objectId(objectId), Fields.ordinal(ordinal).toLong())) {
            if (!it.isNull(0)) out = UploadState.of(it.string(0))
        }
        return out
    }

    /** The retry generation of an object's upload, whatever the age of the object (a bound: the feeder numbers its operations by it); null when there is no upload row. */
    fun uploadGenerationOf(sql: SqlExecutor, objectId: ByteArray): Int? {
        var out: Int? = null
        sql.query(UPLOAD_GENERATION_OF, listOf(Fields.objectId(objectId))) { out = it.long(0).toInt() }
        return out
    }

    /** Whether the operation of (object, ordinal, generation, resend) exists, whatever the age of its object (a bound). */
    fun operationExists(sql: SqlExecutor, objectId: ByteArray, ordinal: Int, retryGen: Int, resendCount: Int): Boolean =
        sql.queryCount(OP_EXISTS, listOf(Fields.objectId(objectId), Fields.ordinal(ordinal).toLong(), retryGen.toLong(), resendCount.toLong())) > 0

    /** The objects (live or not) with a fragment row that names [blobHash]: who loses the blob if its file is gone (the reconcile report). */
    fun objectsNaming(sql: SqlExecutor, blobHash: ByteArray): List<ByteArray> {
        val out = ArrayList<ByteArray>()
        sql.query(OBJECTS_NAMING, listOf(Fields.hash("media_fragment.blob_hash", blobHash))) { out += it.blob(0) }
        return out
    }

    // ---------------------------------------------------------------- writes

    /**
     * `MEDIA-COMMIT` (§6.3 point 3): the `F + 1` fragment rows of a sealed object, `bound` and `unsent`, the manifest at
     * ordinal -1 and the fragments at 0 to F - 1. The blob rows must exist already (the schema refuses a `bound` row
     * naming a blob that is not there, `media_fragment_bound_blob_insert`). [fragmentHashes] has exactly `F` entries.
     */
    fun insertSealed(tx: SyncTransaction, objectId: ByteArray, classCode: Int, manifestHash: ByteArray, fragmentHashes: List<ByteArray>) {
        Fields.objectId(objectId)
        if (fragmentHashes.size != MediaLimits.CLASSES.getOrNull(classCode)) throw MediaStoreException(MediaStoreError.BAD_VALUE, "media_fragment.ordinal")
        insertSealedRow(tx, objectId, MediaLimits.MANIFEST_ORDINAL, manifestHash)
        for ((ordinal, hash) in fragmentHashes.withIndex()) insertSealedRow(tx, objectId, ordinal, hash)
    }

    private fun insertSealedRow(tx: SyncTransaction, objectId: ByteArray, ordinal: Int, blobHash: ByteArray) {
        tx.sql.exec(
            "INSERT INTO media_fragment(object_id, ordinal, blob_hash, state, upload_state) VALUES (?, ?, ?, 'bound', 'unsent')",
            listOf(objectId, Fields.ordinal(ordinal).toLong(), Fields.hash("media_fragment.blob_hash", blobHash)),
        )
    }

    /**
     * `MEDIA-BIND` (§7.2): one row per ordinal of an incoming object, `bound` if a blob row with that hash exists and
     * `expected` otherwise, **whether or not another object names the same hash** (D25). The manifest's own row (ordinal
     * -1) comes first. The caller then moves the object to `fetching` ([MediaObjects.markFetching]).
     *
     * **The blob row is looked for whatever its retention day** (the schema's `media_fragment_bound_blob_insert` demands exactly
     * that: a row for a blob that exists is `bound`): a pooled blob past its last day that `MEDIA-GC` has not collected yet is
     * adopted by a late descriptor, and one the collector has taken is waited for. The outcome depends on when the maintenance
     * ran and on nothing a relay sees; judged and accepted, and pinned by
     * `MediaFragmentsTest.aLateDescriptorAdoptsAPooledBlobPastItsDayUntilTheCollectorHasRunAndWaitsForTheBlobAfterIt` (§22.4 row 30).
     */
    fun insertIncoming(tx: SyncTransaction, objectId: ByteArray, classCode: Int, manifestHash: ByteArray, fragmentHashes: List<ByteArray>) {
        Fields.objectId(objectId)
        if (fragmentHashes.size != MediaLimits.CLASSES.getOrNull(classCode)) throw MediaStoreException(MediaStoreError.BAD_VALUE, "media_fragment.ordinal")
        insertIncomingRow(tx, objectId, MediaLimits.MANIFEST_ORDINAL, manifestHash)
        for ((ordinal, hash) in fragmentHashes.withIndex()) insertIncomingRow(tx, objectId, ordinal, hash)
    }

    private fun insertIncomingRow(tx: SyncTransaction, objectId: ByteArray, ordinal: Int, blobHash: ByteArray) {
        tx.sql.exec(
            "INSERT INTO media_fragment(object_id, ordinal, blob_hash, state, upload_state) " +
                "SELECT ?, ?, ?, CASE WHEN EXISTS (SELECT 1 FROM media_blob WHERE blob_hash = ?) THEN 'bound' ELSE 'expected' END, NULL",
            listOf(objectId, Fields.ordinal(ordinal).toLong(), Fields.hash("media_fragment.blob_hash", blobHash), blobHash),
        )
    }

    /**
     * `MEDIA-INGEST` (§7.2): the blob [blobHash] has arrived (its row is inserted, in this transaction, by
     * [MediaBlobs.insert]); every `expected` fragment row naming it, **of any object**, becomes `bound`. Returns the
     * number of rows bound.
     */
    fun bindExpected(tx: SyncTransaction, blobHash: ByteArray): Int =
        tx.sql.execUpdate(
            "UPDATE media_fragment SET state = 'bound' WHERE blob_hash = ? AND state = 'expected'",
            listOf(Fields.hash("media_fragment.blob_hash", blobHash)),
        )

    /** The objects that have an `expected` row for [blobHash]: read before [bindExpected], they are the ones whose completeness is then checked. */
    fun objectsExpecting(sql: SqlExecutor, blobHash: ByteArray): List<ByteArray> {
        val out = ArrayList<ByteArray>()
        sql.query(OBJECTS_EXPECTING, listOf(Fields.hash("media_fragment.blob_hash", blobHash))) { out += it.blob(0) }
        return out
    }

    /**
     * `MEDIA-FEED` (§6.4): the operation [op] is recorded and its ordinal goes `unsent` → `open`, in the caller's
     * transaction with the `Outbox.enqueue` that carries it. At most [MediaLimits.OPEN_PER_OBJECT] ordinals of an object
     * and [MediaLimits.OPEN_PER_DEVICE] of the device are open: a feeder that asks for more has a defect
     * ([MediaStoreError.LIMIT]), the schema does not count.
     */
    fun enqueue(tx: SyncTransaction, op: MediaOp) {
        checkOp(op)
        // The first operation of an ordinal in a generation is resend 0, and a fresh feed happens in the object's current
        // generation: the op id is derived from both (§6.4), and a feeder with a stale one would re-feed a past generation.
        if (op.resendCount != 0) throw MediaStoreException(MediaStoreError.BAD_VALUE, "media_outbound_op.resend_count")
        val generation = uploadGenerationOf(tx.sql, op.objectId) ?: throw MediaStoreException(MediaStoreError.MISSING_ROW, "media_upload")
        if (op.retryGen != generation) throw MediaStoreException(MediaStoreError.BAD_VALUE, "media_outbound_op.retry_gen")
        if (openCount(tx.sql, op.objectId) >= MediaLimits.OPEN_PER_OBJECT) throw MediaStoreException(MediaStoreError.LIMIT, "media_fragment.upload_state")
        if (openCountOfDevice(tx.sql) >= MediaLimits.OPEN_PER_DEVICE) throw MediaStoreException(MediaStoreError.LIMIT, "media_fragment.upload_state")
        // The ordinal first: a fragment that is not `unsent` (already open, or acknowledged) is a feeder defect, and no
        // operation is written for it.
        val changed = tx.sql.execUpdate(
            "UPDATE media_fragment SET upload_state = 'open' WHERE object_id = ? AND ordinal = ? AND upload_state = 'unsent'",
            listOf(op.objectId, op.ordinal.toLong()),
        )
        if (changed != 1) throw MediaStoreException(MediaStoreError.ILLEGAL_TRANSITION, "media_fragment.upload_state")
        insertOp(tx, op)
    }

    /**
     * `MEDIA-OUTCOME` (§6.4): an INDETERMINATE outcome with a resend left is the Phase 7 identical-bytes resend as a new
     * operation of the **same** ordinal and retry generation, `resend_count + 1`; the ordinal stays `open`. At most
     * [MediaLimits.MAX_RESENDS] resends per ordinal and generation. **The previous operation must exist** (same ordinal and
     * generation, `resend_count - 1`): the generation of a resend is the one of the operation it repeats, which is not the
     * upload's current one when the user retried while the ordinal was still in flight (`failed` ordinals go back to `unsent`,
     * the `open` ones keep their operations).
     */
    fun insertResend(tx: SyncTransaction, op: MediaOp) {
        checkOp(op)
        if (op.resendCount < 1) throw MediaStoreException(MediaStoreError.BAD_VALUE, "media_outbound_op.resend_count")
        if (uploadStateOf(tx.sql, op.objectId, op.ordinal) != UploadState.OPEN) {
            throw MediaStoreException(MediaStoreError.ILLEGAL_TRANSITION, "media_fragment.upload_state")
        }
        if (!operationExists(tx.sql, op.objectId, op.ordinal, op.retryGen, op.resendCount - 1)) {
            throw MediaStoreException(MediaStoreError.ILLEGAL_TRANSITION, "media_outbound_op.resend_count")
        }
        insertOp(tx, op)
    }

    private fun checkOp(op: MediaOp) {
        Fields.bytes("media_outbound_op.operation_id", op.operationId, 16)
        Fields.objectId(op.objectId)
        Fields.ordinal(op.ordinal)
        Fields.range("media_outbound_op.retry_gen", op.retryGen.toLong(), 0, MediaLimits.MAX_RETRIES.toLong())
        Fields.range("media_outbound_op.resend_count", op.resendCount.toLong(), 0, MediaLimits.MAX_RESENDS.toLong())
    }

    private fun insertOp(tx: SyncTransaction, op: MediaOp) {
        tx.sql.exec(
            "INSERT INTO media_outbound_op(operation_id, object_id, ordinal, retry_gen, resend_count) VALUES (?, ?, ?, ?, ?)",
            listOf(op.operationId, op.objectId, op.ordinal.toLong(), op.retryGen.toLong(), op.resendCount.toLong()),
        )
    }

    /** §6.4's corrupt-file rule ([MediaObjects.retryUpload]): whether any ordinal of the object failed. */
    fun hasFailed(sql: SqlExecutor, objectId: ByteArray): Boolean =
        sql.queryCount(HAS_FAILED, listOf(Fields.objectId(objectId))) > 0

    /**
     * `MEDIA-OUTCOME` (§6.4): an ordinal's final state. `open` → `sent`, `degraded`, `indeterminate` or `failed`; anything
     * else is not an outcome ([MediaStoreError.ILLEGAL_TRANSITION]).
     */
    fun settle(tx: SyncTransaction, objectId: ByteArray, ordinal: Int, to: UploadState) {
        if (to == UploadState.UNSENT || to == UploadState.OPEN) throw MediaStoreException(MediaStoreError.ILLEGAL_TRANSITION, "media_fragment.upload_state")
        val changed = tx.sql.execUpdate(
            "UPDATE media_fragment SET upload_state = ? WHERE object_id = ? AND ordinal = ? AND upload_state = 'open'",
            listOf(to.code, Fields.objectId(objectId), Fields.ordinal(ordinal).toLong()),
        )
        if (changed != 1) throw MediaStoreException(MediaStoreError.ILLEGAL_TRANSITION, "media_fragment.upload_state")
    }

    /** True when every ordinal of the object is final in {`sent`, `degraded`, `indeterminate`} and there is at least one: `MEDIA-READY`'s condition (§6.4). */
    fun allAcknowledged(sql: SqlExecutor, objectId: ByteArray): Boolean {
        val total = sql.queryCount(ROWS_OF_OBJECT, listOf(Fields.objectId(objectId)))
        val acknowledged = sql.queryCount(ACKNOWLEDGED_OF_OBJECT, listOf(objectId))
        return total > 0 && total == acknowledged
    }

    /**
     * Releases an object's references (§7.2 "Releasing references"): deletes its fragment rows and then the blob rows that
     * no fragment names any more, by [policy]. Returns the number of blob **rows** deleted; their files are deleted by the
     * reconcile that follows the commit (file deletions come after the commit that dereferences them, §13.5).
     */
    fun release(tx: SyncTransaction, objectIds: List<ByteArray>, policy: ReleasePolicy): Int {
        if (objectIds.isEmpty()) return 0
        var deleted = 0
        for (chunk in objectIds.chunked(CHUNK)) {
            val ids = chunk.map { Fields.objectId(it) }
            // The blobs the objects name, read before the rows go: only these may become unnamed by this release (a pooled
            // blob of another object must not be deleted by it).
            val hashes = LinkedHashSet<List<Byte>>()
            for (id in ids) tx.sql.query(HASHES_OF_OBJECT, listOf(id)) { hashes += it.blob(0).toList() }
            tx.sql.exec("DELETE FROM media_fragment WHERE object_id IN (${Fields.marks(ids.size)})", ids)
            deleted += deleteUnnamed(tx, hashes.map { it.toByteArray() }, policy)
        }
        return deleted
    }

    /** The hashes of the blobs the fragments of an object name: what a release or an erasure must look at afterwards. */
    fun hashesOf(sql: SqlExecutor, objectId: ByteArray): List<ByteArray> {
        val out = ArrayList<ByteArray>()
        sql.query(HASHES_OF_OBJECT, listOf(Fields.objectId(objectId))) { out += it.blob(0) }
        return out
    }

    /** Deletes, of [hashes], the blob rows that no fragment names (and, for [ReleasePolicy.RELEASE], that are sealed). */
    internal fun deleteUnnamed(tx: SyncTransaction, hashes: List<ByteArray>, policy: ReleasePolicy): Int {
        var deleted = 0
        for (chunk in hashes.chunked(CHUNK)) {
            val origin = if (policy == ReleasePolicy.RELEASE) " AND origin = 'sealed'" else ""
            deleted += tx.sql.execUpdate(
                "DELETE FROM media_blob WHERE blob_hash IN (${Fields.marks(chunk.size)})$origin " +
                    "AND NOT EXISTS (SELECT 1 FROM media_fragment f WHERE f.blob_hash = media_blob.blob_hash)",
                chunk,
            )
        }
        return deleted
    }

    private fun readFragment(objectId: ByteArray, row: SqlExecutor.Row): MediaFragment = MediaFragment(
        objectId = objectId,
        ordinal = row.long(0).toInt(),
        blobHash = row.blob(1),
        state = FragmentState.of(row.string(2)),
        uploadState = if (row.isNull(3)) null else UploadState.of(row.string(3)),
    )

    private companion object {
        /** The bound variables of one statement stay far below SQLite's limit. */
        const val CHUNK = 400

        const val FRAGMENTS_OF =
            "SELECT f.ordinal, f.blob_hash, f.state, f.upload_state FROM media_fragment f " +
                "JOIN media_object o ON o.object_id = f.object_id LEFT JOIN dm_message m ON m.message_id = o.message_id " +
                "WHERE f.object_id = ? AND (m.message_id IS NULL OR m.delete_at_minute IS NULL OR m.delete_at_minute > ?) " +
                "AND NOT (o.state IN ('awaiting', 'fetching') AND o.incomplete_after_hour <= ?) ORDER BY f.ordinal"

        const val FRAGMENT =
            "SELECT f.ordinal, f.blob_hash, f.state, f.upload_state FROM media_fragment f " +
                "JOIN media_object o ON o.object_id = f.object_id LEFT JOIN dm_message m ON m.message_id = o.message_id " +
                "WHERE f.object_id = ? AND f.ordinal = ? AND (m.message_id IS NULL OR m.delete_at_minute IS NULL OR m.delete_at_minute > ?) " +
                "AND NOT (o.state IN ('awaiting', 'fetching') AND o.incomplete_after_hour <= ?)"

        const val UNSENT =
            "SELECT f.ordinal, f.blob_hash, f.state, f.upload_state FROM media_fragment f " +
                "JOIN media_object o ON o.object_id = f.object_id LEFT JOIN dm_message m ON m.message_id = o.message_id " +
                "WHERE f.object_id = ? AND f.upload_state = 'unsent' " +
                "AND (m.message_id IS NULL OR m.delete_at_minute IS NULL OR m.delete_at_minute > ?) ORDER BY f.ordinal LIMIT ?"

        const val OP_BY_ID =
            "SELECT p.object_id, p.ordinal, p.retry_gen, p.resend_count FROM media_outbound_op p " +
                "JOIN media_object o ON o.object_id = p.object_id LEFT JOIN dm_message m ON m.message_id = o.message_id " +
                "WHERE p.operation_id = ? AND (m.message_id IS NULL OR m.delete_at_minute IS NULL OR m.delete_at_minute > ?)"

        const val OPEN_OF_OBJECT = "SELECT count(*) FROM media_fragment WHERE object_id = ? AND upload_state = 'open'"
        const val OPEN_OF_DEVICE = "SELECT count(*) FROM media_fragment WHERE upload_state = 'open'"
        const val HAS_FAILED = "SELECT count(*) FROM media_fragment WHERE object_id = ? AND upload_state = 'failed'"
        const val EXPECTED_OF_OBJECT = "SELECT count(*) FROM media_fragment WHERE object_id = ? AND state = 'expected'"
        const val BOUND_OF_OBJECT = "SELECT count(*) FROM media_fragment WHERE object_id = ? AND state = 'bound'"
        const val OBJECTS_NAMING = "SELECT DISTINCT object_id FROM media_fragment WHERE blob_hash = ? ORDER BY object_id"
        const val OBJECTS_EXPECTING = "SELECT DISTINCT object_id FROM media_fragment WHERE blob_hash = ? AND state = 'expected' ORDER BY object_id"
        const val UPLOAD_STATE_OF = "SELECT upload_state FROM media_fragment WHERE object_id = ? AND ordinal = ?"
        const val UPLOAD_GENERATION_OF = "SELECT retry_gen FROM media_upload WHERE object_id = ?"
        const val OP_EXISTS =
            "SELECT count(*) FROM media_outbound_op WHERE object_id = ? AND ordinal = ? AND retry_gen = ? AND resend_count = ?"
        const val ROWS_OF_OBJECT = "SELECT count(*) FROM media_fragment WHERE object_id = ?"
        const val HASHES_OF_OBJECT = "SELECT DISTINCT blob_hash FROM media_fragment WHERE object_id = ?"
        const val ACKNOWLEDGED_OF_OBJECT =
            "SELECT count(*) FROM media_fragment WHERE object_id = ? AND upload_state IN ('sent', 'degraded', 'indeterminate')"
    }
}

/**
 * What an object's blobs become when its references go (§7.2): an object that turns `corrupt` or `incomplete` **releases**
 * them (an ingested blob that no row names returns to the pool with its original retention; a sealed one is deleted), and an
 * erasure (SWEEP, view-once close, the sender's view-once cleanup) **erases** them (every blob no row names any more, whatever
 * its origin).
 */
enum class ReleasePolicy { RELEASE, ERASE }

internal fun SqlExecutor.queryCount(sql: String, args: List<Any?>): Int {
    var out = 0
    query(sql, args) { out = it.long(0).toInt() }
    return out
}
