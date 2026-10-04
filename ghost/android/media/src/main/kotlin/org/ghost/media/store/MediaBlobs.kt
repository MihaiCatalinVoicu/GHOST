package org.ghost.media.store

import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.SyncTransaction

/**
 * The blob-side rows of the media schema (Phase 11 design §7.2, §7.5, §13.6): `media_blob`, one row and one file per
 * **distinct** ciphertext blob (D25), and the references that name it — any number of `media_fragment` rows, of any number
 * of objects. A blob is **pooled** when no fragment row names it (§7.2): an ingested blob that arrived before its
 * descriptor, or that an object released. The pool is bounded by retention (at most [MediaLimits.POOL_MAX_DAYS] days, or
 * the blob's relay expiry, whichever is first) and by [MediaLimits.POOL_CAP_BYTES], enforced by local eviction and
 * **never by fetching less** (§7.5, T47).
 *
 * The rows say which file holds a blob; the file itself is [CiphertextFiles]'s. File writes happen **before** the
 * transaction that inserts the row, and file deletions **after** the commit that deletes it (§13.5), by [MediaReconcile]:
 * a crash between the two leaves an orphan file or an orphan row, both of which the reconcile repairs.
 *
 * **The reads of this class see every row, the expired ones included**, because each is a count, a lookup or an ordering
 * that must agree with what is on the disk and with the schema's own triggers (`MediaBoundQueries`, the lint of mutant
 * ME-16 judges them by that) — except [files], which serves a live object and so carries the expiry filter; the sweep
 * reads ([expiredPooled]) name exactly the expired pooled rows.
 */
class MediaBlobs(private val fragments: MediaFragments) {

    // ---------------------------------------------------------------- reads (bounds: every row)

    /** The blob row for a hash, if there is one: ingest consumes a blob it already has without writing a file (§7.2). */
    fun byHash(sql: SqlExecutor, blobHash: ByteArray): MediaBlob? {
        var out: MediaBlob? = null
        sql.query(BY_HASH, listOf(Fields.hash("media_blob.blob_hash", blobHash))) { out = readBlob(it) }
        return out
    }

    fun exists(sql: SqlExecutor, blobHash: ByteArray): Boolean = sql.queryCount(EXISTS, listOf(Fields.hash("media_blob.blob_hash", blobHash))) > 0

    /** Every (hash, file name) pair: the names the reconcile keeps. */
    fun fileNames(sql: SqlExecutor): List<BlobFile> {
        val out = ArrayList<BlobFile>()
        sql.query(FILE_NAMES, emptyList()) { out += BlobFile(it.blob(0), it.blob(1)) }
        return out
    }

    /** Whether any fragment row names the blob. */
    fun isNamed(sql: SqlExecutor, blobHash: ByteArray): Boolean =
        sql.queryCount(IS_NAMED, listOf(Fields.hash("media_fragment.blob_hash", blobHash))) > 0

    /** The pooled blobs: ingested, and named by no fragment row. */
    fun pooledCount(sql: SqlExecutor): Int = sql.queryCount(POOLED_COUNT, emptyList())

    /** The bytes the pool holds on disk: one fragment per pooled blob. */
    fun pooledBytes(sql: SqlExecutor): Long = pooledCount(sql).toLong() * MediaLimits.FRAGMENT_BYTES

    /** The pooled blobs in eviction order, the earliest retention first and ties by hash (§7.5). */
    fun evictionOrder(sql: SqlExecutor, limit: Int): List<MediaBlob> {
        val out = ArrayList<MediaBlob>()
        sql.query(EVICTION_ORDER, listOf(limit.toLong())) { out += readBlob(it) }
        return out
    }

    // ---------------------------------------------------------------- reads (expiry-filtered)

    /** The ordinal and file name of every bound fragment of a live object: where to read the object's ciphertext (S7). An incoming object past its deadline has none to a reader. */
    fun files(sql: SqlExecutor, objectId: ByteArray, nowE: Long): List<OrdinalFile> {
        val out = ArrayList<OrdinalFile>()
        sql.query(FILES_OF, listOf(Fields.objectId(objectId), nowE, nowE)) { out += OrdinalFile(it.long(0).toInt(), it.blob(1)) }
        return out
    }

    // ---------------------------------------------------------------- reads (sweeps: they name exactly the expired rows)

    /** The pooled blobs whose last day has passed (`MEDIA-GC`, §7.5): the same ones `evictionOrder` starts with, and no others. */
    fun expiredPooled(sql: SqlExecutor, nowE: Long, limit: Int): List<MediaBlob> {
        val out = ArrayList<MediaBlob>()
        sql.query(EXPIRED_POOLED, listOf(MediaLimits.day(nowE), limit.toLong())) { out += readBlob(it) }
        return out
    }

    // ---------------------------------------------------------------- writes

    /**
     * Inserts a blob row. The file is already on disk (written, forced and renamed, with the directory synced). A hash that
     * has a row is [MediaStoreError.ROW_EXISTS]: ingest checks [byHash] first and consumes a duplicate without writing a file.
     */
    fun insert(tx: SyncTransaction, blob: MediaBlob) {
        Fields.hash("media_blob.blob_hash", blob.blobHash)
        Fields.bytes("media_blob.file_name", blob.fileName, 16)
        when (blob.origin) {
            BlobOrigin.SEALED -> if (blob.retainUntilDay != null) throw MediaStoreException(MediaStoreError.BAD_VALUE, "media_blob.retain_until_day")
            BlobOrigin.INGESTED -> Fields.day("media_blob.retain_until_day", blob.retainUntilDay ?: throw MediaStoreException(MediaStoreError.BAD_VALUE, "media_blob.retain_until_day"))
        }
        if (exists(tx.sql, blob.blobHash)) throw MediaStoreException(MediaStoreError.ROW_EXISTS, "media_blob")
        tx.sql.exec(
            "INSERT INTO media_blob(blob_hash, file_name, origin, retain_until_day) VALUES (?, ?, ?, ?)",
            listOf(blob.blobHash, blob.fileName, blob.origin.code, blob.retainUntilDay),
        )
    }

    /**
     * `MEDIA-INGEST` (§7.2), the database half: the blob row (`origin = 'ingested'`) is inserted and **every** `expected`
     * fragment row naming it, of any object, becomes `bound`. Returns the objects that had such a row, for the
     * completeness check (when the last `expected` row of an object is bound the object becomes `complete`).
     */
    fun ingest(tx: SyncTransaction, blobHash: ByteArray, fileName: ByteArray, retainUntilDay: Long): List<ByteArray> {
        insert(tx, MediaBlob(blobHash, fileName, BlobOrigin.INGESTED, retainUntilDay))
        val waiting = fragments.objectsExpecting(tx.sql, blobHash)
        fragments.bindExpected(tx, blobHash)
        return waiting
    }

    /**
     * Deletes the blob rows of [blobHashes] that no fragment row names (a row that something names is kept: "a file goes
     * only when nothing references it", and the schema's `media_blob_referenced` would refuse). Returns the rows deleted.
     */
    fun deleteUnnamed(tx: SyncTransaction, blobHashes: List<ByteArray>): Int =
        fragments.deleteUnnamed(tx, blobHashes.map { Fields.hash("media_blob.blob_hash", it) }, ReleasePolicy.ERASE)

    /**
     * `MEDIA-GC` (§7.5): the pooled blobs past their last day are deleted, **rows now and files by the reconcile**. Returns
     * the rows deleted (at most [limit]).
     */
    fun collectExpired(tx: SyncTransaction, nowE: Long, limit: Int): Int {
        val expired = expiredPooled(tx.sql, nowE, limit)
        return deleteUnnamed(tx, expired.map { it.blobHash })
    }

    /**
     * The **sealed** blobs that no fragment names (§11.1: "the FK from `media_object.message_id` also cascades from any other
     * deletion of a message, such as a deleted contact; `MediaObjects` deletes the unnamed blobs in that path too"). A sealed
     * blob is never pooled: `MEDIA-COMMIT` inserts it in the transaction that inserts the fragment rows naming it, so at every
     * commit boundary one that nothing names is garbage — what a deletion that did not go through
     * [MediaObjects.deleteObjectsOfMessages] (a contact, a conversation: the foreign keys took the object and its fragments and
     * knew nothing of the blobs) left behind, with a file that no row would ever release. `MEDIA-GC` calls this on every pass
     * and after such a deletion; the rows go now and the files with the reconcile. An **ingested** blob that lost its references
     * the same way is not touched: it is in the pool with its own retention, and [collectExpired] takes it at its day.
     * Returns the rows deleted.
     */
    fun collectUnnamedSealed(tx: SyncTransaction): Int =
        tx.sql.execUpdate(
            "DELETE FROM media_blob WHERE origin = 'sealed' " +
                "AND NOT EXISTS (SELECT 1 FROM media_fragment f WHERE f.blob_hash = media_blob.blob_hash)",
            emptyList(),
        )

    /**
     * The pool cap (§7.5): while the pooled files exceed [capBytes], the pooled blobs with the earliest retention (ties by
     * hash) are deleted, rows in this transaction and files by the reconcile. **Never a stop**: ingest keeps claiming and
     * Phase 7 keeps fetching, so the `get`s on `M_0` stay a function of what others stored (T47). Returns the rows deleted.
     */
    fun evictOverCap(tx: SyncTransaction, capBytes: Long = MediaLimits.POOL_CAP_BYTES): Int {
        var evicted = 0
        while (true) {
            val excess = pooledBytes(tx.sql) - capBytes
            if (excess <= 0L) return evicted
            val needed = ((excess + MediaLimits.FRAGMENT_BYTES - 1) / MediaLimits.FRAGMENT_BYTES).toInt()
            val batch = evictionOrder(tx.sql, minOf(needed, EVICTION_BATCH))
            if (batch.isEmpty()) return evicted
            val deleted = deleteUnnamed(tx, batch.map { it.blobHash })
            if (deleted == 0) return evicted
            evicted += deleted
        }
    }

    /**
     * Repairs a row whose **file is gone** (the reconcile found none), when nothing names the row: a pooled blob with no
     * file is garbage. A row that a fragment names is not repaired here: its object lost a blob, which the engine decides
     * (S6, S8: the object turns `corrupt` or `incomplete`, which releases its references and erases its key). Returns the
     * rows deleted.
     */
    fun dropLostUnnamed(tx: SyncTransaction, blobHashes: List<ByteArray>): Int = deleteUnnamed(tx, blobHashes)

    private fun readBlob(row: SqlExecutor.Row): MediaBlob = MediaBlob(
        blobHash = row.blob(0),
        fileName = row.blob(1),
        origin = BlobOrigin.of(row.string(2)),
        retainUntilDay = if (row.isNull(3)) null else row.long(3),
    )

    companion object {
        private const val EVICTION_BATCH = 256

        /**
         * The last day an ingested blob is kept while no object names it (§7.2): `min(day(E) + 1, today + 8)` with `E` the
         * relay expiry of the blob (`InboundBlob.relayExpiryHour`), so an unmatched blob lives at most eight days or until
         * its relay expiry, whichever is first.
         */
        fun retentionDay(relayExpirySeconds: Long, nowE: Long): Long =
            maxOf(0L, minOf(MediaLimits.day(relayExpirySeconds) + 1, MediaLimits.day(nowE) + MediaLimits.POOL_MAX_DAYS))

        private const val BY_HASH = "SELECT blob_hash, file_name, origin, retain_until_day FROM media_blob WHERE blob_hash = ?"

        private const val EXISTS = "SELECT count(*) FROM media_blob WHERE blob_hash = ?"

        private const val FILE_NAMES = "SELECT blob_hash, file_name FROM media_blob ORDER BY blob_hash"

        private const val IS_NAMED = "SELECT count(*) FROM media_fragment WHERE blob_hash = ?"

        private const val POOLED_COUNT =
            "SELECT count(*) FROM media_blob b WHERE b.origin = 'ingested' " +
                "AND NOT EXISTS (SELECT 1 FROM media_fragment f WHERE f.blob_hash = b.blob_hash)"

        private const val EVICTION_ORDER =
            "SELECT b.blob_hash, b.file_name, b.origin, b.retain_until_day FROM media_blob b WHERE b.origin = 'ingested' " +
                "AND NOT EXISTS (SELECT 1 FROM media_fragment f WHERE f.blob_hash = b.blob_hash) " +
                "ORDER BY b.retain_until_day, b.blob_hash LIMIT ?"

        private const val EXPIRED_POOLED =
            "SELECT b.blob_hash, b.file_name, b.origin, b.retain_until_day FROM media_blob b WHERE b.origin = 'ingested' " +
                "AND b.retain_until_day < ? AND NOT EXISTS (SELECT 1 FROM media_fragment f WHERE f.blob_hash = b.blob_hash) " +
                "ORDER BY b.retain_until_day, b.blob_hash LIMIT ?"

        private const val FILES_OF =
            "SELECT f.ordinal, b.file_name FROM media_fragment f JOIN media_blob b ON b.blob_hash = f.blob_hash " +
                "JOIN media_object o ON o.object_id = f.object_id LEFT JOIN dm_message m ON m.message_id = o.message_id " +
                "WHERE f.object_id = ? AND f.state = 'bound' " +
                "AND (m.message_id IS NULL OR m.delete_at_minute IS NULL OR m.delete_at_minute > ?) " +
                "AND NOT (o.state IN ('awaiting', 'fetching') AND o.incomplete_after_hour <= ?) ORDER BY f.ordinal"
    }
}

/** A blob and the name of its file (the hash is the identity, the name is 16 random bytes). */
class BlobFile(val blobHash: ByteArray, val fileName: ByteArray) {
    override fun toString(): String = "BlobFile"
}

/** The file that holds the blob at an ordinal of an object. */
class OrdinalFile(val ordinal: Int, val fileName: ByteArray) {
    override fun toString(): String = "OrdinalFile(ordinal=$ordinal)"
}
