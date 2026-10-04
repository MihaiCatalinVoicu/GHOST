package org.ghost.media.store

import org.ghost.sync.api.SyncDatabase

/**
 * The reconcile (Phase 11 design §10.4, §13.5): the startup pass, and the pass after every transaction that deletes media
 * rows, that makes the files in `noBackupFilesDir/m/` and the `media_blob` rows agree, **in both directions**.
 *
 *  1. **Files no row names** are deleted: every entry of the directory that no `media_blob` row names and that is not in
 *     `preparing` (the files a sealer wrote and `MEDIA-COMMIT` has not yet referenced), whether an orphan blob (a crash
 *     between a file write and its transaction, or between a deletion's commit and its file removal) or a leftover temp
 *     file. A crash between a deletion's commit and the reconcile leaves ciphertext whose key is already erased; the next
 *     reconcile removes it.
 *  2. **The times are re-applied** to every file that is kept (S0-12): a crash between a write and `setTimes` left a file
 *     with real times, and a restore or an older build may have too.
 *  3. **Rows no file backs** are found. A row that **no fragment names** (a pooled blob whose file is gone) is garbage and is
 *     deleted. A row that a fragment names cannot be repaired here: its object lost a blob, which is reported
 *     ([ReconcileReport.lostNamed]) with the objects affected, because what the engine does about it (turn the object
 *     `corrupt` or `incomplete`, which erases its key and needs F9 §10.7's checkpoint) is the media actor's (S6, S8).
 *
 * **Why the order of the reads is what it is.** A concurrent sealer writes a file, `MEDIA-COMMIT` inserts the row and only
 * then drops the name from `preparing`. The reconcile lists the directory **first**, then takes the `preparing` snapshot,
 * then reads the rows: a file created before the listing is in `preparing` until after its row commits, so it is in the
 * snapshot or in the rows (or both) — never in neither — and a file created after the listing is not in the listing. Any
 * other order can delete a file whose row commits a moment later.
 *
 * **Crash-safe and idempotent.** Every step is a single file operation or a single transaction that can be repeated:
 * a crash after any deletion leaves a directory a second run finishes, and a run on a consistent store changes nothing and
 * reports zeros.
 */
class MediaReconcile(
    private val files: CiphertextFiles,
    private val blobs: MediaBlobs,
    private val fragments: MediaFragments,
) {

    /**
     * Runs one reconcile. [preparing] returns the names (as listed: 32 hex characters) of the files a sealer has written for
     * an object that is not committed yet; it is called once, after the directory was listed and before the rows are read.
     * The database is touched in short transactions of its own: never call this from inside one.
     */
    fun run(database: SyncDatabase, preparing: () -> Set<String>): ReconcileReport {
        val listing = files.list()
        val inProgress = preparing()
        val rows = database.transaction { tx -> blobs.fileNames(tx.sql) }
        val named = HashMap<String, ByteArray>()
        for (row in rows) named[hex(row.fileName)] = row.blobHash

        // 1. files no row names (and no sealer is writing)
        var deleted = 0
        for (entry in listing) {
            if (entry in named || entry in inProgress) continue
            if (files.deleteNamed(entry)) deleted++
        }
        if (deleted > 0) files.syncDirectory()

        // 2. the times of the files that are kept
        var retimed = 0
        for (entry in listing) if (entry in named && files.reapplyTimes(entry)) retimed++

        // 3. rows no file backs (re-checked right before, for a file written after the listing)
        val gone = named.filter { (name, _) -> name !in listing && !files.exists(unhex(name)) }
        var dropped = 0
        val lostNamed = ArrayList<LostBlob>()
        if (gone.isNotEmpty()) {
            database.transaction { tx ->
                val unnamed = ArrayList<ByteArray>()
                for ((_, hash) in gone) {
                    if (blobs.isNamed(tx.sql, hash)) lostNamed += LostBlob(hash, fragments.objectsNaming(tx.sql, hash)) else unnamed += hash
                }
                dropped = blobs.dropLostUnnamed(tx, unnamed)
            }
        }
        return ReconcileReport(deleted, retimed, dropped, lostNamed)
    }

    private fun unhex(listed: String): ByteArray = ByteArray(listed.length / 2) { listed.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    override fun toString(): String = "MediaReconcile"
}

/** What one reconcile did. Counts only: no name, hash or path (T3). */
class ReconcileReport(
    /** Files that no row named and no sealer was writing, deleted. */
    val orphansDeleted: Int,
    /** Kept files whose `mtime` or `atime` was not zero and was set to it. */
    val timesReapplied: Int,
    /** Rows with no file and no fragment naming them, deleted. */
    val rowsDropped: Int,
    /** Rows with no file that a fragment names: the engine decides what becomes of their objects. */
    val lostNamed: List<LostBlob>,
) {
    /** True when the store was consistent and nothing was changed (the second run of an idempotent pass). */
    val clean: Boolean get() = orphansDeleted == 0 && timesReapplied == 0 && rowsDropped == 0

    override fun toString(): String =
        "ReconcileReport(orphans=$orphansDeleted, retimed=$timesReapplied, dropped=$rowsDropped, lostNamed=${lostNamed.size})"
}

/** A blob whose file is gone while a fragment still names it, and the objects that lose it. */
class LostBlob(val blobHash: ByteArray, val objectIds: List<ByteArray>) {
    override fun toString(): String = "LostBlob(objects=${objectIds.size})"
}
