package org.ghost.media.store

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The reconcile (Phase 11 design §10.4, §13.5) in both directions: files no row names are deleted unless a sealer is
 * writing them, the times of the files it keeps are re-applied, rows no file backs are found, and a second run on a
 * consistent store changes nothing. The crash enumeration of the reconcile itself is [MediaStoreScenarioTest]'s.
 */
class MediaReconcileTest {

    private fun hexOf(name: ByteArray) = hex(name)

    @Test
    fun filesNoRowNamesAreDeletedAndTheDirectoryIsSyncedAfterwards() = MediaWorld().use { w ->
        val kept = (1..3).map { w.putBlob(it) }
        // two orphan blobs (a crash between a file write and its transaction) and a leftover temp file
        val orphans = (10..11).map { (w.files.writeFresh(blobOf(it), enforceFloor = false) as WriteResult.Written).fileName }
        File(w.files.directory, CiphertextFiles.TEMP_PREFIX + "ab".repeat(16)).writeBytes(ByteArray(100))
        w.disk.reset()
        val report = w.reconcile.run(w.database) { emptySet() }
        assertEquals(3, report.orphansDeleted)
        val trace = w.disk.trace.toList() // before the listings below, which are calls of the port too
        assertEquals(0, report.rowsDropped)
        assertTrue(report.lostNamed.isEmpty())
        assertEquals(kept.map { hexOf(it) }.sorted(), w.listed())
        for (orphan in orphans) assertFalse(w.files.exists(orphan))
        // the removals were made durable: the last call is the directory sync, after the deletes
        assertEquals("list", trace.first())
        assertEquals("syncDirectory", trace.last())
        assertEquals(3, trace.count { it == "delete" })
        // nothing left to do
        w.disk.reset()
        val again = w.reconcile.run(w.database) { emptySet() }
        assertTrue(again.clean)
        assertEquals("a clean run deletes nothing and syncs nothing", listOf("list"), w.disk.trace)
    }

    @Test
    fun aFileASealerIsStillWritingIsKeptAndIsAnOrphanOnceItIsNotInPreparing() = MediaWorld().use { w ->
        w.putBlob(1)
        val writing = (w.files.writeFresh(blobOf(2), enforceFloor = false) as WriteResult.Written).fileName
        val report = w.reconcile.run(w.database) { setOf(hexOf(writing)) }
        assertEquals(0, report.orphansDeleted)
        assertTrue(w.files.exists(writing))
        // MEDIA-COMMIT inserts its row and only then drops the name from `preparing`: the next run keeps it as a named file
        w.tx { w.stores.blobs.insert(it, MediaBlob(hashOfBlob(2), writing, BlobOrigin.SEALED, null)) }
        assertTrue(w.reconcile.run(w.database) { emptySet() }.clean)
        assertTrue(w.files.exists(writing))
        // an abandoned preparation (the user left): the name is dropped from `preparing` without a row, and the file goes
        val abandoned = (w.files.writeFresh(blobOf(3), enforceFloor = false) as WriteResult.Written).fileName
        assertEquals(0, w.reconcile.run(w.database) { setOf(hexOf(abandoned)) }.orphansDeleted)
        assertEquals(1, w.reconcile.run(w.database) { emptySet() }.orphansDeleted)
        assertFalse(w.files.exists(abandoned))
    }

    /**
     * The order of the reads: list, then the `preparing` snapshot, then the rows. A file written after the listing is not
     * in it, so a run cannot delete it; a file written before the listing whose row commits (and whose name leaves `preparing`)
     * while the snapshot is taken is in the rows, so a run cannot delete that either.
     */
    @Test
    fun noOrderOfAConcurrentSealerMakesTheReconcileDeleteAFileItsRowNamesOrWillName() = MediaWorld().use { w ->
        // (a) a file created after the listing: the snapshot callback runs after the listing, so it writes one there
        var lateName: ByteArray? = null
        val late = w.reconcile.run(w.database) {
            lateName = (w.files.writeFresh(blobOf(5), enforceFloor = false) as WriteResult.Written).fileName
            emptySet()
        }
        assertEquals(0, late.orphansDeleted)
        assertTrue(w.files.exists(lateName!!))
        w.files.delete(lateName)
        // (b) a file created before the listing, in preparing at the snapshot or already committed by the time the rows are read
        val early = (w.files.writeFresh(blobOf(6), enforceFloor = false) as WriteResult.Written).fileName
        val committedDuringSnapshot = w.reconcile.run(w.database) {
            // MEDIA-COMMIT lands while the snapshot is taken: the row is committed, then the name leaves `preparing`
            w.tx { w.stores.blobs.insert(it, MediaBlob(hashOfBlob(6), early, BlobOrigin.SEALED, null)) }
            emptySet()
        }
        assertEquals("the row was read after the snapshot, so it names the file", 0, committedDuringSnapshot.orphansDeleted)
        assertTrue(w.files.exists(early))
        assertEquals(1L, w.count("media_blob"))
    }

    /**
     * A temp file `.t<x>` belongs to the final name `<x>`: one reservation covers both. A name that merely looks like a temp
     * name (not hex, the wrong length) is no one's and goes, and so does a temp file whose name nobody reserves. (The race
     * itself is [MediaReconcileRaceTest]'s.)
     */
    @Test
    fun aTempFileIsKeptWhileItsFinalNameIsReservedAndNotOtherwise() = MediaWorld().use { w ->
        val name = w.preparing.reserve(w.files)
        File(w.files.directory, CiphertextFiles.TEMP_PREFIX + hex(name)).writeBytes(ByteArray(10))
        val junk = listOf(".tzz", CiphertextFiles.TEMP_PREFIX + hex(name).substring(1), "readme")
        for (entry in junk) File(w.files.directory, entry).writeBytes(ByteArray(1))
        val first = w.reconcile.run(w.database, w.preparing::snapshot)
        assertEquals("only the junk goes", junk.size, first.orphansDeleted)
        assertTrue(File(w.files.directory, CiphertextFiles.TEMP_PREFIX + hex(name)).exists())
        w.preparing.release(name)
        assertEquals("released, the temp file is an orphan", 1, w.reconcile.run(w.database, w.preparing::snapshot).orphansDeleted)
        assertEquals(emptyList<String>(), w.listed())
    }

    /**
     * A `MEDIA-COMMIT` that lands between the listing and the row read: its files were written after the listing (so they are not
     * in it) and its rows are committed before the rows are read (so they are). A row whose file is not in the listing is not
     * lost until the file is looked for, and it is there: without that look every such row is dropped (a bare one) or reported
     * lost (one an object names), and the engine would corrupt a healthy object and erase its key.
     */
    @Test
    fun aRowCommittedAfterTheListingIsNotLostBecauseItsFileIsNotInTheListing() = MediaWorld().use { w ->
        // a bare row: one sealed blob
        var late: ByteArray? = null
        val bare = w.reconcile.run(w.database) {
            late = w.files.writeFresh(blobOf(5), enforceFloor = false).let { (it as WriteResult.Written).fileName }
            w.tx { tx -> w.stores.blobs.insert(tx, MediaBlob(hashOfBlob(5), late, BlobOrigin.SEALED, null)) }
            emptySet()
        }
        assertEquals("the row is not dropped", 0, bare.rowsDropped)
        assertTrue(bare.lostNamed.isEmpty())
        assertTrue(bare.clean)
        assertTrue(w.files.exists(late!!))
        assertEquals(1L, w.count("media_blob"))
        // a whole object: 17 files and rows, named by fragments
        val committed = w.reconcile.run(w.database) {
            for (hash in w.blobsOf(1).all) File(w.files.directory, hex(w.nameOf(hash))).writeBytes(blobOf(1))
            w.commitOutgoing(1)
            emptySet()
        }
        assertEquals(0, committed.rowsDropped)
        assertTrue("an object that a fragment names is not reported lost: ${committed.lostNamed}", committed.lostNamed.isEmpty())
        assertEquals(18L, w.count("media_blob"))
        assertEquals(17L, w.count("media_fragment"))
    }

    @Test
    fun theTimesOfAKeptFileAreReappliedAndOnlyThoseOfAKeptFile() = MediaWorld().use { w ->
        val fine = w.putBlob(1)
        val stamped = w.putBlob(2)
        assertTrue(File(w.files.directory, hexOf(stamped)).setLastModified(1_700_000_000_000L))
        val report = w.reconcile.run(w.database) { emptySet() }
        assertEquals(1, report.timesReapplied)
        assertEquals(0L, java.nio.file.Files.getLastModifiedTime(File(w.files.directory, hexOf(stamped)).toPath()).toMillis())
        assertEquals(0L, java.nio.file.Files.getLastModifiedTime(File(w.files.directory, hexOf(fine)).toPath()).toMillis())
        assertTrue(w.reconcile.run(w.database) { emptySet() }.clean)
    }

    @Test
    fun aRowWithNoFileThatNothingNamesIsGarbageAndOneThatAnObjectNamesIsReported() = MediaWorld().use { w ->
        // a pooled blob whose file is gone
        val pooledName = w.putBlob(1, BlobOrigin.INGESTED, 20_100L)
        // an object's blob whose file is gone, and another file that is fine
        val objectId = w.receive(7)
        val blobs = w.blobsOf(7)
        val namedName = w.putBlobIngestedFor(7, blobs.manifest)
        w.files.delete(pooledName)
        w.files.delete(namedName)
        val report = w.reconcile.run(w.database) { emptySet() }
        assertEquals("the pooled row is deleted", 1, report.rowsDropped)
        assertEquals(1, report.lostNamed.size)
        assertEquals(listOf(objectId.toList()), report.lostNamed.single().objectIds.map { it.toList() })
        assertEquals(blobs.manifest.toList(), report.lostNamed.single().blobHash.toList())
        assertFalse(w.stores.blobs.exists(w.db, hashOfBlob(1)))
        assertTrue("the named row stays: the engine decides what becomes of its object", w.stores.blobs.exists(w.db, blobs.manifest))
        // the report repeats until the engine acts (a rerun is idempotent in what it changes)
        val again = w.reconcile.run(w.database) { emptySet() }
        assertEquals(0, again.rowsDropped)
        assertEquals(1, again.lostNamed.size)
        assertTrue(again.clean)
    }

    @Test
    fun aRunOnAConsistentStoreOfSeveralObjectsChangesNothing() = MediaWorld().use { w ->
        for (n in 1..4) w.putBlob(n)
        w.putBlob(5, BlobOrigin.INGESTED, 20_100L)
        val before = w.listed()
        w.disk.reset()
        val report = w.reconcile.run(w.database) { emptySet() }
        val trace = w.disk.trace.toList()
        assertTrue(report.clean)
        assertEquals(0, report.orphansDeleted + report.timesReapplied + report.rowsDropped)
        assertEquals(before, w.listed())
        assertEquals(listOf("list"), trace)
    }

    /** The test world's helper: a file for a blob row that an incoming object (not a pool entry) names, with the row ingested and the fragments bound. */
    private fun MediaWorld.putBlobIngestedFor(n: Int, hash: ByteArray): ByteArray {
        val written = files.writeFresh(blobOf(n + 100), enforceFloor = false) as WriteResult.Written
        tx { stores.blobs.ingest(it, hash, written.fileName, 20_100L) }
        return written.fileName
    }
}
