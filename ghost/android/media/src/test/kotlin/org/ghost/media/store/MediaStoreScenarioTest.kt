package org.ghost.media.store

import org.ghost.storage.queryLong
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.BasicFileAttributes

/**
 * SCN-MF's storage half and the storage halves of SCN-MA, SCN-MC and SCN-ME (Phase 11 design §15.3: "Every media transaction
 * runs under the harness that crashes at every SQL statement **and** at every `CiphertextFiles` call ... reboots, checks
 * structural invariants at once, runs to quiescence and checks everything. File faults include 'an unsynced write is lost'
 * at the reboot"): the three storage protocols of §13.5 — the commit of a sealed object, the ingest of a received blob and
 * the erasure of an expired object — each crashed at **every file operation and every statement** of one scripted run, then
 * rebooted, reconciled and checked. (The migration's own crash enumeration is `Migration8Test`'s, in `:storage`.)
 *
 * The invariants checked after every reboot and reconcile:
 *  1. every `media_blob` row names a **whole** file (64 KiB, `mtime` = `atime` = 0) and every file of the store is named by a
 *     row ([checkFiles]);
 *  2. a second reconcile changes nothing ([checkFiles]);
 *  3. every `bound` fragment names an existing blob row; a committed outgoing object has all `F + 1` of its fragments, bound,
 *     its upload row and its blobs, and a crash before the commit leaves **no** row of the object anywhere — no partial
 *     object ([checkCommitted]).
 * What they cannot show is the engine's reaction to a lost blob (S6, S8) and the keys' checkpoint (S8).
 */
class MediaStoreScenarioTest {

    private fun attributes(file: File): BasicFileAttributes = Files.readAttributes(file.toPath(), BasicFileAttributes::class.java)

    /** Invariants 1 and 2 after a reboot and a reconcile. */
    private fun checkFiles(w: MediaWorld, label: String) {
        val report = w.reconcile.run(w.database) { emptySet() }
        assertTrue("$label: nothing a row named is lost: ${report.lostNamed}", report.lostNamed.isEmpty())
        assertEquals("$label: no row without a file", 0, report.rowsDropped)
        val rows = w.stores.blobs.fileNames(w.db).map { hex(it.fileName) }.sorted()
        assertEquals("$label: the files are exactly the rows' files", rows, w.listed())
        for (name in w.listed()) {
            val file = File(w.files.directory, name)
            assertEquals("$label: $name is whole", MediaLimits.FRAGMENT_BYTES.toLong(), file.length())
            assertEquals("$label: mtime", 0L, attributes(file).lastModifiedTime().toMillis())
            assertEquals("$label: atime", 0L, attributes(file).lastAccessTime().toMillis())
        }
        assertTrue("$label: a second reconcile changes nothing", w.reconcile.run(w.database) { emptySet() }.clean)
    }

    /** Invariant 3: [objects] outgoing objects of class 0 are committed whole, or none is there at all. */
    private fun checkCommitted(w: MediaWorld, label: String, objects: Int) {
        assertEquals("$label: objects", objects.toLong(), w.count("media_object"))
        assertEquals("$label: uploads", objects.toLong(), w.count("media_upload"))
        assertEquals("$label: fragments", 17L * objects, w.count("media_fragment"))
        assertEquals("$label: blobs", 17L * objects, w.count("media_blob"))
        assertEquals(
            "$label: every fragment names its blob",
            0L,
            w.db.queryLong("SELECT count(*) FROM media_fragment f WHERE NOT EXISTS (SELECT 1 FROM media_blob b WHERE b.blob_hash = f.blob_hash)"),
        )
    }

    private inline fun crashed(block: () -> Unit): Boolean {
        try {
            block()
        } catch (e: InjectedCrash) {
            return true
        }
        return false
    }

    // ------------------------------------------------------------------ SCN-MA: MEDIA-COMMIT

    /** The files of the commit of a class-0 object (§6.3): 17 blobs, each written, forced and renamed, the directory synced. */
    private fun writeObjectFiles(w: MediaWorld, n: Int): List<Pair<ByteArray, ByteArray>> =
        w.blobsOf(n).all.mapIndexed { i, hash ->
            hash to (w.files.write(blobOf(n * 1000 + i), enforceFloor = false) as WriteResult.Written).fileName
        }

    /** The transaction of the commit: every row of the object at once. */
    private fun commitRows(w: MediaWorld, n: Int, names: List<Pair<ByteArray, ByteArray>>) {
        val blobs = w.blobsOf(n)
        w.tx { tx ->
            for ((hash, name) in names) w.stores.blobs.insert(tx, MediaBlob(hash, name, BlobOrigin.SEALED, null))
            w.stores.objects.insertOutgoing(
                tx,
                NewOutgoing(
                    MediaDescriptor(id16(0xA0 + n), MediaKind.VIDEO, false, 0, blobs.manifest), id16(0xD1), bytes(60, 0x30 + n),
                    id16(0x90 + n), hash32(0x4D), 604_800L, 3_600L * 1_000_000,
                ),
            )
            w.stores.fragments.insertSealed(tx, id16(0xA0 + n), 0, blobs.manifest, blobs.fragments)
        }
    }

    private fun commit(w: MediaWorld, n: Int = 1) {
        val names = writeObjectFiles(w, n)
        w.dmMessage(id16(0x90 + n))
        w.ensureNamespace(hash32(0x4D))
        commitRows(w, n, names)
    }

    @Test
    fun aCrashAtAnyFileOperationOfTheCommitLeavesNoPartialObject() {
        val total = MediaWorld().use { w -> w.disk.reset(); commit(w); w.disk.points }
        assertEquals("17 writes of five calls, two kill points each", 17 * 5 * 2, total)
        for (point in 0 until total) MediaWorld().use { w ->
            w.disk.reset()
            w.disk.arm(point)
            assertTrue("point $point must be reached", crashed { commit(w) })
            w.disk.reboot()
            // every kill point is before the transaction: the object is not committed and its files are orphans
            checkFiles(w, "commit, point $point")
            checkCommitted(w, "commit, point $point", objects = 0)
            assertEquals("point $point", emptyList<String>(), w.listed())
            // a restart resumes by preparing again and committing (every tenth point, to keep the run short)
            if (point % 10 == 0 || point == total - 1) {
                commit(w)
                checkFiles(w, "commit, point $point, then the retry")
                checkCommitted(w, "commit, point $point, then the retry", objects = 1)
            }
        }
    }

    /** The transaction of the commit has 36 statements: the 17 blob rows, the object, its upload, the 17 fragments. */
    @Test
    fun aFailureAtAnyStatementOfTheCommitTransactionLeavesNoRowAndOnlyOrphanFiles() {
        val statements = 17 + 1 + 1 + 17
        for (failAt in 0 until statements) {
            lateinit var injector: FailAtStatement
            MediaWorld(wrap = { FailAtStatement(it).also { f -> injector = f } }).use { w ->
                // the files are written before the transaction, so only the transaction's statements are counted
                val names = writeObjectFiles(w, 1)
                w.dmMessage(id16(0x91))
                w.ensureNamespace(hash32(0x4D))
                injector.failAt = injector.calls + failAt
                var failed = false
                try {
                    commitRows(w, 1, names)
                } catch (e: IllegalStateException) {
                    failed = true
                }
                assertTrue("statement $failAt must be reached", failed)
                checkCommitted(w, "commit statement $failAt", objects = 0)
                assertEquals("statement $failAt", 17, w.listed().size)
                // the process dies there; at the restart the 17 files are orphans
                w.disk.reboot()
                checkFiles(w, "commit statement $failAt")
                assertEquals(emptyList<String>(), w.listed())
            }
        }
        // ... and one past the last statement is the commit itself
        MediaWorld(wrap = { FailAtStatement(it) }).use { w ->
            commit(w)
            checkFiles(w, "commit whole")
            checkCommitted(w, "commit whole", objects = 1)
        }
    }

    // ------------------------------------------------------------------ SCN-MC: MEDIA-INGEST

    /** The manifest blob of object 1 of the world. */
    private fun manifestHash(): ByteArray = hashOfBlob(1000)

    /** The ingest of one blob (§7.2): the file first (the floor enforced), then the transaction that inserts the row and binds. */
    private fun ingestOne(w: MediaWorld, n: Int, hash: ByteArray): Boolean {
        if (w.stores.blobs.exists(w.db, hash)) return false // a duplicate is consumed without a file
        val written = w.files.write(blobOf(n), enforceFloor = true) as? WriteResult.Written ?: return false
        w.tx { w.stores.blobs.ingest(it, hash, written.fileName, 20_200L) }
        return true
    }

    @Test
    fun aCrashAtAnyFileOperationOfAnIngestLosesNothingAndWritesNoFileTwice() {
        val hash = manifestHash()
        val total = MediaWorld().use { w -> w.receive(1); w.disk.reset(); ingestOne(w, 1, hash); w.disk.points }
        assertEquals(10, total)
        for (point in 0 until total) MediaWorld().use { w ->
            val objectId = w.receive(1)
            w.disk.reset()
            w.disk.arm(point)
            assertTrue(crashed { ingestOne(w, 1, hash) })
            w.disk.reboot()
            // the crash was before the row: the blob is still wanted (the inbox row is not consumed), the object still
            // waits, and the file, if the directory sync completed, is an orphan
            val report = w.reconcile.run(w.database) { emptySet() }
            assertEquals("point $point", 0L, w.count("media_blob"))
            assertEquals("point $point: the object still expects the blob", 17, w.stores.fragments.expectedCount(w.db, objectId))
            assertEquals("point $point", emptyList<String>(), w.listed())
            assertEquals("point $point", if (point == total - 1) 1 else 0, report.orphansDeleted)
            // offered again: the ingest succeeds, once
            assertTrue(ingestOne(w, 1, hash))
            assertFalse("and a replay is consumed without a second file", ingestOne(w, 1, hash))
            assertEquals(1, w.listed().size)
            assertEquals(16, w.stores.fragments.expectedCount(w.db, objectId))
            checkFiles(w, "ingest, point $point, then the retry")
        }
    }

    @Test
    fun aFailureAtAnyStatementOfAnIngestTransactionLeavesTheObjectWaitingAndTheFileAnOrphan() {
        for (failAt in 0 until 2) { // the blob row, then the binding of the expected rows
            lateinit var injector: FailAtStatement
            MediaWorld(wrap = { FailAtStatement(it).also { f -> injector = f } }).use { w ->
                val objectId = w.receive(1)
                injector.failAt = injector.calls + failAt
                var failed = false
                try {
                    ingestOne(w, 1, manifestHash())
                } catch (e: IllegalStateException) {
                    failed = true
                }
                assertTrue("statement $failAt must be reached", failed)
                assertEquals(0L, w.count("media_blob"))
                assertEquals(17, w.stores.fragments.expectedCount(w.db, objectId))
                assertEquals("the file was written before the transaction", 1, w.listed().size)
                w.disk.reboot()
                checkFiles(w, "ingest statement $failAt")
                assertEquals(emptyList<String>(), w.listed())
            }
        }
    }

    @Test
    fun belowTheFreeSpaceFloorAnIngestConsumesTheBlobWithoutAFileAndTheObjectGoesOnWaiting() = MediaWorld(freeFloorBytes = Long.MAX_VALUE).use { w ->
        val objectId = w.receive(1)
        assertFalse("the blob is consumed with no file", ingestOne(w, 1, manifestHash()))
        assertEquals(emptyList<String>(), w.listed())
        assertEquals(0L, w.count("media_blob"))
        assertEquals(17, w.stores.fragments.expectedCount(w.db, objectId))
    }

    // ------------------------------------------------------------------ SCN-ME: the erasure and its reconcile

    @Test
    fun aCrashAtAnyFileOperationOfTheReconcileAfterAnErasureLeavesNothingTheNextOneDoesNotRemove() {
        val total = MediaWorld().use { w ->
            commit(w)
            w.tx { w.stores.objects.deleteObjectsOfMessages(it, listOf(id16(0x91))) }
            w.disk.reset()
            w.reconcile.run(w.database) { emptySet() }
            w.disk.points
        }
        // list, 17 deletes, the directory sync: 19 calls, two kill points each
        assertEquals(19 * 2, total)
        for (point in 0 until total) MediaWorld().use { w ->
            commit(w)
            // the erasure commits: no row, no key; the 17 files are still there until the reconcile
            w.tx { w.stores.objects.deleteObjectsOfMessages(it, listOf(id16(0x91))) }
            checkCommitted(w, "erasure, point $point, before the reconcile", objects = 0)
            assertEquals(17, w.listed().size)
            w.disk.reset()
            w.disk.arm(point)
            assertTrue("point $point", crashed { w.reconcile.run(w.database) { emptySet() } })
            w.disk.reboot() // a delete that was not synced comes back
            checkFiles(w, "erasure, point $point")
            assertEquals("point $point: the next reconcile removed what the crash left", emptyList<String>(), w.listed())
        }
    }

    @Test
    fun theCrashModelSeesAnObjectCommittedOnFilesThatWereNeverMadeDurable() {
        // without the force every file of the object is empty after a power cut although every row says otherwise
        MediaWorld().use { w ->
            w.disk.skipForce = true
            commit(w)
            w.disk.reboot()
            val report = w.reconcile.run(w.database) { emptySet() }
            assertEquals("the rows are all there", 17L, w.count("media_blob"))
            val empty = w.listed().count { File(w.files.directory, it).length() != MediaLimits.FRAGMENT_BYTES.toLong() }
            assertEquals("and every file is empty", 17, empty)
            assertEquals(0, report.rowsDropped)
        }
        // without the directory sync every name is gone although every row says otherwise: the reconcile finds 17 lost blobs
        MediaWorld().use { w ->
            w.disk.skipDirectorySync = true
            commit(w)
            w.disk.reboot()
            val report = w.reconcile.run(w.database) { emptySet() }
            assertEquals(17, report.lostNamed.size)
            assertEquals(emptyList<String>(), w.listed())
        }
    }

    // ------------------------------------------------------------------ the pool and the objects together

    @Test
    fun aWholeLifeOfAnObjectAndOfThePoolEndsWithAnEmptyStoreAndAnEmptyDirectory() = MediaWorld().use { w ->
        commit(w)
        // a received object whose blobs arrive, one pooled stranger, then both are erased or collected
        val received = w.receive(2)
        val blobs = w.blobsOf(2)
        for ((i, hash) in blobs.all.withIndex()) assertTrue(ingestOne(w, 2000 + i, hash))
        assertTrue(ingestOne(w, 3000, hashOfBlob(3000)))
        assertEquals(35, w.listed().size)
        w.tx { w.stores.objects.markComplete(it, received) }
        w.tx { w.stores.objects.markVerified(it, received) }
        // the sender's message and the recipient's message expire; the stranger's retention passes
        w.tx { w.stores.objects.deleteObjectsOfMessages(it, listOf(id16(0x91), id16(0x92))) }
        assertEquals("the stranger is pooled, not named", 1L, w.count("media_blob"))
        w.tx { w.stores.blobs.collectExpired(it, 1_900_000_000L, 100) }
        assertEquals(0L, w.count("media_blob"))
        val report = w.reconcile.run(w.database) { emptySet() }
        assertEquals(35, report.orphansDeleted)
        assertEquals(emptyList<String>(), w.listed())
        checkFiles(w, "end")
        checkCommitted(w, "end", objects = 0)
    }
}
