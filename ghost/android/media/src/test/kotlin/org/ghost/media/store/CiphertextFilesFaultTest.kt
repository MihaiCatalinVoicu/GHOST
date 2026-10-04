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
 * The ciphertext store under a crash at **every file operation** (Phase 11 design §15.3: "before and after `write`, `force`,
 * `setTimes` (S0-12), directory sync, `delete`, `list`", with "an unsynced write is lost" at the reboot) — the kill points
 * of one write, the order a write must have to survive them, and the proof that the crash model is sharp enough to see the
 * two orders that would lose data (a rename without a force, a rename without a directory sync).
 */
class CiphertextFilesFaultTest {

    private fun attributes(file: File): BasicFileAttributes = Files.readAttributes(file.toPath(), BasicFileAttributes::class.java)

    /** The calls of one write, in the order the design gives them (S0-12: the times before the force and the rename). */
    @Test
    fun aWriteIsFiveCallsInTheOrderThatSurvivesACrash() = MediaWorld().use { w ->
        w.disk.reset()
        w.files.write(blobOf(1), enforceFloor = false)
        assertEquals(listOf("write", "setTimes", "force", "rename", "syncDirectory"), w.disk.trace)
        assertEquals("two kill points per call: before and after", 10, w.disk.points)
    }

    /**
     * Crash at each of the ten kill points of one write, reboot, and look at the directory: **no file with a final name that
     * is not whole**, at any point; a final name appears only once the directory sync completed (the last point), and then it
     * holds the blob and carries zero times; whatever else is left (a temp file the reboot did not revert) is an orphan that
     * the reconcile deletes.
     */
    @Test
    fun everyKillPointOfAWriteLeavesNoPartialFileUnderAFinalName() {
        val total = MediaWorld().use { w -> w.disk.reset(); w.files.write(blobOf(1), false); w.disk.points }
        assertEquals(10, total)
        for (point in 0 until total) MediaWorld().use { w ->
            w.disk.reset()
            w.disk.arm(point)
            val crash = runCatchingCrash { w.files.write(blobOf(1), enforceFloor = false) }
            assertTrue("point $point must be reached", crash != null)
            w.disk.reboot()
            val finals = w.listed().filter { CiphertextFiles.isFinalName(it) }
            if (point == total - 1) {
                // after the directory sync: durable, whole, no times — and no row names it yet, so it is an orphan
                assertEquals("point $point", 1, finals.size)
                val file = File(w.files.directory, finals.single())
                assertEquals(MediaLimits.FRAGMENT_BYTES.toLong(), file.length())
                assertEquals(0L, attributes(file).lastModifiedTime().toMillis())
                assertEquals(0L, attributes(file).lastAccessTime().toMillis())
            } else {
                assertEquals("point $point: nothing under a final name before the directory sync", emptyList<String>(), finals)
            }
            val report = w.reconcile.run(w.database) { emptySet() }
            assertEquals("point $point: the orphans are gone", emptyList<String>(), w.listed())
            assertEquals("point $point: only a completed directory sync leaves an orphan", if (point == total - 1) 1 else 0, report.orphansDeleted)
            assertTrue(w.reconcile.run(w.database) { emptySet() }.clean)
        }
    }

    /** The two orders the write must not have, put back: the model loses the data (the mutants are killed). */
    @Test
    fun theCrashModelSeesARenameWithoutAForceAndARenameWithoutADirectorySync() {
        // the real order: whole and named after a reboot
        MediaWorld().use { w ->
            val written = w.files.write(blobOf(1), enforceFloor = false) as WriteResult.Written
            w.disk.reboot()
            assertEquals(MediaLimits.FRAGMENT_BYTES.toLong(), File(w.files.directory, hex(written.fileName)).length())
        }
        // no force: the name survives and the bytes do not (an empty file under the final name)
        MediaWorld().use { w ->
            w.disk.skipForce = true
            val written = w.files.write(blobOf(1), enforceFloor = false) as WriteResult.Written
            w.disk.reboot()
            assertTrue(File(w.files.directory, hex(written.fileName)).exists())
            assertEquals("the unforced bytes are lost", 0L, File(w.files.directory, hex(written.fileName)).length())
        }
        // no directory sync: the bytes survive and the name does not
        MediaWorld().use { w ->
            w.disk.skipDirectorySync = true
            val written = w.files.write(blobOf(1), enforceFloor = false) as WriteResult.Written
            w.disk.reboot()
            assertFalse("the unsynced rename is reverted", File(w.files.directory, hex(written.fileName)).exists())
        }
    }

    /**
     * A crash between the write of a row's file and the row's commit leaves an orphan file; a crash after the commit leaves
     * both. At every kill point of the file operations the invariant of §15.3 holds after a reboot and a reconcile: every row
     * names a whole file, and no file is unnamed.
     */
    @Test
    fun aBlobWrittenAndThenReferencedSurvivesACrashAtAnyFileOperationOfTheNextWrite() {
        val total = MediaWorld().use { w ->
            w.putBlob(1)
            w.disk.reset()
            w.putBlob(2)
            w.disk.points
        }
        assertEquals(10, total)
        for (point in 0 until total) MediaWorld().use { w ->
            w.putBlob(1)
            w.disk.reset()
            w.disk.arm(point)
            runCatchingCrash { w.putBlob(2) }
            w.disk.reboot()
            val report = w.reconcile.run(w.database) { emptySet() }
            // the first blob is whole and named; the second never got its row (its transaction comes after its write returns),
            // so whatever the crash left of it was an orphan, and the reconcile removed it
            val rows = w.db.queryLong("SELECT count(*) FROM media_blob")!!
            assertEquals("point $point", 1L, rows)
            assertEquals("point $point", 1, w.listed().size)
            assertEquals("point $point", if (point == total - 1) 1 else 0, report.orphansDeleted)
            for (name in w.listed()) {
                assertEquals(MediaLimits.FRAGMENT_BYTES.toLong(), File(w.files.directory, name).length())
                assertEquals(0L, attributes(File(w.files.directory, name)).lastModifiedTime().toMillis())
            }
            assertEquals(0, report.rowsDropped)
            assertTrue(report.lostNamed.isEmpty())
        }
    }

    private inline fun runCatchingCrash(block: () -> Unit): InjectedCrash? {
        try {
            block()
        } catch (e: InjectedCrash) {
            return e
        }
        return null
    }
}
