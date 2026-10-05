package org.ghost.media.store

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * The race between a sealer and the reconcile (Phase 11 design §6.2, §10.4, §13.7; finding R1/R2 of the adversarial review of
 * slice S3, §22.4 row 25). The sealer runs on the media worker, the reconcile on the media actor, and the reconcile deletes
 * every entry of the store directory that no row names and that is not in `preparing`. The first version of the store generated
 * a file's name inside `write` and returned it after the file was visible, so the sealer could not have the name in `preparing`
 * in time: a reconcile in the window deleted the temp file (the write then failed) or the final file (the write then returned
 * the name of a file that was not there, and the object that `MEDIA-COMMIT` built on it lost a blob for ever).
 *
 * [HookedFileSystem] calls a function before and after every call of the write path, so a reconcile can be run **at every one of
 * the ten points of a write**, deterministically (the thread-level test beside it does the same with two real threads). The
 * enumeration runs twice: with the protocol (the name reserved before the write, released after the row commits), where no
 * point may lose anything, and as the control without it, where it must lose the file at nine points of ten — so the first
 * result is not an enumeration that cannot fail.
 */
class MediaReconcileRaceTest {

    /**
     * Calls [onPoint] with the number of the kill point (0 to 9 for one write) before and after each call of the write path.
     * The calls the hook itself makes (the reconcile's own file operations) are not counted and do not fire it again.
     */
    private class HookedFileSystem(private val real: CiphertextFileSystem) : CiphertextFileSystem by real {
        var onPoint: ((Int) -> Unit)? = null
        private var point = 0
        private var busy = false

        private fun <T> around(block: () -> T): T {
            fire()
            val result = block()
            fire()
            return result
        }

        private fun fire() {
            val hook = onPoint
            if (busy || hook == null) return
            busy = true
            try {
                hook(point++)
            } finally {
                busy = false
            }
        }

        override fun writeNew(file: File, bytes: ByteArray) = around { real.writeNew(file, bytes) }
        override fun setTimes(file: File, lastModifiedMillis: Long, lastAccessMillis: Long) = around { real.setTimes(file, lastModifiedMillis, lastAccessMillis) }
        override fun force(file: File) = around { real.force(file) }
        override fun rename(from: File, to: File) = around { real.rename(from, to) }
        override fun syncDirectory(directory: File) = around { real.syncDirectory(directory) }
    }

    private class Run(val point: Int, val report: ReconcileReport, val result: Any, val fileExists: Boolean)

    /**
     * One write with a reconcile run at kill point [point]: the sealer's side ([reserve] says whether it reserved its name first),
     * then the outcome of the write and whether the file is there once the write has returned.
     */
    private fun runAt(point: Int, reserve: Boolean): Run = MediaWorld().use { w ->
        val port = HookedFileSystem(NioCiphertextFileSystem())
        val files = CiphertextFiles(File(w.dir, "race"), port, SequentialNames()).also { it.open() }
        val reconcile = MediaReconcile(files, w.stores.blobs, w.stores.fragments)
        val preparing = PreparingFiles()
        val name = if (reserve) preparing.reserve(files) else files.newName()
        var report: ReconcileReport? = null
        port.onPoint = { here ->
            // the reconcile is the media actor's: it runs between two calls of the sealer, with the names reserved so far
            if (here == point) report = reconcile.run(w.database) { preparing.snapshot() }
        }
        val result: Any = try {
            files.write(name, blobOf(1), enforceFloor = false)
        } catch (e: CiphertextFilesException) {
            e
        }
        port.onPoint = null
        Run(point, report!!, result, files.exists(name))
    }

    @Test
    fun aReconcileAtAnyOfTheTenPointsOfAWriteLosesNothingWhenTheNameWasReservedFirst() {
        for (point in 0 until 10) {
            val run = runAt(point, reserve = true)
            assertEquals("point $point: nothing is deleted", 0, run.report.orphansDeleted)
            assertTrue("point $point: the write succeeded (${run.result})", run.result is WriteResult.Written)
            assertTrue("point $point: and the file is there", run.fileExists)
        }
    }

    @Test
    fun withoutTheReservationTheSameEnumerationLosesTheFileAtNineOfTenPoints() {
        // Point 0 is before the first call: nothing exists yet. From point 1 on there is a temp file and, from point 7, the final
        // file: a reconcile that has not been told the name deletes it, and the sealer either fails (temp) or is told a name
        // whose file is gone (final).
        val lost = (0 until 10).map { runAt(it, reserve = false) }.filter { !(it.result is WriteResult.Written && it.fileExists) }
        assertEquals((1..9).toList(), lost.map { it.point })
        assertTrue("every one of them was a deletion by the reconcile", lost.all { it.report.orphansDeleted == 1 })
        assertTrue("from the rename on the sealer is told success for a file that is gone", lost.filter { it.point >= 7 }.all { it.result is WriteResult.Written })
        assertTrue("before it the write fails", lost.filter { it.point in 1..6 }.all { it.result is CiphertextFilesException })
    }

    @Test
    fun theWholeProtocolReserveWriteCommitReleaseSurvivesAReconcileBeforeAndAfterEachStep() = MediaWorld().use { w ->
        val name = w.preparing.reserve(w.files)
        assertTrue("reserved, no file yet", w.reconcile.run(w.database, w.preparing::snapshot).clean)
        w.files.write(name, blobOf(1), enforceFloor = false)
        assertEquals("written, no row yet", 0, w.reconcile.run(w.database, w.preparing::snapshot).orphansDeleted)
        assertTrue(w.files.exists(name))
        // MEDIA-COMMIT: the row, then the release
        w.tx { w.stores.blobs.insert(it, MediaBlob(hashOfBlob(1), name, BlobOrigin.SEALED, null)) }
        assertTrue("committed, still reserved", w.reconcile.run(w.database, w.preparing::snapshot).clean)
        w.preparing.release(name)
        assertTrue("committed and released: named by its row", w.reconcile.run(w.database, w.preparing::snapshot).clean)
        assertTrue(w.files.exists(name))
        assertTrue(w.preparing.isEmpty)
        // an abandoned preparation: reserved, written, never committed, released: the next reconcile deletes it
        val abandoned = w.preparing.reserve(w.files)
        w.files.write(abandoned, blobOf(2), enforceFloor = false)
        w.preparing.release(abandoned)
        assertEquals(1, w.reconcile.run(w.database, w.preparing::snapshot).orphansDeleted)
        assertFalse(w.files.exists(abandoned))
    }

    /** The temp file is named after the final name, so that one reservation covers both (and so the reconcile can tell whose it is). */
    @Test
    fun theTempFileIsNamedAfterTheFinalNameAndIsTheOnlyEntryUntilTheRename() = MediaWorld().use { w ->
        val name = w.preparing.reserve(w.files)
        var seen: List<String>? = null
        val port = HookedFileSystem(NioCiphertextFileSystem())
        // A name source that can never produce the reserved name, so that a temp file named from the source (the first version's
        // `.t<random>`) is told from one named after the final name.
        val files = CiphertextFiles(File(w.dir, "temp"), port, NameSource { ByteArray(16) { 0x42 } }).also { it.open() }
        port.onPoint = { here -> if (here == 1) seen = files.list() } // after the bytes were written
        files.write(name, blobOf(1), enforceFloor = false)
        assertEquals(listOf(CiphertextFiles.TEMP_PREFIX + hex(name)), seen)
        assertEquals(hex(name), CiphertextFiles.finalNameOfTemp(seen!!.single()))
        assertEquals(listOf(hex(name)), files.list())
        assertNull(CiphertextFiles.finalNameOfTemp(hex(name)))
        assertNull(CiphertextFiles.finalNameOfTemp(CiphertextFiles.TEMP_PREFIX + "zz"))
        assertNull(CiphertextFiles.finalNameOfTemp(CiphertextFiles.TEMP_PREFIX + hex(name).substring(1)))
    }

    /** The two real threads of §13.7: the sealer is held inside a call of its write, the reconcile runs on the media actor's thread. */
    @Test
    fun withTwoThreadsASealerHeldInsideItsWriteKeepsItsFileWhateverTheCallItIsHeldIn() {
        for (heldIn in listOf("setTimes", "force", "rename", "syncDirectory")) MediaWorld().use { w ->
            val parked = CountDownLatch(1)
            val release = CountDownLatch(1)
            val real = NioCiphertextFileSystem()
            // Only the sealer's thread is held: the reconcile's own calls of the same port must not wait for it.
            fun park(call: String) {
                if (call == heldIn && Thread.currentThread().name == "sealer") {
                    parked.countDown()
                    check(release.await(30, TimeUnit.SECONDS)) { "not released" }
                }
            }
            val port = object : CiphertextFileSystem by real {
                override fun setTimes(file: File, lastModifiedMillis: Long, lastAccessMillis: Long) {
                    park("setTimes")
                    real.setTimes(file, lastModifiedMillis, lastAccessMillis)
                }
                override fun force(file: File) {
                    park("force")
                    real.force(file)
                }
                override fun rename(from: File, to: File) {
                    park("rename")
                    real.rename(from, to)
                }
                override fun syncDirectory(directory: File) {
                    park("syncDirectory")
                    real.syncDirectory(directory)
                }
            }
            val files = CiphertextFiles(File(w.dir, "two"), port, SequentialNames()).also { it.open() }
            val reconcile = MediaReconcile(files, w.stores.blobs, w.stores.fragments)
            val preparing = PreparingFiles()
            val name = preparing.reserve(files)
            val outcome = AtomicReference<Any>()
            val worker = Thread({ outcome.set(try { files.write(name, blobOf(1), enforceFloor = false) } catch (e: Throwable) { e }) }, "sealer")
            worker.start()
            assertTrue("the sealer must be inside $heldIn", parked.await(10, TimeUnit.SECONDS))
            val report = reconcile.run(w.database) { preparing.snapshot() }
            release.countDown()
            worker.join(10_000)
            assertEquals("held in $heldIn: the reconcile deleted nothing", 0, report.orphansDeleted)
            assertTrue("held in $heldIn: ${outcome.get()}", outcome.get() is WriteResult.Written)
            assertTrue("held in $heldIn: the file is there", files.exists(name))
        }
    }
}
