package org.ghost.media.store

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.nio.file.attribute.BasicFileAttributeView
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.FileTime

/**
 * The ciphertext store without faults (Phase 11 design §10.4): atomic, durable writes of 64 KiB blobs under random names, the
 * times of S0-12, the free-space floor of §7.5, reads, deletion, listing. The faults are [CiphertextFilesFaultTest]'s.
 */
class CiphertextFilesTest {
    @get:Rule
    val temp = TemporaryFolder()

    private fun files(
        fileSystem: CiphertextFileSystem = NioCiphertextFileSystem(),
        floor: Long = 0L,
        names: NameSource = SequentialNames(),
    ): CiphertextFiles = CiphertextFiles(File(temp.root, "m"), fileSystem, names, floor).also { it.open() }

    private fun attributes(f: CiphertextFiles, fileName: ByteArray): BasicFileAttributes =
        Files.readAttributes(File(f.directory, hex(fileName)).toPath(), BasicFileAttributes::class.java)

    @Test
    fun aWrittenBlobIsReadBackWholeUnderTheNameItReturns() {
        val f = files()
        val written = f.writeFresh(blobOf(7), enforceFloor = true) as WriteResult.Written
        assertEquals(16, written.fileName.size)
        assertArrayEquals(blobOf(7), f.read(written.fileName))
        assertTrue(f.exists(written.fileName))
        assertEquals(listOf(hex(written.fileName)), f.list())
        assertEquals(MediaLimits.FRAGMENT_BYTES.toLong(), File(f.directory, hex(written.fileName)).length())
        // the name is the hex of the 16 bytes, and nothing else is in the directory (no temp file is left behind)
        assertTrue(CiphertextFiles.isFinalName(f.list().single()))
    }

    /** The name is the caller's (reserved before the write, see [MediaReconcileRaceTest]); the temp file is named after it. */
    @Test
    fun aWriteTakesTheCallersNameAndRefusesANameThatIsTakenWithoutTouchingTheFileThatHoldsIt() {
        val f = files()
        val name = f.newName()
        assertEquals(16, name.size)
        val written = f.write(name, blobOf(1), enforceFloor = false) as WriteResult.Written
        assertArrayEquals(name, written.fileName)
        assertEquals(listOf(hex(name)), f.list())
        assertEquals(CiphertextFilesError.BAD_SIZE, assertThrows(CiphertextFilesException::class.java) { f.write(ByteArray(15), blobOf(1), enforceFloor = false) }.error)
        assertEquals(CiphertextFilesError.BAD_SIZE, assertThrows(CiphertextFilesException::class.java) { f.write(ByteArray(17), blobOf(1), enforceFloor = false) }.error)
        // a second write under the same name meets the file that holds it: refused, the file is as it was, no temp file is left
        val taken = assertThrows(CiphertextFilesException::class.java) { f.write(name, blobOf(2), enforceFloor = false) }
        assertEquals(CiphertextFilesError.IO, taken.error)
        assertEquals(listOf(hex(name)), f.list())
        assertArrayEquals(blobOf(1), f.read(name))
    }

    @Test
    fun aBlobOrANameOfTheWrongSizeIsRefusedBeforeAnythingIsTouched() {
        val f = files()
        for (size in listOf(0, 1, 65_535, 65_537, 262_144)) {
            val e = assertThrows(CiphertextFilesException::class.java) { f.writeFresh(ByteArray(size), enforceFloor = false) }
            assertEquals(CiphertextFilesError.BAD_SIZE, e.error)
        }
        assertEquals(emptyList<String>(), f.list())
        assertEquals(CiphertextFilesError.BAD_SIZE, assertThrows(CiphertextFilesException::class.java) { f.read(ByteArray(15)) }.error)
        assertEquals(CiphertextFilesError.BAD_SIZE, assertThrows(CiphertextFilesException::class.java) { f.delete(ByteArray(17)) }.error)
    }

    /**
     * S0-12: `setTimes(0, 0)` zeroes `mtime` **and** `atime` (`setLastModified(0)` leaves `atime` at the creation second, and
     * `/data` is mounted `noatime`, so it would never move again). The file has them from the moment it has its final name.
     */
    @Test
    fun aWrittenFileHasNoModificationTimeAndNoAccessTime() {
        val f = files()
        val written = f.writeFresh(blobOf(1), enforceFloor = false) as WriteResult.Written
        val a = attributes(f, written.fileName)
        assertEquals("mtime", 0L, a.lastModifiedTime().toMillis())
        assertEquals("atime", 0L, a.lastAccessTime().toMillis())
        // Reading the file does not stamp it on this volume's mount; the store's own read must not rewrite the times either.
        f.read(written.fileName)
        assertEquals(0L, attributes(f, written.fileName).lastModifiedTime().toMillis())
    }

    @Test
    fun reapplyingTheTimesFixesAFileThatKeptItsTimesAndOnlyThatFile() {
        val f = files()
        val good = f.writeFresh(blobOf(1), enforceFloor = false) as WriteResult.Written
        val stamped = f.writeFresh(blobOf(2), enforceFloor = false) as WriteResult.Written
        // a file as an older build, a restore or a crash before setTimes would leave it
        assertTrue(File(f.directory, hex(stamped.fileName)).setLastModified(1_700_000_000_000L))
        assertNotEquals(0L, attributes(f, stamped.fileName).lastModifiedTime().toMillis())
        assertFalse("a file with zero times is left alone", f.reapplyTimes(hex(good.fileName)))
        assertTrue(f.reapplyTimes(hex(stamped.fileName)))
        assertEquals(0L, attributes(f, stamped.fileName).lastModifiedTime().toMillis())
        assertEquals(0L, attributes(f, stamped.fileName).lastAccessTime().toMillis())
        assertFalse("the second call changes nothing", f.reapplyTimes(hex(stamped.fileName)))
    }

    /**
     * S0-12 on a `relatime` mount: a read stamps `atime` and leaves `mtime` at zero. The reapplication reads both times and
     * must write when **either** is not zero (the first version looked at `atime` in its condition and passed a mutant that
     * dropped it, because every other test stamps `mtime` too).
     */
    @Test
    fun reapplyingTheTimesAlsoFixesAFileWhoseOnlyAccessTimeWasStamped() {
        val f = files()
        val written = f.writeFresh(blobOf(1), enforceFloor = false) as WriteResult.Written
        val listed = hex(written.fileName)
        val path = File(f.directory, listed).toPath()
        Files.getFileAttributeView(path, BasicFileAttributeView::class.java)
            .setTimes(FileTime.fromMillis(0L), FileTime.fromMillis(1_700_000_000_000L), null)
        assertEquals("mtime is zero", 0L, attributes(f, written.fileName).lastModifiedTime().toMillis())
        assertNotEquals("atime is not", 0L, attributes(f, written.fileName).lastAccessTime().toMillis())
        assertTrue(f.reapplyTimes(listed))
        assertEquals(0L, attributes(f, written.fileName).lastAccessTime().toMillis())
        assertFalse(f.reapplyTimes(listed))
        // and the other way round: only mtime
        Files.getFileAttributeView(path, BasicFileAttributeView::class.java)
            .setTimes(FileTime.fromMillis(1_700_000_000_000L), FileTime.fromMillis(0L), null)
        assertTrue(f.reapplyTimes(listed))
        assertEquals(0L, attributes(f, written.fileName).lastModifiedTime().toMillis())
    }

    /**
     * The tests build the platform's own port, so where the host can open a directory for `force` (Linux, Android) every write of
     * every test syncs the directory for real. This is the one place that says so: the sync opens the directory (a directory
     * that is not there is an I/O error), and it is skipped only by the flag, never by accident.
     */
    @Test
    fun theProductionPortSyncsTheDirectoryWhereTheHostCanAndSkipsItOnlyByTheFlag() {
        val windows = System.getProperty("os.name").orEmpty().startsWith("Windows")
        val missing = File(temp.root, "missing")
        val platform = NioCiphertextFileSystem()
        if (windows) {
            platform.syncDirectory(missing) // a directory cannot be opened for force on Windows: the port skips the sync
        } else {
            assertThrows(IOException::class.java) { platform.syncDirectory(missing) }
            platform.syncDirectory(temp.root)
        }
        NioCiphertextFileSystem(directorySyncSupported = false).syncDirectory(missing)
        assertThrows(IOException::class.java) { NioCiphertextFileSystem(directorySyncSupported = true).syncDirectory(missing) }
    }

    /** Wraps a real port and reports a chosen amount of free space and, optionally, a failure on the next write. */
    private class Scripted(val real: CiphertextFileSystem, var free: Long = Long.MAX_VALUE, var failWriteWith: String? = null) :
        CiphertextFileSystem by real {
        override fun freeSpace(directory: File): Long = free
        override fun writeNew(file: File, bytes: ByteArray) {
            failWriteWith?.let {
                // a partial file, as a full disk leaves it
                real.writeNew(file, bytes.copyOf(1024))
                throw IOException(it)
            }
            real.writeNew(file, bytes)
        }
    }

    @Test
    fun belowTheFreeSpaceFloorAnIngestConsumesTheBlobWithoutAFile() {
        val port = Scripted(NioCiphertextFileSystem(), free = MediaLimits.FREE_FLOOR_BYTES - 1)
        val f = files(port, floor = MediaLimits.FREE_FLOOR_BYTES)
        assertEquals(WriteResult.BelowFloor, f.writeFresh(blobOf(1), enforceFloor = true))
        assertEquals("no file, no temp file", emptyList<String>(), f.list())
        // exactly at the floor there is room; the sealer, which owns its object, is not held back by the floor
        port.free = MediaLimits.FREE_FLOOR_BYTES
        assertTrue(f.writeFresh(blobOf(1), enforceFloor = true) is WriteResult.Written)
        port.free = 0L
        assertTrue(f.writeFresh(blobOf(2), enforceFloor = false) is WriteResult.Written)
        assertEquals(2, f.list().size)
    }

    @Test
    fun aFullDiskIsATypedErrorAndLeavesNoTempFileBehind() {
        val port = Scripted(NioCiphertextFileSystem(), failWriteWith = "No space left on device")
        val f = files(port)
        val e = assertThrows(CiphertextFilesException::class.java) { f.writeFresh(blobOf(1), enforceFloor = false) }
        assertEquals(CiphertextFilesError.DISK_FULL, e.error)
        assertTrue(e.cause is IOException)
        assertEquals("the partial temp file was removed", emptyList<String>(), f.list())
        port.failWriteWith = "Input/output error"
        assertEquals(CiphertextFilesError.IO, assertThrows(CiphertextFilesException::class.java) { f.writeFresh(blobOf(1), enforceFloor = false) }.error)
        assertEquals(emptyList<String>(), f.list())
        // the exception names no file, no path and no byte
        assertRedacted(e.toString(), blobOf(1).copyOf(32))
        assertFalse(e.message.orEmpty().contains(temp.root.name))
    }

    /**
     * R4 of the review: the free space of a directory that is not there is 0, which read as "below the floor" and consumed every
     * ingested blob without a file. A missing store is a typed I/O error, with the floor or without it.
     */
    @Test
    fun aMissingStoreDirectoryIsAnIoErrorAndNeverBelowTheFloor() {
        val f = files(floor = 1L)
        assertTrue("the control: with the directory there and a byte of room the ingest writes", f.writeFresh(blobOf(1), enforceFloor = true) is WriteResult.Written)
        f.directory.deleteRecursively()
        for (enforceFloor in listOf(true, false)) {
            val e = assertThrows(CiphertextFilesException::class.java) { f.writeFresh(blobOf(1), enforceFloor) }
            assertEquals("enforceFloor = $enforceFloor", CiphertextFilesError.IO, e.error)
        }
        assertEquals(CiphertextFilesError.IO, assertThrows(CiphertextFilesException::class.java) { f.freeSpace() }.error)
        assertEquals(CiphertextFilesError.IO, assertThrows(CiphertextFilesException::class.java) { f.list() }.error)
    }

    /**
     * T3: the exception names no file, no path and no byte, **and neither does its cause**. A file system's message does
     * (`NoSuchFileException: C:\...\m\ab12...`), a crash report prints the chain, and the first version kept the original as
     * the cause: the review read the name of the file in the `Caused by:` line.
     */
    @Test
    fun aFailureCarriesItsClassAndItsFramesAndNothingThatNamesAFileOrAPath() {
        val f = files()
        val present = f.newName()
        f.write(present, blobOf(1), enforceFloor = false)
        val absent = f.newName()
        val missingDirectory = CiphertextFiles(File(temp.root, "never-created"), NioCiphertextFileSystem())
        val failures: List<Pair<String, () -> Unit>> = listOf(
            "reading a file that is not there" to { f.read(absent) },
            "writing onto a name that is taken" to { f.write(present, blobOf(2), enforceFloor = false) },
            "listing a directory that is not there" to { missingDirectory.list() },
            "writing into a directory that is not there" to { missingDirectory.writeFresh(blobOf(1), enforceFloor = false) },
        )
        for ((label, action) in failures) {
            val e = assertThrows(label, CiphertextFilesException::class.java) { action() }
            val trace = e.stackTraceToString()
            val cause = e.cause
            assertTrue("$label: there is a cause, an I/O failure", cause is IOException)
            assertTrue("$label: it says what kind: ${cause!!.message}", cause.message.orEmpty().contains("Exception"))
            assertTrue("$label: and keeps the frames", cause.stackTrace.isNotEmpty())
            assertFalse("$label: the temporary folder is in the trace: $trace", trace.contains(temp.root.name))
            assertFalse("$label: a path is in the trace: $trace", trace.contains(f.directory.path) || trace.contains(f.directory.name + File.separator))
            assertFalse("$label: a file name is in the trace", trace.lowercase().contains(hex(present)) || trace.lowercase().contains(hex(absent)))
            assertRedacted(trace, present, absent, blobOf(1).copyOf(32))
        }
    }

    @Test
    fun deletingIsIdempotentAndListingShowsOnlyTheStore() {
        val f = files()
        val a = f.writeFresh(blobOf(1), enforceFloor = false) as WriteResult.Written
        val b = f.writeFresh(blobOf(2), enforceFloor = false) as WriteResult.Written
        assertEquals(setOf(hex(a.fileName), hex(b.fileName)), f.list().toSet())
        assertTrue(f.delete(a.fileName))
        assertFalse("a second delete finds nothing and is no error", f.delete(a.fileName))
        assertEquals(listOf(hex(b.fileName)), f.list())
        assertFalse(f.exists(a.fileName))
    }

    @Test
    fun aFileOfAnotherLengthIsCorruptNotShort() {
        val f = files()
        val written = f.writeFresh(blobOf(1), enforceFloor = false) as WriteResult.Written
        File(f.directory, hex(written.fileName)).writeBytes(ByteArray(100))
        assertEquals(CiphertextFilesError.CORRUPT_LENGTH, assertThrows(CiphertextFilesException::class.java) { f.read(written.fileName) }.error)
        f.delete(written.fileName)
        assertEquals(CiphertextFilesError.IO, assertThrows(CiphertextFilesException::class.java) { f.read(written.fileName) }.error)
    }

    @Test
    fun theDefaultNamesAreRandomSixteenBytesAndNeverRepeat() {
        val f = CiphertextFiles(File(temp.root, "r"), NioCiphertextFileSystem()).also { it.open() }
        val seen = HashSet<String>()
        repeat(40) { n ->
            val written = f.writeFresh(blobOf(n), enforceFloor = false) as WriteResult.Written
            assertEquals(16, written.fileName.size)
            assertTrue(seen.add(hex(written.fileName)))
        }
        assertEquals(40, f.list().size)
        assertTrue(f.list().all { CiphertextFiles.isFinalName(it) })
        // not a counter and not a constant: 40 names differ in their first byte somewhere
        assertTrue(seen.map { it.substring(0, 2) }.toSet().size > 8)
        assertFalse(CiphertextFiles.isFinalName(CiphertextFiles.TEMP_PREFIX + "ab".repeat(16)))
        assertFalse(CiphertextFiles.isFinalName("ab".repeat(15)))
        assertFalse(CiphertextFiles.isFinalName("AB".repeat(16)))
    }

    @Test
    fun theTypesShowNothing() {
        val f = files()
        val written = f.writeFresh(blobOf(3), enforceFloor = false) as WriteResult.Written
        assertEquals("CiphertextFiles", f.toString())
        assertRedacted(written.toString(), written.fileName)
        assertRedacted(WriteResult.BelowFloor.toString())
        assertRedacted(CiphertextFilesException(CiphertextFilesError.IO, "write", null).toString())
    }
}
