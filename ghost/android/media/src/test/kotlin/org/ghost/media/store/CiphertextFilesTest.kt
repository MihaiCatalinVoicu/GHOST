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
import java.nio.file.attribute.BasicFileAttributes

/**
 * The ciphertext store without faults (Phase 11 design §10.4): atomic, durable writes of 64 KiB blobs under random names, the
 * times of S0-12, the free-space floor of §7.5, reads, deletion, listing. The faults are [CiphertextFilesFaultTest]'s.
 */
class CiphertextFilesTest {
    @get:Rule
    val temp = TemporaryFolder()

    private fun files(
        fileSystem: CiphertextFileSystem = NioCiphertextFileSystem(directorySyncSupported = false),
        floor: Long = 0L,
        names: NameSource = SequentialNames(),
    ): CiphertextFiles = CiphertextFiles(File(temp.root, "m"), fileSystem, names, floor).also { it.open() }

    private fun attributes(f: CiphertextFiles, fileName: ByteArray): BasicFileAttributes =
        Files.readAttributes(File(f.directory, hex(fileName)).toPath(), BasicFileAttributes::class.java)

    @Test
    fun aWrittenBlobIsReadBackWholeUnderTheNameItReturns() {
        val f = files()
        val written = f.write(blobOf(7), enforceFloor = true) as WriteResult.Written
        assertEquals(16, written.fileName.size)
        assertArrayEquals(blobOf(7), f.read(written.fileName))
        assertTrue(f.exists(written.fileName))
        assertEquals(listOf(hex(written.fileName)), f.list())
        assertEquals(MediaLimits.FRAGMENT_BYTES.toLong(), File(f.directory, hex(written.fileName)).length())
        // the name is the hex of the 16 bytes, and nothing else is in the directory (no temp file is left behind)
        assertTrue(CiphertextFiles.isFinalName(f.list().single()))
    }

    @Test
    fun aBlobOrANameOfTheWrongSizeIsRefusedBeforeAnythingIsTouched() {
        val f = files()
        for (size in listOf(0, 1, 65_535, 65_537, 262_144)) {
            val e = assertThrows(CiphertextFilesException::class.java) { f.write(ByteArray(size), enforceFloor = false) }
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
        val written = f.write(blobOf(1), enforceFloor = false) as WriteResult.Written
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
        val good = f.write(blobOf(1), enforceFloor = false) as WriteResult.Written
        val stamped = f.write(blobOf(2), enforceFloor = false) as WriteResult.Written
        // a file as an older build, a restore or a crash before setTimes would leave it
        assertTrue(File(f.directory, hex(stamped.fileName)).setLastModified(1_700_000_000_000L))
        assertNotEquals(0L, attributes(f, stamped.fileName).lastModifiedTime().toMillis())
        assertFalse("a file with zero times is left alone", f.reapplyTimes(hex(good.fileName)))
        assertTrue(f.reapplyTimes(hex(stamped.fileName)))
        assertEquals(0L, attributes(f, stamped.fileName).lastModifiedTime().toMillis())
        assertEquals(0L, attributes(f, stamped.fileName).lastAccessTime().toMillis())
        assertFalse("the second call changes nothing", f.reapplyTimes(hex(stamped.fileName)))
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
        val port = Scripted(NioCiphertextFileSystem(false), free = MediaLimits.FREE_FLOOR_BYTES - 1)
        val f = files(port, floor = MediaLimits.FREE_FLOOR_BYTES)
        assertEquals(WriteResult.BelowFloor, f.write(blobOf(1), enforceFloor = true))
        assertEquals("no file, no temp file", emptyList<String>(), f.list())
        // exactly at the floor there is room; the sealer, which owns its object, is not held back by the floor
        port.free = MediaLimits.FREE_FLOOR_BYTES
        assertTrue(f.write(blobOf(1), enforceFloor = true) is WriteResult.Written)
        port.free = 0L
        assertTrue(f.write(blobOf(2), enforceFloor = false) is WriteResult.Written)
        assertEquals(2, f.list().size)
    }

    @Test
    fun aFullDiskIsATypedErrorAndLeavesNoTempFileBehind() {
        val port = Scripted(NioCiphertextFileSystem(false), failWriteWith = "No space left on device")
        val f = files(port)
        val e = assertThrows(CiphertextFilesException::class.java) { f.write(blobOf(1), enforceFloor = false) }
        assertEquals(CiphertextFilesError.DISK_FULL, e.error)
        assertTrue(e.cause is IOException)
        assertEquals("the partial temp file was removed", emptyList<String>(), f.list())
        port.failWriteWith = "Input/output error"
        assertEquals(CiphertextFilesError.IO, assertThrows(CiphertextFilesException::class.java) { f.write(blobOf(1), enforceFloor = false) }.error)
        assertEquals(emptyList<String>(), f.list())
        // the exception names no file, no path and no byte
        assertRedacted(e.toString(), blobOf(1).copyOf(32))
        assertFalse(e.message.orEmpty().contains(temp.root.name))
    }

    @Test
    fun deletingIsIdempotentAndListingShowsOnlyTheStore() {
        val f = files()
        val a = f.write(blobOf(1), enforceFloor = false) as WriteResult.Written
        val b = f.write(blobOf(2), enforceFloor = false) as WriteResult.Written
        assertEquals(setOf(hex(a.fileName), hex(b.fileName)), f.list().toSet())
        assertTrue(f.delete(a.fileName))
        assertFalse("a second delete finds nothing and is no error", f.delete(a.fileName))
        assertEquals(listOf(hex(b.fileName)), f.list())
        assertFalse(f.exists(a.fileName))
    }

    @Test
    fun aFileOfAnotherLengthIsCorruptNotShort() {
        val f = files()
        val written = f.write(blobOf(1), enforceFloor = false) as WriteResult.Written
        File(f.directory, hex(written.fileName)).writeBytes(ByteArray(100))
        assertEquals(CiphertextFilesError.CORRUPT_LENGTH, assertThrows(CiphertextFilesException::class.java) { f.read(written.fileName) }.error)
        f.delete(written.fileName)
        assertEquals(CiphertextFilesError.IO, assertThrows(CiphertextFilesException::class.java) { f.read(written.fileName) }.error)
    }

    @Test
    fun theDefaultNamesAreRandomSixteenBytesAndNeverRepeat() {
        val f = CiphertextFiles(File(temp.root, "r"), NioCiphertextFileSystem(false)).also { it.open() }
        val seen = HashSet<String>()
        repeat(40) { n ->
            val written = f.write(blobOf(n), enforceFloor = false) as WriteResult.Written
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
        val written = f.write(blobOf(3), enforceFloor = false) as WriteResult.Written
        assertEquals("CiphertextFiles", f.toString())
        assertRedacted(written.toString(), written.fileName)
        assertRedacted(WriteResult.BelowFloor.toString())
        assertRedacted(CiphertextFilesException(CiphertextFilesError.IO, "write", null).toString())
    }
}
