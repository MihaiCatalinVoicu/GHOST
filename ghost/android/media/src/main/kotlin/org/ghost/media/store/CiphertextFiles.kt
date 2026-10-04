package org.ghost.media.store

import java.io.File
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.FileAlreadyExistsException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributeView
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.FileTime
import java.security.SecureRandom

/**
 * The ciphertext store: **the only writer of media bytes on the device** (Phase 11 design §10.4; invariant T44, gate G-M1's
 * writer allowlist). One file per blob, exactly [MediaLimits.FRAGMENT_BYTES] bytes of relay-identical ciphertext, under a
 * random 16-byte name (hex on disk, the bytes in `media_blob.file_name`), in `noBackupFilesDir/m/`. **No plaintext ever reaches
 * this class** — it is handed a blob that is already ciphertext — and it names no network class and uses no coroutine.
 *
 * **Writing is atomic and durable before the row that names the file exists** (§10.4: "every write is `force(true)` and the
 * directory is synced before the transaction that references the file"): the bytes go to a temp file in the same directory,
 * the times are set, the file is forced, renamed to its final name and the directory synced. A crash anywhere leaves either
 * no file under the final name or a whole, durable one; a leftover temp file is an orphan the reconcile deletes. Each step is
 * a call of the [CiphertextFileSystem] port, which the tests wrap with a fault-injecting implementation that crashes before
 * and after every call and loses what a power loss loses (§15.3).
 *
 * **The times (S0-12, §10.4).** `setTimes(0, 0)` zeroes `mtime` **and** `atime` (`setLastModified(0)` leaves `atime` at the
 * creation second, and `/data` is mounted `noatime`, so it would never move again). It is applied to the temp file, before
 * the force and the rename, so a file never has its final name with a real time; a crash between the write and the call
 * leaves only a temp file. The reconcile re-applies it to every file it keeps ([reapplyTimes]). What an app cannot set is
 * declared (L9-M6): `ctime`, the birth time and the inode numbers.
 *
 * **The free-space floor (§7.5).** Below [MediaLimits.FREE_FLOOR_BYTES] of free storage an ingest consumes a blob without
 * writing a file ([WriteResult.BelowFloor]), so that local state never changes what is fetched; a sealer writing its own
 * object passes `enforceFloor = false` and meets a full disk as [CiphertextFilesException] with kind
 * [CiphertextFilesError.DISK_FULL].
 *
 * **Deletion removes the name and nothing more.** The design asks for no overwrite of a ciphertext file: the key of a deleted
 * blob is erased (crypto-shredding, D19), the bytes are ciphertext whose key exists nowhere, and an in-place overwrite
 * promises nothing on flash with a log-structured file system (declared, §11.1). `delete` therefore unlinks the file.
 */
class CiphertextFiles(
    val directory: File,
    private val fileSystem: CiphertextFileSystem = NioCiphertextFileSystem(),
    private val names: NameSource = SecureNameSource,
    private val freeFloorBytes: Long = MediaLimits.FREE_FLOOR_BYTES,
) {

    /** Creates the directory if it is not there (the app calls it once, at start). */
    fun open() {
        try {
            fileSystem.makeDirectory(directory)
        } catch (e: IOException) {
            throw CiphertextFilesException(CiphertextFilesError.IO, "open", e)
        }
    }

    /**
     * Writes one blob under a fresh random name and returns the name, or [WriteResult.BelowFloor] when [enforceFloor] holds
     * and the free storage is below the floor. The caller inserts the `media_blob` row **after** this returns, in its
     * transaction, and a file whose row never commits is an orphan the reconcile deletes.
     */
    fun write(blob: ByteArray, enforceFloor: Boolean): WriteResult {
        if (blob.size != MediaLimits.FRAGMENT_BYTES) throw CiphertextFilesException(CiphertextFilesError.BAD_SIZE, "write", null)
        if (enforceFloor && freeSpace() < freeFloorBytes) return WriteResult.BelowFloor
        val name = names.next16()
        val target = File(directory, hex(name))
        val temp = File(directory, TEMP_PREFIX + hex(names.next16()))
        try {
            fileSystem.writeNew(temp, blob)
            fileSystem.setTimes(temp, 0L, 0L)
            fileSystem.force(temp)
            fileSystem.rename(temp, target)
            fileSystem.syncDirectory(directory)
        } catch (e: IOException) {
            discard(temp)
            throw CiphertextFilesException(if (isDiskFull(e)) CiphertextFilesError.DISK_FULL else CiphertextFilesError.IO, "write", e)
        }
        return WriteResult.Written(name)
    }

    /** The blob in the file [fileName]: exactly [MediaLimits.FRAGMENT_BYTES] bytes or a typed error (a file of another length is corrupt). */
    fun read(fileName: ByteArray): ByteArray {
        val file = fileOf(fileName)
        val bytes = try {
            fileSystem.read(file)
        } catch (e: IOException) {
            throw CiphertextFilesException(CiphertextFilesError.IO, "read", e)
        }
        if (bytes.size != MediaLimits.FRAGMENT_BYTES) throw CiphertextFilesException(CiphertextFilesError.CORRUPT_LENGTH, "read", null)
        return bytes
    }

    fun exists(fileName: ByteArray): Boolean = fileSystem.exists(fileOf(fileName))

    /** Removes the file; false when there was none (deleting is idempotent: a reconcile rerun after a crash meets the files it already removed). */
    fun delete(fileName: ByteArray): Boolean = deleteNamed(hex(requireName(fileName)))

    /** [delete] for a name as listed (hex, or a leftover temp name). */
    internal fun deleteNamed(listed: String): Boolean {
        try {
            return fileSystem.delete(File(directory, listed))
        } catch (e: IOException) {
            throw CiphertextFilesException(CiphertextFilesError.IO, "delete", e)
        }
    }

    /** Every entry of the directory by name (final files are 32 hex characters, a temp file starts with `.t`), sorted. */
    fun list(): List<String> {
        try {
            return fileSystem.list(directory)
        } catch (e: IOException) {
            throw CiphertextFilesException(CiphertextFilesError.IO, "list", e)
        }
    }

    /** Syncs the directory: after a batch of deletions the removals are durable, so a reboot does not bring the files back. */
    fun syncDirectory() {
        try {
            fileSystem.syncDirectory(directory)
        } catch (e: IOException) {
            throw CiphertextFilesException(CiphertextFilesError.IO, "syncDirectory", e)
        }
    }

    /**
     * Re-applies `setTimes(0, 0)` to a file that kept real times (a crash before the call, a file written by an older
     * build, a restore): reads the times first and writes only when one is not zero. Returns whether it changed the file.
     */
    fun reapplyTimes(listed: String): Boolean {
        val file = File(directory, listed)
        try {
            val times = fileSystem.times(file)
            if (times.lastModifiedMillis == 0L && times.lastAccessMillis == 0L) return false
            fileSystem.setTimes(file, 0L, 0L)
            return true
        } catch (e: IOException) {
            throw CiphertextFilesException(CiphertextFilesError.IO, "setTimes", e)
        }
    }

    /** Free storage on the volume of the store, in bytes. */
    fun freeSpace(): Long = fileSystem.freeSpace(directory)

    private fun fileOf(fileName: ByteArray): File = File(directory, hex(requireName(fileName)))

    private fun requireName(fileName: ByteArray): ByteArray {
        if (fileName.size != NAME_BYTES) throw CiphertextFilesException(CiphertextFilesError.BAD_SIZE, "name", null)
        return fileName
    }

    /** A temp file left by a failed write is removed if it can be; the failure that matters is the write's. */
    private fun discard(temp: File) {
        try {
            fileSystem.delete(temp)
        } catch (e: IOException) {
            // The reconcile deletes an orphan temp file: nothing else can be done for it here.
            return
        }
    }

    private fun isDiskFull(e: IOException): Boolean {
        val message = e.message.orEmpty().lowercase()
        return message.contains("no space left") || message.contains("not enough space") || message.contains("disk full")
    }

    override fun toString(): String = "CiphertextFiles"

    companion object {
        /** The length of a file name in bytes (`media_blob.file_name`); its hex is the name on disk. */
        const val NAME_BYTES: Int = 16

        /** A temp file starts with this; no final name does (those are hex). */
        const val TEMP_PREFIX: String = ".t"

        /** Whether [listed] is the name of a final file (32 lower-case hex characters). */
        fun isFinalName(listed: String): Boolean = listed.length == NAME_BYTES * 2 && listed.all { it in '0'..'9' || it in 'a'..'f' }
    }
}

/** The result of [CiphertextFiles.write]. */
sealed class WriteResult {
    /** The blob is on disk, durable, under [fileName] (the 16 bytes for `media_blob.file_name`). */
    class Written(val fileName: ByteArray) : WriteResult() {
        override fun toString(): String = "Written"
    }

    /** The free storage is below the floor: the blob is consumed without a file (counted by the caller). */
    object BelowFloor : WriteResult() {
        override fun toString(): String = "BelowFloor"
    }
}

/** A failure of the file store, typed and carrying no name, path or byte (T3); the cause is kept for the stack. */
class CiphertextFilesException(val error: CiphertextFilesError, val where: String, cause: IOException?) :
    RuntimeException("${error.name} at $where", cause)

enum class CiphertextFilesError {
    /** A blob that is not [MediaLimits.FRAGMENT_BYTES] long, or a name that is not 16 bytes. */
    BAD_SIZE,

    /** A file of the store whose length is not [MediaLimits.FRAGMENT_BYTES]. */
    CORRUPT_LENGTH,

    /** The device is out of space. */
    DISK_FULL,

    /** Any other failure of the file system. */
    IO,
}

/** Where the 16 random bytes of a file name come from; the default is `SecureRandom`. */
fun interface NameSource {
    fun next16(): ByteArray
}

internal object SecureNameSource : NameSource {
    private val random = SecureRandom()
    override fun next16(): ByteArray = ByteArray(CiphertextFiles.NAME_BYTES).also { random.nextBytes(it) }
}

/** The times of a file the store looks at: `mtime` and `atime` in milliseconds since the epoch. */
class FileTimes(val lastModifiedMillis: Long, val lastAccessMillis: Long)

/**
 * The file-system operations the store uses, as a port: the real one is [NioCiphertextFileSystem], the tests wrap it with
 * one that crashes before and after each call and loses unsynced data (Phase 11 design §15.1, §15.3). Every method may
 * throw [IOException]; none reads a clock or names a network class.
 */
interface CiphertextFileSystem {
    fun makeDirectory(directory: File)

    /** The names in [directory], sorted; an empty list for an empty directory. */
    fun list(directory: File): List<String>

    fun exists(file: File): Boolean

    fun read(file: File): ByteArray

    /** Creates [file], which must not exist, and writes all of [bytes]. Not durable until [force]. */
    fun writeNew(file: File, bytes: ByteArray)

    /** Flushes the data and metadata of [file] to the device (`fsync`). */
    fun force(file: File)

    /** Sets the modification and access times of [file] (the creation time is left alone). */
    fun setTimes(file: File, lastModifiedMillis: Long, lastAccessMillis: Long)

    fun times(file: File): FileTimes

    /** Renames [from] to [to] atomically; [to] must not exist. */
    fun rename(from: File, to: File)

    /** Removes [file]; false when there was none. */
    fun delete(file: File): Boolean

    /** Flushes the entries of [directory] (the creations, renames and removals in it). */
    fun syncDirectory(directory: File)

    fun freeSpace(directory: File): Long
}

/**
 * The real port over `java.nio`. **This class holds the only calls that write a media byte** (`FileChannel` with `CREATE_NEW`,
 * `Files.move`): gate G-M1's writer allowlist names this file. A directory cannot be opened for `force` on Windows, so the
 * directory sync is skipped there ([directorySyncSupported]); Android is Linux and syncs.
 */
class NioCiphertextFileSystem(
    private val directorySyncSupported: Boolean = !System.getProperty("os.name").orEmpty().startsWith("Windows"),
) : CiphertextFileSystem {

    override fun makeDirectory(directory: File) {
        Files.createDirectories(directory.toPath())
    }

    override fun list(directory: File): List<String> =
        (directory.list() ?: throw IOException("the store directory cannot be listed")).sorted()

    override fun exists(file: File): Boolean = Files.exists(file.toPath())

    override fun read(file: File): ByteArray = Files.readAllBytes(file.toPath())

    override fun writeNew(file: File, bytes: ByteArray) {
        FileChannel.open(file.toPath(), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE).use { channel ->
            val buffer = ByteBuffer.wrap(bytes)
            while (buffer.hasRemaining()) channel.write(buffer)
        }
    }

    override fun force(file: File) {
        FileChannel.open(file.toPath(), StandardOpenOption.WRITE).use { it.force(true) }
    }

    override fun setTimes(file: File, lastModifiedMillis: Long, lastAccessMillis: Long) {
        Files.getFileAttributeView(file.toPath(), BasicFileAttributeView::class.java)
            .setTimes(FileTime.fromMillis(lastModifiedMillis), FileTime.fromMillis(lastAccessMillis), null)
    }

    override fun times(file: File): FileTimes {
        val attributes = Files.readAttributes(file.toPath(), BasicFileAttributes::class.java)
        return FileTimes(attributes.lastModifiedTime().toMillis(), attributes.lastAccessTime().toMillis())
    }

    override fun rename(from: File, to: File) {
        if (Files.exists(to.toPath())) throw FileAlreadyExistsException(to.path)
        Files.move(from.toPath(), to.toPath(), StandardCopyOption.ATOMIC_MOVE)
    }

    override fun delete(file: File): Boolean = Files.deleteIfExists(file.toPath())

    override fun syncDirectory(directory: File) {
        if (!directorySyncSupported) return
        FileChannel.open(directory.toPath(), StandardOpenOption.READ).use { it.force(true) }
    }

    override fun freeSpace(directory: File): Long = directory.usableSpace
}
