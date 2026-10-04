package org.ghost.media.store

import java.io.File

/**
 * A process death at a kill point of the file store (Phase 11 design §15.3). An [Error], like the sync layer's injected
 * crashes, so that no catch-all swallows it and it reaches the test that armed it.
 */
class InjectedCrash(val point: Int, val operation: String) : Error("injected crash at kill point $point ($operation)")

/**
 * A fault-injecting [CiphertextFileSystem] over a real one (Phase 11 design §15.1: "a `CiphertextFiles` port on a real
 * temporary directory with a fault-injecting wrapper"; §15.3: "crashes ... at every `CiphertextFiles` call (before and after
 * `write`, `force`, `setTimes`, directory sync, `delete`, `list`), reboots ... File faults include 'an unsynced write is lost'
 * at the reboot, which is what a power loss does").
 *
 * **Kill points.** Every call of the port is two points: point `2k` is before the `k`-th call (nothing of it happened) and
 * `2k + 1` is after it (all of it happened). [arm] picks one; reaching it throws [InjectedCrash]. A run that is not armed
 * counts its points in [points], which is how a test enumerates them all.
 *
 * **What a reboot loses** ([reboot]; the model of a journalling file system after a power cut, kept deliberately
 * pessimistic):
 *  - the bytes of a file written and **not forced** are gone: the file is there, empty (what delayed allocation leaves);
 *  - the directory entries changed since the last **directory sync** revert: a created file vanishes, a renamed one
 *    returns to its old name (the new name is gone), a deleted one comes back with its bytes.
 * So a write that is renamed without a force leaves an empty file under its final name, and a rename without a directory
 * sync leaves no file under it at all: exactly the two orders [CiphertextFiles] is written to avoid, which the mutants
 * ([skipForce], [skipDirectorySync]) put back so that the tests can see the model catch them.
 */
internal class CrashableFileSystem(private val real: CiphertextFileSystem) : CiphertextFileSystem {

    private var armedAt = -1
    private var counter = 0

    /** The calls made, in order, with the kind of each (for a reader of a failure). */
    val trace = ArrayList<String>()

    /** Mutants: a `force` or a directory sync that does nothing (the model still loses what they should have kept). */
    var skipForce = false
    var skipDirectorySync = false

    /** Kill points counted since the last [reset]: twice the number of calls. */
    val points: Int get() = counter

    // The durability model.
    private val unforced = LinkedHashSet<File>()

    private sealed class Entry {
        class Created(val file: File) : Entry()
        class Renamed(val from: File, val to: File) : Entry()
        class Deleted(val file: File, val shadow: ByteArray?) : Entry()
    }

    private val pending = ArrayList<Entry>()

    /** Arms kill point [point]; the call that reaches it throws. */
    fun arm(point: Int) {
        armedAt = point
    }

    /** Forgets the counter, the trace and any armed point (not the model's pending losses: [reboot] settles those). */
    fun reset() {
        counter = 0
        armedAt = -1
        trace.clear()
    }

    private fun hit(label: String) {
        val here = counter++
        if (here == armedAt) throw InjectedCrash(here, label)
    }

    private inline fun <T> op(name: String, block: () -> T): T {
        trace += name
        hit("before $name")
        val result = block()
        hit("after $name")
        return result
    }

    /** A power cut: loses the unforced data and reverts the unsynced directory entries (see the class comment), then resets. */
    fun reboot() {
        for (file in unforced) if (file.exists()) file.writeBytes(ByteArray(0))
        for (entry in pending.asReversed()) {
            when (entry) {
                is Entry.Renamed -> if (entry.to.exists()) entry.to.renameTo(entry.from)
                is Entry.Created -> entry.file.delete()
                is Entry.Deleted -> if (!entry.file.exists()) entry.file.writeBytes(entry.shadow ?: ByteArray(0))
            }
        }
        unforced.clear()
        pending.clear()
        reset()
    }

    // ---------------------------------------------------------------- the port

    override fun makeDirectory(directory: File) = real.makeDirectory(directory)

    override fun list(directory: File): List<String> = op("list") { real.list(directory) }

    override fun exists(file: File): Boolean = real.exists(file)

    override fun read(file: File): ByteArray = real.read(file)

    override fun writeNew(file: File, bytes: ByteArray) = op("write") {
        real.writeNew(file, bytes)
        unforced += file
        pending += Entry.Created(file)
    }

    override fun force(file: File) = op("force") {
        if (!skipForce) {
            real.force(file)
            unforced -= file
        }
    }

    override fun setTimes(file: File, lastModifiedMillis: Long, lastAccessMillis: Long) = op("setTimes") {
        real.setTimes(file, lastModifiedMillis, lastAccessMillis)
    }

    override fun times(file: File): FileTimes = real.times(file)

    override fun rename(from: File, to: File) = op("rename") {
        real.rename(from, to)
        if (from in unforced) {
            unforced -= from
            unforced += to
        }
        pending += Entry.Renamed(from, to)
    }

    override fun delete(file: File): Boolean = op("delete") {
        val shadow = if (real.exists(file)) real.read(file) else null
        val existed = real.delete(file)
        if (existed) {
            pending += Entry.Deleted(file, if (file in unforced) null else shadow)
            unforced -= file
        }
        existed
    }

    override fun syncDirectory(directory: File) = op("syncDirectory") {
        if (!skipDirectorySync) pending.clear()
        real.syncDirectory(directory)
    }

    override fun freeSpace(directory: File): Long = real.freeSpace(directory)
}
