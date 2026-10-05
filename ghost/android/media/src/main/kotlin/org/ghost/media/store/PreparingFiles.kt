package org.ghost.media.store

import java.util.concurrent.ConcurrentHashMap

/**
 * The `preparing` set of Phase 11 design §6.2 and §10.4: the names of the files a sealer is writing for an object that
 * `MEDIA-COMMIT` has not referenced yet, which a concurrent [MediaReconcile] must keep.
 *
 * **The protocol is the whole point, and its order is the argument.** A name is
 *  1. **reserved** ([reserve]) **before** any file of that name exists — the temp file `.t<hex>` and the final file `<hex>` are
 *     both covered by the one reservation ([CiphertextFiles.write]);
 *  2. written ([CiphertextFiles.write]);
 *  3. committed (`MEDIA-COMMIT` inserts the `media_blob` row, on the DM actor);
 *  4. **released** ([release]) only **after** that commit — or, when the preparation is abandoned (an abort, a sandbox or a
 *     Transformer error, the user leaving), when the sealer gives the file up; the next reconcile then deletes the orphan.
 *
 * The reconcile lists the directory, then takes [snapshot], then reads the rows. A file in the listing was created after its
 * name was reserved (step 1 precedes step 2), so the name was in the set when the listing was taken; it left the set only after
 * its row committed (step 4 follows step 3) or because it was abandoned. So it is in the snapshot, or in the rows, or in both —
 * never in neither — and a file created after the listing is not in the listing. The design said this and the first version of
 * the store broke step 1 (the name was generated inside `write` and returned after it), which the adversarial review of this
 * slice demonstrated (§22.4 row 25); the tests enumerate a reconcile at every file operation of a write.
 *
 * Thread-safe: the media worker reserves and releases, the media actor takes snapshots. The set holds random names and nothing
 * else (T3: no `toString` shows one).
 */
class PreparingFiles {
    private val names: MutableSet<String> = ConcurrentHashMap.newKeySet()

    /** A fresh name from [files], registered before the caller can create any file of it. */
    fun reserve(files: CiphertextFiles): ByteArray {
        val name = files.newName()
        names += hex(name)
        return name
    }

    /** Drops [name] from the set: after the `MEDIA-COMMIT` that references its file, or when the preparation is given up. */
    fun release(name: ByteArray) {
        names -= hex(name)
    }

    /** The reserved names as listed on disk (32 lower-case hex characters): what [MediaReconcile.run] takes as `preparing`. */
    fun snapshot(): Set<String> = HashSet(names)

    /** Whether any name is reserved (the sealer's teardown asserts it released everything). */
    val isEmpty: Boolean get() = names.isEmpty()

    override fun toString(): String = "PreparingFiles"
}
