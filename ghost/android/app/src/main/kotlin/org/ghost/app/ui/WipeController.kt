package org.ghost.app.ui

import java.io.File

/**
 * Phase 13 design §5.5: the local wipe, crypto-shred first, over an abstract file system so the
 * crash enumeration (CS-U1, MC-U3, MC-U4) runs on the JVM with an in-memory tree.
 *
 * Steps (the UI's W1 — read, re-enter the PIN, HoldToConfirm — precedes this controller):
 *  - W2: [stopStacks] — GhostApp.onWipe's engine stops, NEVER on the main thread (the caller
 *    runs this controller on the `ghost-wipe` thread).
 *  - W3: [deleteEnvelopes] — the database-key and identity envelopes: from here no envelope
 *    file names the keys.
 *  - W4: [deleteKeystoreAliases] — every GHOST Keystore alias (the database/secret wrap, the two
 *    DM keys, Phase 10's MLS state key, `ghost.v1.pin-mac`, the crash key): THIS is the
 *    crypto-shred — a surviving envelope cannot be unwrapped without its key, provided the
 *    Keystore deletes with rollback resistance (V-U29 reads the property on the test phones).
 *  - W5: [files] — `ghost.db` with `-wal`, `-shm`, `-journal`; all of `noBackupFilesDir`
 *    (`secrets/`, Arti state `tor/`, Phase 11's `m/`, Phase 14's `update/`, `crash/`); the
 *    CONTENTS of `filesDir` and `cacheDir` (the directories themselves survive).
 *  - W6: [cancelNotifications], [clearClipboard] unconditionally.
 *  - W7: [exitProcess] — `finishAndRemoveTask()` then process exit; the next launch is a fresh
 *    onboarding.
 *
 * **Resumption (CS-U1):** in `GhostApp.onCreate`, before any wiring, if the database-key envelope
 * is missing but `ghost.db`, its WAL or any GHOST file beyond a fresh install's baseline exists,
 * W4–W6 run silently first. A crash before W3 leaves an intact app; any crash after W3 is
 * completed at the next start. [residue] returns exactly that predicate's evidence.
 */
class WipeController(
    private val files: Filesystem,
    private val stopStacks: () -> Unit,
    private val deleteEnvelopes: () -> Unit,
    private val deleteKeystoreAliases: () -> Unit,
    private val cancelNotifications: () -> Unit,
    private val clearClipboard: () -> Unit,
    private val exitProcess: () -> Unit,
) {
    /** The abstract file system: [File] paths as strings, directories' contents listed. */
    interface Filesystem {
        fun exists(path: String): Boolean
        fun delete(path: String): Boolean
        fun isDirectory(path: String): Boolean
        /** Every file (recursively) under [path], paths relative to [path], in a stable order. */
        fun listRecursively(path: String): List<String>
    }

    /** W2–W7 in order; a wipe never returns. */
    fun wipe() {
        stopStacks()
        deleteEnvelopes()
        deleteKeystoreAliases()
        deleteFiles()
        cancelNotifications()
        clearClipboard()
        exitProcess()
    }

    /** W6 alone: the resumption tail after W5 (CS-U1 runs W4–W6, never W3). */
    fun resumptionCleanups() {
        cancelNotifications()
        clearClipboard()
    }

    /** W5 alone (the resumption path runs W4–W6, never W3's envelopes again). */
    fun deleteFiles() {
        files.delete(DATABASE_WAL)
        files.delete(DATABASE_SHM)
        files.delete(DATABASE_JOURNAL)
        files.delete(DATABASE)
        deleteDirectoryContents(NO_BACKUP)
        deleteDirectoryContents(FILES)
        deleteDirectoryContents(CACHE)
    }

    /** The CS-U1 resumption predicate: no key envelope, but data beyond a fresh install. */
    fun needsResumption(): Boolean =
        !files.exists(KEY_ENVELOPE) && (
            files.exists(DATABASE) || files.exists(DATABASE_WAL) ||
                files.listRecursively(NO_BACKUP).isNotEmpty() ||
                files.listRecursively(FILES).isNotEmpty()
            )

    private fun deleteDirectoryContents(dir: String) {
        if (!files.isDirectory(dir)) return
        for (entry in files.listRecursively(dir)) {
            files.delete("$dir/$entry")
        }
    }

    companion object {
        const val DATABASE = "databases/ghost.db"
        const val DATABASE_WAL = "databases/ghost.db-wal"
        const val DATABASE_SHM = "databases/ghost.db-shm"
        const val DATABASE_JOURNAL = "databases/ghost.db-journal"
        const val NO_BACKUP = "no_backup"
        const val FILES = "files"
        const val CACHE = "cache"
        const val KEY_ENVELOPE = "no_backup/secrets/db-key.v1"
    }
}

/** The production [WipeController.Filesystem] over a Context's sandbox. */
class ContextFilesystem(private val root: File) : WipeController.Filesystem {
    override fun exists(path: String): Boolean = File(root, path).exists()

    override fun delete(path: String): Boolean {
        val f = File(root, path)
        return !f.exists() || f.delete()
    }

    override fun isDirectory(path: String): Boolean = File(root, path).isDirectory

    override fun listRecursively(path: String): List<String> {
        val base = File(root, path)
        if (!base.isDirectory) return emptyList()
        val out = ArrayList<String>()
        base.walkTopDown().filter { it.isFile }.forEach { out.add(it.relativeTo(base).path.replace('\\', '/')) }
        return out.sorted()
    }
}
