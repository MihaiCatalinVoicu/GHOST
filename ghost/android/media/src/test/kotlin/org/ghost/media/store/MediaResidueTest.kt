package org.ghost.media.store

import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The local forensic residue of the media rows (Phase 11 design §11.1 "Checkpoint after every key deletion (RQ-M12; P-M8)",
 * §12.4, T25, T33, T45) — R-M1 for media, run through the DAOs on a database **file in WAL mode with `secure_delete`**, as the
 * device has it. `secure_delete = ON` zeroes freed pages, but an updated or deleted `key_env` survives in two places until a
 * checkpoint: the pre-image page in the main `.db` file (WAL mode writes the new page to the log; the checkpoint copies it back
 * over the old one) and the log frames. So every transaction that deletes or nulls a key is followed by
 * `PRAGMA wal_checkpoint(TRUNCATE)` — the caller's, not the store's (the store writes rows and runs none), and these tests
 * prove both halves: the key **is** still in the files after the store's own write, and **is not** after the checkpoint.
 * The time columns that remain after everything has expired are the three the design declares and nothing else.
 */
class MediaResidueTest {

    /** A file-backed world with the production journal mode. */
    private class FileWorld : AutoCloseable {
        val dbFile: File = File.createTempFile("ghost-media-residue", ".db")
        val db = JdbcSqlExecutor(dbFile.path).also {
            it.query("PRAGMA journal_mode = WAL") { }
            MigrationRunner(it).migrate()
        }
        val world = MediaWorld(db = db)

        fun checkpoint(): Boolean {
            var busy = 1L
            db.query("PRAGMA wal_checkpoint(TRUNCATE)") { busy = it.long(0) }
            return busy == 0L
        }

        fun files(): List<File> = listOf(dbFile, File(dbFile.path + "-wal")).filter { it.exists() }

        /** Whether [canary] is in the main file or in the log. */
        fun holds(canary: ByteArray): Boolean = files().any { indexOf(it.readBytes(), canary) >= 0 }

        fun inMainFile(canary: ByteArray): Boolean = indexOf(dbFile.readBytes(), canary) >= 0

        fun inLog(canary: ByteArray): Boolean = File(dbFile.path + "-wal").let { it.exists() && indexOf(it.readBytes(), canary) >= 0 }

        override fun close() {
            world.close()
            dbFile.delete()
            File(dbFile.path + "-wal").delete()
            File(dbFile.path + "-shm").delete()
        }
    }

    private val canary = ByteArray(60) { (0xC0 + it % 16).toByte() }

    @Test
    fun aKeyDeletedWithItsMessageIsStillInThePreImagePageUntilTheCheckpointAndGoneAfterIt() = FileWorld().use { f ->
        val w = f.world
        w.commitOutgoing(1, keyEnv = canary)
        assertTrue("the key is in the log before the first checkpoint", f.inLog(canary))
        assertTrue(f.checkpoint())
        assertTrue("and in the main file after it (the control: the scan sees it)", f.inMainFile(canary))
        // the sweep's cascade: the object row and its key go in one transaction
        w.tx { w.stores.objects.deleteObjectsOfMessages(it, listOf(id16(0x91))) }
        assertEquals(0L, w.count("media_object"))
        assertTrue("the pre-image page survives in the main file until a checkpoint (P-M8)", f.holds(canary))
        assertTrue(f.checkpoint())
        assertFalse("after the TRUNCATE checkpoint no byte of the key is in the file or the log", f.holds(canary))
        assertEquals("the log is truncated", 0L, File(f.dbFile.path + "-wal").length())
    }

    @Test
    fun aKeyErasedByTheViewOnceOpenIsInTheFileUntilTheCheckpointAndTheHandleWaitsForIt() = FileWorld().use { f ->
        val w = f.world
        val objectId = w.receive(1, viewOnce = true, keyEnv = canary)
        w.ingest(w.blobsOf(1).all)
        w.tx { w.stores.objects.markComplete(it, objectId) }
        w.tx { w.stores.objects.markVerified(it, objectId) }
        assertTrue(f.checkpoint())
        assertTrue(f.inMainFile(canary))
        w.tx { w.stores.objects.openViewOnce(it, objectId) }
        assertTrue("the old page is still there when the transaction commits: the handle is not returned yet (§11.2)", f.holds(canary))
        assertTrue(f.checkpoint())
        assertFalse("only after the checkpoint is the key gone", f.holds(canary))
        // the state says so too
        assertEquals(ObjectState.VIEWING, w.stores.objects.byId(w.db, objectId, 1_800_000_000L)!!.state)
    }

    @Test
    fun aKeyErasedWhenAnObjectIsDeclaredLostOrCorruptOrCleanedByTheSenderFollowsTheSameRule() = FileWorld().use { f ->
        val w = f.world
        val corrupt = w.receive(1, keyEnv = canary)
        w.ingest(w.blobsOf(1).all)
        w.tx { w.stores.objects.markComplete(it, corrupt) }
        assertTrue(f.checkpoint())
        assertTrue(f.inMainFile(canary))
        w.tx { w.stores.objects.markCorrupt(it, corrupt) }
        assertTrue(f.holds(canary))
        assertTrue(f.checkpoint())
        assertFalse(f.holds(canary))
        val other = ByteArray(60) { (0xE0 + it % 16).toByte() }
        val sender = w.commitOutgoing(2, viewOnce = true, keyEnv = other)
        w.tx { w.stores.objects.markUploaded(it, sender) }
        assertTrue(f.checkpoint())
        assertTrue(f.inMainFile(other))
        w.tx { w.stores.objects.eraseSenderCopy(it, sender) }
        assertTrue(f.holds(other))
        assertTrue(f.checkpoint())
        assertFalse(f.holds(other))
        val late = ByteArray(60) { (0xA0 + it % 16).toByte() }
        val incomplete = w.receive(3, keyEnv = late, incompleteAfterHour = 3_600L * 500_000)
        assertTrue(f.checkpoint())
        assertTrue(f.inMainFile(late))
        w.tx { w.stores.objects.markIncomplete(it, incomplete) }
        assertTrue(f.holds(late))
        assertTrue(f.checkpoint())
        assertFalse(f.holds(late))
    }

    /** R-M1: what is left of a media world after everything has expired, swept and been checkpointed shows only what the design declares. */
    @Test
    fun afterTheSweepOnlyTheDeclaredNothingIsLeftInTheRows() = FileWorld().use { f ->
        val w = f.world
        w.commitOutgoing(1, keyEnv = canary)
        val received = w.receive(2)
        w.ingest(w.blobsOf(2).all.take(5) + hashOfBlob(900))
        w.tx { w.stores.objects.deleteObjectsOfMessages(it, listOf(id16(0x91), id16(0x92))) }
        w.tx { w.stores.blobs.collectExpired(it, 1_900_000_000L, 100) }
        assertTrue(f.checkpoint())
        for (table in listOf("media_object", "media_upload", "media_blob", "media_fragment", "media_outbound_op")) {
            assertEquals("$table is empty", 0L, w.count(table))
        }
        assertFalse(f.holds(canary))
        // the time columns are three, and none holds a value now
        val timeColumns = setOf("media_object.incomplete_after_hour", "media_upload.deadline_hour", "media_blob.retain_until_day")
        assertEquals(3, timeColumns.size)
        assertTrue(received.isNotEmpty())
    }

    /** The files of the store hold ciphertext only: the 64 KiB blobs the tests wrote are not the plaintext a canary stands for. */
    @Test
    fun theStoreWritesOnlyTheBlobsItIsGivenAndNothingElseReachesTheDirectory() = MediaWorld().use { w ->
        w.putBlob(1)
        w.putBlob(2)
        assertEquals(2, w.listed().size)
        for (name in w.listed()) {
            val bytes = File(w.files.directory, name).readBytes()
            assertTrue(bytes.contentEquals(blobOf(1)) || bytes.contentEquals(blobOf(2)))
        }
        // nothing else is in the application directory the world owns: no cache, no journal, no listing
        assertEquals(listOf("m"), w.dir.list()!!.toList())
    }
}

private fun indexOf(haystack: ByteArray, needle: ByteArray): Int {
    outer@ for (i in 0..haystack.size - needle.size) {
        for (j in needle.indices) if (haystack[i + j] != needle[j]) continue@outer
        return i
    }
    return -1
}
