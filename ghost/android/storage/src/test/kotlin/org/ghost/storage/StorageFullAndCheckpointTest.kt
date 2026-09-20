package org.ghost.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files

/**
 * `SQLITE_FULL` as a typed outcome and the checked WAL checkpoint (Phase 9 design §13.1, §10.7,
 * §21.12 point 1): a database that cannot grow raises [StorageFullException] instead of the
 * driver's own exception, the transaction it happened in rolls back, and
 * [Checkpoint.truncate] reports whether the log was really truncated.
 */
class StorageFullAndCheckpointTest {

    private fun file(): String = Files.createTempDirectory("ghost-storage-full").resolve("full.db").toString()

    /** A distinct 16-byte nonce per row, so a full database is the only reason an insert can fail. */
    private fun nonce(i: Int): ByteArray = ByteArray(16).also { java.nio.ByteBuffer.wrap(it).putInt(i) }

    @Test
    fun aFullDatabaseRaisesTheTypedExceptionOnEveryWritingPath() {
        JdbcSqlExecutor(file()).use { db ->
            MigrationRunner(db).migrate()
            db.exec("INSERT INTO invite_nonces(nonce, seen_at) VALUES (?, 1)", listOf(nonce(1)))
            val pages = db.queryLong("PRAGMA page_count")!!
            // The database may not grow past what it already uses: a write that needs a page is
            // SQLITE_FULL, which both executors raise as StorageFullException (§13.1).
            db.query("PRAGMA max_page_count = $pages") { }
            assertEquals(pages, db.queryLong("PRAGMA max_page_count"))
            var written = 0
            val full = assertThrows(StorageFullException::class.java) {
                for (i in 2..20_000) {
                    db.exec("INSERT INTO invite_nonces(nonce, seen_at) VALUES (?, ?)", listOf(nonce(i), i.toLong()))
                    written++
                }
            }
            assertTrue("the limit was reached, not the loop", written < 19_999)
            assertEquals("the local database is full", full.message)
            assertNotNull(full.cause)
            assertTrue(StorageFull.matches(checkNotNull(full.cause)))
            assertFalse(db.inTransaction)
            // The guarded path (execUpdate) maps it too, and nothing else was swallowed.
            assertThrows(StorageFullException::class.java) {
                db.execUpdate("INSERT INTO invite_nonces(nonce, seen_at) VALUES (?, 1)", listOf(nonce(20_001)))
            }
            assertThrows(java.sql.SQLException::class.java) {
                db.execUpdate("INSERT INTO invite_nonces(nonce, seen_at) VALUES (?, 1)", listOf(nonce(1)))
            }
            // The database works again once there is room.
            db.query("PRAGMA max_page_count = 1073741823") { }
            db.exec("INSERT INTO invite_nonces(nonce, seen_at) VALUES (?, 2)", listOf(nonce(20_002)))
            assertEquals((written + 2).toLong(), db.queryLong("SELECT count(*) FROM invite_nonces"))
        }
    }

    /** Both drivers name `SQLITE_FULL` differently; every form is recognised, and nothing else is. */
    @Test
    fun theRecognitionCoversBothDriversAndNothingElse() {
        class SQLiteFullException(message: String) : RuntimeException(message)
        assertTrue(StorageFull.matches(SQLiteFullException("disk I/O")))
        assertTrue(StorageFull.matches(IllegalStateException("[SQLITE_FULL] Insertion failed")))
        assertTrue(StorageFull.matches(IllegalStateException("database or disk is full")))
        assertTrue("the cause chain is walked", StorageFull.matches(IllegalStateException("wrapper", SQLiteFullException("inner"))))
        assertFalse(StorageFull.matches(IllegalStateException("CHECK constraint failed")))
        assertFalse(StorageFull.matches(IllegalStateException(null as String?)))
        // A cycle in the cause chain is bounded, never a hang.
        val a = IllegalStateException("a")
        assertFalse(StorageFull.matches(IllegalStateException("b", a)))
    }

    @Test
    fun theCheckpointTruncatesTheLogAndReportsWhetherItRan() {
        JdbcSqlExecutor(file()).use { db ->
            MigrationRunner(db).migrate()
            db.query("PRAGMA journal_mode = WAL") { }
            db.exec("INSERT INTO invite_nonces(nonce, seen_at) VALUES (?, 1)", listOf(ByteArray(16) { 1 }))
            val pauses = ArrayList<Long>()
            assertTrue(Checkpoint.truncate(db) { pauses += it })
            assertEquals("no retry was needed", emptyList<Long>(), pauses)
            assertEquals(0L, db.queryLong("PRAGMA wal_checkpoint(TRUNCATE)"))
            // Inside a transaction the checkpoint is a bug, not a busy answer.
            assertThrows(IllegalStateException::class.java) { db.transaction { Checkpoint.truncate(db) } }
        }
    }
}
