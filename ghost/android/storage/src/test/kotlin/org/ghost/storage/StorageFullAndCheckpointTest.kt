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

    /**
     * §10.7's "retry 3 times 100 ms apart", which nothing asserted before the S9 review: the
     * success path takes the first attempt and never pauses, so lowering [Checkpoint.ATTEMPTS] to
     * 1 or [Checkpoint.PAUSE_MILLIS] to 0 left the whole suite green.
     *
     * The busy path is driven here by a stub, because the answer being pinned is the **shape of
     * the retry** — how many attempts, how long between them, and that the last attempt is not
     * followed by a pointless pause. That a real reader holding the log really produces `busy = 1`
     * is `GcCheckpointDebtTest`'s, over two connections; that the debt is then kept and retried is
     * `SweepTest`'s.
     */
    @Test
    fun aBusyLogIsRetriedThreeTimesOneHundredMillisecondsApart() {
        val busy = BusyExecutor()
        val pauses = ArrayList<Long>()
        assertFalse("a log held through every attempt answers false", Checkpoint.truncate(busy) { pauses += it })
        assertEquals("three attempts, the first included", 3, busy.attempts)
        assertEquals("two pauses: none after the last attempt", listOf(100L, 100L), pauses)
        assertEquals(3, Checkpoint.ATTEMPTS)
        assertEquals(100L, Checkpoint.PAUSE_MILLIS)
    }

    /** A connection whose `wal_checkpoint` always answers `busy = 1`, and counts the asking. */
    private class BusyExecutor : SqlExecutor {
        var attempts = 0

        override fun query(sql: String, args: List<Any?>, onRow: (SqlExecutor.Row) -> Unit) {
            check(sql == "PRAGMA wal_checkpoint(TRUNCATE)") { "unexpected query: $sql" }
            attempts += 1
            onRow(BusyRow)
        }

        override fun exec(sql: String, args: List<Any?>) = throw UnsupportedOperationException()
        override fun execUpdate(sql: String, args: List<Any?>): Int = throw UnsupportedOperationException()
        override fun <T> transaction(block: () -> T): T = throw UnsupportedOperationException()
        override val inTransaction: Boolean get() = false
        override var userVersion: Int
            get() = 0
            set(_) = throw UnsupportedOperationException()
    }

    /** `(busy, log, checkpointed)` with `busy = 1`. */
    private object BusyRow : SqlExecutor.Row {
        override fun isNull(index: Int): Boolean = false
        override fun long(index: Int): Long = if (index == 0) 1L else 0L
        override fun string(index: Int): String = throw UnsupportedOperationException()
        override fun blob(index: Int): ByteArray = throw UnsupportedOperationException()
    }
}
