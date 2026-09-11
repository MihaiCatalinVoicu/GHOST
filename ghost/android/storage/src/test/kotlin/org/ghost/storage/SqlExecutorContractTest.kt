package org.ghost.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/** The [SqlExecutor] contract, exercised on the JVM executor shared with :sync. */
class SqlExecutorContractTest {
    private fun scratch(): JdbcSqlExecutor = JdbcSqlExecutor().also {
        it.exec("CREATE TABLE t (k INTEGER PRIMARY KEY, v INTEGER NOT NULL)")
    }

    private fun JdbcSqlExecutor.count(): Long = queryLong("SELECT count(*) FROM t")!!

    @Test
    fun execUpdateReturnsRowsChanged() {
        scratch().use { db ->
            assertEquals(1, db.execUpdate("INSERT INTO t(k, v) VALUES (?, ?)", listOf(1L, 10)))
            assertEquals(1, db.execUpdate("INSERT INTO t(k, v) VALUES (2, 10)"))
            assertEquals(1, db.execUpdate("INSERT INTO t(k, v) VALUES (3, 20)"))
            assertEquals(0, db.execUpdate("INSERT INTO t(k, v) VALUES (1, 99) ON CONFLICT(k) DO NOTHING"))
            assertEquals(1, db.execUpdate("INSERT INTO t(k, v) VALUES (1, 11) ON CONFLICT(k) DO UPDATE SET v = excluded.v"))
            assertEquals(2, db.execUpdate("UPDATE t SET v = v + 1 WHERE v >= ?", listOf(11L)))
            assertEquals(0, db.execUpdate("UPDATE t SET v = 0 WHERE k = 42"))
            assertEquals(2, db.execUpdate("DELETE FROM t WHERE k IN (1, 2)"))
            assertEquals(0, db.execUpdate("DELETE FROM t WHERE k = 1"))
            assertEquals(1L, db.count())
            // A failing statement throws and changes nothing.
            assertThrows(java.sql.SQLException::class.java) { db.execUpdate("INSERT INTO t(k, v) VALUES (3, 1)") }
            assertEquals(1L, db.count())
        }
    }

    @Test
    fun execUpdateCountsOnlyDirectChangesNotTriggersOrCascades() {
        JdbcSqlExecutor().use { db ->
            db.exec("CREATE TABLE parent (id INTEGER PRIMARY KEY)")
            db.exec("CREATE TABLE child (id INTEGER PRIMARY KEY, parent INTEGER NOT NULL REFERENCES parent(id) ON DELETE CASCADE)")
            db.exec("CREATE TABLE audit (n INTEGER)")
            db.exec("CREATE TRIGGER parent_audit AFTER DELETE ON parent BEGIN INSERT INTO audit VALUES (OLD.id); INSERT INTO audit VALUES (OLD.id); END")
            db.exec("INSERT INTO parent VALUES (1)")
            db.exec("INSERT INTO child VALUES (1, 1), (2, 1), (3, 1)")
            assertEquals(1, db.execUpdate("DELETE FROM parent WHERE id = 1"))
            assertEquals(0L, db.queryLong("SELECT count(*) FROM child"))
            assertEquals(2L, db.queryLong("SELECT count(*) FROM audit"))
        }
    }

    @Test
    fun inTransactionIsTrueOnlyInsideTheBlockOnTheCallingThread() {
        scratch().use { db ->
            assertFalse(db.inTransaction)
            val seenFromOtherThread = AtomicReference<Boolean>()
            db.transaction {
                assertTrue(db.inTransaction)
                val t = Thread { seenFromOtherThread.set(db.inTransaction) }
                t.start()
                t.join()
            }
            assertEquals(false, seenFromOtherThread.get())
            assertFalse(db.inTransaction)
            assertThrows(IllegalArgumentException::class.java) { db.transaction { throw IllegalArgumentException("boom") } }
            assertFalse(db.inTransaction)
        }
    }

    @Test
    fun transactionCommitsOnSuccessAndRollsBackOnFailure() {
        scratch().use { db ->
            assertEquals(7, db.transaction { db.exec("INSERT INTO t VALUES (1, 1)"); 7 })
            assertThrows(IllegalStateException::class.java) {
                db.transaction {
                    db.exec("INSERT INTO t VALUES (2, 2)")
                    error("abort")
                }
            }
            assertEquals(1L, db.count())
        }
    }

    @Test
    fun nestedTransactionThrowsAndNeverCommitsOuterWorkEarly() {
        scratch().use { db ->
            // The nested call fails before touching the connection; the outer work is still
            // uncommitted afterwards, so the outer rollback removes it.
            assertThrows(IllegalArgumentException::class.java) {
                db.transaction {
                    db.exec("INSERT INTO t VALUES (1, 1)")
                    val nested = assertThrows(IllegalStateException::class.java) { db.transaction { db.exec("INSERT INTO t VALUES (2, 2)") } }
                    assertTrue(nested.message!!, nested.message!!.contains("nested"))
                    assertTrue("outer transaction still open", db.inTransaction)
                    db.exec("INSERT INTO t VALUES (3, 3)")
                    throw IllegalArgumentException("outer fails after the nested attempt")
                }
            }
            assertEquals(0L, db.count())
            assertFalse(db.inTransaction)
            // When the nested failure propagates, the whole outer block rolls back.
            assertThrows(IllegalStateException::class.java) {
                db.transaction {
                    db.exec("INSERT INTO t VALUES (4, 4)")
                    db.transaction { db.exec("INSERT INTO t VALUES (5, 5)") }
                }
            }
            assertEquals(0L, db.count())
            // A caught nested failure does not prevent the outer block from committing its own work.
            db.transaction {
                db.exec("INSERT INTO t VALUES (6, 6)")
                assertThrows(IllegalStateException::class.java) { db.transaction { } }
            }
            assertEquals(1L, db.count())
        }
    }

    @Test
    fun aTransactionThatCannotStartLeavesNoTransactionFlag() {
        val db = scratch()
        db.close()
        // setAutoCommit fails on the closed connection; the thread must not stay "in a transaction",
        // or every later call would report a nested transaction instead of the real failure.
        repeat(2) {
            assertThrows(java.sql.SQLException::class.java) { db.transaction { } }
            assertFalse(db.inTransaction)
        }
    }

    @Test
    fun transactionsOfTwoThreadsNeverInterleave() {
        scratch().use { db ->
            db.exec("CREATE TABLE counter (id INTEGER PRIMARY KEY CHECK (id = 1), n INTEGER NOT NULL)")
            db.exec("CREATE TABLE seen (n INTEGER PRIMARY KEY, thread INTEGER NOT NULL)")
            db.exec("INSERT INTO counter VALUES (1, 0)")
            val perThread = 300
            val errors = Collections.synchronizedList(ArrayList<Throwable>())
            val start = CountDownLatch(1)
            val threads = (1..2).map { id ->
                Thread {
                    try {
                        start.await()
                        repeat(perThread) {
                            // Read-modify-write: an interleaving would read a stale value and hit
                            // the primary key of `seen`, or commit the other thread's half.
                            db.transaction {
                                val n = db.queryLong("SELECT n FROM counter")!!
                                db.exec("INSERT INTO seen(n, thread) VALUES (?, ?)", listOf(n, id))
                                Thread.yield()
                                assertEquals(1, db.execUpdate("UPDATE counter SET n = ? WHERE n = ?", listOf(n + 1, n)))
                            }
                        }
                    } catch (t: Throwable) {
                        errors += t
                    }
                }.also { it.start() }
            }
            start.countDown()
            threads.forEach { it.join(TimeUnit.SECONDS.toMillis(60)) }
            assertTrue("errors: $errors", errors.isEmpty())
            assertEquals(2L * perThread, db.queryLong("SELECT n FROM counter"))
            assertEquals(2L * perThread, db.queryLong("SELECT count(*) FROM seen"))
            assertEquals(2L * perThread - 1, db.queryLong("SELECT max(n) FROM seen"))
        }
    }

    @Test
    fun anotherThreadsStatementWaitsAndIsNotRolledBackWithTheTransaction() {
        scratch().use { db ->
            val inside = CountDownLatch(1)
            val otherError = AtomicReference<Throwable?>()
            val other = Thread {
                try {
                    inside.await()
                    db.exec("INSERT INTO t VALUES (2, 2)")
                } catch (t: Throwable) {
                    otherError.set(t)
                }
            }
            other.start()
            assertThrows(IllegalStateException::class.java) {
                db.transaction {
                    db.exec("INSERT INTO t VALUES (1, 1)")
                    inside.countDown()
                    val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30)
                    while (db.waitingThreads == 0) {
                        check(System.nanoTime() < deadline) { "the other thread never queued" }
                        Thread.yield()
                    }
                    // The other thread is blocked on the executor, not running inside this transaction.
                    assertNull(db.queryLong("SELECT v FROM t WHERE k = 2"))
                    error("roll back")
                }
            }
            other.join(TimeUnit.SECONDS.toMillis(30))
            assertNull(otherError.get())
            assertNull(db.queryLong("SELECT v FROM t WHERE k = 1"))
            assertEquals(2L, db.queryLong("SELECT v FROM t WHERE k = 2"))
        }
    }

    @Test
    fun fileDatabaseSurvivesReopenLikeAProcessRestart() {
        val file = File.createTempFile("ghost-storage", ".db")
        try {
            JdbcSqlExecutor(file.absolutePath).use { db ->
                MigrationRunner(db).migrate()
                db.exec("INSERT INTO invite_nonces(nonce, seen_at) VALUES (?, 1)", listOf(ByteArray(16)))
            }
            JdbcSqlExecutor(file.absolutePath).use { db ->
                assertEquals(emptyList<Int>(), MigrationRunner(db).migrate())
                MigrationRunner(db).verifyIntegrity()
                assertEquals(1L, db.queryLong("SELECT count(*) FROM invite_nonces"))
            }
        } finally {
            file.delete()
        }
    }
}
