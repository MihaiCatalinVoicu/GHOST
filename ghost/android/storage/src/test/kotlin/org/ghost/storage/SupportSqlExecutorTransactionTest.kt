package org.ghost.storage

import androidx.sqlite.db.SupportSQLiteDatabase
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.lang.reflect.Proxy

/**
 * The device executor's transaction frame (Phase 9 design §13.1, §21.12 point 1). On the device the
 * COMMIT is issued by `endTransaction`, not by `setTransactionSuccessful`, so a commit that runs out
 * of space must be mapped to [StorageFullException] like any statement: a RECV or BUNDLE transaction
 * that fails on a full disk has to reach its caller as the typed outcome, not as the driver's own
 * exception. A failure already in flight keeps its place and the rollback's own failure is attached
 * to it, exactly as the JVM double does.
 */
class SupportSqlExecutorTransactionTest {

    /** What the driver raises for `SQLITE_FULL`: SQLCipher repackages the platform's exception. */
    private class SQLiteFullException(message: String) : RuntimeException(message)

    /**
     * The driver's transaction frame: `endTransaction` runs the COMMIT (when the frame was marked
     * successful) or the ROLLBACK, and pops the frame before running it, whether or not the
     * statement fails (`SQLiteSession.endTransactionUnchecked`). Any other use of the database
     * fails the test.
     */
    private class Frame {
        val calls = ArrayList<String>()
        var open = false
        var successful = false
        var commitFailure: RuntimeException? = null
        var rollbackFailure: RuntimeException? = null

        val db: SupportSQLiteDatabase = Proxy.newProxyInstance(
            SupportSQLiteDatabase::class.java.classLoader, arrayOf(SupportSQLiteDatabase::class.java),
        ) { _, method, _ ->
            calls += method.name
            when (method.name) {
                "inTransaction" -> open
                "beginTransaction" -> { open = true; successful = false; null }
                "setTransactionSuccessful" -> { successful = true; null }
                "endTransaction" -> {
                    open = false
                    val failure = if (successful) commitFailure else rollbackFailure
                    if (failure != null) throw failure
                    null
                }
                else -> throw UnsupportedOperationException(method.name)
            }
        } as SupportSQLiteDatabase

        fun ended(): Int = calls.count { it == "endTransaction" }
    }

    @Test
    fun aCommitThatRunsOutOfSpaceRaisesTheTypedException() {
        val frame = Frame()
        val driverFailure = SQLiteFullException("database or disk is full (code 13 SQLITE_FULL)")
        frame.commitFailure = driverFailure
        val db = SupportSqlExecutor(frame.db)
        val full = assertThrows(StorageFullException::class.java) { db.transaction { "written" } }
        assertSame(driverFailure, full.cause)
        assertArrayEquals(emptyArray<Throwable>(), full.suppressed)
        // The work ran, the frame was marked successful, and the failing commit ended it exactly once.
        assertEquals(listOf("inTransaction", "beginTransaction", "setTransactionSuccessful", "endTransaction"), frame.calls.take(4))
        assertEquals(1, frame.ended())
        assertFalse(frame.open)
        // The executor is usable again: the driver popped the frame with the failing commit.
        frame.commitFailure = null
        assertEquals("next", db.transaction { "next" })
        assertEquals(2, frame.ended())
    }

    @Test
    fun aFailureInsideTheBlockKeepsItsPlaceAndCarriesAFailedRollback() {
        val frame = Frame()
        val rollbackFailure = SQLiteFullException("database or disk is full")
        frame.rollbackFailure = rollbackFailure
        val db = SupportSqlExecutor(frame.db)
        val boom = IllegalStateException("the block failed")
        val seen = assertThrows(IllegalStateException::class.java) { db.transaction<Unit> { throw boom } }
        assertSame("the first failure reaches the caller", boom, seen)
        assertArrayEquals(arrayOf<Throwable>(rollbackFailure), seen.suppressed)
        assertEquals("the frame was rolled back, never committed", listOf("inTransaction", "beginTransaction", "inTransaction", "endTransaction"), frame.calls)
        assertFalse(frame.open)
    }

    @Test
    fun aStatementThatRunsOutOfSpaceInsideTheBlockRollsBackAsTheTypedException() {
        val frame = Frame()
        val db = SupportSqlExecutor(frame.db)
        // A cursor's own failure reaches the block unwrapped (`query` maps nothing).
        val driverFailure = SQLiteFullException("database or disk is full")
        val full = assertThrows(StorageFullException::class.java) {
            db.transaction<Unit> { throw driverFailure }
        }
        assertSame(driverFailure, full.cause)
        assertArrayEquals(emptyArray<Throwable>(), full.suppressed)
        assertEquals(1, frame.ended())
        assertFalse(frame.open)
    }

    @Test
    fun anErrorReachesTheCallerUnchangedAndStillEndsTheFrame() {
        val frame = Frame()
        val db = SupportSqlExecutor(frame.db)
        val death = AssertionError("injected process death")
        val seen = assertThrows(AssertionError::class.java) { db.transaction<Unit> { throw death } }
        assertSame("crash fidelity: an Error is never wrapped", death, seen)
        assertEquals(1, frame.ended())
        assertFalse(frame.open)
    }

    @Test
    fun aTransactionCommitsOnceAndRefusesToNest() {
        val frame = Frame()
        val db = SupportSqlExecutor(frame.db)
        assertEquals(7, db.transaction { 7 })
        assertEquals(listOf("inTransaction", "beginTransaction", "setTransactionSuccessful", "endTransaction"), frame.calls.take(4))
        assertTrue("a committed frame is not ended twice", frame.ended() == 1 && !frame.open)
        // The reentrancy check reads the driver's own per-thread state, before any frame is opened.
        frame.open = true
        assertThrows(IllegalStateException::class.java) { db.transaction { 0 } }
        assertEquals(1, frame.calls.count { it == "beginTransaction" })
    }
}
