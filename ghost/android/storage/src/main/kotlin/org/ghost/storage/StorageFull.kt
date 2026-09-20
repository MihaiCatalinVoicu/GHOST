package org.ghost.storage

/**
 * The local database could not grow: SQLite answered `SQLITE_FULL` (Phase 9 design §13.1, §21.12
 * point 1). Both executors raise this typed exception instead of the driver's own, so a caller
 * catches one type (`sync-no-catch-all.sh`) and a transaction that hit a full disk is told apart
 * from a bug. The message names nothing (T3).
 */
class StorageFullException(cause: Throwable) : IllegalStateException("the local database is full", cause)

/**
 * Recognition of `SQLITE_FULL` across the two drivers the executors run on: sqlite-jdbc on the JVM
 * and SQLCipher on device. Neither exposes a shared exception type here (SQLCipher repackages the
 * platform's `SQLiteFullException`), so the class name and the two texts SQLite itself produces for
 * the code are matched, over a bounded cause chain.
 */
object StorageFull {
    private const val EXCEPTION_NAME = "SQLiteFullException"
    private const val CODE = "SQLITE_FULL"
    private const val TEXT = "database or disk is full"
    private const val MAX_CAUSES = 8

    fun matches(failure: Throwable): Boolean {
        var e: Throwable? = failure
        var depth = 0
        while (e != null && depth < MAX_CAUSES) {
            if (e.javaClass.simpleName == EXCEPTION_NAME) return true
            val message = e.message
            if (message != null && (message.contains(CODE) || message.contains(TEXT))) return true
            e = e.cause
            depth++
        }
        return false
    }

    /** [failure] as [StorageFullException] when it is `SQLITE_FULL`, unchanged otherwise. */
    fun wrap(failure: Throwable): Throwable = if (matches(failure)) StorageFullException(failure) else failure
}

/**
 * `PRAGMA wal_checkpoint(TRUNCATE)` with its result checked (Phase 9 design §10.7, which replaces
 * the ignored result of the Phase 7 garbage collector): the pragma answers `(busy, log, checkpointed)`
 * and a `busy` of 1 means a reader held the write-ahead log, so the log was not truncated and freed
 * pages stayed in it. The call is retried [ATTEMPTS] times, [PAUSE_MILLIS] apart; a caller whose
 * checkpoint stayed busy keeps the need in memory and asks again at its next sweep.
 */
object Checkpoint {
    /** Attempts in one call, the first included. */
    const val ATTEMPTS: Int = 3

    /** Wait between two attempts. */
    const val PAUSE_MILLIS: Long = 100

    /**
     * True once the log was truncated. [pause] waits between attempts (the default sleeps; a test
     * clock passes its own). Must run outside any transaction.
     */
    fun truncate(sql: SqlExecutor, pause: (Long) -> Unit = { Thread.sleep(it) }): Boolean {
        check(!sql.inTransaction) { "checkpoint inside a transaction" }
        for (attempt in 1..ATTEMPTS) {
            var busy = true
            sql.query("PRAGMA wal_checkpoint(TRUNCATE)") { busy = it.long(0) != 0L }
            if (!busy) return true
            if (attempt < ATTEMPTS) pause(PAUSE_MILLIS)
        }
        return false
    }
}
