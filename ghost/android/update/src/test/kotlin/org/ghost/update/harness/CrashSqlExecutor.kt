package org.ghost.update.harness

import org.ghost.storage.SqlExecutor

/**
 * Process death at one SQL statement (the F7 §8.3 crash model for the update world): every
 * `exec`, `execUpdate` and `query` is one event; the event numbered [crashAt] throws
 * [WorldCrash] before running, exactly once (the world then reopens the database and continues
 * with the injector spent). A crash inside a transaction leaves it uncommitted — closing the
 * connection on [org.ghost.update.harness.Client.reopen] rolls it back, which is the device
 * crash the design's §9.6.1 crash rules describe.
 */
internal class CrashSqlExecutor(
    private val delegate: SqlExecutor,
    @Volatile var crashAt: Long,
) : SqlExecutor {

    /** Fired exactly once, then the injector is inert (the continuation must not crash again). */
    @Volatile
    var fired: Boolean = false
        private set

    var statementsSeen: Long = 0
        private set

    class WorldCrash(val at: Long) : RuntimeException("process death at SQL statement $at")

    private fun event() {
        val n = statementsSeen
        statementsSeen++
        if (!fired && n == crashAt) {
            fired = true
            throw WorldCrash(n)
        }
    }

    override fun exec(sql: String, args: List<Any?>) {
        event()
        delegate.exec(sql, args)
    }

    override fun execUpdate(sql: String, args: List<Any?>): Int {
        event()
        return delegate.execUpdate(sql, args)
    }

    override fun query(sql: String, args: List<Any?>, onRow: (SqlExecutor.Row) -> Unit) {
        event()
        delegate.query(sql, args, onRow)
    }

    override fun <T> transaction(block: () -> T): T = delegate.transaction(block)

    override val inTransaction: Boolean get() = delegate.inTransaction

    override var userVersion: Int
        get() = delegate.userVersion
        set(value) {
            delegate.userVersion = value
        }
}
