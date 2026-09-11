package org.ghost.storage

import java.sql.Connection
import java.sql.DriverManager
import java.sql.PreparedStatement
import java.util.concurrent.locks.ReentrantLock

/**
 * JVM test double for [SqlExecutor] over sqlite-jdbc. Same SQL dialect as SQLCipher (SQLite).
 * Shared test source (`src/testShared/kotlin`) of `:storage` and `:sync`.
 *
 * [path] is `:memory:` (default, private to this instance) or a file path; opening a second
 * executor on the same file after [close] models a process restart over durable state.
 *
 * Models the device executor's threading contract (see [SqlExecutor]) over one JDBC connection:
 *  - every call takes one executor-wide [ReentrantLock]; [transaction] holds it until commit or
 *    rollback, so statements and transactions of other threads wait and never run inside another
 *    thread's transaction;
 *  - [transaction] is not reentrant per thread: a nested call throws [IllegalStateException]
 *    before touching the connection, so the outer work is never committed early.
 * On open it applies [Schema.connectionPragmas], like SQLCipher `onConfigure` on device.
 */
class JdbcSqlExecutor(path: String = ":memory:") : SqlExecutor, AutoCloseable {
    private val conn: Connection = DriverManager.getConnection("jdbc:sqlite:$path")
    private val lock = ReentrantLock()
    private val insideTransaction = ThreadLocal.withInitial { false }

    /** When set, the next statement whose SQL contains this marker throws (interruption test). */
    @Volatile
    var failOnStatementContaining: String? = null

    init {
        conn.createStatement().use { st -> for (pragma in Schema.connectionPragmas) st.execute(pragma) }
    }

    /** Threads currently waiting for this executor's lock (threading-contract tests). */
    val waitingThreads: Int get() = lock.queueLength

    override fun exec(sql: String, args: List<Any?>) = locked {
        injectFailure(sql)
        conn.prepareStatement(sql).use { ps -> bind(ps, args); ps.execute() }
        Unit
    }

    override fun execUpdate(sql: String, args: List<Any?>): Int = locked {
        injectFailure(sql)
        conn.prepareStatement(sql).use { ps -> bind(ps, args); ps.executeUpdate() }
    }

    override fun query(sql: String, args: List<Any?>, onRow: (SqlExecutor.Row) -> Unit) = locked {
        conn.prepareStatement(sql).use { ps ->
            bind(ps, args)
            ps.executeQuery().use { rs ->
                val row = object : SqlExecutor.Row {
                    override fun isNull(index: Int): Boolean { rs.getObject(index + 1); return rs.wasNull() }
                    override fun long(index: Int) = rs.getLong(index + 1)
                    override fun string(index: Int): String = rs.getString(index + 1)
                    override fun blob(index: Int): ByteArray = rs.getBytes(index + 1)
                }
                while (rs.next()) onRow(row)
            }
        }
    }

    override fun <T> transaction(block: () -> T): T {
        check(!insideTransaction.get()) { "nested transaction on the same thread" }
        return locked {
            insideTransaction.set(true)
            conn.autoCommit = false
            try {
                val r = block()
                conn.commit()
                r
            } catch (t: Throwable) {
                conn.rollback()
                throw t
            } finally {
                conn.autoCommit = true
                insideTransaction.set(false)
            }
        }
    }

    override val inTransaction: Boolean
        get() = insideTransaction.get()

    override var userVersion: Int
        get() = locked {
            conn.createStatement().use { st -> st.executeQuery("PRAGMA user_version").use { rs -> rs.next(); rs.getInt(1) } }
        }
        set(value) = locked {
            conn.createStatement().use { it.execute("PRAGMA user_version = $value") }
            Unit
        }

    private inline fun <T> locked(block: () -> T): T {
        lock.lock()
        try {
            return block()
        } finally {
            lock.unlock()
        }
    }

    private fun injectFailure(sql: String) {
        failOnStatementContaining?.let { if (sql.contains(it)) throw IllegalStateException("injected failure") }
    }

    private fun bind(ps: PreparedStatement, args: List<Any?>) {
        args.forEachIndexed { i, a ->
            when (a) {
                null -> ps.setNull(i + 1, java.sql.Types.NULL)
                is ByteArray -> ps.setBytes(i + 1, a)
                is Long -> ps.setLong(i + 1, a)
                is Int -> ps.setInt(i + 1, a)
                is String -> ps.setString(i + 1, a)
                else -> throw IllegalArgumentException("unsupported bind type ${a::class}")
            }
        }
    }

    override fun close() = locked { conn.close() }
}
