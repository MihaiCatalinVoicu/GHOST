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
 * On open it first sets [BASELINE_PRAGMAS], then applies [pragmas] ([Schema.connectionPragmas] by
 * default), like SQLCipher `onConfigure` on device. Tests pass a reduced [pragmas] list only to
 * show that dropping a connection pragma is caught.
 */
class JdbcSqlExecutor(
    path: String = ":memory:",
    pragmas: List<String> = Schema.connectionPragmas,
) : SqlExecutor, AutoCloseable {
    private val conn: Connection = DriverManager.getConnection("jdbc:sqlite:$path")
    private val lock = ReentrantLock()
    private val insideTransaction = ThreadLocal.withInitial { false }

    /** When set, the next statement whose SQL contains this marker throws (interruption test). */
    @Volatile
    var failOnStatementContaining: String? = null

    init {
        conn.createStatement().use { st ->
            for (pragma in BASELINE_PRAGMAS) st.execute(pragma)
            for (pragma in pragmas) st.execute(pragma)
        }
    }

    companion object {
        /**
         * The connection's starting values before [Schema.connectionPragmas], each different from
         * its [Schema.expectedPragmaValues] entry, so a pragma missing from the list is observable
         * on the JVM. `synchronous = NORMAL` is SQLCipher's default on device; plain sqlite-jdbc
         * would start at FULL and hide a missing `synchronous` pragma.
         */
        val BASELINE_PRAGMAS: List<String> = listOf(
            "PRAGMA foreign_keys = OFF",
            "PRAGMA synchronous = NORMAL",
            "PRAGMA secure_delete = OFF",
        )

        /** Prepared statements kept per executor. */
        private const val STATEMENT_CACHE = 512
    }

    /** Threads currently waiting for this executor's lock (threading-contract tests). */
    val waitingThreads: Int get() = lock.queueLength

    override fun exec(sql: String, args: List<Any?>) = locked {
        injectFailure(sql)
        withStatement(sql) { ps -> bind(ps, args); ps.execute() }
        Unit
    }

    override fun execUpdate(sql: String, args: List<Any?>): Int = locked {
        injectFailure(sql)
        withStatement(sql) { ps -> bind(ps, args); ps.executeUpdate() }
    }

    override fun query(sql: String, args: List<Any?>, onRow: (SqlExecutor.Row) -> Unit) = locked {
        withStatement(sql) { ps ->
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
            try {
                // Inside the try: a failing setAutoCommit (closed connection) still clears the flag.
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
                }
            } finally {
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

    /**
     * Prepared statements by SQL text, reused across calls (a JVM-side speed-up for the exit-gate
     * harness, which runs the same statements millions of times; SQLite semantics are unchanged).
     * A statement already running (a nested use of the same text inside a row callback) gets a
     * fresh one. Callers hold [lock].
     */
    private val statements = object : LinkedHashMap<String, PreparedStatement>(64, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, PreparedStatement>): Boolean {
            if (size <= STATEMENT_CACHE || eldest.key in inUse) return false
            eldest.value.close()
            return true
        }
    }
    private val inUse = HashSet<String>()

    private inline fun <T> withStatement(sql: String, block: (PreparedStatement) -> T): T {
        if (sql in inUse) return conn.prepareStatement(sql).use(block)
        val ps = statements.getOrPut(sql) { conn.prepareStatement(sql) }
        inUse += sql
        try {
            ps.clearParameters()
            return block(ps)
        } finally {
            inUse -= sql
        }
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

    override fun close() = locked {
        statements.values.forEach { it.close() }
        statements.clear()
        conn.close()
    }
}
