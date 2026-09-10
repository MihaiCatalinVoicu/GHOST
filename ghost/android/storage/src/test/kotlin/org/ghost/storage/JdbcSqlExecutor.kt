package org.ghost.storage

import java.sql.Connection
import java.sql.DriverManager
import java.sql.PreparedStatement

/** JVM test double for [SqlExecutor] over sqlite-jdbc. Same SQL dialect as SQLCipher (SQLite). */
class JdbcSqlExecutor(path: String = ":memory:") : SqlExecutor, AutoCloseable {
    private val conn: Connection = DriverManager.getConnection("jdbc:sqlite:$path")
    /** When set, the next statement whose SQL contains this marker throws (interruption test). */
    var failOnStatementContaining: String? = null

    override fun exec(sql: String, args: List<Any?>) {
        failOnStatementContaining?.let { if (sql.contains(it)) throw IllegalStateException("injected failure") }
        conn.prepareStatement(sql).use { ps -> bind(ps, args); ps.execute() }
    }

    override fun query(sql: String, args: List<Any?>, onRow: (SqlExecutor.Row) -> Unit) {
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
        conn.autoCommit = false
        try {
            val r = block()
            conn.commit()
            return r
        } catch (t: Throwable) {
            conn.rollback()
            throw t
        } finally {
            conn.autoCommit = true
        }
    }

    override var userVersion: Int
        get() = conn.createStatement().use { st -> st.executeQuery("PRAGMA user_version").use { rs -> rs.next(); rs.getInt(1) } }
        set(value) { conn.createStatement().use { it.execute("PRAGMA user_version = $value") } }

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

    override fun close() = conn.close()
}
