package org.ghost.storage

/**
 * Minimal SQL execution contract so the schema, migrations and repositories are testable on the
 * JVM (sqlite-jdbc) and run on device over SQLCipher through androidx.sqlite. Bind arguments are
 * `ByteArray`, `Long`, `Int`, `String` or `null`; everything network-originated is bound, never
 * concatenated (§8.1: untrusted data is parsed with limits before insertion).
 *
 * Threading contract (both implementations):
 *  - one executor may be shared by several threads;
 *  - [transaction] is not reentrant per thread: a call on a thread that is already inside a
 *    transaction of this executor throws [IllegalStateException] before touching the connection,
 *    so the outer transaction is neither committed nor rolled back by the nested call;
 *  - while one thread is inside a transaction, statements and transactions of other threads wait
 *    until it ends, so work of different threads never interleaves inside one transaction;
 *  - ordering between threads is not defined here: a component that needs one (the sync engine's
 *    `SyncDatabase`) adds its own lock around [transaction].
 */
interface SqlExecutor {
    /** Runs one statement that returns no rows. PRAGMAs that return a row go through [query]. */
    fun exec(sql: String, args: List<Any?> = emptyList())

    /**
     * Runs one INSERT, UPDATE or DELETE and returns the number of rows it changed. Rows changed
     * by triggers or by foreign-key actions are not counted (SQLite `sqlite3_changes`). Guarded
     * state transitions check this count to learn whether their guard matched.
     */
    fun execUpdate(sql: String, args: List<Any?> = emptyList()): Int

    /** Runs `sql`, invoking [onRow] once per row. */
    fun query(sql: String, args: List<Any?> = emptyList(), onRow: (Row) -> Unit)

    /**
     * Atomic block: any exception rolls everything back, including schema changes. Not reentrant:
     * see the threading contract above.
     */
    fun <T> transaction(block: () -> T): T

    /** True when the calling thread is inside a transaction on this executor's connection. */
    val inTransaction: Boolean

    var userVersion: Int

    interface Row {
        fun isNull(index: Int): Boolean
        fun long(index: Int): Long
        fun string(index: Int): String
        fun blob(index: Int): ByteArray
    }
}

fun SqlExecutor.queryLong(sql: String, args: List<Any?> = emptyList()): Long? {
    var out: Long? = null
    query(sql, args) { if (!it.isNull(0)) out = it.long(0) }
    return out
}

fun SqlExecutor.queryBlob(sql: String, args: List<Any?> = emptyList()): ByteArray? {
    var out: ByteArray? = null
    query(sql, args) { if (!it.isNull(0)) out = it.blob(0) }
    return out
}

fun SqlExecutor.queryString(sql: String, args: List<Any?> = emptyList()): String? {
    var out: String? = null
    query(sql, args) { if (!it.isNull(0)) out = it.string(0) }
    return out
}
