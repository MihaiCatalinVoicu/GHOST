package org.ghost.storage

/**
 * Minimal SQL execution contract so the schema, migrations and repositories are testable on the
 * JVM (sqlite-jdbc) and run on device over SQLCipher through androidx.sqlite. Bind arguments are
 * `ByteArray`, `Long`, `Int`, `String` or `null`; everything network-originated is bound, never
 * concatenated (§8.1: untrusted data is parsed with limits before insertion).
 */
interface SqlExecutor {
    fun exec(sql: String, args: List<Any?> = emptyList())

    /** Runs `sql`, invoking [onRow] once per row. */
    fun query(sql: String, args: List<Any?> = emptyList(), onRow: (Row) -> Unit)

    /** Atomic block: any exception rolls everything back, including schema changes. */
    fun <T> transaction(block: () -> T): T

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
