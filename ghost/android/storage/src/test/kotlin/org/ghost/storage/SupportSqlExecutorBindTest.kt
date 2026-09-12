package org.ghost.storage

import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.sqlite.db.SupportSQLiteStatement
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.lang.reflect.Proxy

/**
 * The device executor binds only the types of the [SqlExecutor] contract, on `exec` as on
 * `execUpdate`: a Double bound into a time column would be stored as a REAL, and a `% 60 = 0`
 * CHECK of a v2 table casts it to INTEGER first, so its sub-minute part would pass (Phase 8 design
 * §11.3, "times finer than a minute" are never persisted; §19.20 point 1, both executors refuse
 * bind types outside the contract).
 */
class SupportSqlExecutorBindTest {
    /** Bind arguments of every `execSQL` call, and every executed compiled statement. */
    private val execSql = ArrayList<List<Any?>>()
    private val executed = ArrayList<String>()

    private val statement = Proxy.newProxyInstance(
        SupportSQLiteStatement::class.java.classLoader, arrayOf(SupportSQLiteStatement::class.java),
    ) { _, method, _ ->
        when {
            method.name == "executeUpdateDelete" -> { executed += method.name; 0 }
            method.name == "close" || method.name.startsWith("bind") -> null
            else -> throw UnsupportedOperationException(method.name)
        }
    } as SupportSQLiteStatement

    /** Records `execSQL`, hands out [statement]; any other use of the database fails. */
    private val recording = Proxy.newProxyInstance(
        SupportSQLiteDatabase::class.java.classLoader, arrayOf(SupportSQLiteDatabase::class.java),
    ) { _, method, args ->
        when (method.name) {
            "execSQL" -> { execSql += (args?.getOrNull(1) as? Array<*>)?.toList().orEmpty(); null }
            "compileStatement" -> statement
            else -> throw UnsupportedOperationException(method.name)
        }
    } as SupportSQLiteDatabase

    @Test
    fun execRefusesBindTypesOutsideTheContract() {
        val db = SupportSqlExecutor(recording)
        for (bad in listOf<Any>(1_757_491_200.5, 1.5f, true, 'k', java.math.BigDecimal.ONE, 7.toShort())) {
            assertThrows(bad.javaClass.name, IllegalArgumentException::class.java) {
                db.exec("INSERT INTO t(a, v) VALUES (?, ?)", listOf(1L, bad))
            }
            assertThrows(bad.javaClass.name, IllegalArgumentException::class.java) {
                db.execUpdate("UPDATE t SET v = ? WHERE a = ?", listOf(bad, 1L))
            }
        }
        assertTrue("a refused statement never runs", execSql.isEmpty() && executed.isEmpty())
        // The contract's types pass through unchanged, in order.
        val blob = byteArrayOf(1, 2)
        db.exec("INSERT INTO t(a, b, c, d, e) VALUES (?, ?, ?, ?, ?)", listOf(null, blob, 2L, 3, "x"))
        db.exec("CREATE TABLE t (v INTEGER)")
        assertEquals(0, db.execUpdate("UPDATE t SET a = ?, b = ?, c = ?, d = ?, e = ?", listOf(null, blob, 2L, 3, "x")))
        assertEquals(2, execSql.size)
        val bound = execSql[0]
        assertEquals(listOf(null, 2L, 3, "x"), bound.filterIndexed { i, _ -> i != 1 })
        assertArrayEquals(blob, bound[1] as ByteArray)
        assertEquals(emptyList<Any?>(), execSql[1])
        assertEquals(listOf("executeUpdateDelete"), executed)
    }
}
