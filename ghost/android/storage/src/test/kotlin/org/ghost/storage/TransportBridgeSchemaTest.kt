package org.ghost.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.sqlite.SQLiteException

/**
 * PT-U8 (Phase 12 design `faza12-transports.md` §6.3, §12.2): the `transport_bridge` migration —
 * the table shape, the day granularity, WITHOUT ROWID, the 1 024-char bound, the DAO's order and
 * dedup, and the additive v8 → v9 upgrade (a populated v8 database gains exactly this table and
 * nothing else changes; an interruption leaves v8 as it was). T20's introspection half: the table
 * is in [Schema.expectedTables] (checked by [SchemaAndMigrationTest]) and carries no trigger and
 * no `*_no_replace` guard (the writer uses `INSERT OR IGNORE`, §6.3's explicit exemption).
 */
class TransportBridgeSchemaTest {

    private val upToV8 = Schema.migrations.filter { it.version <= 8 }
    private val v9 = Schema.migrations.single { it.version == 9 }

    private fun freshV9(): JdbcSqlExecutor = JdbcSqlExecutor().also { db ->
        MigrationRunner(db).migrate()
    }

    private fun tableSql(db: SqlExecutor): String =
        db.queryString("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'transport_bridge'")!!
            .replace(Regex("\\s+"), " ")

    @Test
    fun tableShapeIsExactlyTheDesignText() {
        val db = freshV9()
        assertEquals(
            "CREATE TABLE transport_bridge ( line TEXT PRIMARY KEY NOT NULL CHECK (length(line) > 0 AND length(line) <= 1024), " +
                "added_day INTEGER NOT NULL CHECK (typeof(added_day) = 'integer' AND added_day >= 0) ) WITHOUT ROWID",
            tableSql(db),
        )
    }

    @Test
    fun dayGranularityAndBoundsAreSchemaChecks() {
        val db = freshV9()
        db.exec("INSERT INTO transport_bridge(line, added_day) VALUES (?, ?)", listOf("192.0.2.1:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 5L))
        // Negative day, an empty line, a too-long line: refused by the CHECKs. (JDBC surfaces
        // the failed CHECK as SQLiteException; SQLCipher on device raises the same text.)
        assertThrows(SQLiteException::class.java) {
            db.exec("INSERT INTO transport_bridge(line, added_day) VALUES (?, ?)", listOf("192.0.2.2:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", -1L))
        }
        assertThrows(SQLiteException::class.java) {
            db.exec("INSERT INTO transport_bridge(line, added_day) VALUES (?, ?)", listOf("", 1L))
        }
        assertThrows(SQLiteException::class.java) {
            db.exec("INSERT INTO transport_bridge(line, added_day) VALUES (?, ?)", listOf("x".repeat(1025), 1L))
        }
        // A 1 024-char line is admitted (the bound is the design's cap, inclusive).
        db.exec("INSERT INTO transport_bridge(line, added_day) VALUES (?, ?)", listOf("x".repeat(1024), 6L))
        assertEquals(2L, db.queryLong("SELECT count(*) FROM transport_bridge"))
    }

    @Test
    fun noTriggersAndNoReplaceGuardOnTheTable() {
        val db = freshV9()
        assertEquals(0L, db.queryLong("SELECT count(*) FROM sqlite_master WHERE tbl_name = 'transport_bridge' AND type = 'trigger'"))
        assertEquals(
            0L,
            db.queryLong("SELECT count(*) FROM sqlite_master WHERE name = 'transport_bridge_no_replace'"),
        )
    }

    @Test
    fun repositoryRoundTripOrderDedupAndDelete() {
        val db = freshV9()
        // §6.3's order: insertion order at day granularity; same-day ties break by line (there
        // is deliberately no finer clock). A day-stepping clock gives the insertion order a
        // distinguishing signal; the same-day pins exercise the deterministic tie-break.
        var today = 100L
        val repo = TransportBridgeRepository(db) { today }
        val a = "192.0.2.1:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        val b = "obfs4 192.0.2.2:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA cert=AA== iat-mode=0"
        val c = "webtunnel 192.0.2.3:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA url=https://192.0.2.3/xx ver=ab"
        repo.replaceAll(listOf(b, a, b, c))
        // Exact duplicate collapsed; same-day ties alphabetical; the day order dominates.
        assertEquals(listOf(a, b, c), repo.list())

        repo.replaceAll(emptyList())
        assertEquals(emptyList<String>(), repo.list())

        var day = 200L
        val ordered = TransportBridgeRepository(db) { day++ }
        ordered.replaceAll(listOf(c, b, a))
        assertEquals(listOf(c, b, a), ordered.list())

        assertTrue(ordered.delete(a))
        assertFalse(ordered.delete(a))
        assertEquals(listOf(c, b), ordered.list())
    }

    @Test
    fun upgradeFromV8IsAdditiveAndTransactional() {
        val before = JdbcSqlExecutor().also { db ->
            assertEquals((1..8).toList(), MigrationRunner(db, upToV8).migrate())
        }
        val objectsBefore = schemaObjects(before)

        // Interruption at the only statement leaves v8 exactly as it was.
        val failing = JdbcSqlExecutor()
        MigrationRunner(failing, upToV8).migrate()
        val failAt = FailAtExec(failing, 0)
        assertThrows(IllegalStateException::class.java) { MigrationRunner(failAt, listOf(v9)).migrate() }
        assertEquals(8, failAt.userVersion)
        assertEquals(objectsBefore, schemaObjects(failAt))

        // The real upgrade adds exactly the table.
        val db = JdbcSqlExecutor()
        MigrationRunner(db, upToV8).migrate()
        assertEquals(listOf(9), MigrationRunner(db, listOf(v9)).migrate())
        assertEquals(9, db.userVersion)
        val after = schemaObjects(db)
        assertEquals(setOf("table|transport_bridge"), after - objectsBefore)
        assertEquals(emptySet<String>(), objectsBefore - after)
    }

    /** Every object of the schema as `type|name` lines, for the additive-delta comparison. */
    private fun schemaObjects(db: SqlExecutor): Set<String> {
        val out = HashSet<String>()
        db.query("SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name") {
            out += "${it.string(0)}|${it.string(1)}"
        }
        return out
    }

    /** Fails the [failAt]-th `exec` call (0-based); everything else is delegated. */
    private class FailAtExec(private val delegate: SqlExecutor, private val failAt: Int) : SqlExecutor by delegate {
        var calls = 0
        override fun exec(sql: String, args: List<Any?>) {
            if (calls++ == failAt) throw IllegalStateException("injected failure at statement $failAt")
            delegate.exec(sql, args)
        }
    }
}
