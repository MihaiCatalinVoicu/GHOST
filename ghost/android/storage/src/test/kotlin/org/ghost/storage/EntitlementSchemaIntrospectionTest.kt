package org.ghost.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * T20 for the v3 entitlement tables by schema introspection (Phase 8 design §11.3, §19.15, §19.17):
 * the persisted time columns are exactly the listed `*_minute`, `*_hour` and `*_day` columns, each
 * with its granularity CHECK; no other column has a time-like name under the Phase 7 rule
 * (sync `SchemaIntrospectionTest`), whose only exemptions here are the `epoch` grid indices; and the
 * former `last_state` is `prev_state`, so the rule's `last_` does not match it.
 */
class EntitlementSchemaIntrospectionTest {
    private val entTables = listOf(
        "ent_key", "ent_schedule_fact", "ent_state", "ent_purchase", "ent_token", "ent_invite", "ent_drop_target",
        "ent_claim", "ent_payout_used",
    )

    /** The Phase 7 time-name rule, unchanged (sync SchemaIntrospectionTest). */
    private val timeLike = Regex("(_at$|time|date|epoch|_ms$|_seconds$|expir|_ts$|stamp|last_|since|until)")

    /** Week and epoch indices of the grid (design §4.1), not points in time: the explicit exemptions (§19.17). */
    private val gridIndexExemptions = setOf("ent_key.epoch", "ent_schedule_fact.epoch", "ent_token.epoch")

    /** Every persisted time of the entitlement tables (design §11.3). */
    private val expectedTimeColumns = setOf(
        "ent_state.restore_scan_until_day",
        "ent_purchase.created_hour", "ent_purchase.receipt_minute", "ent_purchase.next_due_minute", "ent_purchase.terminal_day",
        "ent_token.eligible_minute",
        "ent_invite.listen_until_day",
        "ent_drop_target.drop_minute", "ent_drop_target.until_day",
        "ent_claim.next_due_minute", "ent_claim.terminal_day",
        "ent_payout_used.until_day",
    )

    private fun columns(db: JdbcSqlExecutor, table: String): List<String> {
        val out = ArrayList<String>()
        db.query("PRAGMA table_info($table)") { out += it.string(1) }
        return out
    }

    private fun createSql(db: JdbcSqlExecutor, table: String): String {
        var sql = ""
        db.query("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", listOf(table)) { sql = it.string(0) }
        return sql.replace(Regex("\\s+"), " ")
    }

    @Test
    fun everyTimeColumnHasItsGranularityCheckAndNoOtherColumnLooksLikeATime(): Unit = JdbcSqlExecutor().use { db ->
        MigrationRunner(db).migrate()
        val timeColumns = ArrayList<String>()
        val exempted = HashSet<String>()
        for (table in entTables) {
            val sql = createSql(db, table)
            assertTrue("missing table $table", sql.isNotEmpty())
            for (column in columns(db, table)) {
                val lower = column.lowercase()
                val qualified = "$table.$column"
                // `%` casts a REAL to INTEGER first, so granularity also needs the stored type.
                val typed = sql.contains("typeof($column) = 'integer'")
                if (lower.endsWith("_minute") || lower.endsWith("_hour") || lower.endsWith("_day") || timeLike.containsMatchIn(lower)) {
                    assertTrue("$qualified needs typeof($column) = 'integer'", typed)
                }
                when {
                    lower.endsWith("_minute") -> {
                        assertTrue("$qualified needs % 60 = 0", sql.contains("$column % 60 = 0"))
                        timeColumns += qualified
                    }
                    lower.endsWith("_hour") -> {
                        assertTrue("$qualified needs % 3600 = 0", sql.contains("$column % 3600 = 0"))
                        timeColumns += qualified
                    }
                    lower.endsWith("_day") -> {
                        assertTrue("$qualified needs a CHECK", Regex("CHECK \\([^)]*\\b$column\\b").containsMatchIn(sql))
                        timeColumns += qualified
                    }
                    timeLike.containsMatchIn(lower) -> {
                        assertTrue("$qualified looks like an unchecked time column", qualified in gridIndexExemptions)
                        exempted += qualified
                    }
                }
            }
        }
        assertEquals(expectedTimeColumns.size, timeColumns.size)
        assertEquals(expectedTimeColumns, timeColumns.toSet())
        // Every exemption is used, so none can hide a new column.
        assertEquals(gridIndexExemptions, exempted)
    }

    @Test
    fun theOnlyWeekColumnIsTheBaseWeekIndex(): Unit = JdbcSqlExecutor().use { db ->
        MigrationRunner(db).migrate()
        val weekColumns = entTables.flatMap { t -> columns(db, t).filter { it.contains("week") }.map { "$t.$it" } }
        assertEquals(listOf("ent_purchase.base_week"), weekColumns)
        assertTrue(createSql(db, "ent_purchase").contains("typeof(base_week) = 'integer'"))
    }

    @Test
    fun theLatestInvoiceStateIsPrevStateSoTheTimeRuleDoesNotMatchIt(): Unit = JdbcSqlExecutor().use { db ->
        MigrationRunner(db).migrate()
        val purchase = columns(db, "ent_purchase")
        assertTrue("prev_state" in purchase)
        assertFalse(purchase.any { it.startsWith("last_") })
        assertFalse(timeLike.containsMatchIn("prev_state"))
        assertTrue(timeLike.containsMatchIn("last_state"))
    }

    @Test
    fun terminalRowsCannotKeepTheCreationHourOrReceiptMinute(): Unit = JdbcSqlExecutor().use { db ->
        MigrationRunner(db).migrate()
        // §19.15: created_hour, receipt_minute and outstanding_atomic are nulled in the terminal
        // transaction (CHECK-enforced); GC keys on terminal_day only.
        val sql = createSql(db, "ent_purchase")
        for (column in listOf("created_hour", "receipt_minute", "outstanding_atomic", "next_due_minute")) {
            assertTrue(column, sql.contains("$column IS NULL AND") || sql.contains("AND $column IS NULL"))
        }
    }

    @Test
    fun keyedTablesKeepNoInsertionOrder(): Unit = JdbcSqlExecutor().use { db ->
        MigrationRunner(db).migrate()
        // Singletons (id = 1) excepted, every entitlement table is WITHOUT ROWID: tokens are keyed by
        // their random nullifier and never reveal the order in which batches arrived.
        for (table in entTables - setOf("ent_state", "ent_drop_target")) {
            assertTrue(table, createSql(db, table).trimEnd().endsWith("WITHOUT ROWID"))
        }
    }
}
