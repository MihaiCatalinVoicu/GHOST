package org.ghost.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * T20 for the v3 entitlement tables by schema introspection (Phase 8 design §11.3, §19.15, §19.17,
 * §19.20), and the shape of the ES rule 5 memory (§19.2, §19.20 point 2):
 * the persisted time columns are exactly the listed `*_minute`, `*_hour` and `*_day` columns, each
 * with its granularity CHECK; no other column has a time-like name under the Phase 7 rule
 * (sync `SchemaIntrospectionTest`), whose only exemptions here are the `epoch` grid indices; the
 * former `last_state` is `prev_state`, so the rule's `last_` does not match it; and every table with
 * rules carries its REPLACE guard (§19.21 point 4).
 */
class EntitlementSchemaIntrospectionTest {
    private val entTables = listOf(
        "ent_key", "ent_schedule_fact", "ent_state", "ent_purchase", "ent_token", "ent_invite", "ent_drop_target",
        "ent_claim", "ent_payout_used",
    )

    /** The Phase 7 time-name rule, unchanged (sync SchemaIntrospectionTest). */
    private val timeLike = Regex("(_at$|time|date|epoch|_ms$|_seconds$|expir|_ts$|stamp|last_|since|until)")

    /**
     * Week and epoch indices of the grid (design §4.1), not points in time: the explicit exemptions
     * (§19.17). `ent_schedule_fact.epoch` is a week (slots), a price epoch (price) or the epoch of a
     * revoked key (revoked_<kind>, §19.20 point 2).
     */
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

    /** The values a `CHECK (column IN ('a', 'b'))` of the whitespace-normalized [sql] allows. */
    private fun allowed(sql: String, column: String): Set<String> {
        val list = Regex("CHECK \\($column IN \\(([^)]*)\\)\\)").find(sql)
        assertTrue("no IN list for $column in $sql", list != null)
        return Regex("'([^']*)'").findAll(list!!.groupValues[1]).map { it.groupValues[1] }.toSet()
    }

    @Test
    fun theScheduleMemoryHoldsEveryRule5FactWithRevocationsPerTokenKind(): Unit = JdbcSqlExecutor().use { db ->
        MigrationRunner(db).migrate()
        // ES rule 5 (design §3.1, §19.2, §19.20 point 2) remembers the keys (ent_key), the slot set of
        // every covered week, the price of every covered price epoch and every revoked (kind, epoch).
        // One revocation fact per kind of ent_key: (fact, epoch) is the key, and access weeks, invite
        // epochs and credit epochs can share an index, so a kind added to ent_key needs its own fact.
        val kinds = allowed(createSql(db, "ent_key"), "kind")
        assertEquals(setOf("access", "invite", "credit"), kinds)
        assertEquals(setOf("slots", "price") + kinds.map { "revoked_$it" }, allowed(createSql(db, "ent_schedule_fact"), "fact"))
        assertTrue(createSql(db, "ent_schedule_fact").contains("PRIMARY KEY (fact, epoch)"))
        // Append-only for every fact, revocations included: the UPDATE and DELETE triggers carry no WHEN.
        val triggers = ArrayList<String>()
        db.query("SELECT sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'ent_schedule_fact'") {
            triggers += it.string(0).replace(Regex("\\s+"), " ")
        }
        for (event in listOf("UPDATE", "DELETE")) {
            val on = triggers.filter { it.contains("BEFORE $event ON ent_schedule_fact") }
            assertEquals(event, 1, on.size)
            assertTrue(on.single(), on.single().contains("ON ent_schedule_fact BEGIN SELECT RAISE(ABORT, 'ent_schedule_fact is append-only')"))
        }
        // And through REPLACE (§19.21 point 4): an insert of a remembered (fact, epoch) is refused before
        // the conflict is resolved, since REPLACE would delete the old row without its DELETE trigger.
        val insert = triggers.filter { it.contains("BEFORE INSERT ON ent_schedule_fact") }
        assertEquals(1, insert.size)
        assertTrue(
            insert.single(),
            insert.single().contains(
                "WHEN EXISTS (SELECT 1 FROM ent_schedule_fact WHERE fact = NEW.fact AND epoch = NEW.epoch) " +
                    "BEGIN SELECT RAISE(ABORT, 'ent_schedule_fact is append-only')",
            ),
        )
        assertEquals(3, triggers.size)
    }

    @Test
    fun everyEntitlementTableWithRulesRefusesAConflictingInsert(): Unit = JdbcSqlExecutor().use { db ->
        MigrationRunner(db).migrate()
        // §19.21 point 4: REPLACE deletes a conflicting row without its DELETE trigger and writes one past
        // the UPDATE triggers, so each table with a rule also carries `<table>_no_replace` (its key
        // coverage is checked for every guard in ReplaceGuardsTest). ent_state and ent_payout_used carry
        // no trigger: nothing of theirs is write-once in the schema.
        val byTable = HashMap<String, MutableSet<String>>()
        db.query("SELECT tbl_name, name FROM sqlite_master WHERE type = 'trigger' AND tbl_name LIKE 'ent\\_%' ESCAPE '\\'") {
            byTable.getOrPut(it.string(0)) { HashSet() } += it.string(1)
        }
        assertEquals(entTables.toSet() - setOf("ent_state", "ent_payout_used"), byTable.keys)
        for ((table, names) in byTable) {
            assertTrue(table, "${table}_no_replace" in names)
            assertTrue("$table has no rule besides its guard", names.size >= 2)
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
