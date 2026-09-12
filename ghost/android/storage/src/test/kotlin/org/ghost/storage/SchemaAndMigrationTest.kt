package org.ghost.storage

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SchemaAndMigrationTest {
    private fun fresh(): JdbcSqlExecutor = JdbcSqlExecutor()

    private val upToV1 = Schema.migrations.filter { it.version <= 1 }
    private val upToV2 = Schema.migrations.filter { it.version <= 2 }
    private val v2 = Schema.migrations.single { it.version == 2 }
    private val v3 = Schema.migrations.single { it.version == 3 }

    /** The nine tables and 13 triggers of v3 (Phase 8 design §11.3, §19.19; SQL as corrected by §19.20). */
    private val v3Tables = setOf(
        "ent_key", "ent_schedule_fact", "ent_state", "ent_purchase", "ent_token", "ent_invite", "ent_drop_target",
        "ent_claim", "ent_payout_used",
    )
    private val v3Triggers = setOf(
        "ent_key_append_only", "ent_key_no_delete", "ent_schedule_fact_append_only", "ent_schedule_fact_no_delete",
        "ent_purchase_transitions", "ent_purchase_frozen", "ent_purchase_invoice_frozen", "ent_purchase_delete_terminal_only",
        "ent_token_state", "ent_token_binding", "ent_invite_transitions", "ent_claim_guard", "ent_drop_target_transitions",
    )

    /** A database at v1 exactly as Phase 4 shipped it. */
    private fun atV1(): JdbcSqlExecutor = fresh().also {
        assertEquals(listOf(1), MigrationRunner(it, upToV1).migrate())
        assertEquals(1, it.userVersion)
    }

    /** A database at v2 exactly as Phase 7 shipped it, holding v1 rows and sync rows. */
    private fun atV2WithData(): JdbcSqlExecutor = atV1().also {
        seedV1Data(it)
        assertEquals(listOf(2), MigrationRunner(it, upToV2).migrate())
        seedV2Data(it)
        assertEquals(2, it.userVersion)
    }

    private fun JdbcSqlExecutor.names(type: String): Set<String> {
        val out = HashSet<String>()
        query("SELECT name FROM sqlite_master WHERE type = ? AND name NOT LIKE 'sqlite_%'", listOf(type)) { out += it.string(0) }
        return out
    }

    /** Full schema text, used to prove that a failed migration left no trace. */
    private fun JdbcSqlExecutor.schemaSnapshot(): List<String> {
        val out = ArrayList<String>()
        query("SELECT type, name, COALESCE(sql, '') FROM sqlite_master ORDER BY type, name") {
            out += "${it.string(0)}|${it.string(1)}|${it.string(2)}"
        }
        return out
    }

    private fun JdbcSqlExecutor.count(table: String): Long = queryLong("SELECT count(*) FROM $table")!!

    /** Rows in tables that v2 and v3 keep, written at v1. */
    private fun seedV1Data(db: JdbcSqlExecutor) {
        db.exec(
            "INSERT INTO identity(id, public_identity, identity_public_key, derivation_version, created_at) VALUES (1, 'ghost:me', ?, 1, 7)",
            listOf(ByteArray(32) { 1 }),
        )
        db.exec(
            "INSERT INTO contacts(public_identity, identity_public_key, trust_state, created_at) VALUES ('ghost:bob', ?, 'verified', 8)",
            listOf(ByteArray(32) { 2 }),
        )
        db.exec("INSERT INTO conversations(contact_id, protocol_version, created_at) VALUES (1, 1, 9)")
        db.exec(
            "INSERT INTO messages(operation_id, conversation_id, direction, envelope, content_type, sent_at_minute, state) VALUES (?, 1, 'in', ?, 'text', 120, 'received')",
            listOf(ByteArray(16) { 3 }, ByteArray(40) { 4 }),
        )
        db.exec("INSERT INTO channels(channel_id, history_policy, created_at) VALUES (?, 'none', 1)", listOf(ByteArray(32) { 5 }))
        db.exec("INSERT INTO channel_pseudonyms(channel_id, pseudonym_public_key) VALUES (?, ?)", listOf(ByteArray(32) { 5 }, ByteArray(32) { 6 }))
        db.exec("INSERT INTO invite_nonces(nonce, seen_at) VALUES (?, 10)", listOf(ByteArray(16) { 7 }))
        db.exec("INSERT INTO revocations(identity_public_key, certificate, received_at) VALUES (?, ?, 11)", listOf(ByteArray(32) { 8 }, ByteArray(64) { 9 }))
    }

    private fun assertV1DataIntact(db: JdbcSqlExecutor) {
        assertEquals("ghost:me", db.queryString("SELECT public_identity FROM identity WHERE id = 1"))
        assertEquals("verified", db.queryString("SELECT trust_state FROM contacts WHERE public_identity = 'ghost:bob'"))
        assertEquals(1L, db.count("conversations"))
        assertArrayEquals(ByteArray(40) { 4 }, db.queryBlob("SELECT envelope FROM messages WHERE operation_id = ?", listOf(ByteArray(16) { 3 })))
        assertArrayEquals(ByteArray(32) { 6 }, db.queryBlob("SELECT pseudonym_public_key FROM channel_pseudonyms"))
        assertEquals(1L, db.count("invite_nonces"))
        assertEquals(1L, db.count("revocations"))
        assertEquals("1", db.queryString("SELECT value FROM schema_meta WHERE key = 'created_schema_version'"))
    }

    private val syncNamespace = bytes(32, 0x21)

    /** Sync rows written at v2 (Phase 7), which v3 keeps. */
    private fun seedV2Data(db: JdbcSqlExecutor) {
        db.exec(
            "INSERT INTO relay_directory(relay_id, onion_address, operator_id, state, source) VALUES (1, ?, ?, 'active', 'config')",
            listOf(onion(1), bytes(16, 1)),
        )
        db.exec("INSERT INTO sync_namespace(namespace_id, consumer, listening) VALUES (?, 'dm', 1)", listOf(syncNamespace))
        db.exec("INSERT INTO namespace_relay(namespace_id, relay_id) VALUES (?, 1)", listOf(syncNamespace))
        db.exec(
            "INSERT INTO relay_capability(relay_id, namespace_id, kind, token, expires_hour, state, generation) VALUES (1, ?, 'write', ?, 7200, 'usable', 1)",
            listOf(syncNamespace, bytes(82, 3)),
        )
        db.exec("INSERT INTO inbox_blob(namespace_id, blob_hash, state, retain_until_day) VALUES (?, ?, 'listed', 112)", listOf(syncNamespace, hash(4)))
    }

    private fun assertV2DataIntact(db: JdbcSqlExecutor) {
        assertEquals(onion(1), db.queryString("SELECT onion_address FROM relay_directory WHERE relay_id = 1"))
        assertEquals(1L, db.count("namespace_relay"))
        assertArrayEquals(bytes(82, 3), db.queryBlob("SELECT token FROM relay_capability WHERE relay_id = 1 AND namespace_id = ?", listOf(syncNamespace)))
        assertEquals("listed", db.queryString("SELECT state FROM inbox_blob WHERE namespace_id = ? AND blob_hash = ?", listOf(syncNamespace, hash(4))))
    }

    /** A row in the v1 `entitlement` table, which v3 refuses to drop. */
    private fun entitlementRow(db: JdbcSqlExecutor) = db.exec(
        "INSERT INTO entitlement(period_id, issuer_key_id, tokens_envelope, valid_from, valid_until) VALUES (?, ?, ?, 1, 2)",
        listOf(ByteArray(8), ByteArray(32), ByteArray(64)),
    )

    /** A row in the v1 `referral` table, which v3 refuses to drop. */
    private fun referralRow(db: JdbcSqlExecutor) = db.exec("INSERT INTO referral(id, commitment) VALUES (1, ?)", listOf(ByteArray(32)))

    @Test
    fun freshDatabaseMigratesToCurrentVersionWithAllTables() {
        fresh().use { db ->
            val applied = MigrationRunner(db).migrate()
            assertEquals(listOf(1, 2, 3), applied)
            assertEquals(Schema.CURRENT_VERSION, db.userVersion)
            MigrationRunner(db).verifyIntegrity()
            assertEquals(Schema.expectedTables, db.names("table"))
            assertEquals(Schema.expectedTriggers, db.names("trigger"))
            assertEquals(25, Schema.expectedTriggers.size)
            assertTrue(Schema.expectedTables.containsAll(v3Tables))
            assertEquals(v3Triggers, Schema.expectedTriggers.filter { it.startsWith("ent_") }.toSet())
            assertEquals(9, v3Tables.size)
            assertEquals(13, v3Triggers.size)
            assertEquals(setOf("idx_ent_token_one_reservation", "idx_ent_claim_one_open"), db.names("index").filter { it.startsWith("idx_ent_") }.toSet())
        }
    }

    @Test
    fun everyUpgradePathReachesTheSameAmendedV3() {
        // v3 is unreleased and amended in place (design §19.20): a fresh install, a v1 upgrade and a
        // v2 upgrade end with the identical schema, which remembers revocations per token kind.
        val freshSchema = fresh().use { db ->
            MigrationRunner(db).migrate()
            db.schemaSnapshot()
        }
        val paths: List<Pair<String, () -> JdbcSqlExecutor>> = listOf(
            "v1" to { atV1().also { seedV1Data(it) } },
            "v2" to { atV2WithData() },
        )
        for ((from, open) in paths) open().use { db ->
            MigrationRunner(db).migrate()
            MigrationRunner(db).verifyIntegrity()
            assertEquals(from, freshSchema, db.schemaSnapshot())
            for (kind in listOf("access", "invite", "credit")) {
                db.exec("INSERT INTO ent_schedule_fact(fact, epoch, digest) VALUES (?, 726, ?)", listOf("revoked_$kind", hash(1)))
            }
            db.rejects(CHECK_FAILED, "INSERT INTO ent_schedule_fact(fact, epoch, digest) VALUES ('revoked', 727, ?)", hash(1))
            db.rejects("ent_schedule_fact is append-only", "DELETE FROM ent_schedule_fact WHERE fact = 'revoked_access'")
            assertEquals(from, 3L, db.count("ent_schedule_fact"))
        }
    }

    @Test
    fun currentVersionIsTheLastMigration() {
        assertEquals(3, Schema.CURRENT_VERSION)
        assertEquals(listOf(1, 2, 3), Schema.migrations.map { it.version })
        assertEquals(Schema.CURRENT_VERSION, Schema.migrations.maxOf { it.version })
    }

    @Test
    fun v2DropsThePreMultiRelayTablesAndItsGuard() {
        fresh().use { db ->
            MigrationRunner(db).migrate()
            val present = db.names("table") + db.names("index")
            for (gone in listOf("relay_queue", "sync_cursor", "idx_relay_queue_due", "v2_migration_guard")) {
                assertFalse("$gone must not survive v2", gone in present)
            }
        }
    }

    @Test
    fun v3DropsTheUnusedV1EntitlementTablesAndItsGuard() {
        fresh().use { db ->
            MigrationRunner(db).migrate()
            val present = db.names("table")
            for (gone in listOf("entitlement", "referral", "v3_migration_guard")) {
                assertFalse("$gone must not survive v3", gone in present)
            }
        }
    }

    @Test
    fun v1DatabaseWithDataMigratesToV3AndKeepsIt() {
        atV1().use { db ->
            seedV1Data(db)
            assertEquals(listOf(2, 3), MigrationRunner(db).migrate())
            MigrationRunner(db).verifyIntegrity()
            assertV1DataIntact(db)
            assertEquals(Schema.expectedTables, db.names("table"))
        }
    }

    @Test
    fun v2DatabaseWithDataMigratesToV3AndKeepsIt() {
        atV2WithData().use { db ->
            assertEquals(listOf(3), MigrationRunner(db).migrate())
            MigrationRunner(db).verifyIntegrity()
            assertV1DataIntact(db)
            assertV2DataIntact(db)
            assertEquals(Schema.expectedTables, db.names("table"))
            assertEquals(Schema.expectedTriggers, db.names("trigger"))
            for (table in v3Tables) assertEquals(table, 0L, db.count(table))
        }
    }

    @Test
    fun guardAbortsV2WhenRelayQueueHasRows() {
        atV1().use { db ->
            seedV1Data(db)
            db.exec(
                "INSERT INTO relay_queue(operation_id, kind, payload, target_policy, next_retry_at) VALUES (?, 'store', ?, 'any2', 0)",
                listOf(ByteArray(16), ByteArray(10)),
            )
            val before = db.schemaSnapshot()
            val e = assertThrows(java.sql.SQLException::class.java) { MigrationRunner(db).migrate() }
            assertTrue(e.message!!, e.message!!.contains("CHECK constraint failed"))
            assertEquals(1, db.userVersion)
            assertEquals(before, db.schemaSnapshot())
            assertEquals(1L, db.count("relay_queue"))
            assertV1DataIntact(db)
            // Recovery path: once the table is empty the migration succeeds.
            db.exec("DELETE FROM relay_queue")
            assertEquals(listOf(2, 3), MigrationRunner(db).migrate())
            assertV1DataIntact(db)
        }
    }

    @Test
    fun guardAbortsV2WhenSyncCursorHasRows() {
        atV1().use { db ->
            db.exec("INSERT INTO sync_cursor(namespace_id, cursor) VALUES (?, ?)", listOf(ByteArray(32), ByteArray(8)))
            val before = db.schemaSnapshot()
            assertThrows(java.sql.SQLException::class.java) { MigrationRunner(db).migrate() }
            assertEquals(1, db.userVersion)
            assertEquals(before, db.schemaSnapshot())
            assertEquals(1L, db.count("sync_cursor"))
        }
    }

    @Test
    fun guardAbortsV3WhenEntitlementOrReferralHasRows() {
        for ((table, writeRow) in listOf("entitlement" to ::entitlementRow, "referral" to ::referralRow)) {
            atV2WithData().use { db ->
                writeRow(db)
                val before = db.schemaSnapshot()
                val e = assertThrows(table, java.sql.SQLException::class.java) { MigrationRunner(db).migrate() }
                assertTrue(e.message!!, e.message!!.contains("CHECK constraint failed"))
                assertEquals(table, 2, db.userVersion)
                assertEquals(table, before, db.schemaSnapshot())
                assertEquals(table, 1L, db.count(table))
                assertV1DataIntact(db)
                assertV2DataIntact(db)
                // A database the guard stopped is never used: the version check refuses it.
                assertThrows(IllegalStateException::class.java) { MigrationRunner(db).verifyIntegrity() }
                // Recovery path: once the table is empty the migration succeeds.
                db.exec("DELETE FROM $table")
                assertEquals(listOf(3), MigrationRunner(db).migrate())
                MigrationRunner(db).verifyIntegrity()
                assertV1DataIntact(db)
                assertV2DataIntact(db)
            }
        }
    }

    @Test
    fun guardOnAV1DatabaseStopsAfterTheCompletedV2() {
        // Each migration commits on its own: a v1 database with an entitlement row reaches v2 and stops.
        atV1().use { db ->
            seedV1Data(db)
            entitlementRow(db)
            assertThrows(java.sql.SQLException::class.java) { MigrationRunner(db).migrate() }
            assertEquals(2, db.userVersion)
            assertEquals(1L, db.count("entitlement"))
            assertFalse("ent_token" in db.names("table"))
            assertThrows(IllegalStateException::class.java) { MigrationRunner(db).verifyIntegrity() }
            assertV1DataIntact(db)
        }
    }

    /** Fails the [failAt]-th `exec` call (0-based); everything else is delegated. */
    private class FailAtExec(private val delegate: SqlExecutor, private val failAt: Int) : SqlExecutor by delegate {
        var calls = 0
        override fun exec(sql: String, args: List<Any?>) {
            if (calls++ == failAt) throw IllegalStateException("injected failure at statement $failAt")
            delegate.exec(sql, args)
        }
    }

    /** Fails when `user_version` is set to [version], the last step of a migration transaction. */
    private class FailOnVersionBump(private val delegate: SqlExecutor, private val version: Int) : SqlExecutor by delegate {
        override var userVersion: Int
            get() = delegate.userVersion
            set(value) {
                check(value != version) { "injected failure at the version bump" }
                delegate.userVersion = value
            }
    }

    @Test
    fun interruptionAtEveryStatementOfV2LeavesV1Intact() {
        for (i in v2.statements.indices) {
            atV1().use { db ->
                seedV1Data(db)
                val before = db.schemaSnapshot()
                val faulty = FailAtExec(db, i)
                assertThrows("statement $i", IllegalStateException::class.java) { MigrationRunner(faulty).migrate() }
                assertEquals("statement $i ran", i + 1, faulty.calls)
                assertEquals("statement $i", 1, db.userVersion)
                assertEquals("statement $i", before, db.schemaSnapshot())
                assertV1DataIntact(db)
                assertFalse(db.inTransaction)
                assertEquals(listOf(2, 3), MigrationRunner(db).migrate())
                MigrationRunner(db).verifyIntegrity()
                assertV1DataIntact(db)
            }
        }
        atV1().use { db ->
            seedV1Data(db)
            val before = db.schemaSnapshot()
            assertThrows(IllegalStateException::class.java) { MigrationRunner(FailOnVersionBump(db, 2)).migrate() }
            assertEquals(1, db.userVersion)
            assertEquals(before, db.schemaSnapshot())
            assertEquals(listOf(2, 3), MigrationRunner(db).migrate())
        }
    }

    @Test
    fun interruptionAtEveryStatementOfV3LeavesV2Intact() {
        for (i in v3.statements.indices) {
            atV2WithData().use { db ->
                val before = db.schemaSnapshot()
                val faulty = FailAtExec(db, i)
                assertThrows("statement $i", IllegalStateException::class.java) { MigrationRunner(faulty).migrate() }
                assertEquals("statement $i ran", i + 1, faulty.calls)
                assertEquals("statement $i", 2, db.userVersion)
                assertEquals("statement $i", before, db.schemaSnapshot())
                assertV1DataIntact(db)
                assertV2DataIntact(db)
                assertFalse(db.inTransaction)
                assertEquals(listOf(3), MigrationRunner(db).migrate())
                MigrationRunner(db).verifyIntegrity()
                assertV1DataIntact(db)
                assertV2DataIntact(db)
            }
        }
        atV2WithData().use { db ->
            val before = db.schemaSnapshot()
            assertThrows(IllegalStateException::class.java) { MigrationRunner(FailOnVersionBump(db, 3)).migrate() }
            assertEquals(2, db.userVersion)
            assertEquals(before, db.schemaSnapshot())
            assertEquals(listOf(3), MigrationRunner(db).migrate())
            assertV2DataIntact(db)
        }
    }

    @Test
    fun aV3InterruptionAfterV2InOneRunKeepsTheCompletedV2() {
        val v2Schema = atV1().use { db ->
            seedV1Data(db)
            MigrationRunner(db, upToV2).migrate()
            db.schemaSnapshot()
        }
        for (i in v3.statements.indices) {
            atV1().use { db ->
                seedV1Data(db)
                val faulty = FailAtExec(db, v2.statements.size + i)
                assertThrows("statement $i", IllegalStateException::class.java) { MigrationRunner(faulty).migrate() }
                assertEquals("statement $i", 2, db.userVersion)
                assertEquals("statement $i", v2Schema, db.schemaSnapshot())
                assertV1DataIntact(db)
                // Until the upgrade completes, the database is refused.
                assertThrows(IllegalStateException::class.java) { MigrationRunner(db).verifyIntegrity() }
                assertEquals(listOf(3), MigrationRunner(db).migrate())
                MigrationRunner(db).verifyIntegrity()
            }
        }
    }

    @Test
    fun interruptedMigrationLeavesPreviousVersionAndNoPartialSchema() {
        fresh().use { db ->
            db.failOnStatementContaining = "CREATE TABLE posts"
            assertThrows(IllegalStateException::class.java) { MigrationRunner(db).migrate() }
            assertEquals(0, db.userVersion)
            val tables = db.names("table")
            assertTrue("rollback must remove partially created tables, found $tables", tables.isEmpty())
            // Recovery path: the same runner succeeds once the fault is gone.
            db.failOnStatementContaining = null
            assertEquals(listOf(1, 2, 3), MigrationRunner(db).migrate())
        }
    }

    @Test
    fun openHelperPathAppliesPendingMigrationsInsideTheCallersTransaction() {
        // The SQLCipher open helper calls onCreate/onUpgrade inside its own transaction and then
        // sets user_version itself; this reproduces that sequence on the JVM.
        fun helperOpen(db: SqlExecutor): List<Int> = db.transaction {
            val applied = MigrationRunner(db).migrateWithinTransaction(db.userVersion)
            db.userVersion = Schema.CURRENT_VERSION
            applied
        }
        fresh().use { db ->
            assertEquals(listOf(1, 2, 3), helperOpen(db))
            MigrationRunner(db).verifyIntegrity()
            assertEquals(emptyList<Int>(), MigrationRunner(db).migrate())
        }
        atV1().use { db ->
            seedV1Data(db)
            assertEquals(listOf(2, 3), helperOpen(db))
            MigrationRunner(db).verifyIntegrity()
            assertV1DataIntact(db)
        }
        atV2WithData().use { db ->
            assertEquals(listOf(3), helperOpen(db))
            MigrationRunner(db).verifyIntegrity()
            assertV1DataIntact(db)
            assertV2DataIntact(db)
        }
        atV1().use { db ->
            db.exec("INSERT INTO sync_cursor(namespace_id) VALUES (?)", listOf(ByteArray(32)))
            val before = db.schemaSnapshot()
            assertThrows(java.sql.SQLException::class.java) { helperOpen(db) }
            assertEquals(1, db.userVersion)
            assertEquals(before, db.schemaSnapshot())
        }
        // On device every pending migration shares the helper's transaction: a v3 guard failure on a
        // v1 database rolls v2 back too.
        atV1().use { db ->
            referralRow(db)
            val before = db.schemaSnapshot()
            assertThrows(java.sql.SQLException::class.java) { helperOpen(db) }
            assertEquals(1, db.userVersion)
            assertEquals(before, db.schemaSnapshot())
        }
        atV2WithData().use { db ->
            entitlementRow(db)
            val before = db.schemaSnapshot()
            assertThrows(java.sql.SQLException::class.java) { helperOpen(db) }
            assertEquals(2, db.userVersion)
            assertEquals(before, db.schemaSnapshot())
            assertV2DataIntact(db)
        }
        fresh().use { db ->
            // Outside a transaction the helper entry point refuses to run.
            assertThrows(IllegalStateException::class.java) { MigrationRunner(db).migrateWithinTransaction(0) }
            db.userVersion = Schema.CURRENT_VERSION + 1
            assertThrows(MigrationRunner.DowngradeException::class.java) {
                db.transaction { MigrationRunner(db).migrateWithinTransaction(db.userVersion) }
            }
        }
    }

    @Test
    fun migrateIsIdempotent() {
        fresh().use { db ->
            MigrationRunner(db).migrate()
            assertEquals(emptyList<Int>(), MigrationRunner(db).migrate())
        }
    }

    @Test
    fun downgradeFailsClosed() {
        fresh().use { db ->
            db.userVersion = Schema.CURRENT_VERSION + 1
            assertThrows(MigrationRunner.DowngradeException::class.java) { MigrationRunner(db).migrate() }
        }
        // An older app (it knows v1 and v2 only) refuses a v3 database and leaves it untouched.
        fresh().use { db ->
            MigrationRunner(db).migrate()
            val before = db.schemaSnapshot()
            assertThrows(MigrationRunner.DowngradeException::class.java) { MigrationRunner(db, upToV2).migrate() }
            assertThrows(MigrationRunner.DowngradeException::class.java) {
                db.transaction { MigrationRunner(db, upToV2).migrateWithinTransaction(db.userVersion) }
            }
            assertEquals(3, db.userVersion)
            assertEquals(before, db.schemaSnapshot())
            MigrationRunner(db).verifyIntegrity()
        }
    }

    @Test
    fun verifyIntegrityRefusesMissingTriggerPragmaOrTable() {
        fresh().use { db ->
            MigrationRunner(db).migrate()
            MigrationRunner(db).verifyIntegrity()
            db.exec("DROP TRIGGER outbox_delivery_state")
            val e = assertThrows(IllegalStateException::class.java) { MigrationRunner(db).verifyIntegrity() }
            assertTrue(e.message!!, e.message!!.contains("outbox_delivery_state"))
        }
        for (trigger in v3Triggers) {
            fresh().use { db ->
                MigrationRunner(db).migrate()
                db.exec("DROP TRIGGER $trigger")
                val e = assertThrows(trigger, IllegalStateException::class.java) { MigrationRunner(db).verifyIntegrity() }
                assertTrue(e.message!!, e.message!!.contains(trigger))
            }
        }
        fresh().use { db ->
            MigrationRunner(db).migrate()
            db.exec("PRAGMA foreign_keys = OFF")
            val e = assertThrows(IllegalStateException::class.java) { MigrationRunner(db).verifyIntegrity() }
            assertTrue(e.message!!, e.message!!.contains("foreign_keys"))
        }
        fresh().use { db ->
            MigrationRunner(db).migrate()
            db.exec("PRAGMA synchronous = NORMAL")
            val e = assertThrows(IllegalStateException::class.java) { MigrationRunner(db).verifyIntegrity() }
            assertTrue(e.message!!, e.message!!.contains("synchronous"))
        }
        fresh().use { db ->
            MigrationRunner(db).migrate()
            db.query("PRAGMA secure_delete = OFF") { }
            val e = assertThrows(IllegalStateException::class.java) { MigrationRunner(db).verifyIntegrity() }
            assertTrue(e.message!!, e.message!!.contains("secure_delete"))
        }
        fresh().use { db ->
            MigrationRunner(db).migrate()
            db.exec("DROP TABLE inbox_source")
            assertThrows(IllegalStateException::class.java) { MigrationRunner(db).verifyIntegrity() }
        }
        fresh().use { db ->
            MigrationRunner(db).migrate()
            db.exec("DROP TABLE ent_payout_used")
            val e = assertThrows(IllegalStateException::class.java) { MigrationRunner(db).verifyIntegrity() }
            assertTrue(e.message!!, e.message!!.contains("ent_payout_used"))
        }
        atV1().use { db ->
            // A v1 database (tables of v2 missing, version 1) is refused, never used.
            assertThrows(IllegalStateException::class.java) { MigrationRunner(db).verifyIntegrity() }
        }
        atV2WithData().use { db ->
            // So is a v2 database (entitlement tables missing, version 2).
            assertThrows(IllegalStateException::class.java) { MigrationRunner(db).verifyIntegrity() }
        }
    }

    @Test
    fun connectionPragmasAreAppliedOnOpen() {
        fresh().use { db ->
            for ((pragma, expected) in Schema.expectedPragmaValues) {
                assertEquals(pragma, expected, db.queryLong("PRAGMA $pragma"))
            }
        }
    }

    @Test
    fun droppingAnyConnectionPragmaIsCaught() {
        // The list sets exactly the pragmas verifyIntegrity asserts.
        val named = Schema.connectionPragmas.map { Regex("""PRAGMA (\w+) = """).find(it)!!.groupValues[1] }
        assertEquals(Schema.expectedPragmaValues.keys, named.toSet())
        assertEquals(named.size, named.toSet().size)
        // Without the list, the JVM connection starts at values that differ from every expected one
        // (synchronous NORMAL as on device), so a missing pragma is visible here, not only at runtime.
        JdbcSqlExecutor(pragmas = emptyList()).use { db ->
            for ((pragma, expected) in Schema.expectedPragmaValues) {
                assertTrue(pragma, db.queryLong("PRAGMA $pragma") != expected)
            }
        }
        for ((i, dropped) in Schema.connectionPragmas.withIndex()) {
            JdbcSqlExecutor(pragmas = Schema.connectionPragmas - dropped).use { db ->
                MigrationRunner(db).migrate()
                val e = assertThrows(IllegalStateException::class.java) { MigrationRunner(db).verifyIntegrity() }
                assertTrue(e.message!!, e.message!!.contains("PRAGMA ${named[i]} "))
            }
        }
    }

    @Test
    fun noPlaintextContentColumnsExist() {
        // Every content-bearing column is an envelope/ciphertext by name; guards schema drift.
        fresh().use { db ->
            MigrationRunner(db).migrate()
            val suspicious = ArrayList<String>()
            for (t in Schema.expectedTables) {
                db.query("PRAGMA table_info($t)") { row ->
                    val col = row.string(1)
                    if (col in setOf("body", "text", "plaintext", "content", "message")) suspicious += "$t.$col"
                }
            }
            assertTrue("plaintext-looking columns: $suspicious", suspicious.isEmpty())
        }
    }

    @Test
    fun constraintsRejectBadRows() {
        fresh().use { db ->
            MigrationRunner(db).migrate()
            db.exec("INSERT INTO channels(channel_id, history_policy, created_at) VALUES (?, 'none', 1)", listOf(ByteArray(32)))
            // Minute granularity is enforced by the schema (ADR-08).
            assertThrows(Exception::class.java) {
                db.exec(
                    "INSERT INTO posts(operation_id, channel_id, author_pseudonym, envelope, content_type, posted_at_minute, state) VALUES (?, ?, ?, ?, 'text', 61, 'received')",
                    listOf(ByteArray(16), ByteArray(32), ByteArray(32), ByteArray(8)),
                )
            }
            // Foreign key: a post for an unknown channel is rejected.
            assertThrows(Exception::class.java) {
                db.exec(
                    "INSERT INTO posts(operation_id, channel_id, author_pseudonym, envelope, content_type, posted_at_minute, state) VALUES (?, ?, ?, ?, 'text', 60, 'received')",
                    listOf(ByteArray(16), ByteArray(32) { 9 }, ByteArray(32), ByteArray(8)),
                )
            }
            // Blob size cap: relay payloads above 64 KiB never enter the outbox (only bucket sizes do).
            db.exec("INSERT INTO sync_namespace(namespace_id, consumer, listening) VALUES (?, 'dm', 1)", listOf(ByteArray(32) { 1 }))
            val insertOp =
                "INSERT INTO outbox_op(operation_id, namespace_id, blob_hash, ciphertext, ttl_seconds, not_before_minute, required_operators, outcome) " +
                    "VALUES (?, ?, ?, ?, 604800, 0, 2, 'pending')"
            for (tooBig in listOf(65537, 131072)) {
                val e = assertThrows(java.sql.SQLException::class.java) {
                    db.exec(insertOp, listOf(ByteArray(16), ByteArray(32) { 1 }, ByteArray(32) { 2 }, ByteArray(tooBig)))
                }
                assertTrue(e.message!!, e.message!!.contains("CHECK constraint failed"))
            }
            db.exec(insertOp, listOf(ByteArray(16), ByteArray(32) { 1 }, ByteArray(32) { 2 }, ByteArray(65536)))
            // Cascade: deleting the channel removes its pseudonym and MLS state.
            db.exec("INSERT INTO channel_pseudonyms(channel_id, pseudonym_public_key) VALUES (?, ?)", listOf(ByteArray(32), ByteArray(32) { 1 }))
            db.exec("DELETE FROM channels WHERE channel_id = ?", listOf(ByteArray(32)))
            assertEquals(null, db.queryLong("SELECT 1 FROM channel_pseudonyms"))
        }
    }
}
