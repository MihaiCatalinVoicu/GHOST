package org.ghost.storage

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SchemaAndMigrationTest {
    private fun fresh(): JdbcSqlExecutor = JdbcSqlExecutor()

    private val v1Only = Schema.migrations.filter { it.version == 1 }
    private val v2 = Schema.migrations.single { it.version == 2 }

    /** A database at v1 exactly as Phase 4 shipped it. */
    private fun atV1(): JdbcSqlExecutor = fresh().also {
        assertEquals(listOf(1), MigrationRunner(it, v1Only).migrate())
        assertEquals(1, it.userVersion)
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

    /** Rows in tables that v2 keeps, written at v1. */
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

    @Test
    fun freshDatabaseMigratesToCurrentVersionWithAllTables() {
        fresh().use { db ->
            val applied = MigrationRunner(db).migrate()
            assertEquals(listOf(1, 2), applied)
            assertEquals(Schema.CURRENT_VERSION, db.userVersion)
            MigrationRunner(db).verifyIntegrity()
            assertEquals(Schema.expectedTables, db.names("table"))
            assertEquals(Schema.expectedTriggers, db.names("trigger"))
            assertEquals(12, Schema.expectedTriggers.size)
        }
    }

    @Test
    fun currentVersionIsTheLastMigration() {
        assertEquals(Schema.CURRENT_VERSION, Schema.migrations.maxOf { it.version })
        assertEquals(Schema.migrations.map { it.version }.distinct().size, Schema.migrations.size)
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
    fun v1DatabaseWithDataMigratesToV2AndKeepsIt() {
        atV1().use { db ->
            seedV1Data(db)
            assertEquals(listOf(2), MigrationRunner(db).migrate())
            MigrationRunner(db).verifyIntegrity()
            assertV1DataIntact(db)
            assertEquals(Schema.expectedTables, db.names("table"))
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
            assertEquals(listOf(2), MigrationRunner(db).migrate())
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
                assertEquals(listOf(2), MigrationRunner(db).migrate())
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
            assertEquals(listOf(2), MigrationRunner(db).migrate())
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
            assertEquals(listOf(1, 2), MigrationRunner(db).migrate())
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
            assertEquals(listOf(1, 2), helperOpen(db))
            MigrationRunner(db).verifyIntegrity()
            assertEquals(emptyList<Int>(), MigrationRunner(db).migrate())
        }
        atV1().use { db ->
            seedV1Data(db)
            assertEquals(listOf(2), helperOpen(db))
            MigrationRunner(db).verifyIntegrity()
            assertV1DataIntact(db)
        }
        atV1().use { db ->
            db.exec("INSERT INTO sync_cursor(namespace_id) VALUES (?)", listOf(ByteArray(32)))
            val before = db.schemaSnapshot()
            assertThrows(java.sql.SQLException::class.java) { helperOpen(db) }
            assertEquals(1, db.userVersion)
            assertEquals(before, db.schemaSnapshot())
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
        atV1().use { db ->
            // A v1 database (tables of v2 missing, version 1) is refused, never used.
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
