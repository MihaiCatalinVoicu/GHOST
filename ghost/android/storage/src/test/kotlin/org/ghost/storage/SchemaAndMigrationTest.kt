package org.ghost.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SchemaAndMigrationTest {
    private fun fresh(): JdbcSqlExecutor = JdbcSqlExecutor()

    @Test
    fun freshDatabaseMigratesToCurrentVersionWithAllTables() {
        fresh().use { db ->
            val applied = MigrationRunner(db).migrate()
            assertEquals(listOf(1), applied)
            assertEquals(Schema.CURRENT_VERSION, db.userVersion)
            MigrationRunner(db).verifyIntegrity()
            val tables = HashSet<String>()
            db.query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'") { tables += it.string(0) }
            assertEquals(Schema.expectedTables, tables)
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
    fun interruptedMigrationLeavesPreviousVersionAndNoPartialSchema() {
        fresh().use { db ->
            db.failOnStatementContaining = "CREATE TABLE posts"
            assertThrows(IllegalStateException::class.java) { MigrationRunner(db).migrate() }
            assertEquals(0, db.userVersion)
            val tables = HashSet<String>()
            db.query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'") { tables += it.string(0) }
            assertTrue("rollback must remove partially created tables, found $tables", tables.isEmpty())
            // Recovery path: the same runner succeeds once the fault is gone.
            db.failOnStatementContaining = null
            assertEquals(listOf(1), MigrationRunner(db).migrate())
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
            // Blob size cap: relay payloads above 64 KiB never enter the queue.
            assertThrows(Exception::class.java) {
                db.exec(
                    "INSERT INTO relay_queue(operation_id, kind, payload, target_policy, next_retry_at) VALUES (?, 'store', ?, 'any2', 0)",
                    listOf(ByteArray(16), ByteArray(65537)),
                )
            }
            // Cascade: deleting the channel removes its pseudonym and MLS state.
            db.exec("INSERT INTO channel_pseudonyms(channel_id, pseudonym_public_key) VALUES (?, ?)", listOf(ByteArray(32), ByteArray(32) { 1 }))
            db.exec("DELETE FROM channels WHERE channel_id = ?", listOf(ByteArray(32)))
            assertEquals(null, db.queryLong("SELECT 1 FROM channel_pseudonyms"))
        }
    }
}
