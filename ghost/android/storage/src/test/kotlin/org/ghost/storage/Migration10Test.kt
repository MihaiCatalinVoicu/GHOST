package org.ghost.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Phase 13 design §10 (Q40): migration 10 — the UI's own state. One transaction, append-only,
 * fail-closed: the guard refuses a database that already has `ui_*` tables, the settings row is
 * exactly the §10 defaults, the PIN record has no retry time (§5.2, T33), and the crash table
 * is bounded by its CHECKs.
 */
class Migration10Test {
    private val upToV9 = Schema.migrations.filter { it.version <= 9 }

    private fun fresh(): JdbcSqlExecutor {
        val db = JdbcSqlExecutor()
        MigrationRunner(db).migrate()
        return db
    }

    @Test
    fun freshInstallCreatesTheUiTablesWithTheDefaults() {
        fresh().use { db ->
            assertEquals(1L, db.queryLong("SELECT count(*) FROM ui_settings"))
            assertEquals(0L, db.queryLong("SELECT privacy_mode FROM ui_settings WHERE id = 1"))
            assertEquals(60L, db.queryLong("SELECT lock_timeout_s FROM ui_settings WHERE id = 1"))
            assertEquals(0L, db.queryLong("SELECT biometric FROM ui_settings WHERE id = 1"))
            assertEquals(1L, db.queryLong("SELECT notif_mode FROM ui_settings WHERE id = 1"))
            assertEquals(0L, db.queryLong("SELECT notif_lockscreen FROM ui_settings WHERE id = 1"))
            assertEquals(0L, db.queryLong("SELECT a11y_hide FROM ui_settings WHERE id = 1"))
            assertEquals(0L, db.queryLong("SELECT onboarding_step FROM ui_settings WHERE id = 1"))
            assertEquals(0L, db.queryLong("SELECT backup_verified FROM ui_settings WHERE id = 1"))
            assertNull(db.queryString("SELECT clip_label FROM ui_settings WHERE id = 1"))
            assertEquals(0L, db.queryLong("SELECT count(*) FROM ui_lock"))
            assertEquals(0L, db.queryLong("SELECT count(*) FROM ui_crash"))
            assertNull(db.queryLong("PRAGMA foreign_key_check"))
        }
    }

    @Test
    fun anUpgradeTakesMigration10() {
        JdbcSqlExecutor().use { db ->
            MigrationRunner(db, upToV9).migrate()
            assertEquals(listOf(10, 11), MigrationRunner(db).migrate())
            assertEquals(1L, db.queryLong("SELECT count(*) FROM ui_settings"))
        }
    }

    @Test
    fun theGuardRefusesAnExistingUiTable() {
        JdbcSqlExecutor().use { db ->
            MigrationRunner(db, upToV9).migrate()
            db.exec("CREATE TABLE ui_settings (id INTEGER PRIMARY KEY)")
            // The guard's CHECK fails inside the transaction; the runner surfaces it as a
            // persistence error (SQLiteException through the executor).
            assertThrows(Exception::class.java) { MigrationRunner(db).migrate() }
        }
    }

    @Test
    fun theCheckConstraintsHold() {
        fresh().use { db ->
            assertThrows(Exception::class.java) {
                db.exec("INSERT INTO ui_settings (id) VALUES (2)")
            }
            assertThrows(Exception::class.java) {
                db.exec("UPDATE ui_settings SET lock_timeout_s = 90 WHERE id = 1")
            }
            assertThrows(Exception::class.java) {
                db.exec("UPDATE ui_settings SET privacy_mode = 7 WHERE id = 1")
            }
            assertThrows(Exception::class.java) {
                db.exec(
                    "INSERT INTO ui_lock (id, salt, tag, failures) VALUES (1, x'00', x'00', 0)",
                )
            }
            // A well-formed record is accepted (the LockController's store seam writes exactly this).
            db.exec(
                "INSERT INTO ui_lock (id, salt, tag, failures) VALUES (1, randomblob(16), randomblob(32), 0)",
            )
            assertEquals(1L, db.queryLong("SELECT count(*) FROM ui_lock"))
            // But the failure counter refuses a negative count.
            assertThrows(Exception::class.java) {
                db.exec(
                    "UPDATE ui_lock SET failures = -1 WHERE id = 1",
                )
            }
        }
    }

    @Test
    fun theExpectedTableSetIncludesTheUiTables() {
        assertTrue(Schema.expectedTables.containsAll(setOf("ui_settings", "ui_lock", "ui_crash")))
    }
}
