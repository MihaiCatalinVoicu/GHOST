package org.ghost.app.ui

import java.security.SecureRandom
import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import org.ghost.storage.queryLong
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Phase 13 §5.2: the ui_lock persistence half — insert then upsert, the record's exact shape
 * (16-byte salt, 32-byte tag, the counter), and the null answer while no database exists.
 */
class LockStoreTest {
    private fun db(): JdbcSqlExecutor {
        val db = JdbcSqlExecutor()
        MigrationRunner(db).migrate()
        return db
    }

    @Test
    fun insertThenUpsertKeepsOneRow() {
        val db = db()
        val store = LockStore({ db })
        assertNull(store.read())
        val salt = ByteArray(16).also(SecureRandom()::nextBytes)
        val tag = ByteArray(32) { it.toByte() }
        store.write(LockController.PinRecord(salt, tag, failures = 0))
        store.read()!!.let {
            assertArrayEquals(salt, it.salt)
            assertArrayEquals(tag, it.tag)
            assertEquals(0, it.failures)
        }
        // The counter commits (MC-U14's order is the controller's; the store upserts one row).
        store.write(LockController.PinRecord(salt, tag, failures = 5))
        assertEquals(5, store.read()!!.failures)
        assertEquals(1L, db.queryLong("SELECT count(*) FROM ui_lock"))
    }

    @Test
    fun withoutADatabaseTheStoreAnswersNull() {
        val store = LockStore({ null })
        assertNull(store.read())
        store.write(LockController.PinRecord(ByteArray(16), ByteArray(32), 0))
    }
}
