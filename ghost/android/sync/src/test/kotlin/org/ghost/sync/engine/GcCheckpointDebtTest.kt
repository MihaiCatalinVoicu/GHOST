package org.ghost.sync.engine

import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.store.TestBytes
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.sql.Connection
import java.sql.DriverManager

/**
 * The sweeper's checkpoint debt (Phase 9 design §10.7): a `wal_checkpoint(TRUNCATE)` that stayed
 * busy is owed to the next pass of the same sweeper, and to that one only. Steps are injected per
 * engine ([Steps.default]), so the debt of one engine — one world of the harness, or an engine
 * rebuilt after a wipe — is never paid or cleared by another.
 */
class GcCheckpointDebtTest {

    /** A consumed blob's tombstone whose retention has passed, so a sweep deletes it. */
    private fun EngineWorld.expiredTombstone(ns: NamespaceId, seed: Int) =
        raw("INSERT INTO inbox_blob(namespace_id, blob_hash, state, retain_until_day) VALUES (?, ?, 'done', 0)", ns, TestBytes.hash(seed))

    /** A listening pair, the write-ahead log, and an online session whose work context runs the step. */
    private fun EngineWorld.sweeper(): Pair<WorkContext, NamespaceId> {
        val relays = relays(1)
        val ns = namespace(1, relays)
        relays.forEach { capability(it, ns, CapabilityKind.READ) }
        sql.query("PRAGMA journal_mode = WAL") { }
        val (session, driver) = session()
        driver.runUntil(0)
        check(session.online)
        return Pair(session.workContext, ns)
    }

    /** Bytes of the write-ahead log; 0 once a checkpoint truncated it. */
    private fun EngineWorld.walBytes(): Long = java.io.File(databaseFile.absolutePath + "-wal").length()

    /** A second connection holding a read transaction: every TRUNCATE checkpoint stays busy. */
    private fun EngineWorld.reader(): Connection {
        val conn = DriverManager.getConnection("jdbc:sqlite:${databaseFile.absolutePath}")
        conn.autoCommit = false
        conn.createStatement().use { it.executeQuery("SELECT count(*) FROM inbox_blob").close() }
        return conn
    }

    @Test
    fun aBusyCheckpointIsOwedToItsOwnSweeperOnly() {
        EngineWorld().use { a ->
            EngineWorld().use { b ->
                assertNotSame("each engine sweeps with its own step", a.engine.steps.gc, b.engine.steps.gc)
                val (ctxA, nsA) = a.sweeper()
                val (ctxB, _) = b.sweeper()
                // A deletes a row while another connection holds its log: the checkpoint stays busy
                // and the truncation is owed to A's next pass.
                a.expiredTombstone(nsA, 1)
                val reader = a.reader()
                try {
                    assertEquals(1, a.engine.steps.gc.run(ctxA)?.total)
                    assertTrue("the log was held, so it was not truncated", a.walBytes() > 0)
                } finally {
                    reader.close()
                }
                // B sweeps with nothing to delete: it owes no checkpoint of its own and pays none of A's.
                assertEquals(0, b.engine.steps.gc.run(ctxB)?.total)
                assertTrue("A still owes its checkpoint", a.walBytes() > 0)
                // A's next pass pays the debt it kept, although that pass deletes nothing.
                assertEquals(0, a.engine.steps.gc.run(ctxA)?.total)
                assertEquals("the truncated log", 0L, a.walBytes())
                // The debt is paid once: a further pass leaves the log alone.
                a.raw("INSERT INTO inbox_blob(namespace_id, blob_hash, state, retain_until_day) VALUES (?, ?, 'done', 999999)", nsA, TestBytes.hash(2))
                assertEquals(0, a.engine.steps.gc.run(ctxA)?.total)
                assertTrue("nothing was deleted, so no checkpoint ran", a.walBytes() > 0)
            }
        }
    }
}
