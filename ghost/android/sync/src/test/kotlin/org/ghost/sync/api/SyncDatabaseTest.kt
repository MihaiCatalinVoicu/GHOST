package org.ghost.sync.api

import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import org.ghost.sync.store.SyncWorld
import org.ghost.sync.store.TestBytes
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/** SyncDatabase concurrency contract (design §9, §11.2 #10) and post-commit hints. */
class SyncDatabaseTest {

    @Test
    fun nestedTransactionOnTheSameThreadThrowsAndKeepsTheOuterWork(): Unit = SyncWorld().use { w ->
        val relays = w.relays(1, 2)
        val ns = w.namespace(1, relays)
        w.tx { tx ->
            tx.sql.exec("UPDATE sync_namespace SET listening = 0 WHERE namespace_id = ?", listOf(ns.toByteArray()))
            val e = assertThrows(IllegalStateException::class.java) { w.db.transaction { } }
            assertEquals("nested sync transaction on the same thread", e.message)
            assertTrue(w.db.inTransaction)
        }
        assertFalse(w.db.inTransaction)
        assertEquals(0L, w.long("SELECT listening FROM sync_namespace"))
    }

    @Test
    fun transactionsOfTwoThreadsNeverInterleave() {
        val sql = JdbcSqlExecutor().also { MigrationRunner(it).migrate() }
        sql.use {
            val db = SyncDatabase(sql)
            val log = Collections.synchronizedList(ArrayList<String>())
            val firstInside = CountDownLatch(1)
            val release = CountDownLatch(1)
            val a = thread {
                db.transaction {
                    log += "a-begin"
                    firstInside.countDown()
                    release.await(10, TimeUnit.SECONDS)
                    log += "a-end"
                }
            }
            assertTrue(firstInside.await(10, TimeUnit.SECONDS))
            val b = thread {
                db.transaction {
                    log += "b-begin"
                    log += "b-end"
                }
            }
            // b waits on the SyncDatabase lock while a is inside its transaction.
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
            while (db.waitingThreads == 0 && System.nanoTime() < deadline) Thread.onSpinWait()
            assertEquals(1, db.waitingThreads)
            assertEquals(listOf("a-begin"), log.toList())
            release.countDown()
            a.join(10_000)
            b.join(10_000)
            assertEquals(listOf("a-begin", "a-end", "b-begin", "b-end"), log.toList())
        }
    }

    @Test
    fun manyThreadsInterleavingTransactionsKeepEachOneAtomic() {
        val sql = JdbcSqlExecutor().also { MigrationRunner(it).migrate() }
        sql.use {
            val db = SyncDatabase(sql)
            sql.exec("CREATE TABLE counter (id INTEGER PRIMARY KEY, value INTEGER NOT NULL)")
            sql.exec("INSERT INTO counter(id, value) VALUES (1, 0)")
            val threads = (1..4).map {
                thread {
                    repeat(50) {
                        db.transaction { tx ->
                            var v = 0L
                            tx.sql.query("SELECT value FROM counter WHERE id = 1") { r -> v = r.long(0) }
                            Thread.yield()
                            tx.sql.exec("UPDATE counter SET value = ? WHERE id = 1", listOf(v + 1))
                        }
                    }
                }
            }
            threads.forEach { it.join(30_000) }
            var value = 0L
            sql.query("SELECT value FROM counter WHERE id = 1") { value = it.long(0) }
            assertEquals(200L, value)
        }
    }

    @Test
    fun hintsArriveAfterCommitOnlyAndListenersMayOpenTransactions(): Unit = SyncWorld().use { w ->
        val relays = w.relays(1, 2)
        val ns = w.namespace(1, relays)
        w.hints.clear()
        var insideDuringHint: Boolean? = null
        var nestedWorked = false
        w.stores.inbox.setListener { changes ->
            insideDuringHint = w.db.inTransaction
            w.db.transaction { nestedWorked = true }
            w.hints += changes
        }
        w.capability(relays[0], ns)
        assertEquals(listOf(setOf(SyncChange.CAPABILITIES)), w.hints)
        assertEquals(false, insideDuringHint)
        assertTrue(nestedWorked)
        // A rolled-back transaction delivers nothing.
        w.hints.clear()
        assertThrows(IllegalArgumentException::class.java) {
            w.tx { tx ->
                w.stores.capabilities.put(tx, relays[1], ns, CapabilityKind.WRITE, TestBytes.of(82, 9), null)
                throw IllegalArgumentException("roll back")
            }
        }
        assertTrue(w.hints.isEmpty())
        assertEquals(0L, w.count("relay_capability", "relay_id = ?", relays[1]))
    }

    @Test
    fun aTransactionObjectIsUsableOnlyInsideItsBlockAndOnItsThread(): Unit = SyncWorld().use { w ->
        val relays = w.relays(1, 2)
        val ns = w.namespace(1, relays)
        val leaked = w.tx { it }
        val stale = assertThrows(IllegalStateException::class.java) {
            w.stores.inbox.markConsumed(leaked, ns, TestBytes.hash(1))
        }
        assertEquals("sync transaction is not active", stale.message)
        w.tx { tx ->
            var foreign: Throwable? = null
            thread { foreign = runCatchingState { w.stores.inbox.defer(tx, ns, TestBytes.hash(1), 60) } }.join(10_000)
            assertEquals("sync transaction is not active", foreign?.message)
        }
        val other = SyncWorld()
        other.use {
            it.tx { tx ->
                val e = assertThrows(IllegalStateException::class.java) { w.stores.inbox.markConsumed(tx, ns, TestBytes.hash(1)) }
                assertEquals("sync transaction is not active", e.message)
            }
        }
    }

    private fun runCatchingState(block: () -> Unit): Throwable? =
        try {
            block()
            null
        } catch (e: IllegalStateException) {
            e
        }
}
