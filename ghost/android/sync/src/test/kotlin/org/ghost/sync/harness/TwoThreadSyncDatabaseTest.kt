package org.ghost.sync.harness

import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.BlobHash
import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.OperationId
import org.ghost.sync.api.OutboundBlob
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.RelayEntry
import org.ghost.sync.api.SyncDatabase
import org.ghost.sync.api.TtlBucket
import org.ghost.sync.store.FixedRandom
import org.ghost.sync.store.ManualClock
import org.ghost.sync.store.SyncStores
import org.ghost.sync.store.TestBytes
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Design §11.2 #10: every lane and consumer transaction goes through one [SyncDatabase] lock. Two
 * real threads (a work lane enqueuing and leasing, a consumer listing, fetching, claiming and
 * consuming) run concurrent transactions over one `JdbcSqlExecutor`; a recording executor proves
 * that no statement of one thread ever lands inside the other thread's open transaction, and the
 * end state is exactly what both threads did.
 */
class TwoThreadSyncDatabaseTest {

    /** Records the thread owning the open transaction; a statement of another thread inside it is a violation. */
    private class Recording(private val delegate: SqlExecutor) : SqlExecutor {
        @Volatile
        var owner: Thread? = null
        val violation = AtomicReference<String?>(null)
        val transactions = AtomicInteger()

        private fun statement() {
            val o = owner
            if (o != null && o !== Thread.currentThread()) violation.compareAndSet(null, "a statement of ${Thread.currentThread().name} ran inside ${o.name}'s transaction")
        }

        override fun exec(sql: String, args: List<Any?>) { statement(); delegate.exec(sql, args) }
        override fun execUpdate(sql: String, args: List<Any?>): Int { statement(); return delegate.execUpdate(sql, args) }
        override fun query(sql: String, args: List<Any?>, onRow: (SqlExecutor.Row) -> Unit) { statement(); delegate.query(sql, args, onRow) }
        override fun <T> transaction(block: () -> T): T = delegate.transaction {
            if (owner != null) violation.compareAndSet(null, "two transactions open at once")
            owner = Thread.currentThread()
            transactions.incrementAndGet()
            try {
                block()
            } finally {
                owner = null
            }
        }
        override val inTransaction: Boolean get() = delegate.inTransaction
        override var userVersion: Int
            get() = delegate.userVersion
            set(v) { delegate.userVersion = v }
    }

    @Test
    fun concurrentLaneAndConsumerTransactionsNeverInterleave() {
        val dir = Files.createTempDirectory("ghost-two-threads").toFile()
        val jdbc = JdbcSqlExecutor(File(dir, "sync.db").absolutePath)
        try {
            MigrationRunner(jdbc).migrate()
            MigrationRunner(jdbc).verifyIntegrity()
            val sql = Recording(jdbc)
            val db = SyncDatabase(sql)
            val clock = ManualClock(1_800_000_000L)
            val stores = SyncStores(db, clock, FixedRandom()) { PrivacyMode.STANDARD }
            val entries = (1..3).map { RelayEntry(TestBytes.onion(40 + it), TestBytes.of(16, 800 + it), RelayEntry.Source.CONFIG) }
            val ids = db.transaction { stores.relayDirectory.upsert(it, entries) }.values.toList()
            val out = NamespaceId(TestBytes.of(32, 1))
            val inbox = NamespaceId(TestBytes.of(32, 2))
            db.transaction { tx ->
                stores.namespaces.register(tx, out, Consumer.DM, ids.toSet(), listen = false)
                stores.namespaces.register(tx, inbox, Consumer.CHANNEL, ids.toSet(), listen = true)
                ids.forEach { r -> stores.capabilities.put(tx, r, out, CapabilityKind.WRITE, TestBytes.of(82, r.value.toInt()), null) }
            }
            val rounds = 150
            val barrier = CyclicBarrier(2)
            val failure = AtomicReference<Throwable?>(null)
            val lane = Thread({
                try {
                    barrier.await()
                    for (i in 0 until rounds) {
                        val op = OperationId(TestBytes.of(16, 10_000 + i))
                        db.transaction { tx -> stores.outbox.enqueue(tx, OutboundBlob(op, out, TestBytes.ciphertext(i), TtlBucket.DAYS_7)) }
                        val due = db.transaction { tx -> stores.outboxStore.dueStores(tx, clock.now, 1) }
                        for (d in due) db.transaction { tx -> stores.outboxStore.lease(tx, d.operationId, d.relayId, clock.now, 60) }
                    }
                } catch (t: Throwable) {
                    failure.compareAndSet(null, t)
                }
            }, "work-lane")
            val consumer = Thread({
                try {
                    barrier.await()
                    for (i in 0 until rounds) {
                        val bytes = TestBytes.ciphertext(50_000 + i)
                        val hash = BlobHash(java.security.MessageDigest.getInstance("SHA-256").digest(bytes))
                        db.transaction { tx -> stores.inboxStore.commitPage(tx, ids[i % 3], inbox, listOf(hash), ByteArray(0), clock.now) }
                        db.transaction { tx -> stores.inboxStore.leaseFetch(tx, inbox, hash, clock.now, 60) }
                        db.transaction { tx -> stores.inboxStore.recordFetched(tx, inbox, hash, bytes, clock.now + 86_400) }
                        for (b in stores.inbox.claim(Consumer.CHANNEL, 4)) db.transaction { tx -> stores.inbox.markConsumed(tx, b.namespace, b.hash) }
                    }
                } catch (t: Throwable) {
                    failure.compareAndSet(null, t)
                }
            }, "consumer")
            lane.start()
            consumer.start()
            lane.join(120_000)
            consumer.join(120_000)
            failure.get()?.let { throw AssertionError("a thread failed", it) }
            assertEquals(null, sql.violation.get())
            assertTrue(sql.transactions.get() >= rounds * 6)
            var ops = 0L
            var leased = 0L
            var consumed = 0L
            jdbc.query("SELECT (SELECT count(*) FROM outbox_op), (SELECT count(*) FROM outbox_delivery WHERE inflight = 1), (SELECT count(*) FROM inbox_blob WHERE state = 'done')") {
                ops = it.long(0)
                leased = it.long(1)
                consumed = it.long(2)
            }
            assertEquals(rounds.toLong(), ops)
            assertTrue(leased >= rounds)
            assertEquals(rounds.toLong(), consumed)
        } finally {
            jdbc.close()
            dir.deleteRecursively()
        }
    }
}
