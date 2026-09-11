package org.ghost.sync.engine

import org.ghost.network.OnionAddress
import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import org.ghost.sync.api.BlobHash
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.EnqueueResult
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.OutboundBlob
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.RelayEntry
import org.ghost.sync.api.SyncDatabase
import org.ghost.sync.api.TtlBucket
import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.port.FetchedBlob
import org.ghost.sync.port.ListPage
import org.ghost.sync.port.RelayPort
import org.ghost.sync.port.StoreReceipt
import org.ghost.sync.port.SyncClock
import org.ghost.sync.port.TransportPort
import org.ghost.sync.port.TransportState
import org.ghost.sync.store.SyncStores
import org.ghost.sync.store.TestBytes
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.util.Collections
import java.util.concurrent.ThreadFactory

/**
 * The production runner on real threads and the real clock (design §1.4, §5.4): both lanes run
 * concurrently over one database, a stop drains and ends every thread, and a throwable from an item
 * stops the runner without being caught (design §11.2 #11).
 */
class ThreadedLaneRunnerTest {

    private object RealClock : SyncClock {
        override fun epochSeconds(): Long = System.currentTimeMillis() / 1000

        override fun monotonicMillis(): Long = System.nanoTime() / 1_000_000
    }

    /** A thread-safe relay that answers at once: lists everything, stores and checks honestly. */
    private class QuickRelays : RelayPort {
        private val held = Collections.synchronizedMap(HashMap<Pair<OnionAddress, NamespaceId>, MutableMap<BlobHash, ByteArray>>())
        val lists = Collections.synchronizedList(ArrayList<Pair<OnionAddress, Long>>())
        val stores = Collections.synchronizedList(ArrayList<OnionAddress>())

        private fun space(relay: OnionAddress, ns: NamespaceId) = held.getOrPut(Pair(relay, ns)) { Collections.synchronizedMap(LinkedHashMap()) }

        override fun store(relay: OnionAddress, ns: NamespaceId, capability: ByteArray, ciphertext: ByteArray, ttlSeconds: Int, deadlineMillis: Int): StoreReceipt {
            stores += relay
            val hash = TestBytes.sha256(ciphertext)
            space(relay, ns)[hash] = ciphertext.copyOf()
            return StoreReceipt(hash, RealClock.epochSeconds() + ttlSeconds + 3_600)
        }

        override fun get(relay: OnionAddress, ns: NamespaceId, capability: ByteArray, hash: BlobHash, deadlineMillis: Int): FetchedBlob =
            FetchedBlob(checkNotNull(space(relay, ns)[hash]), RealClock.epochSeconds() + 86_400)

        override fun list(relay: OnionAddress, ns: NamespaceId, capability: ByteArray, cursor: ByteArray, limit: Int, deadlineMillis: Int): ListPage {
            lists += Pair(relay, RealClock.monotonicMillis())
            return ListPage(synchronized(space(relay, ns)) { space(relay, ns).keys.take(limit) }, ByteArray(0))
        }

        override fun check(relay: OnionAddress, ns: NamespaceId, capability: ByteArray, hashes: List<BlobHash>, deadlineMillis: Int): Set<BlobHash> =
            hashes.filter { space(relay, ns).containsKey(it) }.toSet()
    }

    private class QuickTransport(override val relays: RelayPort) : TransportPort {
        override fun ensureReady(deadlineMonotonicMillis: Long): TransportState = TransportState.READY

        override fun abort() = Unit
    }

    private class Captured : ThreadFactory {
        val failures: MutableList<Throwable> = Collections.synchronizedList(ArrayList())

        override fun newThread(r: Runnable): Thread = Thread(r, "ghost-sync-test").apply {
            isDaemon = true
            setUncaughtExceptionHandler { _, e -> failures += e }
        }
    }

    private class World(steps: Steps = Steps.DEFAULT) : AutoCloseable {
        private val dir: File = Files.createTempDirectory("ghost-runner-test").toFile()
        val sql = JdbcSqlExecutor(File(dir, "sync.db").absolutePath).also { MigrationRunner(it).migrate() }
        val db = SyncDatabase(sql)
        val random = KeyedRandomSources()
        val stores = SyncStores(db, RealClock, random) { PrivacyMode.STANDARD }
        val relays = QuickRelays()
        val policy = TrafficPolicy(intervalMillis = 100, passIntervalMillis = 50, lateToleranceMillis = 2_000)
        val engine = SyncEngine(stores, QuickTransport(relays), RealClock, random, policy, steps) { PrivacyMode.STANDARD }
        val addresses = (1..3).map { TestBytes.onion(it) }
        val ns: NamespaceId = TestBytes.namespace(1)

        init {
            val ids = db.transaction { tx ->
                stores.relayDirectory.upsert(tx, addresses.mapIndexed { i, a -> RelayEntry(a, TestBytes.of(16, 500 + i), RelayEntry.Source.CONFIG) })
            }
            db.transaction { tx -> stores.namespaces.register(tx, ns, Consumer.DM, ids.values.toSet(), listen = true) }
            db.transaction { tx -> ids.values.forEach { stores.capabilities.put(tx, it, ns, CapabilityKind.WRITE, TestBytes.of(82, it.value.toInt()), null) } }
        }

        override fun close() {
            sql.close()
            dir.deleteRecursively()
        }
    }

    private fun waitFor(timeoutMillis: Long, condition: () -> Boolean): Boolean {
        val end = System.nanoTime() + timeoutMillis * 1_000_000
        while (System.nanoTime() < end) {
            if (condition()) return true
            Thread.sleep(10)
        }
        return condition()
    }

    @Test
    fun bothLanesRunOnThreadsAndStopEndsEveryThread(): Unit = World().use { w ->
        val threads = Captured()
        val session = w.engine.startSession(SessionKind.FOREGROUND)
        val runner = ThreadedLaneRunner(session, RealClock, threads)
        runner.start()
        assertTrue(waitFor(5_000) { session.online })
        val op = TestBytes.op(1)
        val result = w.db.transaction { tx -> w.stores.outbox.enqueue(tx, OutboundBlob(op, w.ns, TestBytes.ciphertext(1), TtlBucket.DAYS_7)) }
        assertEquals(EnqueueResult.Enqueued, result)
        session.expedite()
        assertTrue("stored on 3 relays and verified by listing", waitFor(10_000) { w.stores.outbox.outcomes(Consumer.DM, 1).isNotEmpty() })
        assertTrue("every read pair listed", waitFor(5_000) { w.addresses.all { a -> w.relays.lists.any { it.first == a } } })
        session.stop()
        assertTrue(runner.awaitStopped(5_000))
        assertTrue(session.isFinished())
        assertFalse(runner.hasFailed)
        assertEquals(emptyList<Throwable>(), threads.failures.toList())
        assertEquals(3, w.relays.stores.size)
    }

    @Test
    fun aThrowableFromAnItemStopsTheRunnerUncaught(): Unit = World(Steps(list = object : ListStep() {
        override fun page(ctx: EngineContext, request: ReadItem): PageOutcome = throw AssertionError("injected process death")
    })).use { w ->
        val threads = Captured()
        val session = w.engine.startSession(SessionKind.FOREGROUND)
        val runner = ThreadedLaneRunner(session, RealClock, threads)
        runner.start()
        assertTrue(runner.awaitStopped(10_000))
        assertTrue(runner.hasFailed)
        // Each read worker that took an item before the stop reports its own error; nothing else fails.
        assertTrue(threads.failures.isNotEmpty())
        assertTrue(threads.failures.all { it is AssertionError })
    }
}
