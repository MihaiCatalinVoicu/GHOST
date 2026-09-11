package org.ghost.sync.android

import org.ghost.network.NetworkException
import org.ghost.network.OnionAddress
import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.BlobHash
import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.RelayEntry
import org.ghost.sync.api.SyncDatabase
import org.ghost.sync.api.TransportStatus
import org.ghost.sync.engine.KeyedRandomSources
import org.ghost.sync.engine.SessionKind
import org.ghost.sync.engine.TrafficPolicy
import org.ghost.sync.port.FetchedBlob
import org.ghost.sync.port.ListPage
import org.ghost.sync.port.RelayPort
import org.ghost.sync.port.StoreReceipt
import org.ghost.sync.port.SyncClock
import org.ghost.sync.port.TransportPort
import org.ghost.sync.port.TransportState
import org.ghost.sync.port.WakeScheduler
import org.ghost.sync.store.SyncStores
import org.ghost.sync.store.TestBytes
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ThreadFactory
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * The Android runtime's session wiring (design §1.4, §5.4, §5.6, §11.3) with the real engine over a
 * file database, real lane threads and the real clock; only the network and the scheduler are
 * fakes. At most one session runs; the foreground preempts a background session after its calls in
 * flight; a hidden app closes the transport only after those calls finish; jobs always report
 * their end (never after onStopJob); an auth-bound key means no network I/O in the background.
 */
class SyncRuntimeTest {

    private object RealClock : SyncClock {
        override fun epochSeconds(): Long = System.currentTimeMillis() / 1000

        override fun monotonicMillis(): Long = System.nanoTime() / 1_000_000
    }

    /** Answers at once, or holds every call until [release] (or an abort, which ends them with `closed`). */
    private class HeldRelays : RelayPort {
        val calls = AtomicInteger()
        val lists = AtomicInteger()
        val inFlight = AtomicInteger()

        @Volatile
        private var latch: CountDownLatch? = null

        @Volatile
        private var aborted = false

        fun hold(): CountDownLatch = CountDownLatch(1).also {
            aborted = false
            latch = it
        }

        fun release() {
            latch?.countDown()
            latch = null
        }

        fun abortHeld() {
            aborted = true
            latch?.countDown()
        }

        private fun <T> call(answer: () -> T): T {
            calls.incrementAndGet()
            inFlight.incrementAndGet()
            try {
                val held = latch
                if (held != null) {
                    check(held.await(20, TimeUnit.SECONDS)) { "a held call was never released" }
                    if (aborted) throw NetworkException("closed")
                }
                return answer()
            } finally {
                inFlight.decrementAndGet()
            }
        }

        override fun store(relay: OnionAddress, ns: NamespaceId, capability: ByteArray, ciphertext: ByteArray, ttlSeconds: Int, deadlineMillis: Int): StoreReceipt =
            call { StoreReceipt(TestBytes.sha256(ciphertext), RealClock.epochSeconds() + ttlSeconds + 3_600) }

        override fun get(relay: OnionAddress, ns: NamespaceId, capability: ByteArray, hash: BlobHash, deadlineMillis: Int): FetchedBlob =
            call { throw NetworkException("not_found") }

        override fun list(relay: OnionAddress, ns: NamespaceId, capability: ByteArray, cursor: ByteArray, limit: Int, deadlineMillis: Int): ListPage {
            lists.incrementAndGet()
            return call { ListPage(emptyList(), ByteArray(0)) }
        }

        override fun check(relay: OnionAddress, ns: NamespaceId, capability: ByteArray, hashes: List<BlobHash>, deadlineMillis: Int): Set<BlobHash> =
            call { emptySet() }
    }

    /** Counts ensures and aborts; an abort ends held calls (and a held bootstrap) like closing the native transport. */
    private class HeldTransport(override val relays: HeldRelays) : TransportPort {
        val ensures = AtomicInteger()
        val aborts = AtomicInteger()
        val abortsDuringCalls = AtomicInteger()

        @Volatile
        var bootstrapHold: CountDownLatch? = null

        override fun ensureReady(deadlineMonotonicMillis: Long): TransportState {
            ensures.incrementAndGet()
            val held = bootstrapHold ?: return TransportState.READY
            held.await(20, TimeUnit.SECONDS)
            return TransportState.UNAVAILABLE
        }

        override fun abort() {
            aborts.incrementAndGet()
            if (relays.inFlight.get() > 0) abortsDuringCalls.incrementAndGet()
            relays.abortHeld()
            bootstrapHold?.countDown()
        }
    }

    private class Threads : ThreadFactory {
        val failures: MutableList<Throwable> = Collections.synchronizedList(ArrayList())

        override fun newThread(r: Runnable): Thread = Thread(r, THREAD_NAME).apply {
            isDaemon = true
            setUncaughtExceptionHandler { _, e -> failures += e }
        }
    }

    private class Opener(private val sql: SqlExecutor) : DatabaseOpener {
        @Volatile
        var foreground = true

        @Volatile
        var background = true

        override fun keyExists(): Boolean = true

        override fun open(purpose: DatabaseOpener.Purpose): SqlExecutor? =
            sql.takeIf { if (purpose == DatabaseOpener.Purpose.FOREGROUND) foreground else background }
    }

    private class RecordingWake : WakeScheduler {
        val ensured: MutableList<String> = Collections.synchronizedList(ArrayList())
        val cancels = AtomicInteger()

        override fun ensurePeriodic() {
            ensured += Thread.currentThread().name
        }

        override fun cancel() {
            cancels.incrementAndGet()
        }
    }

    private class World : AutoCloseable {
        private val dir: File = Files.createTempDirectory("ghost-runtime-test").toFile()
        val sql = JdbcSqlExecutor(File(dir, "sync.db").absolutePath).also { MigrationRunner(it).migrate() }
        val relays = HeldRelays()
        val transport = HeldTransport(relays)
        val threads = Threads()
        val opener = Opener(sql)
        val wake = RecordingWake()
        val policy = TrafficPolicy(intervalMillis = 200, backgroundWindowMillis = 200, passIntervalMillis = 100, lateToleranceMillis = 2_000)
        val runtime = SyncRuntime(opener, transport, RealClock, KeyedRandomSources(), policy, threads)
        val controller = AndroidSyncController(runtime, wake, opener)

        init {
            // Three relays of three operators, one listening namespace, a write token on each: three read pairs.
            val db = SyncDatabase(sql)
            val stores = SyncStores(db, RealClock, KeyedRandomSources()) { PrivacyMode.STANDARD }
            val ns = TestBytes.namespace(1)
            val ids = db.transaction { tx ->
                stores.relayDirectory.upsert(tx, (1..3).map { RelayEntry(TestBytes.onion(it), TestBytes.of(16, 500 + it), RelayEntry.Source.CONFIG) })
            }
            db.transaction { tx -> stores.namespaces.register(tx, ns, Consumer.DM, ids.values.toSet(), listen = true) }
            db.transaction { tx -> ids.values.forEach { stores.capabilities.put(tx, it, ns, CapabilityKind.WRITE, TestBytes.of(82, it.value.toInt()), null) } }
        }

        override fun close() {
            relays.release()
            controller.onAppBackground()
            val idle = runtime.awaitIdle(20_000)
            sql.close()
            dir.deleteRecursively()
            check(idle) { "the runtime did not become idle" }
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
    fun aHiddenAppClosesTheTransportOnlyAfterItsCallsInFlightFinish(): Unit = World().use { w ->
        w.relays.hold()
        w.controller.onAppForeground()
        assertTrue("a list call is in flight", waitFor(5_000) { w.relays.inFlight.get() >= 1 })
        assertEquals(SessionKind.FOREGROUND, w.runtime.activeKind)
        w.controller.onAppBackground()
        Thread.sleep(300)
        assertEquals("no abort while calls are in flight", 0, w.transport.aborts.get())
        assertEquals(SessionKind.FOREGROUND, w.runtime.activeKind)
        w.relays.release()
        assertTrue(w.runtime.awaitIdle(10_000))
        assertEquals(1, w.transport.aborts.get())
        assertEquals(0, w.transport.abortsDuringCalls.get())
        assertNull(w.runtime.activeKind)
        assertEquals(TransportStatus.OFF, w.controller.status().transport)
        assertEquals(emptyList<Throwable>(), w.threads.failures.toList())
    }

    @Test
    fun aJobWhileTheAppIsVisibleReturnsAtOnce(): Unit = World().use { w ->
        w.controller.onAppForeground()
        assertTrue(waitFor(5_000) { w.transport.ensures.get() == 1 })
        val finished = CountDownLatch(1)
        w.controller.startBackgroundJob { finished.countDown() }
        assertTrue(finished.await(5, TimeUnit.SECONDS))
        assertEquals(SessionKind.FOREGROUND, w.runtime.activeKind)
        assertEquals("the job opened no second transport", 1, w.transport.ensures.get())
    }

    @Test
    fun theForegroundTakesOverFromABackgroundSessionAfterItsCallsFinish(): Unit = World().use { w ->
        w.relays.hold()
        val finished = AtomicInteger()
        val abortsAtFinish = AtomicInteger(-1)
        w.controller.startBackgroundJob {
            abortsAtFinish.set(w.transport.aborts.get())
            finished.incrementAndGet()
        }
        assertTrue(waitFor(5_000) { w.relays.inFlight.get() >= 1 })
        assertEquals(SessionKind.BACKGROUND, w.runtime.activeKind)
        w.controller.onAppForeground()
        Thread.sleep(300)
        assertEquals("the background session drains first", SessionKind.BACKGROUND, w.runtime.activeKind)
        assertEquals(0, w.transport.aborts.get())
        assertEquals(0, finished.get())
        w.relays.release()
        assertTrue(waitFor(10_000) { w.runtime.activeKind == SessionKind.FOREGROUND && w.transport.ensures.get() == 2 })
        assertEquals(1, finished.get())
        assertEquals("the transport is closed before jobFinished", 1, abortsAtFinish.get())
        assertEquals(0, w.transport.abortsDuringCalls.get())
        assertEquals(emptyList<Throwable>(), w.threads.failures.toList())
    }

    @Test
    fun anAuthBoundKeyEndsTheBackgroundJobWithNoNetworkIO(): Unit = World().use { w ->
        w.opener.background = false
        val finished = CountDownLatch(1)
        w.controller.startBackgroundJob { finished.countDown() }
        assertTrue(finished.await(5, TimeUnit.SECONDS))
        assertTrue(w.runtime.awaitIdle(5_000))
        assertEquals(0, w.transport.ensures.get())
        assertEquals(0, w.relays.calls.get())
        assertNull(w.runtime.activeKind)
        assertNull("the database was never opened", w.controller.stores)
    }

    @Test
    fun aBackgroundJobRunsOneSessionClosesTheTransportAndReportsOnce(): Unit = World().use { w ->
        val finished = AtomicInteger()
        val abortsAtFinish = AtomicInteger(-1)
        val done = CountDownLatch(1)
        w.controller.startBackgroundJob {
            abortsAtFinish.set(w.transport.aborts.get())
            finished.incrementAndGet()
            done.countDown()
        }
        assertTrue(done.await(30, TimeUnit.SECONDS))
        assertTrue(w.runtime.awaitIdle(5_000))
        Thread.sleep(200)
        assertEquals(1, finished.get())
        assertEquals(1, w.transport.ensures.get())
        assertEquals(1, abortsAtFinish.get())
        assertEquals("one list event per read pair", 3, w.relays.lists.get())
        assertNotNull(w.controller.stores)
        assertEquals(emptyList<Throwable>(), w.threads.failures.toList())
    }

    @Test
    fun onStopJobAbortsAtOnceAndReportsNothing(): Unit = World().use { w ->
        w.relays.hold()
        val finished = AtomicInteger()
        val ticket = w.controller.startBackgroundJob { finished.incrementAndGet() }
        assertTrue(waitFor(5_000) { w.relays.inFlight.get() >= 1 })
        w.controller.stopBackgroundJob(ticket)
        assertTrue("aborted from the caller's thread", w.transport.aborts.get() >= 1)
        assertTrue(w.runtime.awaitIdle(10_000))
        Thread.sleep(200)
        assertEquals(0, finished.get())
        assertNull(w.runtime.activeKind)
        assertEquals(emptyList<Throwable>(), w.threads.failures.toList())
    }

    @Test
    fun aJobStoppedBeforeItStartsRunsNothing(): Unit = World().use { w ->
        w.relays.hold()
        val finished = AtomicInteger()
        // Occupy the runtime thread so both commands queue behind this one.
        val gate = CountDownLatch(1)
        w.runtime.post { gate.await(5, TimeUnit.SECONDS) }
        val ticket = w.controller.startBackgroundJob { finished.incrementAndGet() }
        w.controller.stopBackgroundJob(ticket)
        gate.countDown()
        assertTrue(w.runtime.awaitIdle(5_000))
        assertEquals(0, w.transport.ensures.get())
        assertEquals(0, finished.get())
    }

    @Test
    fun aSessionStillBootstrappingIsAbortedWhenTheAppIsHidden(): Unit = World().use { w ->
        w.transport.bootstrapHold = CountDownLatch(1)
        w.controller.onAppForeground()
        assertTrue(waitFor(5_000) { w.transport.ensures.get() == 1 })
        w.controller.onAppBackground()
        assertTrue(w.runtime.awaitIdle(5_000))
        assertTrue(w.transport.aborts.get() >= 1)
        assertEquals(0, w.relays.calls.get())
    }

    @Test
    fun wipeStopsSyncAndNothingStartsUntilTheDatabaseIsAvailableAgain(): Unit = World().use { w ->
        w.controller.onAppForeground()
        assertTrue(waitFor(5_000) { w.transport.ensures.get() == 1 })
        w.controller.onWipe()
        assertEquals("the periodic job is cancelled at once", 1, w.wake.cancels.get())
        assertTrue(w.runtime.awaitIdle(10_000))
        assertNull(w.controller.stores)
        assertEquals(TransportStatus.OFF, w.controller.status().transport)
        w.controller.onAppBackground()
        val finished = CountDownLatch(1)
        w.controller.startBackgroundJob { finished.countDown() }
        assertTrue(finished.await(5, TimeUnit.SECONDS))
        w.controller.onAppForeground()
        assertTrue(w.runtime.awaitCommands(5_000))
        Thread.sleep(200)
        assertNull(w.runtime.activeKind)
        assertEquals(1, w.transport.ensures.get())
        w.controller.onDatabaseAvailable()
        assertTrue(waitFor(5_000) { w.runtime.activeKind == SessionKind.FOREGROUND && w.transport.ensures.get() == 2 })
        assertNotNull(w.controller.stores)
    }

    @Test
    fun rapidVisibilityChangesAndJobsNeverRunTwoSessions(): Unit = World().use { w ->
        val finished = AtomicInteger()
        var jobs = 0
        repeat(40) { i ->
            if (i % 2 == 0) w.controller.onAppForeground() else w.controller.onAppBackground()
            if (i % 3 == 0) {
                jobs++
                w.controller.startBackgroundJob { finished.incrementAndGet() }
            }
            Thread.sleep((i % 5) * 7L)
        }
        w.controller.onAppBackground()
        assertTrue(w.runtime.awaitIdle(30_000))
        assertTrue("every job reported its end once", waitFor(5_000) { finished.get() == jobs })
        assertNull(w.runtime.activeKind)
        assertEquals("no second session was ever started", emptyList<Throwable>(), w.threads.failures.toList())
    }

    @Test
    fun statusIsOffBeforeTheDatabaseOpensAndFollowsThePrivacyMode(): Unit = World().use { w ->
        w.controller.setPrivacyMode(PrivacyMode.HIGH)
        val before = w.controller.status()
        assertEquals(TransportStatus.OFF, before.transport)
        assertEquals(PrivacyMode.HIGH, before.mode)
        assertEquals(0, before.counts.pendingOperations)
        w.controller.onAppForeground()
        assertTrue(waitFor(5_000) { w.controller.status().transport == TransportStatus.READY })
        assertEquals(PrivacyMode.HIGH, w.controller.status().mode)
        assertEquals(0, w.controller.status().counts.pendingOperations)
    }

    @Test
    fun ensurePeriodicRunsOnTheRuntimeThreadNeverTheCaller(): Unit = World().use { w ->
        w.controller.ensurePeriodic()
        assertTrue(w.runtime.awaitCommands(5_000))
        assertEquals(listOf(THREAD_NAME), w.wake.ensured.toList())
        assertNotEquals(THREAD_NAME, Thread.currentThread().name)
    }

    @Test
    fun aJobTicketReportsOnceAndNeverAfterStop() {
        val reports = AtomicInteger()
        val ticket = JobTicket { reports.incrementAndGet() }
        ticket.finish()
        ticket.finish()
        assertEquals(1, reports.get())
        val stoppedTicket = JobTicket { reports.incrementAndGet() }
        stoppedTicket.stop()
        assertTrue(stoppedTicket.stopped)
        stoppedTicket.finish()
        assertEquals(1, reports.get())
        assertEquals("JobTicket", ticket.toString())
    }

    private companion object {
        const val THREAD_NAME = "sync-runtime-test"
    }
}
