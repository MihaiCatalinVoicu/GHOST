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
import org.ghost.sync.api.ParticipantSession
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.RelayEntry
import org.ghost.sync.api.SessionParticipant
import org.ghost.sync.api.SyncDatabase
import org.ghost.sync.api.TransportStatus
import org.ghost.sync.engine.EngineWorld
import org.ghost.sync.engine.EngineWorld.Companion.MINUTE
import org.ghost.sync.engine.EngineWorld.Companion.SECOND
import org.ghost.sync.engine.ErrorPolicy
import org.ghost.sync.engine.KeyedRandomSources
import org.ghost.sync.engine.QuietRunScheduler
import org.ghost.sync.engine.ReadItem
import org.ghost.sync.engine.RecordingCalls
import org.ghost.sync.engine.RecordingLease
import org.ghost.sync.engine.SessionKind
import org.ghost.sync.engine.TestRelays
import org.ghost.sync.engine.TrafficPolicy
import org.ghost.sync.engine.category
import org.ghost.sync.port.EntitlementCalls
import org.ghost.sync.port.FetchedBlob
import org.ghost.sync.port.LeasePort
import org.ghost.sync.port.ListPage
import org.ghost.sync.port.RandomSources
import org.ghost.sync.port.RelayPort
import org.ghost.sync.port.StoreReceipt
import org.ghost.sync.port.SyncClock
import org.ghost.sync.port.TransportLease
import org.ghost.sync.port.TransportPort
import org.ghost.sync.port.TransportState
import org.ghost.sync.port.WakeScheduler
import org.ghost.sync.store.SyncStores
import org.ghost.sync.store.TestBytes
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.ByteBuffer
import java.nio.file.Files
import java.security.MessageDigest
import java.util.Collections
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ThreadFactory
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock
import org.ghost.sync.api.SessionKind as ParticipantKind

/**
 * The session participant (Phase 8 design §11.6, §12.2, §19.11, §19.14; ADR-23; G-10).
 *
 *  - T19 with a participant: in the deterministic engine world of `T19BasicTest` (8 read pairs, a
 *    fixed list-latency trace), a participant that fails every call (every category of the error
 *    table, transport-level ones included) or one that keeps calling until its deadline, with its
 *    database reads and transactions between lane items, leaves the read schedule identical: the
 *    first pages (STANDARD), the whole list sequence (HIGH), and a background job's list sequence
 *    and end time. On the real runtime, such participants and one that never returns change neither
 *    a job's calls nor its end.
 *  - A quiet run makes no `RelayPort` call and at most one issuer call; a relay session exposes no
 *    issuer access; foreground sessions are never quiet; a foreground wanted during a quiet run ends
 *    it at once; no automatic issuer call runs while a relay session runs.
 *  - The quiet-run pattern follows the client's key only: twin runtimes whose issuer answers, work
 *    and failures differ run the same jobs quiet, exactly those [QuietRunScheduler.quiet] names.
 *  - User issuer calls and the payment-screen hold of relay sessions.
 */
class SessionParticipantTest {

    // ------------------------------------------------------------------ T19 with a participant (deterministic)

    private enum class Behaviour { FAILS_EVERY_CALL, CALLS_UNTIL_THE_DEADLINE }

    private class T19Run(val requests: List<Triple<Long, String, Int>>, val endedAt: Long?, val participantCalls: Int)

    /** A deterministic value in [0, n) from the call's pair and start time (the fixed list-latency trace). */
    private fun keyed(call: TestRelays.Call, n: Int, salt: String): Int {
        val d = MessageDigest.getInstance("SHA-256").digest("$salt|${call.relay}|${call.namespace.toByteArray().contentToString()}|${call.startMillis}".toByteArray())
        return Math.floorMod(((d[0].toInt() and 0xff) shl 8) or (d[1].toInt() and 0xff), n)
    }

    private fun t19(mode: PrivacyMode, kind: SessionKind, behaviour: Behaviour?): T19Run = EngineWorld(TrafficPolicy(listLimit = 4)).use { w ->
        w.mode = mode
        val relays = w.relays(1, 2, 3, 4)
        val listened = (1..2).map { n -> w.namespace(n, relays).also { ns -> relays.forEach { w.capability(it, ns) } } }
        w.namespace(3, relays, listen = false).also { ns -> relays.forEach { w.capability(it, ns) } }
        val firstList = HashSet<String>()
        w.net.latency = { call ->
            when (call.kind) {
                TestRelays.Kind.LIST -> {
                    val rendezvous = if (firstList.add("${call.relay}|${call.namespace.toByteArray().contentToString()}")) 3 * SECOND else 0
                    500L + keyed(call, 9_000, "latency") + rendezvous
                }
                else -> 5 * SECOND
            }
        }
        w.net.failBefore = { call -> if (call.kind == TestRelays.Kind.LIST && keyed(call, 10, "fail") == 0) "timeout" else null }
        val (session, driver) = w.session(kind)
        var calls = 0
        if (behaviour != null) {
            val lease = RecordingLease()
            val categories = ErrorPolicy.CATEGORIES.keys.toList()
            var n = 0
            if (behaviour == Behaviour.FAILS_EVERY_CALL) lease.calls.failure = { categories[n++ % categories.size] }
            val foreground = kind == SessionKind.FOREGROUND
            val deadline = if (foreground) Long.MAX_VALUE else session.startedAt + w.policy.backgroundSessionMillis
            val ps = QuietRunScheduler(w.random, w.clock).session(
                if (foreground) ParticipantKind.FOREGROUND else ParticipantKind.BACKGROUND, lease, deadline, w.engine::clockTrusted,
            ) { w.db.inTransaction }
            assertNull(ps.issuer)
            // The participant's thread, interleaved between lane items: calls, clock checks, reads, transactions.
            driver.beforeItem = {
                if (!ps.closed) {
                    calls++
                    category {
                        checkNotNull(ps.relayRedeem).redeem(w.address(relays[calls % 4]), listened[calls % 2], ByteArray(354) { calls.toByte() }, ByteArray(16) { calls.toByte() })
                    }
                    ps.clockTrusted()
                    w.stores.capabilities.needed()
                    w.tx { it.sql.query("SELECT count(*) FROM relay_directory", emptyList()) { } }
                }
            }
        }
        val endedAt = if (kind == SessionKind.BACKGROUND) {
            assertTrue(driver.runUntilFinished(30 * MINUTE))
            driver.time
        } else {
            driver.runUntil(20 * MINUTE)
            null
        }
        val requests = if (mode == PrivacyMode.HIGH || kind == SessionKind.BACKGROUND) {
            w.net.callsOf(TestRelays.Kind.LIST).map { Triple(it.startMillis, "${it.relay}|${it.namespace.toByteArray().contentToString()}", it.limit) }
        } else {
            driver.started.map { it.second }.filterIsInstance<ReadItem>().filter { !it.continuation }.map {
                Triple(it.startMillis, "${it.relay}|${it.pair.namespace.toByteArray().contentToString()}", it.limit)
            }
        }
        T19Run(requests, endedAt, calls)
    }

    @Test
    fun t19StandardFirstPagesAreIdenticalWithAParticipant() {
        val idle = t19(PrivacyMode.STANDARD, SessionKind.FOREGROUND, null)
        assertTrue(idle.requests.size > 200)
        for (b in Behaviour.entries) {
            val with = t19(PrivacyMode.STANDARD, SessionKind.FOREGROUND, b)
            assertTrue("$b made calls", with.participantCalls > 200)
            assertEquals("$b", idle.requests, with.requests)
        }
    }

    @Test
    fun t19HighModeListSequencesAreIdenticalWithAParticipant() {
        val idle = t19(PrivacyMode.HIGH, SessionKind.FOREGROUND, null)
        assertTrue(idle.requests.size > 200)
        for (b in Behaviour.entries) assertEquals("$b", idle.requests, t19(PrivacyMode.HIGH, SessionKind.FOREGROUND, b).requests)
    }

    @Test
    fun t19ABackgroundJobListsAndEndsTheSameWithAParticipant() {
        val idle = t19(PrivacyMode.STANDARD, SessionKind.BACKGROUND, null)
        assertTrue(idle.requests.size >= 8)
        for (b in Behaviour.entries) {
            val with = t19(PrivacyMode.STANDARD, SessionKind.BACKGROUND, b)
            assertTrue("$b made calls", with.participantCalls > 10)
            assertEquals("$b", idle.requests, with.requests)
            assertEquals("$b: the job ends at the same time", idle.endedAt, with.endedAt)
        }
    }

    // ------------------------------------------------------------------ the runtime (real threads)

    /** Real time plus a settable offset (the payment hold spans tens of minutes). */
    private class OffsetClock : SyncClock {
        @Volatile
        var offsetMillis: Long = 0

        override fun epochSeconds(): Long = Math.floorDiv(System.currentTimeMillis() + offsetMillis, 1000L)

        override fun monotonicMillis(): Long = System.nanoTime() / 1_000_000 + offsetMillis
    }

    /** Relay calls answer at once; lists wait while [listHold] is set. */
    private class CountingRelays(private val clock: SyncClock) : RelayPort {
        val calls = AtomicInteger()
        val lists = AtomicInteger()

        @Volatile
        var listHold: CountDownLatch? = null

        override fun store(relay: OnionAddress, ns: NamespaceId, capability: ByteArray, ciphertext: ByteArray, ttlSeconds: Int, deadlineMillis: Int): StoreReceipt {
            calls.incrementAndGet()
            return StoreReceipt(TestBytes.sha256(ciphertext), clock.epochSeconds() + ttlSeconds + 3_600)
        }

        override fun get(relay: OnionAddress, ns: NamespaceId, capability: ByteArray, hash: BlobHash, deadlineMillis: Int): FetchedBlob {
            calls.incrementAndGet()
            throw NetworkException("not_found")
        }

        override fun list(relay: OnionAddress, ns: NamespaceId, capability: ByteArray, cursor: ByteArray, limit: Int, deadlineMillis: Int): ListPage {
            calls.incrementAndGet()
            lists.incrementAndGet()
            listHold?.await(20, TimeUnit.SECONDS)
            return ListPage(emptyList(), ByteArray(0))
        }

        override fun check(relay: OnionAddress, ns: NamespaceId, capability: ByteArray, hashes: List<BlobHash>, deadlineMillis: Int): Set<BlobHash> {
            calls.incrementAndGet()
            return emptySet()
        }
    }

    /** A transport that is also the lease port: READY from an ensure until the next abort. */
    private class LeasingTransport(private val clock: SyncClock) : TransportPort, LeasePort {
        override val relays = CountingRelays(clock)
        val calls = RecordingCalls()
        val ensures = AtomicInteger()
        val aborts = AtomicInteger()
        private val lock = ReentrantLock()
        private val changed = lock.newCondition()
        private var ready = false
        private var generation = 0L

        @Volatile
        var bootstrapHold: CountDownLatch? = null

        override fun ensureReady(deadlineMonotonicMillis: Long): TransportState {
            ensures.incrementAndGet()
            val startedAt = lock.withLock { generation }
            bootstrapHold?.await(20, TimeUnit.SECONDS)
            return lock.withLock {
                if (generation != startedAt) {
                    TransportState.UNAVAILABLE
                } else {
                    ready = true
                    changed.signalAll()
                    TransportState.READY
                }
            }
        }

        override fun abort() {
            aborts.incrementAndGet()
            lock.withLock {
                generation++
                ready = false
                changed.signalAll()
            }
            bootstrapHold?.countDown()
        }

        override fun openLease(): TransportLease = Lease()

        private inner class Lease : TransportLease {
            private var open = true

            override val closed: Boolean get() = lock.withLock { !open }

            override fun close() = lock.withLock {
                open = false
                changed.signalAll()
            }

            override fun awaitReady(deadlineMonotonicMillis: Long): Boolean = lock.withLock {
                while (open && !ready) {
                    val left = deadlineMonotonicMillis - clock.monotonicMillis()
                    if (left <= 0) return@withLock false
                    changed.await(minOf(left, 1_000L), TimeUnit.MILLISECONDS)
                }
                open
            }

            override fun <T> use(block: (EntitlementCalls) -> T): T {
                if (lock.withLock { !open || !ready }) throw NetworkException("closed")
                return block(calls)
            }

            override fun newFlow(): ByteArray = ByteBuffer.allocate(16).putLong(FLOWS.incrementAndGet()).array()

            override fun endFlow(flow: ByteArray) {
                if (!closed) calls.endFlow(flow)
            }
        }
    }

    private class Threads : ThreadFactory {
        val failures: MutableList<Throwable> = Collections.synchronizedList(ArrayList())

        override fun newThread(r: Runnable): Thread = Thread(r, "participant-test").apply {
            isDaemon = true
            setUncaughtExceptionHandler { _, e -> failures += e }
        }
    }

    private class Opener(private val sql: SqlExecutor) : DatabaseOpener {
        override fun keyExists(): Boolean = true

        override fun open(purpose: DatabaseOpener.Purpose): SqlExecutor = sql
    }

    private object NoWake : WakeScheduler {
        override fun ensurePeriodic() = Unit

        override fun cancel() = Unit
    }

    /** Client randomness with chosen quiet draws and payment holds; every other stream keyed. */
    private class Draws(private val quiet: (Long) -> Boolean, private val hold: Double = 0.5) :
        RandomSources by KeyedRandomSources(ByteArray(32) { 5 }) {
        override fun quietRun(index: Long): Double = if (quiet(index)) 0.0 else 0.99

        override fun paymentHold(index: Long): Double = hold
    }

    private class ScriptedParticipant(
        val onQuiet: (ParticipantSession) -> Unit = {},
        val onRelay: (ParticipantSession) -> Unit = {},
    ) : SessionParticipant {
        val quietSessions = CopyOnWriteArrayList<ParticipantSession>()
        val relaySessions = CopyOnWriteArrayList<ParticipantSession>()
        val returned = AtomicInteger()

        override fun onRelaySession(session: ParticipantSession) {
            relaySessions += session
            onRelay(session)
            returned.incrementAndGet()
        }

        override fun onQuietRun(session: ParticipantSession) {
            quietSessions += session
            onQuiet(session)
            returned.incrementAndGet()
        }
    }

    private class World(random: RandomSources = Draws({ false })) : AutoCloseable {
        private val dir: File = Files.createTempDirectory("ghost-participant-test").toFile()
        val sql = JdbcSqlExecutor(File(dir, "sync.db").absolutePath).also { MigrationRunner(it).migrate() }
        val clock = OffsetClock()
        val transport = LeasingTransport(clock)
        val threads = Threads()
        val policy = TrafficPolicy(intervalMillis = 200, backgroundWindowMillis = 200, passIntervalMillis = 100, lateToleranceMillis = 2_000)
        val runtime = SyncRuntime(Opener(sql), transport, clock, random, policy, threads, leases = transport)
        val controller = AndroidSyncController(runtime, NoWake, Opener(sql))

        /** Issuer calls made while a relay session ran (automatic ones never may). */
        val issuerCallsDuringRelaySessions = AtomicInteger()

        /** Held until the test ends (participants that never return). */
        val gate = CountDownLatch(1)

        init {
            // Three relays of three operators, one listening namespace, a write token on each: three read pairs.
            val db = SyncDatabase(sql)
            val stores = SyncStores(db, clock, KeyedRandomSources()) { PrivacyMode.STANDARD }
            val ns = TestBytes.namespace(1)
            val ids = db.transaction { tx ->
                stores.relayDirectory.upsert(tx, (1..3).map { RelayEntry(TestBytes.onion(it), TestBytes.of(16, 500 + it), RelayEntry.Source.CONFIG) })
            }
            db.transaction { tx -> stores.namespaces.register(tx, ns, Consumer.DM, ids.values.toSet(), listen = true) }
            db.transaction { tx -> ids.values.forEach { stores.capabilities.put(tx, it, ns, CapabilityKind.WRITE, TestBytes.of(82, it.value.toInt()), null) } }
            transport.calls.during = { name -> if (name != "redeem" && runtime.activeKind != null) issuerCallsDuringRelaySessions.incrementAndGet() }
        }

        fun job(): CountDownLatch = CountDownLatch(1).also { done -> controller.startBackgroundJob { done.countDown() } }

        override fun close() {
            gate.countDown()
            transport.relays.listHold?.countDown()
            transport.bootstrapHold?.countDown()
            controller.onAppBackground()
            val idle = runtime.awaitIdle(20_000)
            sql.close()
            dir.deleteRecursively()
            check(idle) { "the runtime did not become idle" }
            check(threads.failures.isEmpty()) { "a thread failed: ${threads.failures}" }
        }
    }

    private fun waitFor(timeoutMillis: Long, condition: () -> Boolean): Boolean {
        val end = System.nanoTime() + timeoutMillis * 1_000_000
        while (System.nanoTime() < end) {
            if (condition()) return true
            Thread.sleep(5)
        }
        return condition()
    }

    private fun redeem(s: ParticipantSession) =
        checkNotNull(s.relayRedeem).redeem(TestBytes.onion(1), TestBytes.namespace(1), ByteArray(354), ByteArray(16))

    private fun invoiceStatus(s: ParticipantSession) = checkNotNull(s.issuer).invoiceStatus(ByteArray(16), ByteArray(32))

    @Test
    fun aQuietRunTouchesNoRelayAndMakesOneIssuerCallOnAFreshFlow(): Unit = World(Draws({ it == 0L })).use { w ->
        val outcomes = CopyOnWriteArrayList<String?>()
        val p = ScriptedParticipant(onQuiet = { s ->
            outcomes += category { checkNotNull(s.issuer).requestInvoice(ByteArray(32), emptyList(), 2960) }
            outcomes += category { invoiceStatus(s) }
            outcomes += category { checkNotNull(s.issuer).refreshCredit(ByteArray(354), ByteArray(32), ByteArray(32)) }
        })
        w.controller.setParticipant(p)
        val abortsAtFinish = AtomicInteger(-1)
        val done = CountDownLatch(1)
        w.controller.startBackgroundJob {
            abortsAtFinish.set(w.transport.aborts.get())
            done.countDown()
        }
        assertTrue(done.await(20, TimeUnit.SECONDS))
        assertTrue(w.runtime.awaitIdle(5_000))
        val s = p.quietSessions.single()
        assertEquals(ParticipantKind.QUIET, s.kind)
        assertNull(s.relayRedeem)
        assertNotNull(s.issuer)
        assertTrue(s.closed)
        assertEquals(listOf(null, "closed", "closed"), outcomes.toList())
        assertEquals("a quiet run makes no RelayPort call", 0, w.transport.relays.calls.get())
        assertEquals(emptyList<ParticipantSession>(), p.relaySessions.toList())
        assertEquals(1, w.transport.ensures.get())
        assertEquals("the transport is closed before jobFinished", 1, abortsAtFinish.get())
        val call = w.transport.calls.calls.single()
        assertEquals("requestInvoice", call.name)
        assertEquals(checkNotNull(call.flow).toList(), w.transport.calls.ended.single().toList())
        assertEquals(0, w.issuerCallsDuringRelaySessions.get())
        assertFalse(w.runtime.quietRunning)
        assertEquals(TransportStatus.OFF, w.controller.status().transport)
    }

    @Test
    fun aRelaySessionGetsRedemptionAndNoIssuerAccess(): Unit = World().use { w ->
        val redeemed = CopyOnWriteArrayList<String?>()
        val hold = CountDownLatch(1)
        w.transport.relays.listHold = hold
        val p = ScriptedParticipant(onRelay = { s ->
            redeemed += category { redeem(s) }
            hold.countDown()
        })
        w.controller.setParticipant(p)
        val done = w.job()
        assertTrue(done.await(30, TimeUnit.SECONDS))
        assertTrue(w.runtime.awaitIdle(5_000))
        assertTrue(waitFor(5_000) { p.returned.get() == 1 })
        val s = p.relaySessions.single()
        assertEquals(ParticipantKind.BACKGROUND, s.kind)
        assertNull(s.issuer)
        assertNotNull(s.relayRedeem)
        assertTrue(s.deadlineMonotonicMillis < Long.MAX_VALUE)
        assertTrue(s.closed)
        assertEquals(listOf<String?>(null), redeemed.toList())
        assertEquals(listOf("redeem"), w.transport.calls.calls.map { it.name })
        assertEquals(3, w.transport.relays.lists.get())
        assertEquals(emptyList<ParticipantSession>(), p.quietSessions.toList())
    }

    private class JobShape(val lists: Int, val ensures: Int, val aborts: Int, val participantCalls: Int, val stillInside: Boolean) {
        val network: Triple<Int, Int, Int> get() = Triple(lists, ensures, aborts)
    }

    /**
     * One background job of a fresh world, with the participant [participant] makes (it counts the
     * latch down once it runs; the session's lists wait for that), every lease call failing when [failAll].
     */
    private fun backgroundJob(participant: ((World, CountDownLatch) -> ScriptedParticipant)?, failAll: Boolean = false): JobShape = World().use { w ->
        if (failAll) {
            val categories = ErrorPolicy.CATEGORIES.keys.toList()
            val n = AtomicInteger()
            w.transport.calls.failure = { categories[n.getAndIncrement() % categories.size] }
        }
        val released = CountDownLatch(1)
        val p = participant?.invoke(w, released)
        if (p != null) {
            // The session's lists wait until the participant is running, so it runs during the session.
            w.transport.relays.listHold = released
            w.controller.setParticipant(p)
        }
        val done = w.job()
        assertTrue(done.await(30, TimeUnit.SECONDS))
        assertTrue(w.runtime.awaitIdle(5_000))
        JobShape(
            w.transport.relays.lists.get(), w.transport.ensures.get(), w.transport.aborts.get(), w.transport.calls.calls.size,
            p != null && p.returned.get() == 0,
        )
    }

    @Test
    fun aParticipantThatFailsEveryCallOrNeverReturnsNeitherDelaysNorSuppressesAJob() {
        val base = backgroundJob(null)
        assertEquals(Triple(3, 1, 1), base.network)
        val failing = backgroundJob({ _, released ->
            ScriptedParticipant(onRelay = { s ->
                var n = 0
                while (!s.closed) {
                    category { redeem(s) }
                    if (++n == 20) released.countDown()
                    Thread.sleep(1)
                }
            })
        }, failAll = true)
        assertEquals(base.network, failing.network)
        assertTrue("the participant failed ${failing.participantCalls} calls", failing.participantCalls >= 20)
        val stuck = backgroundJob({ w, released ->
            ScriptedParticipant(onRelay = { _ ->
                released.countDown()
                w.gate.await(60, TimeUnit.SECONDS)
            })
        })
        assertEquals(base.network, stuck.network)
        assertTrue("the job ended while the participant was still inside its callback", stuck.stillInside)
    }

    @Test
    fun aForegroundSessionEndsWhileItsParticipantNeverReturns(): Unit = World().use { w ->
        val entered = CountDownLatch(1)
        val p = ScriptedParticipant(onRelay = { s ->
            assertEquals(ParticipantKind.FOREGROUND, s.kind)
            assertEquals(Long.MAX_VALUE, s.deadlineMonotonicMillis)
            entered.countDown()
            w.gate.await(60, TimeUnit.SECONDS)
        })
        w.controller.setParticipant(p)
        w.controller.onAppForeground()
        assertTrue(entered.await(10, TimeUnit.SECONDS))
        w.controller.onAppBackground()
        assertTrue(w.runtime.awaitIdle(10_000))
        assertEquals(0, p.returned.get())
        assertTrue(p.relaySessions.single().closed)
        assertEquals("closed", category { redeem(p.relaySessions.single()) })
    }

    @Test
    fun theQuietRunPatternDependsOnClientRandomnessOnly() {
        val jobs = 16
        // A key whose first runs hold at least two quiet runs and two relay sessions (a deterministic search).
        val key = generateSequence(1) { it + 1 }.map { seed -> ByteArray(32) { (it * 13 + seed).toByte() } }.first { k ->
            val q = (0L until jobs).count { QuietRunScheduler(KeyedRandomSources(k), OffsetClock()).quiet(it) }
            q in 2..jobs - 2
        }
        val expected = (0L until jobs).map { QuietRunScheduler(KeyedRandomSources(key), OffsetClock()).quiet(it) }

        /** The runs of [jobs] jobs, quiet (no list) or not, under one issuer behaviour. */
        fun pattern(behaviour: String): List<Boolean> = World(KeyedRandomSources(key)).use { w ->
            when (behaviour) {
                "every call fails" -> {
                    val categories = ErrorPolicy.CATEGORIES.keys.toList()
                    val n = AtomicInteger()
                    w.transport.calls.failure = { categories[n.getAndIncrement() % categories.size] }
                }
                "signed" -> Unit
            }
            val p = ScriptedParticipant(onQuiet = { s ->
                // Work is due in every quiet run, except for the twin that has none.
                if (behaviour != "no work") category { checkNotNull(s.issuer).blindSign(ByteArray(16), ByteArray(32), ByteArray(32), 1, 2960, ByteArray(32), 16) }
            })
            w.controller.setParticipant(p)
            val out = ArrayList<Boolean>()
            repeat(jobs) {
                val listsBefore = w.transport.relays.lists.get()
                assertTrue(w.job().await(30, TimeUnit.SECONDS))
                assertTrue(w.runtime.awaitIdle(5_000))
                out += w.transport.relays.lists.get() == listsBefore
            }
            assertEquals(out.count { it }, p.quietSessions.size)
            assertEquals(0, w.issuerCallsDuringRelaySessions.get())
            out
        }
        assertEquals(expected, pattern("signed"))
        assertEquals(expected, pattern("every call fails"))
        assertEquals(expected, pattern("no work"))
    }

    @Test
    fun foregroundSessionsAreNeverQuietAndAJobWhileVisibleRunsNothing(): Unit = World(Draws({ true })).use { w ->
        val p = ScriptedParticipant()
        w.controller.setParticipant(p)
        w.controller.onAppForeground()
        assertTrue(waitFor(5_000) { p.relaySessions.size == 1 })
        assertEquals(ParticipantKind.FOREGROUND, p.relaySessions.single().kind)
        assertTrue(w.job().await(5, TimeUnit.SECONDS))
        assertTrue(w.runtime.awaitCommands(5_000))
        assertEquals(SessionKind.FOREGROUND, w.runtime.activeKind)
        assertEquals(emptyList<ParticipantSession>(), p.quietSessions.toList())
        assertEquals(1, w.transport.ensures.get())
    }

    @Test
    fun aForegroundWantedDuringAQuietRunEndsItAtOnce(): Unit = World(Draws({ true })).use { w ->
        val entered = CountDownLatch(1)
        val afterClose = CopyOnWriteArrayList<String?>()
        val p = ScriptedParticipant(onQuiet = { s ->
            entered.countDown()
            waitFor(20_000) { s.closed }
            afterClose += category { invoiceStatus(s) }
        })
        w.controller.setParticipant(p)
        val done = w.job()
        assertTrue(entered.await(10, TimeUnit.SECONDS))
        assertTrue(w.runtime.quietRunning)
        w.controller.onAppForeground()
        assertTrue("the quiet job ended at once", done.await(10, TimeUnit.SECONDS))
        assertTrue(waitFor(10_000) { w.runtime.activeKind == SessionKind.FOREGROUND })
        assertTrue(waitFor(10_000) { afterClose.size == 1 })
        assertEquals(listOf<String?>("closed"), afterClose.toList())
        assertEquals(0, w.transport.calls.calls.size)
        assertEquals(0, w.issuerCallsDuringRelaySessions.get())
        assertTrue(w.transport.aborts.get() >= 1)
    }

    @Test
    fun aQuietRunEndsAtItsDeadlineWhetherOrNotTheParticipantReturns(): Unit = World(Draws({ true })).use { w ->
        val entered = CountDownLatch(1)
        val p = ScriptedParticipant(onQuiet = { entered.countDown(); w.gate.await(60, TimeUnit.SECONDS) })
        w.controller.setParticipant(p)
        val done = w.job()
        assertTrue(entered.await(10, TimeUnit.SECONDS))
        val s = p.quietSessions.single()
        assertTrue(s.deadlineMonotonicMillis - w.clock.monotonicMillis() <= w.policy.backgroundSessionMillis)
        assertFalse(done.await(200, TimeUnit.MILLISECONDS))
        // Past the deadline (a clock jump: the watchdog reads the sync clock, not a timer), the run ends.
        w.clock.offsetMillis += w.policy.backgroundSessionMillis + MINUTE
        assertTrue(s.closed)
        assertEquals("closed", category { invoiceStatus(s) })
        assertTrue(done.await(10, TimeUnit.SECONDS))
        assertTrue(w.runtime.awaitIdle(5_000))
        assertFalse(w.runtime.quietRunning)
        assertEquals(0, p.returned.get())
        assertEquals(0, w.transport.calls.calls.size)
    }

    @Test
    fun aUserIssuerCallRunsOnTheForegroundSessionsTransport(): Unit = World().use { w ->
        w.controller.setParticipant(ScriptedParticipant())
        w.controller.onAppForeground()
        assertTrue(waitFor(5_000) { w.runtime.activeKind == SessionKind.FOREGROUND && w.controller.status().transport == TransportStatus.READY })
        val seen = CompletableFuture<Pair<ParticipantSession, List<String?>>>()
        w.controller.runUserIssuerCall { s -> seen.complete(Pair(s, listOf(category { invoiceStatus(s) }, category { invoiceStatus(s) }))) }
        val (s, outcomes) = seen.get(10, TimeUnit.SECONDS)
        assertEquals(ParticipantKind.USER_ISSUER_CALL, s.kind)
        assertNull(s.relayRedeem)
        assertTrue(s.clockTrusted() || s.closed)
        assertEquals(listOf(null, "closed"), outcomes)
        assertEquals(listOf("invoiceStatus"), w.transport.calls.calls.map { it.name })
        assertEquals("no second ensure", 1, w.transport.ensures.get())
        assertEquals(0, w.transport.aborts.get())
        assertEquals(SessionKind.FOREGROUND, w.runtime.activeKind)
    }

    @Test
    fun aUserIssuerCallWithNoSessionMakesTheTransportReadyAndClosesIt(): Unit = World().use { w ->
        val seen = CompletableFuture<Pair<String?, Boolean>>()
        w.controller.runUserIssuerCall { s -> seen.complete(Pair(category { invoiceStatus(s) }, s.clockTrusted())) }
        assertEquals(Pair<String?, Boolean>(null, true), seen.get(10, TimeUnit.SECONDS))
        assertTrue(w.runtime.awaitIdle(5_000))
        assertEquals(1, w.transport.ensures.get())
        assertEquals(1, w.transport.aborts.get())
        assertEquals(0, w.transport.relays.calls.get())
        assertNull(w.runtime.activeKind)
        // Afterwards a job runs an ordinary relay session.
        assertTrue(w.job().await(30, TimeUnit.SECONDS))
        assertEquals(3, w.transport.relays.lists.get())
    }

    @Test
    fun aUserIssuerCallWaitsForAQuietRunToEnd(): Unit = World(Draws({ it == 0L })).use { w ->
        val release = CountDownLatch(1)
        val p = ScriptedParticipant(onQuiet = { s ->
            category { invoiceStatus(s) }
            release.await(20, TimeUnit.SECONDS)
        })
        w.controller.setParticipant(p)
        val done = w.job()
        assertTrue(waitFor(10_000) { w.transport.calls.calls.size == 1 })
        val quietAtCall = CompletableFuture<Boolean>()
        w.controller.runUserIssuerCall { s ->
            quietAtCall.complete(w.runtime.quietRunning)
            category { invoiceStatus(s) }
        }
        Thread.sleep(200)
        assertFalse("the user call waits", quietAtCall.isDone)
        release.countDown()
        assertTrue(done.await(10, TimeUnit.SECONDS))
        assertEquals(false, quietAtCall.get(10, TimeUnit.SECONDS))
        assertTrue(waitFor(10_000) { w.transport.calls.calls.size == 2 })
        assertTrue(w.runtime.awaitIdle(10_000))
    }

    @Test
    fun aUserIssuerCallAfterAWipeFailsClosedWithoutNetwork(): Unit = World().use { w ->
        w.controller.onWipe()
        val seen = CompletableFuture<Pair<Boolean, String?>>()
        w.controller.runUserIssuerCall { s -> seen.complete(Pair(s.closed, category { invoiceStatus(s) })) }
        assertEquals(Pair<Boolean, String?>(true, "closed"), seen.get(10, TimeUnit.SECONDS))
        assertEquals(0, w.transport.ensures.get())
        assertEquals(0, w.transport.calls.calls.size)
    }

    @Test
    fun thePaymentScreenClosesTheRelaySessionAndHoldsRelaySessionsOff(): Unit = World(Draws({ false }, hold = 0.5)).use { w ->
        w.controller.onAppForeground()
        assertTrue(waitFor(5_000) { w.runtime.activeKind == SessionKind.FOREGROUND && w.transport.relays.lists.get() >= 1 })
        w.controller.onPaymentScreenShown()
        assertTrue("the relay session is closed at once", waitFor(5_000) { w.runtime.activeKind == null })
        assertTrue(w.transport.aborts.get() >= 1)
        val ensures = w.transport.ensures.get()
        // While it is shown nothing starts, visible or not; hiding the app hides it (hold U[20, 60] min: 40 here).
        w.controller.onAppForeground()
        assertTrue(w.runtime.awaitCommands(5_000))
        w.controller.onAppBackground()
        assertTrue(w.job().await(5, TimeUnit.SECONDS))
        w.controller.onAppForeground()
        assertTrue(w.runtime.awaitCommands(5_000))
        Thread.sleep(200)
        assertNull(w.runtime.activeKind)
        assertEquals(ensures, w.transport.ensures.get())
        w.clock.offsetMillis += 39 * MINUTE
        w.controller.onAppForeground()
        assertTrue(w.runtime.awaitCommands(5_000))
        Thread.sleep(200)
        assertNull("still held at 39 min", w.runtime.activeKind)
        w.clock.offsetMillis += 2 * MINUTE
        w.controller.onAppForeground()
        assertTrue("the visible app's session after the hold", waitFor(5_000) { w.runtime.activeKind == SessionKind.FOREGROUND })
    }

    @Test
    fun thePaymentScreenHoldsNoQuietRunAndNoUserIssuerCall(): Unit = World(Draws({ true })).use { w ->
        val p = ScriptedParticipant(onQuiet = { s -> category { invoiceStatus(s) } })
        w.controller.setParticipant(p)
        w.controller.onPaymentScreenShown()
        assertTrue(w.job().await(20, TimeUnit.SECONDS))
        assertEquals(1, p.quietSessions.size)
        assertTrue(w.runtime.awaitIdle(5_000))
        val user = CompletableFuture<String?>()
        w.controller.runUserIssuerCall { s -> user.complete(category { invoiceStatus(s) }) }
        assertNull(user.get(10, TimeUnit.SECONDS))
        assertEquals(listOf("invoiceStatus", "invoiceStatus"), w.transport.calls.calls.map { it.name })
        assertEquals(0, w.transport.relays.calls.get())
    }

    private companion object {
        val FLOWS = AtomicLong()
    }
}
