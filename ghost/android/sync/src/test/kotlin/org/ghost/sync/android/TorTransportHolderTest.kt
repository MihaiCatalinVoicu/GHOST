package org.ghost.sync.android

import org.ghost.network.NetworkException
import org.ghost.network.OnionAddress
import org.ghost.network.RelayTransport
import org.ghost.sync.port.SyncClock
import org.ghost.sync.port.TransportState
import org.ghost.sync.store.TestBytes
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ThreadFactory
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * The transport holder's state machine (design §1.4, §3.6, §5.4) over a fake factory, on real
 * threads and the real clock: one live native transport at a time, bootstrap bounded by the
 * deadline, abort from any thread, and the failure categories mapped to transport states.
 */
class TorTransportHolderTest {

    private object RealClock : SyncClock {
        override fun epochSeconds(): Long = System.currentTimeMillis() / 1000

        override fun monotonicMillis(): Long = System.nanoTime() / 1_000_000
    }

    private object Daemons : ThreadFactory {
        override fun newThread(r: Runnable): Thread = Thread(r, "holder-test").apply { isDaemon = true }
    }

    private sealed class Boot {
        object Ok : Boot()

        class Fail(val category: String) : Boot()

        /** Blocks until the transport is closed, then fails with `closed` (the native abort). */
        object UntilClosed : Boot()
    }

    /** A native transport stand-in that counts its native calls and its closes. */
    private class FakeTor(private val boot: Boot) : RelayTransport {
        @Volatile
        var closed = false
        val closes = AtomicInteger()
        val nativeCalls = AtomicInteger()
        val bootstraps = AtomicInteger()
        val lists = AtomicInteger()
        private val closeSignal = CountDownLatch(1)

        /** When set, a list call waits for it, whether or not the transport is closed (a slow native return). */
        @Volatile
        var listHold: CountDownLatch? = null

        override fun bootstrap() {
            nativeCalls.incrementAndGet()
            try {
                bootstraps.incrementAndGet()
                when (boot) {
                    Boot.Ok -> Unit
                    is Boot.Fail -> throw NetworkException(boot.category)
                    Boot.UntilClosed -> {
                        closeSignal.await(30, TimeUnit.SECONDS)
                        throw NetworkException("closed")
                    }
                }
            } finally {
                nativeCalls.decrementAndGet()
            }
        }

        override fun list(relay: OnionAddress, namespace: ByteArray, capability: ByteArray, cursor: ByteArray, limit: Int, deadlineMillis: Int): RelayTransport.Page {
            nativeCalls.incrementAndGet()
            try {
                lists.incrementAndGet()
                listHold?.await(30, TimeUnit.SECONDS)
                if (closed) throw NetworkException("closed")
                return RelayTransport.Page(emptyList(), ByteArray(0))
            } finally {
                nativeCalls.decrementAndGet()
            }
        }

        override fun store(relay: OnionAddress, namespace: ByteArray, capability: ByteArray, ciphertext: ByteArray, ttlSeconds: Int, deadlineMillis: Int): RelayTransport.StoreReceipt =
            throw NetworkException("transport")

        override fun get(relay: OnionAddress, namespace: ByteArray, capability: ByteArray, blobHash: ByteArray, deadlineMillis: Int): RelayTransport.FetchedBlob =
            throw NetworkException("transport")

        override fun check(relay: OnionAddress, namespace: ByteArray, capability: ByteArray, hashes: List<ByteArray>, deadlineMillis: Int): List<ByteArray> =
            throw NetworkException("transport")

        override fun rotateCircuits() = Unit

        override fun close() {
            closes.incrementAndGet()
            closed = true
            closeSignal.countDown()
        }
    }

    /**
     * Makes [FakeTor]s from a script. [overlaps] counts transports created while an earlier one was
     * still open or still inside a native call: two live Tor clients would share Arti's state
     * directory.
     */
    private class Factory(
        private val boot: (Int) -> Boot = { Boot.Ok },
        private val createFailure: (Int) -> String? = { null },
    ) : RelayTransportFactory {
        val made = CopyOnWriteArrayList<FakeTor>()
        val attempts = AtomicInteger()
        val overlaps = AtomicInteger()

        override fun create(): RelayTransport {
            val attempt = attempts.getAndIncrement()
            createFailure(attempt)?.let { throw NetworkException(it) }
            if (made.any { !it.closed || it.nativeCalls.get() > 0 }) overlaps.incrementAndGet()
            return FakeTor(boot(made.size)).also { made += it }
        }
    }

    private fun holder(factory: Factory) = TorTransportHolder(factory, RealClock, Daemons)

    private fun deadline(ms: Long): Long = RealClock.monotonicMillis() + ms

    private fun list(h: TorTransportHolder) = h.relays.list(TestBytes.onion(1), TestBytes.namespace(1), ByteArray(82), ByteArray(0), 4, 1_000)

    private fun waitFor(timeoutMillis: Long, condition: () -> Boolean): Boolean {
        val end = System.nanoTime() + timeoutMillis * 1_000_000
        while (System.nanoTime() < end) {
            if (condition()) return true
            Thread.sleep(5)
        }
        return condition()
    }

    @Test
    fun readyCreatesOneTransportAndBootstrapsItAgainOnEachEnsure() {
        val factory = Factory()
        val h = holder(factory)
        assertEquals(TransportState.READY, h.ensureReady(deadline(5_000)))
        assertEquals(TransportState.READY, h.ensureReady(deadline(5_000)))
        assertEquals(1, factory.made.size)
        assertEquals(2, factory.made[0].bootstraps.get())
        assertFalse(factory.made[0].closed)
    }

    @Test
    fun relaysReachTheCurrentTransportOnlyWhileItIsOpen() {
        val factory = Factory()
        val h = holder(factory)
        assertEquals("closed", assertThrows(NetworkException::class.java) { list(h) }.category)
        assertEquals(TransportState.READY, h.ensureReady(deadline(5_000)))
        list(h)
        assertEquals(1, factory.made[0].lists.get())
        h.abort()
        assertTrue(factory.made[0].closed)
        assertEquals("closed", assertThrows(NetworkException::class.java) { list(h) }.category)
        assertEquals(1, factory.made[0].lists.get())
    }

    @Test
    fun abortGivesTheNextSessionAFreshTransport() {
        val factory = Factory()
        val h = holder(factory)
        assertEquals(TransportState.READY, h.ensureReady(deadline(5_000)))
        h.abort()
        h.abort()
        assertEquals(1, factory.made[0].closes.get())
        assertEquals(TransportState.READY, h.ensureReady(deadline(5_000)))
        assertEquals(2, factory.made.size)
        assertFalse(factory.made[1].closed)
        assertEquals(0, factory.overlaps.get())
    }

    @Test
    fun aBootstrapPastTheDeadlineIsAbandonedAndItsTransportClosed() {
        val factory = Factory(boot = { if (it == 0) Boot.UntilClosed else Boot.Ok })
        val h = holder(factory)
        val started = System.nanoTime()
        assertEquals(TransportState.UNAVAILABLE, h.ensureReady(deadline(300)))
        val tookMillis = (System.nanoTime() - started) / 1_000_000
        assertTrue("returned at the deadline, took $tookMillis ms", tookMillis in 250..3_000)
        assertTrue(factory.made[0].closed)
        assertEquals(TransportState.READY, h.ensureReady(deadline(5_000)))
        assertEquals(2, factory.made.size)
        assertEquals(0, factory.overlaps.get())
    }

    @Test
    fun abortDuringABootstrapEndsItAtOnce() {
        val factory = Factory(boot = { Boot.UntilClosed })
        val h = holder(factory)
        val result = AtomicReference<TransportState>()
        val caller = Thread { result.set(h.ensureReady(deadline(30_000))) }.apply { isDaemon = true; start() }
        assertTrue(waitFor(5_000) { factory.made.size == 1 && factory.made[0].nativeCalls.get() == 1 })
        val started = System.nanoTime()
        h.abort()
        caller.join(5_000)
        assertFalse(caller.isAlive)
        assertTrue((System.nanoTime() - started) / 1_000_000 < 3_000)
        assertEquals(TransportState.UNAVAILABLE, result.get())
        assertTrue(factory.made[0].closed)
    }

    @Test
    fun bootstrapFailuresSpendTheTransportAndMapToStates() {
        val categories = listOf("tor_bootstrap_timeout", "tor_bootstrap", "closed", "timeout", "bridge_config", "tor_setup", "runtime")
        val expected = listOf(
            TransportState.UNAVAILABLE, TransportState.UNAVAILABLE, TransportState.UNAVAILABLE, TransportState.UNAVAILABLE,
            TransportState.BRIDGE_CONFIG, TransportState.FAILED, TransportState.FAILED,
        )
        val factory = Factory(boot = { i -> if (i < categories.size) Boot.Fail(categories[i]) else Boot.Ok })
        val h = holder(factory)
        for ((i, state) in expected.withIndex()) {
            assertEquals(categories[i], state, h.ensureReady(deadline(5_000)))
            assertTrue("a failed bootstrap closes ${categories[i]}", factory.made[i].closed)
        }
        assertEquals(TransportState.READY, h.ensureReady(deadline(5_000)))
        assertEquals(categories.size + 1, factory.made.size)
        assertEquals(0, factory.overlaps.get())
        assertFalse(h.nativeMissing)
    }

    @Test
    fun creationFailuresMapToStatesAndNativeMissingIsFinal() {
        val failures = listOf("bridge_config", "tor_setup", "internal", "native_missing")
        val factory = Factory(createFailure = { failures.getOrNull(it) })
        val h = holder(factory)
        assertEquals(TransportState.BRIDGE_CONFIG, h.ensureReady(deadline(5_000)))
        assertEquals(TransportState.FAILED, h.ensureReady(deadline(5_000)))
        assertEquals(TransportState.UNAVAILABLE, h.ensureReady(deadline(5_000)))
        assertFalse(h.nativeMissing)
        assertEquals(TransportState.FAILED, h.ensureReady(deadline(5_000)))
        assertTrue(h.nativeMissing)
        assertEquals(TransportState.FAILED, h.ensureReady(deadline(5_000)))
        assertEquals("no further attempt once the Tor core is missing", 4, factory.attempts.get())
        assertEquals(0, factory.made.size)
    }

    @Test
    fun aNewTransportWaitsUntilTheOldOneHasNoNativeCallLeft() {
        val factory = Factory()
        val h = holder(factory)
        assertEquals(TransportState.READY, h.ensureReady(deadline(5_000)))
        val old = factory.made[0]
        val slowReturn = CountDownLatch(1)
        old.listHold = slowReturn
        val outcome = AtomicReference<String>()
        val caller = Thread {
            try {
                list(h)
                outcome.set("answered")
            } catch (e: NetworkException) {
                outcome.set(e.category)
            }
        }.apply { isDaemon = true; start() }
        assertTrue(waitFor(5_000) { old.nativeCalls.get() == 1 })
        h.abort()
        assertTrue(old.closed)
        // The old call has not returned: no second client may start, even past the deadline.
        assertEquals(TransportState.UNAVAILABLE, h.ensureReady(deadline(300)))
        assertEquals(1, factory.made.size)
        slowReturn.countDown()
        caller.join(5_000)
        assertEquals("closed", outcome.get())
        assertEquals(TransportState.READY, h.ensureReady(deadline(5_000)))
        assertEquals(2, factory.made.size)
        assertEquals(0, factory.overlaps.get())
    }

    @Test
    fun anExpiredDeadlineCreatesNothing() {
        val factory = Factory()
        val h = holder(factory)
        assertEquals(TransportState.UNAVAILABLE, h.ensureReady(RealClock.monotonicMillis() - 1))
        assertEquals(0, factory.attempts.get())
        h.abort()
        assertEquals("TorTransportHolder", h.toString())
    }
}
