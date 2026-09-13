package org.ghost.sync.android

import org.ghost.network.NetworkException
import org.ghost.network.OnionAddress
import org.ghost.network.RelayTransport
import org.ghost.sync.engine.RecordingCalls
import org.ghost.sync.engine.category
import org.ghost.sync.port.SyncClock
import org.ghost.sync.port.TransportLease
import org.ghost.sync.port.TransportState
import org.ghost.sync.store.TestBytes
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ThreadFactory
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * The holder's leases (Phase 8 design §11.6), on real threads and the real clock: a lease reaches
 * only the transport that answered READY, nothing after it closed (in particular no transport made
 * later, for another session), never one still bootstrapping; a lease call in flight holds back the
 * next transport like a relay call does; ending a flow never throws.
 */
class TransportLeaseTest {

    private object RealClock : SyncClock {
        override fun epochSeconds(): Long = System.currentTimeMillis() / 1000

        override fun monotonicMillis(): Long = System.nanoTime() / 1_000_000
    }

    private object Daemons : ThreadFactory {
        override fun newThread(r: Runnable): Thread = Thread(r, "lease-test").apply { isDaemon = true }
    }

    /** A native transport stand-in; [bootHold] holds its bootstrap until released or closed. */
    private class FakeTor(private val bootHold: CountDownLatch?) : RelayTransport {
        @Volatile
        var closed = false
        val nativeCalls = AtomicInteger()

        override fun bootstrap() {
            nativeCalls.incrementAndGet()
            try {
                bootHold?.await(30, TimeUnit.SECONDS)
                if (closed) throw NetworkException("closed")
            } finally {
                nativeCalls.decrementAndGet()
            }
        }

        override fun store(relay: OnionAddress, namespace: ByteArray, capability: ByteArray, ciphertext: ByteArray, ttlSeconds: Int, deadlineMillis: Int): RelayTransport.StoreReceipt =
            throw NetworkException("transport")

        override fun get(relay: OnionAddress, namespace: ByteArray, capability: ByteArray, blobHash: ByteArray, deadlineMillis: Int): RelayTransport.FetchedBlob =
            throw NetworkException("transport")

        override fun list(relay: OnionAddress, namespace: ByteArray, capability: ByteArray, cursor: ByteArray, limit: Int, deadlineMillis: Int): RelayTransport.Page =
            throw NetworkException("transport")

        override fun check(relay: OnionAddress, namespace: ByteArray, capability: ByteArray, hashes: List<ByteArray>, deadlineMillis: Int): List<ByteArray> =
            throw NetworkException("transport")

        override fun rotateCircuits() = Unit

        override fun close() {
            closed = true
            bootHold?.countDown()
        }
    }

    private class Factory(private val holds: (Int) -> CountDownLatch? = { null }) : RelayTransportFactory {
        val made = CopyOnWriteArrayList<FakeTor>()
        val overlaps = AtomicInteger()

        override fun create(): RelayTransport {
            if (made.any { !it.closed || it.nativeCalls.get() > 0 }) overlaps.incrementAndGet()
            return FakeTor(holds(made.size)).also { made += it }
        }
    }

    /** Entitlement calls per transport; a call counts as a native call of its transport while it runs. */
    private class Calls {
        val byTransport = ConcurrentHashMap<RelayTransport, RecordingCalls>()
        val onClosedTransport = AtomicInteger()

        @Volatile
        var callHold: CountDownLatch? = null

        val factory = EntitlementCallsFactory { t ->
            val tor = t as FakeTor
            RecordingCalls().also { rc ->
                byTransport[t] = rc
                rc.during = {
                    tor.nativeCalls.incrementAndGet()
                    try {
                        if (tor.closed) onClosedTransport.incrementAndGet()
                        callHold?.await(30, TimeUnit.SECONDS)
                    } finally {
                        tor.nativeCalls.decrementAndGet()
                    }
                }
            }
        }

        fun on(t: FakeTor): Int = byTransport[t]?.calls?.size ?: 0
    }

    private fun deadline(ms: Long): Long = RealClock.monotonicMillis() + ms

    private fun redeem(lease: TransportLease) {
        lease.use { it.redeem(TestBytes.onion(1), ByteArray(32), ByteArray(354), ByteArray(16), 1_000) }
    }

    private fun waitFor(timeoutMillis: Long, condition: () -> Boolean): Boolean {
        val end = System.nanoTime() + timeoutMillis * 1_000_000
        while (System.nanoTime() < end) {
            if (condition()) return true
            Thread.sleep(5)
        }
        return condition()
    }

    @Test
    fun aLeaseReachesOnlyTheReadyTransportAndNothingOnceClosed() {
        val f = Factory()
        val c = Calls()
        val h = TorTransportHolder(f, RealClock, Daemons, c.factory)
        val lease = h.openLease()
        assertEquals("no transport yet", "closed", category { redeem(lease) })
        assertFalse(lease.awaitReady(deadline(50)))
        assertEquals(TransportState.READY, h.ensureReady(deadline(5_000)))
        assertTrue(lease.awaitReady(deadline(50)))
        redeem(lease)
        assertEquals(1, c.on(f.made[0]))
        lease.close()
        assertTrue(lease.closed)
        assertFalse(lease.awaitReady(deadline(5_000)))
        assertEquals("closed", category { redeem(lease) })
        assertEquals(1, c.on(f.made[0]))
    }

    @Test
    fun aClosedLeaseNeverReachesATransportMadeLater() {
        val f = Factory()
        val c = Calls()
        val h = TorTransportHolder(f, RealClock, Daemons, c.factory)
        val first = h.openLease()
        assertEquals(TransportState.READY, h.ensureReady(deadline(5_000)))
        redeem(first)
        // The runtime closes an activity's lease, then aborts the transport; the next activity makes another.
        first.close()
        h.abort()
        assertEquals(TransportState.READY, h.ensureReady(deadline(5_000)))
        val next = h.openLease()
        redeem(next)
        assertEquals("closed", category { redeem(first) })
        assertEquals(2, f.made.size)
        assertEquals(1, c.on(f.made[0]))
        assertEquals("only the new lease reached the new transport", 1, c.on(f.made[1]))
        assertEquals(0, c.onClosedTransport.get())
    }

    @Test
    fun anOpenLeaseReachesNoTransportBetweenAnAbortAndTheNextReady() {
        val f = Factory()
        val c = Calls()
        val h = TorTransportHolder(f, RealClock, Daemons, c.factory)
        val lease = h.openLease()
        assertEquals(TransportState.READY, h.ensureReady(deadline(5_000)))
        h.abort()
        assertEquals("closed", category { redeem(lease) })
        assertFalse(lease.awaitReady(deadline(50)))
        assertEquals(0, c.onClosedTransport.get())
    }

    @Test
    fun aLeaseNeverReachesATransportStillBootstrapping() {
        val hold = CountDownLatch(1)
        val f = Factory { hold }
        val c = Calls()
        val h = TorTransportHolder(f, RealClock, Daemons, c.factory)
        val lease = h.openLease()
        val state = AtomicReference<TransportState>()
        val t = Thread { state.set(h.ensureReady(deadline(10_000))) }.apply { start() }
        assertTrue(waitFor(5_000) { f.made.size == 1 && f.made[0].nativeCalls.get() == 1 })
        assertEquals("closed", category { redeem(lease) })
        assertFalse(lease.awaitReady(deadline(100)))
        hold.countDown()
        assertTrue(lease.awaitReady(deadline(5_000)))
        redeem(lease)
        t.join(5_000)
        assertEquals(TransportState.READY, state.get())
        assertEquals(1, c.on(f.made[0]))
    }

    @Test
    fun awaitReadyEndsWhenTheLeaseCloses() {
        val h = TorTransportHolder(Factory(), RealClock, Daemons, Calls().factory)
        val lease = h.openLease()
        val result = AtomicReference<Boolean>()
        val t = Thread { result.set(lease.awaitReady(Long.MAX_VALUE)) }.apply { start() }
        Thread.sleep(100)
        assertNull(result.get())
        lease.close()
        t.join(5_000)
        assertEquals(false, result.get())
    }

    @Test
    fun aLeaseCallInFlightHoldsBackTheNextTransport() {
        val f = Factory()
        val c = Calls()
        val h = TorTransportHolder(f, RealClock, Daemons, c.factory)
        assertEquals(TransportState.READY, h.ensureReady(deadline(5_000)))
        val lease = h.openLease()
        c.callHold = CountDownLatch(1)
        val outcome = AtomicReference<String?>("pending")
        val call = Thread { outcome.set(category { redeem(lease) }) }.apply { start() }
        assertTrue(waitFor(5_000) { f.made[0].nativeCalls.get() == 1 })
        lease.close()
        h.abort()
        val state = AtomicReference<TransportState>()
        val next = Thread { state.set(h.ensureReady(deadline(10_000))) }.apply { start() }
        Thread.sleep(200)
        assertEquals("no new transport while the lease call runs on the old one", 1, f.made.size)
        c.callHold?.countDown()
        call.join(5_000)
        next.join(5_000)
        assertNull("the call in flight completed", outcome.get())
        assertEquals(TransportState.READY, state.get())
        assertEquals(2, f.made.size)
        assertEquals(0, f.overlaps.get())
    }

    @Test
    fun endFlowNeverThrowsAndFlowsAreFresh() {
        val f = Factory()
        val c = Calls()
        val h = TorTransportHolder(f, RealClock, Daemons, c.factory)
        val lease = h.openLease()
        val flow = lease.newFlow()
        assertEquals(16, flow.size)
        assertNotEquals(flow.toList(), lease.newFlow().toList())
        lease.endFlow(flow)
        assertEquals(TransportState.READY, h.ensureReady(deadline(5_000)))
        lease.endFlow(flow)
        assertEquals(1, c.byTransport.getValue(f.made[0]).ended.size)
        h.abort()
        lease.endFlow(flow)
        lease.close()
        lease.endFlow(flow)
        assertEquals(1, c.byTransport.getValue(f.made[0]).ended.size)
    }

    @Test
    fun aTransportWithoutEntitlementCallsFailsInternalBeforeAnyIO() {
        // The production factory on a transport that is not the Rust core's.
        val h = TorTransportHolder(Factory(), RealClock, Daemons)
        assertEquals(TransportState.READY, h.ensureReady(deadline(5_000)))
        val lease = h.openLease()
        assertEquals("internal", category { redeem(lease) })
        assertEquals("internal", category { lease.use { it.invoiceStatus(ByteArray(16), ByteArray(16), ByteArray(32), 1_000) } })
        lease.endFlow(ByteArray(16))
        assertEquals("TransportLease", lease.toString())
    }
}
