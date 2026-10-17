package org.ghost.sync.android

import org.ghost.network.NetworkException
import org.ghost.network.OnionAddress
import org.ghost.network.RelayTransport
import org.ghost.sync.port.SyncClock
import org.ghost.sync.port.TransportState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.ThreadFactory
import java.util.concurrent.atomic.AtomicInteger

/**
 * PT-U4 (Phase 12 design `faza12-transports.md` §6.5, §12.2): the reduced auto mode as a pure
 * policy over the real holder — direct first (when allowed), the configured bridge lines in
 * order, one fresh client per attempt, the exhausted plan failing fast with the spent category
 * (no client created) until the caller gives up, a new epoch on [TorTransportHolder.abort], and
 * never a clearnet shape: every created transport is either direct or carries exactly the
 * configured lines (Q6, X-T2, R12-6; D11's per-attempt native deadline is the shipped Phase 6
 * bound, unchanged here).
 */
class BootstrapPlanTest {

    private object RealClock : SyncClock {
        override fun epochSeconds(): Long = System.currentTimeMillis() / 1000
        override fun monotonicMillis(): Long = System.nanoTime() / 1_000_000
    }

    private object Daemons : ThreadFactory {
        override fun newThread(r: Runnable): Thread = Thread(r, "plan-test").apply { isDaemon = true }
    }

    private val line1 = "obfs4 192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=AA== iat-mode=0"
    private val line2 = "webtunnel 192.0.2.11:443 0123456789ABCDEF0123456789ABCDEF01234567 url=https://192.0.2.11/xx ver=ab"

    /** A transport stand-in whose bootstrap fails after [failures] successes... always fails here. */
    private class FailingTor : RelayTransport {
        override fun bootstrap() = throw NetworkException("tor_bootstrap_timeout")
        override fun list(relay: OnionAddress, namespace: ByteArray, capability: ByteArray, cursor: ByteArray, limit: Int, deadlineMillis: Int): RelayTransport.Page =
            throw NetworkException("transport")
        override fun store(relay: OnionAddress, namespace: ByteArray, capability: ByteArray, ciphertext: ByteArray, ttlSeconds: Int, deadlineMillis: Int): RelayTransport.StoreReceipt =
            throw NetworkException("transport")
        override fun get(relay: OnionAddress, namespace: ByteArray, capability: ByteArray, blobHash: ByteArray, deadlineMillis: Int): RelayTransport.FetchedBlob =
            throw NetworkException("transport")
        override fun check(relay: OnionAddress, namespace: ByteArray, capability: ByteArray, hashes: List<ByteArray>, deadlineMillis: Int): List<ByteArray> =
            throw NetworkException("transport")
        override fun rotateCircuits() = Unit
        override fun close() = Unit
    }

    /** The production wiring of [TorTransportHolder.forApp], minus the Android context. */
    private class Wired(
        lines: List<String>,
        allowDirect: Boolean,
        private val boot: (Int) -> Unit = {},
    ) {
        val plan = BootstrapPlan(lines = { lines }, allowDirect = { allowDirect })
        val created = CopyOnWriteArrayList<List<String>>()
        val creates = AtomicInteger()
        val holder = TorTransportHolder(
            {
                val attempt = plan.claim() ?: throw NetworkException("tor_bootstrap")
                created += attempt.bridgeLines
                creates.incrementAndGet()
                boot(creates.get() - 1)
                FailingTor()
            },
            RealClock,
            Daemons,
            bootstrapPlan = plan,
        )
    }

    private fun deadline(): Long = RealClock.monotonicMillis() + 30_000

    @Test
    fun policySequenceIsDirectThenLinesInOrder() {
        val plan = BootstrapPlan(lines = { listOf(line1, line2) })
        assertEquals(BootstrapAttempt.Direct, plan.claim())
        assertEquals(BootstrapAttempt.Bridges(line1), plan.claim())
        assertEquals(BootstrapAttempt.Bridges(line2), plan.claim())
        assertEquals(null, plan.claim())
    }

    @Test
    fun bridgesOnlyModeSkipsDirect() {
        val plan = BootstrapPlan(lines = { listOf(line1) }, allowDirect = { false })
        assertEquals(BootstrapAttempt.Bridges(line1), plan.claim())
        assertEquals(null, plan.claim())
    }

    @Test
    fun noLinesIsSingleDirectAttemptPerEpoch() {
        val plan = BootstrapPlan(lines = { emptyList() })
        assertEquals(BootstrapAttempt.Direct, plan.claim())
        assertEquals(null, plan.claim())
        plan.reset()
        assertEquals(BootstrapAttempt.Direct, plan.claim())
    }

    @Test
    fun failedBootstrapsWalkTheSequenceThenFailFastWithoutCreating() {
        val w = Wired(listOf(line1, line2), allowDirect = true)
        // Direct fails, line 1 fails, line 2 fails: one fresh client per attempt, in order.
        repeat(3) { assertEquals(TransportState.UNAVAILABLE, w.holder.ensureReady(deadline())) }
        assertEquals(listOf(emptyList(), listOf(line1), listOf(line2)), w.created)

        // Exhausted: the spent category answers without creating a client, however often the
        // caller retries (it gives up; §6.5 point 4).
        repeat(3) { assertEquals(TransportState.UNAVAILABLE, w.holder.ensureReady(deadline())) }
        assertEquals(3, w.creates.get())
    }

    @Test
    fun abortStartsANewEpochFromTheTop() {
        val w = Wired(listOf(line1), allowDirect = true)
        repeat(2) { w.holder.ensureReady(deadline()) } // direct + line 1, both fail
        assertEquals(2, w.creates.get())
        w.holder.abort()
        assertEquals(TransportState.UNAVAILABLE, w.holder.ensureReady(deadline()))
        assertEquals(listOf(emptyList(), listOf(line1), emptyList()), w.created)
    }

    @Test
    fun everyCreatedTransportIsTorDirectOrConfiguredLines() {
        // The never-clearnet shape: the factory only ever sees the direct config (empty lines)
        // or the exact user-provided lines — there is no other path into TorRelayTransport.create.
        val w = Wired(listOf(line1, line2), allowDirect = true)
        repeat(2) { w.holder.ensureReady(deadline()) }
        val allowed = setOf(emptyList(), listOf(line1), listOf(line2))
        assertTrue(w.created.all { it in allowed })
    }
}
