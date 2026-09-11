package org.ghost.sync.android

import android.content.Context
import org.ghost.network.NetworkException
import org.ghost.network.RelayTransport
import org.ghost.network.TorRelayTransport
import org.ghost.sync.engine.ErrorClass
import org.ghost.sync.engine.ErrorPolicy
import org.ghost.sync.port.RelayPort
import org.ghost.sync.port.SyncClock
import org.ghost.sync.port.TransportPort
import org.ghost.sync.port.TransportState
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ThreadFactory
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/** Creates a transport without network access; production: [TorRelayTransport.create]. */
internal fun interface RelayTransportFactory {
    fun create(): RelayTransport
}

/**
 * [TransportPort] over the embedded Tor client (design §1.4, §3.6, §5.4). The process has one holder
 * (created by [forApp], owned by [SyncRuntime]) and the holder has at most one live native
 * transport: two live Tor clients must never share Arti's state directory (client-core transport).
 *
 *  - [ensureReady] creates a transport if there is none and bootstraps it on a helper thread,
 *    waiting at most until the deadline. At the deadline, or when [abort] runs meanwhile, the
 *    transport is closed, which ends the native bootstrap, and the answer is UNAVAILABLE. Bootstrap
 *    runs on every call: on a bootstrapped client it returns at once (client-core: "a successful
 *    bootstrap may be awaited again"), and after `not_bootstrapped` it bootstraps again.
 *  - A failed or abandoned bootstrap spends the transport: it is closed, and the next [ensureReady]
 *    creates a fresh one (NEW_TRANSPORT). `native_missing` is final for the process (FAILED).
 *  - A new transport is created only after every closed one has no native call left (bootstrap or
 *    relay call). If that takes past the deadline, the answer is UNAVAILABLE and nothing is created.
 *  - [abort] (any thread: onStopJob, a session's end, a transport fault) closes the current
 *    transport; in-flight calls end with `closed`, and the next session gets new circuits.
 */
internal class TorTransportHolder(
    private val factory: RelayTransportFactory,
    private val clock: SyncClock,
    private val threads: ThreadFactory,
) : TransportPort {

    /** One native transport and the native calls running on it (bootstrap and relay calls). */
    private class Slot(val transport: RelayTransport) {
        var busy = 0
        var closed = false
    }

    /** Result of one bootstrap attempt on its helper thread. */
    private class Attempt {
        val done = CountDownLatch(1)

        @Volatile
        var succeeded = false

        @Volatile
        var category: String? = null
    }

    private val lock = ReentrantLock()
    private val released = lock.newCondition()
    private val ensuring = ReentrantLock()
    private var current: Slot? = null
    private var generation = 0L
    private val retired = HashSet<Slot>()

    /** `native_missing` was seen: the Tor core cannot load in this process. */
    @Volatile
    var nativeMissing: Boolean = false
        private set

    private val access = object : TransportAccess {
        override fun <T> use(block: (RelayTransport) -> T): T {
            val slot = lock.withLock { current?.takeIf { !it.closed }?.also { it.busy++ } } ?: throw NetworkException(CLOSED)
            try {
                return block(slot.transport)
            } finally {
                release(slot)
            }
        }
    }

    override val relays: RelayPort = TorRelayPort(access)

    override fun ensureReady(deadlineMonotonicMillis: Long): TransportState = ensuring.withLock {
        when {
            nativeMissing -> TransportState.FAILED
            deadlineMonotonicMillis <= clock.monotonicMillis() -> TransportState.UNAVAILABLE
            else -> {
                val slot = lock.withLock { current }
                if (slot != null) bootstrap(slot, deadlineMonotonicMillis) else createAndBootstrap(deadlineMonotonicMillis)
            }
        }
    }

    override fun abort() {
        val slot = lock.withLock {
            generation++
            current
        }
        if (slot != null) retire(slot)
    }

    private fun createAndBootstrap(deadline: Long): TransportState {
        if (!awaitRetired(deadline)) return TransportState.UNAVAILABLE
        val startedAt = lock.withLock { generation }
        val transport = try {
            factory.create()
        } catch (e: NetworkException) {
            return stateAfterFailure(e.category)
        }
        val slot = Slot(transport)
        // An abort while the transport was being created wins: it is closed unused.
        val installed = lock.withLock { (generation == startedAt).also { if (it) current = slot } }
        if (!installed) {
            transport.close()
            return TransportState.UNAVAILABLE
        }
        return bootstrap(slot, deadline)
    }

    /** Waits until no closed transport has a native call left; false at the deadline. */
    private fun awaitRetired(deadline: Long): Boolean = lock.withLock {
        while (retired.isNotEmpty()) {
            val left = deadline - clock.monotonicMillis()
            if (left <= 0) return@withLock false
            released.await(left, TimeUnit.MILLISECONDS)
        }
        true
    }

    private fun bootstrap(slot: Slot, deadline: Long): TransportState {
        val left = deadline - clock.monotonicMillis()
        if (left <= 0) return TransportState.UNAVAILABLE
        val entered = lock.withLock { (!slot.closed).also { if (it) slot.busy++ } }
        if (!entered) return TransportState.UNAVAILABLE
        val attempt = Attempt()
        threads.newThread {
            try {
                slot.transport.bootstrap()
                attempt.succeeded = true
            } catch (e: NetworkException) {
                attempt.category = e.category
            } finally {
                attempt.done.countDown()
                release(slot)
            }
        }.start()
        if (!attempt.done.await(left, TimeUnit.MILLISECONDS)) {
            // Past the deadline: closing the transport ends the native bootstrap.
            retire(slot)
            return TransportState.UNAVAILABLE
        }
        if (attempt.succeeded) {
            return lock.withLock { if (current === slot && !slot.closed) TransportState.READY else TransportState.UNAVAILABLE }
        }
        retire(slot)
        // No category: a JVM error ended the helper thread, which ends the process.
        val category = attempt.category ?: return TransportState.FAILED
        return stateAfterFailure(category)
    }

    private fun stateAfterFailure(category: String): TransportState = when (ErrorPolicy.classify(category)) {
        ErrorClass.LOCAL_FATAL -> {
            if (category == ErrorPolicy.NATIVE_MISSING) nativeMissing = true
            TransportState.FAILED
        }
        ErrorClass.CONFIG -> TransportState.BRIDGE_CONFIG
        // tor_bootstrap, tor_bootstrap_timeout, closed (aborted) and anything else: a fresh
        // transport next time, after the session's in-memory backoff.
        else -> TransportState.UNAVAILABLE
    }

    /** Closes [slot] once; while native calls remain on it, no new transport is created. */
    private fun retire(slot: Slot) {
        val close = lock.withLock {
            if (current === slot) current = null
            if (slot.closed) {
                false
            } else {
                slot.closed = true
                if (slot.busy > 0) retired += slot
                true
            }
        }
        if (close) slot.transport.close()
    }

    private fun release(slot: Slot) = lock.withLock {
        slot.busy--
        if (slot.busy == 0 && retired.remove(slot)) released.signalAll()
    }

    override fun toString(): String = "TorTransportHolder"

    companion object {
        private const val CLOSED = "closed"
        private val created = AtomicBoolean()

        /**
         * The process's holder. Arti's state and directory cache live under the app's no-backup
         * directory (app-private, excluded from backup and device transfer); the directories are
         * resolved when the first transport is created, on a sync thread.
         */
        fun forApp(context: Context, clock: SyncClock, threads: ThreadFactory): TorTransportHolder {
            check(created.compareAndSet(false, true)) { "one Tor transport holder per process" }
            val app = context.applicationContext
            return TorTransportHolder({
                val base = File(app.noBackupFilesDir, "tor")
                TorRelayTransport.create(File(base, "state"), File(base, "cache"))
            }, clock, threads)
        }
    }
}
