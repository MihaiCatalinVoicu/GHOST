package org.ghost.sync.android

import android.content.Context
import org.ghost.network.NetworkException
import org.ghost.network.PtInstaller
import org.ghost.network.RelayTransport
import org.ghost.network.TorIssuerTransport
import org.ghost.network.TorRelayTransport
import org.ghost.sync.engine.ErrorClass
import org.ghost.sync.engine.ErrorPolicy
import org.ghost.sync.port.EntitlementCalls
import org.ghost.sync.port.LeasePort
import org.ghost.sync.port.MirrorCalls
import org.ghost.sync.port.RelayPort
import org.ghost.sync.port.SyncClock
import org.ghost.sync.port.TransportLease
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
 *    transport; in-flight calls end with `closed`, and the next session gets new circuits. It
 *    also starts a new [BootstrapPlan] epoch (Phase 12 §6.5): the next session re-runs the
 *    reduced auto mode from its first attempt.
 *  - The reduced auto mode (Q6, design `faza12-transports.md` §6.5): when a [BootstrapPlan] is
 *    present, each `create` claims the epoch's next attempt — direct first (when allowed), then
 *    the configured bridge lines in order, one fresh client per attempt, each with its own
 *    native 180 s deadline. An exhausted plan fails fast with the spent category (`tor_bootstrap`)
 *    without creating a client, until the caller gives up; never clearnet, never a non-Tor
 *    fallback (R12-6). PT attempts resolve `pt_dir` through [PtInstaller]: already-extracted is
 *    a cheap check, the first PT need installs (verify + chmod 700 + atomic replace), and a
 *    refused extraction fails closed — no `pt_dir`, so PT lines meet `bridge_config`
 *    (`PtBinaryMissing`), never a half-trusted exec (§5.4.4).
 *  - [LeasePort] (Phase 8 design §11.6): the session participant's redemption and issuer calls run
 *    on the same transport under a lease. A lease reaches only the current transport once it has
 *    answered READY, never one closed or not yet bootstrapped; the lease check and the transport's
 *    use count are taken under one lock, so after [TransportLease.close] no call of that lease can
 *    land on any transport, in particular not on one created for a later session. A lease never
 *    creates or bootstraps a transport.
 */
private class MirrorCallsOn(transport: RelayTransport) : MirrorCalls {
    private val tor = transport as? TorRelayTransport
        ?: throw NetworkException("internal")

    override fun fetchBundle(mirrorSet: Long, slot: Int, deadlineMillis: Int): ByteArray =
        tor.fetchMirrorBundle(mirrorSet, slot, deadlineMillis)

    override fun fetchApkChunk(mirrorSet: Long, slot: Int, chunkIndex: Long, deadlineMillis: Int): ByteArray =
        tor.fetchMirrorApkChunk(mirrorSet, slot, chunkIndex, deadlineMillis)
}

internal class TorTransportHolder(
    private val factory: RelayTransportFactory,
    private val clock: SyncClock,
    private val threads: ThreadFactory,
    private val entitlement: EntitlementCallsFactory = EntitlementCallsFactory.TOR,
    private val bootstrapPlan: BootstrapPlan? = null,
) : TransportPort, LeasePort {

    /** One native transport and the native calls running on it (bootstrap, relay and participant calls). */
    private class Slot(val transport: RelayTransport, val calls: EntitlementCalls) {
        var busy = 0
        var closed = false

        /** The transport answered READY (a bootstrap succeeded while it was current). */
        var ready = false
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
    private val readyChanged = lock.newCondition()
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
        bootstrapPlan?.reset()
        val slot = lock.withLock {
            generation++
            current
        }
        if (slot != null) retire(slot)
    }

    override fun openLease(): TransportLease = Lease()

    private fun createAndBootstrap(deadline: Long): TransportState {
        if (!awaitRetired(deadline)) return TransportState.UNAVAILABLE
        val startedAt = lock.withLock { generation }
        val transport = try {
            factory.create()
        } catch (e: NetworkException) {
            return stateAfterFailure(e.category)
        }
        val slot = Slot(transport, entitlement.of(transport))
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
            return lock.withLock {
                if (current === slot && !slot.closed) {
                    slot.ready = true
                    readyChanged.signalAll()
                    TransportState.READY
                } else {
                    TransportState.UNAVAILABLE
                }
            }
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

    /** The current transport if it answered READY and is not closed (call with [lock] held). */
    private fun readySlot(): Slot? = current?.takeIf { it.ready && !it.closed }

    /** One lease; its state is guarded by the holder's [lock], like the slots it reaches. */
    private inner class Lease : TransportLease {
        private var open = true

        override val closed: Boolean get() = lock.withLock { !open }

        override fun close() = lock.withLock {
            open = false
            readyChanged.signalAll()
        }

        override fun awaitReady(deadlineMonotonicMillis: Long): Boolean = lock.withLock {
            while (open && readySlot() == null) {
                val left = deadlineMonotonicMillis - clock.monotonicMillis()
                if (left <= 0) return@withLock false
                readyChanged.await(left, TimeUnit.MILLISECONDS)
            }
            open
        }

        override fun <T> use(block: (EntitlementCalls) -> T): T {
            val slot = enter() ?: throw NetworkException(CLOSED)
            val failure = try {
                return block(slot.calls)
            } catch (e: NetworkException) {
                e
            } finally {
                release(slot)
            }
            if (failure.category != ONION_SERVICE_NOT_FOUND) throw failure
            return retryWithFreshDirectory(slot, failure, block)
        }

        /** Recreate Arti's DirMgr from the same state/cache and retry once, never under the old call's use count. */
        private fun <T> retryWithFreshDirectory(
            stale: Slot,
            original: NetworkException,
            block: (EntitlementCalls) -> T,
        ): T {
            bootstrapPlan?.reset()
            retire(stale)
            val state = ensureReady(clock.monotonicMillis() + DIRECTORY_RECOVERY_BOOTSTRAP_MILLIS)
            if (state != TransportState.READY) throw original
            val refreshed = enter() ?: throw original
            try {
                return block(refreshed.calls)
            } catch (e: NetworkException) {
                if (e.category == ONION_SERVICE_NOT_FOUND) retire(refreshed)
                throw e
            } finally {
                release(refreshed)
            }
        }

        override fun <T> useMirror(block: (MirrorCalls) -> T): T {
            val slot = enter() ?: throw NetworkException(CLOSED)
            try {
                return block(MirrorCallsOn(slot.transport))
            } finally {
                release(slot)
            }
        }

        override fun newFlow(): ByteArray = TorIssuerTransport.newFlow()

        override fun endFlow(flow: ByteArray) {
            val slot = enter() ?: return
            try {
                slot.calls.endFlow(flow)
            } finally {
                release(slot)
            }
        }

        /** The READY transport with its use count taken, or null when the lease is closed or none is READY. */
        private fun enter(): Slot? = lock.withLock { if (open) readySlot()?.also { it.busy++ } else null }

        override fun toString(): String = "TransportLease"
    }

    override fun toString(): String = "TorTransportHolder"

    companion object {
        private const val CLOSED = "closed"
        private const val ONION_SERVICE_NOT_FOUND = "onion_service_not_found"
        private const val DIRECTORY_RECOVERY_BOOTSTRAP_MILLIS = 180_000L

        /** The exhausted plan's category: `BootstrapSpent`'s mapping (design §6.5 point 4). */
        private const val PLAN_SPENT = "tor_bootstrap"
        private val created = AtomicBoolean()

        /**
         * The process's holder. Arti's state and directory cache live under the app's no-backup
         * directory (app-private, excluded from backup and device transfer); the directories are
         * resolved when the first transport is created, on a sync thread.
         *
         * [bridgeLines] and [allowDirect] feed the reduced auto mode (§6.5): the providers are
         * read when an attempt is claimed, so a line change takes effect next epoch. The defaults
         * are today's shape — direct only — and every existing caller is unchanged.
         */
        fun forApp(
            context: Context,
            clock: SyncClock,
            threads: ThreadFactory,
            bridgeLines: () -> List<String> = { emptyList() },
            allowDirect: () -> Boolean = { true },
        ): TorTransportHolder {
            check(created.compareAndSet(false, true)) { "one Tor transport holder per process" }
            val app = context.applicationContext
            val plan = BootstrapPlan(bridgeLines, allowDirect)
            val installer = try {
                PtInstaller.forApp(app)
            } catch (e: NetworkException) {
                null
            }
            val ptLock = Any()
            var ptResolved = false
            var ptDir: File? = null

            /**
             * `pt_dir` for the next attempt: the extracted, hash-verified binary's directory, or
             * null (PT unavailable). A direct attempt never installs (§5.4.4: extraction at first
             * PT use); the first PT attempt does. A refused extraction is remembered only when PT
             * was actually needed — a "no" on the direct path is not final.
             */
            fun resolvePtDir(need: Boolean): File? {
                if (installer == null) return null
                synchronized(ptLock) {
                    if (!ptResolved) {
                        ptDir = try {
                            when {
                                installer.installed() -> installer.ptDir()
                                need -> installer.install()
                                else -> null
                            }
                        } catch (e: NetworkException) {
                            // Fail closed (§5.4.4): no pt_dir, so PT lines meet PtBinaryMissing
                            // (bridge_config) — never a half-trusted exec. The explicit PT-1
                            // entry ([PtInstaller.install] called directly) surfaces the category.
                            null
                        }
                        if (ptDir != null || need) ptResolved = true
                    }
                }
                return ptDir
            }

            val base = File(app.noBackupFilesDir, "tor")
            return TorTransportHolder(
                {
                    val attempt = plan.claim() ?: throw NetworkException(PLAN_SPENT)
                    val needsPt = attempt.bridgeLines.any { it.startsWith("obfs4 ") || it.startsWith("webtunnel ") }
                    TorRelayTransport.create(
                        File(base, "state"),
                        File(base, "cache"),
                        attempt.bridgeLines,
                        resolvePtDir(needsPt),
                    )
                },
                clock,
                threads,
                bootstrapPlan = plan,
            )
        }
    }
}
