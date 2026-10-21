package org.ghost.sync.android

import org.ghost.network.TorRelayTransport
import org.ghost.sync.engine.KeyedRandomSources
import org.ghost.sync.engine.TrafficPolicy
import org.ghost.sync.port.RandomSources
import org.ghost.sync.port.SyncClock
import org.ghost.sync.port.WakeScheduler
import java.io.File

/**
 * Headless host support for the staging harness (tools/staging-harness, Phase 13 Appendix B.2):
 * the app's real sync runtime over the real Tor transport, without an Android context. The
 * harness runs on a JVM in WSL against the live staging deployment; this factory is the only
 * production-code door it uses, and everything else is the app's own wiring.
 *
 * The differences from [AndroidSyncController.create] are exactly the Android-shaped ones: the
 * transport's state lives in caller-owned directories (the app used the no-backup dir), the wake
 * is caller-supplied (the app used JobScheduler), and the clock is [HostClock]. One transport
 * holder per process still holds - do not call [TorTransportHolder.forApp] in the same process.
 */
object HostSync {

    /** The no-op wake of a headless process: nothing schedules background jobs; sessions run on foreground calls. */
    val NO_WAKE: WakeScheduler = object : WakeScheduler {
        override fun ensurePeriodic() = Unit
        override fun cancel() = Unit
        override fun toString(): String = "HostSync.NoWake"
    }

    /** Wall clock from `currentTimeMillis`; monotonic from `nanoTime` (deep sleeps do not matter on a host). */
    object HostClock : SyncClock {
        private val startNanos = System.nanoTime()

        override fun epochSeconds(): Long = Math.floorDiv(System.currentTimeMillis(), 1000L)

        override fun monotonicMillis(): Long = (System.nanoTime() - startNanos) / 1_000_000

        override fun toString(): String = "HostSync.HostClock"
    }

    /**
     * A real controller: one Tor transport (created in [torState]/[torCache], direct mode, no
     * bridge lines), the default traffic policy and [KeyedRandomSources]. [opener] is the caller's
     * database access; the runtime calls it on its own thread before a session.
     */
    fun controller(
        torState: File,
        torCache: File,
        opener: DatabaseOpener,
        wake: WakeScheduler = NO_WAKE,
        clock: SyncClock = HostClock,
        random: RandomSources = KeyedRandomSources(),
    ): AndroidSyncController {
        val threads = SyncThreads()
        val holder = TorTransportHolder({ TorRelayTransport.create(torState, torCache) }, clock, threads)
        val runtime = SyncRuntime(opener, holder, clock, random, TrafficPolicy.DEFAULT, threads, leases = holder)
        return AndroidSyncController(runtime, wake, opener)
    }
}
