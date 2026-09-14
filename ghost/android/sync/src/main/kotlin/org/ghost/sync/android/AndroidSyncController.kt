package org.ghost.sync.android

import android.content.Context
import android.os.SystemClock
import org.ghost.sync.api.ParticipantSession
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.SessionParticipant
import org.ghost.sync.api.SyncController
import org.ghost.sync.api.SyncStatus
import org.ghost.sync.engine.KeyedRandomSources
import org.ghost.sync.engine.TrafficPolicy
import org.ghost.sync.port.SyncClock
import org.ghost.sync.port.WakeScheduler
import org.ghost.sync.store.SyncStores
import java.util.concurrent.ThreadFactory
import java.util.concurrent.atomic.AtomicInteger

/**
 * The Android [SyncController] (design §5.4, §9), created once per process by the app ([create])
 * and wired to the process lifecycle there. It delegates visibility to [ForegroundDriver], jobs and
 * sessions to [SyncRuntime], and the periodic job to [WakeScheduler].
 */
class AndroidSyncController internal constructor(
    private val runtime: SyncRuntime,
    private val wake: WakeScheduler,
    private val opener: DatabaseOpener,
) : SyncController {
    private val foreground = ForegroundDriver(runtime)

    override fun onAppForeground() = foreground.onAppForeground()

    override fun onAppBackground() = foreground.onAppBackground()

    override fun requestExpedite() = foreground.requestExpedite()

    override fun setPrivacyMode(mode: PrivacyMode) {
        runtime.privacyMode = mode
    }

    /** The global privacy mode (read by the entitlement engine; opens no transaction, unlike [status]). */
    val privacyMode: PrivacyMode get() = runtime.privacyMode

    override fun status(): SyncStatus = runtime.status()

    /** Cancels the periodic job at once, then stops every session and drops the engine (§11.2 #17). */
    override fun onWipe() {
        wake.cancel()
        runtime.wipe()
    }

    override fun setParticipant(p: SessionParticipant?) = runtime.setParticipant(p)

    override fun runUserIssuerCall(block: (ParticipantSession) -> Unit) = runtime.runUserIssuerCall(block)

    override fun onPaymentScreenShown() = runtime.paymentScreenShown()

    override fun onPaymentScreenHidden() = runtime.paymentScreenHidden()

    override fun restorePaymentHold(lastShownEpochSeconds: Long) = runtime.restorePaymentHold(lastShownEpochSeconds)

    /**
     * [restorePaymentHold] with the moment read by [lastShown] on the runtime thread (reading it opens
     * the database: a Keystore unwrap and the key derivation stay off the main thread), before every
     * command posted after this call (Phase 8 design §19.11, §19.23 point 1). The app calls it at
     * process start, before a job or the foreground can start a relay session.
     */
    fun restorePaymentHoldFrom(lastShown: () -> Long?) = runtime.restorePaymentHoldFrom(lastShown)

    /**
     * Runs [block] on its own thread once the runtime has opened the database for the foreground and
     * [stores] is set, after the commands posted before it (the entitlement engine's foreground work,
     * Phase 8 design §8.3); starts no session, runs nothing after a wipe.
     */
    fun runWhenStoresOpen(block: () -> Unit) = runtime.runWhenStoresOpen(block)

    /**
     * Schedules the periodic job unless the pending one already has the wanted fields. Runs on the
     * runtime thread (binder calls stay off the main thread). The app calls it at process start
     * only when the database key envelope exists, and right after the key is first created (design
     * §5.4, §11.2 #17, #18); never because of user activity or data arrival.
     */
    fun ensurePeriodic() = runtime.post { wake.ensurePeriodic() }

    /** The database became usable (key created, unlocked): lifts a wipe; a visible app gets its session. */
    fun onDatabaseAvailable() = runtime.resume()

    /** The public sync API (outbox, inbox, namespaces, capabilities, directory) once the database is open. */
    val stores: SyncStores? get() = runtime.stores

    /**
     * Waits until no session, quiet run or user call runs and no participant or user-call thread is
     * still running (the wipe flow calls it before closing the database); false at the timeout.
     */
    fun awaitIdle(timeoutMillis: Long): Boolean = runtime.awaitIdle(timeoutMillis)

    internal fun databaseKeyExists(): Boolean = opener.keyExists()

    internal fun cancelPeriodic() = wake.cancel()

    internal fun startBackgroundJob(onFinished: () -> Unit): JobTicket = runtime.startJob(onFinished)

    internal fun stopBackgroundJob(ticket: JobTicket) = runtime.stopJob(ticket)

    override fun toString(): String = "AndroidSyncController"

    companion object {
        /**
         * The process's controller: the Tor transport holder (Arti state in the no-backup
         * directory; it also leases the transport to the session participant), a fresh schedule
         * key from SecureRandom (never persisted), the default traffic policy and the JobScheduler
         * wake-up. Call once, from the `Application`.
         */
        fun create(context: Context, opener: DatabaseOpener): AndroidSyncController {
            val threads = SyncThreads()
            val holder = TorTransportHolder.forApp(context, AndroidSyncClock, threads)
            val runtime = SyncRuntime(opener, holder, AndroidSyncClock, KeyedRandomSources(), TrafficPolicy.DEFAULT, threads, leases = holder)
            return AndroidSyncController(runtime, JobSchedulerWake(context), opener)
        }
    }
}

/** Wall clock for the database; elapsed realtime (counts deep sleep) for schedules, breakers and budgets. */
internal object AndroidSyncClock : SyncClock {
    override fun epochSeconds(): Long = Math.floorDiv(System.currentTimeMillis(), 1000L)

    override fun monotonicMillis(): Long = SystemClock.elapsedRealtime()

    override fun toString(): String = "AndroidSyncClock"
}

/**
 * Named daemon threads for the runtime, the lanes and bootstraps. No uncaught-exception handler is
 * set: a throwable ends the process (design §11.2 #11).
 */
internal class SyncThreads : ThreadFactory {
    private val count = AtomicInteger()

    override fun newThread(r: Runnable): Thread = Thread(r, "ghost-sync-" + count.incrementAndGet()).apply { isDaemon = true }

    override fun toString(): String = "SyncThreads"
}
