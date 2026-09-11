package org.ghost.sync.engine

import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.RelayId
import org.ghost.sync.api.StatusFlag
import org.ghost.sync.api.SyncChange
import org.ghost.sync.api.SyncStatus
import org.ghost.sync.api.TransportStatus
import org.ghost.sync.port.PairKey
import org.ghost.sync.port.RandomSources
import org.ghost.sync.port.SyncClock
import org.ghost.sync.port.TransportPort
import org.ghost.sync.store.SyncStores
import java.util.Collections
import java.util.EnumSet
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Process-wide sync engine (design §1.1, §1.4): the stores, the ports, the policy, the injected
 * steps, and the in-memory state that outlives one session (whether the transport reached READY in
 * this process, status flags, 24-hour pauses). It owns at most one [Session] at a time; the Android
 * runtime (step S7) runs it with a [ThreadedLaneRunner], tests with a deterministic driver.
 *
 * Nothing here is persisted (design §2.4, T20).
 */
internal class SyncEngine(
    val stores: SyncStores,
    val transport: TransportPort,
    val clock: SyncClock,
    val random: RandomSources,
    val policy: TrafficPolicy = TrafficPolicy.DEFAULT,
    val steps: Steps = Steps.DEFAULT,
    private val mode: () -> PrivacyMode,
) {
    /** The transport reached READY in this process: Arti accepted the consensus clock, so M3, D2 sweeps and GC may run (§3.7). */
    @Volatile
    var readyInProcess: Boolean = false
        private set

    @Volatile
    var transportStatus: TransportStatus = TransportStatus.OFF
        private set

    /** `native_missing` was seen: sync stays off for the life of the process (§3.6). */
    @Volatile
    var disabled: Boolean = false
        private set

    private val flags: MutableSet<StatusFlag> = Collections.synchronizedSet(EnumSet.noneOf(StatusFlag::class.java))
    private val readPauses = ConcurrentHashMap<PairKey, Long>()
    private val workPauses = ConcurrentHashMap<PairKey, Long>()
    private val relayWorkPauses = ConcurrentHashMap<Long, Long>()
    private val jobs = AtomicLong()

    /** Consecutive transport failures, for the 1 → 15 min recreation backoff (§3.6). */
    internal var transportFailures: Int = 0

    @Volatile
    private var session: Session? = null

    init {
        stores.database.setEngineListener { changes ->
            if (SyncChange.CAPABILITIES in changes || SyncChange.TOPOLOGY in changes) session?.refreshPairs()
        }
    }

    fun privacyMode(): PrivacyMode = mode()

    /**
     * Creates and starts a session; the caller runs it (a runner or a driver). The previous session
     * must have finished (design §1.4: at most one session). Background sessions are numbered in
     * this process (the job index of the keyed offsets).
     */
    fun startSession(kind: SessionKind): Session {
        check(session?.isFinished() != false) { "a sync session is still running" }
        check(!disabled) { "sync is disabled for this process" }
        val job = if (kind == SessionKind.BACKGROUND) jobs.getAndIncrement() else 0L
        val next = Session(this, kind, job)
        session = next
        next.start()
        return next
    }

    /** The current session, if any. */
    fun currentSession(): Session? = session

    /** Counts and enums only (design §7.3). Opens its own transaction. */
    fun status(): SyncStatus {
        val counts = stores.counts()
        val out = EnumSet.noneOf(StatusFlag::class.java)
        synchronized(flags) { out.addAll(flags) }
        if (counts.consumerPoisoned > 0) out += StatusFlag.CONSUMER_POISONED
        if (counts.expiredUnconsumed > 0) out += StatusFlag.EXPIRED_UNCONSUMED
        if (counts.capabilityNeeds > 0) out += StatusFlag.CAPABILITY_NEEDED
        return SyncStatus(transportStatus, mode(), out, counts)
    }

    internal fun flag(flag: StatusFlag) {
        flags += flag
    }

    internal fun hasFlag(flag: StatusFlag): Boolean = flag in flags

    internal fun markReady() {
        readyInProcess = true
        transportFailures = 0
        transportStatus = TransportStatus.READY
    }

    internal fun setTransportStatus(status: TransportStatus) {
        transportStatus = status
    }

    internal fun disable() {
        disabled = true
        transportStatus = TransportStatus.NATIVE_MISSING
    }

    // ------------------------------------------------------------------ 24-hour pauses (§3.6), monotonic time

    /** A list outcome (`rejected`, a local bug) paused the pair's listing; work-lane outcomes never do (T19). */
    internal fun pauseRead(pair: PairKey, until: Long) {
        readPauses[pair] = until
    }

    internal fun readPaused(pair: PairKey, now: Long): Boolean = (readPauses[pair] ?: return false) > now

    /** A get or check outcome paused the pair's work (fetches, checks, stores); lists continue. */
    internal fun pauseWork(pair: PairKey, until: Long) {
        workPauses[pair] = until
    }

    internal fun workPaused(pair: PairKey, now: Long): Boolean = (workPauses[pair] ?: return false) > now

    /** `not_onion` on a store: the relay's work lane is held for 24 h. */
    internal fun pauseRelayWork(relay: RelayId, until: Long) {
        relayWorkPauses[relay.value] = until
    }

    internal fun relayWorkPaused(relay: RelayId, now: Long): Boolean =
        (relayWorkPauses[relay.value] ?: return false) > now

    override fun toString(): String = "SyncEngine"

    companion object {
        /** Length of the pauses for `rejected` and local bugs (design §3.6). */
        const val PAUSE_MILLIS: Long = 24 * 3_600_000L
    }
}
