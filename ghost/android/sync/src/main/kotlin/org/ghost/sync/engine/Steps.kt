package org.ghost.sync.engine

import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.RelayId
import org.ghost.sync.api.StatusFlag
import org.ghost.sync.api.SyncDatabase
import org.ghost.sync.port.PairKey
import org.ghost.sync.port.RandomSources
import org.ghost.sync.port.RelayPort
import org.ghost.sync.store.CapabilityToken
import org.ghost.sync.store.SyncStores

/**
 * The injected steps of the engine (design §1.3). Production uses [DEFAULT]; the exit-gate harness
 * substitutes mutant steps (subclasses in test sources, design §8.8) to prove it catches classic
 * bugs. There are no test switches or observers in production code: a harness sees the engine only
 * through the ports, the clock, the SqlExecutor and these objects.
 */
internal class Steps(
    val schedule: (RandomSources, TrafficPolicy) -> PairSchedule = { random, policy -> PairSchedule(random, policy) },
    val list: ListStep = ListStep(),
    val fetch: FetchStep = FetchStep(),
    val store: StoreStep = StoreStep(),
    val verify: VerifyStep = VerifyStep(),
    val resolve: ResolveStep = ResolveStep(),
    val maintenance: Maintenance = Maintenance(),
    val gc: GcStep = GcStep(),
) {
    override fun toString(): String = "Steps"

    companion object {
        val DEFAULT: Steps = Steps()
    }
}

/** What every step may use: the stores, the relay port and the clocks. */
internal open class EngineContext(val engine: SyncEngine) {
    val db: SyncDatabase get() = engine.stores.database
    val stores: SyncStores get() = engine.stores
    val port: RelayPort get() = engine.transport.relays
    val policy: TrafficPolicy get() = engine.policy
    val steps: Steps get() = engine.steps

    /** Wall clock, unix seconds (the stores persist it at minute/hour/day granularity only). */
    fun now(): Long = engine.clock.epochSeconds()

    /** Monotonic milliseconds (schedules, breakers, budgets). */
    fun monotonic(): Long = engine.clock.monotonicMillis()

    override fun toString(): String = "EngineContext"
}

/**
 * The work lane's view of its session: whether a call may be made, its deadline, the work-lane
 * breaker and budgets, status flags and transport faults. Only the work lane uses it, so nothing
 * here can reach the read lane's schedule (T19, design §11.2 #13).
 */
internal class WorkContext(engine: SyncEngine, private val session: Session) : EngineContext(engine) {
    val kind: SessionKind get() = session.kind

    fun mode(): PrivacyMode = engine.privacyMode()

    /** The session may still make calls (online, not stopping, budget left). */
    val active: Boolean get() = session.canUseNetwork(monotonic())

    /** A work-lane call for [pair] may be made now: session active, breaker closed, no pause, relay budget left. */
    fun allows(pair: PairKey): Boolean {
        val now = monotonic()
        return session.canUseNetwork(now) &&
            session.work.breaker.allows(pair.relayId, now) &&
            !engine.workPaused(pair, now) &&
            !engine.relayWorkPaused(pair.relayId, now) &&
            session.work.relayBudgetLeft(pair.relayId) > 0
    }

    /**
     * Deadline of the next work-lane call to [relay]: `min(60 s, remaining session budget − 5 s)`
     * and, in the background, the relay's remaining work budget; null when too little is left.
     */
    fun deadline(relay: RelayId): Int? {
        var limit = policy.callDeadlineMillis.toLong()
        if (session.kind == SessionKind.BACKGROUND) limit = minOf(limit, session.work.relayBudgetLeft(relay))
        return session.budget.deadline(monotonic(), limit)
    }

    /** Runs one call to [relay] and charges its duration to the relay's work budget. */
    fun <T> timed(relay: RelayId, call: () -> T): T {
        val start = monotonic()
        val out = call()
        session.work.recordCall(relay, monotonic() - start)
        return out
    }

    /** Backoff jitter from the selection stream (never used by the read lane). */
    fun selection(): Double = engine.random.selection()

    fun success(relay: RelayId) = session.work.breaker.success(relay)

    fun failure(relay: RelayId, weight: Int) {
        if (weight > 0) session.work.breaker.failure(relay, weight, monotonic())
    }

    fun flag(flag: StatusFlag) = engine.flag(flag)

    /** A transport-level failure: the session stops its calls (design §3.6). */
    fun fault(failed: CallResult.Failed) = session.fault(failed)

    /**
     * Applies the list/get/check disposition of a failed work-lane get or check (design §3.6):
     * breaker weight, flag, transport fault, token refusal (generation-guarded) or a 24-hour pause
     * of the pair's work. Returns the action so the caller can do the per-row part.
     */
    fun readFailure(pair: PairKey, token: CapabilityToken, failed: CallResult.Failed, isGet: Boolean): ReadAction {
        val disposition = ErrorPolicy.read(failed.errorClass, isGet)
        disposition.flag?.let { engine.flag(it) }
        failure(pair.relayId, disposition.breakerWeight)
        when (disposition.action) {
            ReadAction.STOP -> fault(failed)
            ReadAction.SUSPEND -> db.transaction { tx ->
                stores.capabilityStore.refuse(tx, pair.relayId, pair.namespace, token.kind, token.generation, exhausted = false)
            }
            ReadAction.PAUSE -> engine.pauseWork(pair, monotonic() + SyncEngine.PAUSE_MILLIS)
            ReadAction.SKIP, ReadAction.HOSTILE, ReadAction.NOT_FOUND -> Unit
        }
        return disposition.action
    }

    override fun toString(): String = "WorkContext"
}
