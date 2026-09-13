package org.ghost.entitlement.engine

import org.ghost.entitlement.port.RedeemPort
import org.ghost.entitlement.port.SessionPort
import org.ghost.entitlement.store.StateStore
import org.ghost.entitlement.store.SyncTables
import org.ghost.entitlement.store.TokenRow
import org.ghost.network.NetworkException
import org.ghost.network.TorRelayTransport
import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.RelayId
import org.ghost.sync.api.SyncTransaction
import org.ghost.sync.store.Time

/**
 * The redeem lane of a relay session (design §11.6, §12.4): at READY + U[0, 30 s] and then every
 * 60 s ± 50 % it reads `Capabilities.needed()`, plans each need and executes the due ones in time
 * order: **tx1** reserve a fresh, eligible token of the right (week, slot) with a new random request
 * id (or take the reservation that is already pending for that relay, namespace and week); **call**
 * the redemption; **tx2** apply the answer, installing the capability and deleting the token in one
 * transaction. A reserved token is only ever retried, identically, at its own relay and namespace (R8).
 * A write capability serves reads (§10.7), so one step makes at most one redemption per (relay,
 * namespace, week), and tx1 takes no fresh token for a pair whose usable write capability already
 * reaches the end of the week (installed earlier in the same step, say).
 */
internal class RedeemLane(private val c: EngineContext) {
    private val planner = RedeemPlanner(c.random)

    private sealed class Reservation {
        class Held(val token: TokenRow) : Reservation()
        object NoToken : Reservation()
        object Wait : Reservation()

        /** The pair's write capability already covers the week: no token is needed. */
        object Covered : Reservation()
    }

    /**
     * Runs until the session closes; [tick] is the engine's other relay-session work (drops, GC). Each
     * step is reported to the session, which ends a background session held open for the pending write
     * needs it started with (design §17 Q29, §19.23 point 5).
     */
    fun run(session: SessionPort, tick: () -> Unit) {
        val redeem = session.redeem ?: return
        var wait = firstWait()
        while (pause(session, wait)) {
            tick()
            step(session, redeem)
            redeem.stepDone()
            wait = nextWait()
        }
    }

    /** The wait from READY to the first step: U[0, 30 s]. */
    fun firstWait(): Long = (c.random.uniform() * FIRST_STEP_MILLIS).toLong()

    /** The wait after a step: 60 s ± 50 %. */
    fun nextWait(): Long = (STEP_MILLIS * (0.5 + c.random.uniform())).toLong()

    /** Waits in short slices; false once the session closed or the thread was interrupted. */
    private fun pause(session: SessionPort, millis: Long): Boolean {
        val end = c.clock.monotonicMillis() + millis
        while (!session.closed) {
            val left = end - c.clock.monotonicMillis()
            if (left <= 0) return true
            if (!c.clock.sleep(minOf(left, SLICE_MILLIS))) return false
        }
        return false
    }

    /** One pass over the current needs. */
    fun step(session: SessionPort, redeem: RedeemPort) {
        val needs = c.sync.capabilities.needed()
        c.memory.forgetNeeds(needs)
        if (needs.isEmpty()) {
            c.memory.needMet()
            return
        }
        val now = c.now()
        val trusted = session.clockTrusted()
        val nowEst = c.memory.clock.now(now)
        val relays = c.tx { tx -> SyncTables.relays(tx).filter { it.active }.associateBy { it.id } }
        val writeExpiry = c.tx { tx -> needs.associateWith { SyncTables.usableWriteExpiry(tx, it.relay, it.namespace) } }
        val plans = ArrayList<RedeemPlanner.Decision.Redeem>()
        for (need in needs) {
            val relay = relays[need.relay]
            val week = if (relay != null) c.memory.clock.week(relay.id, now) else Grid.week(nowEst)
            when (val d = planner.plan(need, relay, c.summary, nowEst, week, trusted, c.memory.firstSeen(need, now), writeExpiry[need])) {
                is RedeemPlanner.Decision.Redeem -> plans += d
                RedeemPlanner.Decision.NoSlot -> c.memory.count(Counters.NO_SLOT)
                else -> Unit
            }
        }
        // One redemption per (relay, namespace, week): a pair's READ and WRITE needs share it (§10.7).
        val single = plans.groupBy { Triple(it.relay.id, it.need.namespace, it.week) }.values.map { same -> same.minBy { it.dueSeconds } }
        var unmet = false
        for (plan in single.sortedBy { it.dueSeconds }) {
            if (session.closed) break
            if (plan.dueSeconds > nowEst) continue
            if (!execute(redeem, plan, now)) unmet = true
        }
        // A due need with no eligible token raises ENTITLEMENT_NEEDED (counts only, §12.4, §19.13).
        if (unmet) c.memory.needUnmet(now) else c.memory.needMet()
    }

    /** False when no eligible token exists for the plan. */
    private fun execute(redeem: RedeemPort, plan: RedeemPlanner.Decision.Redeem, now: Long): Boolean {
        val held = when (val r = c.tx { tx -> reserve(tx, plan, now) }) {
            is Reservation.Held -> r.token
            Reservation.NoToken -> return false
            Reservation.Wait, Reservation.Covered -> return true
        }
        val requestId = held.requestId()
        val answer = try {
            redeem.redeem(plan.relay.address, plan.need.namespace, held.token(), requestId)
        } catch (e: NetworkException) {
            failed(held, requestId, RetryPolicy.classify(e.category))
            return true
        } catch (e: IllegalArgumentException) {
            failed(held, requestId, Failure.REJECTED)
            return true
        }
        val wrongPeriod = answer.result == TorRelayTransport.REDEEM_WRONG_PERIOD
        c.memory.clock.record(plan.relay.id, answer.relayMinute, answer.relayPeriodId, now, wrongPeriod)
        c.tx { tx -> apply(tx, plan, held, requestId, answer) }
        return true
    }

    private fun reserve(tx: SyncTransaction, plan: RedeemPlanner.Decision.Redeem, now: Long): Reservation {
        val nowEst = c.memory.clock.now(now)
        val ns = plan.need.namespace.toByteArray()
        val held = c.tokens.relayReservation(tx, plan.relay.id.value, ns, plan.week)
        if (held != null) {
            if (windowOver(held.epoch, nowEst)) {
                c.tokens.deleteRelayReservation(tx, held.nullifier(), held.requestId())
                return Reservation.Wait
            }
            val after = c.memory.retryAfter(held.nullifier())
            return if (after != null && nowEst < after) Reservation.Wait else Reservation.Held(held)
        }
        if (windowOver(plan.week, nowEst)) return Reservation.Wait
        val expiry = SyncTables.usableWriteExpiry(tx, plan.relay.id, plan.need.namespace)
        if (expiry != null && expiry >= Grid.start(plan.week + 1)) return Reservation.Covered
        val minute = Time.floorMinute(now)
        val fresh = c.tokens.freshEligibleAccess(tx, plan.week, plan.slots, minute) ?: return Reservation.NoToken
        c.tokens.reserveForRelay(tx, fresh.nullifier(), plan.relay.id.value, ns, c.random.bytes(REQUEST_ID_BYTES), minute)
        return Reservation.Held(checkNotNull(c.tokens.get(tx, fresh.nullifier())))
    }

    private fun apply(tx: SyncTransaction, plan: RedeemPlanner.Decision.Redeem, token: TokenRow, requestId: ByteArray, answer: TorRelayTransport.RedeemAnswer) {
        val nullifier = token.nullifier()
        when (answer.result) {
            TorRelayTransport.REDEEM_OK -> {
                val capability = checkNotNull(answer.capability()) { "capability missing" }
                val relay: RelayId = plan.relay.id
                // Interim READ-by-write (§10.7): every redemption yields a write capability.
                if (SyncTables.relayKnown(tx, relay) && SyncTables.namespaceRegistered(tx, plan.need.namespace)) {
                    c.sync.capabilities.put(tx, relay, plan.need.namespace, CapabilityKind.WRITE, capability, answer.expiryUnixSeconds)
                }
                c.tokens.deleteRelayReservation(tx, nullifier, requestId)
                clear(nullifier)
            }
            TorRelayTransport.REDEEM_REPLAYED -> {
                c.memory.count(Counters.TOKENS_REPLAYED)
                c.tokens.deleteRelayReservation(tx, nullifier, requestId)
                clear(nullifier)
            }
            TorRelayTransport.REDEEM_WRONG_PERIOD -> {
                if (token.epoch > answer.relayPeriodId) {
                    // Too early at this relay: keep the reservation, retry from start(week) − 23 h.
                    c.memory.setRetryAfter(nullifier, Grid.start(token.epoch) - EARLY_RETRY_LEAD)
                } else {
                    c.tokens.deleteRelayReservation(tx, nullifier, requestId)
                    clear(nullifier)
                }
            }
        }
    }

    private fun failed(token: TokenRow, requestId: ByteArray, failure: Failure) {
        val nullifier = token.nullifier()
        when (failure) {
            // Keep the reservation: the identical retry at the next lane step.
            Failure.TRANSIENT -> Unit
            Failure.UNAUTHORIZED -> c.tx { tx ->
                // A key or configuration inconsistency, possibly tagging (§11.6).
                c.tokens.deleteRelayReservation(tx, nullifier, requestId)
                c.alarm(tx, StateStore.ALARM_REFUSED_BY_RELAY)
                clear(nullifier)
            }
            Failure.REJECTED -> c.tx { tx ->
                // Refused before any I/O (the token is bound elsewhere): it never left the device and is
                // never offered to another relay (R8).
                c.memory.count(Counters.TOKENS_REFUSED_LOCALLY)
                c.tokens.deleteRelayReservation(tx, nullifier, requestId)
                clear(nullifier)
            }
            Failure.MALFORMED -> if (!c.memory.firstMalformed(nullifier)) {
                c.tx { tx ->
                    c.tokens.deleteRelayReservation(tx, nullifier, requestId)
                    c.alarm(tx, StateStore.ALARM_REFUSED_BY_RELAY)
                    clear(nullifier)
                }
            }
        }
    }

    private fun clear(nullifier: ByteArray) {
        c.memory.clearMalformed(nullifier)
        c.memory.clearRetryAfter(nullifier)
    }

    /** A week's tokens are refused from `start(week + 1) + 1 h` (design §3.4). */
    private fun windowOver(week: Long, nowEst: Long): Boolean = nowEst >= Grid.start(week + 1) + Grid.HOUR

    override fun toString(): String = "RedeemLane"

    companion object {
        const val FIRST_STEP_MILLIS = 30_000L
        const val STEP_MILLIS = 60_000L
        private const val SLICE_MILLIS = 1_000L
        private const val REQUEST_ID_BYTES = 16
        private const val EARLY_RETRY_LEAD: Long = 23 * Grid.HOUR
    }
}
