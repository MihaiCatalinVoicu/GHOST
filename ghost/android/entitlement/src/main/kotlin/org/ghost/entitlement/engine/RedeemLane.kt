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

    /** Runs until the session closes; [tick] is the engine's other relay-session work (drops, GC). */
    fun run(session: SessionPort, tick: () -> Unit) {
        val redeem = session.redeem ?: return
        var wait = firstWait()
        while (pause(session, wait)) {
            tick()
            step(session, redeem)
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

    /** The answer of one execution: the plan's relay refused the token's period ([WRONG_PERIOD]), or not. */
    private enum class Outcome { DONE, NO_TOKEN, WRONG_PERIOD }

    /** One pass over the current needs. */
    fun step(session: SessionPort, redeem: RedeemPort) {
        val now = c.now()
        // A device clock set since the last step makes the relay-facing offsets stale (§19.24 point 1).
        c.memory.clock.observe(now, c.clock.monotonicMillis())
        val needs = c.sync.capabilities.needed()
        c.memory.forgetNeeds(needs)
        if (needs.isEmpty()) {
            c.memory.needMet()
            return
        }
        val trusted = session.clockTrusted()
        val relays = c.tx { tx -> SyncTables.relays(tx).filter { it.active }.associateBy { it.id } }
        val writeExpiry = c.tx { tx -> needs.associateWith { SyncTables.usableWriteExpiry(tx, it.relay, it.namespace) } }
        val plans = ArrayList<RedeemPlanner.Decision.Redeem>()
        for (need in needs) {
            val relay = relays[need.relay]
            // Each relay's decisions run on its own clock once it answered (§12.5, §19.24 point 1).
            val relayNow = if (relay != null) c.memory.clock.relayNow(relay.id, now) else c.memory.clock.now(now)
            val week = if (relay != null) c.memory.clock.week(relay.id, now) else Grid.week(relayNow)
            when (val d = planner.plan(need, relay, c.summary, relayNow, week, trusted, c.memory.firstSeen(need, now), writeExpiry[need])) {
                is RedeemPlanner.Decision.Redeem -> plans += d
                RedeemPlanner.Decision.NoSlot -> c.memory.count(Counters.NO_SLOT)
                else -> Unit
            }
        }
        // One redemption per (relay, namespace, week): a pair's READ and WRITE needs share it (§10.7).
        val single = plans.groupBy { Triple(it.relay.id, it.need.namespace, it.week) }.values.map { same -> same.minBy { it.dueSeconds } }
        var unmet = false
        // A relay that refused a period in this step is planned again at the next step, on the period
        // and the clock its answer set: never a second refused redemption from the stale plan.
        val refused = HashSet<RelayId>()
        for (plan in single.sortedBy { it.dueSeconds }) {
            if (session.closed) break
            if (plan.relay.id in refused) continue
            if (plan.dueSeconds > c.memory.clock.relayNow(plan.relay.id, now)) continue
            when (execute(redeem, plan, now)) {
                Outcome.NO_TOKEN -> unmet = true
                Outcome.WRONG_PERIOD -> refused += plan.relay.id
                Outcome.DONE -> Unit
            }
        }
        // A due need with no eligible token raises ENTITLEMENT_NEEDED (counts only, §12.4, §19.13).
        if (unmet) c.memory.needUnmet(now) else c.memory.needMet()
    }

    private fun execute(redeem: RedeemPort, plan: RedeemPlanner.Decision.Redeem, now: Long): Outcome {
        val held = when (val r = c.tx { tx -> reserve(tx, plan, now) }) {
            is Reservation.Held -> r.token
            Reservation.NoToken -> return Outcome.NO_TOKEN
            Reservation.Wait, Reservation.Covered -> return Outcome.DONE
        }
        val requestId = held.requestId()
        val answer = try {
            redeem.redeem(plan.relay.address, plan.need.namespace, held.token(), requestId)
        } catch (e: NetworkException) {
            failed(held, requestId, RetryPolicy.classify(e.category))
            return Outcome.DONE
        } catch (e: IllegalArgumentException) {
            failed(held, requestId, Failure.REJECTED)
            return Outcome.DONE
        }
        val wrongPeriod = answer.result == TorRelayTransport.REDEEM_WRONG_PERIOD
        c.memory.clock.record(plan.relay.id, answer.relayMinute, answer.relayPeriodId, now, wrongPeriod)
        c.tx { tx -> apply(tx, plan, held, requestId, answer) }
        return if (wrongPeriod) Outcome.WRONG_PERIOD else Outcome.DONE
    }

    private fun reserve(tx: SyncTransaction, plan: RedeemPlanner.Decision.Redeem, now: Long): Reservation {
        val relayNow = c.memory.clock.relayNow(plan.relay.id, now)
        val ns = plan.need.namespace.toByteArray()
        val held = c.tokens.relayReservation(tx, plan.relay.id.value, ns, plan.week)
        val expiry = SyncTables.usableWriteExpiry(tx, plan.relay.id, plan.need.namespace)
        return when (reserveStep(held != null, held?.let { c.memory.retryAfter(it.nullifier()) }, plan.week, relayNow, expiry)) {
            ReserveStep.RETRY -> Reservation.Held(checkNotNull(held))
            ReserveStep.DROP -> {
                val h = checkNotNull(held)
                c.tokens.deleteRelayReservation(tx, h.nullifier(), h.requestId())
                clear(h.nullifier())
                Reservation.Wait
            }
            ReserveStep.WAIT -> Reservation.Wait
            ReserveStep.COVERED -> Reservation.Covered
            ReserveStep.FRESH -> {
                val minute = Time.floorMinute(now)
                val fresh = c.tokens.freshEligibleAccess(tx, plan.week, plan.slots, minute) ?: return Reservation.NoToken
                c.tokens.reserveForRelay(tx, fresh.nullifier(), plan.relay.id.value, ns, c.random.bytes(REQUEST_ID_BYTES), minute)
                Reservation.Held(checkNotNull(c.tokens.get(tx, fresh.nullifier())))
            }
        }
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
                val after = wrongPeriodRetryAfter(token.epoch, answer.relayPeriodId)
                if (after != null) {
                    // Too early at this relay: keep the reservation, retry from start(week) − 23 h on
                    // the relay's clock (the plan of that week comes due no earlier).
                    c.memory.setRetryAfter(nullifier, after)
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

    override fun toString(): String = "RedeemLane"

    /** What tx1 does with a plan (pinned by `entitlement_policy.txt`, `reserve`). */
    enum class ReserveStep {
        /** Retry the pending reservation of the pair and week identically (R8). */
        RETRY,

        /** Nothing now (a kept reservation waits for its retry time, or the week's window is over). */
        WAIT,

        /** The pending reservation's week is over: delete it (never retried after its week), then wait. */
        DROP,

        /** The pair's write capability already reaches past the week. */
        COVERED,

        /** Reserve a fresh eligible token of the week with a new request id. */
        FRESH,
    }

    companion object {
        const val FIRST_STEP_MILLIS = 30_000L
        const val STEP_MILLIS = 60_000L
        private const val SLICE_MILLIS = 1_000L
        private const val REQUEST_ID_BYTES = 16
        private const val EARLY_RETRY_LEAD: Long = 23 * Grid.HOUR

        /** A week's tokens are refused from `start(week + 1) + 1 h` (design §3.4). */
        fun windowOver(week: Long, relayNow: Long): Boolean = relayNow >= Grid.start(week + 1) + Grid.HOUR

        /**
         * tx1 for a plan of [week] at [relayNow] (the plan's relay's clock): the pair's pending
         * reservation of that week ([held], with its [retryAfter] if a `WRONG_PERIOD` set one) is
         * retried identically unless its week is over; otherwise a fresh token, unless the week is
         * over or the pair's write capability ([writeExpiry]) reaches past it.
         */
        fun reserveStep(held: Boolean, retryAfter: Long?, week: Long, relayNow: Long, writeExpiry: Long?): ReserveStep = when {
            held && windowOver(week, relayNow) -> ReserveStep.DROP
            held -> if (retryAfter != null && relayNow < retryAfter) ReserveStep.WAIT else ReserveStep.RETRY
            windowOver(week, relayNow) -> ReserveStep.WAIT
            writeExpiry != null && writeExpiry >= Grid.start(week + 1) -> ReserveStep.COVERED
            else -> ReserveStep.FRESH
        }

        /**
         * A `WRONG_PERIOD` answer: a token of a week after the relay's period is kept and retried from
         * `start(week) − 23 h` (returned); one of the relay's period or before is deleted (null).
         */
        fun wrongPeriodRetryAfter(tokenWeek: Long, relayPeriod: Long): Long? =
            if (tokenWeek > relayPeriod) Grid.start(tokenWeek) - EARLY_RETRY_LEAD else null
    }
}
