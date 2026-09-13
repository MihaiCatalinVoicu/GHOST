package org.ghost.sync.harness

import org.ghost.sync.port.SyncClock

/**
 * Harness clock (design §8.1 TestClock). [millis] is true elapsed time since the world started and
 * is also the monotonic clock; the device's wall clock is true time plus [deviceOffsetSeconds]
 * (clock jumps). Model relays read true time plus their own skew.
 */
internal class TestClock(val startEpochSeconds: Long) : SyncClock {
    @Volatile
    var millis: Long = 0

    @Volatile
    var deviceOffsetSeconds: Long = 0

    /** True unix seconds (what honest relays read, before their own skew). */
    fun trueEpochSeconds(): Long = startEpochSeconds + Math.floorDiv(millis, 1000L)

    override fun epochSeconds(): Long = trueEpochSeconds() + deviceOffsetSeconds

    override fun monotonicMillis(): Long = millis

    fun advance(ms: Long) {
        require(ms >= 0) { "time never moves back" }
        millis += ms
    }

    override fun toString(): String = "TestClock(t=$millis ms, offset=$deviceOffsetSeconds s)"
}

/**
 * Process death at an injected event (design §8.1): an [Error], so nothing in the engine may catch
 * it (§11.2 #11). The harness catches it only at the top level and checks that the one it catches
 * is the one it injected.
 */
internal class SimulatedCrash(val event: Long, val kind: EventKind) : Error("injected process death at event $event ($kind)")

/** Every point where the harness may inject a fault (design §8.2). */
internal enum class EventKind(val relay: Boolean) {
    SQL_EXEC(false),
    SQL_UPDATE(false),
    SQL_QUERY(false),

    /** Inside the transaction block after its last statement: a crash here rolls the block back. */
    PRE_COMMIT(false),

    /** After the commit, before the caller sees success. */
    POST_COMMIT(false),

    /** TransportPort.ensureReady. */
    TRANSPORT_ENSURE(false),

    /** A relay call is about to be sent: nothing was applied. */
    RELAY_BEFORE_SEND(true),

    /** The relay applied the call; its response has not reached the client (the dangerous window). */
    RELAY_AFTER_APPLY(true),

    /** The response reached the client; the engine has not seen it yet. */
    RELAY_AFTER_RESPONSE(true),
}

/** The relay call an event belongs to. */
internal class CallInfo(
    val kind: CallKind,
    val relay: String,
    /** Hex of the namespace (harness-internal; never leaves the test). */
    val namespace: String,
    /** Hex of the op's blob hash for a store, of each hash for get/check. */
    val hashes: List<String>,
) {
    override fun toString(): String = "CallInfo($kind, $relay)"
}

/**
 * Relay calls of the sync engine, and the Phase 8 calls an extension of this harness adds on the
 * same bus (the `:entitlement` harness: token redemption at a relay and issuer calls).
 */
internal enum class CallKind { STORE, GET, LIST, CHECK, REDEEM, ISSUER }

/** One event: its index in the armed phase (1-based), kind, and call. */
internal class Event(val index: Long, val kind: EventKind, val call: CallInfo?) {
    override fun toString(): String = "Event($index, $kind${call?.let { ", ${it.kind}@${it.relay}" } ?: ""})"
}

/** What the plan wants at an event. */
internal sealed class Fault {
    /** Process death. */
    object Crash : Fault()

    /** A relay call fails with this category (relay events only); after apply means the relay applied it. */
    class Network(val category: String) : Fault()

    /** Runs [action] here (only at points outside any transaction: relay events). */
    class Interleave(val action: () -> Unit) : Fault()
}

/** Decides, per event, what happens; the default plan never injects anything. */
internal fun interface FaultPlan {
    fun at(event: Event): Fault?

    companion object {
        val NONE: FaultPlan = FaultPlan { null }
    }
}

/**
 * The single event counter of the armed client (design §8.2). Every SQL statement, transaction
 * pre/post-commit, transport ensure and relay call phase is an event while [armed]. [onEvent]
 * observers see every event before the plan (the classification of crash points uses it).
 */
internal class EventBus {
    var armed: Boolean = false
    var plan: FaultPlan = FaultPlan.NONE
    var count: Long = 0
        private set

    /** Crashes thrown by this bus, in order. */
    val injected = ArrayList<SimulatedCrash>()

    /** Network faults the plan injected. */
    var networkFaults: Int = 0
        private set

    /** Whether the plan injected anything at all. */
    val faulted: Boolean get() = injected.isNotEmpty() || networkFaults > 0

    var onEvent: ((Event) -> Unit)? = null

    /** Resets the counter (the recovery phase of a double-crash run counts from 1 again). */
    fun resetCount() {
        count = 0
    }

    /**
     * Records one event and applies the plan: throws [SimulatedCrash] for a crash, returns a
     * network fault or an interleaving to the caller, or null.
     */
    fun event(kind: EventKind, call: CallInfo? = null): Fault? {
        if (!armed) return null
        count++
        val e = Event(count, kind, call)
        onEvent?.invoke(e)
        return when (val f = plan.at(e)) {
            null -> null
            is Fault.Crash -> {
                val crash = SimulatedCrash(count, kind)
                injected += crash
                Harness.injectedCrashes.incrementAndGet()
                throw crash
            }
            is Fault.Network -> {
                check(kind.relay) { "network fault planned at a non-relay event" }
                networkFaults++
                f
            }
            is Fault.Interleave -> f
        }
    }

    override fun toString(): String = "EventBus(count=$count, armed=$armed)"
}

/** A harness finding: an invariant broken by the engine (never a JVM error of the harness itself). */
internal class InvariantViolation(message: String) : AssertionError(message)

internal fun violation(message: String): Nothing = throw InvariantViolation(message)

internal fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }
