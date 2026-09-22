package org.ghost.messaging.harness

/**
 * The crash-injection mechanism of Phase 9 design §15.3, slice S10.
 *
 * > For each scenario: run it without faults and record K events (every `exec`, `execUpdate` and
 * > `query`, pre-commit and post-commit, and the model relay's before-send, after-apply and
 * > after-response events); for every k crash at k, reboot (drop the uncommitted connection,
 * > reopen the same file, migrate, `verifyIntegrity`, R-K1, build a new client: engine, actor, DM
 * > context), check the structural invariants, run to quiescence, check everything.
 *
 * This file is the counter and the vocabulary; [FaultyDmSqlExecutor] raises the SQL events,
 * [ModelDmRelay] the three relay ones, [DmNode] performs the reboot, [DmStructuralInvariants] is
 * the "check the structural invariants" half and [DmCrashRunner] is the loop.
 *
 * It is the Phase 7 `:sync` harness's `Core.kt` adapted rather than reinvented (the slice's own
 * instruction, and the two harnesses have to report crash classes the same way). Three things are
 * different and each is a DM fact:
 *  - the bus is **per world**, not per client, because a DM scenario's atomicity properties span
 *    two devices and a relay ("A's ratchet stepped, B never saw the message");
 *  - [DmFault.StorageFull] exists, because SCN-J injects `SQLITE_FULL` "at every statement of SEND,
 *    RECV, BUNDLE and SWEEP" and a full disk is a *typed failure the engine must survive*, not a
 *    process death;
 *  - [DmFault.NativeCrash] exists, because §15.1 names `SimulatedNativeCrash` "thrown from the
 *    `DmNative` port during RECV (the process-death model of a SIGSEGV or an uncaught native
 *    abort)", which a SQL-level injector cannot express.
 */

/** Every point where the harness may inject a fault (§15.3). */
internal enum class DmEventKind(val relay: Boolean) {
    SQL_EXEC(false),
    SQL_UPDATE(false),
    SQL_QUERY(false),

    /** Inside the transaction block after its last statement: a crash here rolls the block back. */
    PRE_COMMIT(false),

    /** After the commit, before the caller sees success. */
    POST_COMMIT(false),

    /** A store is about to reach the relay: nothing was applied. */
    RELAY_BEFORE_SEND(true),

    /** The relay stored the blob; the sender has not learned it (the dangerous window). */
    RELAY_AFTER_APPLY(true),

    /** The sender learned the outcome; nothing has been applied to its database yet. */
    RELAY_AFTER_RESPONSE(true),
    ;

    val sql: Boolean get() = this == SQL_EXEC || this == SQL_UPDATE || this == SQL_QUERY

    /**
     * Where a `SQLITE_FULL` can actually come from.
     *
     * SQLite raises it when it needs a page it cannot get, which is a **write**: a read never
     * extends the file, and a commit that has already returned cannot fail afterwards. Injecting it
     * at a `SELECT` would make the harness demand that the engine handle an input SQLite cannot
     * produce, and "the engine does not map an impossible failure" is not a finding. So SCN-J's
     * "every statement of SEND, RECV, BUNDLE and SWEEP" is every statement that writes, plus the
     * commit — which is the statement a full disk fails most often.
     */
    val canBeFull: Boolean get() = this == SQL_EXEC || this == SQL_UPDATE || this == PRE_COMMIT
}

/**
 * One event: its index in the armed phase (1-based), its kind, the node it happened on, and a
 * short label used only in failure messages.
 */
internal class DmEvent(
    val index: Long,
    val kind: DmEventKind,
    val node: String,
    val detail: String,
) {
    override fun toString(): String = "DmEvent($index, $kind, $node, $detail)"
}

/** What a plan wants at an event. */
internal sealed class DmFault {
    /** Process death (§15.3's crash at k). */
    object Crash : DmFault()

    /**
     * `SQLITE_FULL` at this statement (SCN-J). A **typed** failure: the engine must roll its
     * transaction back, report it and carry on, so this is not an [Error] and the engine is allowed
     * — required, even — to catch it where §7.8 says it may.
     */
    object StorageFull : DmFault()

    /** `SimulatedNativeCrash` from the `DmNative` port (§15.1, SCN-J). Process death. */
    object NativeCrash : DmFault()

    /**
     * Relay events only: the relay applied the call and the response never arrived (§15.3's
     * "every relay event also runs as *timeout after apply*").
     */
    object TimeoutAfterApply : DmFault()
}

/** Decides, per event, what happens; the default plan never injects anything. */
internal fun interface DmFaultPlan {
    fun at(event: DmEvent): DmFault?

    companion object {
        val NONE: DmFaultPlan = DmFaultPlan { null }
    }
}

/**
 * Process death at an injected event: an [Error], so no `catch (e: Exception)` in the engine may
 * swallow it. The runner catches it at the top level and checks that the one it caught is the one
 * the bus injected — a crash the engine absorbed and turned into a normal return would otherwise
 * be reported as a clean run.
 */
internal class SimulatedDmCrash(val event: Long, val kind: DmEventKind, val node: String) :
    Error("injected process death at event $event ($kind on $node)")

/**
 * The native-port death of §15.1: a SIGSEGV or an uncaught abort inside `ghost-dm-host`, modelled
 * on the JVM side of the closed JNI surface. An [Error] for the same reason as [SimulatedDmCrash].
 *
 * A **caught Rust panic** is a different thing entirely — it comes back through the surface as the
 * `INTERNAL` result code, and SCN-J asserts that *that* one "rolls back and crashes like any
 * `IllegalStateException`". Only the uncatchable half is here.
 */
internal class SimulatedNativeCrash(val event: Long, val node: String) :
    Error("injected native crash at event $event on $node")

/** A harness finding: an invariant the engine broke (never a JVM error of the harness itself). */
internal class DmInvariantViolation(message: String) : AssertionError(message)

internal fun dmViolation(message: String): Nothing = throw DmInvariantViolation(message)

/**
 * The single event counter of an armed world (§15.3).
 *
 * The counter is the world's, not a device's: a DM crash class is a state of *the world* ("A
 * committed the ratchet step, the relay holds the blob, B has not read it"), and a per-device
 * counter cannot name it.
 */
internal class DmEventBus {
    var armed: Boolean = false
    var plan: DmFaultPlan = DmFaultPlan.NONE

    var count: Long = 0
        private set

    /** Crashes this bus threw, in order. */
    val injected = ArrayList<Error>()

    /** How many typed `SQLITE_FULL` failures the plan injected. */
    var storageFulls: Int = 0
        private set

    /** How many relay responses the plan dropped after the relay applied them. */
    var timeouts: Int = 0
        private set

    val faulted: Boolean get() = injected.isNotEmpty() || storageFulls > 0 || timeouts > 0

    /** Observers of every event, before the plan (the recording run classifies through it). */
    var onEvent: ((DmEvent) -> Unit)? = null

    /** The recovery phase of a double-crash run counts from 1 again (§15.3's second crash). */
    fun resetCount() {
        count = 0
    }

    /**
     * Records one event and applies the plan. Throws for the two process-death faults and for
     * `SQLITE_FULL` (which the caller must let out as a [org.ghost.storage.StorageFullException]);
     * returns [DmFault.TimeoutAfterApply] to the model relay, which is the only caller that can act
     * on it.
     */
    fun event(kind: DmEventKind, node: String, detail: String = ""): DmFault? {
        if (!armed) return null
        count++
        val e = DmEvent(count, kind, node, detail)
        onEvent?.invoke(e)
        return when (plan.at(e)) {
            null -> null
            DmFault.Crash -> {
                val crash = SimulatedDmCrash(count, kind, node)
                injected += crash
                throw crash
            }

            DmFault.NativeCrash -> {
                val crash = SimulatedNativeCrash(count, node)
                injected += crash
                throw crash
            }

            DmFault.StorageFull -> {
                storageFulls++
                DmFault.StorageFull
            }

            DmFault.TimeoutAfterApply -> {
                check(kind.relay) { "a timeout-after-apply was planned at a non-relay event" }
                timeouts++
                DmFault.TimeoutAfterApply
            }
        }
    }

    override fun toString(): String = "DmEventBus(count=$count, armed=$armed)"
}

internal fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }
