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
     * A statement that changes the file.
     *
     * Narrower than [canBeFull] by exactly one kind, and the difference is the point:
     * [PRE_COMMIT] fires for **every** transaction, including a read-only one, so counting it as a
     * write would report `DmActor`'s post-death `schedule.afterCommit()` — which is four read-only
     * transactions — as four writes. A full disk can still fail such a commit, which is why
     * `canBeFull` keeps it; nothing about it changes a row, which is why this does not.
     */
    val writes: Boolean get() = this == SQL_EXEC || this == SQL_UPDATE

    /**
     * Where a `SQLITE_FULL` can actually come from.
     *
     * SQLite raises it when it needs a page it cannot get, which is a **write**: a read never
     * extends the file, and a commit that has already returned cannot fail afterwards. Injecting it
     * at a `SELECT` would make the harness demand that the engine handle an input SQLite cannot
     * produce, and "the engine does not map an impossible failure" is not a finding. So SCN-J's
     * "every statement of SEND, RECV, BUNDLE and SWEEP" is every statement that writes, plus the
     * commit — which is the statement a full disk fails most often.
     *
     * **Before the statement, not during it, and that is a declared narrowing.** `FaultyDmSqlExecutor`
     * raises the event and throws *before* it calls the delegate, so the statement never runs at
     * all; the real `SQLITE_FULL` surfaces after SQLite has already done partial work inside the
     * transaction. The two are equivalent for every path here, because every one of them takes a
     * whole-transaction rollback and a rollback undoes the partial work either way. They stop being
     * equivalent the moment a path uses a SAVEPOINT and continues after the failure — then "the
     * statement did nothing" and "the statement did half of something and was rolled back to the
     * savepoint" are different states, and this injector only ever produces the first. No DM path
     * uses a savepoint today; one that does needs its own injection point rather than this one.
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
     * The relay applied the store and the response never arrived (§15.3's "every relay event also
     * runs as *timeout after apply*").
     *
     * **Only at [DmEventKind.RELAY_AFTER_APPLY]**, the one event at which it means anything: before
     * the send nothing has been applied yet, and after the response the sender already knows. The
     * first version planned it at all three relay events and the bus counted it at all three, while
     * the model relay acted on it at one — so two thirds of the "timeout" runs injected nothing, ran
     * exactly as the fault-free recording run did, and were still counted and still skipped the
     * final checks as faulted runs. The bus now refuses it anywhere else.
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
 * `INTERNAL` result code and "rolls back and crashes like any `IllegalStateException`" (§15.3).
 * Only the uncatchable half is here; the caught one is
 * `DmPoisonTest.aCaughtRustPanicRollsBackAndNeverReachesThePoisonThreshold`, which is a case and
 * not, as this comment used to imply, a sentence in SCN-J that nothing ran.
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

    /** How many relay responses the plan dropped after the relay applied the store. */
    var timeouts: Int = 0
        private set

    val faulted: Boolean get() = injected.isNotEmpty() || storageFulls > 0 || timeouts > 0

    /** Observers of every event, before the plan (the recording run classifies through it). */
    var onEvent: ((DmEvent) -> Unit)? = null

    /**
     * True while a mutation that **split a transaction** still owes its second half (see
     * [DmMutants.MC1] and [FaultyDmSqlExecutor.defer]).
     *
     * A crash raised while this is set loses work the unmutated engine had already committed, so
     * the indices collected in [vulnerable] are the crash points at which the split is observable.
     * Nothing in an unmutated world ever sets it.
     */
    var inSplitWindow: Boolean = false

    /** The event indices raised inside a split window, in order (the recording run collects them). */
    val vulnerable = ArrayList<Long>()

    /**
     * Where a mutation's statement rewrite **acted**, one span per transaction (§22.27's review):
     * from the event of the first statement of that transaction whose text or arguments the rewrite
     * changed, to the last event the transaction raised — its post-commit event when it committed,
     * the last statement it reached when it rolled back. A rewritten statement outside a
     * transaction is a span of one event. Nothing in an unmutated world ever adds one.
     *
     * A mutant kill that puts its crash points "where the mutant acts" reads the first span after
     * the scenario's mark from the mutated fault-free run: the window is the transaction the mutant
     * first changes, and a crash there interrupts the defect itself rather than preceding it or
     * following its commit — which is what the review measured of the marks alone (the six points
     * of MC-21 all fell after its only effect had committed, and four of MC-24's before it began).
     */
    val rewrittenSpans = ArrayList<LongRange>()

    /**
     * Where a **native** mutation acted (§22.37): the index of the first event at which the mutated
     * world departs from the clean one — measured by tracing both fault-free runs, since a mutation
     * inside the crate raises no event of its own. The transaction that raises it goes into
     * [rewrittenSpans] as a rewrite's would, from its **first** event to its last (the mutant acted
     * in a native call before any statement of it could tell). Null — the default — records nothing.
     *
     * A rewrite whose window is measured the same way (ME-17, [DmMutants.Mutation.windowByDeparture];
     * §22.38's review) records no span of its own while this is set, so the departure's transaction,
     * whole, is the one span of the run.
     */
    var actsFrom: Long? = null

    /**
     * The node a crash has just killed, from the moment the [Error] is thrown until the runner has
     * rebooted it — and every **write** it performed in between.
     *
     * A process death is not a `finally`, and on the way out of `DmActor.runPass` one runs:
     * `schedule.afterCommit()` executes after the injected `Error` has begun propagating, so the
     * "dead" device performs two more transactions before the runner ever sees the crash. They are
     * read-only today (`UnreadNotices` re-reads its deadline), which is why the model is still
     * faithful — but nothing enforced that, and a step that starts writing there would make every
     * crash run a crash-plus-one-more-transaction run without a single test changing. So the writes
     * are collected and the runner refuses them; reads are left alone, because a read after death
     * changes nothing a reboot would not overwrite.
     */
    var deadNode: String? = null

    val afterDeathWrites = ArrayList<String>()

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
        if (inSplitWindow) vulnerable += count
        if (deadNode == node && kind.writes) afterDeathWrites += "$kind($detail)"
        val e = DmEvent(count, kind, node, detail)
        onEvent?.invoke(e)
        return when (plan.at(e)) {
            null -> null
            DmFault.Crash -> {
                val crash = SimulatedDmCrash(count, kind, node)
                injected += crash
                deadNode = node
                throw crash
            }

            DmFault.NativeCrash -> {
                val crash = SimulatedNativeCrash(count, node)
                injected += crash
                deadNode = node
                throw crash
            }

            DmFault.StorageFull -> {
                storageFulls++
                DmFault.StorageFull
            }

            DmFault.TimeoutAfterApply -> {
                check(kind == DmEventKind.RELAY_AFTER_APPLY) {
                    "a timeout-after-apply was planned at $kind, where the relay cannot act on it"
                }
                timeouts++
                DmFault.TimeoutAfterApply
            }
        }
    }

    override fun toString(): String = "DmEventBus(count=$count, armed=$armed)"
}

internal fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }
