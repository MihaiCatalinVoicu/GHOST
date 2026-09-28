package org.ghost.messaging.harness

import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.SqlExecutor
import org.ghost.storage.StorageFullException

/**
 * The fault-injecting executor of Phase 9 design §15.1 and §15.3.
 *
 * > **Faults:** `FaultySqlExecutor` (a crash before every statement, before and after commit, and
 * > `SQLITE_FULL` injection mapped to `StorageFullException`)
 *
 * Every `exec`, `execUpdate` and `query` raises an event **before** it runs, so a crash there
 * leaves the statement unexecuted; a transaction adds a pre-commit event inside the block (a crash
 * there rolls the block back, which is what SQLite does when the process dies mid-transaction) and
 * a post-commit event after the commit (so the caller never learns it succeeded).
 *
 * `SQLITE_FULL` is injected in the same place but as a typed [StorageFullException], because that
 * is what the real thing is: SQLite raises it *from the statement*, `JdbcSqlExecutor` wraps it, and
 * §7.8 lets the engine handle it. The distinction is the whole of SCN-J: "single and double SQL
 * crashes never reach the threshold" — which SCN-J's own `alwaysChecks` asserts — while "a caught
 * Rust panic (`INTERNAL`) rolls back and crashes like any `IllegalStateException`", which is not a
 * SQL fault at all and lives in `DmPoisonTest`.
 *
 * A **nested** transaction is a harness failure, not an engine one — the device executor would
 * refuse it — so it is reported as an [IllegalStateException] from the delegate and never counted.
 */
internal class FaultyDmSqlExecutor(
    val delegate: JdbcSqlExecutor,
    private val bus: DmEventBus,
    private val node: String,
) : SqlExecutor {

    /**
     * Optional statement rewriting: the SQL-level mutants of [DmMutants], exactly as the Phase 7
     * harness's `FaultySqlExecutor.rewrite` (design §15.7 "implemented only in `src/test`").
     */
    var rewrite: ((String, List<Any?>) -> Pair<String, List<Any?>>)? = null

    /**
     * The **transaction-split** seam: a predicate over a statement's SQL that, when it matches
     * inside a transaction, holds the statement back and commits it in a transaction of its own
     * once the enclosing one has committed.
     *
     * It is the third mutation mechanism of this harness, beside [rewrite] and the `DmEnvelopes`
     * decorator, and it exists because the two of them cannot express §15.7's MC-1 — "ratchet state
     * and op committed in two transactions" — which is the mutant CS-1 names first and the one
     * SCN-A exists to kill. §22.15 item 8 recorded MC-1 as out of reach of a statement rewrite,
     * and it is: a rewrite can change what a statement says, never when it commits. What a split
     * can do is exactly the defect, with no change to the production code.
     *
     * A split is invisible without a crash — the second transaction follows the first immediately,
     * so a fault-free run of the mutated world passes — and fatal with one: a crash anywhere in the
     * window between the two commits loses the second half for good. Those event indices are what
     * [DmEventBus.vulnerable] collects.
     *
     * Only [exec] is deferrable. `execUpdate` returns a row count its callers check (`updateExactly`
     * and `check(deliveries >= QUORUM)` in `OutboxStore`), and a harness that invented a count
     * would be mutating what the engine *reads* as well as when it commits — two defects in one
     * mutant, and the run would no longer say which of them it detected.
     */
    var defer: ((String) -> Boolean)? = null

    /**
     * The same seam for an [execUpdate] (design §22.37, MC-7′'s second half), which [defer] refuses
     * because a split must not invent what the engine reads. Here the count is **declared** by the
     * mutation and **checked**: the predicate returns the row count the held-back statement returns
     * in the unmutated world at that call (or null to run the statement now); the caller is given
     * that count, and when the statement runs in its own transaction its real count must be the
     * declared one, or the run fails as a harness error — never as a kill. Its one user holds back
     * `SessionStore.markFirstFlightUsed`'s insert, whose only caller (`ReceiveStep`) discards the
     * count and reaches it only after `firstFlightUsed` found no tuple, so the unmutated insert
     * returns 1 there and the split changes nothing the engine reads.
     */
    var deferUpdate: ((String) -> Int?)? = null

    /** A held-back statement, and the count its caller was given when it was an [execUpdate]. */
    private class Held(val sql: String, val args: List<Any?>, val declaredCount: Int?)

    private val deferred = ArrayList<Held>()

    /** True while the held-back statements are being replayed, so the predicate does not re-hold them. */
    private var replaying = false

    /**
     * The event index of the first statement of the open transaction whose text or arguments
     * [rewrite] changed, or null when none has (see [DmEventBus.rewrittenSpans]).
     */
    private var rewrittenFrom: Long? = null

    /**
     * Told when a `PRAGMA wal_checkpoint` through this executor answered `busy = 0` — a checkpoint
     * that reports it truncated the log (§22.38). The pragma is recognised by the statement the
     * engine **issued**, before any rewrite, so a mutant that answers for the checkpoint without
     * running it (ME-11) is measured like the real one.
     */
    var afterCheckpoint: (() -> Unit)? = null

    /** The event index of the open transaction's first event, for [DmEventBus.actsFrom]. */
    private var transactionFrom: Long? = null

    /**
     * The statement [rewrite] makes of this one. Called right after the statement's own event was
     * raised, so the bus's count is that event's index.
     *
     * Its span is not recorded in a run whose window is found by tracing ([DmEventBus.actsFrom] set):
     * there the window is the transaction in which the worlds part, whole, and a rewritten statement
     * says only that a text changed — ME-17's first one after its mark decided nothing (§22.38's
     * review). Every other mutant found by tracing rewrites nothing in the armed phase.
     */
    private fun rewritten(sql: String, args: List<Any?>): Pair<String, List<Any?>> {
        val out = rewrite?.invoke(sql, args) ?: return Pair(sql, args)
        if (bus.armed && bus.actsFrom == null && (out.first != sql || out.second != args)) {
            if (delegate.inTransaction) {
                if (rewrittenFrom == null) rewrittenFrom = bus.count
            } else {
                bus.rewrittenSpans += bus.count..bus.count
            }
        }
        return out
    }

    /** Closes the open transaction's span, at the last event it raised. */
    private fun closeRewrittenSpan() {
        val from = rewrittenFrom ?: return
        rewrittenFrom = null
        if (bus.armed) bus.rewrittenSpans += from..bus.count
    }

    /** True when this statement is to be held back for the second transaction. */
    private fun held(sql: String): Boolean =
        !replaying && delegate.inTransaction && defer?.invoke(sql) == true

    /**
     * Raises the event and turns a planned `SQLITE_FULL` into the exception the device would see.
     *
     * The message carries `[SQLITE_FULL]` because `StorageFull.wrap` recognises the real one by
     * that text, and a fake whose shape differs from the real one tests the injector.
     */
    private fun fire(kind: DmEventKind, sql: String) {
        val fault = bus.event(kind, node, label(sql))
        if (delegate.inTransaction && transactionFrom == null) transactionFrom = bus.count
        if (bus.armed && bus.count == bus.actsFrom) {
            // A native mutant's departure (§22.37): its whole transaction is the span.
            if (delegate.inTransaction) {
                if (rewrittenFrom == null) rewrittenFrom = transactionFrom
            } else {
                bus.rewrittenSpans += bus.count..bus.count
            }
        }
        if (fault === DmFault.StorageFull) {
            throw StorageFullException(IllegalStateException("[SQLITE_FULL] injected at: ${label(sql)}"))
        }
    }

    override fun exec(sql: String, args: List<Any?>) {
        if (held(sql)) {
            deferred += Held(sql, args, declaredCount = null)
            return
        }
        fire(DmEventKind.SQL_EXEC, sql)
        val (s, a) = rewritten(sql, args)
        delegate.exec(s, a)
    }

    override fun execUpdate(sql: String, args: List<Any?>): Int {
        val declared = if (!replaying && delegate.inTransaction) deferUpdate?.invoke(sql) else null
        if (declared != null) {
            deferred += Held(sql, args, declared)
            return declared
        }
        fire(DmEventKind.SQL_UPDATE, sql)
        val (s, a) = rewritten(sql, args)
        return delegate.execUpdate(s, a)
    }

    override fun query(sql: String, args: List<Any?>, onRow: (SqlExecutor.Row) -> Unit) {
        fire(DmEventKind.SQL_QUERY, sql)
        val (s, a) = rewritten(sql, args)
        val measure = afterCheckpoint
        if (measure == null || !sql.startsWith("PRAGMA wal_checkpoint")) {
            delegate.query(s, a, onRow)
            return
        }
        var busy: Long? = null
        delegate.query(s, a) { row ->
            if (busy == null) busy = row.long(0)
            onRow(row)
        }
        if (busy == 0L) measure()
    }

    override fun <T> transaction(block: () -> T): T {
        rewrittenFrom = null
        if (!delegate.inTransaction) transactionFrom = null
        val result = try {
            delegate.transaction {
                val r = block()
                // Inside the block, so a crash here unwinds through `JdbcSqlExecutor.transaction`'s
                // own `catch` and the connection is rolled back — the committed state a process
                // death mid-transaction leaves.
                fire(DmEventKind.PRE_COMMIT, "commit")
                r
            }
        } catch (e: Throwable) {
            // Rolled back: a span the rewrite opened ends at the last statement it reached.
            closeRewrittenSpan()
            throw e
        }
        // After the commit: the caller never learns it succeeded, which is the other half of the
        // window §7.8 is about.
        if (deferred.isEmpty()) {
            // The second half of a split has just committed: from its post-commit event on, a
            // crash loses nothing the unmutated engine had committed, so the window closes before
            // that event (§22.37: [DmEventBus.vulnerable] had counted it, and a crash there is not
            // one at which the split is observable).
            if (replaying) bus.inSplitWindow = false
            try {
                fire(DmEventKind.POST_COMMIT, "commit")
            } finally {
                closeRewrittenSpan()
            }
            return result
        }
        // A split transaction (see [defer]). The window opens **before** the post-commit event,
        // because a crash there is already past the first commit and already loses the second half.
        bus.inSplitWindow = true
        try {
            try {
                fire(DmEventKind.POST_COMMIT, "commit")
            } catch (death: Throwable) {
                // A crash at the first commit's post-commit event: the process is dead, and a
                // process that died owes nothing — the held-back statements are lost, which is the
                // split's defect. They must not be committed by a transaction the dying device still
                // runs on its way out (`DmActor.runPass`'s `afterCommit`), which the runner refuses
                // as a write after death (found by §22.37's MC-7′ kill; MC-1's seam had the gap).
                deferred.clear()
                throw death
            } finally {
                closeRewrittenSpan()
            }
            replayDeferred()
        } finally {
            bus.inSplitWindow = false
        }
        return result
    }

    /**
     * The second half of a split transaction: the held-back statements, in their own transaction,
     * through this executor — so every one of them raises its event and a crash at any of them, or
     * at either of that transaction's own commit events, loses the whole buffer.
     *
     * The buffer is cleared **before** the replay, so a crash inside it does not leave statements
     * that a later transaction would then commit: a process that died owes nothing.
     */
    private fun replayDeferred() {
        val pending = ArrayList(deferred)
        deferred.clear()
        replaying = true
        try {
            transaction {
                for (held in pending) {
                    val declared = held.declaredCount
                    if (declared == null) {
                        exec(held.sql, held.args)
                    } else {
                        val real = execUpdate(held.sql, held.args)
                        check(real == declared) {
                            "the split told its caller ${label(held.sql)} changed $declared row(s), and it " +
                                "changed $real: the mutation's declared count is wrong (a harness error)"
                        }
                    }
                }
            }
        } finally {
            replaying = false
        }
    }

    override val inTransaction: Boolean get() = delegate.inTransaction

    override var userVersion: Int
        get() = delegate.userVersion
        set(value) {
            delegate.userVersion = value
        }

    override fun toString(): String = "FaultyDmSqlExecutor($node)"

    private companion object {
        /** The first words of a statement: enough to read a failure, never a bound value. */
        fun label(sql: String): String = sql.trim().take(48).replace(Regex("\\s+"), " ")
    }
}
