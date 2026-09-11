package org.ghost.sync.engine

import org.ghost.sync.store.GcReport

/** Counts from one maintenance pass (tests and status; nothing is persisted). */
internal class PassReport(val parked: Int, val closed: Int, val decided: Int) {
    override fun toString(): String = "PassReport(parked=$parked, closed=$closed, decided=$decided)"
}

/**
 * Outbox maintenance on the work lane (design §3.5): M1 once at session start, before any other
 * work; M2 on every pass; M3 (closure) and M4 (the D1/D2/W sweep) only while the transport is READY,
 * because they trust the clock (§3.7). Every statement is local SQL; no network.
 *
 * Open so the exit-gate harness can substitute a mutant that omits M1 (design §8.8 M12).
 */
internal open class Maintenance {

    /** M1: leases left in flight by a dead process or an aborted session count as ambiguous. */
    open fun normalize(ctx: EngineContext): Int =
        ctx.db.transaction { tx -> ctx.stores.outboxStore.normalizeLeases(tx, ctx.now()) }

    /** M2, then M3 and M4 when [trustedClock]. */
    open fun pass(ctx: EngineContext, trustedClock: Boolean): PassReport =
        ctx.db.transaction { tx ->
            val now = ctx.now()
            val parked = ctx.stores.outboxStore.parkWithoutCapability(tx, now)
            if (trustedClock) {
                val closed = ctx.stores.outboxStore.close(tx, now)
                val decided = ctx.stores.outboxStore.decideAll(tx, now)
                PassReport(parked, closed, decided)
            } else {
                PassReport(parked, 0, 0)
            }
        }

    override fun toString(): String = "Maintenance"
}

/**
 * The garbage-collection hook of the work lane (design §2.3): one bounded pass of the store's
 * [org.ghost.sync.store.Gc] in a transaction, then, if it deleted rows, the WAL checkpoint outside
 * any transaction. Runs only after the transport reached READY in this process (trusted clock).
 */
internal open class GcStep {

    /** Returns the pass report, or null when the clock is not trusted yet. */
    open fun run(ctx: EngineContext): GcReport? {
        if (!ctx.engine.readyInProcess) return null
        val report = ctx.db.transaction { tx -> ctx.stores.gc.pass(tx, ctx.now()) }
        if (report.total > 0) ctx.stores.gc.checkpoint(ctx.db.sql)
        return report
    }

    override fun toString(): String = "GcStep"
}
