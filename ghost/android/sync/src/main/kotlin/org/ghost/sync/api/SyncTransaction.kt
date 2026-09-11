package org.ghost.sync.api

import org.ghost.storage.SqlExecutor
import java.util.EnumSet

/**
 * One open sync transaction (design §9). Callers do their own writes through [sql], in the same
 * atomic commit as the sync call they make with this object, and do no network I/O inside it.
 * A transaction object is valid only inside its [SyncDatabase.transaction] block and only on the
 * thread that opened it; store calls with a stale or foreign transaction throw
 * [IllegalStateException].
 */
class SyncTransaction internal constructor(
    val sql: SqlExecutor,
    private val database: SyncDatabase,
    private val thread: Thread,
) {
    private var open = true
    private val changes: MutableSet<SyncChange> = EnumSet.noneOf(SyncChange::class.java)

    /** Throws unless this transaction is open, on its own thread, and belongs to [owner]. */
    internal fun requireActive(owner: SyncDatabase) {
        check(open && owner === database && Thread.currentThread() === thread) { "sync transaction is not active" }
    }

    internal fun hint(change: SyncChange) {
        check(open) { "sync transaction is not active" }
        changes += change
    }

    internal fun end() {
        open = false
    }

    internal fun recordedChanges(): Set<SyncChange> = changes.toSet()

    override fun toString(): String = "SyncTransaction"
}
