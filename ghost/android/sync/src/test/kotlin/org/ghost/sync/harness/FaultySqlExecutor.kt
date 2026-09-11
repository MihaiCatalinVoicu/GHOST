package org.ghost.sync.harness

import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.SqlExecutor

/**
 * Fault-injecting [SqlExecutor] (design §8.2). Every `exec`, `execUpdate` and `query` is an event
 * before it runs; a transaction adds a pre-commit event (inside the block, so a crash there rolls
 * the block back) and a post-commit event (after the commit, so the caller never sees success).
 * A nested transaction is a harness failure (the device executor would nest silently).
 *
 * It also counts durable writes for the classification of crash points: [dirtyCommits] (commits
 * of transactions in which a statement changed a row or ran DDL) and [autocommitWrites]. Statement
 * observers ([onUpdate]) see every executed update with its arguments and row count (the
 * retention-safety check watches garbage-collection deletes through it).
 */
internal class FaultySqlExecutor(val delegate: JdbcSqlExecutor, private val bus: EventBus) : SqlExecutor {
    var dirtyCommits: Long = 0
        private set
    var autocommitWrites: Long = 0
        private set
    private var dirty = false

    /** Observers of executed updates: (sql, args, changed rows). */
    val onUpdate = ArrayList<(String, List<Any?>, Int) -> Unit>()

    /**
     * Checks run after every commit that changed an outbox, capability, directory or relay-set row,
     * before the post-commit event (the outcome-truth invariants hold at every committed state, not
     * only at reboots and at the end).
     */
    val onCommit = ArrayList<() -> Unit>()

    /** Optional statement rewriting (mutants M2, M6, M8, M10, M11 are SQL-level, design §8.8). */
    var rewrite: ((String, List<Any?>) -> Pair<String, List<Any?>>)? = null

    /** The open transaction changed a table the outcome-truth checks read. */
    private var truthTouched = false

    private fun wrote() {
        if (delegate.inTransaction) dirty = true else autocommitWrites++
    }

    private fun touches(sql: String): Boolean =
        sql.contains("outbox_") || sql.contains("relay_capability") || sql.contains("relay_directory") || sql.contains("namespace_relay")

    private fun rewritten(sql: String, args: List<Any?>): Pair<String, List<Any?>> = rewrite?.invoke(sql, args) ?: Pair(sql, args)

    override fun exec(sql: String, args: List<Any?>) {
        bus.event(EventKind.SQL_EXEC)
        val (s, a) = rewritten(sql, args)
        delegate.exec(s, a)
        wrote()
        if (touches(s)) truthTouched = true
    }

    override fun execUpdate(sql: String, args: List<Any?>): Int {
        bus.event(EventKind.SQL_UPDATE)
        val (s, a) = rewritten(sql, args)
        val changed = delegate.execUpdate(s, a)
        if (changed > 0) {
            wrote()
            if (touches(s)) truthTouched = true
        }
        onUpdate.forEach { it(s, a, changed) }
        return changed
    }

    override fun query(sql: String, args: List<Any?>, onRow: (SqlExecutor.Row) -> Unit) {
        bus.event(EventKind.SQL_QUERY)
        val (s, a) = rewritten(sql, args)
        delegate.query(s, a, onRow)
    }

    override fun <T> transaction(block: () -> T): T {
        if (delegate.inTransaction) violation("nested transaction on the sync executor")
        val result = delegate.transaction {
            dirty = false
            truthTouched = false
            val r = block()
            bus.event(EventKind.PRE_COMMIT)
            r
        }
        val check = truthTouched
        if (dirty) dirtyCommits++
        dirty = false
        truthTouched = false
        if (check) onCommit.forEach { it() }
        bus.event(EventKind.POST_COMMIT)
        return result
    }

    override val inTransaction: Boolean get() = delegate.inTransaction

    override var userVersion: Int
        get() = delegate.userVersion
        set(value) {
            delegate.userVersion = value
        }

    override fun toString(): String = "FaultySqlExecutor"
}
