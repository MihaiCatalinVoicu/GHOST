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
 * crashes never reach the threshold; a caught Rust panic (`INTERNAL`) rolls back and crashes like
 * any `IllegalStateException`".
 *
 * A **nested** transaction is a harness failure, not an engine one — the device executor would
 * refuse it — so it is reported as an [IllegalStateException] from the delegate and never counted.
 */
internal class FaultyDmSqlExecutor(
    val delegate: JdbcSqlExecutor,
    private val bus: DmEventBus,
    private val node: String,
) : SqlExecutor {

    /** Commits of transactions in which a statement changed a row or ran DDL (crash classes). */
    var dirtyCommits: Long = 0
        private set

    /** Statements that changed rows outside any transaction. */
    var autocommitWrites: Long = 0
        private set

    private var dirty = false

    /**
     * Optional statement rewriting: the SQL-level mutants of [DmMutants], exactly as the Phase 7
     * harness's `FaultySqlExecutor.rewrite` (design §15.7 "implemented only in `src/test`").
     */
    var rewrite: ((String, List<Any?>) -> Pair<String, List<Any?>>)? = null

    /** Observers of every executed update: (sql, args, changed rows). */
    val onUpdate = ArrayList<(String, List<Any?>, Int) -> Unit>()

    /** Observers of every transaction end: true once committed, false when rolled back. */
    val onTransactionEnd = ArrayList<(Boolean) -> Unit>()

    private fun rewritten(sql: String, args: List<Any?>): Pair<String, List<Any?>> =
        rewrite?.invoke(sql, args) ?: Pair(sql, args)

    private fun wrote() {
        if (delegate.inTransaction) dirty = true else autocommitWrites++
    }

    /**
     * Raises the event and turns a planned `SQLITE_FULL` into the exception the device would see.
     *
     * The message carries `[SQLITE_FULL]` because `StorageFull.wrap` recognises the real one by
     * that text, and a fake whose shape differs from the real one tests the injector.
     */
    private fun fire(kind: DmEventKind, sql: String) {
        if (bus.event(kind, node, label(sql)) === DmFault.StorageFull) {
            throw StorageFullException(IllegalStateException("[SQLITE_FULL] injected at: ${label(sql)}"))
        }
    }

    override fun exec(sql: String, args: List<Any?>) {
        fire(DmEventKind.SQL_EXEC, sql)
        val (s, a) = rewritten(sql, args)
        delegate.exec(s, a)
        wrote()
    }

    override fun execUpdate(sql: String, args: List<Any?>): Int {
        fire(DmEventKind.SQL_UPDATE, sql)
        val (s, a) = rewritten(sql, args)
        val changed = delegate.execUpdate(s, a)
        if (changed > 0) wrote()
        onUpdate.forEach { it(s, a, changed) }
        return changed
    }

    override fun query(sql: String, args: List<Any?>, onRow: (SqlExecutor.Row) -> Unit) {
        fire(DmEventKind.SQL_QUERY, sql)
        val (s, a) = rewritten(sql, args)
        delegate.query(s, a, onRow)
    }

    override fun <T> transaction(block: () -> T): T {
        var committed = false
        val result = try {
            delegate.transaction {
                dirty = false
                val r = block()
                fire(DmEventKind.PRE_COMMIT, "commit")
                r
            }.also { committed = true }
        } finally {
            if (!committed) onTransactionEnd.forEach { it(false) }
        }
        onTransactionEnd.forEach { it(true) }
        if (dirty) dirtyCommits++
        dirty = false
        fire(DmEventKind.POST_COMMIT, "commit")
        return result
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
