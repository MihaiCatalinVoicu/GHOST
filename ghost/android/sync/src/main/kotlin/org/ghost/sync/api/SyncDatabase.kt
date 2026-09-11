package org.ghost.sync.api

import org.ghost.storage.SqlExecutor
import java.util.concurrent.locks.ReentrantLock

/**
 * The only way to get a [SyncTransaction] (design §9, §11.2 #10).
 *
 * Concurrency contract:
 *  - every transaction of every thread (read lane, work lane, consumers) is serialized through one
 *    [ReentrantLock] owned by this object, so sync transactions never interleave;
 *  - [transaction] is not reentrant per thread: a call on a thread that is already inside one throws
 *    [IllegalStateException] before touching the lock or the connection, so the outer work is
 *    neither committed nor rolled back by the nested call;
 *  - no network call may run inside a transaction (design §1.4); the block does SQL only;
 *  - [SyncChange] hints recorded during a transaction are delivered after it commits, on the
 *    committing thread, after the lock is released. A rolled-back transaction delivers nothing.
 *    Listeners must not throw: an exception from a listener reaches the caller of [transaction]
 *    although the transaction is already durable.
 */
class SyncDatabase(sql: SqlExecutor) {
    internal val sql: SqlExecutor = sql
    private val lock = ReentrantLock()
    private val inside = ThreadLocal.withInitial { false }

    @Volatile
    private var consumerListener: SyncListener? = null

    @Volatile
    private var engineListener: SyncListener? = null

    fun <T> transaction(block: (SyncTransaction) -> T): T {
        check(inside.get() != true) { "nested sync transaction on the same thread" }
        val tx = SyncTransaction(sql, this, Thread.currentThread())
        lock.lock()
        val result = try {
            inside.set(true)
            sql.transaction { block(tx) }
        } finally {
            tx.end()
            inside.set(false)
            lock.unlock()
        }
        val changes = tx.recordedChanges()
        if (changes.isNotEmpty()) {
            engineListener?.onChanged(changes)
            consumerListener?.onChanged(changes)
        }
        return result
    }

    /** True while the calling thread is inside a [transaction] of this database. */
    val inTransaction: Boolean get() = inside.get() == true

    /** Threads waiting for the transaction lock (threading tests). */
    internal val waitingThreads: Int get() = lock.queueLength

    /** Consumer hint listener (set through [Inbox.setListener]). */
    internal fun setConsumerListener(listener: SyncListener?) {
        consumerListener = listener
    }

    /** Engine hint listener: refreshes the read-lane snapshot after capability and topology changes. */
    internal fun setEngineListener(listener: SyncListener?) {
        engineListener = listener
    }

    override fun toString(): String = "SyncDatabase"
}

/** Hint after commit; carries no payload. */
fun interface SyncListener {
    fun onChanged(changes: Set<SyncChange>)
}

enum class SyncChange {
    /** A blob became available to [Inbox.claim]. */
    INBOX,

    /** An outbound outcome was decided and awaits [Outbox.release]. */
    OUTCOMES,

    /** A capability was installed, rejected or exhausted ([Capabilities.needed] may have changed). */
    CAPABILITIES,

    /** The relay directory, a namespace or a relay set changed (read pairs may have changed). */
    TOPOLOGY,
}
