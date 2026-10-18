package org.ghost.app.ui

import java.util.concurrent.Executors
import kotlin.concurrent.thread
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.asCoroutineDispatcher

/**
 * Phase 13 design §3.2: the `ghost-ui-io` executor — a fixed pool of 2 threads every gateway
 * adapter runs its blocking facade calls on, wrapped as a coroutine dispatcher. CS-U6: adapters
 * assert this thread name. The DM actor serializes its own calls; at most two UI reads are in
 * flight, so a due time-triggered turn waits behind at most those two (§3.2, RT-UI1's bound).
 */
object GhostUiIo {
    const val THREAD_PREFIX = "ghost-ui-io"

    private val pool = Executors.newFixedThreadPool(2) { runnable ->
        thread(name = "$THREAD_PREFIX-${threadCounter++}", start = false) { runnable.run() }
    }

    private var threadCounter = 0

    val dispatcher: CoroutineDispatcher = pool.asCoroutineDispatcher()

    /** Asserts the current thread is one of ours; adapters call this first (CS-U6). */
    fun assertThread() {
        check(Thread.currentThread().name.startsWith(THREAD_PREFIX)) {
            "gateway adapter call on ${Thread.currentThread().name}, not on $THREAD_PREFIX"
        }
    }
}
