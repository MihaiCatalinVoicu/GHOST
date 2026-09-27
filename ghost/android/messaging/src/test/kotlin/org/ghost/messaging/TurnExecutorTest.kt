package org.ghost.messaging

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.Callable
import java.util.concurrent.RejectedExecutionException

/**
 * [TurnExecutor], the DM actor's turns in a virtual-time world (design §22.36): what makes the
 * worlds' production triggers behave as they do behind the one actor thread. No native library.
 */
class TurnExecutorTest {

    @Test
    fun aTurnPostedFromATurnRunsAfterItAndNeverInsideIt() {
        val log = ArrayList<String>()
        val turns = TurnExecutor { throw AssertionError(it) }
        turns.execute {
            log += "first begins"
            turns.execute { log += "posted by the first" }
            log += "first ends"
        }
        turns.execute { log += "second" }
        assertEquals(listOf("first begins", "first ends", "posted by the first", "second"), log)
        assertEquals(3L, turns.turns)
    }

    @Test
    fun postingQueuesWhatTheBlockPostsBehindIt() {
        val log = ArrayList<String>()
        val turns = TurnExecutor { throw AssertionError(it) }
        turns.posting {
            turns.execute { log += "a" }
            log += "the block goes on"
            turns.execute { log += "b" }
        }
        assertEquals(listOf("the block goes on", "a", "b"), log)
        // The block itself is no turn: only what it posted counts.
        assertEquals(2L, turns.turns)
    }

    @Test
    fun aFailedTurnIsHandedOverAndTheNextOnesStillRun() {
        val failures = ArrayList<Throwable>()
        val log = ArrayList<String>()
        val turns = TurnExecutor { failures += it }
        turns.execute { throw IllegalStateException("a pass threw") }
        turns.execute { log += "the next turn" }
        assertEquals(listOf("a pass threw"), failures.map { it.message })
        assertEquals(listOf("the next turn"), log)
    }

    @Test
    fun aFailureRethrownEndsTheQueueWithIt() {
        val log = ArrayList<String>()
        val turns = TurnExecutor { throw it }
        val thrown = runCatching {
            turns.execute {
                turns.execute { log += "queued behind the crash" }
                throw StackOverflowError("an injected crash")
            }
        }.exceptionOrNull()
        assertTrue("the crash did not reach the caller: $thrown", thrown is StackOverflowError)
        assertTrue("a turn of the crashed process ran: $log", log.isEmpty())
        // The executor is usable by the next process's turns.
        turns.execute { log += "after" }
        assertEquals(listOf("after"), log)
    }

    @Test
    fun aTurnThatWaitsForATurnQueuedBehindItIsRefusedNotAHang() {
        val failures = ArrayList<Throwable>()
        val turns = TurnExecutor { failures += it }
        turns.execute {
            val behind = turns.submit(Callable { 1 })
            behind.get()
        }
        assertEquals(1, failures.size)
        assertTrue(failures.single().message!!.contains("queued behind it"))
    }

    @Test
    fun aStoppedExecutorRefusesATurn() {
        val turns = TurnExecutor { throw AssertionError(it) }
        turns.shutdown()
        assertTrue(runCatching { turns.execute { } }.exceptionOrNull() is RejectedExecutionException)
    }
}
