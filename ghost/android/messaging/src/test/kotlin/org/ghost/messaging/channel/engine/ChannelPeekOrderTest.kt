package org.ghost.messaging.channel.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [ChannelPeekOrder] alone (Phase 10 design §6.3.3, §19.38), with no native library: the gap held in place without
 * pressure, the entries a gap holds deferred under pressure and offered back by key once the gap fills, the hour after
 * which a gap under pressure is decrypted past, and an idle pass that forgets the hold of the last one.
 */
class ChannelPeekOrderTest {

    private val channel = ByteArray(32) { 7 }
    private val namespace = List(32) { 3.toByte() }
    private val start = 1_000_000L

    private fun entry(seq: Long, pressure: Boolean, leaf: Long = 0): ChannelPeekOrder.Entry<String> =
        ChannelPeekOrder.Entry(channel, 1, leaf, seq, key(leaf, seq), namespace, "s$seq", pressure)

    private fun key(leaf: Long, seq: Long): List<Byte> = namespace + List(32) { i -> if (i == 0) leaf.toByte() else if (i == 1) seq.toByte() else 0 }

    private fun ChannelPeekOrder.Plan<String>.taken(): List<Long> = batches.flatten().map { it.seq }

    @Test
    fun withoutPressureAGapIsHeldInPlaceForTwelveMinutesThenDecryptedPast() {
        val order = ChannelPeekOrder()
        val entries = listOf(entry(0, false), entry(1, false), entry(3, false))
        val first = order.plan(entries, entries.map { it.key }.toSet(), start)
        assertEquals(listOf(0L, 1L), first.taken())
        assertTrue(first.deferrals.isEmpty())
        assertEquals(start + ChannelTime.GAP_HOLD_SECONDS, order.holdEnds())
        order.decrypted(channel, 1, 0, 0)
        order.decrypted(channel, 1, 0, 1)
        val rest = listOf(entry(3, false))
        assertEquals(emptyList<Long>(), order.plan(rest, rest.map { it.key }.toSet(), start + 60).taken())
        assertEquals(listOf(3L), order.plan(rest, rest.map { it.key }.toSet(), start + ChannelTime.GAP_HOLD_SECONDS).taken())
    }

    @Test
    fun underPressureTheEntriesAGapHoldsAreDeferredAndOfferedBackByKeyOnceItFills() {
        val order = ChannelPeekOrder()
        // an unknown sender under pressure waits for its seq 0, which this window does not show
        val window = listOf(entry(1, true), entry(2, true))
        val plan = order.plan(window, window.map { it.key }.toSet(), start)
        assertEquals(emptyList<Long>(), plan.taken())
        assertEquals(listOf(1L to 0L, 2L to 0L), plan.deferrals.map { it.first.seq to it.second })
        for ((e, waiting) in plan.deferrals) order.deferred(e, waiting, start + ChannelPeekOrder.GAP_DEFER_SECONDS)
        assertEquals(start + ChannelPeekOrder.GAP_DEFER_SECONDS, order.holdEnds())
        // seq 0 comes into view: decrypted; the namespace is due a re-offer, once
        val zero = listOf(entry(0, true))
        assertEquals(listOf(0L), order.plan(zero, zero.map { it.key }.toSet(), start + 1).taken())
        order.decrypted(channel, 1, 0, 0)
        assertEquals(setOf(namespace), order.reofferDue(channel))
        assertEquals(emptySet<List<Byte>>(), order.reofferDue(channel))
        // the next round offers the deferred rows back by their keys, with no value, wherever the window is
        val back = order.plan(emptyList<ChannelPeekOrder.Entry<String>>(), emptySet(), start + 2)
        assertEquals(listOf(1L, 2L), back.taken())
        assertTrue(back.batches.flatten().all { it.value == null })
        assertEquals(listOf(key(0, 1), key(0, 2)), back.batches.flatten().map { it.key })
    }

    @Test
    fun underPressureAGapIsDecryptedPastAfterAnHourOfWaiting() {
        val order = ChannelPeekOrder()
        order.decrypted(channel, 1, 0, 4)
        val window = listOf(entry(7, true), entry(8, true))
        val first = order.plan(window, window.map { it.key }.toSet(), start)
        assertEquals(listOf(7L to 5L, 8L to 5L), first.deferrals.map { it.first.seq to it.second })
        for ((e, waiting) in first.deferrals) order.deferred(e, waiting, start + ChannelPeekOrder.GAP_DEFER_SECONDS)
        // the rows come back at their deferral's end; the gap (5, 6) never filled: an hour after they were first seen,
        // they are decrypted past
        val late = order.plan(window, window.map { it.key }.toSet(), start + ChannelPeekOrder.PRESSURE_HOLD_SECONDS)
        assertEquals(listOf(7L, 8L), late.taken())
        assertTrue(late.deferrals.isEmpty())
    }

    @Test
    fun anIdlePassForgetsTheHoldOfTheLastOne() {
        val order = ChannelPeekOrder()
        val entries = listOf(entry(0, false), entry(2, false))
        order.plan(entries, entries.map { it.key }.toSet(), start)
        assertEquals(start + ChannelTime.GAP_HOLD_SECONDS, order.holdEnds())
        order.idle(start + 60)
        assertNull(order.holdEnds())
    }
}
