package org.ghost.messaging.channel.store

import org.ghost.storage.chBytes
import org.ghost.storage.queryLong
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `ch_epoch`, `ch_epoch_log` and `ch_fork_signal` through [EpochStore] (Phase 10 design §6.4, §8.3, §9, §19.21;
 * slice S3): an epoch is opened, anchored, finalized once with its winner and its retention, and read only while
 * it is within that retention; the own post sequence is taken and incremented in the caller's transaction; the
 * log and the fork signals keep their bounds.
 */
class EpochStoreTest {

    private val today = 20_000L

    private fun EpochStore.openEpoch(w: StoreWorld, epoch: Long, anchor: Long? = null) =
        w.tx { insert(it, w.ch, epoch, chBytes(68, 5 + epoch.toInt()), chBytes(32, 6 + epoch.toInt()), anchorMinute = anchor) }

    @Test
    fun anOpenEpochIsAnchoredAndFinalizedOnceWithItsWinnerAndItsRetention() = StoreWorld().use { w ->
        w.channel()
        w.stores.epochs.openEpoch(w, 0)
        var row = w.stores.epochs.open(w.db, w.ch, today)!!
        assertEquals(EpochState.OPEN, row.state)
        assertArrayEquals(chBytes(68, 5), row.kEnv)
        assertArrayEquals(chBytes(32, 6), row.rEp)
        assertEquals(0L, row.ownSeq)
        assertNull(row.winnerHash)
        assertNull(row.anchorMinute)
        assertTrue(w.tx { w.stores.epochs.setAnchor(it, w.ch, 0, 600) })
        assertEquals(600L, w.stores.epochs.epoch(w.db, w.ch, 0, today)!!.anchorMinute)
        // CO-5: the epoch is final, its anchor gone (§19.21), its winner and the days recorded
        val winner = chBytes(32, 7)
        assertTrue(w.tx { w.stores.epochs.finalize(it, w.ch, 0, winner, 19_999, 20_002) })
        row = w.stores.epochs.epoch(w.db, w.ch, 0, today)!!
        assertEquals(EpochState.FINAL, row.state)
        assertNull("a final epoch keeps no anchor", row.anchorMinute)
        assertArrayEquals(winner, row.winnerHash)
        assertEquals(19_999L, row.finalDay)
        assertEquals(20_002L, row.keepUntilDay)
        // sticky: a second finalize, an anchor on a final epoch: nothing matches
        assertFalse(w.tx { w.stores.epochs.finalize(it, w.ch, 0, winner, 20_000, 20_003) })
        assertFalse(w.tx { w.stores.epochs.setAnchor(it, w.ch, 0, 660) })
        assertNull(w.stores.epochs.open(w.db, w.ch, today))
        assertRedacted(row, chBytes(68, 5), chBytes(32, 6), winner, w.ch)
    }

    @Test
    fun everyReadAppliesTheRetentionBoundOfSectionEightThree() = StoreWorld().use { w ->
        w.channel()
        for (e in 0L..3L) w.stores.epochs.openEpoch(w, e)
        // epochs 0 and 1 final with different bounds, 2 final without one yet, 3 open
        assertTrue(w.tx { w.stores.epochs.finalize(it, w.ch, 0, chBytes(32, 7), 19_990, 19_999) })
        assertTrue(w.tx { w.stores.epochs.finalize(it, w.ch, 1, chBytes(32, 8), 19_998, 20_000) })
        assertTrue(w.tx { w.stores.epochs.finalize(it, w.ch, 2, chBytes(32, 9), 19_999, 20_001) })
        assertEquals(listOf(3L, 2L, 1L), w.stores.epochs.retained(w.db, w.ch, today).map { it.epoch })
        assertEquals(listOf(3L, 2L), w.stores.epochs.retained(w.db, w.ch, 20_001).map { it.epoch })
        assertEquals(listOf(3L), w.stores.epochs.retained(w.db, w.ch, 20_002).map { it.epoch })
        assertNull(w.stores.epochs.epoch(w.db, w.ch, 0, today))
        assertEquals(1L, w.stores.epochs.epoch(w.db, w.ch, 1, today)!!.epoch)
        assertNull(w.stores.epochs.epoch(w.db, w.ch, 1, 20_001))
        // n of §8.3: the past epochs still within retention, which sweepPast keeps
        assertEquals(2, w.stores.epochs.pastCount(w.db, w.ch, today))
        assertEquals(1, w.stores.epochs.pastCount(w.db, w.ch, 20_001))
        assertEquals(0, w.stores.epochs.pastCount(w.db, w.ch, 20_002))
        // the sweep names exactly what the reads hide
        assertEquals(listOf(0L), w.stores.epochs.expired(w.db, today, 10).map { it.epoch })
        assertEquals(listOf(0L, 1L), w.stores.epochs.expired(w.db, 20_001, 10).map { it.epoch })
        assertEquals(listOf(0L), w.stores.epochs.expired(w.db, 20_001, 1).map { it.epoch })
        assertTrue(w.tx { w.stores.epochs.delete(it, w.ch, 0) })
        assertEquals(emptyList<Long>(), w.stores.epochs.expired(w.db, today, 10).map { it.epoch })
    }

    @Test
    fun theOwnSequenceIsTakenAndIncrementedInTheCallersTransaction() = StoreWorld().use { w ->
        w.channel()
        w.stores.epochs.openEpoch(w, 0)
        assertEquals(0L, w.tx { w.stores.epochs.nextOwnSeq(it, w.ch, 0, today) })
        assertEquals(1L, w.tx { w.stores.epochs.nextOwnSeq(it, w.ch, 0, today) })
        assertEquals(2L, w.stores.epochs.epoch(w.db, w.ch, 0, today)!!.ownSeq)
        // two calls in one transaction take two numbers; a failed transaction takes none
        w.tx {
            assertEquals(2L, w.stores.epochs.nextOwnSeq(it, w.ch, 0, today))
            assertEquals(3L, w.stores.epochs.nextOwnSeq(it, w.ch, 0, today))
        }
        assertThrows(IllegalStateException::class.java) {
            w.tx {
                w.stores.epochs.nextOwnSeq(it, w.ch, 0, today)
                error("the encrypt call failed")
            }
        }
        assertEquals(4L, w.stores.epochs.epoch(w.db, w.ch, 0, today)!!.ownSeq)
        // a final epoch encrypts nothing; a missing one neither - and it keeps no count of the posts the member wrote
        // in it (T33: the count would show, until the epoch's keys go, how much each past epoch was written in)
        assertTrue(w.tx { w.stores.epochs.finalize(it, w.ch, 0, null, 20_000, 20_002) })
        assertEquals(0L, w.stores.epochs.epoch(w.db, w.ch, 0, today)!!.ownSeq)
        assertEquals(0L, w.db.queryLong("SELECT own_seq FROM ch_epoch WHERE epoch = 0"))
        assertEquals(ChannelStoreError.MISSING_ROW, assertThrows(ChannelStoreException::class.java) { w.tx { w.stores.epochs.nextOwnSeq(it, w.ch, 0, today) } }.error)
        assertEquals(ChannelStoreError.MISSING_ROW, assertThrows(ChannelStoreException::class.java) { w.tx { w.stores.epochs.nextOwnSeq(it, w.ch, 9, today) } }.error)
        // the u32 of ChannelOrder is spent at 2^32 - 1
        w.stores.epochs.openEpoch(w, 1)
        w.db.exec("UPDATE ch_epoch SET own_seq = 4294967295 WHERE epoch = 1")
        assertEquals(ChannelStoreError.LIMIT, assertThrows(ChannelStoreException::class.java) { w.tx { w.stores.epochs.nextOwnSeq(it, w.ch, 1, today) } }.error)
    }

    @Test
    fun aChannelHoldsTheCurrentEpochAndSixteenPastAndTheStoreSaysWhenItIsFull() = StoreWorld().use { w ->
        w.channel()
        for (e in 0L until 17L) w.stores.epochs.openEpoch(w, e)
        assertEquals(ChannelStoreError.LIMIT, assertThrows(ChannelStoreException::class.java) { w.stores.epochs.openEpoch(w, 17) }.error)
        assertTrue(w.tx { w.stores.epochs.delete(it, w.ch, 0) })
        w.stores.epochs.openEpoch(w, 17)
        assertEquals(17L, w.count("ch_epoch"))
        // a repeat of an epoch that exists is a different error from a full table
        assertTrue(w.tx { w.stores.epochs.delete(it, w.ch, 1) })
        assertEquals(ChannelStoreError.ROW_EXISTS, assertThrows(ChannelStoreException::class.java) { w.stores.epochs.openEpoch(w, 17) }.error)
    }

    @Test
    fun theEpochLogIsAppendOnlyAndTrimmedFromTheOldEnd() = StoreWorld().use { w ->
        w.channel()
        for (e in 0L until 10L) w.tx { w.stores.epochs.appendLog(it, w.ch, e, chBytes(32, 20 + e.toInt()), 19_990 + e) }
        assertEquals(10, w.stores.epochs.logCount(w.db, w.ch))
        val row = w.stores.epochs.logged(w.db, w.ch, 3)!!
        assertArrayEquals(chBytes(32, 23), row.winnerHash)
        assertEquals(19_993L, row.finalDay)
        assertNull(w.stores.epochs.logged(w.db, w.ch, 99))
        assertEquals(ChannelStoreError.ROW_EXISTS, assertThrows(ChannelStoreException::class.java) { w.tx { w.stores.epochs.appendLog(it, w.ch, 3, chBytes(32, 99), 20_000) } }.error)
        assertEquals(6, w.tx { w.stores.epochs.trimLog(it, w.ch, 4) })
        assertEquals(listOf(6L, 7L, 8L, 9L), (0L until 10L).filter { w.stores.epochs.logged(w.db, w.ch, it) != null })
        assertEquals(0, w.tx { w.stores.epochs.trimLog(it, w.ch, 4) })
        assertEquals(ChannelStoreError.BAD_VALUE, assertThrows(ChannelStoreException::class.java) { w.tx { w.stores.epochs.trimLog(it, w.ch, 1025) } }.error)
        assertRedacted(row, chBytes(32, 23), w.ch)
    }

    @Test
    fun forkSignalsAreRecordedOnceWithTheirDayAndTheOldestIsDroppedAtSixteen() = StoreWorld().use { w ->
        w.channel()
        w.stores.epochs.openEpoch(w, 4)
        w.stores.epochs.openEpoch(w, 5)
        assertTrue(w.tx { w.stores.epochs.addForkSignal(it, w.ch, 4, chBytes(32, 40), 19_990) })
        assertFalse("a repeat is no new signal", w.tx { w.stores.epochs.addForkSignal(it, w.ch, 4, chBytes(32, 40), 19_995) })
        assertEquals(19_990L, w.stores.epochs.forkSignals(w.db, w.ch, today).single().firstSeenDay)
        for (i in 1 until 16) assertTrue(w.tx { w.stores.epochs.addForkSignal(it, w.ch, 5, chBytes(32, 40 + i), 19_990L + i) })
        assertEquals(16L, w.count("ch_fork_signal"))
        // the 17th drops the oldest: (epoch 4, hash 40, day 19 990)
        assertTrue(w.tx { w.stores.epochs.addForkSignal(it, w.ch, 5, chBytes(32, 99), 20_000) })
        val signals = w.stores.epochs.forkSignals(w.db, w.ch, today)
        assertEquals(16, signals.size)
        assertFalse(signals.any { it.epoch == 4L })
        assertTrue(signals.any { it.hash.contentEquals(chBytes(32, 99)) })
        // the signals of an epoch go with its key
        assertEquals(16, w.tx { w.stores.epochs.deleteForkSignals(it, w.ch, 5) })
        assertEquals(0L, w.count("ch_fork_signal"))
        assertRedacted(signals.first(), signals.first().hash, w.ch)
    }

    /**
     * A fork signal goes with the key of the epoch it names (§6.3.5): it is read only while that epoch is within its
     * retention, whether or not `CH-SWEEP` has deleted it yet. The first version read the signals of a channel with
     * no term at all (the review of S3).
     */
    @Test
    fun aForkSignalIsOfferedOnlyWhileItsEpochIsWithinItsRetention() = StoreWorld().use { w ->
        w.channel()
        for (e in 0L..2L) w.stores.epochs.openEpoch(w, e)
        assertTrue(w.tx { w.stores.epochs.finalize(it, w.ch, 0, chBytes(32, 7), 19_990, today - 1) })   // past its bound
        assertTrue(w.tx { w.stores.epochs.finalize(it, w.ch, 1, chBytes(32, 8), 19_998, today) })       // on its last day
        for (e in 0L..2L) assertTrue(w.tx { w.stores.epochs.addForkSignal(it, w.ch, e, chBytes(32, 40 + e.toInt()), 19_995 + e) })
        assertEquals(listOf(1L, 2L), w.stores.epochs.forkSignals(w.db, w.ch, today).map { it.epoch })
        assertEquals("the sweep has not run: the row is still there", 3L, w.count("ch_fork_signal"))
        assertEquals(listOf(2L), w.stores.epochs.forkSignals(w.db, w.ch, today + 1).map { it.epoch })
        // the epoch's row gone (swept) while its signals are not yet: they are not offered either
        assertTrue(w.tx { w.stores.epochs.delete(it, w.ch, 2) })
        assertEquals(3L, w.count("ch_fork_signal"))
        assertEquals(emptyList<Long>(), w.stores.epochs.forkSignals(w.db, w.ch, today + 1).map { it.epoch })
    }

    @Test
    fun valuesTheSchemaWouldRefuseAreTypedErrors() = StoreWorld().use { w ->
        w.channel()
        fun refused(where: String, block: () -> Unit) = assertEquals(where, ChannelStoreError.BAD_VALUE, assertThrows(ChannelStoreException::class.java) { block() }.error)
        refused("k_env") { w.tx { w.stores.epochs.insert(it, w.ch, 0, chBytes(60, 5), chBytes(32, 6)) } }
        refused("r_ep") { w.tx { w.stores.epochs.insert(it, w.ch, 0, chBytes(68, 5), chBytes(31, 6)) } }
        refused("epoch") { w.tx { w.stores.epochs.insert(it, w.ch, -1, chBytes(68, 5), chBytes(32, 6)) } }
        refused("anchor") { w.tx { w.stores.epochs.insert(it, w.ch, 0, chBytes(68, 5), chBytes(32, 6), anchorMinute = 61) } }
        w.stores.epochs.openEpoch(w, 0)
        refused("winner") { w.tx { w.stores.epochs.finalize(it, w.ch, 0, chBytes(31, 7), 20_000, 20_002) } }
        refused("keep_until") { w.tx { w.stores.epochs.finalize(it, w.ch, 0, null, 20_000, -1) } }
        refused("fork hash") { w.tx { w.stores.epochs.addForkSignal(it, w.ch, 1, chBytes(31, 1), 20_000) } }
        assertEquals(EpochState.OPEN, w.stores.epochs.open(w.db, w.ch, today)!!.state)
    }
}
