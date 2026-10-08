package org.ghost.messaging.channel.store

import org.ghost.storage.chBytes
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `ch_candidate` through [CandidateStore] (Phase 10 design §6.4 CO-1 to CO-6, §6.3.5 CS-C8; slice S3): the commits
 * a member holds for its current epoch, the own commit with its wrapped Welcomes and box key, the bounds (8
 * foreign, one own, one per sender) as typed errors, and the erasure when the commit loses.
 */
class CandidateStoreTest {

    private fun CandidateStore.add(
        w: StoreWorld,
        i: Int,
        epoch: Long = 0,
        rank: Int = 255,
        own: Boolean = false,
        welcome: ByteArray? = null,
        box: ByteArray? = null,
        storeHour: Long? = null,
    ) = w.tx {
        insert(
            it, w.ch, epoch, chBytes(32, 100 + i), chBytes(32, 150 + i), rank, own, chBytes(300, i), 600L + 60 * i,
            storeHour = storeHour, welcomeEnv = welcome, boxEnv = box,
        )
    }

    @Test
    fun theCandidatesOfAnEpochAreReadByRankThenHashAndFindableBySenderAndHash() = StoreWorld().use { w ->
        w.channel()
        w.stores.candidates.add(w, 3, rank = 255)
        w.stores.candidates.add(w, 1, rank = 1)
        w.stores.candidates.add(w, 2, rank = 0)
        w.stores.candidates.add(w, 9, epoch = 1, rank = 0)
        assertEquals(
            listOf(chBytes(32, 102), chBytes(32, 101), chBytes(32, 103)).map { it.toList() },
            w.stores.candidates.candidates(w.db, w.ch, 0).map { it.hash.toList() },
        )
        assertEquals(1, w.stores.candidates.candidates(w.db, w.ch, 1).size)
        val row = w.stores.candidates.candidate(w.db, w.ch, 0, chBytes(32, 101))!!
        assertEquals(1, row.rank)
        assertFalse(row.own)
        assertFalse(row.verified)
        assertArrayEquals(chBytes(300, 1), row.bodyEnv)
        assertEquals(660L, row.firstSeenMinute)
        assertArrayEquals(chBytes(32, 151), row.sender)
        assertEquals(chBytes(32, 102).toList(), w.stores.candidates.candidateOf(w.db, w.ch, 0, chBytes(32, 152))!!.hash.toList())
        assertNull(w.stores.candidates.candidateOf(w.db, w.ch, 1, chBytes(32, 152)))
        assertNull(w.stores.candidates.own(w.db, w.ch, 0))
        assertEquals(3, w.stores.candidates.count(w.db, w.ch, 0))
        assertRedacted(row, chBytes(32, 101), chBytes(32, 151), chBytes(300, 1), w.ch)
    }

    @Test
    fun anOwnCommitCarriesItsWelcomesAndItsBoxKeyUntilItIsVerifiedWonOrCleared() = StoreWorld().use { w ->
        w.channel()
        val welcomes = chBytes(5_000, 7)
        val box = chBytes(60, 8)
        w.stores.candidates.add(w, 1, rank = 0, own = true, welcome = welcomes, box = box, storeHour = 7_200)
        var own = w.stores.candidates.own(w.db, w.ch, 0)!!
        assertTrue(own.own)
        assertFalse("not verified before a copy is seen", own.verified)
        assertArrayEquals(welcomes, own.welcomeEnv)
        assertArrayEquals(box, own.boxEnv)
        assertEquals(listOf(own.hash.toList()), w.stores.candidates.ownCommits(w.db, w.ch).map { it.hash.toList() })
        // the op's outcome is SENT or DEGRADED: a copy was verified (CO-4); once true it stays
        // true. The sighting is the minute the copy evidenced (D-4): it only moves earlier.
        assertTrue(w.tx { w.stores.candidates.markVerified(it, w.ch, 0, own.hash, 60) })
        assertFalse(w.tx { w.stores.candidates.markVerified(it, w.ch, 0, chBytes(32, 99), 60) })
        assertTrue(w.stores.candidates.own(w.db, w.ch, 0)!!.verified)
        assertEquals(60L, w.stores.candidates.own(w.db, w.ch, 0)!!.firstSeenMinute)
        // the sighting only moves earlier: a later evidence changes nothing, verified stays
        assertTrue(w.tx { w.stores.candidates.markVerified(it, w.ch, 0, own.hash, 120) })
        assertEquals(60L, w.stores.candidates.own(w.db, w.ch, 0)!!.firstSeenMinute)
        // another relay's copy was stored earlier: the anchor moves earlier, never later
        assertTrue(w.tx { w.stores.candidates.lowerStoreHour(it, w.ch, 0, own.hash, 3_600) })
        assertFalse(w.tx { w.stores.candidates.lowerStoreHour(it, w.ch, 0, own.hash, 7_200) })
        assertEquals(3_600L, w.stores.candidates.own(w.db, w.ch, 0)!!.storeHour)
        // the commit lost: the Welcomes and the box key are erased and the row goes on with its epoch
        assertTrue(w.tx { w.stores.candidates.eraseOwnSecrets(it, w.ch, 0, own.hash) })
        own = w.stores.candidates.own(w.db, w.ch, 0)!!
        assertNull(own.welcomeEnv)
        assertNull(own.boxEnv)
        assertTrue(w.tx { w.stores.candidates.delete(it, w.ch, 0, own.hash) })
        assertNull(w.stores.candidates.own(w.db, w.ch, 0))
        assertRedacted(own, own.hash, welcomes, box, w.ch)
    }

    @Test
    fun aForeignCandidateHasNoWelcomesNoBoxKeyAndNoVerifiedCopy() = StoreWorld().use { w ->
        w.channel()
        fun refused(block: () -> Unit) = assertEquals(ChannelStoreError.BAD_VALUE, assertThrows(ChannelStoreException::class.java) { block() }.error)
        refused { w.stores.candidates.add(w, 1, welcome = chBytes(100, 1)) }
        refused { w.stores.candidates.add(w, 1, box = chBytes(60, 1)) }
        refused {
            w.tx {
                w.stores.candidates.insert(it, w.ch, 0, chBytes(32, 101), chBytes(32, 151), 255, false, chBytes(300, 1), 600, verified = true)
            }
        }
        refused { w.stores.candidates.add(w, 1, rank = 256) }
        refused { w.stores.candidates.add(w, 1, box = chBytes(59, 1), own = true) }
        assertEquals(0L, w.count("ch_candidate"))
    }

    @Test
    fun theBoundsAreTypedErrorsBeforeTheTriggerAndMakeRoomWhenACandidateIsDeleted() = StoreWorld().use { w ->
        w.channel()
        fun refused(error: ChannelStoreError, block: () -> Unit) = assertEquals(error, assertThrows(ChannelStoreException::class.java) { block() }.error)
        w.stores.candidates.add(w, 0)
        // one candidate per sender: the same sender under another hash, the same hash under another sender
        refused(ChannelStoreError.ROW_EXISTS) {
            w.tx { w.stores.candidates.insert(it, w.ch, 0, chBytes(32, 177), chBytes(32, 150), 255, false, chBytes(300, 1), 600) }
        }
        refused(ChannelStoreError.ROW_EXISTS) {
            w.tx { w.stores.candidates.insert(it, w.ch, 0, chBytes(32, 100), chBytes(32, 177), 255, false, chBytes(300, 1), 600) }
        }
        for (i in 1 until 8) w.stores.candidates.add(w, i)
        refused(ChannelStoreError.LIMIT) { w.stores.candidates.add(w, 8) }
        w.stores.candidates.add(w, 20, own = true, rank = 0)
        refused(ChannelStoreError.LIMIT) { w.stores.candidates.add(w, 21, own = true, rank = 0) }
        // another epoch has its own room; deleting one makes room in this one; settling empties the epoch
        w.stores.candidates.add(w, 30, epoch = 1)
        assertTrue(w.tx { w.stores.candidates.delete(it, w.ch, 0, chBytes(32, 100)) })
        w.stores.candidates.add(w, 8)
        assertEquals(9, w.stores.candidates.count(w.db, w.ch, 0))
        assertEquals(9, w.tx { w.stores.candidates.deleteEpoch(it, w.ch, 0) })
        assertEquals(0, w.stores.candidates.count(w.db, w.ch, 0))
        assertEquals(1, w.stores.candidates.count(w.db, w.ch, 1))
    }
}
