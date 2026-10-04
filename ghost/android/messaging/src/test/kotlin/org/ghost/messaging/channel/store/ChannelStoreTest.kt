package org.ghost.messaging.channel.store

import org.ghost.storage.chBytes
import org.ghost.storage.queryLong
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `ch_channel`, `ch_liveness` and `ch_schedule` through [ChannelStore] (Phase 10 design §9; slice S3): the rows
 * `CH-CREATE`, `CH-ACCEPT`, `CH-JOIN`, `CH-SETTLE`, `CH-LEAVE` and the sweep write, with the typed errors of
 * [ChannelStoreException] and no value in a `toString`.
 */
class ChannelStoreTest {

    private fun new(
        id: ByteArray,
        state: ChannelState = ChannelState.ACTIVE,
        generation: Long = 0,
        name: ByteArray? = null,
    ) = ChannelStore.NewChannel(
        channelId = id, state = state, generation = generation, epoch = 0, joinedEpoch = 0, sizeClass = 0,
        timerCode = 4, myPseudonym = chBytes(32, 0x50), nameEnv = name,
    )

    @Test
    fun aCreatedChannelIsActiveWithItsFlagsClearAndReadsBack() = StoreWorld().use { w ->
        val name = chBytes(40, 9)
        w.tx { w.stores.channels.insert(it, new(w.ch, name = name)) }
        val row = w.stores.channels.channel(w.db, w.ch)!!
        assertEquals(ChannelState.ACTIVE, row.state)
        assertFalse(row.splitSuspected || row.partitionSuspected || row.staleSuspected || row.pwRequired)
        assertEquals(0L, row.generation)
        assertEquals(4, row.timerCode)
        assertArrayEquals(name, row.nameEnv)
        assertNull(row.lastCommitterCommitDay)
        assertArrayEquals(chBytes(32, 0x50), row.myPseudonym)
        assertEquals(3L, w.db.queryLong("SELECT suite FROM ch_channel"))
        assertEquals(listOf(w.ch.toList()), w.stores.channels.channels(w.db).map { it.channelId.toList() })
        assertNull(w.stores.channels.channel(w.db, w.ch2))
    }

    @Test
    fun aChannelThatExistsIsAnErrorAndAJoiningOneIsInsertedAsJoining(): Unit = StoreWorld().use { w ->
        w.tx { w.stores.channels.insert(it, new(w.ch, ChannelState.JOINING)) }
        assertEquals(ChannelState.JOINING, w.stores.channels.channel(w.db, w.ch)!!.state)
        val e = assertThrows(ChannelStoreException::class.java) { w.tx { w.stores.channels.insert(it, new(w.ch)) } }
        assertEquals(ChannelStoreError.ROW_EXISTS, e.error)
        // The refusal undid nothing that was there, and said nothing about the row.
        assertEquals(ChannelState.JOINING, w.stores.channels.channel(w.db, w.ch)!!.state)
        assertEquals("ROW_EXISTS at ch_channel", e.message)
        // A channel starts active or joining and nothing else.
        assertThrows(IllegalArgumentException::class.java) { w.tx { w.stores.channels.insert(it, new(w.ch2, ChannelState.REMOVED)) } }
    }

    @Test
    fun valuesTheSchemaWouldRefuseAreTypedErrorsBeforeTheStatementRuns() = StoreWorld().use { w ->
        fun refused(where: String, block: () -> Unit) {
            val e = assertThrows(where, ChannelStoreException::class.java) { block() }
            assertEquals(where, ChannelStoreError.BAD_VALUE, e.error)
            assertTrue(e.message!!, e.message!!.contains(where))
        }
        refused("ch_channel.channel_id") { w.tx { w.stores.channels.insert(it, new(chBytes(31, 1))) } }
        refused("ch_channel.generation") { w.tx { w.stores.channels.insert(it, new(w.ch, generation = 4_294_967_296L)) } }
        refused("ch_channel.name_env") { w.tx { w.stores.channels.insert(it, new(w.ch, name = chBytes(77, 1))) } }
        refused("ch_channel.timer_code") {
            w.tx {
                w.stores.channels.insert(
                    it, ChannelStore.NewChannel(w.ch, ChannelState.ACTIVE, 0, 0, 0, 0, 6, chBytes(32, 0x50), null),
                )
            }
        }
        refused("ch_channel.size_class") {
            w.tx {
                w.stores.channels.insert(
                    it, ChannelStore.NewChannel(w.ch, ChannelState.ACTIVE, 0, 0, 0, 2, 4, chBytes(32, 0x50), null),
                )
            }
        }
        assertEquals("nothing was written", 0L, w.count("ch_channel"))
        w.channel()
        refused("ch_channel.last_committer_commit_day") { w.tx { w.stores.channels.setLastCommitterCommitDay(it, w.ch, -1) } }
        refused("ch_channel.epoch") { w.tx { w.stores.channels.setPosition(it, w.ch, 1, -1) } }
        refused("ch_channel.timer_code") { w.tx { w.stores.channels.setPolicy(it, w.ch, 9, 0, false, null) } }
    }

    @Test
    fun theStateMachineIsTheOneOfSectionSixElevenAndAnIllegalEdgeIsATypedErrorNotATriggerAbort() = StoreWorld().use { w ->
        w.channel(state = ChannelState.JOINING)
        // joining -> active, guarded by the state it expects
        assertFalse(w.tx { w.stores.channels.transition(it, w.ch, ChannelState.ACTIVE, ChannelState.LEAVING) })
        assertTrue(w.tx { w.stores.channels.transition(it, w.ch, ChannelState.JOINING, ChannelState.ACTIVE) })
        assertEquals(ChannelState.ACTIVE, w.stores.channels.channel(w.db, w.ch)!!.state)
        // a second change from the old state matches nothing
        assertFalse(w.tx { w.stores.channels.transition(it, w.ch, ChannelState.JOINING, ChannelState.ACTIVE) })
        // an edge the machine lacks never reaches SQL
        val e = assertThrows(ChannelStoreException::class.java) {
            w.tx { w.stores.channels.transition(it, w.ch, ChannelState.ACTIVE, ChannelState.LEFT) }
        }
        assertEquals(ChannelStoreError.ILLEGAL_TRANSITION, e.error)
        assertEquals(ChannelState.ACTIVE, w.stores.channels.channel(w.db, w.ch)!!.state)
        assertTrue(w.tx { w.stores.channels.transition(it, w.ch, ChannelState.ACTIVE, ChannelState.LEAVING) })
        assertTrue(w.tx { w.stores.channels.transition(it, w.ch, ChannelState.LEAVING, ChannelState.LEFT) })
        // a new invitation re-enters joining (§6.2.2)
        assertTrue(w.tx { w.stores.channels.transition(it, w.ch, ChannelState.LEFT, ChannelState.JOINING) })
        assertEquals(listOf(w.ch.toList()), w.stores.channels.channelsIn(w.db, ChannelState.JOINING).map { it.channelId.toList() })
        assertEquals(emptyList<Any>(), w.stores.channels.channelsIn(w.db, ChannelState.ACTIVE))
    }

    @Test
    fun theWritesOfASettleAJoinAndTheUiMoveOnlyTheirColumns() = StoreWorld().use { w ->
        w.channel()
        val name = chBytes(33, 4)
        assertTrue(w.tx { w.stores.channels.setFlags(it, w.ch, split = true, partition = false, stale = true) })
        var row = w.stores.channels.channel(w.db, w.ch)!!
        assertTrue(row.splitSuspected && !row.partitionSuspected && row.staleSuspected)
        assertTrue(w.tx { w.stores.channels.setPolicy(it, w.ch, 2, 1, true, name) })
        assertTrue(w.tx { w.stores.channels.setPosition(it, w.ch, 3, 9) })
        assertTrue(w.tx { w.stores.channels.setLastCommitterCommitDay(it, w.ch, 20_001) })
        row = w.stores.channels.channel(w.db, w.ch)!!
        assertEquals(2, row.timerCode)
        assertEquals(1, row.sizeClass)
        assertTrue(row.pwRequired)
        assertEquals(3L, row.generation)
        assertEquals(9L, row.epoch)
        assertEquals(20_001L, row.lastCommitterCommitDay)
        assertTrue(row.splitSuspected)
        assertTrue(w.tx { w.stores.channels.setJoined(it, w.ch, 5, 4) })
        row = w.stores.channels.channel(w.db, w.ch)!!
        assertEquals(5L, row.joinedEpoch)
        assertEquals(5L, row.epoch)
        assertEquals(4L, row.generation)
        assertTrue(w.tx { w.stores.channels.setLastCommitterCommitDay(it, w.ch, null) })
        assertNull(w.stores.channels.channel(w.db, w.ch)!!.lastCommitterCommitDay)
        // a channel that is not there: every write says so by returning false
        assertFalse(w.tx { w.stores.channels.setFlags(it, w.ch2, false, false, false) })
        assertFalse(w.tx { w.stores.channels.setPosition(it, w.ch2, 1, 1) })
    }

    @Test
    fun deletingAChannelWipesEverythingItOwns() = StoreWorld().use { w ->
        w.fixture.put("ch_epoch")
        w.fixture.put("ch_post")
        w.fixture.put("mls_kv")
        w.fixture.put("ch_liveness")
        assertTrue(w.tx { w.stores.channels.delete(it, w.ch) })
        for (table in listOf("ch_channel", "ch_epoch", "ch_post", "mls_kv", "ch_liveness")) assertEquals(table, 0L, w.count(table))
        assertFalse(w.tx { w.stores.channels.delete(it, w.ch) })
    }

    @Test
    fun theLivenessWindowOfCoElevenIsWrittenWholeAndClosesAtProgress() = StoreWorld().use { w ->
        w.channel()
        val empty = chBytes(28, 1)
        assertNull(w.stores.channels.liveness(w.db, w.ch))
        w.tx { w.stores.channels.putLiveness(it, w.ch, 1, 0b001, 1, empty, 600) }
        var row = w.stores.channels.liveness(w.db, w.ch)!!
        assertEquals(1, row.unopenableCount)
        assertEquals(1, row.unopenableOperators)
        assertEquals(600L, row.unopenableFirstMinute)
        val progress = chBytes(93, 2)
        w.tx { w.stores.channels.putLiveness(it, w.ch, 3, 0b101, 2, progress, 600) }
        row = w.stores.channels.liveness(w.db, w.ch)!!
        assertEquals(3, row.unopenableCount)
        assertEquals(0b101, row.unopenableOperators)
        assertEquals(2, row.sessions)
        assertArrayEquals(progress, row.progressEnv)
        assertEquals(1L, w.count("ch_liveness"))
        // progress: nothing stays of the window
        w.tx { w.stores.channels.resetLiveness(it, w.ch, empty) }
        row = w.stores.channels.liveness(w.db, w.ch)!!
        assertEquals(0, row.unopenableCount)
        assertEquals(0, row.sessions)
        assertNull(row.unopenableFirstMinute)
        assertArrayEquals(empty, row.progressEnv)
        // the schema ties the window's start to the count; the store says so before the statement runs
        val tied = assertThrows(ChannelStoreException::class.java) { w.tx { w.stores.channels.putLiveness(it, w.ch, 0, 0, 0, empty, 120) } }
        assertEquals(ChannelStoreError.BAD_VALUE, tied.error)
        val untied = assertThrows(ChannelStoreException::class.java) { w.tx { w.stores.channels.putLiveness(it, w.ch, 2, 0, 0, empty, null) } }
        assertEquals(ChannelStoreError.BAD_VALUE, untied.error)
    }

    @Test
    fun theScheduleIsWrittenByUpdateThenInsertAndTheDueChannelsAreReadByTheMinute() = StoreWorld().use { w ->
        w.channel()
        w.channel(w.ch2)
        w.tx { w.stores.channels.putSchedule(it, w.ch, 20_010, null, 3_600) }
        w.tx { w.stores.channels.putSchedule(it, w.ch2, 20_010, 20_000, 7_200) }
        var s = w.stores.channels.schedule(w.db, w.ch)!!
        assertEquals(20_010L, s.nextSelfupdateDay)
        assertNull(s.lastOwnCommitDay)
        assertEquals(3_600L, s.nextPassMinute)
        w.tx { w.stores.channels.putSchedule(it, w.ch, 20_020, 20_005, null) }
        s = w.stores.channels.schedule(w.db, w.ch)!!
        assertEquals(20_020L, s.nextSelfupdateDay)
        assertEquals(20_005L, s.lastOwnCommitDay)
        assertNull(s.nextPassMinute)
        assertEquals(2L, w.count("ch_schedule"))
        // a pass is due when its minute has come; a schedule with no pass is never due
        assertEquals(emptyList<Any>(), w.stores.channels.duePasses(w.db, 7_199, 10))
        assertEquals(listOf(w.ch2.toList()), w.stores.channels.duePasses(w.db, 7_200, 10).map { it.toList() })
        assertEquals(1, w.stores.channels.duePasses(w.db, 1_000_000, 1).size)
        val offGrid = assertThrows(ChannelStoreException::class.java) { w.tx { w.stores.channels.putSchedule(it, w.ch, 1, null, 61) } }
        assertEquals(ChannelStoreError.BAD_VALUE, offGrid.error)
    }

    @Test
    fun noRowShowsAKeyAPseudonymOrANameInItsToString() = StoreWorld().use { w ->
        val pseudonym = chBytes(32, 0x50)
        val name = chBytes(40, 0x77)
        w.tx { w.stores.channels.insert(it, new(w.ch, name = name)) }
        w.tx { w.stores.channels.putLiveness(it, w.ch, 1, 1, 1, chBytes(28, 0x66), 600) }
        w.tx { w.stores.channels.putSchedule(it, w.ch, 20_000, null, null) }
        assertRedacted(w.stores.channels.channel(w.db, w.ch)!!, pseudonym, name, w.ch)
        assertRedacted(w.stores.channels.liveness(w.db, w.ch)!!, chBytes(28, 0x66), w.ch)
        assertRedacted(w.stores.channels.schedule(w.db, w.ch)!!, w.ch)
        assertRedacted(new(w.ch, name = name), pseudonym, name, w.ch)
        assertNotNull(w.stores.toString())
    }
}
