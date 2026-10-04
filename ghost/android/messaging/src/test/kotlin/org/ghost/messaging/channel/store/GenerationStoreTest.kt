package org.ghost.messaging.channel.store

import org.ghost.storage.chBytes
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `ch_generation` through [GenerationStore] (Phase 10 design §6.5, §19.8; slice S3): the creation of generation
 * 0, the pending generation a rotating commit derives, `CH-SWITCH` (promote, demote, delete) in the order the
 * schema's triggers require, the route of a namespace to its channel, and the drain filter on every read.
 */
class GenerationStoreTest {

    private val today = 20_000L

    private fun ns(i: Int) = chBytes(32, 0x60 + i)

    private fun GenerationStore.add(
        w: StoreWorld,
        generation: Long,
        state: GenerationState,
        switchHour: Long? = null,
        drainUntilDay: Long? = null,
        channel: ByteArray = w.ch,
    ) = w.tx {
        insert(
            it, channel, generation, ns(generation.toInt()), state, chBytes(60, 2), chBytes(60, 3), chBytes(32, 4),
            switchHour, drainUntilDay,
        )
    }

    @Test
    fun generationZeroIsCurrentAndReadsBackWithItsSecretsAsEnvelopes() = StoreWorld().use { w ->
        w.channel()
        w.stores.generations.add(w, 0, GenerationState.CURRENT)
        val row = w.stores.generations.generation(w.db, w.ch, 0, today)!!
        assertEquals(GenerationState.CURRENT, row.state)
        assertArrayEquals(ns(0), row.namespaceId)
        assertArrayEquals(chBytes(60, 2), row.gEnv)
        assertArrayEquals(chBytes(60, 3), row.jkEnv)
        assertArrayEquals(chBytes(32, 4), row.rJoin)
        assertNull(row.switchHour)
        assertNull(row.drainUntilDay)
        assertEquals(0L, w.stores.generations.current(w.db, w.ch, today)!!.generation)
        assertNull(w.stores.generations.generation(w.db, w.ch, 1, today))
        assertRedacted(row, chBytes(60, 2), chBytes(60, 3), chBytes(32, 4), ns(0), w.ch)
    }

    @Test
    fun theSwitchRunsInTheOrderTheSchemaRequiresAndKeepsTheStateMachine() = StoreWorld().use { w ->
        w.channel()
        w.stores.generations.add(w, 0, GenerationState.CURRENT)
        // a rotating commit derives g1 and stores it pending, with the hour of the switch (§6.5)
        w.stores.generations.add(w, 1, GenerationState.PENDING_SWITCH, switchHour = 7_200)
        assertEquals(emptyList<Long>(), w.stores.generations.duePending(w.db, w.ch, 3_600, today).map { it.generation })
        assertEquals(listOf(1L), w.stores.generations.duePending(w.db, w.ch, 7_200, today).map { it.generation })
        // CH-SWITCH: the current one drains first, then the pending one is promoted
        assertTrue(w.tx { w.stores.generations.demote(it, w.ch, 0, 20_014) })
        assertTrue(w.tx { w.stores.generations.promote(it, w.ch, 1) })
        val live = w.stores.generations.live(w.db, w.ch, today)
        assertEquals(listOf(0L to GenerationState.DRAINING, 1L to GenerationState.CURRENT), live.map { it.generation to it.state })
        assertEquals(20_014L, live[0].drainUntilDay)
        assertNull("the switch hour is spent", live[1].switchHour)
        // a state that is not the expected one matches nothing
        assertFalse(w.tx { w.stores.generations.promote(it, w.ch, 1) })
        assertFalse(w.tx { w.stores.generations.demote(it, w.ch, 0, 20_020) })
    }

    @Test
    fun anOlderDrainIsEndedBeforeTheNextSwitchOrTheSchemaRefuses() = StoreWorld().use { w ->
        w.channel()
        w.stores.generations.add(w, 0, GenerationState.DRAINING, drainUntilDay = 20_014)
        w.stores.generations.add(w, 1, GenerationState.CURRENT)
        w.stores.generations.add(w, 2, GenerationState.PENDING_SWITCH, switchHour = 7_200)
        // demoting g1 while g0 still drains is the schema's "at most one draining"
        assertThrows(java.sql.SQLException::class.java) { w.tx { w.stores.generations.demote(it, w.ch, 1, 20_030) } }
        // §6.5: "a switch while a generation is already draining ends the older drain at once"
        assertTrue(w.tx { w.stores.generations.delete(it, w.ch, 0) })
        assertTrue(w.tx { w.stores.generations.demote(it, w.ch, 1, 20_030) })
        assertTrue(w.tx { w.stores.generations.promote(it, w.ch, 2) })
        assertEquals(listOf(1L, 2L), w.stores.generations.live(w.db, w.ch, today).map { it.generation })
    }

    @Test
    fun aNamespaceRoutesToItsChannelAndGenerationWhileItIsListenedTo() = StoreWorld().use { w ->
        w.channel()
        w.channel(w.ch2)
        w.stores.generations.add(w, 0, GenerationState.DRAINING, drainUntilDay = 20_000)
        w.stores.generations.add(w, 1, GenerationState.CURRENT)
        w.stores.generations.add(w, 5, GenerationState.CURRENT, channel = w.ch2)
        val route = w.stores.generations.route(w.db, ns(0), today)!!
        assertEquals(0L, route.generation)
        assertEquals(GenerationState.DRAINING, route.state)
        assertArrayEquals(w.ch, route.channelId)
        assertArrayEquals(w.ch2, w.stores.generations.route(w.db, ns(5), today)!!.channelId)
        assertNull(w.stores.generations.route(w.db, ns(9), today))
        // the drain ends: the namespace is not routed from the next day on, swept or not
        assertNotNull(w.stores.generations.route(w.db, ns(0), 20_000))
        assertNull(w.stores.generations.route(w.db, ns(0), 20_001))
        assertNull(w.stores.generations.generation(w.db, w.ch, 0, 20_001))
        assertEquals(listOf(1L), w.stores.generations.live(w.db, w.ch, 20_001).map { it.generation })
        // the sweep finds exactly what the reads hide
        assertEquals(listOf(0L), w.stores.generations.drained(w.db, 20_001, 10).map { it.generation })
        assertEquals(emptyList<Long>(), w.stores.generations.drained(w.db, 20_000, 10).map { it.generation })
        assertTrue(w.tx { w.stores.generations.delete(it, w.ch, 0) })
        assertEquals(emptyList<Long>(), w.stores.generations.drained(w.db, 20_001, 10).map { it.generation })
    }

    @Test
    fun aJoinersPendingGenerationHasNoSwitchHourAndIsDueAtOnce() = StoreWorld().use { w ->
        w.channel()
        w.stores.generations.add(w, 0, GenerationState.CURRENT)
        w.stores.generations.add(w, 1, GenerationState.PENDING_SWITCH, switchHour = null)
        assertEquals(listOf(1L), w.stores.generations.duePending(w.db, w.ch, 0, today).map { it.generation })
        assertNull(w.stores.generations.generation(w.db, w.ch, 1, today)!!.switchHour)
    }

    @Test
    fun anInsertTheSchemaWouldRefuseIsATypedErrorFirst() = StoreWorld().use { w ->
        w.channel()
        w.stores.generations.add(w, 0, GenerationState.CURRENT)
        fun refused(error: ChannelStoreError, block: () -> Unit) = assertEquals(error, assertThrows(ChannelStoreException::class.java) { block() }.error)
        // the same generation, the same namespace under another generation
        refused(ChannelStoreError.ROW_EXISTS) { w.stores.generations.add(w, 0, GenerationState.PENDING_SWITCH, switchHour = 3_600) }
        refused(ChannelStoreError.ROW_EXISTS) {
            w.tx {
                w.stores.generations.insert(it, w.ch, 7, ns(0), GenerationState.PENDING_SWITCH, chBytes(60, 2), chBytes(60, 3), chBytes(32, 4), 3_600)
            }
        }
        // a switch hour on a row that is not pending, a drain day on one that is not draining, and the reverse
        refused(ChannelStoreError.BAD_VALUE) { w.stores.generations.add(w, 8, GenerationState.CURRENT, switchHour = 3_600) }
        refused(ChannelStoreError.BAD_VALUE) { w.stores.generations.add(w, 8, GenerationState.DRAINING) }
        refused(ChannelStoreError.BAD_VALUE) { w.stores.generations.add(w, 8, GenerationState.CURRENT, drainUntilDay = 20_014) }
        refused(ChannelStoreError.BAD_VALUE) { w.stores.generations.add(w, 8, GenerationState.PENDING_SWITCH, switchHour = 3_601) }
        refused(ChannelStoreError.BAD_VALUE) { w.stores.generations.add(w, 4_294_967_296L, GenerationState.CURRENT) }
        assertEquals(1L, w.count("ch_generation"))
    }
}
