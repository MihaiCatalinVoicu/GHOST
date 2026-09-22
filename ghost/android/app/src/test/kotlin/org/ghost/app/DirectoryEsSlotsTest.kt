package org.ghost.app

import org.ghost.network.EntitlementCrypto
import org.ghost.sync.api.RelayEntry
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The DM slot table (Phase 9 design §5.2, §13.1 `EsSlots`; slice S12): the accepted schedule's
 * valid slots resolved against the **active** relay directory, by the slot→relay rule of
 * `RedeemPlanner.slotsFor`, from outside a transaction and from inside one.
 */
class DirectoryEsSlotsTest {

    private val db = TestDatabase()

    @After
    fun tearDown() = db.close()

    private fun slot(n: Int, onion: Int, from: Long = 0, until: Long = 0, port: Int = 443) =
        EntitlementCrypto.Slot(n, from, until, Onions.onion(onion, port))

    private fun directory(vararg entries: Pair<Int, Int>, port: Int = 443) = db.database.transaction { tx ->
        db.stores.relayDirectory.upsert(
            tx,
            entries.map { (onion, operator) -> RelayEntry(Onions.onion(onion, port), Onions.operatorId(operator), RelayEntry.Source.CONFIG) },
        )
    }

    @Test
    fun eachValidSlotIsTheActiveRelayListedUnderItsOnion() {
        val ids = directory(0 to 0, 1 to 1, 2 to 0)
        val table = DirectoryEsSlots(db.database) { listOf(slot(2, 2), slot(0, 0), slot(1, 1)) }.slotsInWeek(100)
        assertEquals(listOf(0, 1, 2), table.map { it.slot })
        assertEquals(listOf(0, 1, 2).map { ids.getValue(Onions.onion(it)) }, table.map { it.relay })
        assertArrayEquals(Onions.operatorId(1), table[1].operatorId)
    }

    @Test
    fun aSlotOutsideItsWeeksOrWithNoRelayIsLeftOut() {
        directory(0 to 0, 1 to 1)
        val table = DirectoryEsSlots(db.database) {
            listOf(slot(0, 0), slot(1, 1, from = 101), slot(2, 1, until = 100), slot(3, 9))
        }.slotsInWeek(100)
        assertEquals(listOf(0), table.map { it.slot })
    }

    @Test
    fun aRetiredRelayServesNoSlot() {
        val ids = directory(0 to 0, 1 to 1)
        db.database.transaction { tx -> db.stores.relayDirectory.retire(tx, ids.getValue(Onions.onion(1))) }
        val table = DirectoryEsSlots(db.database) { listOf(slot(0, 0), slot(1, 1)) }.slotsInWeek(100)
        assertEquals(listOf(0), table.map { it.slot })
    }

    @Test
    fun anUnlistedPortFallsBackToTheServiceKeyWhenItIsUnique() {
        directory(4 to 0, port = 8443)
        val table = DirectoryEsSlots(db.database) { listOf(slot(0, 4, port = 443)) }.slotsInWeek(100)
        assertEquals(listOf(0), table.map { it.slot })
    }

    @Test
    fun aServiceKeyWithSeveralEntriesAndNoExactMatchServesNothing() {
        directory(4 to 0, port = 8443)
        directory(4 to 0, port = 9443)
        val table = DirectoryEsSlots(db.database) { listOf(slot(0, 4, port = 443)) }.slotsInWeek(100)
        assertTrue(table.isEmpty())
    }

    @Test
    fun anUnacceptedScheduleIsAnEmptyTable() {
        directory(0 to 0)
        assertTrue(DirectoryEsSlots(db.database) { null }.slotsInWeek(100).isEmpty())
    }

    @Test
    fun itReadsFromInsideTheCallersTransaction() {
        directory(0 to 0, 1 to 1)
        val slots = DirectoryEsSlots(db.database) { listOf(slot(0, 0), slot(1, 1)) }
        // `SyncDatabase.transaction` is not reentrant; the DM steps resolve relay sets inside theirs.
        val inside = db.database.transaction { slots.slotsInWeek(100) }
        assertEquals(listOf(0, 1), inside.map { it.slot })
    }
}
