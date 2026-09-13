package org.ghost.entitlement.engine

import org.ghost.entitlement.TestCrypto
import org.ghost.entitlement.WEEK0
import org.ghost.entitlement.World
import org.ghost.entitlement.api.EntitlementFlag
import org.ghost.entitlement.api.PayWith
import org.ghost.entitlement.store.KeyStore
import org.ghost.entitlement.store.StateStore
import org.ghost.network.EntitlementCrypto
import org.ghost.network.NetworkException
import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import org.ghost.sync.api.SyncDatabase
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * ES rule 5 on the device (design §3.1, §19.2, §19.20 point 2, §19.21 point 4): the built-in schedule
 * is remembered in `ent_key` and `ent_schedule_fact`; a later schedule may add, never change or drop;
 * a conflict raises the persistent `SCHEDULE_CONFLICT` and leaves the engine inert.
 */
class ScheduleAcceptanceTest {

    private fun accept(w: World) = w.tx { ScheduleAcceptance(KeyStore(), StateStore()).accept(it, w.crypto.scheduleSummary()) { ByteArray(32) { 9 } } }

    private fun facts(w: World, fact: String) = w.count("SELECT count(*) FROM ent_schedule_fact WHERE fact = ?1", listOf(fact))

    private fun alarms(w: World) = w.count("SELECT alarm_flags FROM ent_state WHERE id = 1")

    @Test
    fun theFirstScheduleIsRememberedWholeWithAFreshPayoutSalt(): Unit = World().use { w ->
        val s = w.crypto.scheduleSummary()
        assertEquals(s.keys.size.toLong(), w.count("SELECT count(*) FROM ent_key"))
        assertEquals(s.lastWeek - s.firstWeek + 1, facts(w, KeyStore.FACT_SLOTS))
        assertEquals(s.prices.size.toLong(), facts(w, KeyStore.FACT_PRICE))
        val st = checkNotNull(w.tx { StateStore().read(it) })
        assertEquals(1L, st.scheduleSeq)
        assertArrayEquals(s.digest(), st.scheduleDigest())
        assertEquals(32, st.payoutSalt().size)
        // The slot digest is the issuer's encoding: SHA-256 of the ascending slot bytes.
        var digest: ByteArray? = null
        w.sql.query("SELECT digest FROM ent_schedule_fact WHERE fact = 'slots' AND epoch = ?1", listOf(WEEK0)) { digest = it.blob(0) }
        assertArrayEquals(ScheduleAcceptance.slotDigest(listOf(2, 0, 1)), digest)
    }

    @Test
    fun theSameScheduleAgainChangesNothingAndALaterOneAppends(): Unit = World().use { w ->
        val keys = w.count("SELECT count(*) FROM ent_key")
        assertEquals(ScheduleAcceptance.Result.ACCEPTED, accept(w))
        assertEquals(keys, w.count("SELECT count(*) FROM ent_key"))
        w.crypto.seq = 2
        w.crypto.lastWeek += 10
        w.crypto.revoked = listOf(EntitlementCrypto.Revoked(EntitlementCrypto.KIND_ACCESS, WEEK0 + 5))
        assertEquals(ScheduleAcceptance.Result.ACCEPTED, accept(w))
        // Ten more access weeks and the invite and credit epochs they reach: the whole new key list.
        assertEquals(w.crypto.scheduleSummary().keys.size.toLong(), w.count("SELECT count(*) FROM ent_key"))
        assertTrue(w.count("SELECT count(*) FROM ent_key") >= keys + 10)
        assertEquals(2L, w.count("SELECT schedule_seq FROM ent_state"))
        var digest: ByteArray? = null
        w.sql.query("SELECT digest FROM ent_schedule_fact WHERE fact = 'revoked_access' AND epoch = ?1", listOf(WEEK0 + 5)) { digest = it.blob(0) }
        assertArrayEquals("a remembered revocation's digest is the revoked key's id", w.crypto.keyId(EntitlementCrypto.KIND_ACCESS, WEEK0 + 5), digest)
        assertEquals(0L, alarms(w))
    }

    private fun conflicts(change: (TestCrypto) -> Unit): Unit = World().use { w ->
        val keys = w.count("SELECT count(*) FROM ent_key")
        val facts = w.count("SELECT count(*) FROM ent_schedule_fact")
        change(w.crypto)
        assertEquals(ScheduleAcceptance.Result.CONFLICT, accept(w))
        assertEquals(StateStore.ALARM_SCHEDULE_CONFLICT.toLong(), alarms(w) and StateStore.ALARM_SCHEDULE_CONFLICT.toLong())
        assertEquals("nothing is remembered from a conflicting schedule", keys, w.count("SELECT count(*) FROM ent_key"))
        assertEquals(facts, w.count("SELECT count(*) FROM ent_schedule_fact"))
        assertEquals(1L, w.count("SELECT schedule_seq FROM ent_state"))
    }

    @Test
    fun aChangedKeyIdConflicts() = conflicts {
        it.seq = 2
        it.keyOverrides[EntitlementCrypto.KIND_ACCESS to WEEK0] = ByteArray(32) { 1 }
    }

    @Test
    fun aKeyIdReusedUnderAnotherEpochConflicts() = conflicts {
        it.seq = 2
        it.lastWeek += 1
        it.keyOverrides[EntitlementCrypto.KIND_ACCESS to it.lastWeek] = it.keyId(EntitlementCrypto.KIND_ACCESS, WEEK0)
    }

    @Test
    fun aChangedSlotSetOfACoveredWeekConflicts() = conflicts {
        it.seq = 2
        it.slots = it.slots.take(2)
    }

    @Test
    fun aChangedPriceConflicts() = conflicts {
        it.seq = 2
        it.priceOverrides[Grid.priceEpoch(WEEK0)] = TestCrypto.PRICE + 10
    }

    @Test
    fun aRollbackOrAnotherScheduleUnderTheSameSeqConflicts() {
        conflicts { it.lastWeek += 1 }
        World().use { w ->
            w.crypto.seq = 3
            assertEquals(ScheduleAcceptance.Result.ACCEPTED, accept(w))
            w.crypto.seq = 2
            assertEquals(ScheduleAcceptance.Result.CONFLICT, accept(w))
        }
    }

    @Test
    fun aRemembredRevocationThatDisappearsConflicts(): Unit = World().use { w ->
        w.crypto.seq = 2
        w.crypto.revoked = listOf(EntitlementCrypto.Revoked(EntitlementCrypto.KIND_CREDIT, Grid.creditEpoch(WEEK0)))
        assertEquals(ScheduleAcceptance.Result.ACCEPTED, accept(w))
        w.crypto.seq = 3
        w.crypto.revoked = emptyList()
        assertEquals(ScheduleAcceptance.Result.CONFLICT, accept(w))
        // A revocation of a key the device never saw fails closed too.
        w.crypto.revoked = listOf(
            EntitlementCrypto.Revoked(EntitlementCrypto.KIND_CREDIT, Grid.creditEpoch(WEEK0)),
            EntitlementCrypto.Revoked(EntitlementCrypto.KIND_INVITE, 5),
        )
        assertEquals(ScheduleAcceptance.Result.CONFLICT, accept(w))
    }

    @Test
    fun aRegtestScheduleIsRefusedWithoutWritesOrAlarm(): Unit = JdbcSqlExecutor().use { sql ->
        MigrationRunner(sql).migrate()
        val crypto = TestCrypto().also { it.network = 3 }
        val result = SyncDatabase(sql).transaction { ScheduleAcceptance(KeyStore(), StateStore()).accept(it, crypto.scheduleSummary()) { ByteArray(32) } }
        assertEquals(ScheduleAcceptance.Result.REFUSED, result)
        var keys = -1L
        sql.query("SELECT count(*) FROM ent_key") { keys = it.long(0) }
        assertEquals(0L, keys)
        var states = -1L
        sql.query("SELECT count(*) FROM ent_state") { states = it.long(0) }
        assertEquals(0L, states)
    }

    @Test
    fun aConflictingBuiltInScheduleLeavesTheEngineInert(): Unit = World().use { w ->
        w.crypto.seq = 2
        w.crypto.priceOverrides[Grid.priceEpoch(WEEK0)] = 1
        val engine = EntitlementEngine(w.deps) { w.stores }
        assertNull(engine.startPurchase(PayWith.XMR))
        assertTrue(EntitlementFlag.SCHEDULE_CONFLICT in engine.status().flags)
        engine.onQuietRun(org.ghost.entitlement.FakeSession(org.ghost.sync.api.SessionKind.QUIET, issuer = w.issuer))
        assertTrue(w.issuer.calls.isEmpty())
        assertFalse(checkNotNull(engine.context()).accepted)
    }

    @Test
    fun aScheduleThatCannotBeReadLeavesTheEngineWithoutContext(): Unit = World().use { w ->
        w.crypto.failSummary = "internal"
        val engine = EntitlementEngine(w.deps) { w.stores }
        assertNull(engine.context())
        assertNull(engine.startPurchase(PayWith.XMR))
        w.crypto.failSummary = null
        assertTrue(checkNotNull(engine.context()).accepted)
        assertEquals(NetworkException::class.java, runCatchingNetwork { w.crypto.also { it.failSummary = "x" }.scheduleSummary() })
    }

    private fun runCatchingNetwork(block: () -> Unit): Class<*>? = try {
        block()
        null
    } catch (e: NetworkException) {
        e.javaClass
    }
}
