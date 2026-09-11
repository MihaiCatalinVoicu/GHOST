package org.ghost.sync.engine

import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.OperationId
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.RelayId
import org.ghost.sync.api.SendDelay
import org.ghost.sync.api.StatusFlag
import org.ghost.sync.api.TtlBucket
import org.ghost.sync.engine.EngineWorld.Companion.HOUR
import org.ghost.sync.port.PairKey
import org.ghost.sync.store.DueStore
import org.ghost.sync.store.TestBytes
import org.ghost.sync.store.Time
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Every path of one store attempt (design §3.3, §3.6, §3.8), run through the real [StoreStep] with a
 * live session's work context against the in-test relay: receipt, ambiguous (applied or not),
 * definite, quota → check, unauthorized with and without the generation race, rejected, local bugs,
 * hostile answers and a transport stop.
 */
class StoreStepTest {

    private class Fixture(val w: EngineWorld, val session: Session, val ns: NamespaceId, val relays: List<RelayId>) {
        val ctx: WorkContext get() = session.workContext
        val steps: Steps get() = w.engine.steps

        fun due(op: OperationId, relay: RelayId): DueStore? =
            w.tx { w.stores.outboxStore.dueStores(it, w.clock.epochSeconds(), 32, relay, ns) }.firstOrNull { it.operationId == op }

        fun attempt(op: OperationId, relay: RelayId): StoreResult = steps.store.attempt(ctx, checkNotNull(due(op, relay)) { "not due" })

        /** Moves the clock past any backoff (at most one hour). */
        fun later() = w.clock.advance(HOUR + 60_000)
    }

    /**
     * A session that is online with no pass or event running: HIGH mode (passes store nothing), a
     * write-only namespace without send delay, write tokens on three relays of three operators.
     */
    private fun fixture(w: EngineWorld): Fixture {
        w.mode = PrivacyMode.HIGH
        val relays = w.relays(1, 2, 3)
        val ns = w.namespace(1, relays, listen = false, sendDelay = SendDelay.OFF)
        relays.forEach { w.capability(it, ns) }
        val (session, driver) = w.session()
        driver.runUntil(0)
        check(session.online)
        return Fixture(w, session, ns, relays)
    }

    private fun EngineWorld.stores() = net.callsOf(TestRelays.Kind.STORE)

    private fun EngineWorld.checks() = net.callsOf(TestRelays.Kind.CHECK)

    private fun EngineWorld.capState(relay: RelayId): String? = string("SELECT state FROM relay_capability WHERE relay_id = ? AND kind = 'write'", relay)

    @Test
    fun aReceiptAcknowledgesTheStoreWithItsLeaseHour(): Unit = EngineWorld().use { w ->
        val f = fixture(w)
        val op = w.enqueue(1, f.ns)
        assertEquals(StoreResult.ACKED, f.attempt(op, f.relays[0]))
        assertEquals("acked", w.state(op, f.relays[0]))
        assertEquals(Time.floorHour(w.clock.epochSeconds()), w.copyHour(op, f.relays[0]))
        assertTrue(w.net.holds(w.address(f.relays[0]), f.ns, w.hashOf(1)))
        // The frozen bytes were sent, and nothing sent to the relay carries the operation id (T1).
        val call = w.stores().single()
        assertArrayEquals(TestBytes.ciphertext(1), call.ciphertext)
        val opBytes = op.toByteArray()
        for (c in w.net.calls) {
            for (bytes in listOf(c.capability, c.cursor, c.ciphertext ?: ByteArray(0)) + c.hashes.map { it.toByteArray() }) {
                assertFalse(bytes.toList().windowed(opBytes.size).any { it == opBytes.toList() })
            }
        }
    }

    @Test
    fun anAppliedButAmbiguousStoreIsCheckedFirstAndVerifiedWithoutASecondUpload(): Unit = EngineWorld().use { w ->
        val f = fixture(w)
        val op = w.enqueue(1, f.ns)
        w.net.failAfter = { if (it.kind == TestRelays.Kind.STORE) "timeout" else null }
        assertEquals(StoreResult.AMBIGUOUS, f.attempt(op, f.relays[0]))
        assertEquals("pending", w.state(op, f.relays[0]))
        assertNotNull("a possible copy is recorded", w.copyHour(op, f.relays[0]))
        assertNull("backing off", f.due(op, f.relays[0]))
        w.net.failAfter = { null }
        f.later()
        assertEquals(StoreResult.VERIFIED, f.attempt(op, f.relays[0]))
        assertEquals("verified", w.state(op, f.relays[0]))
        assertEquals("one upload only", 1, w.stores().size)
        assertEquals(listOf(w.hashOf(1)), w.checks().single().hashes)
    }

    @Test
    fun anAmbiguousStoreThatNeverLandedIsClearedByTheCheckAndStoredAgainWithTheSameBytes(): Unit = EngineWorld().use { w ->
        val f = fixture(w)
        val op = w.enqueue(1, f.ns)
        w.net.failBefore = { if (it.kind == TestRelays.Kind.STORE) "relay_unavailable" else null }
        assertEquals(StoreResult.AMBIGUOUS, f.attempt(op, f.relays[0]))
        val firstCopy = w.copyHour(op, f.relays[0])
        assertNotNull(firstCopy)
        w.net.failBefore = { null }
        f.later()
        assertEquals(StoreResult.ACKED, f.attempt(op, f.relays[0]))
        // The check proved absence while a copy would still be live: the copy hour is the new lease's.
        assertEquals(Time.floorHour(w.clock.epochSeconds()), w.copyHour(op, f.relays[0]))
        assertTrue(w.copyHour(op, f.relays[0])!! > firstCopy!!)
        assertEquals(2, w.stores().size)
        assertArrayEquals("the same frozen bytes on every retry (OUT-3)", w.stores()[0].ciphertext, w.stores()[1].ciphertext)
        assertEquals(1, w.checks().size)
    }

    @Test
    fun aDefiniteFailureLeavesNoCopyAndFeedsTheWorkBreaker(): Unit = EngineWorld().use { w ->
        val f = fixture(w)
        val op = w.enqueue(1, f.ns)
        w.net.failBefore = { if (it.kind == TestRelays.Kind.STORE) "transport" else null }
        assertEquals(StoreResult.NOT_APPLIED, f.attempt(op, f.relays[0]))
        assertEquals("pending", w.state(op, f.relays[0]))
        assertNull(w.copyHour(op, f.relays[0]))
        assertEquals(1, f.session.work.breaker.failures(f.relays[0]))
        assertEquals("the read lane's breaker never sees work-lane failures", 0, f.session.read.breaker.failures(f.relays[0]))
        // Three failures open the work breaker for that relay only.
        repeat(2) {
            f.later()
            f.attempt(op, f.relays[0])
        }
        assertFalse(f.ctx.allows(PairKey(f.relays[0], f.ns)))
        assertTrue(f.ctx.allows(PairKey(f.relays[1], f.ns)))
    }

    @Test
    fun quotaChecksWithTheSameTokenBeforeParking(): Unit = EngineWorld().use { w ->
        val f = fixture(w)
        // The relay already holds the bytes (e.g. an earlier attempt's copy the client forgot): verified.
        val op = w.enqueue(1, f.ns)
        w.net.put(w.address(f.relays[0]), f.ns, TestBytes.ciphertext(1))
        w.net.failBefore = { if (it.kind == TestRelays.Kind.STORE) "quota" else null }
        assertEquals(StoreResult.VERIFIED, f.attempt(op, f.relays[0]))
        assertEquals("verified", w.state(op, f.relays[0]))
        assertEquals("usable", w.capState(f.relays[0]))
        assertArrayEquals(w.stores().single().capability, w.checks().single().capability)
        // Absent: the token is exhausted and the delivery waits for a new one.
        val op2 = w.enqueue(2, f.ns)
        assertEquals(StoreResult.PARKED, f.attempt(op2, f.relays[1]))
        assertEquals("wait_capability", w.state(op2, f.relays[1]))
        assertEquals("exhausted", w.capState(f.relays[1]))
        assertNull(w.copyHour(op2, f.relays[1]))
    }

    @Test
    fun unauthorizedRejectsTheTokenOnlyIfNoNewerGenerationArrivedDuringTheCall(): Unit = EngineWorld().use { w ->
        val f = fixture(w)
        val op = w.enqueue(1, f.ns)
        w.net.failBefore = { if (it.kind == TestRelays.Kind.STORE) "unauthorized" else null }
        assertEquals(StoreResult.PARKED, f.attempt(op, f.relays[0]))
        assertEquals("wait_capability", w.state(op, f.relays[0]))
        assertEquals("rejected", w.capState(f.relays[0]))
        // The race: Phase 8 installs generation 2 while the generation-1 call is in flight.
        var raced = false
        w.net.during = { if (it.kind == TestRelays.Kind.STORE && !raced) raced = true.also { w.capability(f.relays[1], f.ns, seed = 5) } }
        assertEquals(StoreResult.PARKED, f.attempt(op, f.relays[1]))
        assertEquals("usable", w.capState(f.relays[1]))
        assertEquals(2L, w.long("SELECT generation FROM relay_capability WHERE relay_id = ? AND kind = 'write'", f.relays[1]))
        assertEquals("pending", w.state(op, f.relays[1]))
        // Due again at once, with the new generation.
        w.net.failBefore = { null }
        w.net.during = {}
        assertEquals(StoreResult.ACKED, f.attempt(op, f.relays[1]))
        assertArrayEquals(TestBytes.of(82, 5 * 17 + f.relays[1].value.toInt()), w.stores().last().capability)
    }

    @Test
    fun rejectedAndLocalBugsFailTheDeliveryAndRaiseTheirFlags(): Unit = EngineWorld().use { w ->
        val f = fixture(w)
        val op = w.enqueue(1, f.ns)
        w.net.failBefore = { if (it.kind == TestRelays.Kind.STORE && it.relay == w.address(f.relays[0])) "rejected" else null }
        assertEquals(StoreResult.FAILED, f.attempt(op, f.relays[0]))
        assertEquals("failed", w.state(op, f.relays[0]))
        assertTrue(w.engine.hasFlag(StatusFlag.RELAY_REJECTS))
        // A Kotlin argument error from the port is a local bug.
        w.net.failBefore = { null }
        w.net.argumentError = { it.kind == TestRelays.Kind.STORE && it.relay == w.address(f.relays[1]) }
        assertEquals(StoreResult.FAILED, f.attempt(op, f.relays[1]))
        assertEquals("failed", w.state(op, f.relays[1]))
        assertTrue(w.engine.hasFlag(StatusFlag.BUG))
        // not_onion: the relay's work lane is also held for 24 h.
        w.net.argumentError = { false }
        w.net.failBefore = { if (it.kind == TestRelays.Kind.STORE) "not_onion" else null }
        assertEquals(StoreResult.FAILED, f.attempt(op, f.relays[2]))
        assertFalse(f.ctx.allows(PairKey(f.relays[2], f.ns)))
        assertTrue(w.engine.relayWorkPaused(f.relays[2], w.clock.millis + 23 * HOUR))
        // No possible copy anywhere: the op is decided FAILED.
        assertEquals("failed", w.outcome(op))
    }

    @Test
    fun hostileAnswersAreAmbiguousAndWeighTwo(): Unit = EngineWorld().use { w ->
        val f = fixture(w)
        val op = w.enqueue(1, f.ns)
        // A receipt naming another hash.
        w.net.receiptHashOverride = { TestBytes.hash(77) }
        assertEquals(StoreResult.AMBIGUOUS, f.attempt(op, f.relays[0]))
        assertNotNull(w.copyHour(op, f.relays[0]))
        assertEquals(2, f.session.work.breaker.failures(f.relays[0]))
        w.net.receiptHashOverride = { null }
        // not_stored (a short membership exists) and malformed_response.
        for ((i, category) in listOf("not_stored", "malformed_response").withIndex()) {
            val relay = f.relays[i + 1]
            w.net.failAfter = { if (it.kind == TestRelays.Kind.STORE) category else null }
            assertEquals(StoreResult.AMBIGUOUS, f.attempt(op, relay))
            assertNotNull(w.copyHour(op, relay))
            assertEquals(2, f.session.work.breaker.failures(relay))
        }
    }

    @Test
    fun aFailedCheckBeforeRestoreEndsTheLeaseAndKeepsThePossibleCopy(): Unit = EngineWorld().use { w ->
        val f = fixture(w)
        val op = w.enqueue(1, f.ns, TtlBucket.DAYS_7)
        w.net.failAfter = { if (it.kind == TestRelays.Kind.STORE) "internal" else null }
        f.attempt(op, f.relays[0])
        val copy = w.copyHour(op, f.relays[0])
        w.net.failAfter = { null }
        w.net.failBefore = { if (it.kind == TestRelays.Kind.CHECK) "timeout" else null }
        f.later()
        assertEquals(StoreResult.NOT_APPLIED, f.attempt(op, f.relays[0]))
        assertEquals(copy, w.copyHour(op, f.relays[0]))
        assertEquals(0L, w.long("SELECT inflight FROM outbox_delivery WHERE operation_id = ? AND relay_id = ?", op, f.relays[0]))
        assertEquals(1, w.stores().size)
    }

    @Test
    fun closedStopsTheSessionAndTheAttemptCountsAsAmbiguous(): Unit = EngineWorld().use { w ->
        val f = fixture(w)
        val op = w.enqueue(1, f.ns)
        w.net.failBefore = { if (it.kind == TestRelays.Kind.STORE) "closed" else null }
        assertEquals(StoreResult.STOPPED, f.attempt(op, f.relays[0]))
        assertNotNull(w.copyHour(op, f.relays[0]))
        assertFalse(f.session.online)
        assertFalse(f.ctx.active)
        assertEquals("nothing more is attempted while offline", 0, f.steps.store.round(f.ctx, PairKey(f.relays[1], f.ns), 8))
        assertEquals(1, w.stores().size)
    }
}
