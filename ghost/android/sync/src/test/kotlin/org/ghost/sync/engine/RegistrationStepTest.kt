package org.ghost.sync.engine

import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.KeyKind
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.RelayId
import org.ghost.sync.api.StatusFlag
import org.ghost.sync.port.RegisterAnswer
import org.ghost.sync.port.RegisterResult
import org.ghost.sync.store.RegistrationKey
import org.ghost.sync.store.TestBytes
import org.ghost.sync.store.Time
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The key-registration step of the work lane (Phase 9 design §4.8, §13.3 item 5) through the real
 * [RegistrationStep] against the in-test relay: the lease, `RegisterKey` on the namespace's circuit,
 * and every result — OK, WRONG_PERIOD, a refused capability, a transient failure and a transport
 * stop. The read lane is never touched (T19).
 */
class RegistrationStepTest {
    private val verifier = TestBytes.of(32, 41)

    private class Fixture(val w: EngineWorld, val session: Session, val ns: NamespaceId, val relays: List<RelayId>, val week: Long) {
        val ctx: WorkContext get() = session.workContext
        val step: RegistrationStep get() = w.engine.steps.registration

        fun key(relay: RelayId = relays[0], period: Long = week, kind: KeyKind = KeyKind.DEPOSIT) = RegistrationKey(relay, ns, period, kind)

        fun due(key: RegistrationKey) = w.tx { w.stores.registrationStore.due(it, w.clock.epochSeconds(), 8, key.relayId, key.namespace) }
            .firstOrNull { it.key == key }

        fun attempt(key: RegistrationKey): RegistrationResult = step.attempt(ctx, checkNotNull(due(key)) { "not due" })

        fun state(key: RegistrationKey): String? =
            w.string(
                "SELECT state FROM relay_key_registration WHERE relay_id = ? AND namespace_id = ? AND period_id = ? AND kind = ?",
                key.relayId.value, key.namespace.toByteArray(), key.periodId, key.kind.dbCode,
            )

        fun later() = w.clock.advance(EngineWorld.HOUR + EngineWorld.MINUTE)
    }

    /** A live session over one own namespace with a write capability of the current week on each relay. */
    private fun fixture(w: EngineWorld, mode: PrivacyMode = PrivacyMode.HIGH): Fixture {
        w.mode = mode
        val relays = w.relays(1, 2)
        val ns = w.namespace(1, relays, listen = true)
        val week = Time.week(w.clock.epochSeconds())
        val expiry = Time.WEEK_ORIGIN + Time.WEEK * (week + 1) + Time.HOUR
        relays.forEach { w.capability(it, ns, CapabilityKind.WRITE, expiresAt = expiry) }
        val (session, driver) = w.session()
        driver.runUntil(0)
        check(session.online)
        return Fixture(w, session, ns, relays, week)
    }

    @Test
    fun anAcceptedRegistrationIsDoneWithTheRelaysValidity(): Unit = EngineWorld().use { w ->
        val f = fixture(w)
        for (period in listOf(f.week, f.week + 1)) w.registration(f.relays[0], f.ns, period, KeyKind.DEPOSIT, verifier)
        assertEquals(2, f.step.round(f.ctx, null, 8))
        val calls = w.net.callsOf(TestRelays.Kind.REGISTER)
        assertEquals(2, calls.size)
        assertEquals(setOf(w.address(f.relays[0])), calls.map { it.relay }.toSet())
        assertEquals("done", f.state(f.key()))
        assertEquals(
            TestRelays.registrationValidity(f.week),
            w.long(
                "SELECT valid_until_hour FROM relay_key_registration WHERE period_id = ? AND kind = 'deposit'",
                f.week,
            ),
        )
        assertEquals(2, w.net.registrations.size)
        assertEquals(0, w.stores.registrations.pendingCount())
        // Nothing is due any more, and the read lane made no call of its own for it.
        assertEquals(0, f.step.round(f.ctx, null, 8))
        assertTrue(w.net.callsOf(TestRelays.Kind.LIST).isEmpty())
    }

    @Test
    fun anIdenticalRetryKeepsTheRequestId(): Unit = EngineWorld().use { w ->
        val f = fixture(w)
        val key = f.key()
        w.registration(key.relayId, key.namespace, key.periodId, key.kind, verifier)
        w.net.failAfter = { if (it.kind == TestRelays.Kind.REGISTER) "timeout" else null }
        assertEquals(RegistrationResult.NOT_APPLIED, f.attempt(key))
        assertEquals("pending", f.state(key))
        w.net.failAfter = { null }
        f.later()
        assertEquals(RegistrationResult.RECORDED, f.attempt(key))
        val ids = w.net.registrationRequestIds.values.single()
        assertEquals("every retry sends the same request id", 2, ids.size)
        assertEquals(ids[0], ids[1])
        assertEquals(1, w.net.registrations.size)
    }

    @Test
    fun aRefusedPeriodLeavesTheRowPendingForTheNextCapabilityGeneration(): Unit = EngineWorld().use { w ->
        val f = fixture(w)
        val key = f.key()
        w.registration(key.relayId, key.namespace, key.periodId, key.kind, verifier)
        w.net.registerOverride = { RegisterAnswer(RegisterResult.WRONG_PERIOD, 0) }
        assertEquals(RegistrationResult.WRONG_PERIOD, f.attempt(key))
        assertEquals("pending", f.state(key))
        assertEquals(0L, w.long("SELECT inflight FROM relay_key_registration"))
        assertNull(f.due(key))
        // The next write capability re-arms it (the M2 idea), and the relay then records it.
        w.net.registerOverride = { null }
        val expiry = Time.WEEK_ORIGIN + Time.WEEK * (f.week + 1) + Time.HOUR
        w.capability(f.relays[0], f.ns, CapabilityKind.WRITE, seed = 9, expiresAt = expiry)
        assertNotNull(f.due(key))
        assertEquals(RegistrationResult.RECORDED, f.attempt(key))
    }

    @Test
    fun aRefusedCapabilityParksTheRowUntilANewOneArrives(): Unit = EngineWorld().use { w ->
        val f = fixture(w)
        val key = f.key()
        w.registration(key.relayId, key.namespace, key.periodId, key.kind, verifier)
        w.net.failBefore = { if (it.kind == TestRelays.Kind.REGISTER) "unauthorized" else null }
        assertEquals(RegistrationResult.PARKED, f.attempt(key))
        assertEquals("pending", f.state(key))
        assertEquals("rejected", w.string("SELECT state FROM relay_capability WHERE kind = 'write' AND relay_id = ?", f.relays[0].value))
        assertNull("no capability, nothing due", f.due(key))
        w.net.failBefore = { null }
        val expiry = Time.WEEK_ORIGIN + Time.WEEK * (f.week + 1) + Time.HOUR
        w.capability(f.relays[0], f.ns, CapabilityKind.WRITE, seed = 9, expiresAt = expiry)
        assertEquals(RegistrationResult.RECORDED, f.attempt(key))
    }

    @Test
    fun transientFailuresBackOffAndATransportFailureStopsTheSession(): Unit = EngineWorld().use { w ->
        val f = fixture(w)
        val key = f.key()
        w.registration(key.relayId, key.namespace, key.periodId, key.kind, verifier)
        w.net.failBefore = { if (it.kind == TestRelays.Kind.REGISTER) "transport" else null }
        assertEquals(RegistrationResult.NOT_APPLIED, f.attempt(key))
        assertNull("the lease's backoff holds it", f.due(key))
        f.later()
        // A permanent refusal raises its flag and still leaves the row for a later attempt.
        w.net.failBefore = { if (it.kind == TestRelays.Kind.REGISTER) "rejected" else null }
        assertEquals(RegistrationResult.NOT_APPLIED, f.attempt(key))
        assertTrue(StatusFlag.RELAY_REJECTS in w.engine.status().flags)
        f.later()
        // A closed transport stops the session's calls (design §3.6).
        w.net.failBefore = { if (it.kind == TestRelays.Kind.REGISTER) "closed" else null }
        assertEquals(RegistrationResult.STOPPED, f.attempt(key))
        assertFalse(f.session.online)
        assertEquals(0, f.step.round(f.ctx, null, 8))
        assertEquals("pending", f.state(key))
    }

    @Test
    fun aStandardPassRunsAtMostItsCapAndAHighEventRunsThePairsRows(): Unit = EngineWorld().use { w ->
        val f = fixture(w, PrivacyMode.STANDARD)
        for (relay in f.relays) for (period in listOf(f.week, f.week + 1)) w.registration(relay, f.ns, period, KeyKind.READ, verifier)
        assertEquals("the cap bounds one pass", 2, f.step.round(f.ctx, null, 2))
        assertEquals(2, w.stores.registrations.pendingCount())
        assertEquals(2, f.step.round(f.ctx, null, 8))
        assertEquals(0, w.stores.registrations.pendingCount())
        assertEquals(4, w.net.callsOf(TestRelays.Kind.REGISTER).size)
    }
}
