package org.ghost.sync.engine

import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.CapabilitySource
import org.ghost.sync.api.Consumer
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
import org.junit.Assert.assertArrayEquals
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

    /**
     * Two rows of one pair read as due in the same pass: the first answer refuses the write
     * capability, so the second row's lease no longer matches the guard (the capability is part of
     * it) and the pass ends with one attempt and both rows pending, never a throw.
     */
    @Test
    fun aRefusedCapabilityLeavesTheOtherDueRowOfThePairUntouched(): Unit = EngineWorld().use { w ->
        val f = fixture(w)
        val deposit = f.key(kind = KeyKind.DEPOSIT)
        val read = f.key(kind = KeyKind.READ)
        for (key in listOf(deposit, read)) w.registration(key.relayId, key.namespace, key.periodId, key.kind, verifier)
        w.net.failBefore = { if (it.kind == TestRelays.Kind.REGISTER) "unauthorized" else null }
        assertEquals("the second row is skipped, not attempted", 1, f.step.round(f.ctx, null, 8))
        assertEquals("rejected", w.string("SELECT state FROM relay_capability WHERE kind = 'write' AND relay_id = ?", f.relays[0].value))
        assertEquals("pending", f.state(deposit))
        assertEquals("pending", f.state(read))
        assertEquals(2, w.stores.registrations.pendingCount())
        assertEquals(0L, w.long("SELECT sum(inflight) FROM relay_key_registration"))
        assertEquals("the skipped row kept its attempts", 0L, w.long("SELECT attempts FROM relay_key_registration WHERE kind = 'read'"))
        // The next capability generation re-arms both rows and the relay then records them.
        w.net.failBefore = { null }
        val expiry = Time.WEEK_ORIGIN + Time.WEEK * (f.week + 1) + Time.HOUR
        w.capability(f.relays[0], f.ns, CapabilityKind.WRITE, seed = 9, expiresAt = expiry)
        assertEquals(2, f.step.round(f.ctx, null, 8))
        assertEquals(0, w.stores.registrations.pendingCount())
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

    /**
     * A funder's channel (Phase 10 design §7.5 item 2): a LOCAL channel namespace whose write slot
     * holds the shared DEPOSIT credential (seed 1, declaring a week, as a redeemed capability would) and
     * whose registrations are served by the registration capability a funder redeemed (seed 2). The
     * tokens differ per seed, so the capability a call presented says which slot served it.
     */
    private fun funded(w: EngineWorld, mode: PrivacyMode = PrivacyMode.HIGH): Fixture {
        w.mode = mode
        val relays = w.relays(1, 2)
        val ns = w.namespace(1, relays, listen = true, consumer = Consumer.CHANNEL, capabilitySource = CapabilitySource.LOCAL)
        val week = Time.week(w.clock.epochSeconds())
        val expiry = Time.WEEK_ORIGIN + Time.WEEK * (week + 1) + Time.HOUR
        relays.forEach { w.capability(it, ns, CapabilityKind.WRITE, seed = 1, expiresAt = expiry) }
        w.fund(ns)
        relays.forEach { w.capability(it, ns, CapabilityKind.REGISTER, seed = 2, expiresAt = expiry) }
        val (session, driver) = w.session()
        driver.runUntil(0)
        check(session.online)
        return Fixture(w, session, ns, relays, week)
    }

    private fun EngineWorld.token(kind: CapabilityKind, relay: RelayId, seed: Int): ByteArray {
        check(kind != CapabilityKind.READ)
        return TestBytes.of(82, seed * 17 + relay.value.toInt())
    }

    @Test
    fun aFundedRegistrationPresentsTheRegistrationCapabilityOnTheRegistrationCallAlone(): Unit = EngineWorld().use { w ->
        val f = funded(w)
        for (period in listOf(f.week, f.week + 1)) w.registration(f.relays[0], f.ns, period, KeyKind.DEPOSIT, verifier)
        w.registration(f.relays[1], f.ns, f.week, KeyKind.READ, verifier)
        assertEquals(3, f.step.round(f.ctx, null, 8))
        val calls = w.net.callsOf(TestRelays.Kind.REGISTER)
        assertEquals(3, calls.size)
        for (call in calls) {
            val relay = f.relays.single { w.address(it) == call.relay }
            assertArrayEquals("the registration capability", w.token(CapabilityKind.REGISTER, relay, 2), call.capability)
            assertFalse("never the channel's DEPOSIT credential", call.capability.contentEquals(w.token(CapabilityKind.WRITE, relay, 1)))
        }
        assertEquals("done", f.state(f.key()))
        assertEquals(0, w.stores.registrations.pendingCount())
        // The read lane made no call of its own for them, and nothing but REGISTER went out (T19; the
        // session is online and the step ran by hand).
        assertTrue(w.net.callsOf(TestRelays.Kind.LIST).isEmpty())
        assertTrue(w.net.callsOf(TestRelays.Kind.STORE).isEmpty())
    }

    /** A refusal blames the capability that was presented: the registration capability, not the channel's credential. */
    @Test
    fun aRefusalOfAFundedRegistrationRejectsTheRegistrationCapabilityOnly(): Unit = EngineWorld().use { w ->
        val f = funded(w)
        val key = f.key()
        w.registration(key.relayId, key.namespace, key.periodId, key.kind, verifier)
        w.net.failBefore = { if (it.kind == TestRelays.Kind.REGISTER) "unauthorized" else null }
        assertEquals(RegistrationResult.PARKED, f.attempt(key))
        assertEquals("rejected", w.string("SELECT state FROM relay_register_capability WHERE relay_id = ?", f.relays[0].value))
        assertEquals("the channel's credential is untouched", "usable", w.string("SELECT state FROM relay_capability WHERE kind = 'write' AND relay_id = ?", f.relays[0].value))
        assertEquals("pending", f.state(key))
        assertNull("no capability, nothing due", f.due(key))
        // The need is REGISTER, source REDEEM: the planner redeems it, and a WRITE need is not raised.
        assertEquals(listOf(CapabilityKind.REGISTER), w.stores.capabilities.needed().map { it.kind })
        // A new registration capability re-arms the row and the relay then records it.
        w.net.failBefore = { null }
        val expiry = Time.WEEK_ORIGIN + Time.WEEK * (f.week + 1) + Time.HOUR
        w.capability(f.relays[0], f.ns, CapabilityKind.REGISTER, seed = 3, expiresAt = expiry)
        assertEquals(RegistrationResult.RECORDED, f.attempt(key))
        assertArrayEquals(w.token(CapabilityKind.REGISTER, f.relays[0], 3), w.net.callsOf(TestRelays.Kind.REGISTER).last().capability)
        assertTrue(w.stores.capabilities.needed().isEmpty())
    }

    @Test
    fun aFunderThatStoppedFundingNeverPresentsTheChannelCredentialForARegistration(): Unit = EngineWorld().use { w ->
        val f = funded(w)
        val key = f.key()
        w.registration(key.relayId, key.namespace, key.periodId, key.kind, verifier)
        w.fund(f.ns, false)
        assertEquals(0, f.step.round(f.ctx, null, 8))
        assertTrue(w.net.callsOf(TestRelays.Kind.REGISTER).isEmpty())
        assertEquals("usable", w.string("SELECT state FROM relay_capability WHERE kind = 'write' AND relay_id = ?", f.relays[0].value))
        assertEquals("pending", f.state(key))
        // Funded again, the row is served as before.
        w.fund(f.ns)
        assertEquals(1, f.step.round(f.ctx, null, 8))
    }

    @Test
    fun aRefusedPeriodOfAFundedRegistrationWaitsForTheNextRegistrationCapability(): Unit = EngineWorld().use { w ->
        val f = funded(w)
        val key = f.key()
        w.registration(key.relayId, key.namespace, key.periodId, key.kind, verifier)
        w.net.registerOverride = { RegisterAnswer(RegisterResult.WRONG_PERIOD, 0) }
        assertEquals(RegistrationResult.WRONG_PERIOD, f.attempt(key))
        assertEquals("usable", w.string("SELECT state FROM relay_register_capability WHERE relay_id = ?", f.relays[0].value))
        assertNull(f.due(key))
        // The channel's credential being put again does not wake the row; the registration capability does.
        val expiry = Time.WEEK_ORIGIN + Time.WEEK * (f.week + 1) + Time.HOUR
        w.capability(f.relays[0], f.ns, CapabilityKind.WRITE, seed = 7, expiresAt = expiry)
        assertNull(f.due(key))
        w.net.registerOverride = { null }
        w.capability(f.relays[0], f.ns, CapabilityKind.REGISTER, seed = 8, expiresAt = expiry)
        assertEquals(RegistrationResult.RECORDED, f.attempt(key))
    }
}
