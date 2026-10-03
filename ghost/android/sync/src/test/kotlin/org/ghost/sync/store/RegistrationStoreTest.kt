package org.ghost.sync.store

import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.CapabilityNeed
import org.ghost.sync.api.CapabilitySource
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.KeyKind
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.RelayId
import org.ghost.sync.store.SyncWorld.Companion.DAY
import org.ghost.sync.store.SyncWorld.Companion.HOUR
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `relay_key_registration` and its due rule (Phase 9 design §4.8, §13.3 items 4 and 5): what the
 * owner asks for, when the work lane may run it, what a result leaves behind, and how a lost
 * registration heals.
 */
class RegistrationStoreTest {
    private val verifier = TestBytes.of(32, 41)
    private val otherVerifier = TestBytes.of(32, 42)

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02X".format(it.toInt() and 0xff) }

    /** The week of a capability that expires at `start(week + 1) + 1 h` (§4.4 point 3). */
    private fun weekOf(now: Long): Long = Time.week(now)

    private fun expiryOf(week: Long): Long = Time.WEEK_ORIGIN + Time.WEEK * (week + 1) + HOUR

    private fun SyncWorld.ownSet(): Triple<NamespaceId, RelayId, Long> {
        val relays = relays(1, 2)
        val ns = namespace(1, relays, listen = true)
        val week = weekOf(now)
        relays.forEach { capability(it, ns, CapabilityKind.WRITE, expiresAt = expiryOf(week)) }
        return Triple(ns, relays[0], week)
    }

    private fun SyncWorld.key(ns: NamespaceId, relay: RelayId, period: Long, kind: KeyKind = KeyKind.DEPOSIT) =
        RegistrationKey(relay, ns, period, kind)

    private fun SyncWorld.request(key: RegistrationKey, v: ByteArray = verifier) =
        tx { stores.registrationStore.request(it, key, v, now) }

    @Test
    fun aRequestIsIdempotentAndKeepsItsVerifier(): Unit = SyncWorld().use { w ->
        val (ns, relay, week) = w.ownSet()
        val key = w.key(ns, relay, week)
        w.request(key)
        val requestId = w.long("SELECT length(request_id) FROM relay_key_registration")
        assertEquals(16L, requestId)
        w.request(key)
        assertEquals("an identical request writes nothing", 1L, w.count("relay_key_registration"))
        assertEquals(1, w.stores.registrations.pendingCount())
        // The verifier of a row is fixed at insert (§4.8).
        assertThrows(IllegalStateException::class.java) { w.request(key, otherVerifier) }
        assertThrows(IllegalArgumentException::class.java) { w.request(key, TestBytes.of(31, 41)) }
        assertThrows(IllegalArgumentException::class.java) { w.request(w.key(ns, relay, -1)) }
        // Every kind is its own row.
        for (kind in KeyKind.entries) w.request(w.key(ns, relay, week, kind))
        assertEquals(3L, w.count("relay_key_registration"))
    }

    @Test
    fun aRowIsDueOnlyWithAWriteCapabilityOfItsWeekOrTheOneBefore(): Unit = SyncWorld().use { w ->
        val (ns, relay, week) = w.ownSet()
        val store = w.stores.registrationStore
        for (period in listOf(week - 1, week, week + 1, week + 2)) w.request(w.key(ns, relay, period))
        val due = w.tx { store.due(it, w.now, 8, null, null) }
        assertEquals("the capability's week and the next", listOf(week, week + 1), due.map { it.key.periodId })

        // No capability at all, a read one, an expired one and a refused one make nothing due.
        val other = w.namespace(2, listOf(relay), listen = true)
        w.request(w.key(other, relay, week))
        assertTrue(w.tx { store.due(it, w.now, 8, relay, other) }.isEmpty())
        w.capability(relay, other, CapabilityKind.READ, expiresAt = expiryOf(week))
        assertTrue(w.tx { store.due(it, w.now, 8, relay, other) }.isEmpty())
        // A capability without a declared expiry names no week, so it makes no row due.
        w.capability(relay, other, CapabilityKind.WRITE, expiresAt = null)
        assertTrue(w.tx { store.due(it, w.now, 8, relay, other) }.isEmpty())
        w.capability(relay, other, CapabilityKind.WRITE, expiresAt = expiryOf(week))
        assertEquals(1, w.tx { store.due(it, w.now, 8, relay, other) }.size)
        w.tx { w.caps.refuse(it, relay, other, CapabilityKind.WRITE, w.caps.generation(it, relay, other, CapabilityKind.WRITE)!!, false) }
        assertTrue(w.tx { store.due(it, w.now, 8, relay, other) }.isEmpty())

        // A retired relay is not due either.
        w.tx { w.stores.relayDirectory.retire(it, relay) }
        assertTrue(w.tx { store.due(it, w.now, 8, null, null) }.isEmpty())
    }

    @Test
    fun aLeaseRunsOnceAndItsResultsAreGuarded(): Unit = SyncWorld().use { w ->
        val (ns, relay, week) = w.ownSet()
        val store = w.stores.registrationStore
        val key = w.key(ns, relay, week)
        w.request(key)
        val lease = w.tx { store.lease(it, key, w.now, 600) }
        assertNotNull(lease)
        assertEquals(16, lease!!.requestId().size)
        assertEquals(CapabilityKind.WRITE, lease.capability.kind)
        assertEquals(1L, w.long("SELECT inflight FROM relay_key_registration"))
        assertEquals(1L, w.long("SELECT attempts FROM relay_key_registration"))
        // A second lease of the same row is refused while the first is in flight.
        assertNull(w.tx { store.lease(it, key, w.now, 600) })
        assertTrue(w.tx { store.due(it, w.now, 8, null, null) }.isEmpty())

        // OK: done until the validity the relay answered, idle, attempts reset.
        val validUntil = Time.WEEK_ORIGIN + Time.WEEK * (week + 2) + HOUR
        assertTrue(w.tx { store.recordDone(it, key, validUntil) })
        assertEquals("done", w.string("SELECT state FROM relay_key_registration"))
        assertEquals(validUntil, w.long("SELECT valid_until_hour FROM relay_key_registration"))
        assertEquals(0L, w.long("SELECT inflight FROM relay_key_registration"))
        assertEquals(0, w.stores.registrations.pendingCount())
        // A result that arrives after the lease ended changes nothing.
        assertFalse(w.tx { store.recordDone(it, key, validUntil) })

        // The healing rule takes done rows back to pending with a new request id (§4.8).
        val doneRequestId = w.long("SELECT hex(request_id) = hex(request_id) FROM relay_key_registration")
        assertEquals(1L, doneRequestId)
        val before = w.string("SELECT hex(request_id) FROM relay_key_registration")
        assertEquals(1, w.tx { w.stores.registrations.rearm(it, relay, ns, week) })
        assertEquals("pending", w.string("SELECT state FROM relay_key_registration"))
        assertNull(w.long("SELECT valid_until_hour FROM relay_key_registration"))
        assertTrue("a new request id", before != w.string("SELECT hex(request_id) FROM relay_key_registration"))
        assertEquals("older periods are left alone", 0, w.tx { w.stores.registrations.rearm(it, relay, ns, week + 5) })
    }

    /**
     * The capability belongs to the lease guard: the caller reads the due rows in one transaction
     * and leases in another, one call apart, so a refusal, an expiry or an undeclared week in
     * between leaves the row alone instead of handing out a lease with no capability.
     */
    @Test
    fun aLeaseIsRefusedWhenTheWriteCapabilityWentAwayAfterThePlan(): Unit = SyncWorld().use { w ->
        val (ns, relay, week) = w.ownSet()
        val store = w.stores.registrationStore
        val key = w.key(ns, relay, week)
        w.request(key)
        assertEquals(1, w.tx { store.due(it, w.now, 8, relay, ns) }.size)
        // Another writer's `unauthorized` refuses the capability between the plan and the lease.
        w.tx { w.caps.refuse(it, relay, ns, CapabilityKind.WRITE, w.caps.generation(it, relay, ns, CapabilityKind.WRITE)!!, false) }
        assertNull(w.tx { store.lease(it, key, w.now, 600) })
        assertEquals(0L, w.long("SELECT attempts FROM relay_key_registration"))
        assertEquals(0L, w.long("SELECT inflight FROM relay_key_registration"))
        assertEquals("pending", w.string("SELECT state FROM relay_key_registration"))
        // A capability that declares no week names no period, so it carries no registration either.
        w.capability(relay, ns, CapabilityKind.WRITE, expiresAt = null, seed = 9)
        assertNull(w.tx { store.lease(it, key, w.now, 600) })
        // An expired one is refused as well; a usable, unexpired one leases.
        w.capability(relay, ns, CapabilityKind.WRITE, expiresAt = w.now - HOUR, seed = 10)
        assertNull(w.tx { store.lease(it, key, w.now, 600) })
        w.capability(relay, ns, CapabilityKind.WRITE, expiresAt = expiryOf(week), seed = 11)
        assertNotNull(w.tx { store.lease(it, key, w.now, 600) })
        assertEquals(1L, w.long("SELECT attempts FROM relay_key_registration"))
    }

    @Test
    fun aRefusedPeriodStaysPendingAndTheNextCapabilityGenerationRearmsIt(): Unit = SyncWorld().use { w ->
        val (ns, relay, week) = w.ownSet()
        val store = w.stores.registrationStore
        val key = w.key(ns, relay, week)
        w.request(key)
        assertNotNull(w.tx { store.lease(it, key, w.now, 3600) })
        assertTrue(w.tx { store.endLease(it, key) })
        assertEquals("pending", w.string("SELECT state FROM relay_key_registration"))
        assertEquals(0L, w.long("SELECT inflight FROM relay_key_registration"))
        // The lease's backoff holds it; the row is due again only after the backoff.
        assertTrue(w.tx { store.due(it, w.now, 8, null, null) }.isEmpty())
        // A new write capability re-arms it at once (the M2 idea, §13.3 item 5).
        w.capability(relay, ns, CapabilityKind.WRITE, expiresAt = expiryOf(week), seed = 9)
        assertEquals(1, w.tx { store.due(it, w.now, 8, null, null) }.size)
        assertEquals(0L, w.long("SELECT attempts FROM relay_key_registration"))
    }

    @Test
    fun anInterruptedLeaseIsNormalizedAtTheNextSessionStart(): Unit = SyncWorld().use { w ->
        val (ns, relay, week) = w.ownSet()
        val store = w.stores.registrationStore
        val key = w.key(ns, relay, week)
        w.request(key)
        assertNotNull(w.tx { store.lease(it, key, w.now, 3600) })
        w.reopen()
        assertEquals(1, w.tx { w.stores.registrationStore.normalizeLeases(it, w.now) })
        assertEquals(0L, w.long("SELECT inflight FROM relay_key_registration"))
        assertNull(w.long("SELECT lease_hour FROM relay_key_registration"))
        assertEquals("due again at once: RegisterKey is idempotent", 1, w.tx { w.stores.registrationStore.due(it, w.now, 8, null, null) }.size)
    }

    @Test
    fun oldRowsAreForgottenAndDoneRowsAreCollectedAfterTheirValidity(): Unit = SyncWorld().use { w ->
        val (ns, relay, week) = w.ownSet()
        val store = w.stores.registrationStore
        for (period in listOf(week - 2, week - 1, week)) w.request(w.key(ns, relay, period))
        assertEquals(2, w.tx { w.stores.registrations.forget(it, relay, ns, week) })
        assertEquals(1L, w.count("relay_key_registration"))
        val validUntil = Time.WEEK_ORIGIN + Time.WEEK * (week + 2) + HOUR
        assertTrue(w.tx { store.lease(it, w.key(ns, relay, week), w.now, 0) } != null)
        assertTrue(w.tx { store.recordDone(it, w.key(ns, relay, week), validUntil) })
        assertEquals(0, w.tx { store.collect(it, w.now) })
        w.clock.now = validUntil
        assertEquals(1, w.tx { store.collect(it, w.now) })
        assertEquals(0L, w.count("relay_key_registration"))
    }

    /**
     * `keep` is `request` plus the one case §4.8 leaves out: the ES slot-table change of §5.2. A
     * verifier binds the relay's **slot number** (§21.2 point 2), a relay may keep a namespace's
     * set while moving to another of its slots, and the rows of the earlier periods then carry a
     * verifier no credential can present. A row never changes its verifier — the
     * `relay_key_registration_state` trigger refuses that — so the stale row goes and a fresh
     * pending one takes its place, which is what the relay expects too: its records accumulate per
     * verifier (SC-1).
     */
    @Test
    fun keepReplacesTheRowOfASlotThatMoved(): Unit = SyncWorld().use { w ->
        val (ns, relay, week) = w.ownSet()
        val store = w.stores.registrationStore
        val key = w.key(ns, relay, week)
        assertTrue("a missing row is inserted, exactly like request", w.tx { store.keep(it, key, verifier, w.now) })
        assertFalse("the same verifier changes nothing", w.tx { store.keep(it, key, verifier, w.now) })

        // The row is done when the slot moves under it.
        assertNotNull(w.tx { store.lease(it, key, w.now, 0) })
        assertTrue(w.tx { store.recordDone(it, key, expiryOf(week) + Time.WEEK) })
        assertTrue(w.tx { store.keep(it, key, otherVerifier, w.now) })
        assertEquals(1L, w.count("relay_key_registration"))
        assertEquals("pending", w.string("SELECT state FROM relay_key_registration"))
        assertNull(w.long("SELECT valid_until_hour FROM relay_key_registration"))
        assertEquals(0L, w.long("SELECT attempts FROM relay_key_registration"))
        assertEquals(hex(otherVerifier), w.string("SELECT hex(verifier) FROM relay_key_registration"))

        // A row with a call in flight is left to its result transaction, as `forget` leaves it.
        assertNotNull(w.tx { store.lease(it, key, w.now, 0) })
        assertFalse(w.tx { store.keep(it, key, verifier, w.now) })
        assertEquals(hex(otherVerifier), w.string("SELECT hex(verifier) FROM relay_key_registration"))
    }

    /**
     * `pending` counts what is still to be registered for one pair from a period on — the "until a
     * row is done again" of §21.2 point 8, which is what bounds KEEPER's re-put of a refused own
     * READ credential (mutant MC-15).
     */
    @Test
    fun pendingCountsOnePairsUnfinishedRowsFromAPeriodOn(): Unit = SyncWorld().use { w ->
        val (ns, relay, week) = w.ownSet()
        val store = w.stores.registrationStore
        val other = w.relays(3)[0]
        w.tx { w.stores.namespaces.setRelays(it, ns, setOf(relay, other)) }
        for (period in listOf(week - 1, week)) w.request(w.key(ns, relay, period))
        w.request(w.key(ns, other, week))

        assertEquals(2, w.tx { w.stores.registrations.pending(it, relay, ns, week - 1) })
        assertEquals("the older period is below the bound", 1, w.tx { w.stores.registrations.pending(it, relay, ns, week) })
        assertEquals("another relay's rows are not this pair's", 1, w.tx { w.stores.registrations.pending(it, other, ns, week) })

        val key = w.key(ns, relay, week)
        assertNotNull(w.tx { store.lease(it, key, w.now, 0) })
        assertEquals("a row in flight is still pending work", 1, w.tx { w.stores.registrations.pending(it, relay, ns, week) })
        assertTrue(w.tx { store.recordDone(it, key, expiryOf(week) + Time.WEEK) })
        assertEquals(0, w.tx { w.stores.registrations.pending(it, relay, ns, week) })
    }

    /** A LOCAL channel namespace on two relays with the channel's DEPOSIT credential in its write slot (declaring a week). */
    private fun SyncWorld.channel(): Triple<NamespaceId, List<RelayId>, Long> {
        val relays = relays(1, 2)
        val ns = namespace(1, relays, listen = true, consumer = Consumer.CHANNEL, capabilitySource = CapabilitySource.LOCAL)
        val week = weekOf(now)
        relays.forEach { capability(it, ns, CapabilityKind.WRITE, expiresAt = expiryOf(week), seed = 1) }
        return Triple(ns, relays, week)
    }

    /**
     * Phase 10 design §7.5 item 2: the rows of a funded namespace are served by its **registration**
     * capability and by nothing else. The channel's DEPOSIT credential sits in the write slot and
     * declares a week like a redeemed capability does, so an implementation that kept reading the
     * write slot would call these rows due and present a bearer credential at `RegisterKey`.
     */
    @Test
    fun aFundedNamespacesRowsAreDueOnlyWithItsRegistrationCapability(): Unit = SyncWorld().use { w ->
        val (ns, relays, week) = w.channel()
        val relay = relays[0]
        val store = w.stores.registrationStore
        w.fund(ns)
        for (period in listOf(week - 1, week, week + 1, week + 2)) w.request(w.key(ns, relay, period))
        fun periods() = w.tx { store.due(it, w.now, 8, null, null) }.map { it.key.periodId }
        assertEquals("a write credential serves no registration of a funded namespace", emptyList<Long>(), periods())
        assertNull(w.tx { store.lease(it, w.key(ns, relay, week), w.now, 600) })
        assertEquals(emptyList<Pair<RelayId, NamespaceId>>(), w.tx { store.workPairs(it, w.now) })
        // A registration capability of the week serves the week and the next, the rule the relay judges by.
        w.capability(relay, ns, CapabilityKind.REGISTER, expiresAt = expiryOf(week), seed = 2)
        assertEquals(listOf(week, week + 1), periods())
        assertEquals(listOf(Pair(relay, ns)), w.tx { store.workPairs(it, w.now) })
        // An unknown expiry names no week, an expired or a refused one serves nothing, and neither does a retired relay.
        // (The API no longer installs a registration capability without an expiry, review of S1a; the table allows it.)
        w.raw("UPDATE relay_register_capability SET expires_hour = NULL")
        assertEquals(emptyList<Long>(), periods())
        w.capability(relay, ns, CapabilityKind.REGISTER, expiresAt = w.now - HOUR, seed = 4)
        assertEquals(emptyList<Long>(), periods())
        w.capability(relay, ns, CapabilityKind.REGISTER, expiresAt = expiryOf(week), seed = 5)
        assertEquals(listOf(week, week + 1), periods())
        w.tx { w.caps.refuse(it, relay, ns, CapabilityKind.REGISTER, w.caps.generation(it, relay, ns, CapabilityKind.REGISTER)!!, false) }
        assertEquals(emptyList<Long>(), periods())
        w.capability(relay, ns, CapabilityKind.REGISTER, expiresAt = expiryOf(week), seed = 6)
        w.tx { w.stores.relayDirectory.retire(it, relay) }
        assertEquals(emptyList<Long>(), periods())
    }

    @Test
    fun theLeaseOfAFundedRowPresentsTheRegistrationCapabilityAndNeverTheWriteCredential(): Unit = SyncWorld().use { w ->
        val (ns, relays, week) = w.channel()
        val relay = relays[0]
        val store = w.stores.registrationStore
        w.fund(ns)
        w.capability(relay, ns, CapabilityKind.REGISTER, expiresAt = expiryOf(week), seed = 2)
        val key = w.key(ns, relay, week)
        w.request(key)
        val lease = checkNotNull(w.tx { store.lease(it, key, w.now, 600) })
        assertEquals(CapabilityKind.REGISTER, lease.capability.kind)
        assertArrayEquals(TestBytes.of(82, 2 * 17 + relay.value.toInt()), lease.capability.token)
        assertEquals(w.tx { w.caps.generation(it, relay, ns, CapabilityKind.REGISTER) }, lease.capability.generation)
        assertTrue("the write credential is not the token the lease carries", !TestBytes.of(82, 1 * 17 + relay.value.toInt()).contentEquals(lease.capability.token))
        // The registration capability going away between the plan and the lease leaves the row alone,
        // exactly as a refused write capability does for an owner's row.
        w.tx { store.endLease(it, key) }
        w.tx { tx -> w.caps.refuse(tx, relay, ns, CapabilityKind.REGISTER, w.caps.generation(tx, relay, ns, CapabilityKind.REGISTER)!!, false) }
        w.clock.advance(HOUR)
        assertNull(w.tx { store.lease(it, key, w.now, 600) })
        assertEquals("pending", w.string("SELECT state FROM relay_key_registration"))
    }

    /** The flag decides at each read: an unfunded REDEEM namespace is served by its write capability as in Phase 9. */
    @Test
    fun theFundingFlagMovesARowBetweenTheTwoCapabilities(): Unit = SyncWorld().use { w ->
        val relays = w.relays(1, 2)
        // Only a channel namespace can be funded; its source here is REDEEM, which the write capability serves unfunded.
        val ns = w.namespace(1, relays, listen = true, consumer = Consumer.CHANNEL, capabilitySource = CapabilitySource.REDEEM)
        val week = weekOf(w.now)
        val relay = relays[0]
        val store = w.stores.registrationStore
        w.capability(relay, ns, CapabilityKind.WRITE, expiresAt = expiryOf(week))
        w.request(w.key(ns, relay, week))
        fun due() = w.tx { store.due(it, w.now, 8, null, null) }.size
        assertEquals("unfunded: the write capability serves it", 1, due())
        w.fund(ns)
        assertEquals("funded: only a registration capability does", 0, due())
        w.capability(relay, ns, CapabilityKind.REGISTER, expiresAt = expiryOf(week), seed = 2)
        assertEquals(1, due())
        w.fund(ns, false)
        assertEquals("unfunded again: the write capability, not the leftover registration one", 1, due())
        // Without the write capability the leftover registration capability serves nothing.
        w.raw("DELETE FROM relay_capability")
        assertEquals(0, due())
    }

    /**
     * A namespace whose credentials the consumer installs itself (a channel, a contact) is never served by its
     * write slot: those are bearer credentials, `RegisterKey` refuses them, and the refusal would mark the
     * credential rejected and park the namespace's stores. A funder that stopped funding with rows still
     * pending is the case that reaches it (hardening of this slice; no Phase 9 step requests a registration
     * for a LOCAL namespace).
     */
    @Test
    fun anUnfundedLocalNamespaceIsNeverServedByItsWriteCredential(): Unit = SyncWorld().use { w ->
        val (ns, relays, week) = w.channel()
        val relay = relays[0]
        val store = w.stores.registrationStore
        w.request(w.key(ns, relay, week))
        assertEquals(emptyList<Long>(), w.tx { store.due(it, w.now, 8, null, null) }.map { it.key.periodId })
        assertNull(w.tx { store.lease(it, w.key(ns, relay, week), w.now, 600) })
        // It was funded, the row was requested, the funding ended: the same.
        w.fund(ns)
        w.capability(relay, ns, CapabilityKind.REGISTER, expiresAt = expiryOf(week), seed = 2)
        assertEquals(1, w.tx { store.due(it, w.now, 8, null, null) }.size)
        w.fund(ns, false)
        assertEquals(0, w.tx { store.due(it, w.now, 8, null, null) }.size)
        assertNull(w.tx { store.lease(it, w.key(ns, relay, week), w.now, 600) })
        assertEquals(0L, w.long("SELECT attempts FROM relay_key_registration"))
    }

    /**
     * A new capability re-arms the pair's pending rows only when it is the kind that serves them: the
     * registration capability of a funded namespace and the write capability of an unfunded REDEEM one. A
     * channel's DEPOSIT credential re-put under a funder (every generation switch, every refresh) must not
     * move a registration's attempts or time, or the registration step's schedule would follow credential
     * puts, which are not a funder's act.
     */
    @Test
    fun onlyTheCapabilityThatServesARowReArmsIt(): Unit = SyncWorld().use { w ->
        fun SyncWorld.backedOff(key: RegistrationKey) {
            request(key)
            check(tx { stores.registrationStore.lease(it, key, now, 3600) } != null)
            check(tx { stores.registrationStore.endLease(it, key) })
        }
        fun SyncWorld.attempts(): Long = long("SELECT attempts FROM relay_key_registration")!!
        // Funded: the registration capability re-arms, the write credential does not.
        run {
            val (ns, relays, week) = w.channel()
            w.fund(ns)
            w.capability(relays[0], ns, CapabilityKind.REGISTER, expiresAt = expiryOf(week), seed = 2)
            w.backedOff(w.key(ns, relays[0], week))
            assertEquals(1L, w.attempts())
            w.capability(relays[0], ns, CapabilityKind.WRITE, expiresAt = expiryOf(week), seed = 3)
            assertEquals("a re-put DEPOSIT credential leaves the row alone", 1L, w.attempts())
            assertEquals(0, w.tx { w.stores.registrationStore.due(it, w.now, 8, null, null) }.size)
            w.capability(relays[0], ns, CapabilityKind.REGISTER, expiresAt = expiryOf(week), seed = 4)
            assertEquals("the registration capability re-arms it", 0L, w.attempts())
            assertEquals(1, w.tx { w.stores.registrationStore.due(it, w.now, 8, null, null) }.size)
        }
        w.raw("DELETE FROM relay_key_registration")
        // Unfunded REDEEM (Phase 9, unchanged): the write capability re-arms, a registration one does not.
        run {
            val relays = w.relays(3, 4)
            val ns = w.namespace(9, relays, listen = true)
            val week = weekOf(w.now)
            w.capability(relays[0], ns, CapabilityKind.WRITE, expiresAt = expiryOf(week), seed = 2)
            w.backedOff(w.key(ns, relays[0], week))
            assertEquals(1L, w.attempts())
            w.capability(relays[0], ns, CapabilityKind.REGISTER, expiresAt = expiryOf(week), seed = 3)
            assertEquals("a registration capability does not serve an unfunded namespace", 1L, w.attempts())
            w.capability(relays[0], ns, CapabilityKind.WRITE, expiresAt = expiryOf(week), seed = 4)
            assertEquals(0L, w.attempts())
        }
    }

    @Test
    fun aPendingRegistrationIsWriteWorkAndCarriesItsNamespacesSource(): Unit = SyncWorld().use { w ->
        val relays = w.relays(1, 2)
        val ns = w.namespace(1, relays, listen = false, consumer = Consumer.DM)
        val week = weekOf(w.now)
        w.request(w.key(ns, relays[0], week))
        // §13.3 item 4 (Q31): a pending row with no write capability is WRITE MISSING, like outbox work.
        val needs = w.stores.capabilities.needed()
        assertEquals(
            listOf(CapabilityNeed(relays[0], ns, CapabilityKind.WRITE, CapabilityNeed.Reason.MISSING, CapabilitySource.REDEEM)),
            needs,
        )
        // With a write capability the need is gone.
        w.capability(relays[0], ns, CapabilityKind.WRITE, expiresAt = w.now + 30 * DAY)
        assertTrue(w.stores.capabilities.needed().none { it.reason == CapabilityNeed.Reason.MISSING })

        // A LOCAL namespace reports its source, so the entitlement planner can skip it (§13.4).
        val contact = w.namespace(2, relays, listen = false, consumer = Consumer.DM, capabilitySource = CapabilitySource.LOCAL)
        w.request(w.key(contact, relays[1], week))
        val local = w.stores.capabilities.needed().single { it.namespace == contact }
        assertEquals(CapabilitySource.LOCAL, local.source)
        assertEquals(CapabilityKind.WRITE, local.kind)
    }
}
