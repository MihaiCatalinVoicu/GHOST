package org.ghost.sync.store

import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.CapabilityNeed
import org.ghost.sync.api.CapabilitySource
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.InstalledCapability
import org.ghost.sync.api.KeyKind
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.RelayId
import org.ghost.sync.api.SyncChange
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
 * `CapabilityKind.REGISTER` and `relay_register_capability` (Phase 10 design §7.5 items 1 and 2, §9
 * migration 6): the capability a funder redeems for `RegisterKey` and for nothing else. Installed,
 * read back and refused like the others; reported as a need for a funded namespace only; and read by
 * nothing but the registration step — "store, list, get and check never read it".
 */
class RegisterCapabilityTest {
    private val verifier = TestBytes.of(32, 41)

    private fun weekOf(now: Long): Long = Time.week(now)

    private fun expiryOf(week: Long): Long = Time.WEEK_ORIGIN + Time.WEEK * (week + 1) + HOUR

    /** Three relays and a LOCAL channel namespace listening on all of them, with its shared credentials installed. */
    private fun SyncWorld.channel(seed: Int = 1): Pair<NamespaceId, List<RelayId>> {
        val relays = relays(1, 2, 3)
        val ns = namespace(seed, relays, consumer = Consumer.CHANNEL, capabilitySource = CapabilitySource.LOCAL)
        relays.forEach {
            capability(it, ns, CapabilityKind.READ, expiresAt = now + 8 * DAY)
            capability(it, ns, CapabilityKind.WRITE, expiresAt = now + 8 * DAY)
        }
        return Pair(ns, relays)
    }

    private fun SyncWorld.request(relay: RelayId, ns: NamespaceId, period: Long = weekOf(now), kind: KeyKind = KeyKind.DEPOSIT) =
        tx { stores.registrations.request(it, relay, ns, period, kind, verifier) }

    private fun SyncWorld.needs(): List<CapabilityNeed> = stores.capabilities.needed()

    private fun SyncWorld.installed(relay: RelayId, ns: NamespaceId, kind: CapabilityKind): InstalledCapability? =
        tx { stores.capabilities.installed(it, relay, ns, kind) }

    @Test
    fun putInstallsAUsableCapabilityAndEveryPutIsANewGeneration(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.channel()
        val expiry = expiryOf(weekOf(w.now))
        assertNull(w.installed(relays[0], ns, CapabilityKind.REGISTER))
        w.capability(relays[0], ns, CapabilityKind.REGISTER, expiresAt = expiry + 1_234, seed = 3)
        val installed = checkNotNull(w.installed(relays[0], ns, CapabilityKind.REGISTER))
        assertEquals(InstalledCapability.State.USABLE, installed.state)
        assertEquals("the expiry is floored to the hour", expiry, installed.expiresHour)
        assertEquals(1L, w.long("SELECT generation FROM relay_register_capability"))
        val token = w.tx { w.caps.usable(it, relays[0], ns, CapabilityKind.REGISTER, w.now) }
        assertNotNull(token)
        assertEquals(CapabilityKind.REGISTER, token!!.kind)
        assertArrayEquals(TestBytes.of(82, 3 * 17 + relays[0].value.toInt()), token.token)
        // A second put replaces the token, counts the generation up and makes a refused capability usable again.
        w.tx { w.caps.refuse(it, relays[0], ns, CapabilityKind.REGISTER, 1, exhausted = false) }
        assertEquals(InstalledCapability.State.REJECTED, w.installed(relays[0], ns, CapabilityKind.REGISTER)!!.state)
        w.capability(relays[0], ns, CapabilityKind.REGISTER, expiresAt = expiry, seed = 4)
        assertEquals(InstalledCapability.State.USABLE, w.installed(relays[0], ns, CapabilityKind.REGISTER)!!.state)
        assertEquals(2L, w.tx { w.caps.generation(it, relays[0], ns, CapabilityKind.REGISTER) })
        assertArrayEquals(TestBytes.of(82, 4 * 17 + relays[0].value.toInt()), w.tx { w.caps.usable(it, relays[0], ns, CapabilityKind.REGISTER, w.now) }!!.token)
        // One row per pair, whatever the number of puts, and a pair's neighbours are untouched.
        assertEquals(1L, w.count("relay_register_capability"))
        assertNull(w.installed(relays[1], ns, CapabilityKind.REGISTER))
        // An unknown expiry is kept as unknown.
        w.capability(relays[1], ns, CapabilityKind.REGISTER, expiresAt = null, seed = 5)
        assertNull(w.installed(relays[1], ns, CapabilityKind.REGISTER)!!.expiresHour)
        // The bounds of a token and of a pair are the others' (design §3.8).
        assertThrows(IllegalArgumentException::class.java) { w.tx { w.caps.put(it, relays[2], ns, CapabilityKind.REGISTER, ByteArray(0), null) } }
        assertThrows(IllegalArgumentException::class.java) { w.tx { w.caps.put(it, relays[2], ns, CapabilityKind.REGISTER, ByteArray(513), null) } }
        assertEquals("unknown relay", assertThrows(IllegalStateException::class.java) {
            w.tx { w.caps.put(it, RelayId(999), ns, CapabilityKind.REGISTER, ByteArray(82), null) }
        }.message)
        assertEquals("namespace is not registered", assertThrows(IllegalStateException::class.java) {
            w.tx { w.caps.put(it, relays[2], TestBytes.namespace(77), CapabilityKind.REGISTER, ByteArray(82), null) }
        }.message)
        assertEquals(2L, w.count("relay_register_capability"))
    }

    @Test
    fun anExpiredOrRefusedCapabilityIsNotUsable(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.channel()
        w.capability(relays[0], ns, CapabilityKind.REGISTER, expiresAt = w.now + 2 * HOUR)
        fun usable() = w.tx { w.caps.usable(it, relays[0], ns, CapabilityKind.REGISTER, w.now) } != null
        assertTrue(usable())
        w.clock.advance(2 * HOUR)
        assertFalse("the expiry hour is exclusive", usable())
        w.capability(relays[0], ns, CapabilityKind.REGISTER, expiresAt = null)
        assertTrue("no declared expiry reads as usable, as for the other kinds", usable())
        w.tx { w.caps.refuse(it, relays[0], ns, CapabilityKind.REGISTER, 2, exhausted = true) }
        assertFalse(usable())
        assertEquals(InstalledCapability.State.EXHAUSTED, w.installed(relays[0], ns, CapabilityKind.REGISTER)!!.state)
    }

    /** The rejection race guard: a stale refusal marks nothing, and a refusal marks only the registration row. */
    @Test
    fun aRefusalMarksOnlyTheGenerationThatFailedAndOnlyTheRegistrationCapability(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.channel()
        w.capability(relays[0], ns, CapabilityKind.REGISTER, expiresAt = w.now + 8 * DAY, seed = 1)
        w.capability(relays[0], ns, CapabilityKind.REGISTER, expiresAt = w.now + 8 * DAY, seed = 2)
        val writeGeneration = w.tx { w.caps.generation(it, relays[0], ns, CapabilityKind.WRITE) }
        // The call that failed used generation 1, and generation 2 is installed: nothing is marked.
        assertFalse(w.tx { w.caps.refuse(it, relays[0], ns, CapabilityKind.REGISTER, 1, exhausted = false) })
        assertEquals(InstalledCapability.State.USABLE, w.installed(relays[0], ns, CapabilityKind.REGISTER)!!.state)
        w.hints.clear()
        assertTrue(w.tx { w.caps.refuse(it, relays[0], ns, CapabilityKind.REGISTER, 2, exhausted = false) })
        assertTrue("the capability hint follows a refusal", w.hints.any { SyncChange.CAPABILITIES in it })
        assertEquals(InstalledCapability.State.REJECTED, w.installed(relays[0], ns, CapabilityKind.REGISTER)!!.state)
        assertFalse("a refused capability is refused once", w.tx { w.caps.refuse(it, relays[0], ns, CapabilityKind.REGISTER, 2, exhausted = true) })
        // The channel's own credentials are other rows of another table: a refusal of the registration
        // capability, with a generation that equals theirs, does not touch them.
        assertEquals(InstalledCapability.State.USABLE, w.installed(relays[0], ns, CapabilityKind.WRITE)!!.state)
        assertEquals(writeGeneration, w.tx { w.caps.generation(it, relays[0], ns, CapabilityKind.WRITE) })
        assertEquals(InstalledCapability.State.USABLE, w.installed(relays[0], ns, CapabilityKind.READ)!!.state)
        // And the other way round: refusing the write credential leaves the registration capability usable.
        w.capability(relays[0], ns, CapabilityKind.REGISTER, expiresAt = w.now + 8 * DAY, seed = 3)
        assertTrue(w.tx { w.caps.refuse(it, relays[0], ns, CapabilityKind.WRITE, writeGeneration!!, exhausted = false) })
        assertEquals(InstalledCapability.State.USABLE, w.installed(relays[0], ns, CapabilityKind.REGISTER)!!.state)
    }

    /**
     * "Store, list, get and check never read it" (design §7.5 item 2). With only a registration
     * capability on a pair, nothing that reads, lists, checks or stores finds a token; the directory
     * snapshot has no read pair for it; and an operation of the namespace waits for a write token and
     * is reported as WRITE work — the registration capability is not mistaken for one.
     */
    @Test
    fun storeListGetAndCheckNeverReadTheRegistrationCapability(): Unit = SyncWorld().use { w ->
        val relays = w.relays(1, 2)
        val ns = w.namespace(1, relays, consumer = Consumer.CHANNEL, capabilitySource = CapabilitySource.LOCAL)
        relays.forEach { w.capability(it, ns, CapabilityKind.REGISTER, expiresAt = w.now + 8 * DAY) }
        val relay = relays[0]
        assertNull(w.tx { w.caps.forReading(it, relay, ns, w.now) })
        assertNull(w.tx { w.caps.forChecking(it, relay, ns, w.now) })
        for (kind in listOf(CapabilityKind.READ, CapabilityKind.WRITE)) {
            assertNull(kind.toString(), w.tx { w.caps.usable(it, relay, ns, kind, w.now) })
            assertNull(kind.toString(), w.installed(relay, ns, kind))
        }
        assertTrue("no read pair for a namespace that holds a registration capability only", w.tx { w.directory.readPairs(it, w.now) }.isEmpty())
        // An operation waits for a write token: no store lease, a WRITE need, and the delivery parked by the lease check.
        val op = w.enqueue(1, ns)
        assertNull(w.tx { w.outbox.lease(it, op, relay, w.now, 600) })
        assertTrue(w.needs().any { it.kind == CapabilityKind.WRITE && it.relay == relay && it.namespace == ns && it.reason == CapabilityNeed.Reason.MISSING })
        // The write credential, once installed, leases; the registration capability stays where it was.
        w.capability(relay, ns, CapabilityKind.WRITE, expiresAt = w.now + 8 * DAY)
        assertNotNull(w.tx { w.outbox.lease(it, op, relay, w.now, 600) })
        assertEquals(InstalledCapability.State.USABLE, w.installed(relay, ns, CapabilityKind.REGISTER)!!.state)
    }

    @Test
    fun aRegistrationCapabilityIsNeverReportedForAnUnfundedNamespace(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.channel()
        w.request(relays[0], ns)
        // Unfunded: the channel's write credential is there, so there is nothing to ask for.
        assertEquals(emptyList<CapabilityNeed>(), w.needs())
        // A registration capability that lingers after the funding ended is inert.
        w.fund(ns)
        w.capability(relays[0], ns, CapabilityKind.REGISTER, expiresAt = w.now + HOUR)
        w.tx { w.caps.refuse(it, relays[0], ns, CapabilityKind.REGISTER, 1, exhausted = false) }
        assertEquals(listOf(CapabilityKind.REGISTER), w.needs().map { it.kind })
        w.fund(ns, false)
        assertEquals(emptyList<CapabilityNeed>(), w.needs())
        w.fund(ns)
        assertEquals(listOf(CapabilityKind.REGISTER), w.needs().map { it.kind })
    }

    /**
     * The needs of a funded namespace (design §7.5 item 1): REGISTER MISSING where a registration is
     * pending and no registration capability is held; REJECTED, EXHAUSTED and EXPIRING for a held one;
     * always source REDEEM, because the planner redeems them as WRITE needs of a REDEEM namespace
     * (§7.6) although the channel's own source is LOCAL; and no WRITE need for the same registration.
     */
    @Test
    fun aFundedNamespaceReportsRegisterNeedsWithSourceRedeem(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.channel()
        w.fund(ns)
        // Funded, nothing pending, nothing held: no need. Funding is a flag, not an act.
        assertEquals(emptyList<CapabilityNeed>(), w.needs())
        w.request(relays[0], ns)
        w.request(relays[0], ns, kind = KeyKind.READ)
        w.request(relays[1], ns)
        val missing = CapabilityNeed.Reason.MISSING
        assertEquals(
            listOf(
                CapabilityNeed(relays[0], ns, CapabilityKind.REGISTER, missing, CapabilitySource.REDEEM),
                CapabilityNeed(relays[1], ns, CapabilityKind.REGISTER, missing, CapabilitySource.REDEEM),
            ),
            w.needs(),
        )
        assertEquals("the channel is LOCAL, the need is not", CapabilitySource.REDEEM, w.needs().first().source)
        // A held, healthy registration capability on the first relay answers it; the second still asks.
        w.capability(relays[0], ns, CapabilityKind.REGISTER, expiresAt = w.now + 8 * DAY)
        assertEquals(listOf(relays[1]), w.needs().map { it.relay })
        // Every state of a held capability, and the whole need each time (kind, reason and source REDEEM):
        // expiring within 24 h (also already expired), rejected, exhausted.
        fun registerNeed(reason: CapabilityNeed.Reason) = CapabilityNeed(relays[0], ns, CapabilityKind.REGISTER, reason, CapabilitySource.REDEEM)
        w.capability(relays[0], ns, CapabilityKind.REGISTER, expiresAt = w.now + 23 * HOUR)
        assertEquals(registerNeed(CapabilityNeed.Reason.EXPIRING), w.needs().single { it.relay == relays[0] })
        w.capability(relays[0], ns, CapabilityKind.REGISTER, expiresAt = w.now - HOUR)
        assertEquals(registerNeed(CapabilityNeed.Reason.EXPIRING), w.needs().single { it.relay == relays[0] })
        w.capability(relays[0], ns, CapabilityKind.REGISTER, expiresAt = w.now + 8 * DAY)
        w.tx { w.caps.refuse(it, relays[0], ns, CapabilityKind.REGISTER, 4, exhausted = false) }
        assertEquals(registerNeed(CapabilityNeed.Reason.REJECTED), w.needs().single { it.relay == relays[0] })
        w.capability(relays[0], ns, CapabilityKind.REGISTER, expiresAt = w.now + 8 * DAY)
        w.tx { w.caps.refuse(it, relays[0], ns, CapabilityKind.REGISTER, 5, exhausted = true) }
        assertEquals(registerNeed(CapabilityNeed.Reason.EXHAUSTED), w.needs().single { it.relay == relays[0] })
        assertTrue("every need of a funded namespace's registration is REGISTER", w.needs().all { it.kind == CapabilityKind.REGISTER })
        // A held capability is renewed at its EXPIRING time even when no registration is pending.
        w.tx { w.stores.registrations.forget(it, relays[0], ns, weekOf(w.now) + 10) }
        w.tx { w.stores.registrations.forget(it, relays[1], ns, weekOf(w.now) + 10) }
        w.capability(relays[0], ns, CapabilityKind.REGISTER, expiresAt = w.now + 20 * HOUR)
        assertEquals(listOf(registerNeed(CapabilityNeed.Reason.EXPIRING)), w.needs())
    }

    @Test
    fun theNeedsFollowTheRelaysOfTheSetAndTheirState(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.channel()
        w.fund(ns)
        w.request(relays[0], ns)
        w.request(relays[1], ns)
        assertEquals(listOf(relays[0], relays[1]), w.needs().map { it.relay })
        // A relay that left the namespace's set is no pair of it any more; a retired relay is not asked.
        w.tx { w.stores.namespaces.setRelays(it, ns, setOf(relays[1], relays[2])) }
        assertEquals(listOf(relays[1]), w.needs().map { it.relay })
        w.tx { w.stores.relayDirectory.retire(it, relays[1]) }
        assertEquals(emptyList<CapabilityNeed>(), w.needs())
        // A done registration is no pending work.
        w.tx { w.stores.namespaces.setRelays(it, ns, setOf(relays[0], relays[2])) }
        assertEquals(listOf(relays[0]), w.needs().map { it.relay })
        val week = weekOf(w.now)
        w.capability(relays[0], ns, CapabilityKind.REGISTER, expiresAt = expiryOf(week))
        val key = RegistrationKey(relays[0], ns, week, KeyKind.DEPOSIT)
        assertNotNull(w.tx { w.stores.registrationStore.lease(it, key, w.now, 600) })
        assertTrue(w.tx { w.stores.registrationStore.recordDone(it, key, expiryOf(week) + Time.WEEK) })
        assertEquals(emptyList<CapabilityNeed>(), w.needs())
    }

    @Test
    fun thePendingRegistrationsOfAFundedNamespaceAreNotWriteWork(): Unit = SyncWorld().use { w ->
        // A REDEEM funded namespace without any write token: before funding the pending row asked for a
        // write capability; funded, it asks for a registration capability instead, and only that.
        val relays = w.relays(1, 2)
        val ns = w.namespace(1, relays, listen = false, consumer = Consumer.DM, capabilitySource = CapabilitySource.REDEEM)
        w.request(relays[0], ns)
        assertEquals(CapabilityKind.WRITE to CapabilitySource.REDEEM, w.needs().single().let { it.kind to it.source })
        w.fund(ns)
        assertEquals(CapabilityKind.REGISTER to CapabilitySource.REDEEM, w.needs().single().let { it.kind to it.source })
        // An unfunded LOCAL namespace keeps the Phase 9 report: a WRITE need that carries its LOCAL source.
        val contact = w.namespace(2, relays, listen = false, consumer = Consumer.DM, capabilitySource = CapabilitySource.LOCAL)
        w.request(relays[1], contact)
        val local = w.needs().single { it.namespace == contact }
        assertEquals(CapabilityKind.WRITE to CapabilitySource.LOCAL, local.kind to local.source)
    }

    @Test
    fun garbageCollectionCollectsAnExpiredRegistrationCapabilityAfterTheGraceAndKeepsTheOthers(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.channel()
        w.fund(ns)
        w.capability(relays[0], ns, CapabilityKind.REGISTER, expiresAt = w.now + HOUR)
        w.capability(relays[1], ns, CapabilityKind.REGISTER, expiresAt = w.now + 30 * DAY)
        w.capability(relays[2], ns, CapabilityKind.REGISTER, expiresAt = null)
        // The write credentials expire at +8 d; the grace is the others' (RetentionPolicy.CAPABILITY_GRACE_SECONDS).
        w.clock.advance(HOUR + RetentionPolicy.CAPABILITY_GRACE_SECONDS - 1)
        assertEquals(0, w.tx { w.caps.collect(it, w.now) })
        w.clock.advance(1)
        assertEquals("the expired registration capability only", 1, w.tx { w.caps.collect(it, w.now) })
        assertEquals(2L, w.count("relay_register_capability"))
        assertNull(w.installed(relays[0], ns, CapabilityKind.REGISTER))
        // The report of a garbage-collection pass counts it with the capabilities.
        w.clock.advance(40 * DAY)
        val report = w.tx { w.gc.pass(it, w.now) }
        assertEquals("the second one; the write and read credentials of the channel are collected too", 1, report.capabilities - 6)
        assertEquals(1L, w.count("relay_register_capability"))
        assertEquals("a capability without an expiry is kept until the namespace goes", relays[2].value, w.long("SELECT relay_id FROM relay_register_capability"))
    }

    /**
     * A registration capability was bought with an ACCESS token, so the namespace GC does not delete
     * the row that names it (as for the write and read credentials): with the relay set emptied and
     * listening off, the capability alone keeps the row, and the pass that collects the capability
     * after its expiry and grace takes the row with it.
     */
    @Test
    fun theNamespaceGcKeepsARowThatARegistrationCapabilityStillNamesUntilItIsCollected(): Unit = SyncWorld().use { w ->
        val relays = w.relays(1)
        val ns = w.namespace(1, relays, listen = false, consumer = Consumer.CHANNEL, capabilitySource = CapabilitySource.LOCAL)
        w.capability(relays[0], ns, CapabilityKind.REGISTER, expiresAt = w.now + 30 * DAY)
        w.tx { w.stores.namespaces.setRelays(it, ns, emptySet()) }
        assertEquals("nothing else names the namespace", 0L, w.count("namespace_relay") + w.count("relay_capability") + w.count("inbox_blob"))
        w.tx { w.gc.pass(it, w.now) }
        assertEquals("the live registration capability keeps the row", 1L, w.count("sync_namespace"))
        assertEquals(1L, w.count("relay_register_capability"))
        w.clock.advance(30 * DAY + RetentionPolicy.CAPABILITY_GRACE_SECONDS + HOUR)
        w.tx { w.gc.pass(it, w.now) }
        assertEquals(0L, w.count("relay_register_capability"))
        assertEquals("collected with its capability", 0L, w.count("sync_namespace"))
    }

    @Test
    fun aPutOfOneKindNeverCreatesTheOthersRowAndTheTablesAreIndependent(): Unit = SyncWorld().use { w ->
        val relays = w.relays(1, 2)
        val ns = w.namespace(1, relays, consumer = Consumer.CHANNEL, capabilitySource = CapabilitySource.LOCAL)
        w.capability(relays[0], ns, CapabilityKind.REGISTER, expiresAt = w.now + 8 * DAY)
        assertEquals(0L, w.count("relay_capability"))
        w.capability(relays[0], ns, CapabilityKind.WRITE, expiresAt = w.now + 8 * DAY)
        assertEquals(1L, w.count("relay_capability"))
        assertEquals(1L, w.count("relay_register_capability"))
        // Generations count per table: the write credential's first put is generation 1 whatever the registration capability's.
        w.capability(relays[0], ns, CapabilityKind.REGISTER, expiresAt = w.now + 8 * DAY, seed = 2)
        assertEquals(2L, w.long("SELECT generation FROM relay_register_capability"))
        assertEquals(1L, w.long("SELECT generation FROM relay_capability"))
    }
}
