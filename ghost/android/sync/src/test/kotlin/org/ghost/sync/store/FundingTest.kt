package org.ghost.sync.store

import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.CapabilitySource
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.KeyKind
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.RelayId
import org.ghost.sync.api.SyncChange
import org.ghost.sync.api.SyncTransaction
import org.ghost.sync.store.SyncWorld.Companion.DAY
import org.ghost.sync.store.SyncWorld.Companion.HOUR
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `Funding` and `sync_namespace_fund` (Phase 10 design §7.5 item 1, §9 migration 6): a flag in the
 * sync database that says this client funds the namespace. The flag is the whole of it: nothing is
 * redeemed, registered or stored by setting it, which these tests pin from the outside (the counts
 * and needs do not move) because the channel engine's T40 argument rests on it. What the flag
 * changes for the needs and for the registration step is tested with them
 * ([RegisterCapabilityTest], [RegistrationStoreTest], `RegistrationStepTest`).
 */
class FundingTest {

    private fun SyncWorld.channelSet(): Pair<NamespaceId, List<RelayId>> {
        val relays = relays(1, 2, 3)
        val ns = namespace(1, relays, consumer = Consumer.CHANNEL, capabilitySource = CapabilitySource.LOCAL)
        return Pair(ns, relays)
    }

    private fun SyncWorld.isFunded(ns: NamespaceId): Boolean = tx { stores.funding.isFunded(it, ns) }

    @Test
    fun theFlagIsSetOnceReadBackAndClearedAndEveryCallIsIdempotent(): Unit = SyncWorld().use { w ->
        val (ns, _) = w.channelSet()
        assertFalse("a namespace starts unfunded", w.isFunded(ns))
        w.fund(ns)
        assertTrue(w.isFunded(ns))
        assertEquals(1L, w.count("sync_namespace_fund"))
        // Setting it again changes nothing, and the REPLACE guard of the table is never met (a plain
        // INSERT of an existing key would be refused, an INSERT OR IGNORE too).
        w.fund(ns)
        w.fund(ns, true)
        assertEquals(1L, w.count("sync_namespace_fund"))
        w.fund(ns, false)
        assertFalse(w.isFunded(ns))
        assertEquals(0L, w.count("sync_namespace_fund"))
        w.fund(ns, false)
        assertEquals(0L, w.count("sync_namespace_fund"))
        // The flag is per namespace.
        val other = w.namespace(2, w.relays(4, 5), consumer = Consumer.CHANNEL, capabilitySource = CapabilitySource.LOCAL)
        w.fund(ns)
        assertTrue(w.isFunded(ns))
        assertFalse(w.isFunded(other))
        // It is the database's fact: a process restart reads it back.
        w.reopen()
        assertTrue(w.isFunded(ns))
        assertFalse(w.isFunded(other))
    }

    @Test
    fun anUnknownNamespaceIsNotFundedAndCannotBe(): Unit = SyncWorld().use { w ->
        val unknown = TestBytes.namespace(77)
        assertFalse(w.isFunded(unknown))
        val e = assertThrows(IllegalStateException::class.java) { w.fund(unknown) }
        assertEquals("namespace is not registered", e.message)
        assertEquals(0L, w.count("sync_namespace_fund"))
        // Taking the flag off a namespace that has none is a no-op, whatever the namespace is.
        w.fund(unknown, false)
        assertEquals(0L, w.count("sync_namespace_fund"))
    }

    @Test
    fun theFlagIsPartOfTheCallersTransactionAndRollsBackWithIt(): Unit = SyncWorld().use { w ->
        val (ns, _) = w.channelSet()
        assertThrows(IllegalStateException::class.java) {
            w.tx { tx ->
                w.stores.funding.set(tx, ns, true)
                assertTrue(w.stores.funding.isFunded(tx, ns))
                throw IllegalStateException("the caller's transaction failed")
            }
        }
        assertFalse(w.isFunded(ns))
        // And the other way round: a removal that rolls back leaves the flag.
        w.fund(ns)
        assertThrows(IllegalStateException::class.java) {
            w.tx { tx ->
                w.stores.funding.set(tx, ns, false)
                throw IllegalStateException("the caller's transaction failed")
            }
        }
        assertTrue(w.isFunded(ns))
    }

    @Test
    fun aStaleOrForeignTransactionIsRefused(): Unit = SyncWorld().use { w ->
        val (ns, _) = w.channelSet()
        var leaked: SyncTransaction? = null
        w.tx { leaked = it }
        assertThrows(IllegalStateException::class.java) { w.stores.funding.set(checkNotNull(leaked), ns, true) }
        assertThrows(IllegalStateException::class.java) { w.stores.funding.isFunded(checkNotNull(leaked), ns) }
        assertFalse(w.isFunded(ns))
    }

    /**
     * Funding causes no traffic by itself (design §7.5 item 7; T40): marking a namespace funded moves
     * no count, creates no registration row and no operation, installs no capability, and reports no
     * need while nothing is pending. The only effect outside the table is the capability hint the
     * engine uses to refresh its pair snapshot, and it is sent when the flag changed, not otherwise.
     */
    @Test
    fun fundingIsAFlagNotAnAct(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.channelSet()
        relays.forEach {
            w.capability(it, ns, CapabilityKind.READ, expiresAt = w.now + 8 * DAY)
            w.capability(it, ns, CapabilityKind.WRITE, expiresAt = w.now + 8 * DAY)
        }
        val before = Triple(w.stores.counts().toString(), w.stores.capabilities.needed(), w.stores.registrations.pendingCount())
        val tables = listOf("outbox_op", "outbox_delivery", "relay_key_registration", "relay_capability", "relay_register_capability", "inbox_blob")
        val rows = tables.map { w.count(it) }
        w.hints.clear()
        w.fund(ns)
        assertEquals(listOf<Set<SyncChange>>(setOf(SyncChange.CAPABILITIES)), w.hints.toList())
        w.hints.clear()
        w.fund(ns)
        assertTrue("an unchanged flag sends no hint", w.hints.isEmpty())
        assertEquals(before, Triple(w.stores.counts().toString(), w.stores.capabilities.needed(), w.stores.registrations.pendingCount()))
        assertEquals(rows, tables.map { w.count(it) })
        w.hints.clear()
        w.fund(ns, false)
        assertEquals("taking the flag off is announced as putting it on is", listOf<Set<SyncChange>>(setOf(SyncChange.CAPABILITIES)), w.hints.toList())
        w.hints.clear()
        w.fund(ns, false)
        assertTrue("taking off a flag that is not there sends no hint", w.hints.isEmpty())
        assertEquals(before, Triple(w.stores.counts().toString(), w.stores.capabilities.needed(), w.stores.registrations.pendingCount()))
    }

    /** Every column of every registration row, as text, in key order. */
    private fun SyncWorld.registrationRows(): List<String> {
        val out = ArrayList<String>()
        sql.query(
            "SELECT relay_id || '|' || hex(namespace_id) || '|' || period_id || '|' || kind || '|' || state || '|' || inflight || '|' || " +
                "ifnull(lease_hour, '-') || '|' || attempts || '|' || next_attempt_minute || '|' || ifnull(valid_until_hour, '-') || '|' || " +
                "hex(request_id) || '|' || hex(verifier) FROM relay_key_registration ORDER BY relay_id, namespace_id, period_id, kind",
        ) { row -> out += row.string(0) }
        return out
    }

    /**
     * "Funding is a flag, not an act" holds for the registrations that are pending, too: setting the flag
     * or taking it off changes which capability serves them (so what is due), never the rows themselves, so
     * a funder's flag flips cannot move a relay-visible call time (T19, T40). The rows carry a refused
     * attempt's counter and a backoff that lies ahead, which is what a flip that re-armed them would reset.
     */
    @Test
    fun fundingNeverTouchesThePendingRegistrationRowsItChangesTheServiceOf(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.channelSet()
        for (relay in relays.take(2)) {
            w.tx { w.stores.registrations.request(it, relay, ns, 2975, KeyKind.DEPOSIT, TestBytes.of(32, 41)) }
            w.tx { w.stores.registrations.request(it, relay, ns, 2976, KeyKind.READ, TestBytes.of(32, 42)) }
        }
        w.raw("UPDATE relay_key_registration SET attempts = 3, next_attempt_minute = ?", Time.floorMinute(w.now) + 6 * HOUR)
        val rows = w.registrationRows()
        assertEquals(4, rows.size)
        assertEquals(
            "the rows carry a counter and a backoff that lies ahead",
            4L,
            w.count("relay_key_registration", "attempts = 3 AND next_attempt_minute > ?", w.now + HOUR),
        )
        w.fund(ns)
        assertEquals(rows, w.registrationRows())
        w.fund(ns, false)
        assertEquals(rows, w.registrationRows())
        w.fund(ns)
        w.fund(ns)
        assertEquals(rows, w.registrationRows())
    }

    /**
     * Only a channel namespace can be funded (Phase 10 review of S1a): the flag moves a namespace's
     * registrations from its write capability to a second, token-bought registration capability, which for a
     * Phase 9 owner namespace would double its token spend without anything saying so. Nothing of the
     * namespace changes when the call is refused, and taking the flag off is a no-op whatever the consumer.
     */
    @Test
    fun onlyAChannelNamespaceCanBeFunded(): Unit = SyncWorld().use { w ->
        val relays = w.relays(1, 2)
        val others = Consumer.entries.filter { it != Consumer.CHANNEL }.mapIndexed { i, consumer ->
            consumer to w.namespace(10 + i, relays, listen = false, consumer = consumer)
        }
        assertEquals("every other consumer is checked", 4, others.size)
        for ((consumer, ns) in others) {
            w.hints.clear()
            val e = assertThrows(consumer.toString(), IllegalStateException::class.java) { w.fund(ns) }
            assertEquals("only a channel namespace can be funded", e.message)
            assertFalse(consumer.toString(), w.isFunded(ns))
            assertTrue("a refused call announces nothing", w.hints.isEmpty())
            w.fund(ns, false)
        }
        assertEquals(0L, w.count("sync_namespace_fund"))
        // The channel namespace of the same world can; a refused call left the transaction usable.
        val channel = w.namespace(20, relays, listen = false, consumer = Consumer.CHANNEL, capabilitySource = CapabilitySource.LOCAL)
        w.fund(channel)
        assertTrue(w.isFunded(channel))
        // A channel namespace of source REDEEM is a funder's too (the API does not read the source).
        val redeem = w.namespace(21, relays, listen = false, consumer = Consumer.CHANNEL, capabilitySource = CapabilitySource.REDEEM)
        w.fund(redeem)
        assertEquals(2L, w.count("sync_namespace_fund"))
        // The kind of check is the same as for an unregistered one: the registration comes first.
        assertEquals("namespace is not registered", assertThrows(IllegalStateException::class.java) { w.fund(TestBytes.namespace(77)) }.message)
    }

    /**
     * A namespace that only the funding flag still names: removing it ends the funding, and the capability
     * hint says so, because which needs the engine's snapshot reports depends on the flag.
     */
    @Test
    fun removingAFundedNamespaceThatHoldsNoCapabilitySendsTheCapabilityHint(): Unit = SyncWorld().use { w ->
        val (ns, _) = w.channelSet()
        w.fund(ns)
        w.hints.clear()
        assertTrue(w.tx { w.stores.namespaces.remove(it, ns) })
        assertEquals(0L, w.count("sync_namespace_fund"))
        assertTrue("dropping the flag alone announces a capability change", w.hints.any { SyncChange.CAPABILITIES in it })
        // And an unfunded namespace with nothing to drop does not.
        val other = w.namespace(2, w.relays(4, 5), consumer = Consumer.CHANNEL, capabilitySource = CapabilitySource.LOCAL)
        w.hints.clear()
        assertTrue(w.tx { w.stores.namespaces.remove(it, other) })
        assertTrue("nothing capability-related changed", w.hints.none { SyncChange.CAPABILITIES in it })
    }

    /** Removing a namespace ends its funding and its registration capabilities (they are capabilities of a namespace that is gone). */
    @Test
    fun removingTheNamespaceEndsItsFundingAndItsRegistrationCapabilities(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.channelSet()
        w.fund(ns)
        relays.forEach { w.capability(it, ns, CapabilityKind.REGISTER, expiresAt = w.now + 8 * DAY) }
        w.capability(relays[0], ns, CapabilityKind.WRITE, expiresAt = w.now + 8 * DAY)
        assertEquals(3L, w.count("relay_register_capability"))
        w.hints.clear()
        assertTrue(w.tx { w.stores.namespaces.remove(it, ns) })
        assertEquals(0L, w.count("relay_register_capability"))
        assertEquals(0L, w.count("relay_capability"))
        assertEquals(0L, w.count("sync_namespace_fund"))
        assertTrue("the capability hint follows", w.hints.any { SyncChange.CAPABILITIES in it })
        // No tombstone is left, so the namespace row went with them (Namespaces.remove deletes it when nothing refers to it).
        assertEquals(0L, w.count("sync_namespace"))
        assertFalse(w.isFunded(ns))
    }

    @Test
    fun aRemovedNamespaceThatKeepsTombstonesKeepsItsRowButNoFundingAndGcWaitsForNothingElse(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.channelSet()
        w.fund(ns)
        relays.forEach { w.capability(it, ns, CapabilityKind.REGISTER, expiresAt = w.now + 8 * DAY) }
        w.raw("INSERT INTO inbox_blob(namespace_id, blob_hash, state, retain_until_day) VALUES (?, ?, 'done', ?)", ns, w.hashOf(1), (Time.day(w.now) / 7 + 3) * 7)
        assertTrue(w.tx { w.stores.namespaces.remove(it, ns) })
        assertEquals("the tombstone keeps the namespace row", 1L, w.count("sync_namespace"))
        assertFalse(w.isFunded(ns))
        assertEquals(0L, w.count("relay_register_capability"))
        // Once the tombstone is collected the garbage collector deletes the row, funded or not.
        w.clock.advance(30 * DAY)
        w.tx { w.gc.pass(it, w.now) }
        assertEquals(0L, w.count("sync_namespace"))
        assertNull(w.long("SELECT 1 FROM sync_namespace_fund"))
    }

    /** A funded namespace with a pending registration is write work of nobody: the flag, not the source, routes it to REGISTER. */
    @Test
    fun theFlagDecidesWhichKindOfNeedARegistrationRaises(): Unit = SyncWorld().use { w ->
        val relays = w.relays(1, 2)
        val ns = w.namespace(1, relays, listen = false, consumer = Consumer.CHANNEL, capabilitySource = CapabilitySource.REDEEM)
        val week = Time.week(w.now)
        w.tx { w.stores.registrations.request(it, relays[0], ns, week, KeyKind.DEPOSIT, TestBytes.of(32, 41)) }
        assertEquals(listOf(CapabilityKind.WRITE), w.stores.capabilities.needed().map { it.kind })
        w.fund(ns)
        assertEquals(listOf(CapabilityKind.REGISTER), w.stores.capabilities.needed().map { it.kind })
        w.fund(ns, false)
        assertEquals(listOf(CapabilityKind.WRITE), w.stores.capabilities.needed().map { it.kind })
    }
}
