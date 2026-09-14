package org.ghost.entitlement.engine

import org.ghost.entitlement.T0
import org.ghost.entitlement.TestBytes
import org.ghost.entitlement.TestOnions
import org.ghost.entitlement.WEEK0
import org.ghost.entitlement.World
import org.ghost.entitlement.api.ActivationResult
import org.ghost.entitlement.api.ActivationState
import org.ghost.entitlement.api.RestoreResult
import org.ghost.entitlement.port.InviteTokenCheck
import org.ghost.entitlement.store.InviteStore
import org.ghost.entitlement.store.PurchaseStore
import org.ghost.identity.DropSeal
import org.ghost.identity.Invite
import org.ghost.identity.RootEntropy
import org.ghost.network.EntitlementCrypto
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.RelayEntry
import org.ghost.sync.store.Time
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The drop scan after an identity restore (design §8.4, §19.26): the drops of invite indices 0..7 are
 * listened to for 5 weeks through `:sync` (`ent_state.restore_scan_until_day`), a credit sent to one
 * of them becomes a refresh flow like any received credit, new invites continue at index 8, a crash
 * anywhere in the restore ends with the scan owed or with nothing, and GC ends the scan. The scan is
 * owed for the restored root only, installed by a relay session with a trusted clock, which fixes its
 * end, and listened on the slot relays of one drop-blob lifetime before the install (§19.26 point 7,
 * review RS-1 … RS-3).
 */
class RestoreScanTest {

    private val until = Grid.day(T0) + 35

    private fun World.mnemonic(): List<String> = identity.root.toMnemonic()

    private fun World.scanDay(): Long? {
        var day: Long? = null
        sql.query("SELECT restore_scan_until_day FROM ent_state WHERE id = 1") { day = if (it.isNull(0)) null else it.long(0) }
        return day
    }

    private fun World.owed(): Boolean = count("SELECT count(*) FROM ent_state WHERE restore_scan_root IS NOT NULL") == 1L

    private fun World.identityNamespaces(): Long = count("SELECT count(*) FROM sync_namespace WHERE consumer = ?1", listOf(Consumer.IDENTITY.code))

    /** A relay session's pass with a trusted clock, where an owed scan is installed. */
    private fun World.trustedPass(e: EntitlementEngine = engine) = e.relayPass(relaySession())

    private fun World.listening(index: Int): Boolean =
        count(
            "SELECT count(*) FROM sync_namespace WHERE namespace_id = ?1 AND listening = 1 AND consumer = ?2",
            listOf(identity.root.inviteDropNamespace(index), Consumer.IDENTITY.code),
        ) == 1L

    private fun World.relaysOf(index: Int): Set<Long> {
        val out = HashSet<Long>()
        sql.query("SELECT relay_id FROM namespace_relay WHERE namespace_id = ?1", listOf(identity.root.inviteDropNamespace(index))) { out += it.long(0) }
        return out
    }

    private fun World.fetched(ns: ByteArray, blob: ByteArray) {
        val hash = TestBytes.sha256(blob)
        tx { t ->
            t.sql.exec("INSERT INTO inbox_blob(namespace_id, blob_hash, state, retain_until_day) VALUES (?1, ?2, 'listed', 0)", listOf(ns, hash))
            t.sql.exec("UPDATE inbox_blob SET state = 'fetched', ciphertext = ?1, fetch_seq = 1 WHERE namespace_id = ?2 AND blob_hash = ?3", listOf(blob, ns, hash))
        }
    }

    @Test
    fun aRestoreListensToTheDropsOfInvites0To7ForFiveWeeks(): Unit = World().use { w ->
        // A pass before the restore settles "nothing owed" in this process; the restore owes the scan anew.
        w.trustedPass()
        assertEquals(RestoreResult.RESTORED, w.engine.restore(w.mnemonic()))
        assertTrue(w.identity.exists)
        assertEquals(listOf("restore"), w.identity.log)
        assertTrue(w.owed())
        assertNull("the end is fixed at the install", w.scanDay())
        assertEquals("indices 0..7 are reserved with the owe", 8L, w.count("SELECT next_invite_index FROM ent_state"))
        w.trustedPass()
        assertEquals(until, w.scanDay())
        val rows = w.tx { w.ctx().invites.all(it) }
        assertEquals((0..7).toList(), rows.map { it.index })
        for (row in rows) {
            assertEquals(InviteStore.CREATED, row.state)
            assertNull("the payload of a pre-restore invite is unknown", row.payload())
            assertArrayEquals(w.identity.root.inviteDropNamespace(row.index), row.dropNamespace())
            assertEquals(until, row.listenUntilDay)
            assertTrue(w.listening(row.index))
            assertEquals("the relays of every ES slot of the scan, not the relay in no slot", w.relayIds.map { it.value }.toSet(), w.relaysOf(row.index))
        }
        assertEquals(8L, w.count("SELECT next_invite_index FROM ent_state"))
    }

    @Test
    fun theScanNamespacesRaiseReadNeedsThatTheRedeemLaneFulfils(): Unit = World().use { w ->
        for (slot in 0..2) w.addAccess(WEEK0, slot, 8)
        w.random.prfValue = 0.0
        w.engine.restore(w.mnemonic())
        // The pass installs the scan, then its lane step meets the new read needs.
        w.trustedPass()
        assertEquals("8 drops x 3 slot relays", 24, w.redeem.calls.size)
        assertEquals(8, w.redeem.calls.map { it.namespace }.toSet().size)
        assertEquals(24L, w.count("SELECT count(*) FROM relay_capability"))
    }

    @Test
    fun aCreditSentToAPreRestoreInviteBecomesARefreshFlow(): Unit = World().use { w ->
        w.engine.restore(w.mnemonic())
        w.trustedPass()
        val keys = w.identity.root.inviteKeys(5)
        val credit = TestBytes.token(4242)
        w.crypto.register(credit, EntitlementCrypto.KIND_CREDIT, Grid.creditEpoch(WEEK0))
        w.fetched(keys.dropNamespace, DropSeal.sealCredit(credit, keys.drop.publicKey, keys.dropNamespace))
        w.ctx().dropSteps.receive(w.clock.now)
        val refresh = w.purchases().single()
        assertEquals(PurchaseStore.REFRESH, refresh.kind)
        assertArrayEquals(credit, refresh.inputToken())
        assertEquals(InviteStore.CREDITED, checkNotNull(w.tx { w.ctx().invites.get(it, 5) }).state)
        assertFalse("the credited drop stops being listened", w.listening(5))
        assertTrue("the other drops are still listened", (0..7).filter { it != 5 }.all { w.listening(it) })
    }

    /**
     * Q31 with the restore scan (§19.26): a scanned drop's invite expiry is unknown, so both its refresh
     * times are one draw 1–14 days after the scan's end; a credit read at the install and one read on
     * the scan's last day are due at that same time, and a later restore that extends the scan draws the
     * times of the drops still without a credit anew.
     */
    @Test
    fun aScannedDropIsRefreshedAfterTheScanEndsWhateverTheRead(): Unit = World().use { w ->
        w.random.uniformValue = 0.25
        w.engine.restore(w.mnemonic())
        w.trustedPass()
        val at = Time.ceilMinute(until * Grid.DAY + Grid.DAY + (0.25 * 13 * Grid.DAY).toLong())
        for (row in w.tx { w.ctx().invites.all(it) }) {
            assertEquals(at, row.refreshMinute)
            assertEquals(at, row.lateRefreshMinute)
        }
        val epoch = Grid.creditEpoch(WEEK0)
        for ((index, readAt) in listOf(5 to w.clock.now, 6 to until * Grid.DAY - Grid.HOUR)) {
            w.clock.now = readAt
            val keys = w.identity.root.inviteKeys(index)
            val credit = TestBytes.token(4300 + index)
            w.crypto.register(credit, EntitlementCrypto.KIND_CREDIT, epoch)
            w.fetched(keys.dropNamespace, DropSeal.sealCredit(credit, keys.drop.publicKey, keys.dropNamespace))
            w.ctx().dropSteps.receive(readAt)
        }
        assertEquals("the read picks no time", listOf(at, at), w.purchases().map { it.nextDueMinute })
        // The identity wiped, the same seed restored on the scan's last day: the scan is extended.
        w.identity.exists = false
        w.random.uniformValue = 0.75
        assertEquals(RestoreResult.RESTORED, w.engine.restore(w.mnemonic()))
        w.trustedPass()
        val extended = until + 34
        assertEquals(extended, w.scanDay())
        val again = Time.ceilMinute(extended * Grid.DAY + Grid.DAY + (0.75 * 13 * Grid.DAY).toLong())
        for (row in w.tx { w.ctx().invites.all(it) }) {
            val credited = row.index == 5 || row.index == 6
            assertEquals(if (credited) InviteStore.CREDITED else InviteStore.CREATED, row.state)
            assertEquals(if (credited) until else extended, row.listenUntilDay)
            assertEquals(if (credited) at else again, row.refreshMinute)
            assertEquals(row.refreshMinute, row.lateRefreshMinute)
        }
    }

    @Test
    fun aNewInviteAfterARestoreTakesIndex8EvenBeforeTheInstall(): Unit = World().use { w ->
        w.engine.restore(w.mnemonic())
        w.addTokens("invite", Grid.inviteEpoch(WEEK0), 1)
        val text = checkNotNull(w.engine.createInvite((Grid.day(T0) + 14).toInt()))
        val invite = Invite.parseAndVerify(text, T0, InviteTokenCheck(w.crypto), Invite.InMemoryNonceStore())
        assertArrayEquals(w.identity.root.inviteDropNamespace(8), invite.dropNamespace)
        assertEquals(9L, w.count("SELECT next_invite_index FROM ent_state"))
        w.trustedPass()
        assertEquals((0..8).toList(), w.tx { t -> w.ctx().invites.all(t) }.map { it.index })
    }

    @Test
    fun aRefusedMnemonicAnExistingIdentityOrNoScheduleRecordNothing(): Unit = World().use { w ->
        val words = w.mnemonic().toMutableList()
        words[3] = "notaword"
        assertEquals(RestoreResult.REFUSED_MNEMONIC, w.engine.restore(words))
        assertEquals(RestoreResult.REFUSED_MNEMONIC, w.engine.restore(w.mnemonic().take(12)))
        assertFalse(w.identity.exists)
        assertFalse(w.owed())
        assertEquals(0L, w.count("SELECT count(*) FROM ent_invite"))
        w.identity.exists = true
        assertEquals(RestoreResult.ALREADY_ACTIVE, w.engine.restore(w.mnemonic()))
        assertFalse(w.owed())
        World({ it.failSummary = "internal" }).use { v ->
            assertEquals(RestoreResult.UNAVAILABLE, v.engine.restore(v.mnemonic()))
            assertFalse(v.identity.exists)
        }
    }

    @Test
    fun aPendingInviteActivationRefusesARestore(): Unit = World().use { w ->
        w.userCalls.deferred = true
        w.engine.activate(w.inviteText())
        w.identity.exists = false
        assertEquals(RestoreResult.ALREADY_ACTIVE, w.engine.restore(w.mnemonic()))
        assertFalse(w.owed())
    }

    @Test
    fun aCrashBeforeTheIdentityWasStoredEndsWithTheRestoreDoneAgain(): Unit = World().use { w ->
        w.identity.failRestore = true
        runCatching { w.engine.restore(w.mnemonic()) }
        assertFalse(w.identity.exists)
        assertTrue("the scan is owed before the identity exists", w.owed())
        assertEquals(0L, w.count("SELECT count(*) FROM ent_invite"))
        w.identity.failRestore = false
        // A new process: nothing is installed without an identity; the user restores again.
        val next = w.newProcess()
        next.onForeground()
        w.trustedPass(next)
        assertEquals(0L, w.count("SELECT count(*) FROM ent_invite"))
        w.clock.now += 3 * Grid.HOUR
        assertEquals(RestoreResult.RESTORED, next.restore(w.mnemonic()))
        w.trustedPass(next)
        assertEquals(until, w.scanDay())
        assertEquals(8L, w.count("SELECT count(*) FROM ent_invite WHERE state = 'created'"))
    }

    @Test
    fun aCrashInsideTheInstallIsCompletedByTheNextProcess(): Unit = World().use { w ->
        w.engine.restore(w.mnemonic())
        w.identity.failInviteKeys = true
        runCatching { w.trustedPass() }
        assertTrue(w.identity.exists)
        assertEquals(0L, w.count("SELECT count(*) FROM ent_invite"))
        w.identity.failInviteKeys = false
        // Before any relay session of the new process, an invite creation never takes a scanned index.
        val next = w.newProcess()
        w.addTokens("invite", Grid.inviteEpoch(WEEK0), 1)
        val text = checkNotNull(next.createInvite((Grid.day(T0) + 14).toInt()))
        val invite = Invite.parseAndVerify(text, T0, InviteTokenCheck(w.crypto), Invite.InMemoryNonceStore())
        assertArrayEquals(w.identity.root.inviteDropNamespace(8), invite.dropNamespace)
        w.trustedPass(next)
        assertEquals((0..8).toList(), w.tx { t -> w.ctx().invites.all(t) }.map { it.index })
        // A later session of yet another process changes nothing.
        val before = w.count("SELECT count(*) FROM namespace_relay")
        w.trustedPass(w.newProcess())
        assertEquals(before, w.count("SELECT count(*) FROM namespace_relay"))
        assertEquals(9L, w.count("SELECT count(*) FROM ent_invite"))
    }

    /** Review RS-2: nothing listens before a relay session with a trusted clock fixed the scan's end. */
    @Test
    fun theScanIsInstalledByTheFirstRelaySessionWithATrustedClock(): Unit = World().use { w ->
        w.engine.restore(w.mnemonic())
        assertEquals(0L, w.identityNamespaces())
        w.engine.onForeground()
        w.engine.relayPass(w.relaySession(trusted = false))
        assertEquals(0L, w.identityNamespaces())
        w.trustedPass()
        assertEquals(8L, w.identityNamespaces())
        assertEquals(until, w.scanDay())
    }

    /** Review RS-2: a device clock 400 days ahead at the restore does not make the scan listen for 435 days. */
    @Test
    fun aDeviceClockAheadAtTheRestoreDoesNotStretchTheScan(): Unit = World().use { w ->
        w.clock.now = T0 + 400 * Grid.DAY
        w.engine.restore(w.mnemonic())
        w.clock.now = T0
        w.trustedPass(w.newProcess())
        assertEquals("the end is fixed under a trusted clock", until, w.scanDay())
        assertTrue(w.tx { w.ctx().invites.all(it) }.all { it.listenUntilDay == until })
        w.ctx().gc.run(until * Grid.DAY)
        assertTrue((0..7).none { w.listening(it) })
        assertNull(w.scanDay())
    }

    /** Review RS-2: a device clock 400 days behind at the restore does not end the scan at the first GC. */
    @Test
    fun aDeviceClockBehindAtTheRestoreDoesNotEndTheScanEarly(): Unit = World().use { w ->
        w.clock.now = T0 - 400 * Grid.DAY
        w.engine.restore(w.mnemonic())
        w.clock.now = T0
        w.trustedPass(w.newProcess())
        w.ctx().gc.run(T0 + Grid.HOUR)
        assertTrue("the scan runs 5 weeks from its install", (0..7).all { w.listening(it) })
        assertEquals(until, w.scanDay())
    }

    /** Review RS-1: the owe of a crashed restore is not installed for an invitee's identity (§8.3 step 3). */
    @Test
    fun aCrashedRestoreFollowedByAnInviteActivationRegistersNothing(): Unit = World().use { w ->
        w.identity.failRestore = true
        runCatching { w.engine.restore(w.mnemonic()) }
        w.identity.failRestore = false
        // Instead of restoring again, the user activates an invite; its trial stays pending.
        w.userCalls.deferred = true
        assertEquals(ActivationResult.PENDING, w.engine.activate(w.inviteText()))
        val next = w.newProcess()
        next.onForeground()
        w.trustedPass(next)
        assertEquals(ActivationState.PENDING, next.activationState())
        assertEquals("no namespace while the activation is pending (§8.3 step 3)", 0L, w.identityNamespaces())
        assertEquals(0L, w.count("SELECT count(*) FROM ent_invite"))
        assertFalse("the activation ends the owe", w.owed())
        assertNull(w.scanDay())
    }

    /** Review RS-1: an identity of another root (genesis, outside the engine) never gets the owed scan. */
    @Test
    fun anIdentityOfAnotherRootAfterACrashedRestoreScansNothing(): Unit = World().use { w ->
        w.identity.failRestore = true
        runCatching { w.engine.restore(w.mnemonic()) }
        w.identity.failRestore = false
        w.identity.root = RootEntropy.fromRaw(ByteArray(32) { (it * 13 + 1).toByte() })
        w.identity.exists = true
        val next = w.newProcess()
        next.onForeground()
        w.trustedPass(next)
        assertEquals(0L, w.identityNamespaces())
        assertEquals(0L, w.count("SELECT count(*) FROM ent_invite"))
        assertFalse("an owe of another root is dropped", w.owed())
        assertNull(w.scanDay())
    }

    @Test
    fun rowsOfAnotherRootAreReplacedAndItsDropRetired(): Unit = World().use { w ->
        // An invite of an earlier identity of this database, at index 0.
        val other = World.INVITER.inviteKeys(0)
        w.tx { t ->
            w.ctx().invites.insert(t, 0, ByteArray(Invite.PAYLOAD_BYTES) { 1 }, other.dropNamespace, Grid.day(T0) + 60, T0 + 20 * Grid.DAY, T0 + 61 * Grid.DAY)
            w.stores.namespaces.register(t, org.ghost.sync.api.NamespaceId(other.dropNamespace), Consumer.IDENTITY, w.relayIds.toSet(), true)
        }
        w.engine.restore(w.mnemonic())
        w.trustedPass()
        val row = checkNotNull(w.tx { w.ctx().invites.get(it, 0) })
        assertArrayEquals(w.identity.root.inviteDropNamespace(0), row.dropNamespace())
        assertNull(row.payload())
        assertEquals(0L, w.count("SELECT count(*) FROM sync_namespace WHERE namespace_id = ?1 AND listening = 1", listOf(other.dropNamespace)))
        assertEquals(8L, w.count("SELECT count(*) FROM ent_invite"))
    }

    @Test
    fun theScanListensOnTheRelaysOfEverySlotValidInItsWeeks(): Unit = World({ c ->
        // Slot 2 moves to the relay in no slot from week + 2; a slot that starts after the scan counts not.
        c.slots = listOf(
            EntitlementCrypto.Slot(0, 0, 0, c.onions[0]),
            EntitlementCrypto.Slot(1, 0, WEEK0 + 5, c.onions[1]),
            EntitlementCrypto.Slot(2, 0, WEEK0 + 2, c.onions[2]),
            EntitlementCrypto.Slot(2, WEEK0 + 2, 0, TestOnions.of(9)),
            EntitlementCrypto.Slot(1, WEEK0 + 6, 0, TestOnions.of(9)),
        )
    }).use { w ->
        w.engine.restore(w.mnemonic())
        w.trustedPass()
        assertEquals((w.relayIds + w.outsider).map { it.value }.toSet(), w.relaysOf(3))
    }

    /**
     * Review RS-3: slot 2 left relay C when the restore's week began, so C still stores the blobs written
     * to slot 2 in the 30 days before (the drop blob's TTL); slot 1 left relay B more than 30 days before,
     * so B stores none of them any more.
     */
    @Test
    fun theScanListensOnTheSlotRelaysOfTheBlobLifetimeBeforeTheRestore(): Unit = World({ c ->
        c.slots = listOf(
            EntitlementCrypto.Slot(0, 0, 0, c.onions[0]),
            EntitlementCrypto.Slot(1, 0, WEEK0 - 5, c.onions[1]),
            EntitlementCrypto.Slot(1, WEEK0 - 5, 0, TestOnions.of(9)),
            EntitlementCrypto.Slot(2, 0, WEEK0, c.onions[2]),
            EntitlementCrypto.Slot(2, WEEK0, 0, TestOnions.of(5)),
        )
    }).use { w ->
        w.engine.restore(w.mnemonic())
        w.trustedPass()
        assertEquals(listOf(w.relayIds[0], w.relayIds[2], w.outsider).map { it.value }.toSet(), w.relaysOf(3))
    }

    @Test
    fun aSlotRelayAddedToTheDirectoryLaterIsListenedFromTheNextProcess(): Unit = World({ c ->
        c.slots = listOf(EntitlementCrypto.Slot(0, 0, 0, c.onions[0]), EntitlementCrypto.Slot(1, 0, 0, c.onions[1]), EntitlementCrypto.Slot(2, 0, 0, TestOnions.of(5)))
    }).use { w ->
        w.engine.restore(w.mnemonic())
        w.trustedPass()
        assertEquals(w.relayIds.take(2).map { it.value }.toSet(), w.relaysOf(1))
        val added = w.tx { w.stores.relayDirectory.upsert(it, listOf(RelayEntry(TestOnions.of(5), w.operator(1), RelayEntry.Source.CONFIG))) }
        w.trustedPass(w.newProcess())
        assertEquals((w.relayIds.take(2) + checkNotNull(added[TestOnions.of(5)])).map { it.value }.toSet(), w.relaysOf(1))
    }

    @Test
    fun theScanEndsOnItsLastDayAndGcForgetsIt(): Unit = World().use { w ->
        w.engine.restore(w.mnemonic())
        w.trustedPass()
        w.ctx().gc.run(until * Grid.DAY - 1)
        assertEquals(until, w.scanDay())
        assertTrue((0..7).all { w.listening(it) })
        w.ctx().gc.run(until * Grid.DAY)
        assertNull(w.scanDay())
        assertFalse(w.owed())
        assertTrue(w.tx { w.ctx().invites.all(it) }.all { it.state == InviteStore.CLOSED })
        assertTrue((0..7).none { w.listening(it) })
        w.ctx().gc.run(until * Grid.DAY)
        assertEquals(0L, w.count("SELECT count(*) FROM ent_invite"))
        // The next process owes nothing any more.
        w.trustedPass(w.newProcess())
        assertEquals(0L, w.count("SELECT count(*) FROM ent_invite"))
        assertEquals("new invites still never reuse indices 0..7", 8L, w.count("SELECT next_invite_index FROM ent_state"))
    }
}
