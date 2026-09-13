package org.ghost.entitlement.engine

import org.ghost.entitlement.T0
import org.ghost.entitlement.TestBytes
import org.ghost.entitlement.WEEK0
import org.ghost.entitlement.World
import org.ghost.entitlement.port.InviteTokenCheck
import org.ghost.entitlement.store.InviteStore
import org.ghost.entitlement.store.PurchaseStore
import org.ghost.identity.DropSeal
import org.ghost.identity.Invite
import org.ghost.network.EntitlementCrypto
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.OperationId
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Drops (design §8.5, §9.3, §19.8, §19.12): an invitee writes exactly one sealed blob at its
 * pre-drawn time (a credit or a dummy), none without coverage; an inviter turns a received credit
 * into a refresh flow and stops listening; invite creation spends one invite token and draws drop
 * slots over two operators.
 */
class DropStepsTest {

    /** An activated invitee at its drop time with coverage of that week. */
    private fun World.atDropTime(credit: Boolean): ByteArray? {
        engine.activate(inviteText())
        val t = checkNotNull(tx { ctx().invites.dropTarget(it) })
        clock.now = t.dropMinute
        addAccess(Grid.week(t.dropMinute), 0, 1)
        return if (credit) addTokens("credit", Grid.creditEpoch(WEEK0), 1).single() else null
    }

    private fun World.opened(): DropSeal.Opened {
        val op = checkNotNull(checkNotNull(tx { ctx().invites.dropTarget(it) }).operationId())
        var blob: ByteArray? = null
        sql.query("SELECT ciphertext FROM outbox_op WHERE operation_id = ?1", listOf(op)) { blob = it.blob(0) }
        assertEquals(1024, checkNotNull(blob).size)
        return DropSeal.open(checkNotNull(blob), World.INVITER.inviteDropKeyPair(0), World.INVITER.inviteDropNamespace(0))
    }

    @Test
    fun theInviteeSealsItsCreditAtTheDrawnTime(): Unit = World().use { w ->
        val credit = checkNotNull(w.atDropTime(credit = true))
        w.clock.now -= 60
        w.ctx().dropSteps.sendDue(w.clock.now)
        assertEquals("before t_drop nothing", InviteStore.WAITING, checkNotNull(w.tx { w.ctx().invites.dropTarget(it) }).state)
        w.clock.now += 60
        w.ctx().dropSteps.sendDue(w.clock.now)
        assertEquals(InviteStore.ENQUEUED, checkNotNull(w.tx { w.ctx().invites.dropTarget(it) }).state)
        val opened = w.opened() as DropSeal.Opened.Credit
        assertArrayEquals(credit, opened.token)
        assertTrue("the credit left the device", w.tokenRows("credit").isEmpty())
        assertEquals(0L, w.count("SELECT listening FROM sync_namespace WHERE namespace_id = ?1", listOf(World.INVITER.inviteDropNamespace(0))))
    }

    @Test
    fun withoutACreditTheInviteeSealsAnIndistinguishableDummy(): Unit = World().use { w ->
        w.atDropTime(credit = false)
        w.ctx().dropSteps.sendDue(w.clock.now)
        assertSame(DropSeal.Opened.Dummy, w.opened())
    }

    @Test
    fun withoutCoverageNothingIsWritten(): Unit = World().use { w ->
        w.engine.activate(w.inviteText())
        val t = checkNotNull(w.tx { w.ctx().invites.dropTarget(it) })
        w.clock.now = t.dropMinute
        w.ctx().dropSteps.sendDue(w.clock.now)
        assertNull(w.tx { w.ctx().invites.dropTarget(it) })
        assertEquals(0L, w.count("SELECT count(*) FROM outbox_op"))
    }

    @Test
    fun aDecidedOutcomeIsReleasedAndTheDropNamespaceRetired(): Unit = World().use { w ->
        w.atDropTime(credit = false)
        w.ctx().dropSteps.sendDue(w.clock.now)
        val op = checkNotNull(checkNotNull(w.tx { w.ctx().invites.dropTarget(it) }).operationId())
        w.ctx().dropSteps.settleSent()
        assertNotNull("undecided: kept", w.tx { w.ctx().invites.dropTarget(it) })
        assertTrue(w.tx { w.stores.outbox.cancel(it, OperationId(op)) })
        w.ctx().dropSteps.settleSent()
        assertNull(w.tx { w.ctx().invites.dropTarget(it) })
        assertEquals(1L, w.count("SELECT released FROM outbox_op WHERE operation_id = ?1", listOf(op)))
        assertEquals(0L, w.count("SELECT count(*) FROM namespace_relay WHERE namespace_id = ?1", listOf(World.INVITER.inviteDropNamespace(0))))
    }

    @Test
    fun anInviteSpendsOneInviteTokenAndListensOnDropSlotsOfTwoOperators(): Unit = World().use { w ->
        w.identity.exists = true
        assertNull("no invite token", w.engine.createInvite((Grid.day(T0) + 14).toInt()))
        w.addTokens("invite", Grid.inviteEpoch(WEEK0), 1)
        assertNull("expiry beyond the token's acceptance window", w.engine.createInvite(Invite.maxExpiryDay(Grid.inviteEpoch(WEEK0)).toInt() + 1))
        val text = checkNotNull(w.engine.createInvite((Grid.day(T0) + 14).toInt()))
        val invite = Invite.parseAndVerify(text, T0, InviteTokenCheck(w.crypto), Invite.InMemoryNonceStore())
        assertEquals(3, invite.dropSlots.toSet().size)
        assertTrue(invite.dropSlots.all { it in 0..2 })
        assertArrayEquals(w.identity.root.inviteDropNamespace(0), invite.dropNamespace)
        assertTrue(w.tokenRows("invite").isEmpty())
        assertEquals(1L, w.count("SELECT next_invite_index FROM ent_state"))
        val row = checkNotNull(w.tx { w.ctx().invites.get(it, 0) })
        assertEquals(InviteStore.CREATED, row.state)
        assertEquals(invite.expiryDay + 56, row.listenUntilDay)
        assertEquals(1L, w.count("SELECT listening FROM sync_namespace WHERE namespace_id = ?1", listOf(invite.dropNamespace)))
        assertEquals(3L, w.count("SELECT count(*) FROM namespace_relay WHERE namespace_id = ?1", listOf(invite.dropNamespace)))
    }

    private fun World.fetched(ns: ByteArray, blob: ByteArray) {
        val hash = TestBytes.sha256(blob)
        tx { t ->
            t.sql.exec("INSERT INTO inbox_blob(namespace_id, blob_hash, state, retain_until_day) VALUES (?1, ?2, 'listed', 0)", listOf(ns, hash))
            t.sql.exec("UPDATE inbox_blob SET state = 'fetched', ciphertext = ?1, fetch_seq = 1 WHERE namespace_id = ?2 AND blob_hash = ?3", listOf(blob, ns, hash))
        }
    }

    @Test
    fun aReceivedCreditBecomesARefreshFlowAndIsExchangedInItsOwnQuietRun(): Unit = World().use { w ->
        w.identity.exists = true
        w.addTokens("invite", Grid.inviteEpoch(WEEK0), 1)
        val invite = Invite.parseAndVerify(checkNotNull(w.engine.createInvite((Grid.day(T0) + 14).toInt())), T0, InviteTokenCheck(w.crypto), Invite.InMemoryNonceStore())
        val credit = TestBytes.token(999)
        w.crypto.register(credit, EntitlementCrypto.KIND_CREDIT, Grid.creditEpoch(WEEK0))
        w.fetched(invite.dropNamespace, DropSeal.sealCredit(credit, invite.dropKey, invite.dropNamespace))
        w.ctx().dropSteps.receive(w.clock.now)
        val refresh = w.purchases().single()
        assertEquals(PurchaseStore.REFRESH, refresh.kind)
        assertArrayEquals(credit, refresh.inputToken())
        val due = checkNotNull(refresh.nextDueMinute)
        assertTrue(due >= T0 + Grid.DAY && due <= T0 + 14 * Grid.DAY + 60)
        assertEquals(InviteStore.CREDITED, checkNotNull(w.tx { w.ctx().invites.get(it, 0) }).state)
        assertEquals(0L, w.count("SELECT count(*) FROM sync_namespace WHERE namespace_id = ?1 AND listening = 1", listOf(invite.dropNamespace)))
        assertTrue("a received credit is never spendable before its refresh", w.tokenRows("credit").isEmpty())
        w.quiet()
        assertTrue(w.issuer.calls.isEmpty())
        w.clock.now = due
        w.quiet()
        assertEquals(1, w.issuer.named("refreshCredit").size)
        assertEquals(PurchaseStore.FINALIZED, checkNotNull(w.purchase(refresh.id())).state)
        assertEquals(listOf(Grid.creditEpoch(WEEK0)), w.tokenRows("credit").map { it.epoch })
    }

    @Test
    fun aDummyOrAStaleCreditIsConsumedAndDropped(): Unit = World().use { w ->
        w.identity.exists = true
        w.addTokens("invite", Grid.inviteEpoch(WEEK0), 1)
        val invite = Invite.parseAndVerify(checkNotNull(w.engine.createInvite((Grid.day(T0) + 14).toInt())), T0, InviteTokenCheck(w.crypto), Invite.InMemoryNonceStore())
        w.fetched(invite.dropNamespace, DropSeal.sealDummy(invite.dropKey, invite.dropNamespace))
        val stale = TestBytes.token(1000)
        w.crypto.register(stale, EntitlementCrypto.KIND_CREDIT, Grid.creditEpoch(WEEK0) - 2)
        val staleBlob = DropSeal.sealCredit(stale, invite.dropKey, invite.dropNamespace)
        w.ctx().dropSteps.receive(w.clock.now)
        assertEquals(1L, w.engine.counter(Counters.DROP_DUMMY))
        w.tx { t ->
            t.sql.exec(
                "INSERT INTO inbox_blob(namespace_id, blob_hash, state, retain_until_day) VALUES (?1, ?2, 'listed', 0)",
                listOf(invite.dropNamespace, TestBytes.sha256(staleBlob)),
            )
            t.sql.exec(
                "UPDATE inbox_blob SET state = 'fetched', ciphertext = ?1, fetch_seq = 2 WHERE namespace_id = ?2 AND blob_hash = ?3",
                listOf(staleBlob, invite.dropNamespace, TestBytes.sha256(staleBlob)),
            )
        }
        w.ctx().dropSteps.receive(w.clock.now)
        assertEquals(1L, w.engine.counter(Counters.CREDIT_DROPPED))
        assertTrue(w.purchases().isEmpty())
        assertEquals(InviteStore.CREATED, checkNotNull(w.tx { w.ctx().invites.get(it, 0) }).state)
        assertEquals(0L, w.count("SELECT count(*) FROM inbox_blob WHERE state = 'fetched'"))
        assertEquals(NamespaceId(invite.dropNamespace), NamespaceId(invite.dropNamespace))
    }
}
