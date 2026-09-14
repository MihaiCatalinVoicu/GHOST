package org.ghost.entitlement.engine

import org.ghost.entitlement.T0
import org.ghost.entitlement.TestBytes
import org.ghost.entitlement.WEEK0
import org.ghost.entitlement.World
import org.ghost.entitlement.port.InviteTokenCheck
import org.ghost.entitlement.store.InviteRow
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
 * Drops (design §8.5, §9.3, §19.8, §19.12, §19.26): an invitee writes exactly one sealed blob at its
 * pre-drawn time (a credit or a dummy), none without coverage; an inviter turns a received credit
 * into a refresh flow due at a time drawn with the invite, never at the read (Q31), and stops
 * listening; invite creation spends one invite token and draws drop slots over two operators.
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
        val expiry = Grid.day(T0) + 14
        val invite = Invite.parseAndVerify(checkNotNull(w.engine.createInvite(expiry.toInt())), T0, InviteTokenCheck(w.crypto), Invite.InMemoryNonceStore())
        // The two refresh times are drawn with the invite (Q31, §19.26): 1–14 days after the latest
        // drop window of an invitee of this invite, and 1–14 days after its listening ends.
        val row = checkNotNull(w.tx { w.ctx().invites.get(it, 0) })
        val lastDropEnd = Grid.start(Grid.week(expiry * Grid.DAY - 1) + 8)
        assertTrue(row.refreshMinute in lastDropEnd + Grid.DAY..lastDropEnd + 14 * Grid.DAY)
        assertTrue(row.lateRefreshMinute in (row.listenUntilDay + 1) * Grid.DAY..(row.listenUntilDay + 14) * Grid.DAY)
        val credit = TestBytes.token(999)
        w.crypto.register(credit, EntitlementCrypto.KIND_CREDIT, Grid.creditEpoch(WEEK0))
        w.fetched(invite.dropNamespace, DropSeal.sealCredit(credit, invite.dropKey, invite.dropNamespace))
        w.ctx().dropSteps.receive(w.clock.now)
        val refresh = w.purchases().single()
        assertEquals(PurchaseStore.REFRESH, refresh.kind)
        assertArrayEquals(credit, refresh.inputToken())
        val due = checkNotNull(refresh.nextDueMinute)
        assertEquals("read before the first refresh time: it waits for it", row.refreshMinute, due)
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

    /** An inviter whose invite 0 was created at T0 receives [credit], a credit of [epoch], at the current clock. */
    private fun World.receive(credit: ByteArray, epoch: Long) {
        identity.exists = true
        addTokens("invite", Grid.inviteEpoch(WEEK0), 1)
        val at = clock.now
        clock.now = T0
        val text = checkNotNull(engine.createInvite((Grid.day(T0) + 14).toInt()))
        clock.now = at
        val invite = Invite.parseAndVerify(text, T0, InviteTokenCheck(crypto), Invite.InMemoryNonceStore())
        crypto.register(credit, EntitlementCrypto.KIND_CREDIT, epoch)
        fetched(invite.dropNamespace, DropSeal.sealCredit(credit, invite.dropKey, invite.dropNamespace))
        ctx().dropSteps.receive(clock.now)
    }

    /**
     * The refresh due time of a credit of the current credit epoch read at [readAt], and the invite
     * row, for an invite whose refresh draws are [first] and [second] (the three draws before them
     * choose the drop slots, `DropSteps.create`).
     */
    private fun dueAfterReadAt(readAt: Long, first: Double = 0.0, second: Double = 0.5): Pair<Long?, InviteRow> = World().use { w ->
        w.random.uniforms.addAll(listOf(0.5, 0.5, 0.5, first, second))
        w.clock.now = readAt
        w.receive(TestBytes.token(1003), Grid.creditEpoch(WEEK0))
        val row = checkNotNull(w.tx { w.ctx().invites.get(it, 0) })
        Pair(w.purchases().singleOrNull()?.nextDueMinute, row)
    }

    @Test
    fun theRefreshTimeIsDrawnWithTheInviteNeverAtTheRead() {
        // Q31 (§19.26): the read is a relay-visible moment; the refresh time does not follow it.
        val (early, row) = dueAfterReadAt(T0 + Grid.DAY)
        val (later, _) = dueAfterReadAt(T0 + 30 * Grid.DAY + 17 * Grid.MINUTE)
        assertEquals("two reads before the first refresh time: the same due time", early, later)
        assertEquals(row.refreshMinute, early)
        // With the first draw 0 the first time lies before the listening ends, so a read can follow it.
        assertTrue(row.refreshMinute + Grid.MINUTE < row.listenUntilDay * Grid.DAY)
        val (afterFirst, _) = dueAfterReadAt(row.refreshMinute + Grid.MINUTE)
        assertEquals("a read after the first time: the second, drawn with the invite too", row.lateRefreshMinute, afterFirst)
        val (lateDraw, lateRow) = dueAfterReadAt(T0 + Grid.DAY, first = 0.9)
        assertTrue("a first time after the listening ends", lateRow.refreshMinute > lateRow.listenUntilDay * Grid.DAY)
        assertEquals(lateRow.refreshMinute, lateDraw)
    }

    @Test
    fun aCreditReceivedNearTheEndOfItsRefreshWindowIsRefreshedInsideIt(): Unit = World().use { w ->
        // Two days before credit epoch c_now + 1 starts, a credit of epoch c_now − 1 arrives: the
        // issuer refreshes it only until that start, so its refresh is due at the cut time (a
        // function of its epoch, never of the read).
        val next = Grid.start((Grid.creditEpoch(WEEK0) + 1) * 13)
        w.clock.now = next - 2 * Grid.DAY
        w.receive(TestBytes.token(1001), Grid.creditEpoch(WEEK0) - 1)
        val refresh = w.purchases().single()
        val due = checkNotNull(refresh.nextDueMinute)
        assertEquals("due at the cut time, inside the issuer's refresh window", next - 2 * Grid.DAY, due)
        w.clock.now = maxOf(w.clock.now, due)
        w.quiet()
        assertEquals(PurchaseStore.FINALIZED, checkNotNull(w.purchase(refresh.id())).state)
        assertEquals(listOf(Grid.creditEpoch(WEEK0) - 1), w.tokenRows("credit").map { it.epoch })
    }

    @Test
    fun aCreditReadAfterItsCutTimeIsDroppedNeverRefreshedAtTheRead(): Unit = World().use { w ->
        val next = Grid.start((Grid.creditEpoch(WEEK0) + 1) * 13)
        w.clock.now = next - Grid.DAY
        w.receive(TestBytes.token(1004), Grid.creditEpoch(WEEK0) - 1)
        assertTrue(w.purchases().isEmpty())
        assertEquals(1L, w.engine.counter(Counters.CREDIT_DROPPED))
        assertEquals(0L, w.count("SELECT count(*) FROM inbox_blob WHERE state = 'fetched'"))
        assertEquals(InviteStore.CREATED, checkNotNull(w.tx { w.ctx().invites.get(it, 0) }).state)
    }

    @Test
    fun aBlobReadAfterTheListeningEndedIsNotTaken(): Unit = World().use { w ->
        // The second refresh time lies after every read because nothing is taken once the listening
        // ended (§9.3), even before GC closed the invite.
        w.clock.now = (Grid.day(T0) + 14 + 56) * Grid.DAY + Grid.MINUTE
        w.receive(TestBytes.token(1005), Grid.creditEpoch(WEEK0))
        assertTrue(w.purchases().isEmpty())
        assertEquals(0L, w.count("SELECT count(*) FROM inbox_blob WHERE state = 'fetched'"))
    }

    @Test
    fun aStallingIssuerGetsAtMostTwoIdenticalRefreshes(): Unit = World().use { w ->
        w.receive(TestBytes.token(1002), Grid.creditEpoch(WEEK0))
        val refresh = w.purchases().single()
        w.issuer.fail = "timeout"
        w.clock.now = checkNotNull(refresh.nextDueMinute)
        repeat(60) {
            w.quiet()
            w.clock.now += 2 * Grid.HOUR
        }
        val calls = w.issuer.named("refreshCredit")
        assertEquals("one planned attempt and one identical retry (E17)", 2, calls.size)
        assertEquals(1, calls.map { it.args }.toSet().size)
        assertEquals(PurchaseStore.FAILED, checkNotNull(w.purchase(refresh.id())).state)
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
