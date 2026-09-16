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
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.OperationId
import org.ghost.sync.api.OutboundBlob
import org.ghost.sync.api.TtlBucket
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
 * into a refresh flow due at the one time drawn with the invite, which the read never decides (§19.29), and stops
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
    fun anIdentityThatRedeemedEveryTokenOfTheWeekIsCoveredAndWritesItsDrop(): Unit = World().use { w ->
        w.engine.activate(w.inviteText())
        val t = checkNotNull(w.tx { w.ctx().invites.dropTarget(it) })
        val week = Grid.week(t.dropMinute)
        // Two hours before t_drop the identity writes to a DM namespace and redeems its last tokens of
        // the week: it holds the week's capabilities and no token of the week any more (§11.4).
        w.clock.now = t.dropMinute - 2 * Grid.HOUR
        val ns = NamespaceId(TestBytes.of(32, 4242))
        w.tx { tx ->
            w.stores.namespaces.register(tx, ns, Consumer.DM, w.relayIds.toSet(), listen = false)
            w.stores.outbox.enqueue(tx, OutboundBlob(OperationId(TestBytes.of(16, 42)), ns, TestBytes.of(1024, 43), TtlBucket.DAYS_7))
        }
        for (slot in 0..2) w.addAccess(week, slot, 1)
        w.laneStep()
        assertEquals(3, w.redeem.calls.size)
        assertTrue("every token of the week is spent", w.tokenRows("access").none { it.epoch >= week })
        w.clock.now = t.dropMinute
        w.ctx().dropSteps.sendDue(w.clock.now)
        val target = w.tx { w.ctx().invites.dropTarget(it) }
        assertEquals("covered by the week's capabilities: exactly one blob (§19.12)", InviteStore.ENQUEUED, target?.state)
        assertSame(DropSeal.Opened.Dummy, w.opened())
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
        // The refresh time is drawn with the invite (§19.29): 1–14 days after its listening ends.
        val row = checkNotNull(w.tx { w.ctx().invites.get(it, 0) })
        assertTrue(row.refreshMinute in (row.listenUntilDay + 1) * Grid.DAY..(row.listenUntilDay + 14) * Grid.DAY)
        val credit = TestBytes.token(999)
        w.crypto.register(credit, EntitlementCrypto.KIND_CREDIT, Grid.creditEpoch(WEEK0))
        w.fetched(invite.dropNamespace, DropSeal.sealCredit(credit, invite.dropKey, invite.dropNamespace))
        w.ctx().dropSteps.receive(w.clock.now)
        val refresh = w.purchases().single()
        assertEquals(PurchaseStore.REFRESH, refresh.kind)
        assertArrayEquals(credit, refresh.inputToken())
        val due = checkNotNull(refresh.nextDueMinute)
        assertEquals("due at the invite's refresh time", row.refreshMinute, due)
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
     * row, for an invite whose refresh draw is [draw] (the three draws before it choose the drop
     * slots, `DropSteps.create`).
     */
    private fun dueAfterReadAt(readAt: Long, draw: Double = 0.0): Pair<Long?, InviteRow> = World().use { w ->
        w.random.uniforms.addAll(listOf(0.5, 0.5, 0.5, draw))
        w.clock.now = readAt
        w.receive(TestBytes.token(1003), Grid.creditEpoch(WEEK0))
        val row = checkNotNull(w.tx { w.ctx().invites.get(it, 0) })
        Pair(w.purchases().singleOrNull()?.nextDueMinute, row)
    }

    /**
     * §19.29 (Q31 simplified): an invite has one refresh time, 1–14 days after its listening ends, and
     * the read decides nothing: a read on the first day and one on the last day of the listening give
     * the same due time, whatever the draw.
     */
    @Test
    fun oneRefreshTimeAfterTheListeningAndTheReadDecidesNothing() {
        for (draw in listOf(0.0, 0.5, 0.999)) {
            val (early, row) = dueAfterReadAt(T0 + Grid.DAY, draw)
            val end = row.listenUntilDay * Grid.DAY
            assertTrue("one time, 1–14 days after the listening ends", row.refreshMinute in end + Grid.DAY..end + 14 * Grid.DAY)
            assertEquals(row.refreshMinute, early)
            val (late, _) = dueAfterReadAt(end - Grid.HOUR, draw)
            assertEquals("a read on the listening's last day: the same time", early, late)
        }
    }

    /**
     * §19.29: a credit whose refresh window (up to two days before credit epoch c + 2) closes before
     * the listening ends is dropped whatever the read, since any due time before the listening's end
     * could precede a later read; a read before the cut is not refreshed at the cut.
     */
    @Test
    fun aCreditWhoseRefreshWindowClosesBeforeTheListeningEndsIsDroppedWhateverTheRead() {
        val epoch = Grid.creditEpoch(WEEK0) - 1
        val cut = Grid.start(Grid.creditEpochFirstWeek(epoch + 2)) - 2 * Grid.DAY
        val listenEnd = (Grid.day(T0) + 14 + 56) * Grid.DAY
        assertTrue("the fixture: the cut precedes the listening's end", cut < listenEnd)
        for (readAt in listOf(T0 + Grid.DAY, cut - Grid.DAY)) {
            World().use { w ->
                w.clock.now = readAt
                w.receive(TestBytes.token(1006), epoch)
                assertTrue("read at $readAt: never refreshed", w.purchases().isEmpty())
                assertEquals(1L, w.engine.counter(Counters.CREDIT_DROPPED))
            }
        }
    }

    /**
     * §19.29: when the invite's time falls after the cut but the cut comes after the listening ends,
     * the same draw is placed inside [listening end, cut]: every read gets that time, and the issuer
     * still refreshes it.
     */
    @Test
    fun aTimeAfterTheCutIsPlacedInsideTheWindowWhateverTheRead() {
        // An invite created in week 2965 and usable until the start of 2967 is listened until the
        // start of 2975; credit epoch 227's refresh window closes 12 days later (start(2977) − 2 d),
        // inside the 1–14-day draw.
        val createdAt = Grid.start(2965) + 12 * Grid.HOUR
        val epoch = Grid.creditEpoch(WEEK0)
        val cut = Grid.start(Grid.creditEpochFirstWeek(epoch + 2)) - 2 * Grid.DAY
        val dues = listOf(createdAt + Grid.DAY, Grid.start(2975) - Grid.HOUR).map { readAt ->
            World().use { w ->
                w.random.uniforms.addAll(listOf(0.5, 0.5, 0.5, 0.999))
                w.clock.now = createdAt
                w.identity.exists = true
                w.addTokens("invite", Grid.inviteEpoch(Grid.week(createdAt)), 1)
                val text = checkNotNull(w.engine.createInvite(Grid.day(Grid.start(2967)).toInt()))
                val row = checkNotNull(w.tx { w.ctx().invites.get(it, 0) })
                val end = row.listenUntilDay * Grid.DAY
                assertTrue("the fixture: the cut lies inside the draw window", cut in end until row.refreshMinute)
                val invite = Invite.parseAndVerify(text, createdAt, InviteTokenCheck(w.crypto), Invite.InMemoryNonceStore())
                w.clock.now = readAt
                val credit = TestBytes.token(1007)
                w.crypto.register(credit, EntitlementCrypto.KIND_CREDIT, epoch)
                w.fetched(invite.dropNamespace, DropSeal.sealCredit(credit, invite.dropKey, invite.dropNamespace))
                w.ctx().dropSteps.receive(w.clock.now)
                val due = checkNotNull(w.purchases().single().nextDueMinute)
                assertTrue("inside [listening end, cut]", due in end..cut)
                due
            }
        }
        assertEquals("the read picks nothing", dues[0], dues[1])
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
        // The refresh time lies after every read because nothing is taken once the listening
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
