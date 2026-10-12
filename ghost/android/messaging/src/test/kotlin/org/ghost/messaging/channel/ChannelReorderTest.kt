package org.ghost.messaging.channel

import org.ghost.crypto.bridge.ChannelCrypto
import org.ghost.messaging.DmWorld
import org.ghost.messaging.api.AcceptResult
import org.ghost.messaging.api.ChannelId
import org.ghost.messaging.channel.ChannelScenes.get
import org.ghost.messaging.channel.engine.ChannelAd
import org.ghost.messaging.channel.engine.ChannelCounters.Reason
import org.ghost.messaging.channel.engine.ChannelReceiveStep
import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import org.ghost.storage.SqlExecutor
import org.ghost.storage.StorageFullException
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.store.StoreLimits
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * **RO-C, the reorder suite** (Phase 10 design §12.6, §6.3.3, §19.18, S0-17; slice S4), over the real OpenMLS: every
 * order of 6 posts of one sender; a burst of 40 with 20 withheld for less than the gap hold and past it (the declared
 * ratchet-range loss, §6.3.6, counted); a batch with a replayed and an undecryptable message in its middle (the rest of
 * the batch decrypts, the failed items leave no state, the reload oracle agrees; MM-43); a member's re-seal of a late post
 * under a false `order` (RESEAL_ORDER, MM-35); a post of the next epoch that arrives before its commit settles (deferred,
 * re-offered by the settle, §7.5 item 6); a committer posting while its own non-removing commit is pending (§19.13); and
 * (§19.38) a backlog of 300 posts behind Phase 7's fetched cap and one wider than the peek window, neither of which may
 * lose a post; and (§19.54 row 3, S13a) a 900-post backlog behind the fetched cap, draining in bounded rounds with every
 * post opened a bounded number of times — the peek cursor's fail-without-fix shape.
 *
 * **Not here, and why** (§19.37): "bursts of 40 over 3 relays with HIGH delays" needs HIGH mode's send delays in the
 * world, a Phase 9 harness debt moved to S11 (§19.33 item B3) — the burst over SHUFFLE is [ChannelPostsTest]'s; posts
 * after the next commit **beyond** retention (REORDER_ACROSS_EPOCH) need 16 epochs of commits, which S5's passes make.
 */
class ChannelReorderTest {

    /**
     * The average native opens per backlog blob the 900-post cursor test bounds ([aNineHundredPostBacklogBehindTheFetchedCapDrainsInBoundedRoundsOpeningEachPostOnce]):
     * a blob is opened once on first sight, and the cursor's by-key deferrals open a taken row once more — measured
     * 2 303 opens for 900 posts (2.56 each) with the cursor, 29 113 (32 each) with it disabled.
     */
    private val MAX_OPENED_PER_POST = 3

    @get:Rule
    val folder = TemporaryFolder()

    @Before
    fun native() {
        assumeTrue("ghost-dm-host is not loaded (-Dghost.dm.native)", ChannelWorld.nativeAvailable())
    }

    private fun permutations(items: List<Int>): List<List<Int>> =
        if (items.size <= 1) {
            listOf(items)
        } else {
            items.flatMap { first -> permutations(items - first).map { listOf(first) + it } }
        }

    @Test
    fun everyOrderOfSixPostsOfOneSenderShowsAllSixInOneOrder() {
        // The world before bob receives anything of the owner's seven posts (an anchor and six): bob's database frozen,
        // the relay's stores kept. Each order restores both and serves the anchor, then one post per round.
        val bobFile = folder.newFile("bob-before.db").also { it.delete() }
        val frozen: ModelChannelRelay
        val now: Long
        val id: ChannelId
        val w = ChannelWorld()
        try {
            val owner = w.client("owner")
            val bob = w.client("bob", path = bobFile.absolutePath)
            id = ChannelScenes.channelOf(w, owner, bob)
            w.relay.hold = { it.from == "owner" && it.purpose == "post" }
            ChannelScenes.post(owner, id, "anchor")
            for (i in 1..6) ChannelScenes.post(owner, id, "p$i")
            w.quiesce()
            assertEquals(7, ChannelScenes.postsOf(w, owner).size)
            frozen = w.relay.copy()
            now = w.now
        } finally {
            w.close()
        }
        val posts = frozen.stored.filter { it.from == "owner" && it.purpose == "post" }
        var reference: List<String>? = null
        var orders = 0
        for (order in permutations((0 until 6).toList())) {
            val copy = java.io.File(folder.root, "bob-${orders}.db")
            bobFile.copyTo(copy)
            val sql = JdbcSqlExecutor(copy.absolutePath)
            val world = ChannelWorld(startSeconds = now, relay = frozen.copy())
            try {
                val bob = world.client("bob", sql, boot = 1)
                for (k in listOf(0) + order.map { it + 1 }) {
                    val next = posts[k]
                    world.relay.hold = { it.from == "owner" && it.purpose == "post" && it !== next }
                    world.pump()
                    bob.hintPass()
                }
                val shown = bob.displayed(id)
                assertEquals("order $order", 7, shown.size)
                if (reference == null) reference = shown
                assertEquals("order $order: one order", reference, shown)
                assertEquals("order $order", 0, bob[Reason.UNDECRYPTABLE])
            } finally {
                world.close()
                sql.close()
                copy.delete()
            }
            orders++
        }
        assertEquals(720, orders)
    }

    /** The burst of the next two tests: 40 posts of the owner, those of index 10 … 29 withheld from bob. */
    private fun burst(w: ChannelWorld, owner: ChannelClient, id: ChannelId) {
        w.relay.holdAt = { client, s ->
            client == "bob" && s.from == "owner" && s.purpose == "post" && ChannelScenes.postsOf(w, owner).indexOf(s) in 10..29
        }
        for (i in 0 until 40) ChannelScenes.post(owner, id, "b$i")
        w.quiesce()
    }

    @Test
    fun aBurstOfFortyWithTwentyWithheldLessThanTheHoldLosesNothing() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        burst(w, owner, id)
        // seq 0 … 9 decrypted; 30 … 39 held behind the gap (§6.3.3)
        assertEquals(10, bob.displayed(id).size)
        w.advance(5 * DmWorld.MINUTE)
        w.relay.holdAt = { _, _ -> false }
        w.quiesce()
        assertEquals(40, bob.displayed(id).size)
        assertEquals(0, bob[Reason.UNDECRYPTABLE])
    }

    @Test
    fun aBurstOfFortyWithTwentyWithheldPastTheHoldLosesWhatTheRatchetCannotReach() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        burst(w, owner, id)
        assertEquals(10, bob.displayed(id).size)
        // past the 12-minute hold the receiver decrypts past the gap
        w.advance(13 * DmWorld.MINUTE)
        bob.timePass()
        assertEquals(20, bob.displayed(id).size)
        // the withheld twenty arrive: the ratchet keeps 16 generations behind its head (40), so 24 … 29 decrypt and
        // 10 … 23 are the declared loss of §6.3.6, counted
        w.relay.holdAt = { _, _ -> false }
        w.quiesce()
        assertEquals(26, bob.displayed(id).size)
        assertEquals(14, bob[Reason.UNDECRYPTABLE])
        val shown = bob.displayed(id).toSet()
        for (i in 24..29) assertTrue("b$i", "b$i" in shown)
        for (i in 10..23) assertTrue("b$i", "b$i" !in shown)
    }

    /**
     * RO-C's HIGH-delay half, deferred to S11 (§19.37 row 47, §19.10's debt): a burst of 40 in
     * HIGH mode — each op's `not_before_minute` is stamped ahead at the enqueue (the harness's
     * fixed 5-minute draw of the 10-minute window) and the relay honours it
     * ([ModelChannelRelay.delayedStores], per distinct op), so the first round stores nothing —
     * `storedEarly == 0`, the strengthened shape of the review of S11 (§19.52 FIX 6) — and a
     * round past the delay stores the rest; the burst itself is delivered complete, in order,
     * like the STANDARD half. The send-delay rule itself (store minute ≥ not_before minute) is
     * checked op by op: ops are collected in rowid order, so the i-th stored post is the i-th
     * post op.
     */
    @Test
    fun aBurstOfFortyWithHighSendDelaysStoresNothingEarlyAndLosesNothing() = ChannelWorld().use { w ->
        val owner = w.client("owner", privacyMode = PrivacyMode.HIGH)
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        for (i in 0 until 40) ChannelScenes.post(owner, id, "b$i")
        w.pump()
        val storedEarly = ChannelScenes.postsOf(w, owner).size
        // Every op's delay is the fixed 5-minute draw (FixedRandomSources.sendDelay's 0.5 of the
        // 10-minute window), stamped ahead of the pump's minute: the first round stores nothing.
        assertEquals("HIGH mode's 5-minute delay holds the whole burst at the first round", 0, storedEarly)
        assertTrue("the relay counted the distinct delayed ops", w.relay.delayedStores >= 40 - storedEarly)
        // Past the delay every op is stored, at or after its not_before (each Stored carries its
        // op's not_before_minute, minute-aligned epoch seconds — Time.floorMinute's unit).
        w.advance(11 * DmWorld.MINUTE)
        w.quiesce()
        val stored = ChannelScenes.postsOf(w, owner)
        assertEquals(40, stored.size)
        for (blob in stored) {
            assertTrue(
                "a store at ${blob.storedAt} honoured its not_before ${blob.notBeforeMinute}",
                blob.storedAt >= blob.notBeforeMinute,
            )
        }
        // The burst is delivered complete and in one order: PostStore's page is ordered by
        // (author_minute, author, op_id) — the same three values on every device (§6.3.3's order
        // is the receive path's; display order never depended on arrival).
        assertEquals(40, bob.displayed(id).size)
        assertEquals(0, bob[Reason.UNDECRYPTABLE])
        assertEquals("one order everywhere: bob's display is the owner's", owner.displayed(id), bob.displayed(id))
    }

    /**
     * Relay rounds and passes until [done]: each round a relay round with its hint passes, another hint pass of every
     * client, then a minute and a time-triggered pass of every client — at most [rounds] times, an hour less than the
     * pressure hold of §19.38 when [rounds] is 59, so nothing here waits a hold out. True when [done] came true.
     */
    private fun drain(w: ChannelWorld, rounds: Int = 59, done: () -> Boolean): Boolean {
        repeat(rounds) {
            if (done()) return true
            w.quiesce()
            for (c in w.clients) c.hintPass()
            if (done()) return true
            w.advance(DmWorld.MINUTE)
            for (c in w.clients) c.timePass()
        }
        return done()
    }

    /** Every shown post's text ([ChannelClient.displayed] pages at 500; a 900-post backlog needs more). */
    private fun allTexts(c: ChannelClient, id: ChannelId): List<String> = c.database.transaction { tx ->
        c.channelStores.posts.page(tx.sql, id.toByteArray(), c.clock.now, 2000).map { row ->
            val text = c.content.open(row.bodyEnv, ChannelAd.postBody(row.opId)) ?: error("a post body that does not open")
            String(text, Charsets.UTF_8)
        }
    }

    /**
     * §19.54 row 3 (slice S13a, the peek cursor — Q-F4-13's relief valve): carol is away while the owner writes 900
     * posts; the relay then serves them scrambled behind Phase 7's fetched cap. Over successive passes the backlog
     * drains within the bounded rounds and every post is shown exactly once, and the receive step opens the backlog's
     * blobs natively at most [MAX_OPENED_PER_POST] times each on average (once on first sight; the cursor leaves a
     * remembered gap deferral out of the window, and it is taken or deferred again by its key — never re-opened pass
     * after pass). Without the cursor the same early window is re-opened every pass: measured on this scenario, 29 113
     * opens against 2 303 — 12.6× —, the cost driver §19.54 row 3 names (0 losses either way, the peek of 512 and the
     * deferral machinery hold; the deviation the cursor relieves is the re-reading). [ChannelReceiveStep.openedBlobs]
     * is the step's test/debug counter.
     */
    @Test
    fun aNineHundredPostBacklogBehindTheFetchedCapDrainsInBoundedRoundsOpeningEachPostOnce() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val carol = w.client("carol")
        val id = ChannelScenes.channelOf(w, owner, bob, carol)
        w.relay.holdAt = { client, s -> client == "carol" && s.purpose == "post" }
        val texts = (0 until 900).map { "p$it" }
        for (t in texts) ChannelScenes.post(owner, id, t)
        w.quiesce(rounds = 100)
        assertEquals("bob, with no backlog, shows them all", 900, allTexts(bob, id).size)
        w.relay.modes = setOf(ModelChannelRelay.Mode.SHUFFLE)
        w.relay.fetchedCap = StoreLimits.FETCHED_CAP
        w.relay.holdAt = { _, _ -> false }
        val openedBefore = carol.engine.receiveStep.openedBlobs
        val drained = drain(w) { allTexts(carol, id).size == 900 }
        val opened = carol.engine.receiveStep.openedBlobs - openedBefore
        assertTrue("the backlog drained within the bounded rounds", drained)
        assertEquals(texts.toSet(), allTexts(carol, id).toSet())
        assertEquals("none fell out of the ratchet's range", 0, carol[Reason.UNDECRYPTABLE])
        assertTrue(
            "every backlog blob opened at most ~$MAX_OPENED_PER_POST times (measured 2 303 with the cursor, 29 113 without)",
            opened <= 900 * MAX_OPENED_PER_POST,
        )
        assertTrue("the cap bound, and the gaps were deferred", carol[Reason.GAP_DEFERRED] > 0)
        assertEquals("one order (CS-C6)", allTexts(bob, id), allTexts(carol, id))
        assertEquals(emptyList<String>(), carol.integrity())
    }

    /**
     * §19.55a (the review of S13a, finding 1): a store failure mid-pass (SQLITE_FULL at the first claim of the
     * deferrals phase) must leave the peek cursor **cleared**, not advanced — the pass drained nothing past the
     * failure, and the actor swallows pass exceptions, so nothing else would repair a wrongly-advanced cursor and
     * the come-back deferrals would stay hidden from the window. Without the fix the faulted pass sees
     * `interrupted` and `leftUnprocessed` false and re-marks the namespaces it swept: [ChannelReceiveStep.cursorSize]
     * stays non-zero and this test fails. The fail-without-fix half is exercised, not by inspection: the same
     * StorageFull seam as [ChannelRevealTest]'s FIX 2 test.
     */
    @Test
    fun aStoreFailureMidPassClearsThePeekCursor() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        // Carol's database answers SQLITE_FULL at the first claim it sees while armed — the offer counter's
        // UPDATE inside `Inbox.claimOne`, which the round's deferrals phase reaches first.
        val carolSql = FullOnFirstClaimSqlExecutor(
            JdbcSqlExecutor(":memory:").also { MigrationRunner(it).migrate() },
        )
        val carol = w.client("carol", sql = carolSql)
        val id = ChannelScenes.channelOf(w, owner, bob, carol)
        w.relay.holdAt = { client, s -> client == "carol" && s.purpose == "post" }
        for (i in 0 until 900) ChannelScenes.post(owner, id, "p$i")
        w.quiesce(rounds = 100)
        assertEquals(900, allTexts(bob, id).size)
        w.relay.modes = setOf(ModelChannelRelay.Mode.SHUFFLE)
        w.relay.fetchedCap = StoreLimits.FETCHED_CAP
        w.relay.holdAt = { _, _ -> false }
        // Fetch to the fetched cap without running passes, then one clean pass under pressure advances the cursor.
        var pumped = 0
        while (carol.count("inbox_blob", "state = 'fetched'") < StoreLimits.FETCHED_CAP && pumped < 20) {
            w.pump()
            pumped++
        }
        carol.hintPass()
        assertTrue("a clean pass advanced the cursor", carol.engine.receiveStep.cursorSize > 0)
        // Refetch to the cap (the deferrals freed it), so the faulted pass is pressured and WOULD advance the
        // cursor without the fix; it fails at its first claim — before anything was consumed or deferred.
        var guard = 0
        while (w.pump() > 0 && guard++ < 25) Unit
        carolSql.armed = true
        assertThrows(StorageFullException::class.java) { carol.hintPass() }
        assertEquals("a mid-pass failure clears the cursor", 0, carol.engine.receiveStep.cursorSize)
    }

    /**
     * A [SqlExecutor] that throws [StorageFullException] at the first claim it sees while [armed] — the offer
     * counter's `UPDATE inbox_blob SET offers …` inside `Inbox.claimOne` ([updateExactly] routes through
     * [execUpdate]), which the round's deferrals phase reaches before any batch.
     */
    private class FullOnFirstClaimSqlExecutor(val delegate: JdbcSqlExecutor) : SqlExecutor {
        var armed: Boolean = false

        override fun exec(sql: String, args: List<Any?>) = delegate.exec(sql, args)

        override fun execUpdate(sql: String, args: List<Any?>): Int {
            if (armed && sql.startsWith("UPDATE inbox_blob SET offers")) {
                throw StorageFullException(IllegalStateException("[SQLITE_FULL] regression test"))
            }
            return delegate.execUpdate(sql, args)
        }

        override fun query(sql: String, args: List<Any?>, onRow: (SqlExecutor.Row) -> Unit) = delegate.query(sql, args, onRow)

        override fun <T> transaction(block: () -> T): T = delegate.transaction(block)

        override val inTransaction: Boolean get() = delegate.inTransaction

        override var userVersion: Int
            get() = delegate.userVersion
            set(value) {
                delegate.userVersion = value
            }
    }

    /**
     * §19.38 (the review of S4, finding 1): carol is away while the owner writes 300 posts; the relay then serves them in a
     * scrambled order, and Phase 7's fetched cap lets carol hold at most 256 of them at a time — so the blob after a gap
     * is often not fetched yet, and no held row is consumed to make room. The first version held the gaps for 12 minutes
     * in a window of 128, then decrypted past them, and the posts it had not seen fell out of the ratchet's range (the
     * review measured 18 of 160, 68 of 200 lost). Now the namespace is under pressure: the entries a gap holds are
     * deferred, the fetch resumes, and the missing `seq` re-offers them.
     */
    @Test
    fun aBacklogOfThreeHundredPostsBehindTheFetchedCapLosesNothing() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val carol = w.client("carol")
        val id = ChannelScenes.channelOf(w, owner, bob, carol)
        w.relay.holdAt = { client, s -> client == "carol" && s.purpose == "post" }
        val texts = (0 until 300).map { "p$it" }
        for (t in texts) ChannelScenes.post(owner, id, t)
        w.quiesce()
        assertEquals("bob, with no backlog, shows them all", 300, bob.displayed(id).size)
        w.relay.modes = setOf(ModelChannelRelay.Mode.SHUFFLE)
        w.relay.fetchedCap = StoreLimits.FETCHED_CAP
        w.relay.holdAt = { _, _ -> false }
        drain(w) { carol.displayed(id).size == 300 }
        assertEquals(texts.toSet(), carol.displayed(id).toSet())
        assertEquals("none fell out of the ratchet's range", 0, carol[Reason.UNDECRYPTABLE])
        assertTrue("the cap bound, and the gaps were deferred", carol[Reason.GAP_DEFERRED] > 0)
        assertEquals("one order (CS-C6)", bob.displayed(id), carol.displayed(id))
        assertEquals(emptyList<String>(), carol.integrity())
    }

    /**
     * §19.38: the same with a peek window narrower than the backlog — two senders' 150 posts each behind a window of 64 —
     * so the next blob of a sender is often one the window does not show. The window advances as the entries a gap holds
     * are deferred; nothing is decrypted past a gap the window may hide.
     */
    @Test
    fun aBacklogWiderThanThePeekWindowLosesNothing() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val carol = w.client("carol", peekLimit = 64)
        val id = ChannelScenes.channelOf(w, owner, bob, carol)
        w.relay.holdAt = { client, s -> client == "carol" && s.purpose == "post" }
        val texts = (0 until 150).flatMap { listOf("o$it", "b$it") }
        for (i in 0 until 150) {
            ChannelScenes.post(owner, id, "o$i")
            ChannelScenes.post(bob, id, "b$i")
        }
        w.quiesce()
        w.relay.modes = setOf(ModelChannelRelay.Mode.SHUFFLE)
        w.relay.holdAt = { _, _ -> false }
        drain(w) { carol.displayed(id).size == 300 }
        assertEquals(texts.toSet(), carol.displayed(id).toSet())
        assertEquals("none fell out of the ratchet's range", 0, carol[Reason.UNDECRYPTABLE])
        assertTrue("the window was full, and the gaps were deferred", carol[Reason.GAP_DEFERRED] > 0)
        assertEquals("one order (CS-C6)", owner.displayed(id), carol.displayed(id))
    }

    @Test
    fun aBatchWithAReplayAndAnUndecryptableMessageInItsMiddleDecryptsTheRest() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val carol = w.client("carol")
        val id = ChannelScenes.channelOf(w, owner, bob, carol)
        ChannelScenes.post(owner, id, "p1")
        ChannelScenes.post(owner, id, "p2")
        w.quiesce()
        assertEquals(2, bob.displayed(id).size)
        w.relay.holdAt = { client, s -> client == "bob" && s.purpose == "post" }
        for (i in 3..5) ChannelScenes.post(owner, id, "p$i")
        w.quiesce()
        val posts = ChannelScenes.postsOf(w, owner)
        // carol, a member: a replay of p2 (its generation already used at bob) and a copy of p4 whose tag is broken,
        // served before the genuine p4 — so the broken copy takes p4's generation first unless it rolls back alone
        val replay = ChannelAdversary.reseal(carol, id, posts[1].ciphertext)
        val broken = ChannelAdversary.reseal(carol, id, posts[3].ciphertext, mutate = ChannelAdversary::corrupt)
        val ns = ChannelAdversary.namespace(carol, id)
        w.relay.inject(ns, broken, w.now, "broken")
        w.relay.stored.add(w.relay.stored.indexOf(posts[3]), w.relay.stored.removeAt(w.relay.stored.size - 1))
        w.relay.inject(ns, replay, w.now, "replay")
        w.relay.holdAt = { _, _ -> false }
        w.quiesce()
        val shown = bob.displayed(id)
        assertEquals("the rest of the batch decrypted", setOf("p1", "p2", "p3", "p4", "p5"), shown.toSet())
        assertEquals("the replay and the broken copy", 2, bob[Reason.UNDECRYPTABLE])
        // The reload oracle: a reboot over the same database (a new native context) shows the same, and goes on.
        bob.die()
        val again = w.client("bob", bob.sql, boot = 1)
        assertEquals(shown, again.displayed(id))
        ChannelScenes.post(owner, id, "p6")
        w.quiesce()
        assertEquals(6, again.displayed(id).size)
        assertEquals(0, again[Reason.UNDECRYPTABLE])
        assertEquals(emptyList<String>(), again.integrity())
    }

    @Test
    fun aMemberResealingALatePostUnderAFalseOrderIsDroppedAtOpen() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val carol = w.client("carol")
        val id = ChannelScenes.channelOf(w, owner, bob, carol)
        w.relay.holdAt = { client, s -> client == "bob" && s.from == "owner" && s.purpose == "post" }
        for (i in 1..5) ChannelScenes.post(owner, id, "q$i")
        w.quiesce()
        val late = ChannelScenes.postsOf(w, owner).last()
        val opened = ChannelAdversary.openEpochBlob(carol, id, late.ciphertext)
        // RESEAL_ORDER: the late post moved to the front of the victim's order, where it would push the others out
        val moved = ChannelAdversary.reseal(carol, id, late.ciphertext, ChannelCrypto.SealOrder(opened.order.epoch, opened.order.senderLeaf, 0))
        w.relay.inject(ChannelAdversary.namespace(carol, id), moved, w.now, "reseal")
        w.relay.stored.add(0, w.relay.stored.removeAt(w.relay.stored.size - 1))
        w.relay.holdAt = { _, _ -> false }
        w.quiesce()
        assertEquals("dropped at open (CS-S7)", 1, bob[Reason.NON_CANONICAL])
        assertEquals((1..5).map { "q$it" }.toSet(), bob.displayed(id).toSet())
        assertEquals(0, bob[Reason.UNDECRYPTABLE])
    }

    @Test
    fun aPostOfTheNextEpochThatArrivesBeforeItsCommitSettlesWaitsAndShowsAtTheSettle() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val carol = w.client("carol")
        val id = ChannelScenes.channelOf(w, owner, bob)
        val link = ChannelAdmissionTest.invite(owner, id)
        w.quiesce()
        assertEquals(AcceptResult.PENDING, carol.engine.accept(link, null))
        w.quiesce()
        w.advance(6 * DmWorld.HOUR)
        // bob sees the owner's commit five minutes after the owner made it: its settle point comes later
        w.relay.holdAt = { client, s -> client == "bob" && s.purpose == "commit" }
        w.admissionPass(owner)
        w.quiesce()
        w.advance(5 * DmWorld.MINUTE)
        w.relay.holdAt = { _, _ -> false }
        w.quiesce()
        assertEquals(1L, bob.count("ch_candidate"))
        // the owner settles first; carol joins and posts in epoch 2 at once
        w.advance(16 * DmWorld.MINUTE)
        // CO-4 (ii), slice S5: a listing pass over every relay after the window opened (S4 settled without it)
        w.pump()
        owner.timePass()
        w.quiesce()
        assertEquals(2L, carol.channel(id)!!.epoch)
        assertEquals(1L, bob.channel(id)!!.epoch)
        ChannelScenes.post(carol, id, "from epoch 2")
        w.quiesce()
        // bob holds no key that matches: deferred (§6.3.2 "no match"), not dropped
        assertEquals(emptyList<String>(), bob.displayed(id))
        assertEquals(0, bob[Reason.UNOPENABLE])
        // bob's settle point: the settle re-offers the deferred post at once (§7.5 item 6), in the same pass
        w.advance(5 * DmWorld.MINUTE)
        // CO-4 (ii), slice S5: a listing pass over every relay after the window opened
        w.pump()
        bob.timePass()
        assertEquals(2L, bob.channel(id)!!.epoch)
        assertEquals(listOf("from epoch 2"), bob.displayed(id))
    }

    @Test
    fun aCommitterPostingWhileItsOwnNonRemovingCommitIsPendingIsALatePostOfThatEpoch() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val carol = w.client("carol")
        val id = ChannelScenes.channelOf(w, owner, bob)
        val link = ChannelAdmissionTest.invite(owner, id)
        w.quiesce()
        assertEquals(AcceptResult.PENDING, carol.engine.accept(link, null))
        w.quiesce()
        w.advance(6 * DmWorld.HOUR)
        w.admissionPass(owner)
        assertEquals("the owner's own commit is pending", 1L, owner.count("ch_candidate", "own = 1"))
        // §19.13: a non-removing own commit does not hold the committer's posts
        w.relay.holdAt = { client, s -> client == "bob" && s.from == "owner" && s.purpose == "post" }
        ChannelScenes.post(owner, id, "during the commit")
        assertEquals("encrypted at once", 0L, owner.count("ch_pending_post"))
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        assertEquals(2L, bob.channel(id)!!.epoch)
        // the post of epoch 1 reaches bob after bob settled epoch 1: a late post, from the retained epoch
        w.relay.holdAt = { _, _ -> false }
        w.quiesce()
        assertTrue(bob.displayed(id).contains("during the commit"))
        assertEquals(0, bob[Reason.UNDECRYPTABLE])
        // carol joined at epoch 2: the post of epoch 1 is not hers to read (T39)
        assertTrue(!carol.displayed(id).contains("during the commit"))
    }
}
