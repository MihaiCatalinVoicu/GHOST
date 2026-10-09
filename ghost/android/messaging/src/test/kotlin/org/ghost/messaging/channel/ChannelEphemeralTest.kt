package org.ghost.messaging.channel

import org.ghost.messaging.DmWorld
import org.ghost.messaging.api.AcceptResult
import org.ghost.messaging.api.ChannelId
import org.ghost.messaging.api.PostResult
import org.ghost.messaging.channel.store.ChannelState
import org.ghost.messaging.channel.store.Direction
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test

/**
 * **SCN-CF and EP-C** (Phase 10 design §12.4, §12.6; slice S8): the ephemeral half of `CH-SWEEP` over the
 * real OpenMLS — the post timers and §8.2's cascade (a fired post takes its reactions and its derived rows;
 * mutant ME-C1, ME-C5), the expired-pending edge recorded for this slice (§19.37 row 11: FAILED), the
 * epochs past retention with the count of §8.3 (`sweepPast`, MM-28) and the box keys of §19.17, the
 * administrative posts' TTL (§8.5: `INVITE_ISSUED` until `expiry_day + 1`), the sweep's no-op cases (a
 * pending commit is custody's, never the sweep's — §19.37 row 47), the checkpoint after the cascade with
 * the §10.7 debt (a busy reader is retried, never lost), and T25's relay half of §5.8 (a handshake blob
 * carries the handshake TTL, not the post TTL, in channels with timers ≤ 1 d; X-7).
 *
 * What runs where: the timer-change half of SCN-CF ("older posts keep their own timer") awaits the policy
 * actions' user entry points (Phase 13, as S6 recorded for the password actions); the per-timer matrix of
 * §8.5's table is the store-level suites' ([org.ghost.messaging.channel.store.PostStoreTest], the residue
 * test's sweep) plus the 5-minute and 7-day channels here.
 */
class ChannelEphemeralTest {

    @Before
    fun native() {
        assumeTrue("ghost-dm-host is not loaded (-Dghost.dm.native)", ChannelWorld.nativeAvailable())
    }

    /** A channel of [timerCode] with [joiners] admitted by one pass, as [ChannelScenes.channelOf] builds it. */
    private fun channelOfTimer(w: ChannelWorld, owner: ChannelClient, timerCode: Int, vararg joiners: ChannelClient): ChannelId {
        val id = owner.engine.create("ephemeral".toByteArray(), timerCode, 0, false).channel!!
        for (j in joiners) {
            assertEquals(AcceptResult.PENDING, j.engine.accept(ChannelAdmissionTest.invite(owner, id), null))
        }
        w.quiesce()
        w.admissionPass(owner)
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        for (j in joiners) assertEquals(ChannelState.ACTIVE, j.channel(id)!!.state)
        return id
    }

    /**
     * §8.2's cascade (SCN-CF, EP-C; mutants ME-C1 "reactions not cascaded", ME-C5 "a derived row outlives
     * its rule"): in a 5-minute channel a fired post takes its reactions and its `ch_reveal` row in one
     * sweep, on every member; the checkpoint after the cascade is called (the -wal half of T25's scan is
     * the residue test's, on a file).
     */
    @Test
    fun aFiredPostTakesItsReactionsAndRevealRowWithIt() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = channelOfTimer(w, owner, 1, bob)
        ChannelScenes.post(bob, id, "gone soon")
        w.quiesce()
        assertEquals(listOf("gone soon"), owner.displayed(id))
        // a reaction on the post, received by the owner, and a reveal row bound to the post's timer
        val target = org.ghost.messaging.api.PostId(ChannelScenes.opIdOf(bob, id, "gone soon"))
        assertEquals(PostResult.QUEUED, bob.engine.react(id, target, "👍".toByteArray(Charsets.UTF_8)))
        w.quiesce()
        assertEquals(1L, owner.count("ch_reaction"))
        val deadline = owner.database.transaction { tx ->
            owner.channelStores.posts.post(tx.sql, target.toByteArray(), owner.clock.now)!!.deleteAtMinute
        }
        assertNotNull(deadline)
        bob.database.transaction { tx ->
            bob.channelStores.posts.putReveal(tx, id.toByteArray(), Direction.OUT, owner.channel(id)!!.myPseudonym, deadline)
        }
        assertEquals(1L, bob.count("ch_reveal"))
        // the timer fires: two hours later (the 5-minute timer's TTL bucket is one hour, §5.8) a
        // time-triggered pass sweeps every member
        w.advance(2 * DmWorld.HOUR)
        owner.timePass()
        bob.timePass()
        for (c in listOf(owner, bob)) {
            assertEquals("${c.name}: the post is gone", 0L, c.count("ch_post"))
            assertEquals("${c.name}: its reactions went with it (ME-C1)", 0L, c.count("ch_reaction"))
            assertEquals("${c.name}: the reveal row followed its timer (ME-C5)", 0L, c.count("ch_reveal"))
            assertEquals(emptyList<String>(), c.integrity())
        }
        assertTrue("the cascade ended with the checkpoint (§8.2)", owner.checkpoint.calls >= 1)
        assertTrue(bob.checkpoint.calls >= 1)
    }

    /**
     * §8.2's cascade, the pending half (mutant ME-C7's "the cascade skipped" half): a post's timer
     * takes the `ch_pending_post` row waiting on it too — even when the pending row's own deadline
     * (`fail_after_hour`) is still ahead and only the cascade can delete it.
     */
    @Test
    fun theCascadeTakesAPendingRetryWhoseOwnDeadlineHasNotPassed() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = channelOfTimer(w, owner, 1, bob)
        val c = id.toByteArray()
        val op = ByteArray(16) { it.toByte() }
        val hour = (w.now / DmWorld.HOUR) * DmWorld.HOUR
        val me = bob.channel(id)!!.myPseudonym
        bob.database.transaction { tx ->
            // an expired outgoing post (its deadline an hour ago) with a pending retry whose
            // fail-after is two hours ahead — only the cascade names the pair
            bob.channelStores.posts.insertOutgoing(
                tx, op, c, me, 1, null, 1, 1, ByteArray(60), hour - 2 * DmWorld.HOUR, hour - DmWorld.HOUR,
            )
            bob.channelStores.posts.insertPending(tx, op, c, 1, ByteArray(60), hour + 2 * DmWorld.HOUR)
        }
        assertEquals(1L, bob.count("ch_post"))
        assertEquals(1L, bob.count("ch_pending_post"))
        bob.timePass()
        assertEquals(0L, bob.count("ch_post"))
        assertEquals("the cascade took the waiting retry (ME-C7)", 0L, bob.count("ch_pending_post"))
        assertEquals(emptyList<String>(), bob.integrity())
    }

    /**
     * The expired-pending edge recorded for this slice (§19.37 row 11, §6.3.1's last sentence, §6.11's
     * `pending_plaintext → failed`): a pending post whose op deadline (`fail_after_hour`) has passed
     * leaves the pending set — the 256 bound of §6.3.5 counts live rows. Mutant ME-C8 ("the edge
     * skipped") kills the pending assertion here. Where a post row exists it is already `failed` (a retry
     * while the channel is not current keeps the row `failed` until it is encrypted,
     * [ChannelTransitionsTest]); the row itself then lives exactly to its own timer, after which
     * §8.2's cascade takes it.
     */
    @Test
    fun aPendingPostPastItsOpDeadlineLeavesTheQueue() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = channelOfTimer(w, owner, 1, bob)
        // a post whose op the relays fail, then the user's retry of it while a removal hold (CO-13)
        // keeps the channel not current: a `failed` row plus a pending row waiting to be encrypted
        w.relay.outcomeFor = { client, purpose -> if (client.name == "bob" && purpose == "post") "failed" else "sent" }
        ChannelScenes.post(bob, id, "retry me")
        w.quiesce()
        w.relay.outcomeFor = { _, _ -> "sent" }
        assertEquals(1L, bob.count("ch_post", "state = 'failed'"))
        val opId = ChannelScenes.opIdOf(bob, id, "retry me")
        val c = id.toByteArray()
        val epoch = bob.channel(id)!!.epoch
        val hash = ChannelWorld.sha256("a removing candidate")
        bob.database.transaction { tx ->
            bob.channelStores.candidates.insert(
                tx, c, epoch, hash, ChannelWorld.sha256("someone"), 0, false,
                bob.env.seal(bob.content, org.ghost.messaging.channel.engine.ChannelAd.candidate(c, epoch, hash), ByteArray(64)),
                org.ghost.messaging.engine.DmTime.floorMinute(w.now), removes = true,
            )
        }
        assertEquals(PostResult.QUEUED, bob.engine.retry(id, org.ghost.messaging.api.PostId(opId)))
        fun states(): String {
            val sb = StringBuilder()
            bob.sql.query("SELECT state, count(*) FROM ch_post GROUP BY state") { sb.append("${it.string(0)}=${it.long(1)} ") }
            bob.sql.query("SELECT count(*) FROM ch_pending_post") { sb.append("pending=${it.long(0)} ") }
            bob.sql.query("SELECT epoch, removes, count(*) FROM ch_candidate GROUP BY epoch, removes") {
                sb.append("cand(e${it.long(0)},r${it.long(1)})=${it.long(2)} ")
            }
            return sb.toString()
        }
        assertTrue(states() + "one failed row", 1L == bob.count("ch_post", "state = 'failed'"))
        assertEquals(1L, bob.count("ch_pending_post"))
        // a post that has waited from the start has a pending row and no post row (it never encrypted)
        ChannelScenes.post(bob, id, "held")
        assertEquals(2L, bob.count("ch_pending_post"))
        assertEquals(0L, bob.count("ch_post", "state = 'queued'"))
        // past the op deadlines (author + 1 h in a 5-minute channel) and their hour: the pass does not
        // encrypt them (the S4 edge); the sweep drops them from the pending set
        w.advance(2 * DmWorld.HOUR + DmWorld.MINUTE)
        bob.timePass()
        assertEquals(0L, bob.count("ch_pending_post"))
        assertEquals("the failed row's own timer swept it an hour after its deadline (§8.2)", 0L, bob.count("ch_post"))
        bob.database.transaction { tx -> bob.channelStores.candidates.delete(tx, c, epoch, hash) }
        assertEquals(emptyList<String>(), bob.integrity())
    }

    /**
     * SCN-CF's "clock step back" and §8.2's "the expiry clock never runs backwards": a read post counts
     * from its display; stepping the clock back before the deadline does not bring a fired timer back,
     * and the displayed post lives exactly to its own deadline.
     */
    @Test
    fun aReadPostCountsFromItsDisplayAndADeadlineNeverMovesLater() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = channelOfTimer(w, owner, 1, bob)
        ChannelScenes.post(bob, id, "displayed")
        w.quiesce()
        val opId = ChannelScenes.opIdOf(owner, id, "displayed")
        owner.database.transaction { tx ->
            assertTrue(owner.channelStores.posts.markDisplayed(tx, opId, org.ghost.messaging.engine.DmTime.floorMinute(w.now), w.now / 60 * 60 + 5 * 60))
        }
        // three minutes back: the deadline is still ahead, the post stays
        w.advance(-3 * DmWorld.MINUTE)
        owner.timePass()
        assertEquals(listOf("displayed"), owner.displayed(id))
        // past the display's 5-minute countdown the post is gone
        w.advance(9 * DmWorld.MINUTE)
        owner.timePass()
        assertEquals(emptyList<String>(), owner.displayed(id))
        assertEquals(0L, owner.count("ch_post"))
    }

    /**
     * The epochs past retention (§8.3, §6.3.5; mutants MM-28 "retention by time, not count", ME-C9 "the
     * bound off by one"): an epoch on its last retention day is kept with its fork signals; the day after
     * the sweep deletes the row, the fork signals and the box keys that only that epoch held, and
     * `sweepPast(keepCount = n)` — n the final epochs still within retention — drains the native past
     * epochs beyond n: the OpenMLS rows and `ch_epoch` stay in lockstep by count, never by OpenMLS's
     * stamps (§19.4).
     */
    @Test
    fun epochsPastRetentionGoWithTheirForkSignalsAndTheNativePastDrainsByCount() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = channelOfTimer(w, owner, 4, bob) // 7-day timer: R = 2 days
        val c = id.toByteArray()
        // a fork signal and a replaced box key of epoch 0, which became past at the admission settle
        owner.database.transaction { tx ->
            owner.channelStores.epochs.addForkSignal(tx, c, 0, ChannelWorld.sha256("late commit"), org.ghost.messaging.engine.DmTime.day(w.now))
            owner.channelStores.members.insertBoxKey(tx, c, ChannelWorld.sha256("old box"), ByteArray(60))
            owner.channelStores.members.retireBoxKey(tx, c, ChannelWorld.sha256("old box"), 0)
        }
        val keepUntil = owner.database.transaction { tx ->
            owner.channelStores.epochs.epoch(tx.sql, c, 0, org.ghost.messaging.engine.DmTime.day(w.now))!!.keepUntilDay
        }
        val day = org.ghost.messaging.engine.DmTime.day(w.now)
        assertEquals("channelOf settled epoch 0 two days before its bound", keepUntil, day + 2)
        fun sweep() {
            owner.timePass()
            bob.timePass()
        }
        fun pastRows(client: ChannelClient): Long {
            var n = 0L
            client.sql.query(
                "SELECT count(*) FROM mls_kv WHERE channel_id = ? AND substr(k, 1, 18) = x'4d6573736167655365637265747350617374'",
                listOf(c),
            ) { n = it.long(0) }
            return n
        }
        // at the bound: kept (the sweep's read is `keep_until_day < today`; ME-C9). The channel's
        // members retired their own leaf keys at the admission commit, so two keys read `last_epoch = 0`.
        w.advance(2 * DmWorld.DAY)
        sweep()
        assertEquals(1L, owner.count("ch_epoch", "epoch = 0"))
        assertEquals(1L, owner.count("ch_fork_signal"))
        assertEquals(2L, owner.count("ch_box_key", "last_epoch = 0"))
        assertEquals("the native past of a retained epoch stays", 1L, pastRows(owner))
        // over the bound: the row, its fork signals and the box keys go; the native past drains to n = 0
        w.advance(DmWorld.DAY)
        sweep()
        assertEquals(0L, owner.count("ch_epoch", "epoch = 0"))
        assertEquals(0L, owner.count("ch_fork_signal"))
        assertEquals(0L, owner.count("ch_box_key", "last_epoch = 0"))
        assertEquals("sweepPast(keepCount = 0) drained the only past epoch (MM-28)", 0L, pastRows(owner))
        for (client in listOf(owner, bob)) {
            assertEquals(1L, client.count("ch_epoch"))
            assertEquals(emptyList<String>(), client.integrity())
        }
        // liveness of the survivors: the channel still works
        ChannelScenes.post(bob, id, "still here")
        w.quiesce()
        assertEquals(listOf("still here"), owner.displayed(id))
    }

    /**
     * The sweep's no-op cases (EP-C; §19.37 row 47): a pending own commit is **never** the sweep's — its
     * custody is CO-4's, the settle's clear and the outcome step's resends — and a post whose timer has
     * not fired is untouched. The scratch mutant that makes the sweep clear a pending commit (ME-C10) is
     * killed by the candidate assertion here.
     */
    @Test
    fun theSweepLeavesAPendingCommitAndALivePostUntouched() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = channelOfTimer(w, owner, 4, bob)
        // the owner's PCS commit of a quiet week (its last commit is 7 days and an hour old): an own
        // candidate, pending, unverified; no relay round runs, so its op is still pending too
        w.advance(7 * DmWorld.DAY + DmWorld.HOUR)
        w.admissionPass(owner)
        assertEquals(1L, owner.count("ch_candidate", "own = 1 AND verified = 0"))
        assertEquals(1L, owner.count("ch_outbound_op", "purpose = 'commit'"))
        // days of sweeps: nothing of the pending commit is the sweep's
        repeat(3) {
            w.advance(DmWorld.DAY)
            owner.timePass()
        }
        assertEquals("the pending commit is untouched by the sweep (ME-C10)", 1L, owner.count("ch_candidate", "own = 1 AND verified = 0"))
        assertEquals(1L, owner.count("ch_outbound_op", "purpose = 'commit'"))
        // a live post is untouched too
        ChannelScenes.post(bob, id, "alive")
        w.quiesce()
        repeat(2) {
            w.advance(DmWorld.HOUR)
            owner.timePass()
        }
        assertEquals("a live post stays", listOf("alive"), owner.displayed(id))
        assertEquals(emptyList<String>(), owner.integrity())
    }

    /**
     * The administrative posts' TTL (§8.5's table, §19.21; mutant ME-C5's invite-record half): an
     * `INVITE_ISSUED` record is declared membership metadata, kept until `expiry_day + 1` — a committer
     * admits up to the invite's expiry — on every member; the sponsor's own link is kept only until
     * `expiry_day`.
     */
    @Test
    fun inviteRecordsLiveUntilTheirExpiryDayPlusOne() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = channelOfTimer(w, owner, 4, bob)
        val link = owner.engine.invite(id, 7, null).link!!
        assertEquals(AcceptResult.PENDING, w.client("carol").let { it.engine.accept(link, null) })
        w.quiesce()
        // carol's issued invite stands at every member; the records of both invites issued today (the
        // admission's among them) expire together. The sponsor keeps only the unconsumed link: the
        // admission's own row went when the invite was consumed.
        val atBob = bob.count("ch_invite_issued")
        assertTrue("bob recorded the invites issued before carol's accept", atBob >= 1)
        assertEquals(2L, owner.count("ch_invite_issued"))
        assertEquals("the sponsor keeps both links until their expiry (§6.2.1)", 2L, owner.count("ch_invite_own"))
        val expiry = bob.database.transaction { tx ->
            // every issued invite of the channel, whatever today's filter
            bob.channelStores.invites.issuedOf(tx.sql, id.toByteArray(), 0).map { it.expiryDay }.distinct().single()
        }
        // at expiry day: still there (the reads' filter is `expiry_day >= today`)
        w.advance((expiry - org.ghost.messaging.engine.DmTime.day(w.now)) * DmWorld.DAY)
        owner.timePass()
        bob.timePass()
        assertEquals(atBob, bob.count("ch_invite_issued"))
        assertEquals(2L, owner.count("ch_invite_issued"))
        assertEquals(2L, owner.count("ch_invite_own"))
        // the day after: the sweep deletes them (kept until expiry_day + 1)
        w.advance(DmWorld.DAY)
        owner.timePass()
        bob.timePass()
        assertEquals(0L, bob.count("ch_invite_issued"))
        assertEquals(0L, owner.count("ch_invite_issued"))
        assertEquals(0L, owner.count("ch_invite_own"))
        assertEquals(emptyList<String>(), bob.integrity())
    }

    /**
     * T25's relay half of §5.8 (X-7, L8-C14): in a channel with a timer ≤ 1 d, posts carry the post TTL
     * (one hour at 5 minutes) and the administrative posts — `INVITE_ISSUED`, `LEAVE` — carry the
     * **handshake** TTL (seven days), so a committer offline longer than the timer still admits and
     * removes. In 7-day channels the two are equal (P-C3), which is why this runs in a 5-minute channel.
     */
    @Test
    fun handshakeBlobsCarryTheHandshakeTtlNotThePostTimer() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = channelOfTimer(w, owner, 1, bob)
        ChannelScenes.post(bob, id, "a post")
        owner.engine.invite(id, 7, null)
        bob.engine.leave(id)
        w.quiesce()
        val posts = ChannelScenes.postsOf(w, bob)
        assertTrue(posts.isNotEmpty())
        assertTrue("a post's TTL is the post TTL (3 600 s at 5 minutes)", posts.all { it.ttl == 3_600L })
        val handshake = w.relay.stored.filter { it.purpose == "request" && !it.injected }
        assertTrue("the INVITE_ISSUED and the LEAVE went out", handshake.size >= 2)
        assertTrue("administrative posts carry the handshake TTL (604 800 s)", handshake.all { it.ttl == 604_800L })
    }

    /**
     * SCN-CF's "a busy reader during checkpoint" (§10.7; the ME-10 shape at the channel sweep): a
     * checkpoint that stays busy keeps the debt; the next sweep that runs retries it — the need is never
     * dropped with the counts.
     */
    @Test
    fun aBusyCheckpointKeepsItsDebtAndTheNextSweepRetriesIt() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val id = channelOfTimer(w, owner, 1)
        ChannelScenes.post(owner, id, "sweep me")
        w.quiesce()
        w.advance(6 * DmWorld.MINUTE)
        owner.checkpoint.busy = true
        owner.timePass()
        assertTrue("the sweep ran and asked the checkpoint", owner.checkpoint.calls >= 1)
        assertTrue("the post is gone even though the reader held the log", 0L == owner.count("ch_post"))
        // the debt is kept: a later sweep retries the checkpoint even with nothing new to delete
        owner.checkpoint.busy = false
        val before = owner.checkpoint.calls
        owner.timePass()
        assertTrue("the debt was retried at the next sweep", owner.checkpoint.calls > before)
        assertEquals(emptyList<String>(), owner.integrity())
    }

    /**
     * §8.2's "Sweeps run where DM sweeps run": the actor's next wake is at the next post timer, so a fired
     * post does not wait for an unrelated alarm (the inexact alarm half is the wiring's, Phase 13).
     */
    @Test
    fun theNextWakeIsTheNextPostTimer() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val id = channelOfTimer(w, owner, 2, w.client("bob")) // 1-hour channel
        ChannelScenes.post(owner, id, "timed")
        w.quiesce()
        val opId = ChannelScenes.opIdOf(owner, id, "timed")
        val deadline = owner.database.transaction { tx ->
            owner.channelStores.posts.post(tx.sql, opId, owner.clock.now)!!.deleteAtMinute
        }!!
        val wake = owner.engine.nextWakeSeconds()
        assertNotNull(wake)
        assertTrue("the wake is at the post's timer ($deadline), not later", deadline - owner.clock.now >= wake!!)
    }
}
