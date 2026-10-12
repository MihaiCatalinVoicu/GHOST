package org.ghost.messaging.channel

import org.ghost.messaging.DmWorld
import org.ghost.messaging.api.AcceptResult
import org.ghost.messaging.api.ChannelId
import org.ghost.messaging.api.PostId
import org.ghost.messaging.api.PostResult
import org.ghost.messaging.channel.ChannelScenes.get
import org.ghost.messaging.channel.engine.ChannelAd
import org.ghost.messaging.channel.engine.ChannelCounters.Reason
import org.ghost.messaging.channel.store.ChannelState
import org.ghost.messaging.engine.DmTime
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test

/**
 * **The state machines of §6.11 as the engine drives them** (slice S4; the stores' legal and illegal edges are S3's
 * `ChannelStateMachinesTest`). Here: every edge of the outgoing post (`pending_plaintext → queued → sent | degraded |
 * failed | indeterminate`, `failed → queued`), the own commit cleared after a FAILED op with its join request pending
 * again, and the epoch's `open → final`. The channel's `joining → active`, `joining → join_expired` and `join_expired →
 * joining` are [ChannelJoinTest]'s and [ChannelAdmissionTest]'s; the join request's `pending → admitted` SCN-CA's and its
 * `ignored` edges JN's refusals. Not driven in S4 (§19.37): `active → leaving → left | removed | replaced`, the role, the
 * generation's rotation and the invite's expiry, whose transactions are slices S5 … S8's. Since §19.38: an own commit
 * waiting for its outcome is no wake, a hint pass runs no time-triggered step (T40), an expired pending post does not
 * stop the pass, and `post` names each refusal.
 */
class ChannelTransitionsTest {

    @Before
    fun native() {
        assumeTrue("ghost-dm-host is not loaded (-Dghost.dm.native)", ChannelWorld.nativeAvailable())
    }

    @Test
    fun everyEdgeOfTheOutgoingPostMachine() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        val c = id.toByteArray()
        // pending_plaintext: a removal hold on bob's epoch (CO-13: a held valid candidate that removes a pseudonym)
        val epoch = bob.channel(id)!!.epoch
        val hash = ChannelWorld.sha256("a removing candidate")
        bob.database.transaction { tx ->
            bob.channelStores.candidates.insert(
                tx, c, epoch, hash, ChannelWorld.sha256("someone"), 0, false,
                bob.env.seal(bob.content, ChannelAd.candidate(c, epoch, hash), ByteArray(64)), DmTime.floorMinute(w.now),
                removes = true,
            )
        }
        ChannelScenes.post(bob, id, "held")
        assertEquals(1L, bob.count("ch_pending_post"))
        assertEquals(0L, bob.count("ch_post", "direction = 'out'"))
        w.quiesce()
        assertEquals("nothing left bob", emptyList<String>(), owner.displayed(id))
        // → queued: the hold ends, the next pass encrypts it (§6.3.1, CH-POST "the channel becoming current")
        bob.database.transaction { tx -> bob.channelStores.candidates.delete(tx, c, epoch, hash) }
        bob.hintPass()
        assertEquals(0L, bob.count("ch_pending_post"))
        assertEquals(1L, bob.count("ch_post", "state = 'queued'"))
        // → sent
        w.quiesce()
        assertEquals(1L, bob.count("ch_post", "state = 'sent'"))
        assertEquals(listOf("held"), owner.displayed(id))
        // → degraded, failed, indeterminate: what the outcome reports (CH-OUTCOME)
        for (outcome in listOf("degraded", "failed", "indeterminate")) {
            w.relay.outcomeFor = { client, purpose -> if (client.name == "bob" && purpose == "post") outcome else "sent" }
            w.advance(DmWorld.MINUTE)
            ChannelScenes.post(bob, id, outcome)
            w.quiesce()
            assertEquals(outcome, 1L, bob.count("ch_post", "state = ?", outcome))
        }
        // failed → queued (the user's retry) → sent
        w.relay.outcomeFor = { _, _ -> "sent" }
        val failed = PostId(ChannelScenes.opIdOf(bob, id, "failed"))
        w.advance(DmWorld.MINUTE)
        assertEquals(PostResult.QUEUED, bob.engine.retry(id, failed))
        assertEquals(0L, bob.count("ch_post", "state = 'failed'"))
        w.quiesce()
        assertEquals(0L, bob.count("ch_post", "state = 'failed'"))
        // The failed op left a hole in bob's `seq` that nothing fills: the owner holds bob's later posts behind it for
        // the 12 minutes of §6.3.3, then decrypts past it (the retry is a new message with a new `seq`).
        assertTrue(!owner.displayed(id).contains("indeterminate"))
        w.advance(13 * DmWorld.MINUTE)
        owner.timePass()
        assertTrue(owner.displayed(id).containsAll(listOf("indeterminate", "failed")))
        // a retry while the channel is not current waits as a pending post, the row still failed; a second tap is a no-op
        w.relay.outcomeFor = { client, purpose -> if (client.name == "bob" && purpose == "post") "failed" else "sent" }
        w.advance(DmWorld.MINUTE)
        ChannelScenes.post(bob, id, "again")
        w.quiesce()
        val again = PostId(ChannelScenes.opIdOf(bob, id, "again"))
        w.relay.outcomeFor = { _, _ -> "sent" }
        bob.database.transaction { tx ->
            bob.channelStores.candidates.insert(
                tx, c, epoch, hash, ChannelWorld.sha256("someone"), 0, false,
                bob.env.seal(bob.content, ChannelAd.candidate(c, epoch, hash), ByteArray(64)), DmTime.floorMinute(w.now),
                removes = true,
            )
        }
        assertEquals(PostResult.QUEUED, bob.engine.retry(id, again))
        assertEquals(PostResult.QUEUED, bob.engine.retry(id, again))
        assertEquals(1L, bob.count("ch_pending_post"))
        assertEquals(1L, bob.count("ch_post", "state = 'failed'"))
        bob.database.transaction { tx -> bob.channelStores.candidates.delete(tx, c, epoch, hash) }
        w.quiesce()
        assertEquals(0L, bob.count("ch_post", "state = 'failed'"))
        w.advance(13 * DmWorld.MINUTE)
        owner.timePass()
        assertTrue(owner.displayed(id).contains("again"))
        // and a retry of a post that is not an own failed one is refused
        assertEquals(PostResult.NOT_FAILED, bob.engine.retry(id, again))
        assertEquals(emptyList<String>(), bob.integrity())
    }

    /**
     * §19.7 (c)'s spacing, strict (slice S13c, §19.54 row 12, F-S11-3): the rotation flag arms when an invite
     * of the current generation expired unconsumed **and** the channel's newest non-removal rotation is at
     * least 14 days old — the history row of the settle that merged each rotating winner, not the old
     * per-generation approximation. The test isolates the spacing rule from the drain rule ("never while a
     * generation drains", kept as is): the first attempt inside the window is refused while the rotation's
     * drain is still out (both rules shut), then the draining row is deleted by hand — the sweep would
     * remove it a day or two later, at its next pass after `drain_until_day` — so the next refusals are
     * the spacing rule's alone, and the arming on day 14 (the window's edge: `day − last ≥ 14`) is its
     * alone too. Two arming-eligible events 10 days apart arm once; events 14 days apart arm twice.
     */
    @Test
    fun theRotationSpacingIsStrictOverTheHistoryRows() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        val c = id.toByteArray()
        // an unused invite expires 7 days out; the pass that sees it arms the rotation and the switch follows
        owner.engine.invite(id, 7, null)
        w.advance(8 * DmWorld.DAY)
        rotateOnce(w, owner, id)
        assertEquals("the expired invite rotated the channel", 1, owner.channel(id)!!.generation)
        assertEquals(1L, owner.count("ch_rotation_history"))
        assertEquals(1L, owner.count("ch_rotation_history", "removal = 0"))
        val rotatedDay = rotationDay(owner, id)

        // 7 days after the rotation: an arming-eligible event, refused — the spacing (7 < 14) and, the same
        // day, the rotation's own drain (it runs 14 days from the switch) both shut the window
        advanceToDay(w, rotatedDay)
        owner.engine.invite(id, 7, null)
        advanceToDay(w, rotatedDay + 7)
        rotateOnce(w, owner, id)
        assertEquals("7 days after a rotation the window is shut", 1, owner.channel(id)!!.generation)
        assertEquals(1L, owner.count("ch_rotation_history"))

        // the drain ends by itself a day or two later; deleting its row now isolates the spacing rule
        assertEquals(1, owner.sql.execUpdate("DELETE FROM ch_generation WHERE channel_id = ? AND state = 'draining'", listOf(c)))

        // 14 days after the rotation (the window's edge): it arms again
        owner.engine.invite(id, 7, null)
        advanceToDay(w, rotatedDay + 14)
        rotateOnce(w, owner, id)
        assertEquals("day 14 is outside the window: one rotation per 14 days", 2, owner.channel(id)!!.generation)
        assertEquals(2L, owner.count("ch_rotation_history"))
        assertEquals(2L, owner.count("ch_rotation_history", "removal = 0"))
        val secondDay = rotationDay(owner, id)
        assertTrue("the second rotation is 14 days after the first", secondDay >= rotatedDay + 14)

        // and the same shape against the second rotation: 7 refused, 14 armed
        owner.sql.execUpdate("DELETE FROM ch_generation WHERE channel_id = ? AND state = 'draining'", listOf(c))
        owner.engine.invite(id, 7, null)
        advanceToDay(w, secondDay + 7)
        rotateOnce(w, owner, id)
        assertEquals("7 days after the second rotation: refused again", 2, owner.channel(id)!!.generation)
        assertEquals(2L, owner.count("ch_rotation_history"))
        owner.engine.invite(id, 7, null)
        advanceToDay(w, secondDay + 14)
        rotateOnce(w, owner, id)
        assertEquals("day 14 after the second rotation: armed", 3, owner.channel(id)!!.generation)
        assertEquals(3L, owner.count("ch_rotation_history"))
        assertEquals(3L, owner.count("ch_rotation_history", "removal = 0"))
        assertEquals(emptyList<String>(), owner.integrity())
        assertEquals(emptyList<String>(), bob.integrity())
    }

    /** The day the channel's newest rotation's switch hour falls on (what §19.7 (c) spaces against). */
    private fun rotationDay(owner: ChannelClient, id: ChannelId): Long {
        var day = -1L
        owner.sql.query(
            "SELECT rotated_day FROM ch_rotation_history WHERE channel_id = ? ORDER BY rotated_day DESC LIMIT 1",
            listOf(id.toByteArray()),
        ) { day = it.long(0) }
        assertTrue("a rotation was recorded", day >= 0)
        return day
    }

    /** Advances the clock until [DmTime.day] is [day] (the same time of day as now). */
    private fun advanceToDay(w: ChannelWorld, day: Long) {
        val target = day * DmWorld.DAY + Math.floorMod(w.now, DmWorld.DAY)
        assertTrue("time only moves forward", target >= w.now)
        w.advance(target - w.now)
    }

    /**
     * One rotation attempt over the owner, the NI-CH5 choreography: the arming pass, the settle, then the
     * switch at the commit's switch hour (two hours on; the third hour covers it).
     */
    private fun rotateOnce(w: ChannelWorld, owner: ChannelClient, id: ChannelId) {
        owner.sessionStart()
        w.advance(6 * DmWorld.MINUTE)
        owner.timePass()
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        owner.sessionStart()
        w.advance(6 * DmWorld.MINUTE)
        owner.timePass()
        w.quiesce()
        w.advance(3 * DmWorld.HOUR)
        owner.sessionStart()
        w.advance(6 * DmWorld.MINUTE)
        owner.timePass()
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
    }

    /**
     * §19.38 (the review of S4, finding 3): an own commit whose outcome has not come — INDETERMINATE here; every commit is
     * in this state between its pass and its outcome — past its settle point. CO-4 waits for the outcome, which comes as a
     * hint; the first version made the settle point a wake at once, for ever (`nextWakeSeconds` 0 after every pass, two
     * days later still), and the actor spun.
     */
    @Test
    fun anOwnCommitWaitingForItsOutcomeIsNoWakeAfterItsSettlePoint() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelAdmissionTest.create(owner)
        assertEquals(AcceptResult.PENDING, bob.engine.accept(ChannelAdmissionTest.invite(owner, id), null))
        w.quiesce()
        w.relay.outcomeFor = { client, purpose -> if (client.name == "owner" && purpose == "commit") "indeterminate" else "sent" }
        w.admissionPass(owner)
        w.quiesce()
        assertEquals("the own commit waits for its outcome", 1L, owner.count("ch_candidate", "own = 1 AND verified = 0"))
        w.advance(21 * DmWorld.MINUTE)
        owner.timePass()
        assertEquals(0L, owner.channel(id)!!.epoch)
        val wake = owner.engine.nextWakeSeconds()
        assertTrue("no wake at once after the settle point: $wake", wake == null || wake > 0)
        w.advance(2 * DmWorld.DAY)
        owner.timePass()
        val later = owner.engine.nextWakeSeconds()
        assertTrue("nor two days later: $later", later == null || later > 0)
    }

    /**
     * §19.38 (the review of S4, finding 10): T40's rule in `runPass` — a pass a listener hint ran never runs the scheduled
     * admission pass or the join expiry, which only a time-triggered pass may — held by no test until now. A scheduled
     * admission is due and a join is past its expiry: a hint pass does neither and enqueues nothing; the next
     * time-triggered pass does both.
     */
    @Test
    fun aHintPassRunsNeitherTheScheduledAdmissionNorTheJoinExpiry() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val dave = w.client("dave")
        val id = ChannelAdmissionTest.create(owner)
        assertEquals(AcceptResult.PENDING, bob.engine.accept(ChannelAdmissionTest.invite(owner, id), null))
        // dave's join will expire: an invite of one day, and the relay drops its request
        w.relay.hold = { it.from == "dave" }
        assertEquals(AcceptResult.PENDING, dave.engine.accept(owner.engine.invite(id, 1, null).link!!, null))
        w.quiesce()
        assertEquals(1L, owner.count("ch_join_request"))
        // a relay session start scheduled the owner's pass (CO-8); it is due once U[0, 5 min] has passed
        owner.engine.passStep.scheduleAtSessionStart()
        w.advance(2 * DmWorld.DAY)
        val ownerOps = owner.count("outbox_op")
        val daveOps = dave.count("outbox_op")
        owner.hintPass()
        dave.hintPass()
        assertEquals("a hint pass commits nothing (T40)", 0L, owner.count("ch_candidate", "own = 1"))
        assertEquals("and enqueues nothing", ownerOps, owner.count("outbox_op"))
        assertEquals("a hint pass expires no join", ChannelState.JOINING, dave.channel(id)!!.state)
        assertEquals(daveOps, dave.count("outbox_op"))
        owner.timePass()
        dave.timePass()
        assertEquals("the time-triggered pass admits", 1L, owner.count("ch_candidate", "own = 1"))
        assertEquals("…and expires the join", ChannelState.JOIN_EXPIRED, dave.channel(id)!!.state)
    }

    /**
     * §19.38 (the review of S4, finding 11): a pending post whose op deadline has passed while its `fail_after_hour`
     * (rounded up to the hour) still shows it — a 5-minute-timer channel, whose post deadline is the author minute plus
     * an hour, held by a removal hold past it. Phase 7 refuses a deadline in the past by throwing, and the first version let
     * that stop the whole pass: the scheduled admission and the join expiry behind it never ran. The post now stays
     * pending (the sweep fails it, S8) and the pass goes on.
     */
    @Test
    fun aPendingPostPastItsDeadlineNeitherThrowsNorStopsThePass() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        // a channel of 5-minute posts with bob in it
        val quick = owner.engine.create("repede".toByteArray(), 1, 0, false).channel!!
        assertEquals(AcceptResult.PENDING, bob.engine.accept(ChannelAdmissionTest.invite(owner, quick), null))
        w.quiesce()
        w.admissionPass(owner)
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        assertEquals(ChannelState.ACTIVE, bob.channel(quick)!!.state)
        // and a channel bob is joining whose join will have expired when the post below is past its deadline
        w.advance(DmWorld.MINUTE)
        val other = ChannelAdmissionTest.create(owner)
        w.relay.hold = { it.from == "bob" && it.purpose == "join" }
        assertEquals(AcceptResult.PENDING, bob.engine.accept(owner.engine.invite(other, 1, null).link!!, null))
        // bob's post waits behind a removal hold (CO-13), written at half past an hour: its deadline is an hour later
        // (the 5-minute timer's bucket), its pending row lives to the next full hour after that
        w.advance(2 * DmWorld.DAY)
        w.advance(Math.floorMod(30 * DmWorld.MINUTE - Math.floorMod(w.now, DmWorld.HOUR), DmWorld.HOUR))
        val q = quick.toByteArray()
        val epoch = bob.channel(quick)!!.epoch
        val hash = ChannelWorld.sha256("a removing candidate")
        bob.database.transaction { tx ->
            bob.channelStores.candidates.insert(
                tx, q, epoch, hash, ChannelWorld.sha256("someone"), 0, false,
                bob.env.seal(bob.content, ChannelAd.candidate(q, epoch, hash), ByteArray(64)), DmTime.floorMinute(w.now),
                removes = true,
            )
        }
        ChannelScenes.post(bob, quick, "too late")
        assertEquals(1L, bob.count("ch_pending_post"))
        w.advance(61 * DmWorld.MINUTE)
        bob.database.transaction { tx -> bob.channelStores.candidates.delete(tx, q, epoch, hash) }
        // the deadline has passed and the hour has not: the pass must not throw, and must reach the join expiry
        bob.timePass()
        assertEquals("the expired pending post is not enqueued", 1L, bob.count("ch_pending_post"))
        assertEquals(0L, bob.count("ch_post", "direction = 'out'"))
        assertEquals("the pass went on to the join expiry", ChannelState.JOIN_EXPIRED, bob.channel(other)!!.state)
        assertEquals(emptyList<String>(), bob.integrity())
    }

    /** §19.38 (the review of S4, finding 13): what `post` and `react` answer for content they refuse. */
    @Test
    fun postRefusesEmptyMalformedAndOversizedContentEachByItsName() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        assertEquals("empty", PostResult.INVALID, owner.engine.post(id, ByteArray(0), null))
        assertEquals("not UTF-8", PostResult.INVALID, owner.engine.post(id, byteArrayOf(0xC3.toByte(), 0x28), null))
        assertEquals("16 001 bytes", PostResult.TOO_LARGE, owner.engine.post(id, ByteArray(16_001) { 'a'.code.toByte() }, null))
        assertEquals("16 000 bytes", PostResult.QUEUED, owner.engine.post(id, ByteArray(16_000) { 'a'.code.toByte() }, null))
        val target = PostId(ByteArray(16) { 9 })
        assertEquals("a grapheme of 33 bytes", PostResult.TOO_LARGE, owner.engine.react(id, target, ByteArray(33) { 'x'.code.toByte() }))
        assertEquals("a grapheme that is not UTF-8", PostResult.INVALID, owner.engine.react(id, target, byteArrayOf(0xFF.toByte())))
        assertEquals("one post queued, nothing else", 1L, owner.count("ch_post", "direction = 'out'"))
    }

    @Test
    fun anOwnCommitWhoseOpFailedIsClearedAndItsRequestWaitsForTheNextPass() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelAdmissionTest.create(owner)
        val link = ChannelAdmissionTest.invite(owner, id)
        assertEquals(AcceptResult.PENDING, bob.engine.accept(link, null))
        w.quiesce()
        w.relay.outcomeFor = { client, purpose -> if (client.name == "owner" && purpose == "commit") "failed" else "sent" }
        w.admissionPass(owner)
        assertEquals("own commit pending", 1L, owner.count("ch_candidate", "own = 1"))
        w.quiesce()
        // pending → cleared (CO-4: a FAILED op leaves no copy anywhere)
        assertEquals(0L, owner.count("ch_candidate", "own = 1"))
        assertEquals(1, owner[Reason.OWN_COMMIT_CLEARED])
        assertEquals("the request is pending again", 1L, owner.count("ch_join_request"))
        assertEquals(0L, owner.channel(id)!!.epoch)
        assertEquals(ChannelState.JOINING, bob.channel(id)!!.state)
        // the next pass (CO-8's spacing) commits again and wins: pending → merged; epoch 0 open → final
        w.relay.outcomeFor = { _, _ -> "sent" }
        w.advance(6 * DmWorld.HOUR)
        w.admissionPass(owner)
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        assertEquals(ChannelState.ACTIVE, bob.channel(id)!!.state)
        assertEquals(1L, owner.channel(id)!!.epoch)
        assertEquals(1L, owner.count("ch_epoch", "epoch = 0 AND state = 'final' AND winner_hash IS NOT NULL"))
        assertEquals(0L, owner.count("ch_join_request"))
        assertEquals(emptyList<String>(), owner.integrity())
    }
}
