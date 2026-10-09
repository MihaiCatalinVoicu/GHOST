package org.ghost.messaging.channel

import org.ghost.messaging.DmWorld
import org.ghost.messaging.api.AcceptResult
import org.ghost.messaging.api.ChannelId
import org.ghost.messaging.channel.engine.ChannelSettleStep
import org.ghost.messaging.channel.store.ChannelState
import org.ghost.messaging.engine.DmTime
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test

/**
 * **SCN-CC's membership half** (Phase 10 design §12.4: "an add and a remove in one pass, settle, rotation,
 * the new generation's funding and registrations, drain") and `CH-SWITCH` (§6.5, §19.8): the switch at the
 * commit's switch hour — the new generation registered and listened, the old one draining until
 * `day(switch_hour) + 14`, the rotating committer's funding and the week's registrations (never at the
 * settle), posts composed between the settle and the switch waiting as plaintext and encrypting into
 * `ns_{g+1}` at the switch, a second rotation ending the older drain at once, and a joiner's hour-less
 * switch at its next session start. The drain's end (the sweep's half) is `ChannelFundingTest`'s.
 */
class ChannelSwitchTest {

    @Before
    fun native() {
        assumeTrue("ghost-dm-host is not loaded (-Dghost.dm.native)", ChannelWorld.nativeAvailable())
    }

    /** §12.4 SCN-CC: an add and a remove in one pass, the settle, the rotation and its switch. */
    @Test
    fun anAddAndARemoveInOnePassRotateAndTheSwitchInstallsTheNewGeneration() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val carol = w.client("carol")
        val id = ChannelScenes.channelOf(w, owner, bob, carol)
        val ns0 = generationNs(owner, id, 0)

        // dave's request waits; the owner's user Remove of carol is a pass at once that also admits dave:
        // one commit with the Add and the Remove (SCN-CC's "an add and a remove in one pass").
        val dave = w.client("dave")
        assertEquals(AcceptResult.PENDING, dave.engine.accept(ChannelAdmissionTest.invite(owner, id), null))
        w.quiesce()
        val carolP = pseudonymOf(carol, id)
        assertEquals(org.ghost.messaging.channel.engine.ChannelEngine.RemoveResult.REMOVED, owner.engine.remove(id, carolP))
        assertEquals("one commit with the add and the remove", 1L, owner.count("ch_candidate", "own = 1 AND removes = 1"))
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()

        // The merge rotated (a remove): generation 1 is pending at the members, and the removed member's
        // old generation drains until the same day as everyone's.
        for (c in listOf(owner, bob, dave)) {
            assertEquals("${c.name}: epoch 2", 2L, c.channel(id)!!.epoch)
            assertEquals("${c.name}: generation 1 pending", 1L, c.count("ch_generation", "generation = 1 AND state = 'pending_switch'"))
        }
        assertEquals(ChannelState.REMOVED, carol.channel(id)!!.state)
        assertEquals("the removed member's generation 0 drains", 1L, carol.count("ch_generation", "generation = 0 AND state = 'draining'"))
        val switchHour = switchHourOf(owner, id)
        val drainDay = DmTime.day(switchHour) + ChannelSettleStep.DRAIN_DAYS
        assertEquals("the removed member's drain day is the commit's switch day + 14", drainDay, drainDayOf(carol, id, 0))

        // The rotating committer does NOT fund at the settle: the funding is the switch's (§19.8 (d)).
        val ns1 = generationNs(owner, id, 1)
        assertEquals("no funding at the settle", 0L, owner.count("sync_namespace_fund", "namespace_id = ?", ns1))

        // A post composed between the settle and the switch waits as plaintext (§6.3.1).
        ChannelScenes.post(owner, id, "intre settle si switch")
        assertEquals(1L, owner.count("ch_pending_post"))

        // Past the switch hour: the pass switches — register, credentials, promote, demote, fund.
        w.advance(40 * DmWorld.MINUTE)
        owner.hintPass()
        assertEquals("generation 1 current", 1L, owner.count("ch_generation", "generation = 1 AND state = 'current'"))
        assertEquals("generation 0 draining", 1L, owner.count("ch_generation", "generation = 0 AND state = 'draining'"))
        assertEquals("the drain ends on the switch day + 14", drainDay, drainDayOf(owner, id, 0))
        assertEquals("ns_1 registered and listened", 1L, owner.count("sync_namespace", "namespace_id = ? AND listening = 1 AND consumer = 'channel'", ns1))
        assertEquals("ns_0 still listened until its drain ends", 1L, owner.count("sync_namespace", "namespace_id = ? AND listening = 1", ns0))
        assertEquals("the READ and DEPOSIT credentials of every slot of the set (3 relays)", 6L, owner.count("relay_capability", "namespace_id = ?", ns1))
        // The rotating committer funds ns_1 for the current week at its switch (§6.5).
        assertEquals("the rotating committer funded ns_1 at its switch", 1L, owner.count("sync_namespace_fund", "namespace_id = ?", ns1))
        assertEquals("the week's READ and DEPOSIT registrations of every slot of the set", 6L, owner.count("relay_key_registration", "namespace_id = ? AND period_id = ?", ns1, DmTime.week(w.now)))
        // The pending post encrypted into ns_1 in the same pass.
        assertEquals(0L, owner.count("ch_pending_post"))
        w.pump()
        assertTrue(
            "the post stored into ns_1",
            w.relay.stored.any { it.purpose == "post" && it.namespace.contentEquals(ns1) && !it.injected },
        )

        // The other member switches at its own next pass (§19.8 (a)); a non-rotating member funds nothing.
        bob.hintPass()
        assertEquals(1L, bob.count("ch_generation", "generation = 1 AND state = 'current'"))
        assertEquals("bob funds nothing", 0L, bob.count("sync_namespace_fund"))

        // The removed member holds nothing of ns_1 and keeps listing ns_0 (§6.5, P-C4 (b)).
        assertEquals(0L, carol.count("ch_generation", "generation = 1"))
        assertEquals(0L, carol.count("sync_namespace", "namespace_id = ?", ns1))
        assertEquals(1L, carol.count("sync_namespace", "namespace_id = ? AND listening = 1", ns0))
        w.pump()
        carol.hintPass()
        // It fetches ns_0's traffic and drops it: the new epoch's posts of ns_0 open, nothing is inserted.
        val carolPosts = carol.count("ch_post", "direction = 'in'")
        assertEquals("a removed member inserts nothing", 0L, carolPosts)

        w.quiesce()
        for (c in listOf(owner, bob, dave)) assertTrue(c.integrity().isEmpty())
    }

    /** §6.5: a switch while a generation is already draining ends the older drain at once. */
    @Test
    fun aSecondRotationWithinTheDrainEndsTheOlderDrainAtOnce() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val carol = w.client("carol")
        val dave = w.client("dave")
        val id = ChannelScenes.channelOf(w, owner, bob, carol, dave)
        val ns0 = generationNs(owner, id, 0)
        owner.engine.remove(id, pseudonymOf(carol, id))
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        w.advance(40 * DmWorld.MINUTE)
        for (c in w.clients) c.hintPass()
        assertEquals(1L, owner.count("ch_generation", "generation = 0 AND state = 'draining'"))

        // The production GC (the model relay runs none) deletes released ops long before a drain ends.
        collectOps(owner)
        // A second rotation before the drain ends: dave goes too; the staying members' switches end
        // the older drain at once (its unfetched posts are the declared loss, §6.3.6).
        owner.engine.remove(id, pseudonymOf(dave, id))
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        w.advance(40 * DmWorld.MINUTE)
        owner.hintPass()
        assertEquals("generation 2 current", 1L, owner.count("ch_generation", "generation = 2 AND state = 'current'"))
        assertEquals("generation 1 draining", 1L, owner.count("ch_generation", "generation = 1 AND state = 'draining'"))
        assertEquals("the older drain ended at once: its row is gone", 0L, owner.count("ch_generation", "generation = 0"))
        assertEquals("its namespace no longer listened", 0L, owner.count("sync_namespace", "namespace_id = ? AND listening = 1", ns0))
        assertEquals("its credentials dropped with it", 0L, owner.count("relay_capability", "namespace_id = ?", ns0))
        assertTrue(owner.integrity().isEmpty())
    }

    /**
     * §6.5, the review of S6 (§19.42): a second rotation while an op of the older namespace is still open
     * (production GC collects released ops long before a drain ends; the model relay runs no GC, so the
     * probe keeps them, as a production client can see them before its GC runs). The switch defers; the
     * next pass must not deadlock on the still-draining row — without the fix the demotion's
     * at-most-one-draining trigger aborts the switch transaction, CH-SWITCH runs before CH-SWEEP, and
     * every pass throws for ever.
     */
    @Test
    fun aSecondRotationWithAnOpenOpOfTheOlderDrainDefersAndCompletesWhenTheOpCloses() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val carol = w.client("carol")
        val dave = w.client("dave")
        val id = ChannelScenes.channelOf(w, owner, bob, carol, dave)
        val ns0 = generationNs(owner, id, 0)
        owner.engine.remove(id, pseudonymOf(carol, id))
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        w.advance(70 * DmWorld.MINUTE)
        for (c in w.clients) c.hintPass()
        assertEquals(1L, owner.count("ch_generation", "generation = 0 AND state = 'draining'"))

        // No op collection: the owner's ops of ns_0 stay, and one is still open.
        owner.engine.remove(id, pseudonymOf(dave, id))
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        w.advance(70 * DmWorld.MINUTE)
        // The switch: the older drain's removal is refused (an op of ns_0 is open) — the switch ends the
        // older drain early, turns its listening off, and defers.
        owner.hintPass()
        assertEquals("the switch waits for the older drain's removal", 1L, owner.count("ch_generation", "generation = 2 AND state = 'pending_switch'"))
        assertEquals("the older drain ended early", DmTime.day(w.now) - 1, drainDayOf(owner, id, 0))
        assertEquals("its listening is off", 0L, owner.count("sync_namespace", "namespace_id = ? AND listening = 1", ns0))

        // A day later the expired draining row is invisible to live() but still reads `draining`: without
        // the fix the demotion aborts on it and the pass throws — the channel is dead for good.
        w.advance(DmWorld.DAY)
        owner.hintPass()
        assertEquals("the pass does not deadlock on the expired draining row", 1L, owner.count("ch_generation", "generation = 2 AND state = 'pending_switch'"))

        // The op closes (production GC) at every member; the switch completes in the next pass and the
        // channel keeps making progress.
        collectOps(owner)
        collectOps(bob)
        owner.hintPass()
        assertEquals("the switch completed once the op closed", 1L, owner.count("ch_generation", "generation = 2 AND state = 'current'"))
        assertEquals("the older drain went with its removal", 0L, owner.count("ch_generation", "generation = 0"))
        assertEquals("the previous generation drains", 1L, owner.count("ch_generation", "generation = 1 AND state = 'draining'"))
        ChannelScenes.post(owner, id, "încă merge")
        // bob's first pass can defer once more — an unconsumed fetched row of ns_0 refuses the removal;
        // the row is consumed in that same pass and the next one switches. The relay serves the post
        // once bob listens to ns_2.
        w.pump()
        bob.hintPass()
        w.pump()
        bob.hintPass()
        w.pump()
        bob.hintPass()
        assertTrue("a post reaches the other member afterwards", bob.displayed(id).contains("încă merge"))
        ChannelScenes.post(bob, id, "și înapoi")
        w.pump()
        owner.hintPass()
        w.pump()
        owner.hintPass()
        assertTrue("and one comes back", owner.displayed(id).contains("și înapoi"))
        assertTrue(owner.integrity().isEmpty())
    }

    /** §19.8: a joiner that joined into a newer generation switches at its next session start. */
    @Test
    fun aJoinerWithANewerGenerationSwitchesAtItsNextSessionStart() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val carol = w.client("carol")
        val id = ChannelScenes.channelOf(w, owner, bob, carol)
        // dave accepts an invite of generation 0; the same pass admits him and removes carol: the Welcome's
        // bootstrap names generation 1, newer than the invite's — CH-JOIN keeps it pending with no hour.
        val dave = w.client("dave")
        assertEquals(AcceptResult.PENDING, dave.engine.accept(ChannelAdmissionTest.invite(owner, id), null))
        w.quiesce()
        owner.engine.remove(id, pseudonymOf(carol, id))
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        assertEquals(ChannelState.ACTIVE, dave.channel(id)!!.state)
        assertEquals(1L, dave.count("ch_generation", "generation = 1 AND state = 'pending_switch' AND switch_hour IS NULL"))
        val ns1 = generationNs(dave, id, 1)
        assertEquals(0L, dave.count("sync_namespace", "namespace_id = ?", ns1))

        // A hint pass is not a session start: nothing switches (§19.8: "the next session start").
        dave.hintPass()
        assertEquals(1L, dave.count("ch_generation", "generation = 1 AND state = 'pending_switch'"))
        dave.sessionStart()
        assertEquals("the joiner switched at its session start", 1L, dave.count("ch_generation", "generation = 1 AND state = 'current'"))
        assertEquals(1L, dave.count("sync_namespace", "namespace_id = ? AND listening = 1", ns1))
        // The joiner is no funder: the renewal step and the rotating committer fund, never CH-JOIN.
        assertEquals(0L, dave.count("sync_namespace_fund"))
        assertTrue(dave.integrity().isEmpty())
    }

    /** The engine exposes the switch step's due generations for the actor's wake. */
    @Test
    fun aPendingSwitchIsAWakeAtItsSwitchHour() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        owner.engine.remove(id, pseudonymOf(bob, id))
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        assertEquals(switchHourOf(owner, id), owner.engine.switchStep.nextDue())
    }

    // ----------------------------------------------------------------------------------------------- helpers

    private fun pseudonymOf(client: ChannelClient, id: ChannelId): ByteArray =
        client.contexts.open(id.toByteArray())!!.pseudonym

    /** The production GC's op collection (the model relay runs no GC): released ops die long before a drain ends. */
    private fun collectOps(client: ChannelClient) {
        client.database.transaction { tx ->
            tx.sql.exec("UPDATE outbox_op SET released = 1 WHERE released = 0 AND outcome <> 'pending'")
            tx.sql.exec("DELETE FROM outbox_op WHERE released = 1 AND ciphertext IS NULL")
        }
    }

    private fun generationNs(client: ChannelClient, id: ChannelId, generation: Long): ByteArray =
        client.database.transaction { tx ->
            var ns: ByteArray? = null
            tx.sql.query("SELECT namespace_id FROM ch_generation WHERE channel_id = ? AND generation = ?", listOf(id.toByteArray(), generation)) { ns = it.blob(0) }
            ns!!
        }

    private fun switchHourOf(client: ChannelClient, id: ChannelId): Long =
        client.database.transaction { tx ->
            var hour = 0L
            tx.sql.query("SELECT switch_hour FROM ch_generation WHERE channel_id = ? AND state = 'pending_switch'", listOf(id.toByteArray())) { hour = it.long(0) }
            hour
        }

    private fun drainDayOf(client: ChannelClient, id: ChannelId, generation: Long): Long =
        client.database.transaction { tx ->
            var d = 0L
            tx.sql.query("SELECT drain_until_day FROM ch_generation WHERE channel_id = ? AND generation = ?", listOf(id.toByteArray(), generation)) { d = it.long(0) }
            d
        }
}
