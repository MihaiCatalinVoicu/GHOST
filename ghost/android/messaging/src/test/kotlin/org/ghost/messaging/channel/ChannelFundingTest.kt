package org.ghost.messaging.channel

import org.ghost.messaging.DmWorld
import org.ghost.messaging.api.ChannelId
import org.ghost.messaging.channel.engine.ChannelFunderStep
import org.ghost.messaging.engine.DmTime
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test

/**
 * **FD, the funding suite's engine half** (Phase 10 design §12.6: "renewal at the PRF time; rotation funding
 * by the rotating committer at its switch hour; a non-rotating funder's first redemption for the new
 * generation at its next EXPIRING renewal, not at the settle (PC-6); ... the drain's end with deferred junk
 * rows still fetched"), §6.5 "Funding at a rotation", §7.5 item 7 and §19.23's drain end: the funder
 * renewal step's window (the week's last 23 h), its coverage of the current generation and of a pending one
 * (never of a draining one), the rotating committer's switch-hour funding (never the settle's), the
 * renewal reflex PC-6's refusal, and `CH-SWEEP`'s drain end marking the deferred rows consumed before
 * `Namespaces.remove`.
 */
class ChannelFundingTest {

    @Before
    fun native() {
        assumeTrue("ghost-dm-host is not loaded (-Dghost.dm.native)", ChannelWorld.nativeAvailable())
    }

    /** PC-6 (§19.8 (d)): a non-rotating funder creates no rows at the settle or the switch of a received rotation — only at its renewal. */
    @Test
    fun aNonRotatingFunderRenewsTheNewGenerationOnlyAtItsExpiryWindow() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val carol = w.client("carol")
        val id = ChannelScenes.channelOf(w, owner, bob, carol)
        makeBobAFunder(w, owner, bob, id)
        val ns1 = rotateRemoving(w, owner, carol, id) // settles; generation 1 pending everywhere

        // Neither the settle nor the (received) switch makes bob redeem: no rows for ns_1 at bob yet
        // (a time-triggered pass outside the window runs no renewal; a hint pass never does).
        w.advance(40 * DmWorld.MINUTE)
        for (c in listOf(owner, bob)) c.hintPass()
        bob.timePass()
        assertEquals("no renewal at the settle or the switch (PC-6)", 0L, bob.count("relay_key_registration", "namespace_id = ?", ns1))

        // The EXPIRING renewal window (the week's last 23 h): bob's time-triggered pass renews — and his
        // unflagged funding flag is set by the renewal step, never by a received commit (§7.5 item 7). The
        // pass switches first (the switch hour has come), so the renewal covers the now-current generation.
        advanceToWindow(w)
        bob.timePass()
        assertEquals("the renewal step flags bob's funding", 1L, bob.count("sync_namespace_fund", "namespace_id = ?", ns1))
        assertTrue(
            "the renewal keeps the week's READ and DEPOSIT rows for every relay of the set",
            bob.count("relay_key_registration", "namespace_id = ? AND period_id = ?", ns1, DmTime.week(w.now)) >= 6,
        )
        assertTrue(owner.integrity().isEmpty())
    }

    /**
     * §19.8: the renewal covers the current generation and creates the next one's registration while a
     * switch pends — reachable when the renewal's pass runs before the commit's switch hour (a rotation
     * late in the week; the settle and the renewal then share one pass, the renewal after the settle).
     * A draining generation is never renewed (§6.5: "Funders stop renewing ns_g").
     */
    @Test
    fun theRenewalCoversTheCurrentGenerationAndAPendingOneButNeverADrainingOne() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val carol = w.client("carol")
        val id = ChannelScenes.channelOf(w, owner, bob, carol)
        makeBobAFunder(w, owner, bob, id)
        val ns0 = generationNs(owner, id, 0)
        // Into the renewal window, then the rotation: the commit's switch hour (commit + 30 min) lies
        // ahead of the settle pass (commit + 21 min), and the settle and the renewal share that pass.
        advanceToWindow(w)
        owner.engine.remove(id, carol.contexts.open(id.toByteArray())!!.pseudonym)
        w.quiesce()
        w.advance(21 * DmWorld.MINUTE)
        w.pump()
        bob.timePass()
        assertEquals(1L, bob.count("ch_generation", "generation = 1 AND state = 'pending_switch'"))
        assertTrue("the current generation renewed", bob.count("relay_key_registration", "namespace_id = ?", ns0) >= 6)
        val ns1 = generationNs(bob, id, 1)
        assertTrue("the pending generation's registration created", bob.count("relay_key_registration", "namespace_id = ?", ns1) >= 6)
        assertEquals("the renewal flags bob's funding (the current and the pending namespace)", 2L, bob.count("sync_namespace_fund"))

        // The switch hour passes: everyone moves; the drain begins. At the NEXT week's window the
        // draining generation gets no new rows — the current one is renewed into the new week.
        w.advance(40 * DmWorld.MINUTE)
        for (c in w.clients) c.hintPass()
        assertEquals(1L, bob.count("ch_generation", "generation = 0 AND state = 'draining'"))
        val rowsOfNs0 = bob.count("relay_key_registration", "namespace_id = ?", ns0)
        advanceToWindow(w)
        bob.timePass()
        assertTrue(
            "the draining generation got no new rows",
            bob.count("relay_key_registration", "namespace_id = ?", ns0) == rowsOfNs0,
        )
        assertTrue(
            "the (now current) new generation renewed into the next week",
            bob.count("relay_key_registration", "namespace_id = ? AND period_id = ?", ns1, DmTime.week(w.now)) >= 6,
        )
        assertTrue(bob.integrity().isEmpty())
    }

    /** §6.5, §19.23: the drain's end — a still-deferred junk row is marked consumed, then the namespace is removed. */
    @Test
    fun theDrainsEndMarksDeferredRowsConsumedAndRemovesTheNamespace() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val carol = w.client("carol")
        val id = ChannelScenes.channelOf(w, owner, bob, carol)
        val ns0 = generationNs(owner, id, 0)
        rotateRemoving(w, owner, carol, id)
        w.advance(40 * DmWorld.MINUTE)
        for (c in w.clients) c.hintPass()
        assertEquals(1L, owner.count("ch_generation", "generation = 0 AND state = 'draining'"))

        // Junk no key opens, fetched and deferred while the namespace drains (its TTL outlives the drain).
        w.relay.inject(ns0, ByteArray(4096) { (it * 31 % 251).toByte() }, w.now, "junk-deferred", ttl = 40 * DmWorld.DAY)
        w.pump()
        owner.hintPass()
        assertEquals("the junk waits deferred", 1L, owner.count("inbox_blob", "namespace_id = ? AND state = 'fetched'", ns0))

        // A time-triggered pass mid-drain removes nothing: the generation, its listening and its
        // credentials live until `drain_until_day` (MM-53's killer).
        owner.timePass()
        assertEquals("mid-drain: the generation still drains", 1L, owner.count("ch_generation", "generation = 0 AND state = 'draining'"))
        assertEquals("mid-drain: still listened", 1L, owner.count("sync_namespace", "namespace_id = ? AND listening = 1", ns0))

        // The production GC (the model relay runs none) deletes released ops long before a drain ends.
        collectOps(owner)
        // Past the drain: the sweep consumes the deferred row and removes the namespace (its listening,
        // credentials and registrations) and the generation; the sync_namespace row itself is the GC's
        // once the tombstones go (§11.2 #19).
        w.advance(15 * DmWorld.DAY)
        owner.timePass()
        assertEquals("the generation went with its drain", 0L, owner.count("ch_generation", "generation = 0"))
        assertEquals("its listening ended with it", 0L, owner.count("sync_namespace", "namespace_id = ? AND listening = 1", ns0))
        assertEquals("its credentials dropped with it", 0L, owner.count("relay_capability", "namespace_id = ?", ns0))
        assertEquals("the deferred row consumed, not offered for ever", 0L, owner.count("inbox_blob", "namespace_id = ? AND state = 'fetched'", ns0))
        assertTrue(owner.integrity().isEmpty())
    }

    /** §6.5's declared case, the engine half: a post composed while the switch pends waits, then completes in ns_{g+1}. */
    @Test
    fun aStoreToTheNewGenerationWaitsForTheSwitchAndCompletes() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val carol = w.client("carol")
        val id = ChannelScenes.channelOf(w, owner, bob, carol)
        rotateRemoving(w, owner, carol, id)
        ChannelScenes.post(owner, id, "astept switch-ul")
        assertEquals(1L, owner.count("ch_pending_post"))
        w.advance(40 * DmWorld.MINUTE)
        owner.hintPass()
        w.quiesce()
        // quiesce stops when the relay stops moving: bob's switch (a hint pass) may not have been followed
        // by a serve round — one more round delivers the post from ns_1.
        w.pump()
        bob.hintPass()
        assertEquals("the store completed", 0L, owner.count("ch_pending_post"))
        val ns1 = generationNs(owner, id, 1)
        assertTrue("and reached the other member from ns_1", bob.displayed(id).contains("astept switch-ul"))
        assertTrue(
            "stored into ns_1",
            w.relay.stored.any { it.purpose == "post" && it.namespace.contentEquals(ns1) && !it.injected },
        )
    }

    // ----------------------------------------------------------------------------------------------- helpers

    /** The owner removes [carol] (a rotation), everyone settles; returns ns_1. */
    private fun rotateRemoving(w: ChannelWorld, owner: ChannelClient, carol: ChannelClient, id: ChannelId): ByteArray {
        owner.engine.remove(id, carol.contexts.open(id.toByteArray())!!.pseudonym)
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        assertEquals(1L, owner.count("ch_generation", "generation = 1 AND state = 'pending_switch'"))
        return generationNs(owner, id, 1)
    }

    /** A rank-0 context change making bob a co-funder (recorded and settled everywhere). */
    private fun makeBobAFunder(w: ChannelWorld, owner: ChannelClient, bob: ChannelClient, id: ChannelId) {
        val before = ChannelAdversary.policy(owner, id)
        val after = org.ghost.crypto.bridge.ChannelPolicy(
            before.channelId, before.sizeClass, before.timerCode, before.timerVersion, before.historyPolicy,
            before.flags, before.idleEvictDays, before.pwVersion, before.name,
            before.committers, listOf(pseudonymOf(owner, id), pseudonymOf(bob, id)),
        )
        val change = ChannelAdversary.commit(owner, id, after)
        w.relay.holdAt = { name, s -> s.purpose == "committers" && name == "owner" }
        ChannelAdversary.stageOwn(owner, id, change, rank = 0)
        ChannelAdversary.inject(w, owner, id, change, "committers")
        w.quiesce()
        w.advance(21 * DmWorld.MINUTE)
        w.pump()
        for (client in w.clients) client.timePass()
        w.quiesce()
        assertEquals(2, ChannelAdversary.policy(owner, id).funders.size)
    }

    /** Advances the world to the first minute of the renewal window (the week's last 23 h). */
    private fun advanceToWindow(w: ChannelWorld) {
        val target = DmTime.weekStart(DmTime.week(w.now) + 1) - ChannelFunderStep.RENEWAL_WINDOW_SECONDS + 60
        if (target > w.now) w.advance(target - w.now)
    }

    /** The production GC's op collection (the model relay runs no GC): released ops die long before a drain ends. */
    private fun collectOps(client: ChannelClient) {
        client.database.transaction { tx ->
            tx.sql.exec("UPDATE outbox_op SET released = 1 WHERE released = 0 AND outcome <> 'pending'")
            tx.sql.exec("DELETE FROM outbox_op WHERE released = 1 AND ciphertext IS NULL")
        }
    }

    private fun pseudonymOf(client: ChannelClient, id: ChannelId): ByteArray =
        client.contexts.open(id.toByteArray())!!.pseudonym

    private fun generationNs(client: ChannelClient, id: ChannelId, generation: Long): ByteArray =
        client.database.transaction { tx ->
            var ns: ByteArray? = null
            tx.sql.query("SELECT namespace_id FROM ch_generation WHERE channel_id = ? AND generation = ?", listOf(id.toByteArray(), generation)) { ns = it.blob(0) }
            ns!!
        }
}
