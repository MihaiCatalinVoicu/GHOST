package org.ghost.messaging

import org.ghost.messaging.api.AddContactResult
import org.ghost.messaging.api.CardSource
import org.ghost.messaging.api.ContactId
import org.ghost.messaging.api.Establishment
import org.ghost.messaging.api.SendResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * PQ-C on two devices with the **real** cryptography (Phase 9 design §9.4, §7.1 R-C5, §22.8.6;
 * slice S13): the offer form SEND chooses, the weekly `pq_key`, the slack rule seen from the relay
 * (PQ4), and a restored or reset peer resuming pair mode (PQ6).
 *
 * The ground truth is the [PqRecorder] at the envelope port — what was encoded, offered and
 * sealed — and never the engine's own rows, except where a row *is* the rule under test
 * (`dm_peer_pq`, `dm_pair_offer.offer_env`, `dm_contact.pq_announced_week`).
 */
class PqcFlowTest {

    private fun requireNative() {
        assumeTrue(
            "set -Dghost.dm.native to the ghost-dm-host library",
            DmWorld.nativeAvailable(),
        )
    }

    private fun world(
        log: PqLog,
        forceClassical: Boolean = false,
        stripPqKey: Boolean = false,
    ): DmWorld {
        val world = DmWorld(
            decorate = { branch, inner -> PqRecorder(inner, branch, log, forceClassical, stripPqKey) },
        )
        log.now = { world.alice.clock.now }
        return world
    }

    /**
     * §9.4 in an ordinary conversation: A's first root offer is PQ-C, encapsulated to the
     * generation of B's bundle A fetched (fresh by the bundle's own validity); B opens it and
     * answers in pair mode under it, which acknowledges it; each side announces each of its generation keys
     * once and the other stores it in band once it is newer than what it had.
     */
    @Test
    @Suppress("LongMethod")
    fun offersArePqToAnnouncedKeysAndTheConversationStaysInPairMode() {
        requireNative()
        val log = PqLog()
        world(log).use { world ->
            val alice = world.alice
            val bob = world.bob
            val (contactB, contactA) = establishBothWays(world)

            // A's offer went out as `seal_root_pq`, to the generation EST-READY stored from B's
            // bundle, and it rode on "pair now".
            val aOffers = log.offers.filter { it.branch == alice.branch }
            assertEquals(1, aOffers.size)
            val bundleGen = requireNotNull(peerPq(alice).singleOrNull { it.source == "bundle" })
            assertEquals(bundleGen.genId, aOffers.single().peerGenId)
            assertEquals("the stored offer is the PQ-C TLV", 1_194, offerEnvLength(alice, aOffers.single().rootGen))
            assertTrue(log.encoded.any { it.branch == alice.branch && it.sealRootPqRode })
            // B has no key of A's before A's first announcement, so B's first offer is classical.
            assertNull(log.offers.first { it.branch == bob.branch }.peerGenId)

            // B answers under A's PQ root: pair mode, and A's offer is acknowledged by it (R12).
            assertEquals(SendResult.QUEUED, bob.engine.send(contactA, "under your pq root", null))
            world.deliver()
            alice.hintPass()
            assertTrue(alice.engine.conversation(contactB, 50, null).any { it.text == "under your pq root" })
            assertTrue("A's PQ offer is acknowledged", offerAcknowledged(alice, aOffers.single().rootGen))
            assertTrue(
                "B sealed it in pair mode under A's generation",
                log.pairBlobs.any { it.branch == bob.branch && it.rootGen == aOffers.single().rootGen },
            )

            // Three weeks of two-way traffic: the first send after each new generation carries it.
            repeat(3) {
                world.advanceTo(alice.clock.now + DmWorld.WEEK)
                alice.timeTriggeredPass()
                bob.timeTriggeredPass()
                repeat(2) { i ->
                    assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "a$it$i", null))
                    world.deliver()
                    bob.hintPass()
                    assertEquals(SendResult.QUEUED, bob.engine.send(contactA, "b$it$i", null))
                    world.deliver()
                    alice.hintPass()
                }
            }
            for (device in listOf(alice, bob)) {
                val perGeneration = log.encoded.filter { it.branch == device.branch && it.pqKeyRode }
                    .groupBy { it.pqKeyWeek }
                assertTrue("${device.branch}: announced", perGeneration.size >= 2)
                assertTrue(
                    "${device.branch}: each generation once: ${perGeneration.mapValues { it.value.size }}",
                    perGeneration.values.all { it.size == 1 },
                )
                // The period index is the last announced generation's week (§22.18).
                assertEquals(perGeneration.keys.maxOf { it ?: 0L }, pqAnnouncedWeek(device))
            }
            assertTrue(
                "A holds a key B announced in band: ${peerPq(alice)}",
                peerPq(alice).any { it.source == "in_band" },
            )
            assertTrue("and B one of A's", peerPq(bob).any { it.source == "in_band" })
            assertTrue("at most three keys per contact (dm_peer_pq_limit)", peerPq(alice).size <= 3)
            assertEquals("nothing was dropped", 0, alice.engine.status().drops.values.sum())
            assertEquals(0, bob.engine.status().drops.values.sum())
        }
    }

    /**
     * **PQ4 through the relay** (§15.5, an NI-DM2 variant; mutant ME-23): over bodies straddling
     * the slack boundaries of the 4 KiB class, with both PQ-C TLVs pending, every blob a relay
     * stores has the size the **body alone** chooses — the same sequence of sizes as a twin world
     * in which no PQ-C TLV ever rides — and each TLV rode exactly when it fitted.
     */
    @Test
    fun pq4TheRelaySeesTheSameSizesWithAndWithoutPqTlvs() {
        requireNative()
        val bodies = listOf(1, 1_100, 1_148, 1_149, 1_210, 1_211, 2_220, 2_221, 5_000, 14_508, 14_509)
        val withPq = PqLog()
        val sizesWithPq = world(withPq).use { world -> relaySizes(world, bodies) }
        val without = PqLog()
        val sizesWithout = world(without, forceClassical = true, stripPqKey = true).use { world ->
            relaySizes(world, bodies)
        }
        assertEquals("the relay-visible sizes do not depend on PQ-C", sizesWithout, sizesWithPq)
        assertTrue("the twin carried no PQ-C TLV", without.encoded.none { it.sealRootPqRode || it.pqKeyRode })

        // Every encode of the PQ world: the bucket is the body's (R-B1), every sealed blob is its
        // bucket, and a PQ-C TLV rode exactly when R-C5's slack admitted it, in the order the send
        // chose (a newly minted offer first, a re-attached one after the announcement).
        var rode = 0
        var deferred = 0
        var reordered = 0
        for (e in withPq.encoded) {
            assertEquals("bucket of a ${e.bodyLength}-byte body", expectedBucket(e.bodyLength), e.bucket)
            val classical = if (e.offerEnvLength == CLASSICAL_OFFER_ENV) SEAL_ROOT_TLV else 0
            var slack = capacity(e.bucket) - (L0_FIXED + e.bodyLength + classical)
            val candidates = buildList {
                if (e.offerEnvLength == PQ_OFFER_ENV) add("seal_root_pq" to SEAL_ROOT_PQ_TLV)
                if (e.pqKeyOffered) add("pq_key" to PQ_KEY_TLV)
            }.let { if (e.pqKeyFirst) it.reversed() else it }
            if (e.pqKeyFirst && candidates.size == 2) reordered++
            for ((name, bytes) in candidates) {
                val fits = slack >= bytes
                val didRide = if (name == "pq_key") e.pqKeyRode else e.sealRootPqRode
                assertEquals("$name at body ${e.bodyLength}", fits, didRide)
                if (fits) slack -= bytes
                if (fits) rode++ else deferred++
            }
        }
        assertTrue("both outcomes happened: rode $rode, deferred $deferred", rode > 0 && deferred > 0)
        assertTrue("a re-attached offer yielded to the announcement at least once", reordered > 0)
        for ((bucket, size) in withPq.sealedSizes) assertEquals(bucket, size)
    }

    /**
     * **PQ6** (§22.8.6): a **restored** peer. A holds an unacknowledged PQ-C offer encapsulated to
     * B's in-band key and that key itself; B restores from its seed and reconnects. The renewal
     * discards both on A, so A's next message carries a classical root and a fresh announcement,
     * and B's answer to it is already pair mode — one round trip, no `NO_SEAL_KEY`, no second
     * bundle fetch.
     */
    @Test
    fun pq6ARestoredPeerResumesPairModeWithinOneRoundTrip() {
        requireNative()
        val log = PqLog()
        world(log).use { world ->
            val alice = world.alice
            val (contactB, _) = arrangeStalePqOffer(world, log)

            // B restores and reconnects: a new session from B under the same Olm identity.
            val restored = world.restored(world.bob)
            restored.engine.onRestored()
            assertEquals(AddContactResult.ADDED, restored.engine.addContact(alice.card(), CardSource.QR_IN_PERSON))
            val contactAOnRestored = restored.engine.contacts().single().id
            assertEquals(1, restored.engine.reconnect(listOf(contactAOnRestored)))
            world.advanceTo(restored.clock.now + 49 * DmWorld.HOUR)
            restored.timeTriggeredPass()
            deliverBundle(world, from = alice, to = restored)
            world.deliverBetween(restored, alice)
            alice.hintPass()

            assertRenewalDiscardedPqState(alice)
            resumesWithinOneRoundTrip(world, log, alice, restored, contactB, contactAOnRestored)
        }
    }

    /** **PQ6**'s second half: a peer that **reset** the session (§8.7) — same generations, new session. */
    @Test
    fun pq6AResetPeerResumesPairModeWithinOneRoundTrip() {
        requireNative()
        val log = PqLog()
        world(log).use { world ->
            val alice = world.alice
            val bob = world.bob
            val (contactB, contactA) = arrangeStalePqOffer(world, log)

            assertEquals(SendResult.QUEUED, bob.engine.resetSession(contactA))
            deliverBundle(world, from = alice, to = bob, again = true)
            world.deliverBetween(bob, alice)
            alice.hintPass()

            assertRenewalDiscardedPqState(alice)
            resumesWithinOneRoundTrip(world, log, alice, bob, contactB, contactA)
        }
    }

    // ---------------------------------------------------------------- PQ6 helpers

    /**
     * Four weeks of two-way pair traffic, B writing first each week (twice: a newly minted offer of
     * B's goes first and B's announcement on the next send), so A holds B's newest generation key
     * in band. In the fourth week A's root is four weeks old and A's send replaces it (rule c) with
     * a **PQ-C** offer to that key, which B never answers: the stale state §22.8.6 is about.
     */
    private fun arrangeStalePqOffer(world: DmWorld, log: PqLog): Pair<ContactId, ContactId> {
        val alice = world.alice
        val bob = world.bob
        val (contactB, contactA) = establishBothWays(world)
        repeat(4) { week ->
            world.advanceTo(alice.clock.now + DmWorld.WEEK)
            alice.timeTriggeredPass()
            bob.timeTriggeredPass()
            repeat(2) { i ->
                assertEquals(SendResult.QUEUED, bob.engine.send(contactA, "b$week$i", null))
                world.deliver()
                alice.hintPass()
            }
            if (week < 3) {
                assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "a$week", null))
                world.deliver()
                bob.hintPass()
            }
        }
        // A's send now replaces its root (four weeks old) with a PQ-C offer to B's fresh key; it
        // is never delivered, so it stays unacknowledged.
        val offersBefore = log.offers.count { it.branch == alice.branch }
        assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "never read", null))
        val newest = log.offers.filter { it.branch == alice.branch }
        assertEquals("a new offer was minted", offersBefore + 1, newest.size)
        val stale = newest.last()
        assertNotNull("and it is PQ-C", stale.peerGenId)
        assertEquals(1_194, offerEnvLength(alice, stale.rootGen))
        assertTrue(
            "to a key B announced in band",
            peerPq(alice).any { it.source == "in_band" && it.genId == stale.peerGenId },
        )
        assertFalse(offerAcknowledged(alice, stale.rootGen))
        return contactB to contactA
    }

    /** §22.8.6 rule 1 on A, after B's renewal reached it. */
    private fun assertRenewalDiscardedPqState(alice: DmDevice) {
        assertTrue("B's keys are gone: ${peerPq(alice)}", peerPq(alice).isEmpty())
        var livePq = 0
        alice.sql.query(
            "SELECT count(*) FROM dm_pair_offer WHERE acknowledged = 0 AND length(offer_env) = 1194",
        ) { livePq = it.long(0).toInt() }
        assertEquals("no unacknowledged PQ-C offer survives", 0, livePq)
        assertNull("A announces its key again", pqAnnouncedWeek(alice))
    }

    @Suppress("LongParameterList")
    private fun resumesWithinOneRoundTrip(
        world: DmWorld,
        log: PqLog,
        alice: DmDevice,
        peer: DmDevice,
        contactB: ContactId,
        contactAOnPeer: ContactId,
    ) {
        // A's reply: a classical root (no key of the renewed B is held) and A's announcement.
        val offersBefore = log.offers.count { it.branch == alice.branch }
        assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "welcome back", null))
        val reply = log.offers.filter { it.branch == alice.branch }
        assertEquals(offersBefore + 1, reply.size)
        val root = reply.last()
        assertNull("classical, not a PQ offer to a key B may no longer hold", root.peerGenId)
        val encoded = log.encoded.last { it.branch == alice.branch }
        assertTrue(encoded.sealRootRode)
        assertTrue("and A's key rides beside it", encoded.pqKeyRode)
        world.deliverBetween(alice, peer)
        peer.hintPass()
        assertEquals(0, peer.engine.status().drops["pq_root_unopenable"] ?: 0)

        // One round trip: B's next message is sealed in pair mode under A's new root.
        val pairBefore = log.pairBlobs.count { it.branch == peer.branch && it.rootGen == root.rootGen }
        assertEquals(SendResult.QUEUED, peer.engine.send(contactAOnPeer, "pair again", null))
        assertEquals("no NO_SEAL_KEY: nothing is pending", 0, peer.engine.status().pendingSends)
        assertEquals(Establishment.READY, peer.engine.contacts().single().establishment)
        assertEquals(
            "sealed in pair mode under A's new root",
            pairBefore + 1,
            log.pairBlobs.count { it.branch == peer.branch && it.rootGen == root.rootGen },
        )
        world.deliverBetween(peer, alice)
        alice.hintPass()
        assertTrue(
            "A shows it: ${alice.engine.status().drops}",
            alice.engine.conversation(contactB, 50, null).any { it.text == "pair again" },
        )
        assertTrue("which acknowledges it on A (R12)", offerAcknowledged(alice, root.rootGen))
        // And B holds A's current generation key — in band, or from the bundle it fetched for the
        // new session when that is the same generation (then the announcement is not newer, §7.1).
        var current: Long? = null
        alice.sql.query("SELECT gen_id FROM olm_prekey_gen WHERE superseded_day IS NULL") { current = it.long(0) }
        assertTrue(
            "B holds A's current key: ${peerPq(peer)}",
            peerPq(peer).any { it.genId == current },
        )
    }

    // ---------------------------------------------------------------- PQ4 helpers

    /** Sends [bodies] from A with both PQ-C TLVs pending where the flow allows, and returns the sizes stored. */
    private fun relaySizes(world: DmWorld, bodies: List<Int>): List<Int> {
        val alice = world.alice
        val bob = world.bob
        val (contactB, contactA) = establishBothWays(world)
        // Five weeks of B's traffic keep a fresh key of B's on A; A's first send of week 5 then
        // replaces its root with a PQ-C offer, and each week's first send carries A's key.
        repeat(5) {
            world.advanceTo(alice.clock.now + DmWorld.WEEK)
            alice.timeTriggeredPass()
            bob.timeTriggeredPass()
            assertEquals(SendResult.QUEUED, bob.engine.send(contactA, "keep", null))
            world.deliver()
            alice.hintPass()
            // A's sends of this week, undelivered, so its PQ offer stays pending and re-attaches.
            for (body in bodies) {
                assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "x".repeat(body), null))
            }
        }
        val out = ArrayList<Int>()
        alice.sql.query("SELECT length(ciphertext) FROM outbox_op ORDER BY rowid") { out += it.long(0).toInt() }
        bob.sql.query("SELECT length(ciphertext) FROM outbox_op ORDER BY rowid") { out += it.long(0).toInt() }
        return out
    }

    // ---------------------------------------------------------------- shared helpers

    private fun establishBothWays(world: DmWorld): Pair<ContactId, ContactId> {
        world.alice.engine.onActivated()
        world.bob.engine.onActivated()
        assertEquals(
            AddContactResult.ADDED,
            world.alice.engine.addContact(world.bob.card(), CardSource.QR_IN_PERSON),
        )
        val contactB = world.alice.engine.contacts().single().id
        assertEquals(SendResult.QUEUED, world.alice.engine.send(contactB, "hello", null))
        world.deliver()
        world.alice.timeTriggeredPass()
        world.advanceTo(world.alice.clock.now + 3 * DmWorld.MINUTE)
        world.alice.timeTriggeredPass()
        world.deliver()
        world.bob.hintPass()
        val contactA = world.bob.engine.contacts().single().id
        assertTrue(world.bob.engine.acceptRequest(contactA))
        assertEquals(SendResult.QUEUED, world.bob.engine.send(contactA, "hi back", null))
        world.deliver()
        world.alice.hintPass()
        assertEquals(SendResult.QUEUED, world.alice.engine.send(contactB, "pair now", null))
        world.deliver()
        world.bob.hintPass()
        assertEquals(0, world.bob.engine.status().drops.values.sum())
        return contactB to contactA
    }

    private fun deliverBundle(world: DmWorld, from: DmDevice, to: DmDevice, again: Boolean = false) {
        world.deliverBetween(from, to, again)
        to.timeTriggeredPass()
        world.advanceTo(to.clock.now + 3 * DmWorld.MINUTE)
        to.timeTriggeredPass()
    }

    private class PeerKey(val genId: Long, val week: Long, val source: String) {
        override fun toString(): String = "PeerKey($genId, $week, $source)"
    }

    private fun peerPq(device: DmDevice): List<PeerKey> {
        val out = ArrayList<PeerKey>()
        device.sql.query("SELECT gen_id, bundle_week, source FROM dm_peer_pq ORDER BY bundle_week") {
            out += PeerKey(it.long(0), it.long(1), it.string(2))
        }
        return out
    }

    private fun offerEnvLength(device: DmDevice, rootGen: Int): Int? {
        var length: Int? = null
        device.sql.query(
            "SELECT length(offer_env) FROM dm_pair_offer WHERE root_gen = ?",
            listOf(rootGen.toLong()),
        ) { if (!it.isNull(0)) length = it.long(0).toInt() }
        return length
    }

    private fun offerAcknowledged(device: DmDevice, rootGen: Int): Boolean {
        var acknowledged = false
        device.sql.query(
            "SELECT acknowledged FROM dm_pair_offer WHERE root_gen = ?",
            listOf(rootGen.toLong()),
        ) { acknowledged = it.long(0) == 1L }
        return acknowledged
    }

    private fun pqAnnouncedWeek(device: DmDevice): Long? {
        var week: Long? = null
        device.sql.query("SELECT pq_announced_week FROM dm_contact") {
            week = if (it.isNull(0)) null else it.long(0)
        }
        return week
    }

    private companion object {
        const val O_MAX = 1_664
        const val L0_FIXED = 52
        const val EXT_RESERVE = 160
        const val SEAL_ROOT_TLV = 46
        const val SEAL_ROOT_PQ_TLV = 1_170
        const val PQ_KEY_TLV = 1_232
        const val CLASSICAL_OFFER_ENV = 70
        const val PQ_OFFER_ENV = 1_194

        fun capacity(bucket: Int): Int = bucket - O_MAX

        /** R-B1 as §6.6 writes it — the test's oracle, not the engine's code path. */
        fun expectedBucket(body: Int): Int =
            listOf(4_096, 16_384, 65_536).first { L0_FIXED + body + EXT_RESERVE <= it - O_MAX }
    }
}
