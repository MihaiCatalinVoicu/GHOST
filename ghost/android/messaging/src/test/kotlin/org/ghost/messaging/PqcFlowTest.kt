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
        corruptPqKey: Boolean = false,
        peerGenIdOffset: Long = 0L,
    ): DmWorld {
        val world = DmWorld(
            decorate = { branch, inner ->
                PqRecorder(inner, branch, log, forceClassical, stripPqKey, corruptPqKey, peerGenIdOffset)
            },
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

    // ------------------------------------------------------- the slice S13 review's cases

    /**
     * **A PQ-C offer with no slack is replaced by a classical one in the same send** (the S13
     * review's finding 1; §9.4 "otherwise the classical `seal_root` is used and the next periodic
     * replacement retries", R-C5).
     *
     * A's first root offer rides on a 1 500-byte message: 4 KiB, whose slack admits a
     * `seal_root_pq` only up to a 1 210-byte body. Before the review the PQ-C offer was dropped,
     * nothing was written, and every later send minted PQ-C again — so with such messages the first
     * root never reached B, and rule (c) never replaced a root. Now the classical form rides in the
     * same send, B answers in pair mode at once, the replacement four weeks on happens on a
     * mid-size message too (classical again), and the one after that, on a short message, is PQ-C.
     */
    @Test
    @Suppress("LongMethod")
    fun aPqOfferThatDoesNotFitIsReplacedByAClassicalOneInTheSameSend() {
        requireNative()
        val log = PqLog()
        world(log).use { world ->
            val alice = world.alice
            val bob = world.bob
            val midSize = "x".repeat(1_500)
            val (contactB, contactA) = establishBothWays(world, firstPairBody = midSize)

            val first = log.offers.filter { it.branch == alice.branch }
            assertEquals("a PQ-C attempt, then the classical offer that replaced it", 2, first.size)
            assertNotNull("A held B's bundle key, so PQ-C was tried", first[0].peerGenId)
            assertNull(first[1].peerGenId)
            assertEquals("one generation, one offer", first[0].rootGen, first[1].rootGen)
            val g0 = first[1].rootGen
            assertEquals("the stored offer is the classical TLV", 70, offerEnvLength(alice, g0))
            val carried = log.encoded.last { it.branch == alice.branch }
            assertEquals(midSize.length, carried.bodyLength)
            assertTrue("the classical offer rode", carried.sealRootRode)
            assertFalse(carried.sealRootPqRode)
            assertEquals(1, alice.engine.status().pq["offer_classical_no_slack"])

            // B answers under it in pair mode, at once: no provisional window, no `NO_SEAL_KEY`.
            assertEquals(SendResult.QUEUED, bob.engine.send(contactA, "under your root", null))
            assertTrue(log.pairBlobs.any { it.branch == bob.branch && it.rootGen == g0 })
            world.deliver()
            alice.hintPass()
            assertTrue("acknowledged (R12)", offerAcknowledged(alice, g0))

            // Four weeks of B's traffic (A keeps a fresh key of B's), then rule (c) on A's next
            // send, again a mid-size one: the root is replaced, classically.
            fourWeeksOfB(world, contactA)
            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, midSize, null))
            val second = log.offers.filter { it.branch == alice.branch }.drop(first.size)
            assertEquals("rule (c) replaced the root: ${second.map { it.peerGenId }}", 2, second.size)
            assertEquals(g0 + 1, second.last().rootGen)
            assertNull(second.last().peerGenId)
            assertEquals(70, offerEnvLength(alice, g0 + 1))
            assertEquals(2, alice.engine.status().pq["offer_classical_no_slack"])
            world.deliver()
            bob.hintPass()
            assertEquals(SendResult.QUEUED, bob.engine.send(contactA, "under the second root", null))
            world.deliver()
            alice.hintPass()
            assertTrue(offerAcknowledged(alice, g0 + 1))

            // The next replacement, on a short message, is PQ-C: the fallback cost one cycle.
            fourWeeksOfB(world, contactA)
            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "short", null))
            val third = log.offers.filter { it.branch == alice.branch }.drop(first.size + second.size)
            assertEquals(1, third.size)
            assertEquals(g0 + 2, third.single().rootGen)
            assertNotNull("PQ-C again", third.single().peerGenId)
            assertEquals(1_194, offerEnvLength(alice, g0 + 2))
            assertEquals("nothing was dropped", 0, bob.engine.status().drops.values.sum())
        }
    }

    /**
     * **Every generation from the newest acknowledged one keeps advancing** (the S13 review's
     * finding 2; §6.3 "a generation stops advancing once a pair envelope under a newer generation
     * from c opens").
     *
     * A's acknowledged root g0 is replaced by rule (c) with a PQ-C g1 whose messages are all lost;
     * at `base_week + 3` §22.8.6 rule 2 replaces the still-unacknowledged g1 with g2, lost too. B
     * never saw either and keeps sealing under g0. The first version of the S13 rule advanced
     * only the newest two generations, so from the next week B's envelopes under g0 found no key
     * on A and were dropped as `unknown_seal`, silently.
     */
    @Test
    @Suppress("LongMethod")
    fun aGenerationBelowTwoUnacknowledgedOffersKeepsAdvancing() {
        requireNative()
        val log = PqLog()
        world(log).use { world ->
            val alice = world.alice
            val bob = world.bob
            val (contactB, contactA) = establishBothWays(world)
            assertEquals(SendResult.QUEUED, bob.engine.send(contactA, "ack", null))
            world.deliver()
            alice.hintPass()
            val g0 = log.offers.last { it.branch == alice.branch }.rootGen
            assertTrue(offerAcknowledged(alice, g0))

            fun week(loseA: Boolean) {
                world.advanceTo(alice.clock.now + DmWorld.WEEK)
                alice.timeTriggeredPass()
                bob.timeTriggeredPass()
                assertEquals(SendResult.QUEUED, bob.engine.send(contactA, "b", null))
                world.deliverBetween(bob, alice)
                alice.hintPass()
                assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "a", null))
                if (loseA) {
                    world.lose(alice, bob)
                } else {
                    world.deliverBetween(alice, bob)
                    bob.hintPass()
                }
            }
            repeat(3) { week(loseA = false) }
            // Week 4: rule (c) mints g1, PQ-C, and its message is lost; so are weeks 5 and 6.
            week(loseA = true)
            val g1 = log.offers.last { it.branch == alice.branch }
            assertEquals(g0 + 1, g1.rootGen)
            assertNotNull("g1 is PQ-C", g1.peerGenId)
            repeat(2) { week(loseA = true) }
            assertFalse(offerAcknowledged(alice, g1.rootGen))
            // Week 7 = base_week(g1) + 3: §22.8.6 rule 2 replaces the unacknowledged g1 with g2.
            week(loseA = true)
            assertEquals(g0 + 2, log.offers.last { it.branch == alice.branch }.rootGen)
            val inGenerations = inKeyGenerations(alice)
            assertEquals("three generations hold in keys", setOf(g0, g0 + 1, g0 + 2), inGenerations)

            // Week 8: the sweep crosses a week boundary with g2 and g1 both unacknowledged.
            world.advanceTo(alice.clock.now + DmWorld.WEEK)
            alice.timeTriggeredPass()
            bob.timeTriggeredPass()
            val unknownBefore = alice.engine.status().drops["unknown_seal"] ?: 0
            assertEquals(SendResult.QUEUED, bob.engine.send(contactA, "still under g0", null))
            assertEquals("B seals under g0", g0, log.pairBlobs.last { it.branch == bob.branch }.rootGen)
            world.deliverBetween(bob, alice)
            alice.hintPass()
            assertTrue(
                "A opens it: ${alice.engine.status().drops}",
                alice.engine.conversation(contactB, 50, null).any { it.text == "still under g0" },
            )
            assertEquals(unknownBefore, alice.engine.status().drops["unknown_seal"] ?: 0)
        }
    }

    /**
     * **A device that re-establishes announces its key again** (the S13 review's finding 5;
     * §22.8.6 rule 1 on the contact's side). A resets the session: B takes A's new first flight as
     * a renewal and deletes every key of A's it held, a responder session naming none. Before the
     * review A's `pq_announced_week` survived its own `EST-READY`, so A did not announce its
     * current generation again until the next one, and B's offers to A stayed classical.
     */
    @Test
    fun aDeviceThatReEstablishesAnnouncesItsKeyAgain() {
        requireNative()
        val log = PqLog()
        world(log).use { world ->
            val alice = world.alice
            val bob = world.bob
            val (contactB, contactA) = establishBothWays(world)
            assertEquals(SendResult.QUEUED, bob.engine.send(contactA, "ack", null))
            world.deliver()
            alice.hintPass()
            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "with my key", null))
            world.deliver()
            bob.hintPass()
            val current = currentGeneration(alice)
            assertTrue("B holds A's key: ${peerPq(bob)}", peerPq(bob).any { it.genId == current })
            assertNotNull(pqAnnouncedWeek(alice))

            assertEquals(SendResult.QUEUED, alice.engine.resetSession(contactB))
            deliverBundle(world, from = bob, to = alice, again = true)
            assertNull("A's EST-READY: the key is announced again", pqAnnouncedWeek(alice))
            world.deliverBetween(alice, bob)
            bob.hintPass()
            assertTrue("B's renewal dropped A's keys: ${peerPq(bob)}", peerPq(bob).isEmpty())

            // B answers on the new session, and A's next normal outputs carry its new root and then,
            // the two not fitting one 4 KiB message, its announcement.
            assertEquals(SendResult.QUEUED, bob.engine.send(contactA, "after the reset", null))
            world.deliver()
            alice.hintPass()
            repeat(2) { i ->
                assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "again $i", null))
                world.deliver()
                bob.hintPass()
            }
            assertEquals(current, currentGeneration(alice))
            assertTrue(
                "B holds A's current key again: ${peerPq(bob)}",
                peerPq(bob).any { it.genId == current && it.source == "in_band" },
            )
        }
    }

    /**
     * RECV's two PQ-C refusals **at the engine** (the S13 review: they were tested only in the
     * crate and at the bridge). A `seal_root_pq` naming a generation B never had is
     * `pq_root_unopenable` (§22.8.6 rule 3) and a `pq_key` whose X25519 half is low-order is
     * `bad_pq_key` (§22.8.2 rule 3): each is counted and ignored, and the message that carried it
     * is shown.
     */
    @Test
    fun anUnopenablePqRootAndAnInvalidPqKeyAreCountedAndTheMessageApplies() {
        requireNative()
        val log = PqLog()
        world(log, corruptPqKey = true, peerGenIdOffset = 0x1_0000L).use { world ->
            val alice = world.alice
            val bob = world.bob
            val (contactB, contactA) = establishBothWays(world, expectNoDrops = false)
            assertTrue("A's first offer is PQ-C", log.encoded.last { it.branch == alice.branch }.sealRootPqRode)
            assertEquals(1, bob.engine.status().drops["pq_root_unopenable"])
            assertTrue(bob.engine.conversation(contactA, 50, null).any { it.text == "pair now" })

            // A's next message: the announcement first (the offer is a re-attachment), corrupted.
            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "with a bad key", null))
            assertTrue(log.encoded.last { it.branch == alice.branch }.pqKeyRode)
            world.deliver()
            bob.hintPass()
            assertEquals(1, bob.engine.status().drops["bad_pq_key"])
            assertTrue("nothing stored in band: ${peerPq(bob)}", peerPq(bob).none { it.source == "in_band" })
            assertTrue(bob.engine.conversation(contactA, 50, null).any { it.text == "with a bad key" })
        }
    }

    /**
     * A `seal_root_pq` that cannot be opened **because the DM context is unavailable** is not the
     * peer's doing (the S13 review's finding 6): it is not counted as `pq_root_unopenable`, RECV
     * answers `CRYPTO_UNAVAILABLE` like every other unavailable native call, the message itself is
     * applied, and the root is not lost — A re-attaches the unacknowledged offer, B opens it once the
     * context is back, and B's next message is sealed under it.
     */
    @Test
    fun aPqRootThatMeetsAClosedContextIsNotCountedAgainstThePeer() {
        requireNative()
        val log = PqLog()
        world(log).use { world ->
            val alice = world.alice
            val bob = world.bob
            log.openUnavailable = true
            val (contactB, contactA) = establishBothWays(world)
            val g0 = log.offers.last { it.branch == alice.branch }
            assertNotNull("A's first offer is PQ-C", g0.peerGenId)
            assertEquals("not the peer's doing", null, bob.engine.status().drops["pq_root_unopenable"])
            assertTrue(bob.engine.conversation(contactA, 50, null).any { it.text == "pair now" })

            log.openUnavailable = false
            // The announcement goes first on A's next message (the offer is a re-attachment), and
            // the offer rides on the one after.
            repeat(2) { i ->
                assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "again $i", null))
                world.deliver()
                bob.hintPass()
            }
            assertEquals(SendResult.QUEUED, bob.engine.send(contactA, "under your root", null))
            assertEquals(g0.rootGen, log.pairBlobs.last { it.branch == bob.branch }.rootGen)
            world.deliver()
            alice.hintPass()
            assertTrue(offerAcknowledged(alice, g0.rootGen))
            assertEquals(0, bob.engine.status().drops.values.sum())
        }
    }

    /** Four weeks of B's messages to A, each delivered, with both devices' weekly passes. */
    private fun fourWeeksOfB(world: DmWorld, contactA: ContactId) {
        repeat(4) {
            world.advanceTo(world.alice.clock.now + DmWorld.WEEK)
            world.alice.timeTriggeredPass()
            world.bob.timeTriggeredPass()
            assertEquals(SendResult.QUEUED, world.bob.engine.send(contactA, "b$it", null))
            world.deliver()
            world.alice.hintPass()
        }
    }

    private fun inKeyGenerations(device: DmDevice): Set<Int> {
        val out = HashSet<Int>()
        device.sql.query("SELECT DISTINCT root_gen FROM dm_pair_key WHERE direction = 'in'") {
            out += it.long(0).toInt()
        }
        return out
    }

    private fun currentGeneration(device: DmDevice): Long? {
        var current: Long? = null
        device.sql.query("SELECT gen_id FROM olm_prekey_gen WHERE superseded_day IS NULL") {
            current = it.long(0)
        }
        return current
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
        // No second bundle fetch (the slice S13 review: this was in prose only). A bundle fetch is
        // an establishment attempt — `EST-START` listening on the contact's bundle namespace — and
        // neither side has one running, or anything pending that would start one.
        for (device in listOf(alice, peer)) {
            assertEquals("${device.branch}: nothing establishing", 0, device.engine.status().establishing)
            assertEquals("${device.branch}: nothing pending", 0, device.engine.status().pendingSends)
            assertEquals(Establishment.READY, device.engine.contacts().single().establishment)
        }
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

    /**
     * A scans B, B accepts and answers, and A's first normal output — [firstPairBody], which
     * carries A's first root offer — reaches B.
     */
    private fun establishBothWays(
        world: DmWorld,
        firstPairBody: String = "pair now",
        expectNoDrops: Boolean = true,
    ): Pair<ContactId, ContactId> {
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
        assertEquals(SendResult.QUEUED, world.alice.engine.send(contactB, firstPairBody, null))
        world.deliver()
        world.bob.hintPass()
        if (expectNoDrops) assertEquals(0, world.bob.engine.status().drops.values.sum())
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
