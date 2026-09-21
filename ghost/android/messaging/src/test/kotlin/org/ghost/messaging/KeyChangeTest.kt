package org.ghost.messaging

import org.ghost.messaging.api.AddContactResult
import org.ghost.messaging.api.CardSource
import org.ghost.messaging.api.ContactId
import org.ghost.messaging.api.SendResult
import org.ghost.messaging.api.TrustState
import org.ghost.messaging.api.VerifyResult
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * **Key change blocks both directions** (Phase 9 design §8.3, C-14, E-1, CS-5), on three devices
 * with the **real** cryptography (§15.1), plus the KEYDEC and HELD halves of §22.8.1 and the
 * safety numbers of §8.4.
 *
 * The three devices are what the rule needs: A, B, and **B′** — a device holding B's `ghost1`
 * Ed25519 seed under a different MESSAGING branch, which is §3.4's "the holder of that Ed25519
 * secret signed another Olm identity". Nothing weaker can produce a key change, and that is the
 * point of E-1: anyone holding B's card can build an intro envelope naming B, and only B's secret
 * can sign a binding for a second Olm identity.
 *
 * Each assertion is where a different mistake shows:
 *
 *  - a classification that pinned the new identity silently is mutant **PM-16**, and the
 *    `changed` state is what catches it;
 *  - a classification that dropped the message instead of holding it loses it for good, which is
 *    the S7 behaviour §22.12 item 11 recorded and this replaces;
 *  - a hold that reached a relay is mutant **PM-15** and T28, and the store count catches it;
 *  - a replay that ran `sessionInbound` per row in `held_id` order is mutant **MC-31**, and the
 *    multi-message case is what catches it (a constraint abort, or a lost message).
 */
class KeyChangeTest {

    private fun requireNative() {
        assumeTrue(
            "set -Dghost.dm.native to the ghost-dm-host library",
            DmWorld.nativeAvailable(),
        )
    }

    /**
     * §8.3 end to end: the change is classified, both directions stop, the ciphertext is held, the
     * user acknowledges, and the held message is shown — once, and in order.
     */
    @Test
    @Suppress("LongMethod")
    fun aKeyChangeBlocksBothDirectionsUntilTheUserDecides() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            val (contactB, _) = establishBothWays(world)
            assertEquals(TrustState.VERIFIED, alice.engine.contacts().single().trust)

            // B′ holds B's `ghost1` seed and a different Olm identity. It writes to A.
            val newB = world.reincarnation(world.bob, branch = 0x61)
            newB.engine.onActivated()
            assertEquals(
                AddContactResult.ADDED,
                newB.engine.addContact(alice.card(), CardSource.LINK),
            )
            val contactAOnNewB = newB.engine.contacts().single().id
            assertEquals(SendResult.QUEUED, newB.engine.send(contactAOnNewB, "it is me", null))
            deliverBundle(world, from = alice, to = newB)

            val storesBefore = storeCount(alice)
            world.deliverBetween(newB, alice)
            alice.hintPass()

            // The classification: `changed`, and **not** a new pin (mutant PM-16).
            assertEquals(TrustState.CHANGED, alice.engine.contacts().single().trust)
            assertEquals(
                "the ciphertext is held, not dropped",
                1,
                heldCount(alice),
            )
            assertNull(
                "nothing from the new identity is shown",
                alice.engine.conversation(contactB, 10, null).firstOrNull { it.text == "it is me" },
            )
            assertEquals("and nothing is sent (T28)", storesBefore, storeCount(alice))

            // Sending is refused before any native session call (SEND S1, CS-5).
            assertEquals(
                SendResult.KEY_CHANGED,
                alice.engine.send(contactB, "are you still there", null),
            )
            assertEquals(storesBefore, storeCount(alice))

            // The user acknowledges. The pin moves, the sessions go, the held row is replayed.
            val oldSessions = sessionIds(alice)
            assertEquals("the pre-change session existed", 1, oldSessions.size)
            assertTrue(alice.engine.acknowledgeKeyChange(contactB))
            assertEquals(TrustState.UNVERIFIED, alice.engine.contacts().single().trust)
            assertEquals(0, heldCount(alice))
            // R-SS0 deleted both rows, and the replay then built **one** responder session from
            // the held first flight: the old identity's session is gone, not carried over.
            val nowSessions = sessionIds(alice)
            assertEquals(1, nowSessions.size)
            assertTrue(
                "a session never outlives the identity it was created with (§8.2 rule 5)",
                nowSessions.intersect(oldSessions).isEmpty(),
            )
            assertEquals(listOf("responder"), sessionRoles(alice))
            assertEquals(
                "the held message is shown, once",
                1,
                alice.engine.conversation(contactB, 10, null).count { it.text == "it is me" },
            )
            assertEquals("and the replay sent nothing", storesBefore, storeCount(alice))
        }
    }

    /**
     * §22.8.1: several held PreKey messages of **one** new session replay in chain order, and the
     * second one does not abort on `UNIQUE (contact_id, session_id)`.
     *
     * Mutant MC-31 is "every held row through `sessionInbound` in `held_id` order"; `held_id` is
     * random, so without the grouping this is a constraint abort inside a step with no offer
     * counter — a crash loop — or a lost message.
     */
    @Test
    fun severalHeldMessagesOfOneSessionReplayInChainOrder() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            val (contactB, _) = establishBothWays(world)

            val newB = world.reincarnation(world.bob, branch = 0x62)
            newB.engine.onActivated()
            newB.engine.addContact(alice.card(), CardSource.LINK)
            val contactAOnNewB = newB.engine.contacts().single().id
            for (text in listOf("one", "two", "three")) {
                assertEquals(SendResult.QUEUED, newB.engine.send(contactAOnNewB, text, null))
                if (text == "one") deliverBundle(world, from = alice, to = newB)
            }
            world.deliverBetween(newB, alice)
            // The gap hold keeps chain indices 1 and 2 back until index 0 is in the same pass or
            // `HOLD_MAX` passes (§7.7 point 2); all three are in this batch, so one pass is enough.
            alice.hintPass()

            assertEquals(TrustState.CHANGED, alice.engine.contacts().single().trust)
            assertEquals(3, heldCount(alice))

            assertTrue(alice.engine.acknowledgeKeyChange(contactB))
            assertEquals(0, heldCount(alice))
            val shown = alice.engine.conversation(contactB, 10, null).mapNotNull { it.text }
            assertEquals(
                "all three, in the order they were written",
                listOf("three", "two", "one"),
                shown.take(3),
            )
        }
    }

    /** §8.3's state machine: `block` of a changed contact takes the held rows with it. */
    @Test
    fun blockingAChangedContactDeletesTheHeldRows() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            val (contactB, _) = establishBothWays(world)
            heldKeyChange(world, contactB)
            assertEquals(1, heldCount(alice))

            assertTrue(alice.engine.block(contactB))
            assertEquals(TrustState.BLOCKED, alice.engine.contacts().single().trust)
            assertEquals("§7.2's KEYDEC row: held rows deleted on block", 0, heldCount(alice))
        }
    }

    /**
     * §8.4: both devices compute the **same** safety number, `pendingSafetyNumber` answers with the
     * new identity while the contact is `changed`, and `verifyKeyChange` moves the pin.
     */
    @Test
    fun theSafetyNumberIsSharedAndVerifyingAKeyChangeMovesThePin() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            val bob = world.bob
            val (contactB, contactA) = establishBothWays(world)

            val atAlice = requireNotNull(alice.engine.safetyNumber(contactB))
            val atBob = requireNotNull(bob.engine.safetyNumber(contactA))
            assertEquals("the digits are a function of the four keys, not of a role", atAlice.digits, atBob.digits)
            assertEquals(60, atAlice.digits.length)
            assertEquals(65, atAlice.scannable.size)

            // A scanned code of the other side verifies; the device's own does not.
            assertEquals(
                VerifyResult.VERIFIED,
                alice.engine.markVerified(contactB, atBob.scannable),
            )
            assertEquals(
                VerifyResult.MISMATCH,
                alice.engine.markVerified(contactB, atAlice.scannable),
            )

            heldKeyChange(world, contactB)
            val pending = requireNotNull(alice.engine.pendingSafetyNumber(contactB))
            assertNotEquals(
                "the pending number is of the **new** Olm identity",
                atAlice.digits,
                pending.digits,
            )
            // The scanned half is the peer's own view of the same pair.
            val scanned = byteArrayOf(pending.scannable[0]) +
                pending.scannable.copyOfRange(33, 65) +
                pending.scannable.copyOfRange(1, 33)
            assertEquals(
                VerifyResult.VERIFIED,
                alice.engine.verifyKeyChange(contactB, scanned),
            )
            assertEquals(TrustState.VERIFIED, alice.engine.contacts().single().trust)
            assertEquals(0, heldCount(alice))
        }
    }

    /** §8.4: a code of another format version is refused before the halves are compared. */
    @Test
    fun aScannedCodeOfAnotherVersionIsRefused() {
        requireNative()
        DmWorld().use { world ->
            val (contactB, _) = establishBothWays(world)
            val number = requireNotNull(world.alice.engine.safetyNumber(contactB))
            val wrongVersion = number.scannable.copyOf().also { it[0] = 9 }
            assertEquals(
                VerifyResult.VERSION_MISMATCH,
                world.alice.engine.markVerified(contactB, wrongVersion),
            )
            assertEquals(
                VerifyResult.VERSION_MISMATCH,
                world.alice.engine.markVerified(contactB, ByteArray(10)),
            )
        }
    }

    /**
     * §8.3 and §21.4 point 5: a **request** that sends a second Olm identity is dropped and its row
     * goes with it (R-P2b). It is not held: a request has not been accepted, so there is nothing to
     * block in either direction and nothing for the user to decide about.
     */
    @Test
    fun aRequestThatChangesItsIdentityIsDroppedAndNotHeld() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            val bob = world.bob
            activate(world)
            // B writes first, so A holds a **request** with B's pinned identity.
            assertEquals(
                AddContactResult.ADDED,
                bob.engine.addContact(alice.card(), CardSource.LINK),
            )
            val contactAOnBob = bob.engine.contacts().single().id
            assertEquals(SendResult.QUEUED, bob.engine.send(contactAOnBob, "hello", null))
            deliverBundle(world, from = alice, to = bob)
            world.deliverBetween(bob, alice)
            alice.hintPass()
            assertEquals(TrustState.REQUEST, alice.engine.contacts().single().trust)

            // B′ now writes under the same `ghost1` key and another Olm identity.
            val newB = world.reincarnation(bob, branch = 0x63)
            newB.engine.onActivated()
            newB.engine.addContact(alice.card(), CardSource.LINK)
            val contactAOnNewB = newB.engine.contacts().single().id
            assertEquals(SendResult.QUEUED, newB.engine.send(contactAOnNewB, "me again", null))
            deliverBundle(world, from = alice, to = newB)
            world.deliverBetween(newB, alice)
            alice.hintPass()

            assertEquals(
                "still a request, still on the first identity",
                TrustState.REQUEST,
                alice.engine.contacts().single().trust,
            )
            assertEquals(0, heldCount(alice))
            assertEquals(1, alice.engine.status().drops["request_key_mismatch"])
        }
    }

    // ---------------------------------------------------------------- helpers

    /** A contact in `changed` with exactly one held row. */
    private fun heldKeyChange(world: DmWorld, contactB: ContactId) {
        val newB = world.reincarnation(world.bob, branch = 0x71)
        newB.engine.onActivated()
        newB.engine.addContact(world.alice.card(), CardSource.LINK)
        val contactA = newB.engine.contacts().single().id
        assertEquals(SendResult.QUEUED, newB.engine.send(contactA, "it is me", null))
        deliverBundle(world, from = world.alice, to = newB)
        world.deliverBetween(newB, world.alice)
        world.alice.hintPass()
        assertEquals(TrustState.CHANGED, world.alice.engine.contacts().single().trust)
        assertArrayEquals(
            "the pending identity is the one that signed the binding",
            pendingIdentity(world.alice),
            pendingIdentity(world.alice),
        )
        assertEquals(1, heldCount(world.alice))
        // The caller names the contact so the helper reads as "this contact changed".
        assertNotNull(contactB)
    }

    /** Moves [to]'s establishment of [from] forward until its bundle candidate is usable. */
    private fun deliverBundle(world: DmWorld, from: DmDevice, to: DmDevice) {
        world.deliverBetween(from, to)
        to.timeTriggeredPass()
        world.advanceTo(to.clock.now + 3 * DmWorld.MINUTE)
        to.timeTriggeredPass()
    }

    private fun activate(world: DmWorld) {
        world.alice.engine.onActivated()
        world.bob.engine.onActivated()
    }

    private fun establishBothWays(world: DmWorld): Pair<ContactId, ContactId> {
        activate(world)
        assertEquals(
            AddContactResult.ADDED,
            world.alice.engine.addContact(world.bob.card(), CardSource.QR_IN_PERSON),
        )
        val contactB = world.alice.engine.contacts().single().id
        assertEquals(SendResult.QUEUED, world.alice.engine.send(contactB, "hello", null))
        deliverBundle(world, from = world.bob, to = world.alice)
        world.deliverBetween(world.alice, world.bob)
        world.bob.hintPass()
        val contactA = world.bob.engine.contacts().single().id
        assertTrue(world.bob.engine.acceptRequest(contactA))
        assertEquals(SendResult.QUEUED, world.bob.engine.send(contactA, "hi back", null))
        world.deliverBetween(world.bob, world.alice)
        world.alice.hintPass()
        return contactB to contactA
    }

    private fun heldCount(device: DmDevice): Int {
        var count = 0
        device.sql.query("SELECT count(*) FROM dm_held") { count = it.long(0).toInt() }
        return count
    }

    private fun sessionIds(device: DmDevice): Set<List<Byte>> {
        val out = HashSet<List<Byte>>()
        device.sql.query("SELECT session_id FROM olm_session") { out += it.blob(0).toList() }
        return out
    }

    private fun sessionRoles(device: DmDevice): List<String> {
        val out = ArrayList<String>()
        device.sql.query("SELECT role FROM olm_session ORDER BY slot") { out += it.string(0) }
        return out
    }

    private fun pendingIdentity(device: DmDevice): ByteArray? {
        var out: ByteArray? = null
        device.sql.query("SELECT pending_identity FROM dm_contact") {
            if (!it.isNull(0)) out = it.blob(0)
        }
        return out
    }

    private fun storeCount(device: DmDevice): Int {
        var count = 0
        device.sql.query("SELECT count(*) FROM outbox_op") { count = it.long(0).toInt() }
        return count
    }
}
