package org.ghost.messaging

import org.ghost.messaging.api.AddContactResult
import org.ghost.messaging.api.CardSource
import org.ghost.messaging.api.ContactId
import org.ghost.messaging.api.RevocationReason
import org.ghost.messaging.api.SendResult
import org.ghost.messaging.api.TrustState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Revocation v2, the scheduled notices, reset and restore-and-reconnect (Phase 9 design §8.5,
 * §8.6, §8.7, §21.9 rule 1), on the **real** cryptography (§15.1).
 *
 * The three flows share one property and it is the reason they are in one file: each is a **user
 * action** that produces relay traffic at a minute the user did not choose. A revocation notice
 * goes out at `U[0, 24 h]`, a reconnect notice at `U[0, 48 h]`, and both offsets are drawn at the
 * action and persisted — because a burst of k deposits into k inboxes inside one relay session
 * shows a degree of k (RP §3.8), and an offset kept in memory would collapse back into a burst at
 * the next process start. The due step is time-triggered for the other half of the same rule
 * (§21.9 rule 1, mutant PM-30): a card holder must not be able to deposit a probe during this
 * device's session and watch the notices follow.
 */
class TrustFlowTest {

    private fun requireNative() {
        assumeTrue(
            "set -Dghost.dm.native to the ghost-dm-host library",
            DmWorld.nativeAvailable(),
        )
    }

    /**
     * §8.5 end to end: B issues, B notifies, the notice goes out at its drawn minute, and A's
     * contact becomes `revoked` — terminal, with its sessions, keys and pending sends gone.
     */
    @Test
    fun aRevocationTravelsInsideE2eAndBlocksTheContactForGood() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            val bob = world.bob
            val (contactB, contactA) = establishBothWays(world)

            val certificate = requireNotNull(bob.engine.issueRevocation(RevocationReason.DEVICE_LOST))
            assertEquals("the certificate v2 is 102 bytes (§8.5)", 102, certificate.size)
            val storesAfterIssue = storeCount(bob)

            assertEquals(1, bob.engine.notifyContactsOfRevocation(certificate))
            assertEquals(
                "issuing and scheduling send nothing: the offset is drawn and persisted",
                storesAfterIssue,
                storeCount(bob),
            )
            assertEquals(1, scheduledCount(bob))

            // A hint pass must not send it: §21.9 rule 2 keeps the due controls off that path.
            bob.hintPass()
            assertEquals(storesAfterIssue, storeCount(bob))

            world.advanceTo(bob.clock.now + 25 * DmWorld.HOUR)
            bob.timeTriggeredPass()
            assertEquals("the notice is one store", storesAfterIssue + 1, storeCount(bob))
            assertEquals(0, scheduledCount(bob))

            world.deliverBetween(bob, alice)
            alice.hintPass()
            assertEquals(TrustState.REVOKED, alice.engine.contacts().single().trust)
            assertEquals(1, alice.engine.status().drops["revoked"])
            assertEquals("both sessions go with it (§8.5)", 0, sessionCount(alice))
            assertEquals(SendResult.REVOKED, alice.engine.send(contactB, "still there?", null))

            // Nothing from B is shown again: an intro envelope hits the revoked contact at R5.
            assertEquals(SendResult.QUEUED, bob.engine.send(contactA, "ignored", null))
            val shownBefore = alice.engine.conversation(contactB, 10, null).size
            world.deliverBetween(bob, alice)
            alice.hintPass()
            assertEquals(shownBefore, alice.engine.conversation(contactB, 10, null).size)
        }
    }

    /** §8.5: a certificate that names another identity is counted and never applied. */
    @Test
    fun aRevocationOfAnotherIdentityIsRefused() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            val bob = world.bob
            val (contactB, contactA) = establishBothWays(world)

            // A's **own** certificate, sent by B: it verifies under A's key, not under B's pinned
            // one, so it must not revoke B (GHOST never links two Ed25519 identities, §8.3).
            val foreign = requireNotNull(alice.engine.issueRevocation(RevocationReason.KEY_ROTATION))
            assertEquals(0, bob.engine.notifyContactsOfRevocation(foreign))
            assertEquals("nothing is scheduled for a certificate of another identity", 0, scheduledCount(bob))

            // And if one arrives anyway, RECV refuses it. The send carries it as a TLV of a normal
            // message, which is what `applyRevocation` sees.
            assertEquals(SendResult.QUEUED, bob.engine.send(contactA, "hello", null))
            world.deliverBetween(bob, alice)
            alice.hintPass()
            assertNotEquals(TrustState.REVOKED, alice.engine.contacts().single().trust)
            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "fine", null))
        }
    }

    /**
     * §8.6: a restored device re-adds the card, asks for a reconnect, and the contact builds a new
     * session under the **same** Olm identity — a renewal, with no key-change warning.
     */
    @Test
    @Suppress("LongMethod")
    fun aRestoredDeviceReconnectsWithoutAKeyChange() {
        requireNative()
        DmWorld().use { world ->
            val bob = world.bob
            establishBothWays(world)

            // The restore: the same seed, a fresh database. Every derivation survives and nothing
            // else does (§8.6's table).
            val restored = world.restored(world.alice)
            restored.engine.onRestored()
            assertTrue("the card is a pure function of the seed", restored.card().contentEquals(world.alice.card()))
            assertTrue("and nothing else survived", restored.engine.contacts().isEmpty())

            assertEquals(
                AddContactResult.ADDED,
                restored.engine.addContact(bob.card(), CardSource.QR_IN_PERSON),
            )
            val contactB = restored.engine.contacts().single().id
            val storesBefore = storeCount(restored)
            assertEquals(1, restored.engine.reconnect(listOf(contactB)))
            assertEquals("scheduling sends nothing", storesBefore, storeCount(restored))
            assertEquals(1, scheduledCount(restored))

            // The notice is due within 48 hours, and the control then waits for B's bundle.
            world.advanceTo(restored.clock.now + 49 * DmWorld.HOUR)
            restored.timeTriggeredPass()
            assertEquals(0, scheduledCount(restored))
            deliverBundle(world, from = bob, to = restored)
            assertTrue("the reconnect notice is enqueued", storeCount(restored) > storesBefore)

            world.deliverBetween(restored, bob)
            bob.hintPass()
            assertEquals(
                "the same Olm identity is a renewal, not a key change (§8.3)",
                TrustState.UNVERIFIED,
                bob.engine.contacts().single().trust,
            )
            assertEquals(
                "and the notice itself is a contact event, with no message row",
                1,
                bob.engine.status().drops["session_renewed"],
            )
            assertEquals(0, heldCount(bob))

            // Pair mode is rebuilt in both directions from the new sessions.
            val contactAOnBob = bob.engine.contacts().single().id
            assertEquals(SendResult.QUEUED, bob.engine.send(contactAOnBob, "welcome back", null))
            world.deliverBetween(bob, restored)
            restored.hintPass()
            assertEquals(
                listOf("welcome back"),
                restored.engine.conversation(contactB, 10, null).mapNotNull { it.text },
            )
        }
    }

    /**
     * §8.7 `resetSession`: both rows go, the next message goes through the one-shot bundle fetch,
     * and the contact sees an ordinary renewal.
     */
    @Test
    fun resettingASessionRebuildsItThroughTheBundleFetch() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            val bob = world.bob
            val (contactB, contactA) = establishBothWays(world)
            val before = sessionIds(alice)
            assertEquals(1, before.size)

            assertEquals(SendResult.QUEUED, alice.engine.resetSession(contactB))
            assertEquals("the old session is gone (R-SS0)", 0, sessionCount(alice))
            // §21.7 point 2: `EST-START` forgot `P_B`'s tombstones, so the relay's copy of B's
            // bundle is fetchable again — which is the whole reason that rule exists.
            deliverBundle(world, from = bob, to = alice, again = true)
            assertEquals(1, sessionCount(alice))
            assertTrue(
                "and the new one is not the old one",
                sessionIds(alice).intersect(before).isEmpty(),
            )

            // The reset control reaches B as an intro envelope of the new session: a renewal.
            world.deliverBetween(alice, bob)
            bob.hintPass()
            assertNotEquals(TrustState.CHANGED, bob.engine.contacts().single().trust)
            assertEquals(0, heldCount(bob))

            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "again", null))
            world.deliverBetween(alice, bob)
            bob.hintPass()
            assertEquals(
                listOf("again"),
                bob.engine.conversation(contactA, 10, null).mapNotNull { it.text }.take(1),
            )
        }
    }

    // ---------------------------------------------------------------- helpers

    private fun deliverBundle(
        world: DmWorld,
        from: DmDevice,
        to: DmDevice,
        again: Boolean = false,
    ) {
        world.deliverBetween(from, to, again)
        to.timeTriggeredPass()
        world.advanceTo(to.clock.now + 3 * DmWorld.MINUTE)
        to.timeTriggeredPass()
    }

    private fun establishBothWays(world: DmWorld): Pair<ContactId, ContactId> {
        world.alice.engine.onActivated()
        world.bob.engine.onActivated()
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

    private fun storeCount(device: DmDevice): Int {
        var count = 0
        device.sql.query("SELECT count(*) FROM outbox_op") { count = it.long(0).toInt() }
        return count
    }

    private fun scheduledCount(device: DmDevice): Int {
        var count = 0
        device.sql.query("SELECT count(*) FROM dm_scheduled") { count = it.long(0).toInt() }
        return count
    }

    private fun heldCount(device: DmDevice): Int {
        var count = 0
        device.sql.query("SELECT count(*) FROM dm_held") { count = it.long(0).toInt() }
        return count
    }

    private fun sessionCount(device: DmDevice): Int {
        var count = 0
        device.sql.query("SELECT count(*) FROM olm_session") { count = it.long(0).toInt() }
        return count
    }

    private fun sessionIds(device: DmDevice): Set<List<Byte>> {
        val out = HashSet<List<Byte>>()
        device.sql.query("SELECT session_id FROM olm_session") { out += it.blob(0).toList() }
        return out
    }
}
