package org.ghost.messaging

import org.ghost.messaging.api.CardSource
import org.ghost.messaging.api.TrustState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * **T28, the behavioural half** (Phase 9 design §16.1's `NoReflexTest`, deferred to S7 by §22.11
 * item 8; P-3, D10, §12.3's "no reflex").
 *
 * > Processing any inbound blob (valid, malformed, duplicate, replayed, reordered, undecryptable,
 * > forged, key-changed, request, probe, poison) enqueues nothing, redeems nothing, registers
 * > nothing, changes no read schedule …
 *
 * `dm-enqueue-callers.sh` (gate G-DM2) is the static half: no branch of `RECV`, `BUNDLE` or the
 * peek order may *name* `Outbox.enqueue`, `Registrations.*`, `Namespaces.*` or `Capabilities.put`,
 * and no inbound path may reach `runOwnerMaintenance`. That is a statement about call sites; this
 * is the statement about behaviour, and the two fail on different mutants. A reflex reached
 * through an alias the script does not track, or through a step the actor runs *because*
 * something arrived, passes the script and fails here.
 *
 * **How the two worlds are made to differ only in what arrived.** B's device is deterministic —
 * the same MESSAGING branch, the same identity seed, the same sequential randomness — so two
 * `DmWorld`s give B the same card, the same namespaces and the same bundle. Both worlds then run
 * the **same** script on the **same** clock, including all of A's actions and passes: A's
 * establishment needs B's bundle, so delivery is split by recipient ([DmWorld.deliverTo]) and B's
 * direction is the single switch. Producing the envelope in a third world would not do: B's
 * X-Wing generation secrets come from the native RNG, so an envelope sealed to one world's bundle
 * does not decapsulate in another.
 *
 * **What "relay-visible" means here** is [DmDevice.relayVisible]: every outbox op with its
 * namespace, TTL, deadline and size, every namespace registration with its listening flag and
 * capability source, every installed capability with its state and generation, and every relay key
 * registration. It is deliberately **wider than the wire** — a capability row is local until it is
 * presented — because T28 forbids the local decision too ("registers nothing, changes no read
 * schedule"), and because a row that exists is a row some later pass will act on.
 */
class NoReflexTest {

    private fun requireNative() {
        assumeTrue(
            "set -Dghost.dm.native to the ghost-dm-host library",
            DmWorld.nativeAvailable(),
        )
    }

    @Test
    fun aGenuineRequestLeavesNoRelayVisibleTrace() {
        var sawRequest = false
        val quiet = bobsRelayView(deliverToBob = false) { _, _ -> }
        val noisy = bobsRelayView(deliverToBob = true) { _, bob ->
            sawRequest = bob.engine.contacts().singleOrNull()?.trust == TrustState.REQUEST
        }
        assertTrue("the world under test really received the request", sawRequest)
        assertEquals(quiet, noisy)
    }

    @Test
    fun aReplayedAndAForgedBlobLeaveNoRelayVisibleTrace() {
        var drops = 0
        val quiet = bobsRelayView(deliverToBob = false) { world, bob ->
            // The quiet world runs the same calls; with nothing delivered there is nothing to
            // re-serve, so only the forgery has a twin here — which is the point: the noisy world
            // must not differ **because** of what it received.
            world.advanceTo(bob.clock.now + 13 * DmWorld.MINUTE)
            bob.hintPass()
        }
        val noisy = bobsRelayView(deliverToBob = true) { world, bob ->
            // The same bytes again (D1/D2b), then 4 KiB of noise in the same namespace: a relay
            // that re-serves, and a relay that invents.
            val (namespace, ciphertext) = lastStore(world.alice)
            world.redeliver(world.alice, bob, namespace, ciphertext)
            world.redeliver(world.alice, bob, namespace, ByteArray(4096) { (it * 31).toByte() })
            world.advanceTo(bob.clock.now + 13 * DmWorld.MINUTE)
            bob.hintPass()
            drops = bob.engine.status().drops.values.sum()
        }
        assertTrue("the world under test really dropped something", drops > 0)
        assertEquals(quiet, noisy)
    }

    @Test
    fun rejectingARequestLeavesNoRelayVisibleTrace() {
        var rejected = false
        val quiet = bobsRelayView(deliverToBob = false) { _, _ -> }
        val noisy = bobsRelayView(deliverToBob = true) { _, bob ->
            rejected = bob.engine.rejectRequest(bob.engine.contacts().single().id)
        }
        assertTrue("the world under test really rejected a request", rejected)
        assertEquals(quiet, noisy)
    }

    @Test
    fun blockingARequesterLeavesNoRelayVisibleTrace() {
        var blocked = false
        val quiet = bobsRelayView(deliverToBob = false) { _, _ -> }
        val noisy = bobsRelayView(deliverToBob = true) { _, bob ->
            blocked = bob.engine.blockRequest(bob.engine.contacts().single().id)
        }
        assertTrue("the world under test really blocked a requester", blocked)
        assertEquals(quiet, noisy)
    }

    /**
     * Accepting is the one request decision that is **not** invisible locally, and §12.3 is exact
     * about what it promises: "Neither arrival, nor accept, nor reject, nor expiry **sends**
     * anything".
     *
     * An accepted contact is sendable, so the next KEEPER pass installs its deposit credential and
     * registers `X_c` write-only (§7.2's KEEPER row, §4.8) — rows that exist so the first send does
     * not have to mint one on its critical path. Nothing of that reaches a relay: a deposit
     * credential is static per (card, relay slot) and is registered by its **owner**, not by the
     * depositor, so no `relay_key_registration` row is made and nothing is stored. This test pins
     * both halves — the stores are equal, the local rows are not — so that the day an accept starts
     * enqueueing, the first assertion fails instead of the difference being explained away.
     */
    @Test
    fun acceptingARequestSendsNothing() {
        var accepted = false
        val quiet = bobsRelayView(deliverToBob = false) { _, _ -> }
        val noisy = bobsRelayView(deliverToBob = true) { _, bob ->
            accepted = bob.engine.acceptRequest(bob.engine.contacts().single().id)
        }
        assertTrue("the world under test really accepted a request", accepted)
        assertEquals(stores(quiet), stores(noisy))
        assertNotEquals("an accepted contact does get its deposit credential", quiet, noisy)
    }

    // ---------------------------------------------------------------- helpers

    /** The `store` lines of a relay-visible view: what actually reaches a relay. */
    private fun stores(view: List<String>): List<String> = view.filter { it.startsWith("store ") }

    /**
     * B's relay-visible view after one fixed script, with [deliverToBob] the only difference and
     * [decision] the user action a test wants B to take once the blob is in.
     *
     * The tail is four time-triggered passes twenty minutes apart: enough for the gap hold to
     * expire (12 min) and for KEEPER, REGROWS and the establishment steps to run repeatedly, and
     * short enough that no week boundary is crossed — a week change would publish a bundle and is
     * a difference of the clock, not of the inbox.
     */
    private fun bobsRelayView(
        deliverToBob: Boolean,
        decision: (DmWorld, DmDevice) -> Unit,
    ): List<String> {
        requireNative()
        return DmWorld().use { world ->
            val alice = world.alice
            val bob = world.bob
            alice.engine.onActivated()
            bob.engine.onActivated()
            bob.timeTriggeredPass()

            // A's half of the script is identical in both worlds, including its two passes and the
            // three minutes `EST-READY` waits for a better candidate (§21.7 point 4).
            alice.engine.addContact(bob.card(), CardSource.QR_IN_PERSON)
            val contactB = alice.engine.contacts().single().id
            alice.engine.send(contactB, "hello", null)
            world.deliverTo(alice)
            alice.timeTriggeredPass()
            world.advanceTo(alice.clock.now + 3 * DmWorld.MINUTE)
            alice.timeTriggeredPass()

            if (deliverToBob) world.deliverTo(bob)
            bob.hintPass()
            decision(world, bob)

            repeat(4) {
                world.advanceTo(bob.clock.now + 20 * DmWorld.MINUTE)
                bob.timeTriggeredPass()
            }
            bob.relayVisible().also { view ->
                // The vacuity floor of this half. Four of the five tests assert only
                // `quiet == noisy`, which two empty lists satisfy — a renamed column, or a closed
                // context making `runPass` return at its first line, would turn every one of them
                // green while proving nothing. B activated and ran five passes, so its own
                // namespaces, capabilities and registrations are there whatever arrived.
                assertTrue("the relay-visible view is empty: it proves nothing", view.isNotEmpty())
            }
        }
    }

    /** The last op A enqueued: `(namespace, ciphertext)`. */
    private fun lastStore(device: DmDevice): Pair<ByteArray, ByteArray> {
        var found: Pair<ByteArray, ByteArray>? = null
        device.sql.query(
            "SELECT namespace_id, ciphertext FROM outbox_op ORDER BY rowid DESC LIMIT 1",
        ) { found = it.blob(0) to it.blob(1) }
        return requireNotNull(found) { "A enqueued no op" }
    }
}
