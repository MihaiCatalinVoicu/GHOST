package org.ghost.messaging

import org.ghost.messaging.api.AddContactResult
import org.ghost.messaging.api.CardSource
import org.ghost.messaging.api.ContactId
import org.ghost.messaging.api.Establishment
import org.ghost.messaging.api.MessageState
import org.ghost.messaging.api.SendResult
import org.ghost.messaging.api.TrustState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * What **block** and **delete** leave behind, and what a **stale session** does to the
 * establishment (Phase 9 design §12.4, §21.12 point 3, §21.7 point 4, §8.2 R-SS0, §13.5).
 *
 * `DmForensicResidueTest` in `:storage` proves the schema's half of R-M1 — which rows a message
 * takes with it — on SQL fixtures, and it has no blocked and no deleted contact in its world
 * because the step that blocks and deletes is this module's. §21.12 point 3 asks for the other
 * half: "R-M1 and a T25 assertion cover the `:sync` tables after block and delete plus that
 * bound", the bound being the ≤ 7 days of L7-D7, which only exists because `dm_orphan_namespace`
 * records the two namespaces for SWEEP. Before this file, `recordOrphans` — the sole mechanism
 * that bounds the residue — had no test at all.
 *
 * The session half is here for the same reason: §21.7 point 4 says `EST-READY` builds a session
 * "unless a **usable** session already exists", and a test that only ever runs the first
 * establishment of a conversation cannot tell a usable session from a row.
 */
class DmResidueTest {

    private fun requireNative() {
        assumeTrue(
            "set -Dghost.dm.native to the ghost-dm-host library",
            DmWorld.nativeAvailable(),
        )
    }

    // ------------------------------------------------------------ block, delete

    /**
     * §12.4 and L7-D6: a block in the middle of an establishment closes the bundle window.
     *
     * The failure this pins is silent and unbounded. `block` sets `establishment = 'card_only'`,
     * and the actor only ever visits contacts whose establishment is `fetching` — so neither
     * `dueStep` nor `EST-END` can run for the contact again and nothing closes `P_c`. The device
     * keeps listening on the blocked contact's bundle namespace, with its READ credentials
     * installed, for as long as the install lasts.
     */
    @Test
    fun aBlockDuringTheFetchStopsListeningOnTheBundleNamespace() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            val contactB = startFetching(world)
            assertEquals(Establishment.FETCHING, alice.engine.contacts().single().establishment)
            assertEquals(
                "the fetch window is open on P_B",
                1,
                listeningNamespaces(alice),
            )

            assertTrue(alice.engine.block(contactB))
            assertEquals(TrustState.BLOCKED, alice.engine.contacts().single().trust)
            assertEquals(
                "a blocked contact's bundle namespace is not listened to any more",
                0,
                listeningNamespaces(alice),
            )
        }
    }

    /**
     * §12.4 and §21.8 point 7: a message queued before the establishment finished is **failed** by
     * the block, not orphaned.
     *
     * `dm_pending_send` is the only row that could ever have resolved the item, so deleting it
     * alone left a `dm_outbound_item` `pending` — with its sealed L0 — and a `dm_message` `queued`,
     * shown by the UI as still on its way with nothing left that could finish it.
     */
    @Test
    fun aBlockFailsTheMessagesThatWereWaitingForTheEstablishment() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            val contactB = startFetching(world)
            assertEquals(1, alice.engine.status().pendingSends)

            assertTrue(alice.engine.block(contactB))
            assertEquals(0, alice.engine.status().pendingSends)
            assertEquals(
                "the item is decided, not left pending",
                0,
                countWhere(alice, "SELECT count(*) FROM dm_outbound_item WHERE state = 'pending'"),
            )
            assertEquals(
                "and so is the message the user wrote",
                0,
                countWhere(alice, "SELECT count(*) FROM dm_message WHERE state = 'queued'"),
            )
            assertEquals(
                listOf(MessageState.FAILED),
                alice.engine.conversation(contactB, 10, null).map { it.state },
            )
        }
    }

    /**
     * §21.12 point 3: block and delete record `X_c` and `P_c` in `dm_orphan_namespace`, which is
     * what carries them to SWEEP and what makes the residue's ≤ 7-day bound (L7-D7) true.
     */
    @Test
    fun blockAndDeleteRecordBothNamespacesAsOrphans() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            val contactB = startFetching(world)
            assertEquals(0, orphans(alice).size)

            assertTrue(alice.engine.block(contactB))
            val afterBlock = orphans(alice)
            assertEquals("X_B and P_B, and those two only", 2, afterBlock.size)
            assertTrue(
                "the bundle namespace this device was fetching from is one of them",
                afterBlock.contains(bundleNamespaceOf(alice)),
            )

            // Unblocking deletes the row. The card is already gone, so nothing can be derived a
            // second time — and nothing has to be, because block recorded it.
            assertTrue(alice.engine.unblock(contactB))
            assertTrue(alice.engine.contacts().isEmpty())
            assertEquals("the orphan rows outlive the contact", 2, orphans(alice).size)
        }
    }

    /**
     * The same for `deleteContact`, on a contact with a live conversation: every row of the contact
     * goes and the two namespaces stay behind as orphans (§12.4, §21.12 point 3).
     */
    @Test
    fun deletingAContactLeavesItsNamespacesRecordedAndNothingElse() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            val (contactB, _) = establishBothWays(world)
            assertTrue(sessionCount(alice) > 0)

            assertTrue(alice.engine.deleteContact(contactB))
            assertTrue(alice.engine.contacts().isEmpty())
            assertEquals("the cascade took the sessions", 0, sessionCount(alice))
            assertEquals(
                "and the pair keys",
                0,
                countWhere(alice, "SELECT count(*) FROM dm_pair_key"),
            )
            assertEquals(
                "and the conversation with its messages",
                0,
                countWhere(alice, "SELECT count(*) FROM dm_message"),
            )
            assertEquals("X_B and P_B are recorded for SWEEP", 2, orphans(alice).size)
        }
    }

    /**
     * §21.12 point 3 and L7-D7, from the other side: a delete that **cannot** record the orphans
     * does not happen at all.
     *
     * With the DM context unavailable the two namespaces cannot be derived, and the card the
     * delete is about to erase is the only thing they could ever be derived from. A delete that
     * committed anyway would leave the `:sync` rows, relay sets and credentials of `X_c` and `P_c`
     * behind for good, with nothing on the device able to name them and no bound able to cover
     * them. Refusing leaves a state the same action succeeds from later.
     */
    @Test
    fun aDeleteThatCannotRecordTheOrphansIsRefused() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            val contactB = startFetching(world)

            // `SelfContexts.get()` answers null without a `dm_self` row: the identity is not
            // available, which is what a locked or wiped device looks like to these steps.
            alice.sql.exec("DELETE FROM dm_self", emptyList())
            alice.contexts.invalidate()

            assertFalse("the delete refuses", alice.engine.deleteContact(contactB))
            assertEquals("and changes nothing", 0, orphans(alice).size)
            assertEquals(
                "the contact is still there, card and all",
                1,
                countWhere(alice, "SELECT count(*) FROM dm_contact WHERE card_env IS NOT NULL"),
            )
        }
    }

    // ------------------------------------------------------- the stale session

    /**
     * §8.7, §21.7 point 4 and §8.2 R-SS0: a send on a session the contact never answered for
     * `UNACK_MAX` days re-establishes, and the establishment **replaces** the session.
     *
     * The bug this pins made the conversation unrecoverable. `EST-READY` treated "a session row
     * exists" as "a usable session exists", so it skipped the whole build block, threw the freshly
     * fetched candidate away, reset `fetch_attempts` and reported the contact `ready` — with the
     * same dead session still in `current`. The pending message was then sealed onto it as an
     * intro envelope addressed to a generation the contact may already have erased, `isStale` was
     * still true at the next send, and the cycle repeated for every user message: L7-D6's "at most
     * three session starts per establishment" became three per send, for ever, which is mutant
     * PM-31 in production code.
     *
     * The clock really moves: `unack_since_day` is immutable by the `olm_session_identity` trigger
     * (§13.6 step 6), so the twenty-nine days are twenty-nine days. B publishes the week's bundle
     * on its own time-triggered pass, exactly as it would have.
     */
    @Test
    fun aStaleSessionIsReplacedRatherThanKept() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            val contactB = introduce(world)
            assertEquals(Establishment.READY, alice.engine.contacts().single().establishment)
            val first = currentSessionId(alice)
            assertNotEquals(null, first)

            // B never answers. Twenty-nine days later A's initiator session is past `UNACK_MAX`
            // (§8.7), and B has published the bundles of the weeks in between.
            world.advanceTo(alice.clock.now + 29 * DAY)
            world.bob.timeTriggeredPass()

            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "still there?", null))
            assertEquals(
                "the send asks for a re-establishment",
                Establishment.FETCHING,
                alice.engine.contacts().single().establishment,
            )
            assertEquals(
                "R-SS0: the stale session is demoted, not deleted — the peer may still answer it",
                first,
                previousSessionId(alice),
            )

            // B's fresh bundle, then the two passes `EST-READY` needs (§21.7 point 4).
            world.deliver()
            alice.timeTriggeredPass()
            world.advanceTo(alice.clock.now + 3 * DmWorld.MINUTE)
            alice.timeTriggeredPass()

            assertEquals(Establishment.READY, alice.engine.contacts().single().establishment)
            assertNotEquals(
                "`EST-READY` built a new session rather than keeping the stale one",
                first,
                currentSessionId(alice),
            )
            assertEquals("and the waiting message went out", 0, alice.engine.status().pendingSends)
        }
    }

    /**
     * The **other** half of §21.7 point 4: `EST-READY` at the window's end **with** a usable
     * session and no candidate.
     *
     * A is fetching B's bundle and never gets it; B, who already has A's card, reaches A first, so
     * an inbound PreKey builds A's session under R-SS1. At the window's end the contact becomes
     * `ready` on that session, `P_c` stops listening and the waiting message goes out — no bundle
     * was ever needed. The case is easy to lose while tightening the "unless a **usable** session
     * already exists" guard the other test is about, because both are read off the same two values.
     */
    @Test
    fun aSessionAnInboundPreKeyBuiltEndsTheWindowWithoutABundle() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            val bob = world.bob
            alice.engine.onActivated()
            bob.engine.onActivated()

            // B establishes towards A first, from A's card, and enqueues its intro envelope.
            assertEquals(
                AddContactResult.ADDED,
                bob.engine.addContact(alice.card(), CardSource.QR_IN_PERSON),
            )
            val contactA = bob.engine.contacts().single().id
            assertEquals(SendResult.QUEUED, bob.engine.send(contactA, "first", null))
            world.deliverTo(bob)
            bob.timeTriggeredPass()
            world.advanceTo(bob.clock.now + 3 * DmWorld.MINUTE)
            bob.timeTriggeredPass()

            // A starts her own fetch of `P_B` and is given **nothing** from the relays but B's
            // intro envelope: no bundle, so no candidate can ever exist.
            val contactB = startFetching(world)
            assertEquals(Establishment.FETCHING, alice.engine.contacts().single().establishment)
            val intro = lastStore(bob)
            world.redeliver(bob, alice, intro.first, intro.second)
            alice.hintPass()
            assertTrue("the inbound PreKey built a session", sessionCount(alice) > 0)
            assertEquals(
                "still fetching, and with no candidate",
                0,
                countWhere(alice, "SELECT count(*) FROM dm_bundle_candidate"),
            )

            // The window ends: `EST-READY`, not `EST-END`, because a usable session exists.
            world.advanceTo(alice.clock.now + 16 * DmWorld.MINUTE)
            alice.timeTriggeredPass()
            assertEquals(Establishment.READY, alice.engine.contacts().single().establishment)
            assertEquals("the window is closed", 0, listeningNamespaces(alice))
            assertEquals("and the waiting message went out", 0, alice.engine.status().pendingSends)
            assertTrue(
                "the conversation shows both messages",
                alice.engine.conversation(contactB, 10, null).size >= 2,
            )
        }
    }

    // ---------------------------------------------------------------- helpers

    private companion object {
        const val DAY: Long = 24 * 60 * 60
    }

    /** The last blob a device enqueued: `(namespace, ciphertext)`. */
    private fun lastStore(device: DmDevice): Pair<ByteArray, ByteArray> {
        var out: Pair<ByteArray, ByteArray>? = null
        device.sql.query(
            "SELECT namespace_id, ciphertext FROM outbox_op ORDER BY rowid DESC LIMIT 1",
        ) { out = it.blob(0) to it.blob(1) }
        return requireNotNull(out) { "nothing was enqueued" }
    }

    /** A adds B's card and sends once: the contact is `fetching` with one pending item. */
    private fun startFetching(world: DmWorld): ContactId {
        world.alice.engine.onActivated()
        world.bob.engine.onActivated()
        assertEquals(
            AddContactResult.ADDED,
            world.alice.engine.addContact(world.bob.card(), CardSource.QR_IN_PERSON),
        )
        val contactB = world.alice.engine.contacts().single().id
        assertEquals(SendResult.QUEUED, world.alice.engine.send(contactB, "hello", null))
        return contactB
    }

    /** [startFetching], plus the bundle and the two passes that finish the establishment. */
    private fun introduce(world: DmWorld): ContactId {
        val contactB = startFetching(world)
        world.deliver()
        world.alice.timeTriggeredPass()
        world.advanceTo(world.alice.clock.now + 3 * DmWorld.MINUTE)
        world.alice.timeTriggeredPass()
        return contactB
    }

    /** The flow to the point where both sides have a live conversation. */
    private fun establishBothWays(world: DmWorld): Pair<ContactId, ContactId> {
        val contactB = introduce(world)
        world.deliver()
        world.bob.hintPass()
        val contactA = world.bob.engine.contacts().single().id
        assertTrue(world.bob.engine.acceptRequest(contactA))
        assertEquals(SendResult.QUEUED, world.bob.engine.send(contactA, "hi back", null))
        world.deliver()
        world.alice.hintPass()
        return contactB to contactA
    }

    private fun countWhere(device: DmDevice, sql: String): Int {
        var count = 0
        device.sql.query(sql) { count = it.long(0).toInt() }
        return count
    }

    private fun sessionCount(device: DmDevice): Int =
        countWhere(device, "SELECT count(*) FROM olm_session")

    private fun listeningNamespaces(device: DmDevice): Int =
        countWhere(device, "SELECT count(*) FROM sync_namespace WHERE consumer = 'prekeys' AND listening = 1")

    private fun orphans(device: DmDevice): List<String> {
        val out = ArrayList<String>()
        device.sql.query("SELECT hex(namespace_id) FROM dm_orphan_namespace ORDER BY namespace_id") {
            out += it.string(0)
        }
        return out
    }

    /** The one `prekeys` namespace this device registered: B's `P_B`. */
    private fun bundleNamespaceOf(device: DmDevice): String {
        var out: String? = null
        device.sql.query(
            "SELECT hex(namespace_id) FROM sync_namespace WHERE consumer = 'prekeys' " +
                "AND capability_source = 'local'",
        ) { out = it.string(0) }
        return requireNotNull(out) { "no contact bundle namespace was registered" }
    }

    private fun currentSessionId(device: DmDevice): String? = sessionId(device, "current")

    private fun previousSessionId(device: DmDevice): String? = sessionId(device, "previous")

    private fun sessionId(device: DmDevice, slot: String): String? {
        var out: String? = null
        device.sql.query(
            "SELECT hex(session_id) FROM olm_session WHERE slot = ?",
            listOf(slot),
        ) { out = it.string(0) }
        return out
    }
}
