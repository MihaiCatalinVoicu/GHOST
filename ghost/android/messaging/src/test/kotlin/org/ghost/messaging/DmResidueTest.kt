package org.ghost.messaging

import org.ghost.crypto.bridge.DmContent
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
 * establishment of a conversation cannot tell a usable session from a row. So is the **attempt
 * budget** of §21.7 points 2 and 5 (slice S10c and its review): three empty windows, `unreachable`,
 * a later send whose own `EST-START` a process death lost, sends to a contact that is still
 * fetching, and each action that reopens an unreachable one.
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

    // ------------------------------------------------------- the spent budget

    /**
     * §21.7 point 5 and §13.5: three empty windows make the contact `unreachable` and fail the
     * waiting message — and a send made **after** that, whose own `EST-START` a process death
     * lost, is resumed by the next time-triggered pass as the user's retry it was (slice S10c).
     *
     * The second half is what SCN-C's crash enumeration found (§22.23). A send and its `EST-START`
     * are two transactions (§7.3), and `DmActor.flushStranded` is the recovery for a death between
     * them — but it asked for the establishment without `userRetry`, which `EST-START` refuses
     * against a spent budget: the contact stayed `unreachable` and the message waited up to seven
     * days for R-T5 to fail it, unless the user wrote again. The test leaves the message exactly
     * where that death leaves it, by running `SendStep.send` without the facade's `EST-START`.
     *
     * The first half also checks that the message stays **queued** through the first two windows
     * ([spendTheBudget]): it fails with the third empty window, not with the first.
     */
    @Test
    fun aSendToAnUnreachableContactIsResumedWhenItsEstablishmentWasLost() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            val contactB = addWithoutABundle(world)
            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "into the void", null))
            spendTheBudget(world)
            assertEquals(
                "and fails the message that waited for it",
                MessageState.FAILED,
                alice.engine.conversation(contactB, 10, null).single().state,
            )
            world.advanceTo(alice.clock.now + 7 * DmWorld.HOUR)
            alice.timeTriggeredPass()
            assertEquals("no fourth window without a user action", 0, listeningNamespaces(alice))

            // B comes online and publishes. A writes again, and the process dies between the
            // send's commit and its `EST-START`: a pending message on an unreachable contact.
            world.bob.engine.onActivated()
            val sent = alice.sendStep.send(
                contactB.toByteArray(), DmContent.Kind.TEXT, "again".toByteArray(), null, null,
            )
            assertTrue("the send owes an establishment", sent.establish)
            assertEquals(Establishment.UNREACHABLE, alice.engine.contacts().single().establishment)

            // The next time-triggered pass resumes it as the user's retry, with a fresh budget.
            alice.timeTriggeredPass()
            assertEquals(
                "the stranded send's establishment is resumed",
                Establishment.FETCHING,
                alice.engine.contacts().single().establishment,
            )
            assertEquals(1, attempts(alice))

            // And it finishes: B's bundle, `EST-READY` two minutes on, the message out.
            world.deliver()
            alice.timeTriggeredPass()
            world.advanceTo(alice.clock.now + 3 * DmWorld.MINUTE)
            alice.timeTriggeredPass()
            assertEquals(Establishment.READY, alice.engine.contacts().single().establishment)
            assertEquals("the resumed message went out", 0, alice.engine.status().pendingSends)
        }
    }

    /**
     * §21.7 point 2: `EST-START` "sets `fetch_attempts = 1`", so a send to a contact that is still
     * fetching starts the count again and does not spend it (slice S10c's review).
     *
     * Before the review a send to a `fetching` contact wrote the stored count **plus one**, so
     * three messages written a minute apart to a contact with no bundle yet were attempts one, two
     * and three of the same open window, and `EST-END` gave up when that one window closed: all
     * three FAILED a quarter of an hour after they were written, where §21.7 point 5 gives them
     * three windows six hours apart. Nothing else in the tree sends twice to a contact that is
     * still fetching — SCN-C writes its second message only once the first went out — so this is
     * the test of it.
     */
    @Test
    fun sendsToAContactThatIsStillFetchingDoNotSpendItsBudget() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            val contactB = addWithoutABundle(world)
            for (text in listOf("one", "two", "three")) {
                assertEquals(SendResult.QUEUED, alice.engine.send(contactB, text, null))
                assertEquals("the send of $text starts the count again", 1, attempts(alice))
                assertEquals(Establishment.FETCHING, alice.engine.contacts().single().establishment)
                world.advanceTo(alice.clock.now + DmWorld.MINUTE)
            }
            assertEquals(3, alice.engine.status().pendingSends)
            spendTheBudget(world)
            assertEquals(
                "the three messages fail with the third window, not the first",
                listOf(MessageState.FAILED, MessageState.FAILED, MessageState.FAILED),
                alice.engine.conversation(contactB, 10, null).map { it.state },
            )
        }
    }

    /**
     * Each of the four actions that queue an item reopens a contact the three windows gave up on
     * **at once**, with a fresh count: the user's retry of a FAILED message, a new send, a session
     * reset, and a due scheduled control (§13.5's `unreachable → fetching`, §21.7 point 5's "the
     * user may retry").
     *
     * Each is checked right after the call that queued the item, before any time-triggered pass:
     * since slice S10c `DmActor.flushStranded` restarts a stranded item's establishment on the
     * next pass anyway, so a later check could not tell a caller that passes `userRetry` from one
     * that leaves the reopening to the recovery. The scheduled control is checked after the pass
     * that sends it, which is enough for the same reason: that pass runs the recovery **before**
     * the scheduled step (`DmActor.pass`), so the recovery cannot be what reopened it.
     */
    @Test
    fun everyActionThatQueuesAnItemReopensAnUnreachableContactAtOnce() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            val contactB = addWithoutABundle(world)
            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "into the void", null))
            spendTheBudget(world)

            val failed = alice.engine.conversation(contactB, 10, null).single()
            assertEquals(MessageState.FAILED, failed.state)
            assertEquals(SendResult.QUEUED, alice.engine.retry(failed.id))
            assertReopened(alice, "the retry of a FAILED message")
            spendTheBudget(world)

            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "again", null))
            assertReopened(alice, "a send")
            spendTheBudget(world)

            assertEquals(SendResult.QUEUED, alice.engine.resetSession(contactB))
            assertReopened(alice, "a session reset")
            spendTheBudget(world)

            assertEquals(1, alice.engine.reconnect(listOf(contactB)))
            // Past the whole §8.6 spread, so the notice is due at the next pass.
            world.advanceTo(alice.clock.now + 48 * DmWorld.HOUR + DmWorld.MINUTE)
            alice.timeTriggeredPass()
            assertReopened(alice, "a due reconnect notice")
        }
    }

    // ---------------------------------------------------------------- helpers

    /** A adds B's card; B has not activated, so it published no bundle and every window is empty. */
    private fun addWithoutABundle(world: DmWorld): ContactId {
        world.alice.engine.onActivated()
        assertEquals(
            AddContactResult.ADDED,
            world.alice.engine.addContact(world.bob.card(), CardSource.QR_IN_PERSON),
        )
        return world.alice.engine.contacts().single().id
    }

    /**
     * Three empty windows from an open first one (§21.7 point 5): each closes empty, the next opens
     * six hours on, the count rises by one per window, and the items that wait for them stay
     * queued until the **third** closes — then the contact is `unreachable` and every one fails.
     */
    private fun spendTheBudget(world: DmWorld) {
        val alice = world.alice
        val pending = alice.engine.status().pendingSends
        assertTrue("an establishment that waits for nothing", pending > 0)
        for (window in 1..3) {
            assertEquals(
                "window $window is open",
                Establishment.FETCHING,
                alice.engine.contacts().single().establishment,
            )
            assertEquals(1, listeningNamespaces(alice))
            assertEquals("window $window is attempt $window", window, attempts(alice))
            world.deliver()
            // Past the window's fifteen minutes: `EST-END`.
            world.advanceTo(alice.clock.now + 16 * DmWorld.MINUTE)
            alice.timeTriggeredPass()
            assertEquals("window $window is closed", 0, listeningNamespaces(alice))
            if (window < 3) {
                assertEquals(
                    "the items still wait after window $window closed empty",
                    pending,
                    alice.engine.status().pendingSends,
                )
                // Six hours on, the next window (§21.7 point 5); R-T5 runs in the same pass.
                world.advanceTo(alice.clock.now + 6 * DmWorld.HOUR + DmWorld.MINUTE)
                alice.timeTriggeredPass()
                assertEquals(
                    "the items still wait when window ${window + 1} opens",
                    pending,
                    alice.engine.status().pendingSends,
                )
            }
        }
        assertEquals(
            "the third empty window gives up (§21.7 point 5)",
            Establishment.UNREACHABLE,
            alice.engine.contacts().single().establishment,
        )
        assertEquals(3, attempts(alice))
        assertEquals("and fails what waited for it", 0, alice.engine.status().pendingSends)
    }

    /** [what] reopened the unreachable contact: `fetching`, a fresh count, `P_B` listened. */
    private fun assertReopened(alice: DmDevice, what: String) {
        assertEquals(
            "$what reopens the contact",
            Establishment.FETCHING,
            alice.engine.contacts().single().establishment,
        )
        assertEquals("$what starts a fresh count", 1, attempts(alice))
        assertEquals("$what opens a window", 1, listeningNamespaces(alice))
    }

    private fun attempts(device: DmDevice): Int = countWhere(device, "SELECT fetch_attempts FROM dm_contact")


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
