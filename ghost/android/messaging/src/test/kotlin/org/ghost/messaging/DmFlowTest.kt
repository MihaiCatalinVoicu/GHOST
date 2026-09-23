package org.ghost.messaging

import org.ghost.messaging.api.AddContactResult
import org.ghost.messaging.api.CardSource
import org.ghost.messaging.api.ContactId
import org.ghost.messaging.api.Establishment
import org.ghost.messaging.api.MessageState
import org.ghost.messaging.api.SendResult
import org.ghost.messaging.api.Timer
import org.ghost.messaging.api.TrustState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The one-scan flow of Phase 9 design §12.2, end to end, on two devices with the **real**
 * cryptography (§15.1).
 *
 * > 1. A scans B's card → A's contact B (`verified`, no pinned Olm identity yet).
 * > 2. A's first send keeps the message pending and starts the fetch of `P_B`.
 * > 3. `BUNDLE` keeps B's verified bundle; `EST-READY` pins `OI_B`, builds the initiator session,
 * >    encrypts the pending message into an Olm PreKey message and seals it in **intro** mode.
 * > 4. B's `RECV` opens the intro envelope: unknown `identity_pk` → a request with the message.
 * > 5. B accepts → contact A. B's reply is a normal message sealed in **provisional** mode, with
 * >    no bundle fetch, carrying B's `seal_root` for A → B.
 * > 6. A's session is now acknowledged; A's next message is pair-sealed under B's root and carries
 * >    A's `seal_root`. B seals in pair mode from its next message.
 *
 * Each step is asserted where it happens, because each one is a different failure: a wrong wrap
 * binding stops at 3, a wrong transcript input at 4, a wrong direction byte at 5, and a wrong
 * root generation or week at 6 — and all of them look the same from the outside ("the peer sees
 * nothing") if only the last step is checked.
 */
class DmFlowTest {

    private fun requireNative() {
        assumeTrue(
            "set -Dghost.dm.native to the ghost-dm-host library",
            DmWorld.nativeAvailable(),
        )
    }

    @Test
    @Suppress("LongMethod")
    fun theOneScanFlowRunsFromACardToPairMode() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            val bob = world.bob
            activate(world)

            // 1. A scans B's card in person: `verified`, and nothing else happens (rule R-E1).
            val added = alice.engine.addContact(bob.card(), CardSource.QR_IN_PERSON)
            assertEquals(AddContactResult.ADDED, added)
            val contactB = alice.engine.contacts().single().id
            assertEquals(TrustState.VERIFIED, alice.engine.contacts().single().trust)
            assertEquals(Establishment.CARD_ONLY, alice.engine.contacts().single().establishment)
            assertTrue("adding a card enqueues nothing", storeCount(alice) == bundleStores(alice))

            // 2. A's first send: the message is stored, and the bundle fetch starts (§5.5).
            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "hello", null))
            assertEquals(Establishment.FETCHING, alice.engine.contacts().single().establishment)
            assertEquals(1, alice.engine.status().pendingSends)
            assertEquals(
                "a pending send has no op yet",
                bundleStores(alice),
                storeCount(alice),
            )

            // 3. B's bundle reaches A, `BUNDLE` verifies it and `EST-READY` builds the session.
            assertTrue("B's bundle reaches A's temporary P_B pair", world.deliver() > 0)
            alice.timeTriggeredPass()
            assertEquals(
                "`BUNDLE` only keeps the candidate: `EST-READY` waits two minutes for a better " +
                    "one (§21.7 point 4)",
                Establishment.FETCHING,
                alice.engine.contacts().single().establishment,
            )
            world.advanceTo(alice.clock.now + 3 * DmWorld.MINUTE)
            alice.timeTriggeredPass()
            assertEquals(Establishment.READY, alice.engine.contacts().single().establishment)
            assertEquals(0, alice.engine.status().pendingSends)
            assertEquals(
                "the intro envelope is enqueued",
                bundleStores(alice) + 1,
                storeCount(alice),
            )

            // 4. B receives it: an unknown card holder becomes a **request** with its message.
            world.deliver()
            bob.hintPass()
            val requests = bob.engine.contacts()
            assertEquals(1, requests.size)
            assertEquals(TrustState.REQUEST, requests.single().trust)
            val contactA = requests.single().id
            assertEquals(
                listOf("hello"),
                bob.engine.conversation(contactA, 10, null).map { it.text },
            )
            assertEquals(
                "no reflex: receiving stores nothing",
                bundleStores(bob),
                storeCount(bob),
            )

            // 5. B accepts and answers. The reply is a normal message in **provisional** mode,
            //    with no bundle fetch of its own (§6.7) and B's root inside (§21.3 point 1).
            assertTrue(bob.engine.acceptRequest(contactA))
            assertEquals(SendResult.QUEUED, bob.engine.send(contactA, "hi back", null))
            assertEquals(
                "B answers without fetching A's bundle",
                Establishment.CARD_ONLY,
                bob.engine.contacts().single().establishment,
            )
            assertEquals(bundleStores(bob) + 1, storeCount(bob))

            world.deliver()
            alice.hintPass()
            val atAlice = alice.engine.conversation(contactB, 10, null)
            assertEquals(listOf("hi back", "hello"), atAlice.map { it.text })
            assertEquals(MessageState.UNREAD, atAlice.first().state)

            // 6. A's next message is pair-sealed under B's root, and carries A's own root.
            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "pair now", null))
            world.deliver()
            bob.hintPass()
            assertEquals(
                listOf("pair now", "hi back", "hello"),
                bob.engine.conversation(contactA, 10, null).map { it.text },
            )

            // And B's next message is pair-sealed too, which is only possible if A's root
            // arrived inside the message above and became B's out key.
            assertEquals(SendResult.QUEUED, bob.engine.send(contactA, "and back", null))
            world.deliver()
            alice.hintPass()
            assertEquals(
                listOf("and back", "pair now", "hi back", "hello"),
                alice.engine.conversation(contactB, 10, null).map { it.text },
            )
            assertEquals(0, alice.engine.status().drops.values.sum())
            assertEquals(0, bob.engine.status().drops.values.sum())
        }
    }

    /**
     * §7.6's four dedup layers, from the outside: a relay that re-serves a delivered blob makes
     * **no** second row and no traffic (CS-7, RP1/RP2).
     */
    @Test
    fun aReServedBlobIsConsumedAndShownOnce() {
        requireNative()
        DmWorld().use { world ->
            val (contactB, contactA) = establishBothWays(world)
            val before = world.bob.engine.conversation(contactA, 10, null).size

            assertEquals(SendResult.QUEUED, world.alice.engine.send(contactB, "once", null))
            world.deliver()
            world.bob.hintPass()
            val after = world.bob.engine.conversation(contactA, 10, null)
            assertEquals(before + 1, after.size)
            assertEquals("once", after.first().text)

            // The relay serves the same bytes again, in the same namespace.
            val blob = lastStore(world.alice)
            val dropsBefore = world.bob.engine.status().drops.values.sum()
            world.redeliver(world.alice, world.bob, blob.first, blob.second)
            val storesBefore = storeCount(world.bob)
            world.bob.hintPass()
            assertEquals(
                "a re-served blob makes no second row",
                before + 1,
                world.bob.engine.conversation(contactA, 10, null).size,
            )
            assertEquals("and no traffic (T28)", storesBefore, storeCount(world.bob))
            // D1 absorbs it before RECV: the `(namespace, blob_hash)` row of the first delivery is
            // still there, so the copy is not even offered, and nothing is counted. (Until slice S13
            // this line asserted a counter had moved, which held only because the sender
            // re-attached a root offer the recipient already had and RECV counted
            // `root_not_newer` — a count of the *first* delivery, not of the re-serve; §22.18.)
            assertEquals(
                "the re-serve never reached RECV",
                dropsBefore,
                world.bob.engine.status().drops.values.sum(),
            )
            var copies = 0
            world.bob.sql.query(
                "SELECT count(*) FROM inbox_blob WHERE namespace_id = ? AND blob_hash = ?",
                listOf(blob.first, java.security.MessageDigest.getInstance("SHA-256").digest(blob.second)),
            ) { copies = it.long(0).toInt() }
            assertEquals("one inbox row for the blob, however often it is served", 1, copies)
        }
    }

    /** §12.4: a blocked contact's envelopes stop opening, and nothing is sent to tell it. */
    @Test
    fun blockingStopsBothDirectionsAndTellsNobody() {
        requireNative()
        DmWorld().use { world ->
            val (contactB, contactA) = establishBothWays(world)
            val storesBefore = storeCount(world.bob)
            assertTrue(world.bob.engine.block(contactA))
            assertEquals("block sends nothing", storesBefore, storeCount(world.bob))
            assertEquals(TrustState.BLOCKED, world.bob.engine.contacts().single().trust)

            assertEquals(
                SendResult.BLOCKED,
                world.bob.engine.send(contactA, "not going out", null),
            )
            // A does not know, and keeps writing; B consumes and shows nothing.
            assertEquals(SendResult.QUEUED, world.alice.engine.send(contactB, "still here", null))
            world.deliver()
            val shownBefore = world.bob.engine.conversation(contactA, 10, null).size
            world.bob.hintPass()
            assertEquals(shownBefore, world.bob.engine.conversation(contactA, 10, null).size)
        }
    }

    /**
     * §10.5: a TIMER_SET is a message both sides see, and R-T9 adopts the greater version from
     * any message — so the recipient's conversation timer follows without a second round trip.
     */
    @Test
    fun aTimerChangeTravelsAsAMessageBothSidesSee() {
        requireNative()
        DmWorld().use { world ->
            val (contactB, contactA) = establishBothWays(world)
            assertEquals(SendResult.QUEUED, world.alice.engine.setTimer(contactB, Timer.HOUR_1))
            world.deliver()
            world.bob.hintPass()
            val shown = world.bob.engine.conversation(contactA, 10, null)
            assertEquals(
                "a timer change is a row with no body (ADR-27 C.8)",
                null,
                shown.first().text,
            )
            // The next message of the conversation carries the adopted timer, which is what makes
            // its relay TTL the 1-hour bucket (R-T2).
            assertEquals(SendResult.QUEUED, world.bob.engine.send(contactA, "short now", null))
            assertEquals(3_600L, lastTtl(world.bob))
        }
    }

    /** §12.6, §13.2: content past `MAX_BODY_BYTES` is `TOO_LARGE` and never reaches a bucket. */
    @Test
    fun contentLargerThanTheApiCapIsRefused() {
        requireNative()
        DmWorld().use { world ->
            val (contactB, _) = establishBothWays(world)
            val storesBefore = storeCount(world.alice)
            val huge = "x".repeat(70_000)
            assertEquals(SendResult.TOO_LARGE, world.alice.engine.send(contactB, huge, null))
            assertEquals(storesBefore, storeCount(world.alice))
        }
    }

    /**
     * §12.3: a rejected request leaves nothing behind, and A cannot re-create it by re-sending the
     * **same** unacknowledged session.
     *
     * A's second message is another PreKey envelope of the session her first one started, so its
     * `session_id` is the one already in `olm_prekey_used`: D2b refuses it (§7.6, §5.6 — vodozemac
     * does not consume a fallback key, so without the reuse set this would build a second session
     * and a second request). The requester learns nothing either way, which is what §12.3's "no
     * reflex" costs and buys.
     */
    @Test
    fun aRejectedRequestLeavesNoContact() {
        requireNative()
        DmWorld().use { world ->
            val contactB = introduce(world)
            world.deliver()
            world.bob.hintPass()
            val request = world.bob.engine.contacts().single()
            assertEquals(TrustState.REQUEST, request.trust)
            assertTrue(world.bob.engine.rejectRequest(request.id))
            assertTrue(world.bob.engine.contacts().isEmpty())

            val storesBefore = storeCount(world.bob)
            assertEquals(SendResult.QUEUED, world.alice.engine.send(contactB, "again", null))
            assertEquals("and it reaches B's inbox", 1, world.deliver())

            // It is the chain index **1** of a session B no longer has, so the gap hold keeps it
            // back for its first pass: with the session gone nothing says index 0 was seen, and
            // §7.7 point 2 waits `HOLD_MAX` rather than showing a chain out of order.
            world.bob.hintPass()
            assertTrue("held, not yet consumed", world.bob.engine.status().drops.isEmpty())

            world.advanceTo(world.bob.clock.now + 13 * DmWorld.MINUTE)
            world.bob.hintPass()
            assertTrue("no second request", world.bob.engine.contacts().isEmpty())
            assertEquals(
                "the re-sent first flight is a D2b replay",
                1,
                world.bob.engine.status().drops["replay"],
            )
            assertEquals("and a drop is silent (R-P2)", storesBefore, storeCount(world.bob))
        }
    }

    /**
     * §22.8.5 rule 4 on both sides of a **one-reply** conversation: A's first message, B's
     * provisional reply carrying B's root, A's pair-sealed answer carrying A's root — and then B
     * never writes again, so A never opens a pair envelope under **its own** root and never
     * acknowledges it.
     *
     * Each side still erases `prov_env` by `prov_anchor_minute + 119 d`. Before slice S11's review
     * only the acknowledgement scheduled an erase minute, so A kept its `reply_seed` for as long as
     * the session lived (defect (3) of §22.8.5, mutant PM-39's behaviour); B, which did open A's
     * pair envelope, got `pair-open + 45 d`.
     */
    @Test
    fun aSideWhosePeerNeverWritesAgainStillErasesItsProvisionalKey() {
        requireNative()
        DmWorld().use { world ->
            establishBothWays(world)
            val a = provisional(world.alice)
            val b = provisional(world.bob)
            val aAnchor = requireNotNull(a.anchor) { "A's anchor is its first decryption" }
            val bAnchor = requireNotNull(b.anchor) { "B's anchor is its first provisional seal" }
            assertTrue("A still holds its reply_seed", a.held)
            assertEquals(
                "A never acknowledged its root, so only the anchor bounds its prov_env",
                aAnchor + 119 * DmWorld.DAY,
                a.eraseMinute,
            )
            val bErase = requireNotNull(b.eraseMinute) { "B acknowledged A's pair envelope" }
            assertTrue(
                "B's erase minute is min(pair-open + 45 d, anchor + 119 d)",
                bErase <= bAnchor + 119 * DmWorld.DAY && bErase < bAnchor + 50 * DmWorld.DAY,
            )

            // One minute before A's bound nothing goes; at it, the session stays and prov_env goes.
            world.advanceTo(aAnchor + 119 * DmWorld.DAY - DmWorld.MINUTE)
            world.alice.timeTriggeredPass()
            assertTrue("not before the bound", provisional(world.alice).held)
            world.advanceTo(aAnchor + 119 * DmWorld.DAY)
            world.alice.timeTriggeredPass()
            world.bob.timeTriggeredPass()
            val after = provisional(world.alice)
            assertTrue("the session itself stays", after.exists)
            assertTrue("A erased prov_env at anchor + 119 d", !after.held)
            assertTrue("and B long before", !provisional(world.bob).held)
        }
    }

    // ---------------------------------------------------------------- helpers

    private class Provisional(val exists: Boolean, val held: Boolean, val anchor: Long?, val eraseMinute: Long?)

    private fun provisional(device: DmDevice): Provisional {
        var out = Provisional(false, false, null, null)
        device.sql.query(
            "SELECT prov_env IS NOT NULL, prov_anchor_minute, prov_erase_minute FROM olm_session " +
                "WHERE slot = 'current'",
        ) { r ->
            out = Provisional(
                exists = true,
                held = r.long(0) == 1L,
                anchor = if (r.isNull(1)) null else r.long(1),
                eraseMinute = if (r.isNull(2)) null else r.long(2),
            )
        }
        return out
    }

    private fun activate(world: DmWorld) {
        world.alice.engine.onActivated()
        world.bob.engine.onActivated()
        assertNotNull(world.alice.engine.myCard())
        assertNotNull(world.bob.engine.myCard())
    }

    /** A adds B's card and sends once; the intro envelope is enqueued but not delivered. */
    private fun introduce(world: DmWorld): ContactId {
        activate(world)
        assertEquals(
            AddContactResult.ADDED,
            world.alice.engine.addContact(world.bob.card(), CardSource.QR_IN_PERSON),
        )
        val contactB = world.alice.engine.contacts().single().id
        assertEquals(SendResult.QUEUED, world.alice.engine.send(contactB, "hello", null))
        world.deliver()
        // Two passes: the first consumes B's bundle and keeps the candidate, the second runs
        // `EST-READY` once the two-minute window for a better candidate has passed (§21.7 point 4).
        world.alice.timeTriggeredPass()
        world.advanceTo(world.alice.clock.now + 3 * DmWorld.MINUTE)
        world.alice.timeTriggeredPass()
        return contactB
    }

    /** The flow to the point where both sides seal in pair mode. */
    private fun establishBothWays(world: DmWorld): Pair<ContactId, ContactId> {
        val contactB = introduce(world)
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
        assertNull(
            "no drop so far",
            world.bob.engine.status().drops.entries.firstOrNull { it.value > 0 }?.key,
        )
        return contactB to contactA
    }

    private fun storeCount(device: DmDevice): Int {
        var count = 0
        device.sql.query("SELECT count(*) FROM outbox_op") { count = it.long(0).toInt() }
        return count
    }

    /** The bundle publications of ACTIVATE and OWNER-WEEK, which are not message traffic. */
    private fun bundleStores(device: DmDevice): Int {
        var count = 0
        device.sql.query(
            "SELECT count(*) FROM dm_outbound_op WHERE purpose = 'bundle'",
        ) { count = it.long(0).toInt() }
        return count
    }

    private fun lastStore(device: DmDevice): Pair<ByteArray, ByteArray> {
        var out: Pair<ByteArray, ByteArray>? = null
        device.sql.query(
            "SELECT namespace_id, ciphertext FROM outbox_op ORDER BY rowid DESC LIMIT 1",
        ) { out = it.blob(0) to it.blob(1) }
        return requireNotNull(out)
    }

    private fun lastTtl(device: DmDevice): Long {
        var ttl = 0L
        device.sql.query(
            "SELECT ttl_seconds FROM outbox_op ORDER BY rowid DESC LIMIT 1",
        ) { ttl = it.long(0) }
        return ttl
    }
}
