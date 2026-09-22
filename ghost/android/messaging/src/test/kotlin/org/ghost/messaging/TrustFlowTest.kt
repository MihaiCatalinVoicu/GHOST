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

            val establishmentBefore = alice.engine.contacts().single().establishment
            world.deliverBetween(bob, alice)
            alice.hintPass()
            assertEquals(TrustState.REVOKED, alice.engine.contacts().single().trust)
            assertEquals(1, alice.engine.status().drops["revoked"])
            assertEquals("both sessions go with it (§8.5)", 0, sessionCount(alice))
            // §21.7 point 7 and mutant PM-31: `RECV` may not call `Namespaces.setListening`, and
            // the actor only visits contacts whose establishment is `fetching` — so a revocation
            // that rewrote this column would leave an open `P_c` window with nothing left that
            // could close it. It leaves the column exactly as it found it, and `EST-END` stays in
            // charge of any window that was open.
            assertEquals(
                "a revocation does not touch the establishment state",
                establishmentBefore,
                alice.engine.contacts().single().establishment,
            )
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

    /**
     * §8.6 and graft G-6: a pre-restore envelope **stays unopenable** on the restored device, and
     * is counted rather than shown.
     *
     * This is the residue the whole of §8.6 is arranged around, and the R-P2b withdrawal of round
     * 9 is the reason it must hold: an intro envelope built on the lost device's bundle names a
     * generation whose secrets were random and are gone, and nothing seed-derived opens it. A
     * restored device therefore learns **nothing** about who wrote to the lost one — which is the
     * price of "no seed-derivable first-contact key", and the thing that would quietly stop being
     * true if a healing path were ever re-introduced.
     */
    @Test
    fun aPreRestoreEnvelopeStaysUnopenableAndIsCounted() {
        requireNative()
        DmWorld().use { world ->
            val bob = world.bob
            val (_, contactA) = establishBothWays(world)
            assertEquals(SendResult.QUEUED, bob.engine.send(contactA, "before the restore", null))
            val (namespace, ciphertext) = lastStore(bob)

            val restored = world.restored(world.alice)
            restored.engine.onRestored()
            // The relay still holds B's blob and serves it to the restored device's inbox, which
            // is the **same** namespace: `X_0` is a card derivation and the card survived.
            world.redeliver(bob, restored, namespace, ciphertext)
            restored.hintPass()

            assertTrue("nothing was shown", restored.engine.contacts().isEmpty())
            val drops = restored.engine.status().drops
            assertTrue(
                "it is counted as unopenable, not applied: $drops",
                (drops["unknown_seal"] ?: 0) + (drops["unknown_generation"] ?: 0) > 0,
            )
        }
    }

    /**
     * §6.3's replacement of an offered root: the same generation while the offer is live, a new one
     * — `1 + max(root_gen)`, so a peer cannot ignore it — once it is not.
     *
     * Without a replacement at all, a root acknowledged once is never replaced and a seizure of
     * either device reads every pair envelope of that conversation back to its base week.
     *
     * **Which of §6.3's two clocks fires first, and why this test measures the earlier one**
     * (changed in S9, when SWEEP's erasure half landed). §6.3 gives the offered root's *secret*
     * two ends: "erased when a pair envelope under its generation opens (acknowledged) **or at
     * `start(b + 1) + FRESH`, whichever comes first** (a new root is then offered on my next user
     * message)". `FRESH` is 45 days, so an unacknowledged offer's secret is gone about 7.4 weeks
     * after its base week — **before** replacement rule (c)'s `ROOT_REPLACE_WEEKS = 13`. Until S9
     * nothing erased it, so (c) was the only rule that could fire and this test advanced 12 weeks
     * to show that it had not yet; with the erasure in place, 12 weeks is past the earlier bound
     * and the test would have measured that instead. It now stays inside both windows and then
     * crosses both. Rule (c) becomes the earlier of the two when S13 lowers
     * `ROOT_REPLACE_WEEKS` to 4 (§22.14).
     */
    @Test
    fun aRootOlderThanTheBoundIsReplacedAtTheNextSend() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            val (contactB, _) = establishBothWays(world)
            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "with a root", null))
            val first = rootGenerations(alice)
            assertEquals("one offered root so far", 1, first.size)

            // Inside both bounds: the same generation, whatever the number of sends. The weekly
            // passes are `PairKeySteps`, which ratchets the out key forward — without them the
            // conversation falls to `NO_SEAL_KEY` at the first week boundary and the test would be
            // measuring that instead (§21.3 point 5).
            weeks(world, 5)
            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "still inside", null))
            assertEquals(first, rootGenerations(alice))

            // Past both: a new generation, and `1 + max(root_gen)` so a peer cannot ignore it.
            weeks(world, 9)
            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "past the bound", null))
            val second = rootGenerations(alice)
            assertEquals(first.max() + 1, second.max())
        }
    }

    /**
     * §8.7: an **initiator** session unanswered for `UNACK_MAX = 28 days` is stale, and the next
     * user send re-establishes rather than sealing onto it.
     *
     * The old session is **demoted**, not deleted (R-SS0): the peer may still answer it, so it
     * receives on `previous` until its `retire_day`. There is no time-triggered re-establishment
     * (T28, T31) — the send is what causes it.
     */
    @Test
    fun anInitiatorSessionUnansweredForTwentyEightDaysIsReEstablished() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            val bob = world.bob
            alice.engine.onActivated()
            bob.engine.onActivated()
            alice.engine.addContact(bob.card(), CardSource.QR_IN_PERSON)
            val contactB = alice.engine.contacts().single().id
            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "hello", null))
            deliverBundle(world, from = bob, to = alice)
            val first = sessionIds(alice)
            assertEquals(1, first.size)

            // B never answers. Nothing time-triggered may replace the session on its own, over
            // five weeks of passes on both devices.
            weeks(world, 5)
            assertEquals("no automatic reset (§8.7, D10)", first, sessionIds(alice))

            // The user's send is what re-establishes it. B has published fresh bundles in the
            // meantime, so the fetch finds a **valid** candidate (§5.4 "Validity").
            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "are you there", null))
            deliverBundle(world, from = bob, to = alice)
            val now = sessionIds(alice)
            assertEquals("two slots: the new current and the demoted old one", 2, now.size)
            assertTrue("the old one was demoted, not deleted", now.containsAll(first))
            assertEquals(listOf("current", "previous"), sessionSlots(alice))
        }
    }

    /**
     * §8.7: the **bound** is 28 days, and this pins the side the other tests do not.
     *
     * `anInitiatorSessionUnansweredForTwentyEightDaysIsReEstablished` advances 35 days and
     * `DmResidueTest` 29; both are above the bound and both assert only that a session past it is
     * replaced, so a mutant `UNACK_MAX_DAYS = 1` survives them — with a smaller bound nothing
     * time-triggered replaces the session either (T28: there is no automatic re-establishment), so
     * "no automatic reset" still holds and the later send still re-establishes. What distinguishes
     * 28 from 1 is a send on **day 27**: it must seal onto the session that already exists.
     */
    @Test
    fun aSendInsideTheStalenessBoundKeepsTheSessionAndOneOutsideItDoesNot() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            val bob = world.bob
            alice.engine.onActivated()
            bob.engine.onActivated()
            alice.engine.addContact(bob.card(), CardSource.QR_IN_PERSON)
            val contactB = alice.engine.contacts().single().id
            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "hello", null))
            deliverBundle(world, from = bob, to = alice)
            val first = sessionIds(alice)
            assertEquals(1, first.size)

            // Day 27, B still silent. `unack_since_day` was written at creation and nothing bumps
            // it, so the age here is one day short of `UNACK_MAX`.
            days(world, 27)
            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "still inside", null))
            assertEquals(
                "a send inside the bound seals onto the session that exists",
                first,
                sessionIds(alice),
            )
            assertEquals(listOf("current"), sessionSlots(alice))

            // Day 29. Now the send must demote and re-establish through the bundle fetch.
            days(world, 2)
            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "past it", null))
            deliverBundle(world, from = bob, to = alice)
            val now = sessionIds(alice)
            assertEquals("the new current and the demoted old one", 2, now.size)
            assertTrue("the old one was demoted, not deleted", now.containsAll(first))
            assertEquals(listOf("current", "previous"), sessionSlots(alice))
        }
    }

    /**
     * **RS2 and CR-13 defect (3)**: a recipient that was away for sixty-one days still opens the
     * pair envelopes that follow.
     *
     * §21.3 point 5 exists for exactly this: "SWEEP first derives and stores … `K_w` for every
     * week up to `week(now)` from the newest stored key, **then** erases keys past
     * `start(w + 1) + FRESH`, in one transaction". Mutant **MC-21** is the two halves in the wrong
     * order, and `aRootOlderThanTheBoundIsReplacedAtTheNextSend` catches that one.
     *
     * This is the *other* way to lose the key, and the S9 review found it open: the ratchet
     * refused to run at all once the gap passed eight week-indices, while the erasure ran anyway
     * and took the newest in-key with it, because that key really is past its own window. What was
     * left was not "falls to `NO_SEAL_KEY` and re-establishes" — a recipient cannot re-establish —
     * but every later envelope of the conversation dropped as `unknown_seal`, silently and for
     * good. The cliff was at nine, and sixty days lands on eight or nine depending only on the
     * weekday the conversation started, so RS2's own sentence was false for half the calendar.
     *
     * Sixty-one days is chosen because it is on the far side of that cliff in this world: with the
     * cap at eight, Bob's sweep below erases every in-key he has and the last assertion fails.
     */
    @Test
    fun aRecipientBackAfterSixtyDaysStillOpensPairEnvelopes() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            val bob = world.bob
            val (contactB, _) = establishBothWays(world)
            assertTrue("Bob starts with in-keys", pairKeyWeeks(bob, "in").isNotEmpty())

            // Alice stays awake and ratchets; Bob's process is not running at all, which is what
            // an absence is. Only the clock is shared.
            repeat(61) {
                world.advanceTo(alice.clock.now + DmWorld.DAY)
                alice.timeTriggeredPass()
            }

            // Bob comes back. One pass, whose first step is SWEEP: derive, then erase.
            bob.timeTriggeredPass()
            assertTrue(
                "the ratchet reached week(now), so the keys of the live weeks are there",
                pairKeyWeeks(bob, "in").isNotEmpty(),
            )

            val before = messageCount(bob)
            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "after the absence", null))
            world.deliverBetween(alice, bob)
            bob.hintPass()
            assertEquals(
                "the pair envelope opened: ${bob.engine.status().drops}",
                before + 1,
                messageCount(bob),
            )
        }
    }

    // ---------------------------------------------------------------- helpers

    private fun pairKeyWeeks(device: DmDevice, direction: String): List<Long> {
        val out = ArrayList<Long>()
        device.sql.query(
            "SELECT week FROM dm_pair_key WHERE direction = ? ORDER BY week",
            listOf(direction),
        ) { out += it.long(0) }
        return out
    }

    private fun messageCount(device: DmDevice): Int {
        var count = 0
        device.sql.query("SELECT count(*) FROM dm_message") { count = it.long(0).toInt() }
        return count
    }

    /**
     * [count] days, a day at a time, with a time-triggered pass on both devices.
     *
     * A day at a time for the reason [weeks] gives: OWNER-WEEK publishes one bundle per week and a
     * device that skipped several would hold none valid (§5.4). It is **not** for the pair-key
     * ratchet any more — see [weeks].
     */
    private fun days(world: DmWorld, count: Int) {
        repeat(count) {
            world.advanceTo(world.alice.clock.now + DmWorld.DAY)
            world.alice.timeTriggeredPass()
            world.bob.timeTriggeredPass()
        }
    }

    /**
     * [count] ISO weeks, a week at a time, with a time-triggered pass on both devices.
     *
     * A week at a time and not one jump because OWNER-WEEK publishes one bundle per week and a
     * device that skipped several would hold none valid (§5.4). The **pair-key ratchet** no longer
     * needs it: §21.3 point 5 derives `K_w` for every week up to `week(now)` whatever the gap, and
     * `aRecipientBackAfterSixtyDaysStillOpensPairEnvelopes` is the test that walks one.
     */
    private fun weeks(world: DmWorld, count: Int) {
        repeat(count) {
            world.advanceTo(world.alice.clock.now + DmWorld.WEEK)
            world.alice.timeTriggeredPass()
            world.bob.timeTriggeredPass()
        }
    }


    private fun rootGenerations(device: DmDevice): List<Int> {
        val out = ArrayList<Int>()
        device.sql.query("SELECT root_gen FROM dm_pair_offer ORDER BY root_gen") {
            out += it.long(0).toInt()
        }
        return out
    }

    private fun sessionSlots(device: DmDevice): List<String> {
        val out = ArrayList<String>()
        device.sql.query("SELECT slot FROM olm_session ORDER BY slot") { out += it.string(0) }
        return out
    }

    private fun lastStore(device: DmDevice): Pair<ByteArray, ByteArray> {
        var found: Pair<ByteArray, ByteArray>? = null
        device.sql.query(
            "SELECT namespace_id, ciphertext FROM outbox_op ORDER BY rowid DESC LIMIT 1",
        ) { found = it.blob(0) to it.blob(1) }
        return requireNotNull(found)
    }

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
