package org.ghost.messaging

import org.ghost.crypto.bridge.DmContent
import org.ghost.messaging.api.AddContactResult
import org.ghost.messaging.api.CardSource
import org.ghost.messaging.api.ContactId
import org.ghost.messaging.api.Establishment
import org.ghost.messaging.api.MessageId
import org.ghost.messaging.api.MessageState
import org.ghost.messaging.api.SendResult
import org.ghost.messaging.api.Timer
import org.ghost.messaging.api.TrustState
import org.ghost.messaging.engine.EstablishmentSteps
import org.ghost.messaging.port.DmEnvelopes
import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import org.ghost.storage.SqlExecutor
import org.ghost.storage.StorageFullException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The regressions of the Phase 9 review (docs/reviews/2026-09-25-faza9-review.md, design §22.34),
 * one test per finding, each on the real engine and the real native library.
 *
 * Every test here failed on the tree the review read, in the way its KDoc says, and passes with the
 * fix it names; the review document records both runs.
 */
class PhaseReviewRegressionTest {

    private fun requireNative() {
        assumeTrue("set -Dghost.dm.native", DmWorld.nativeAvailable())
    }

    // ------------------------------------------------------------------ ENG-1, ENG-3

    /** Bodies the tampering decorator recognises in a sender's L0. */
    private val emptyMarker = "EMPTY-ME".toByteArray()
    private val echoMarker = "ECHO-ME".toByteArray()

    /** The id [echoMarker] is re-sent under: another row's id on the receiver. */
    private var echoId: ByteArray? = null

    /**
     * A **modified sender**: an L0 whose body is [emptyMarker] goes out as an unquoted empty TEXT
     * (timer off, so a held one would wait its whole 30 days), one whose body is [echoMarker] under
     * [echoId]. Only the contact's own client can build either — the L0 is inside its session.
     */
    private fun tampering(inner: DmEnvelopes): DmEnvelopes = object : DmEnvelopes by inner {
        override fun encodeContent(
            kind: DmContent.Kind,
            messageId: ByteArray,
            authorMinute: Long,
            minuteIndex: Int,
            timerCode: Int,
            timerVersion: Long,
            quoteRef: ByteArray?,
            body: ByteArray,
            contactId: ByteArray,
            offerRootGen: Int,
            offerEnv: ByteArray,
            revocation: ByteArray,
            sessionReset: Boolean,
            pqKey: DmContent.PqKeyCandidate?,
            pqKeyFirst: Boolean,
        ): DmContent.Encoded {
            val empty = body.contentEquals(emptyMarker)
            val echo = body.contentEquals(echoMarker) && echoId != null
            return inner.encodeContent(
                kind, if (echo) echoId!! else messageId, authorMinute, minuteIndex,
                if (empty) 0 else timerCode, timerVersion,
                quoteRef, if (empty) ByteArray(0) else body, contactId, offerRootGen, offerEnv, revocation,
                sessionReset, pqKey, pqKeyFirst,
            )
        }
    }

    /**
     * ENG-3: an unquoted empty TEXT from a contact made `RECV` throw a CHECK abort (`body_env`
     * 30 …) on three passes, then R2 consumed it as poison; one that re-used this device's own
     * outgoing id threw the `dm_message_no_replace` trigger. Both are dropped now — as bad content
     * and as `id_taken` — in the first pass, which throws nothing, and poison counts nothing.
     */
    @Test
    fun aPeerCannotMakeRecvThrowWithAnEmptyTextOrAReusedId() {
        requireNative()
        DmWorld(decorate = { branch, inner -> if (branch == 0x41) tampering(inner) else inner }).use { world ->
            val alice = world.alice
            val bob = world.bob
            val (contactB, contactA) = establishBothWays(world)
            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "EMPTY-ME", null))
            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "after", null))
            world.deliver()
            bob.hintPass()
            assertEquals("both blobs consumed in one pass", 0, fetched(bob))
            assertTrue(bob.engine.conversation(contactA, 10, null).any { it.text == "after" })
            assertEquals(1, bob.engine.status().drops["bad_content"])
            assertEquals(0, bob.engine.status().poisoned)

            echoId = bob.engine.conversation(contactA, 10, null).first { it.outgoing }.id.toByteArray()
            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "ECHO-ME", null))
            world.deliver()
            bob.hintPass()
            assertEquals(0, fetched(bob))
            assertEquals(1, bob.engine.status().drops["id_taken"])
            assertEquals(
                "the own row the id named is untouched",
                1,
                count(bob, "SELECT count(*) FROM dm_message WHERE direction = 'out' AND message_id = ?", echoId!!),
            )
            assertEquals(0, bob.engine.status().poisoned)
        }
    }

    /**
     * ENG-1: a held key-change message whose replay aborted — an empty TEXT from the device that
     * holds the contact's `ghost1` seed — made `acknowledgeKeyChange` throw after KEYDEC committed
     * and every later pass throw until the hold expired (30 days with the timer off): OWNER-WEEK,
     * KEEPER, `RECV` and the establishment steps all stopped. The replay drops it as bad content.
     */
    @Test
    fun aHeldEmptyTextNoLongerStopsEveryPass() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            val (contactB, _) = establishBothWays(world)
            val newB = DmDevice(
                branch = 0x61,
                slotCount = world.bob.slotCount,
                operators = world.bob.operators,
                startSeconds = alice.clock.now,
                identityBranch = world.bob.identityBranch,
                decorateEnvelopes = { tampering(it) },
            )
            newB.use {
                newB.engine.onActivated()
                assertEquals(AddContactResult.ADDED, newB.engine.addContact(alice.card(), CardSource.LINK))
                val cA = newB.engine.contacts().single().id
                assertEquals(SendResult.QUEUED, newB.engine.send(cA, "EMPTY-ME", null))
                world.deliverBetween(alice, newB)
                newB.timeTriggeredPass()
                newB.clock.now += 3 * DmWorld.MINUTE
                world.advanceTo(newB.clock.now)
                newB.timeTriggeredPass()
                world.deliverBetween(newB, alice)
                alice.hintPass()
                assertEquals(TrustState.CHANGED, alice.engine.contacts().single().trust)
                assertEquals(1, count(alice, "SELECT count(*) FROM dm_held"))

                assertTrue(alice.engine.acknowledgeKeyChange(contactB))
                assertEquals("the replay dropped it", 0, count(alice, "SELECT count(*) FROM dm_held"))
                assertEquals(1, alice.engine.status().drops["bad_content"])
                // The passes of the next four weeks run to the end: OWNER-WEEK publishes again.
                val weekBefore = requireNotNull(bundleWeek(alice))
                val t0 = alice.clock.now
                for (days in listOf(1L, 8L, 15L, 22L, 29L)) {
                    world.advanceTo(t0 + days * DmWorld.DAY)
                    alice.timeTriggeredPass()
                    alice.hintPass()
                }
                assertTrue("OWNER-WEEK ran again", requireNotNull(bundleWeek(alice)) > weekBefore)
            }
        }
    }

    // ------------------------------------------------------------------ ENG-2

    /** An executor whose `dm_message` inserts (and, when asked, its deferrals) hit a full disk. */
    private class FullDisk(private val inner: JdbcSqlExecutor) : SqlExecutor by inner {
        @Volatile var messages = false

        @Volatile var deferrals = false

        private fun check(sql: String) {
            val statement = sql.trimStart()
            if ((messages && statement.startsWith("INSERT INTO dm_message(")) ||
                (deferrals && statement.startsWith("UPDATE inbox_blob SET offer_after_minute"))
            ) {
                throw StorageFullException(IllegalStateException("[SQLITE_FULL] regression test"))
            }
        }

        override fun exec(sql: String, args: List<Any?>) {
            check(sql)
            inner.exec(sql, args)
        }

        override fun execUpdate(sql: String, args: List<Any?>): Int {
            check(sql)
            return inner.execUpdate(sql, args)
        }
    }

    /** Alice's first message to carol, in carol's inbox; carol's database is [sql]. */
    private fun introToCarol(world: DmWorld, sql: SqlExecutor): DmDevice {
        val alice = world.alice
        val carolClock = MovableClock(alice.clock.now)
        val carol = DmDevice(
            0x55, alice.slotCount, alice.operators, alice.clock.now,
            harness = DmDevice.HarnessOverride(sql, carolClock, 0),
        )
        alice.engine.onActivated()
        carol.engine.onActivated()
        assertEquals(AddContactResult.ADDED, alice.engine.addContact(carol.card(), CardSource.QR_IN_PERSON))
        val contactC = alice.engine.contacts().single().id
        assertEquals(SendResult.QUEUED, alice.engine.send(contactC, "hello carol", null))
        world.deliverBetween(carol, alice)
        alice.timeTriggeredPass()
        world.advanceTo(alice.clock.now + 3 * DmWorld.MINUTE)
        carolClock.now = alice.clock.now
        carolClock.monotonic += 1_000
        alice.timeTriggeredPass()
        assertTrue("the intro reached carol's inbox", world.deliverBetween(alice, carol) > 0)
        return carol
    }

    /**
     * ENG-2 (§21.12 point 1, §7.8 "disk full"): a full disk that failed `RECV` for as long as four
     * offers consumed the intro as poison — the message was lost, with nothing dead. Each rolled
     * back `RECV` is followed by `Inbox.defer(60 s)`, which resets the counter, so the blob waits
     * for the disk and is received when it frees.
     */
    @Test
    fun aPersistentlyFullDiskDefersTheBlobAndLosesNothing() {
        requireNative()
        DmWorld().use { world ->
            val raw = JdbcSqlExecutor(":memory:").also { MigrationRunner(it).migrate() }
            val full = FullDisk(raw)
            val carol = introToCarol(world, full)
            carol.use {
                full.messages = true
                repeat(6) {
                    carol.hintPass()
                    carol.clock.now += 2 * DmWorld.HOUR
                    carol.clock.monotonic += 1_000
                }
                assertEquals("never poison", 0, carol.engine.status().poisoned)
                assertEquals(1, count(raw, "SELECT count(*) FROM inbox_blob WHERE state = 'fetched'"))
                assertEquals("the counter was reset each time", 0, count(raw, "SELECT max(offers) FROM inbox_blob"))
                full.messages = false
                carol.hintPass()
                assertEquals("received once the disk freed", 1, carol.engine.contacts().size)
                assertEquals(1, count(raw, "SELECT count(*) FROM dm_message"))
            }
            raw.close()
        }
    }

    /**
     * ENG-2, the latch: when the deferral cannot be written either, no DM blob is claimed — the
     * offer counter stays where the failed claim left it — until a write succeeds.
     */
    @Test
    fun aDeferralThatCannotBeWrittenLatchesTheClaims() {
        requireNative()
        DmWorld().use { world ->
            val raw = JdbcSqlExecutor(":memory:").also { MigrationRunner(it).migrate() }
            val full = FullDisk(raw)
            val carol = introToCarol(world, full)
            carol.use {
                full.messages = true
                full.deferrals = true
                repeat(6) {
                    carol.hintPass()
                    carol.clock.now += 2 * DmWorld.HOUR
                    carol.clock.monotonic += 1_000
                }
                assertEquals("one claim, then none while latched", 1, count(raw, "SELECT max(offers) FROM inbox_blob"))
                assertEquals(0, carol.engine.status().poisoned)
                full.messages = false
                full.deferrals = false
                // The first write that succeeds is the owed deferral: the blob is re-offered 60 s on.
                carol.hintPass()
                assertEquals("the owed deferral reset the counter", 0, count(raw, "SELECT max(offers) FROM inbox_blob"))
                carol.clock.now += 2 * DmWorld.MINUTE
                carol.clock.monotonic += 1_000
                carol.hintPass()
                assertEquals(1, carol.engine.contacts().size)
                assertEquals(1, count(raw, "SELECT count(*) FROM dm_message"))
            }
            raw.close()
        }
    }

    // ------------------------------------------------------------------ ENG-4

    /**
     * ENG-4: `react(target, null)` and `react(target, "")` — §7.1's removal — threw the
     * `grapheme_env` CHECK every time; a target with no row threw a foreign-key abort; a grapheme
     * over 32 bytes threw "the engine built a non-canonical L0". Each is a `SendResult` now.
     */
    @Test
    fun reactAnswersEveryCaseWithAResult() {
        requireNative()
        DmWorld().use { world ->
            val (_, contactA) = establishBothWays(world)
            val bob = world.bob
            val target = bob.engine.conversation(contactA, 10, null).first { !it.outgoing }.id
            assertEquals(SendResult.QUEUED, bob.engine.react(contactA, target, "👍"))
            assertEquals(1, count(bob, "SELECT count(*) FROM dm_reaction WHERE from_self = 1"))
            assertEquals(SendResult.QUEUED, bob.engine.react(contactA, target, null))
            assertEquals("removed", 0, count(bob, "SELECT count(*) FROM dm_reaction WHERE from_self = 1"))
            assertEquals(SendResult.QUEUED, bob.engine.react(contactA, target, "👍"))
            assertEquals(SendResult.QUEUED, bob.engine.react(contactA, target, ""))
            assertEquals("removed again", 0, count(bob, "SELECT count(*) FROM dm_reaction WHERE from_self = 1"))
            assertEquals(SendResult.UNKNOWN, bob.engine.react(contactA, MessageId(ByteArray(16) { 7 }), "👍"))
            val kiss = "👩🏽‍❤️‍💋‍👨🏿"
            assertEquals(35, kiss.toByteArray().size)
            assertEquals(SendResult.TOO_LARGE, bob.engine.react(contactA, target, kiss))
            assertEquals("the conversation still sends", SendResult.QUEUED, bob.engine.send(contactA, "still", null))
        }
    }

    // ------------------------------------------------------------------ ENG-5

    /**
     * ENG-5 (§10.2 row 6, R-T3): an INDETERMINATE resend took the conversation's **current**
     * bucket. A 7-day TEXT resent after the timer was turned off was stored for 30 days, and a
     * TIMER_SET that shortened the timer lost R-T3's larger bucket. The resend repeats the op's own.
     */
    @Test
    fun anIndeterminateResendRepeatsTheOpsOwnTtl() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            val (contactB, _) = establishBothWays(world)
            decideAll(alice, "sent")
            alice.outcomeStep.run()

            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "seven-day", null))
            val textOp = newestItemOp(alice)
            assertEquals(604_800L, ttlOf(alice, textOp))
            assertEquals(SendResult.QUEUED, alice.engine.setTimer(contactB, Timer.OFF))
            decideOne(alice, textOp, "indeterminate")
            alice.outcomeStep.run()
            assertEquals("the TEXT's resend", 604_800L, ttlOf(alice, newestItemOp(alice)))

            assertEquals(SendResult.QUEUED, alice.engine.setTimer(contactB, Timer.HOUR_1))
            val timerOp = newestItemOp(alice)
            assertEquals("R-T3: the larger of OFF's and 1 h's buckets", 2_592_000L, ttlOf(alice, timerOp))
            decideOne(alice, timerOp, "indeterminate")
            alice.outcomeStep.run()
            assertEquals("the TIMER_SET's resend", 2_592_000L, ttlOf(alice, newestItemOp(alice)))
        }
    }

    // ------------------------------------------------------------------ ENG-7

    /**
     * ENG-7 (§21.12 point 3, L7-D7 "≤ 7 days"): a deleted contact that had never sent or fetched
     * left two orphan rows whose namespaces `:sync` never held, and SWEEP kept them for ever —
     * card-derived values, and so evidence of the contact. The next sweep discharges them. Re-adding
     * a card clears the rows its namespaces left.
     */
    @Test
    fun orphanRowsOfUnregisteredNamespacesAreDischargedAndReAddClearsThem() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            alice.engine.onActivated()
            world.bob.engine.onActivated()
            assertEquals(AddContactResult.ADDED, alice.engine.addContact(world.bob.card(), CardSource.LINK))
            val contactB = alice.engine.contacts().single().id
            assertTrue(alice.engine.deleteContact(contactB))
            assertEquals(2, count(alice, "SELECT count(*) FROM dm_orphan_namespace"))
            assertEquals(0, count(alice, "SELECT count(*) FROM sync_namespace WHERE namespace_id IN (SELECT namespace_id FROM dm_orphan_namespace)"))
            world.advanceTo(alice.clock.now + DmWorld.DAY)
            alice.timeTriggeredPass()
            assertEquals("discharged by the next sweep", 0, count(alice, "SELECT count(*) FROM dm_orphan_namespace"))

            // Re-add: rows a delete left for namespaces that are still registered go with the add.
            assertEquals(AddContactResult.ADDED, alice.engine.addContact(world.bob.card(), CardSource.LINK))
            val again = alice.engine.contacts().single().id
            assertEquals(SendResult.QUEUED, alice.engine.send(again, "hello", null))
            assertTrue(alice.engine.deleteContact(again))
            assertEquals(2, count(alice, "SELECT count(*) FROM dm_orphan_namespace"))
            assertEquals(AddContactResult.ADDED, alice.engine.addContact(world.bob.card(), CardSource.LINK))
            assertEquals("the card is live again", 0, count(alice, "SELECT count(*) FROM dm_orphan_namespace"))
        }
    }

    // ------------------------------------------------------------------ MD-2

    /**
     * MD-2 (§21.7 point 5, Q42): the second and third fetch attempts open "at a relay session start
     * at least 6 h later". The alarm and the timer opened them, so with no session in those
     * windows the contact was unreachable and its first message FAILED about 13 hours after the
     * send, whatever its 7-day deadline. Alarm passes now close the open window and open nothing;
     * the next session start opens attempt 2.
     */
    @Test
    fun laterFetchAttemptsOpenAtASessionStartOnly() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            val bob = world.bob
            alice.engine.onActivated()
            assertEquals(AddContactResult.ADDED, alice.engine.addContact(bob.card(), CardSource.QR_IN_PERSON))
            val contactB = alice.engine.contacts().single().id
            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "hello", null))
            world.deliver()
            alice.timeTriggeredPass()
            assertEquals("the send opened attempt 1", 1, attempts(alice))
            val t0 = alice.clock.now
            // Bob publishes a bundle five minutes on; no relay session reaches it until the end.
            world.advanceTo(t0 + 5 * DmWorld.MINUTE)
            bob.engine.onActivated()
            for (minutes in listOf(20L, 380L, 395L, 755L, 770L, 24 * 60L)) {
                world.advanceTo(t0 + minutes * DmWorld.MINUTE)
                alice.alarmPass()
                assertEquals("+$minutes min", Establishment.FETCHING, alice.engine.contacts().single().establishment)
                assertEquals("+$minutes min: no attempt opened by the alarm", 1, attempts(alice))
            }
            assertEquals(MessageState.QUEUED, alice.engine.conversation(contactB, 10, null).single().state)

            // A relay session start: attempt 2 opens, and the bundle it lists establishes.
            alice.timeTriggeredPass()
            assertEquals(2, attempts(alice))
            world.deliver()
            alice.hintPass()
            world.advanceTo(alice.clock.now + 3 * DmWorld.MINUTE)
            alice.alarmPass()
            assertEquals(Establishment.READY, alice.engine.contacts().single().establishment)
        }
    }

    // ------------------------------------------------------------------ MD-3

    /**
     * MD-3 (§21.7 point 4, §21.9 rule 1 "next EST timer"): nothing woke the actor two minutes
     * after the first bundle candidate, so in a foreground session — whose start was long past —
     * the first message waited for the fetch window's end, about fifteen minutes. The actor timer
     * now asks for the candidate's `EST-READY`, and that timer's pass establishes.
     */
    @Test
    fun theActorTimerWakesForEstReady() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            val bob = world.bob
            alice.engine.onActivated()
            bob.engine.onActivated()
            assertEquals(AddContactResult.ADDED, alice.engine.addContact(bob.card(), CardSource.QR_IN_PERSON))
            val contactB = alice.engine.contacts().single().id
            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "hello", null))
            alice.hintPass()
            world.advanceTo(alice.clock.now + 30)
            world.deliver()
            alice.hintPass()
            assertEquals(1, count(alice, "SELECT count(*) FROM dm_bundle_candidate"))
            val delay = requireNotNull(alice.timerWakes.last) { "the timer was cancelled" }
            assertTrue(
                "the timer asks for EST-READY (${EstablishmentSteps.READY_DELAY_SECONDS} s after the candidate), got $delay",
                delay <= EstablishmentSteps.READY_DELAY_SECONDS,
            )
            world.advanceTo(alice.clock.now + delay)
            alice.alarmPass()
            assertEquals(Establishment.READY, alice.engine.contacts().single().establishment)
        }
    }

    // ------------------------------------------------------------------ ENG-6

    /**
     * ENG-6 (R-T7): after a forward step raised the expiry clock and the wall clock was corrected,
     * an own one-hour message was given `wall + 1 h`, already behind `now_e`: it vanished at the
     * next sweep while its copy went out. The countdown starts from `now_e`, as `DisplayStep`'s.
     */
    @Test
    fun anOwnMessageAfterABackwardStepOutlivesTheNextSweep() {
        requireNative()
        DmWorld().use { world ->
            val bob = world.bob
            val (contactB, contactA) = establishBothWays(world)
            assertEquals(SendResult.QUEUED, world.alice.engine.setTimer(contactB, Timer.HOUR_1))
            world.deliver()
            bob.hintPass()
            val t = bob.clock.now
            bob.clock.now = t + DmWorld.DAY
            bob.hintPass()
            bob.clock.now = t
            assertEquals(SendResult.QUEUED, bob.engine.send(contactA, "bob one hour", null))
            bob.hintPass()
            assertTrue(
                "the own message survives the sweep that follows it",
                bob.engine.conversation(contactA, 10, null).any { it.text == "bob one hour" },
            )
        }
    }

    // ------------------------------------------------------------------ ENG-8

    /**
     * ENG-8 (§7.7 point 2, "delays display by at most 12 minutes"): the gap hold measured
     * `now − first_seen` on the wall clock, so a clock stepped back a day held the blobs for the
     * day. A step back restarts the hold from the new time instead: 12 minutes on, they are shown.
     */
    @Test
    fun aBackwardStepDoesNotStretchTheGapHold() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            val bob = world.bob
            val (contactB, contactA) = establishBothWays(world)
            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "m1 lost", null))
            world.lose(alice, bob)
            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "m2", null))
            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "m3", null))
            world.deliver()
            val t = bob.clock.now
            bob.hintPass()
            assertFalse("held for the gap", bob.engine.conversation(contactA, 10, null).any { it.text == "m2" })
            bob.clock.now = t - DmWorld.DAY
            bob.clock.monotonic += 60_000
            bob.hintPass()
            bob.clock.now = t - DmWorld.DAY + 13 * DmWorld.MINUTE
            bob.clock.monotonic += 13 * 60_000
            bob.hintPass()
            val shown = bob.engine.conversation(contactA, 10, null).mapNotNull { it.text }
            assertTrue("released 13 minutes after the step, got $shown", "m2" in shown && "m3" in shown)
        }
    }

    // ---------------------------------------------------------------- helpers

    private fun fetched(device: DmDevice): Int =
        count(device, "SELECT count(*) FROM inbox_blob WHERE state = 'fetched'")

    private fun count(device: DmDevice, sql: String, vararg args: Any?): Int = count(device.sql, sql, *args)

    private fun count(sql: SqlExecutor, query: String, vararg args: Any?): Int {
        var n = 0
        sql.query(query, args.toList()) { if (!it.isNull(0)) n = it.long(0).toInt() }
        return n
    }

    private fun attempts(device: DmDevice): Int = count(device, "SELECT fetch_attempts FROM dm_contact")

    private fun bundleWeek(device: DmDevice): Long? {
        var week: Long? = null
        device.sql.query("SELECT bundle_week FROM dm_self") { week = if (it.isNull(0)) null else it.long(0) }
        return week
    }

    private fun newestItemOp(device: DmDevice): ByteArray {
        var out: ByteArray? = null
        device.sql.query(
            "SELECT d.operation_id FROM dm_outbound_op d JOIN outbox_op o ON o.operation_id = d.operation_id " +
                "WHERE d.purpose = 'item' ORDER BY o.rowid DESC LIMIT 1",
        ) { out = it.blob(0) }
        return requireNotNull(out)
    }

    private fun ttlOf(device: DmDevice, op: ByteArray): Long {
        var ttl = -1L
        device.sql.query("SELECT ttl_seconds FROM outbox_op WHERE operation_id = ?", listOf(op)) { ttl = it.long(0) }
        return ttl
    }

    /** Settles every pending DM op of [device] as [outcome], as `DmOutcomeTest` does. */
    private fun decideAll(device: DmDevice, outcome: String) {
        val hour = device.clock.nowEpochSeconds().let { it - it % 3600 }
        device.sql.exec(
            "UPDATE outbox_delivery SET state = 'verified', inflight = 0, copy_hour = ? WHERE state = 'pending' " +
                "AND operation_id IN (SELECT o.operation_id FROM outbox_op o JOIN sync_namespace n " +
                "ON n.namespace_id = o.namespace_id WHERE o.outcome = 'pending' AND n.consumer = 'dm')",
            listOf(hour),
        )
        device.sql.exec(
            "UPDATE outbox_op SET outcome = ?, ciphertext = NULL WHERE outcome = 'pending' " +
                "AND namespace_id IN (SELECT namespace_id FROM sync_namespace WHERE consumer = 'dm')",
            listOf(outcome),
        )
    }

    private fun decideOne(device: DmDevice, op: ByteArray, outcome: String) {
        val hour = device.clock.nowEpochSeconds().let { it - it % 3600 }
        device.sql.exec(
            "UPDATE outbox_delivery SET state = 'verified', inflight = 0, copy_hour = ? " +
                "WHERE state = 'pending' AND operation_id = ?",
            listOf(hour, op),
        )
        device.sql.exec(
            "UPDATE outbox_op SET outcome = ?, ciphertext = NULL WHERE outcome = 'pending' AND operation_id = ?",
            listOf(outcome, op),
        )
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
        assertEquals(TrustState.UNVERIFIED, world.bob.engine.contacts().single().trust)
        return contactB to contactA
    }
}
