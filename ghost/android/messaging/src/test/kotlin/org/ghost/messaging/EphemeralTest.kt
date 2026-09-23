package org.ghost.messaging

import org.ghost.messaging.api.AddContactResult
import org.ghost.messaging.api.CardSource
import org.ghost.messaging.api.ContactId
import org.ghost.messaging.api.MessageId
import org.ghost.messaging.api.MessageState
import org.ghost.messaging.api.SendResult
import org.ghost.messaging.api.Timer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * **T25 for DMs** (Phase 9 design §10.9, §15.5's EP suite), on two devices with the **real**
 * cryptography: a message that goes out, arrives, is or is not displayed, and then stops existing
 * — logically and in the bytes of the file.
 *
 * `SweepTest` drives SWEEP table by table on rows written straight into the database, which is the
 * only way to reach a generation two months past its retention or a `prov_env` past its erase
 * minute. This file is the other half: the **bounds** of §10.3, measured from the outside, through
 * the facade, with nothing but the clock moved by hand.
 *
 * > advance the virtual clock to the §10.3 bound + 1 min, sweep, then assert: **logically** no
 * > row, reaction, held row, pending row, retained blob or outbound mapping remains, the
 * > notification sink's last count is correct; **physically** the raw `.db` and `-wal` bytes
 * > contain neither the plaintext canary, nor the `body_env` bytes, nor the `message_id`; the WAL
 * > is 0 bytes.
 *
 * What is **not** here, and why (§22.14): the exit-gate EP suite of §15.5 — every timer × path
 * crossed with an honest, a short-lying and a long-lying relay, the request and pending-send
 * paths, the held replay at 1 h and 30 d, and the capture assertions of §10.9 point 5 — is S10's,
 * driven against a `ModelRelay` rather than this world's envelope path; NI-DM4's "captures for
 * 5 min vs 1 h are identical" is S11's twin. What this file pins is the behaviour those suites
 * will measure, with one case per rule rather than a cross product.
 */
class EphemeralTest {

    @get:Rule
    val temp = TemporaryFolder()

    private val minute = DmWorld.MINUTE
    private val hour = DmWorld.HOUR
    private val day = DmWorld.DAY

    private fun requireNative() {
        assumeTrue("set -Dghost.dm.native to the ghost-dm-host library", DmWorld.nativeAvailable())
    }

    // ------------------------------------------------------------- the sender bound

    /**
     * §10.3, row 1: the **sender's** countdown starts at the commit of SEND —
     * `expire_at_minute = ceil_minute(commit + timer)` — and is independent of the network.
     *
     * At the bound the row, its item, its op and its retained blob are gone; the conversation shows
     * nothing. §10.9 point 1's "no row, reaction, held row, pending row, retained blob or outbound
     * mapping remains".
     */
    @Test
    fun aSentMessageAndEverythingItHangsOffGoAtTheSendersBound() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            val (contactB, _) = establishBothWays(world)
            assertEquals(SendResult.QUEUED, alice.engine.setTimer(contactB, Timer.HOUR_1))
            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, CANARY, null))

            val id = idOfText(alice, contactB, CANARY)
            val expireAt = checkNotNull(columnById(alice, id, "expire_at_minute"))
            assertEquals(
                "ceil_minute(commit + 1 h)",
                ceilMinute(alice.clock.now + hour),
                expireAt,
            )
            assertEquals("the item is there before the bound", 1, itemsOf(alice, id))
            assertEquals("and its retained blob with it", 1, opsOf(alice, id))

            world.advanceTo(expireAt + minute)
            alice.timeTriggeredPass()

            // Per id, because the two establishment messages carry the default 7-day timer and are
            // still live — which is the point: SWEEP deletes by **each row's own** deadline
            // (§10.5), not by the conversation's current timer.
            assertEquals("the message row went", 0, rowsOf(alice, id))
            assertEquals("its outbound item went", 0, itemsOf(alice, id))
            assertEquals("its retained blob went (ME-20)", 0, opsOf(alice, id))
            assertEquals(
                "its reactions went",
                0,
                count(alice, "SELECT count(*) FROM dm_reaction WHERE target_id = ?", listOf(id)),
            )
            assertEquals(
                "its pending send went",
                0,
                count(alice, "SELECT count(*) FROM dm_pending_send WHERE item_id = ?", listOf(id)),
            )
            assertTrue(
                "and the messages whose own timer has not passed are untouched",
                alice.engine.conversation(contactB, 50, null).isNotEmpty(),
            )
        }
    }

    // ------------------------------------------------------- the recipient bounds

    /**
     * §10.3, rows 2 and 3, and ADR-27 point 9: an **unread** message goes at
     * `min(E, consume + bucket + 1 h)`; a **displayed** one goes at `ceil_minute(display + timer)`,
     * which may be later than the unread cap.
     *
     * Mutant **ME-7** ("recipient countdown at receive") is the second half not existing, and
     * **ME-8** ("no unread cap") the first.
     */
    @Test
    fun anUnreadMessageGoesAtTheCapAndADisplayedOneAtItsOwnCountdown() {
        requireNative()
        DmWorld().use { world ->
            val bob = world.bob
            val (contactB, contactA) = establishBothWays(world)
            assertEquals(SendResult.QUEUED, world.alice.engine.setTimer(contactB, Timer.DAYS_7))
            assertEquals(SendResult.QUEUED, world.alice.engine.send(contactB, CANARY, null))
            world.deliver()
            bob.hintPass()

            val consume = bob.clock.now
            val id = idOfText(bob, contactA, CANARY)
            val deadline = checkNotNull(columnById(bob, id, "unread_deadline_minute"))
            assertEquals(
                "min(E, consume + 7 d + 1 h), and the honest relay's E is above it",
                ceilMinute(consume + 7 * day + hour),
                deadline,
            )
            assertNull("an unread row has no display countdown", columnById(bob, id, "expire_at_minute"))

            // Displayed: the countdown restarts, and `delete_at_minute` may move **later** than the
            // cap — the one direction in which it legitimately does (§21.10 point 6).
            world.advanceTo(consume + day)
            assertEquals(1, bob.engine.markDisplayed(listOf(MessageId(id))))
            assertEquals(
                ceilMinute(bob.clock.now + 7 * day),
                checkNotNull(columnById(bob, id, "expire_at_minute")),
            )
            val deleteAt = checkNotNull(columnById(bob, id, "delete_at_minute"))
            assertTrue("later than the unread cap", deleteAt > deadline)
            assertEquals(
                listOf(MessageState.READ),
                bob.engine.conversation(contactA, 50, null)
                    .filter { it.text == CANARY }
                    .map { it.state },
            )

            world.advanceTo(deleteAt + minute)
            bob.timeTriggeredPass()
            assertEquals("the displayed message went at its own countdown", 0, rowsOf(bob, id))
        }
    }

    /**
     * §10.3's **E**, both directions of a lie.
     *
     * > A relay lying **short** can only make deletion earlier (a denial of service it could cause
     * > by withholding); a relay lying **long** is clamped.
     */
    @Test
    fun aRelayLyingShortMakesDeletionEarlierAndOneLyingLongIsClamped() {
        requireNative()
        DmWorld(databaseDirectory = null).use { world ->
            world.relayExpirySeconds = 2 * hour
            val bob = world.bob
            val (contactB, _) = establishBothWays(world)
            assertEquals(SendResult.QUEUED, world.alice.engine.send(contactB, CANARY, null))
            world.deliver()
            bob.hintPass()
            val consume = bob.clock.now
            val contactA = bob.engine.contacts().single().id
            val id = idOfText(bob, contactA, CANARY)
            assertEquals(
                "E wins: the blob is gone from the relay in two hours",
                ceilMinute(ceilHour(consume + 2 * hour)),
                checkNotNull(columnById(bob, id, "unread_deadline_minute")),
            )
        }
        DmWorld().use { world ->
            world.relayExpirySeconds = 90 * day
            val bob = world.bob
            val (contactB, _) = establishBothWays(world)
            assertEquals(SendResult.QUEUED, world.alice.engine.send(contactB, CANARY, null))
            world.deliver()
            bob.hintPass()
            val consume = bob.clock.now
            val contactA = bob.engine.contacts().single().id
            val id = idOfText(bob, contactA, CANARY)
            assertEquals(
                "the cap wins: a relay cannot extend a deadline",
                ceilMinute(consume + 7 * day + hour),
                checkNotNull(columnById(bob, id, "unread_deadline_minute")),
            )
        }
    }

    /**
     * Mutant **ME-19** and C-11: the unread deadline is **consume**-derived, never content-derived.
     *
     * A sender whose clock runs five days ahead authors a message five days in the future. If the
     * deadline were `author + bucket` — which is what ME-19 is — the recipient would keep it five
     * days longer than the rule allows, and a hostile sender would set its own retention on
     * somebody else's device. The recipient's own consume minute decides.
     */
    @Test
    fun aSenderClockFiveDaysAheadDoesNotExtendTheUnreadDeadline() {
        requireNative()
        DmWorld().use { world ->
            val bob = world.bob
            val (contactB, _) = establishBothWays(world)
            val bobNow = bob.clock.now
            val contactA = bob.engine.contacts().single().id

            world.alice.clock.now = bobNow + 5 * day
            assertEquals(SendResult.QUEUED, world.alice.engine.send(contactB, CANARY, null))
            world.deliver()
            bob.hintPass()

            val id = idOfText(bob, contactA, CANARY)
            val deadline = checkNotNull(columnById(bob, id, "unread_deadline_minute"))
            assertEquals(
                "consume + bucket + 1 h, on the recipient's clock",
                ceilMinute(bob.clock.now + 7 * day + hour),
                deadline,
            )
            assertTrue(
                "and strictly earlier than the content-derived one ME-19 would produce",
                deadline < (bobNow + 5 * day) + 7 * day,
            )
        }
    }

    /**
     * §21.10 point 6: **DISPLAY ignores ids whose `delete_at_minute ≤ now_e`.**
     *
     * The UI held a list across the unread cap — the phone was frozen, the user came back a week
     * later — and marking it displayed must not give the message a fresh countdown starting now.
     * The read that finds the row carries the expiry filter of §10.7 point 4, so the guard is the
     * filter itself.
     */
    @Test
    fun aStaleMarkDisplayedPastTheUnreadCapIsIgnored() {
        requireNative()
        DmWorld().use { world ->
            val bob = world.bob
            val (contactB, contactA) = establishBothWays(world)
            assertEquals(SendResult.QUEUED, world.alice.engine.setTimer(contactB, Timer.HOUR_1))
            assertEquals(SendResult.QUEUED, world.alice.engine.send(contactB, CANARY, null))
            world.deliver()
            bob.hintPass()
            val id = idOfText(bob, contactA, CANARY)
            val deadline = checkNotNull(columnById(bob, id, "unread_deadline_minute"))

            world.advanceTo(deadline + minute)
            assertEquals(
                "nothing was displayed",
                0,
                bob.engine.markDisplayed(listOf(MessageId(id))),
            )
            assertEquals(
                "and no fresh countdown was written",
                deadline,
                checkNotNull(columnById(bob, id, "delete_at_minute")),
            )
            assertNull("nor an expiry minute", columnById(bob, id, "expire_at_minute"))
            bob.timeTriggeredPass()
            assertEquals(0, rowsOf(bob, id))
        }
    }

    // --------------------------------------------------------------- no cancel

    /**
     * Mutant **ME-21** and §21.10 point 2: **SWEEP never calls `Outbox.cancel`.**
     *
     * The temptation is obvious — the message is gone, why keep storing it — and it is exactly
     * wrong: a cancel is relay-visible, so a 5-minute message whose op is still in flight at its
     * own expiry would produce a different pattern on the wire from a 1-hour one, which is the
     * whole of NI-DM4. What the op carries is E2E ciphertext no key on this device opens.
     *
     * The assertion is the **whole** relay-visible projection before and after the sweep, which is
     * wider than the wire on purpose (it covers `outbox_op.outcome` and the `outbox_delivery`
     * rows a cancel fails, which is how `Outbox.cancel` shows at all: it does not delete the op).
     *
     * **The other half of §21.10 point 2 is the second part of this test** (added by the S9
     * review): "ops run to their outcome or deadline" is not only "the sweep does not cancel", it
     * is also "the outcome still lands afterwards". SWEEP took the `dm_outbound_op` row with the
     * message, so OUTCOME finds nothing to record — and must still release the operation rather
     * than leave it in the outbox for ever, which is `OutcomeStep`'s "the release stands and there
     * is nothing left to record".
     */
    @Test
    fun sweepingAnExpiredMessageCancelsNothingInTheOutbox() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            val (contactB, _) = establishBothWays(world)
            assertEquals(SendResult.QUEUED, alice.engine.setTimer(contactB, Timer.MIN_5))
            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, CANARY, null))
            val id = idOfText(alice, contactB, CANARY)
            val before = alice.relayVisible()
            assertTrue("the op is in flight", before.any { it.startsWith("store ") })

            world.advanceTo(checkNotNull(columnById(alice, id, "expire_at_minute")) + minute)
            alice.timeTriggeredPass()

            assertEquals("the message row went", 0, rowsOf(alice, id))
            assertEquals(
                "and nothing the relays can see changed (ME-21)",
                before,
                alice.relayVisible(),
            )
            assertEquals("SWEEP took the op row with the message", 0, opsOf(alice, id))

            // The relays decide the operation the sweep left alone. It must be released, once.
            decideEverythingSent(alice)
            assertTrue("the outcome is released although its row is gone", alice.outcomeStep.run() > 0)
            assertEquals("and only once", 0, alice.outcomeStep.run())
            assertEquals(
                "no DM operation is left undecided",
                0,
                count(
                    alice,
                    "SELECT count(*) FROM outbox_op o JOIN sync_namespace n " +
                        "ON n.namespace_id = o.namespace_id " +
                        "WHERE o.outcome = 'pending' AND n.consumer = 'dm'",
                ),
            )
        }
    }

    /**
     * What the Phase 7 outbox engine writes when every DM operation is verified: the deliveries
     * settle first, because `outbox_op_payload` refuses to wipe a ciphertext while any delivery is
     * still pending ("wiped only after the last possible store").
     */
    private fun decideEverythingSent(device: DmDevice) {
        val hour = device.clock.nowEpochSeconds().let { it - it % 3600 }
        device.sql.exec(
            "UPDATE outbox_delivery SET state = 'verified', inflight = 0, copy_hour = ? " +
                "WHERE state = 'pending' AND operation_id IN (" +
                "SELECT o.operation_id FROM outbox_op o JOIN sync_namespace n " +
                "ON n.namespace_id = o.namespace_id WHERE o.outcome = 'pending' AND n.consumer = 'dm')",
            listOf(hour),
        )
        device.sql.exec(
            "UPDATE outbox_op SET outcome = 'sent', ciphertext = NULL WHERE outcome = 'pending' " +
                "AND namespace_id IN (SELECT namespace_id FROM sync_namespace WHERE consumer = 'dm')",
        )
    }

    // ------------------------------------------------------------- the physical half

    /**
     * §10.9 point 2 and point 3: after the sweep the **bytes** hold neither the canary, nor the
     * `body_env` ciphertext, nor the `message_id` — and the write-ahead log is 0 bytes.
     *
     * This is what the checkpoint is for (mutants **ME-10**, "checkpoint result ignored", and
     * **ME-11**, "no checkpoint"). `secure_delete = ON` scrubs the freed pages of the main file;
     * the pages that moved through the log leave it only when something truncates it, and nothing
     * else would — the in-memory `checkpoint_due` dies with the process and R-K1's open checkpoint
     * is the other end of the same rule.
     */
    @Test
    fun afterTheSweepNeitherTheFileNorTheLogHoldsTheMessage() {
        requireNative()
        val directory = temp.newFolder("t25")
        DmWorld(databaseDirectory = directory).use { world ->
            val bob = world.bob
            val (contactB, _) = establishBothWays(world)
            assertEquals(SendResult.QUEUED, world.alice.engine.setTimer(contactB, Timer.HOUR_1))
            assertEquals(SendResult.QUEUED, world.alice.engine.send(contactB, CANARY, null))
            world.deliver()
            bob.hintPass()

            val contactA = bob.engine.contacts().single().id
            val messageId = idOfText(bob, contactA, CANARY)
            val bodyEnv = bodyEnvOf(bob, messageId)
            val deadline = checkNotNull(columnById(bob, messageId, "unread_deadline_minute"))

            // Before: the ciphertext is in the file, so the scan below is not vacuous. The canary
            // itself never is — `body_env` is sealed under the content key (§13.8) — which is why
            // §10.9 point 2 also asks for a logical scan, and why this asserts the *envelope* is
            // there rather than the plaintext.
            world.alice.timeTriggeredPass()
            bob.timeTriggeredPass()
            assertTrue("the world wrote something to scan", checkNotNull(bob.databaseFile).length() > 0)
            assertTrue("the sealed body is in the file", fileHolds(bob, bodyEnv))

            // SWEEP is driven directly for this one assertion, rather than through a pass: §10.9
            // point 3 asks for "the WAL is 0 bytes", and the rest of a pass — OUTCOME, the bundle
            // claims, RECV — writes to the log again after the checkpoint. What the rule is about
            // is that the pages SWEEP freed leave the log, and that is this instant.
            world.advanceTo(deadline + minute)
            val report = bob.sweeper.sweep()
            assertTrue("the sweep deleted something", report.rows > 0)
            assertTrue("and the log was truncated (ME-10, ME-11)", report.checkpointed)
            assertEquals(
                "the write-ahead log is empty",
                0L,
                checkNotNull(bob.walFile).length(),
            )

            assertEquals(0, rowsOf(bob, messageId))
            assertFalseWithReason("the sealed body survived the sweep", fileHolds(bob, bodyEnv))
            assertFalseWithReason("the message id survived the sweep", fileHolds(bob, messageId))
            assertFalseWithReason(
                "the plaintext canary is in the bytes",
                fileHolds(bob, CANARY.toByteArray(Charsets.UTF_8)),
            )
        }
    }

    // ----------------------------------------------------------------- the wake

    /**
     * §10.7 triggers 1 and 5: every pass ends by moving the wake to the next due minute, and
     * **cancels** it — null — when nothing is pending.
     *
     * The cancel is a rule: an alarm left standing is an expiry minute a rooted examiner reads out
     * of the system's alarm table (L7-D7), and §10.7 says "cancelled when nothing is pending and
     * at wipe".
     */
    @Test
    fun everyPassMovesTheWakeAndTheLastOneCancelsIt() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            val (contactB, _) = establishBothWays(world)
            assertEquals(SendResult.QUEUED, alice.engine.setTimer(contactB, Timer.HOUR_1))
            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, CANARY, null))
            alice.timeTriggeredPass()

            val id = idOfText(alice, contactB, CANARY)
            val expireAt = checkNotNull(columnById(alice, id, "expire_at_minute"))
            assertEquals(
                "the delay to the next deadline, which is this message's",
                expireAt - alice.clock.now,
                alice.wakes.last,
            )

            // Past every message deadline of the world — the two establishment messages carry the
            // default 7-day timer. One deadline is left: A never opened a pair envelope under its
            // own root (B never wrote after receiving it), so its `prov_env` goes at
            // `prov_anchor_minute + 119 d` (§22.8.5 rule 4), and the wake is for that minute.
            world.advanceTo(expireAt + 8 * day)
            alice.timeTriggeredPass()
            assertEquals(0, count(alice, "SELECT count(*) FROM dm_message"))
            var provErase: Long? = null
            alice.sql.query("SELECT min(prov_erase_minute) FROM olm_session") { r ->
                if (!r.isNull(0)) provErase = r.long(0)
            }
            val erase = checkNotNull(provErase) { "the anchor bounds A's prov_env" }
            assertEquals("the one deadline left is prov_env's", erase - alice.clock.now, alice.wakes.last)

            // Past that too: nothing at all is pending and the wake is a cancel.
            world.advanceTo(erase)
            alice.timeTriggeredPass()
            assertEquals(0, count(alice, "SELECT count(*) FROM olm_session WHERE prov_env IS NOT NULL"))
            assertNull("nothing is pending, so the alarm is cancelled", alice.wakes.last)
            assertTrue("and a wake was asked for on every pass", alice.wakes.requested.size >= 4)
        }
    }

    /**
     * **R-T7 and §10.9 point 4, on the wake itself**: a clock stepped back one day does not delay
     * a deletion.
     *
     * This is the case the S9 review found open. `Sweeper.nextWake` already answered the right
     * *minute* — every deadline it considers is compared against `now_e` — but the two
     * implementations of the port subtracted their own wall clock from it, so a device whose clock
     * had been moved back a day scheduled a row due in an hour for 25 hours' time and the message
     * outlived its timer by a day. Nothing in the suite could see it: both worlds record the
     * minute and never convert it, and `ExpiryTimer` and `ExpiryAlarm` are wired to a process only
     * from S12. The delay is now measured where `now_e` is known, and this is the assertion that
     * pins it.
     */
    @Test
    fun aClockSteppedBackDoesNotDelayTheWake() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            val (contactB, _) = establishBothWays(world)
            assertEquals(SendResult.QUEUED, alice.engine.setTimer(contactB, Timer.HOUR_1))
            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, CANARY, null))
            alice.timeTriggeredPass()
            val expireAt = checkNotNull(
                columnById(alice, idOfText(alice, contactB, CANARY), "expire_at_minute"),
            )
            val honest = checkNotNull(alice.wakes.last)

            // The sweep just above fixed `dm_self.expiry_clock_minute` at this minute. Now the
            // user — or NTP, or a reboot — moves the wall clock back a day.
            alice.clock.now -= day
            alice.timeTriggeredPass()

            assertEquals(
                "the deadline itself did not move",
                expireAt,
                columnById(alice, idOfText(alice, contactB, CANARY), "expire_at_minute"),
            )
            assertEquals(
                "and neither did the delay: a day on the wall clock is not a day of survival",
                honest,
                alice.wakes.last,
            )
            assertTrue(
                "a wall-clock subtraction would have asked for a day more",
                checkNotNull(alice.wakes.last) < day,
            )
        }
    }

    // ------------------------------------------------------------ timer versions

    /**
     * R-T9's first case (§10.5): a **greater** version is adopted from any L0, so a TIMER_SET
     * that never arrived heals implicitly at the next ordinary message.
     */
    @Test
    fun aLostTimerSetHealsAtTheNextMessage() {
        requireNative()
        DmWorld().use { world ->
            val bob = world.bob
            val (contactB, _) = establishBothWays(world)

            assertEquals(SendResult.QUEUED, world.alice.engine.setTimer(contactB, Timer.HOUR_1))
            assertEquals(SendResult.QUEUED, world.alice.engine.send(contactB, "after the change", null))
            world.deliver()
            bob.hintPass()
            assertEquals(Timer.HOUR_1.code.toLong(), timerOf(bob))
            assertTrue("a version was adopted", timerVersionOf(bob) > 0)
        }
    }

    /**
     * R-T9's second case (§10.5): a **lower** version changes nothing, so a delayed message
     * cannot lengthen a timer that has already been shortened.
     *
     * The S9 review found this case named in a test's title and never executed. It is written
     * here as the situation that really produces it — two sides acting at once — rather than as a
     * replay, because a replay is refused one rule earlier by R1's `(namespace, hash)` tombstone
     * and would prove nothing about R-T9: Alice's message is already in flight, carrying the
     * version she had, when Bob shortens the timer on his own device. What must not happen is
     * that her message pushes Bob's conversation back to 7 days.
     *
     * The rule is kept **twice** and this test is what shows the path reaches both: `ReceiveStep`
     * adopts only on a greater or an equal version, and `ContactStore.adoptTimer` writes under
     * `timer_version <= ?`, which is the invariant `dm_conversation_timer` names. Either one alone
     * refuses the message below, so a mutant in one of them is masked by the other — that is the
     * point of having two, and it is why this test fails only when both are broken.
     */
    @Test
    fun aMessageAtAStaleVersionDoesNotLengthenTheTimer() {
        requireNative()
        DmWorld().use { world ->
            val bob = world.bob
            val (contactB, contactA) = establishBothWays(world)
            assertEquals(Timer.DAYS_7.code.toLong(), timerOf(bob))

            // In flight at Alice's version, which is still 0.
            assertEquals(SendResult.QUEUED, world.alice.engine.send(contactB, "in flight", null))
            // Bob shortens the timer while it travels: his version is now 1.
            assertEquals(SendResult.QUEUED, bob.engine.setTimer(contactA, Timer.MIN_5))
            assertEquals(1L, timerVersionOf(bob))

            world.deliverBetween(world.alice, bob)
            bob.hintPass()

            assertEquals(
                "a lower version changes nothing: the 5-minute timer stands",
                Timer.MIN_5.code.toLong(),
                timerOf(bob),
            )
            assertEquals("and the version did not move", 1L, timerVersionOf(bob))
            assertEquals(
                "the message itself is still shown — an ignored version is not a dropped message",
                "in flight",
                bob.engine.conversation(contactA, 50, null).first { it.text == "in flight" }.text,
            )
        }
    }

    /**
     * R-T9's third case (§10.5, RE §8.2): **equal** versions with different codes converge on the
     * **shorter** timer, in one exchange and with no round trip.
     *
     * This is the tie-break Signal's `expireTimerVersion` leaves open, and the whole point of it
     * is two devices acting at the same instant — so the test makes two real `setTimer` calls at
     * the same version and delivers both, rather than writing one side's column by hand, which is
     * what it did before the S9 review. Both sides must land on the same code without either of
     * them sending again.
     */
    @Test
    fun twoSimultaneousTimerSetsConvergeOnTheShorterOne() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            val bob = world.bob
            val (contactB, contactA) = establishBothWays(world)

            assertEquals(SendResult.QUEUED, alice.engine.setTimer(contactB, Timer.HOUR_1))
            assertEquals(SendResult.QUEUED, bob.engine.setTimer(contactA, Timer.DAY_1))
            assertEquals("the same version on both sides", timerVersionOf(alice), timerVersionOf(bob))

            world.deliver()
            alice.hintPass()
            bob.hintPass()

            assertEquals("Alice keeps the shorter one she already had", Timer.HOUR_1.code.toLong(), timerOf(alice))
            assertEquals("Bob takes the shorter one", Timer.HOUR_1.code.toLong(), timerOf(bob))
            assertEquals("and neither version moved", timerVersionOf(alice), timerVersionOf(bob))
        }
    }

    /**
     * The same tie-break with **off = ∞** on one side (§10.5): a timer that is off is longer than
     * every real one, so the side that turned it off adopts, and the side that set a real timer
     * keeps it. An incoming `off` never wins at an equal version.
     */
    @Test
    fun atAnEqualVersionOffIsLongerThanEveryTimer() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            val bob = world.bob
            val (contactB, contactA) = establishBothWays(world)

            assertEquals(SendResult.QUEUED, alice.engine.setTimer(contactB, Timer.OFF))
            assertEquals(SendResult.QUEUED, bob.engine.setTimer(contactA, Timer.HOUR_1))

            world.deliver()
            alice.hintPass()
            bob.hintPass()

            assertEquals("off is ∞, so Alice adopts the hour", Timer.HOUR_1.code.toLong(), timerOf(alice))
            assertEquals("and Bob keeps it", Timer.HOUR_1.code.toLong(), timerOf(bob))
        }
    }

    /**
     * R-T3 (§10.1) and mutant **ME-14**: a TIMER_SET travels in the **larger** of the old and the
     * new bucket, so a change from 7 days to 1 hour still reaches a recipient offline for more
     * than an hour.
     */
    @Test
    fun aTimerSetTravelsInTheLargerBucket() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            val (contactB, _) = establishBothWays(world)
            assertEquals(SendResult.QUEUED, alice.engine.setTimer(contactB, Timer.HOUR_1))
            assertEquals(
                "7 d, the old bucket, not the new 1 h one (ME-14)",
                7 * day,
                lastTtl(alice),
            )
            // And an ordinary message afterwards uses the conversation's own bucket (R-T2).
            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, CANARY, null))
            assertEquals(hour, lastTtl(alice))
        }
    }

    // ---------------------------------------------------------------- helpers

    private companion object {
        /** The plaintext the physical scan looks for; long and unique enough not to occur by luck. */
        const val CANARY = "ghost-t25-canary-0f1e2d3c4b5a69788796a5b4c3d2e1f0"
    }

    private fun assertFalseWithReason(reason: String, value: Boolean) {
        org.junit.Assert.assertFalse(reason, value)
    }

    private fun ceilMinute(seconds: Long): Long = -Math.floorDiv(-seconds, minute) * minute

    private fun ceilHour(seconds: Long): Long = -Math.floorDiv(-seconds, hour) * hour

    private fun count(device: DmDevice, sql: String, args: List<Any?> = emptyList()): Int {
        var out = 0
        device.sql.query(sql, args) { out = it.long(0).toInt() }
        return out
    }

    /**
     * Every assertion about what SWEEP took is **per id**, never over the whole table.
     *
     * The two establishment messages of `establishBothWays` carry the conversation's default
     * 7-day timer and are still live when a 1-hour or 5-minute message has gone — which is
     * §10.5's own rule ("a message is always deleted by **its own** `timer_code`, whatever the
     * conversation timer is now"), and a table-wide count would either hide it or contradict it.
     */
    private fun rowsOf(device: DmDevice, id: ByteArray): Int =
        count(device, "SELECT count(*) FROM dm_message WHERE message_id = ?", listOf(id))

    private fun itemsOf(device: DmDevice, id: ByteArray): Int =
        count(device, "SELECT count(*) FROM dm_outbound_item WHERE item_id = ?", listOf(id))

    private fun opsOf(device: DmDevice, id: ByteArray): Int =
        count(device, "SELECT count(*) FROM dm_outbound_op WHERE item_id = ?", listOf(id))

    private fun timerOf(device: DmDevice): Long {
        var out = -1L
        device.sql.query("SELECT timer_code FROM dm_conversation") { out = it.long(0) }
        return out
    }

    private fun timerVersionOf(device: DmDevice): Long {
        var out = -1L
        device.sql.query("SELECT timer_version FROM dm_conversation") { out = it.long(0) }
        return out
    }

    /** The TTL of the last blob this device enqueued (§10.1's table). */
    private fun lastTtl(device: DmDevice): Long {
        var out = -1L
        device.sql.query("SELECT ttl_seconds FROM outbox_op ORDER BY rowid DESC LIMIT 1") {
            out = it.long(0)
        }
        return out
    }

    /**
     * The id of the message whose decrypted text is [text], read **through the facade** — the test
     * holds no content key, and `body_env` is sealed under one (§13.8).
     *
     * It must be called while the row is still live, because the facade's read carries the expiry
     * filter of §10.7 point 4 and a message past its deadline is invisible there by design. Every
     * assertion about what expired therefore captures the id first and then reads the columns by
     * it, which is also the shape of the failure this avoids: a test that looked the message up
     * again after the bound would find nothing and pass for the wrong reason.
     */
    private fun idOfText(device: DmDevice, contact: ContactId, text: String): ByteArray =
        device.engine.conversation(contact, 50, null)
            .first { it.text == text }
            .id
            .toByteArray()

    /** One time column of a row, by id, with no expiry filter: this is the oracle, not a read path. */
    private fun columnById(device: DmDevice, id: ByteArray, column: String): Long? {
        var out: Long? = null
        device.sql.query(
            "SELECT $column FROM dm_message WHERE message_id = ?",
            listOf(id),
        ) { out = if (it.isNull(0)) null else it.long(0) }
        return out
    }

    private fun bodyEnvOf(device: DmDevice, id: ByteArray): ByteArray {
        var out: ByteArray? = null
        device.sql.query("SELECT body_env FROM dm_message WHERE message_id = ?", listOf(id)) {
            out = it.blob(0)
        }
        return checkNotNull(out) { "no body_env" }
    }

    /** Whether the raw database file or its write-ahead log holds [needle] (§10.9 point 2). */
    private fun fileHolds(device: DmDevice, needle: ByteArray): Boolean {
        val files = listOfNotNull(device.databaseFile, device.walFile).filter { it.isFile }
        check(files.isNotEmpty()) { "the world is in memory; pass a databaseDirectory" }
        return files.any { contains(it.readBytes(), needle) }
    }

    private fun contains(haystack: ByteArray, needle: ByteArray): Boolean {
        if (needle.isEmpty() || needle.size > haystack.size) return false
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) if (haystack[i + j] != needle[j]) continue@outer
            return true
        }
        return false
    }

    // The flow helpers, in the shape the other DM suites use.

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

    private fun introduce(world: DmWorld): ContactId {
        val contactB = startFetching(world)
        world.deliver()
        world.alice.timeTriggeredPass()
        world.advanceTo(world.alice.clock.now + 3 * minute)
        world.alice.timeTriggeredPass()
        return contactB
    }

    private fun establishBothWays(world: DmWorld): Pair<ContactId, ContactId> {
        val contactB = introduce(world)
        world.deliver()
        world.bob.hintPass()
        val contactA = world.bob.engine.contacts().single().id
        assertTrue(world.bob.engine.acceptRequest(contactA))
        assertEquals(SendResult.QUEUED, world.bob.engine.send(contactA, "hi back", null))
        world.deliver()
        world.alice.hintPass()
        assertNotNull(world.alice.engine.contacts().single())
        return contactB to contactA
    }
}
