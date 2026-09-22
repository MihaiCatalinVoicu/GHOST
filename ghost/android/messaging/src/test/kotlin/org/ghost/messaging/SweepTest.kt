package org.ghost.messaging

import org.ghost.messaging.engine.DmTime
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * **SWEEP, table by table** (Phase 9 design §7.2's SWEEP row, §10.6, §10.7, §21.3 point 5,
 * §21.12 point 3), over a real migrated v5 database with rows written straight into it.
 *
 * `EphemeralTest` drives the same step from the other end — two devices, the real library, a
 * message that goes out, arrives, is displayed and disappears — which is what §10.9's bounds are
 * about. This file is the half a world cannot reach: a generation two months past its retention
 * with a held row still naming it, a `prov_env` past its erase minute, a request past its day, a
 * clock stepped backwards, and a checkpoint a reader holds. Building each of those through a live
 * conversation would take months of virtual time and a fault injector; writing the row is exact.
 *
 * Every assertion names the rule it comes from, because SWEEP is a list of deletions and a list is
 * exactly the shape in which a missing line is invisible.
 */
class SweepTest {

    private val day = 86_400L
    private val hour = 3_600L
    private val minute = 60L

    // ------------------------------------------------------------------ messages

    /**
     * §10.6's first two rows: the message goes, and its reactions, items, ops, retained blobs and
     * pending sends go with it — by `ON DELETE CASCADE`, which is the mechanism the design names.
     *
     * The retained blob is the one that matters for T25's physical bound: it is the E2E ciphertext
     * `dm_outbound_op.blob` holds so an INDETERMINATE resend can repeat identical bytes, and mutant
     * **ME-20** is exactly "the retained blob survives its message's deletion".
     */
    @Test
    fun anExpiredMessageTakesItsReactionsItemsOpsAndPendingSendWithIt() = OwnerWorld().use { world ->
        world.activate()
        val now = world.clock.now
        world.seedConversation()
        world.seedMessage(id = 0xE1, deleteAt = DmTime.floorMinute(now) - minute, withItem = true)
        world.seedMessage(id = 0x11, deleteAt = DmTime.floorMinute(now) + hour, withItem = true)

        assertEquals(2, world.count("SELECT count(*) FROM dm_message"))
        assertEquals(2, world.count("SELECT count(*) FROM dm_reaction"))
        assertEquals(2, world.count("SELECT count(*) FROM dm_outbound_item"))
        // ACTIVATE left a bundle op of its own, which is not an item's and is not swept here.
        assertEquals(2, world.count("SELECT count(*) FROM dm_outbound_op WHERE purpose = 'item'"))
        assertEquals(2, world.count("SELECT count(*) FROM dm_pending_send"))

        val report = world.sweeper.sweep()

        assertEquals("one message, and only the expired one", 1, report.messages)
        assertEquals(1, world.count("SELECT count(*) FROM dm_message"))
        assertEquals("the reaction cascaded", 1, world.count("SELECT count(*) FROM dm_reaction"))
        assertEquals("the item cascaded", 1, world.count("SELECT count(*) FROM dm_outbound_item"))
        assertEquals(
            "the op and its retained blob cascaded (ME-20)",
            1,
            world.count("SELECT count(*) FROM dm_outbound_op WHERE purpose = 'item'"),
        )
        assertEquals("the pending send cascaded", 1, world.count("SELECT count(*) FROM dm_pending_send"))
        assertEquals(
            "the live message is untouched",
            1,
            world.count("SELECT count(*) FROM dm_message WHERE message_id = X'${"11".repeat(16)}'"),
        )
    }

    /**
     * §10.6's "at most 500 per transaction" bounds the **transaction**, and one sweep drains what
     * a transaction cannot.
     *
     * The reason is the wake, not throughput. Every "next wake" query is strictly in the future
     * (`> now_e`), because a wake for a minute the sweep has already passed would be an alarm that
     * fires and finds nothing to do; so rows left over from a full batch — whose deadlines are all
     * in the **past** — would have nothing scheduled to come back for them, and a device back
     * after a long absence would delete 500 messages and then wait for an unrelated trigger to
     * take the next 500.
     */
    @Test
    fun oneSweepDrainsMoreThanOneTransactionWorthOfExpiredRows() = OwnerWorld().use { world ->
        world.activate()
        world.seedConversation()
        val expired = DmTime.floorMinute(world.clock.now) - minute
        val count = org.ghost.messaging.engine.Sweeper.BATCH + 3
        for (i in 0 until count) world.seedMessage(id = 0x10_000 + i, deleteAt = expired)
        assertEquals(count, world.count("SELECT count(*) FROM dm_message"))

        val report = world.sweeper.sweep()
        assertEquals("every expired row, not the first batch", count, report.messages)
        assertEquals(0, world.count("SELECT count(*) FROM dm_message"))
    }

    /** §10.6: `MediaPort.onMessagesDeleted(tx, ids)` is given exactly the ids that then disappear. */
    @Test
    fun theMediaPortIsToldTheIdsInsideTheSameTransaction() = OwnerWorld().use { world ->
        world.activate()
        world.seedConversation()
        val expired = DmTime.floorMinute(world.clock.now) - minute
        world.seedMessage(id = 0xE1, deleteAt = expired)
        world.seedMessage(id = 0xE2, deleteAt = expired)
        world.seedMessage(id = 0x11, deleteAt = expired + day)

        world.sweeper.sweep()

        assertEquals(
            listOf("e1".repeat(16), "e2".repeat(16)),
            world.media.allIds.sorted(),
        )
    }

    // ---------------------------------------------------------------- held rows

    /**
     * §22.13 item 10, which named this slice: **a generation past `delete_after_day` is not erased
     * while a live `dm_held` row names it.**
     *
     * The reference is code and not schema — `dm_held.gen_id` carries a range CHECK and no
     * `REFERENCES` (§22.10 item 1) — so the `NOT EXISTS` in `OwnerStore.erasableGenerations` is the
     * whole of the rule. Without it the user's decision to release a hold answers
     * `drop(unknown_generation)` for every row that named it: the decision loses exactly the
     * messages it was taken to recover.
     *
     * The case needs a hold that outlives a generation, which the numbers make possible: the hold
     * bound is ≤ 30 d + 1 h from the consume minute and the generation retention is 91 days past
     * supersession, so a hold taken near the end of the window straddles it.
     */
    @Test
    fun aGenerationIsKeptWhileALiveHeldRowNamesIt() = OwnerWorld().use { world ->
        world.activate()
        world.seedContact()
        val now = DmTime.floorMinute(world.clock.now)
        world.seedGeneration(genId = 7, deleteAfterDay = DmTime.day(now) - 1)
        world.seedHeld(heldId = 0xA1, genId = 7, holdUntil = now + 10 * day)

        world.sweeper.sweep()
        assertEquals(
            "the generation the hold names survives its own retention",
            1,
            world.count("SELECT count(*) FROM olm_prekey_gen WHERE gen_id = 7"),
        )

        // The hold expires; the same sweep that deletes it erases the generation, because held
        // rows are deleted **first** (§10.6's order).
        world.clock.now = now + 11 * day
        val report = world.sweeper.sweep()
        assertEquals("the held row went", 1, report.held)
        assertEquals("and the generation with it", 1, report.generations)
        assertEquals(0, world.count("SELECT count(*) FROM olm_prekey_gen WHERE gen_id = 7"))
        assertEquals(0, world.count("SELECT count(*) FROM dm_held"))
    }

    /** §5.4: a generation whose retention has not passed is kept whether or not a hold names it. */
    @Test
    fun aGenerationInsideItsRetentionIsKept() = OwnerWorld().use { world ->
        world.activate()
        world.seedGeneration(genId = 9, deleteAfterDay = DmTime.day(world.clock.now) + 5)
        world.sweeper.sweep()
        assertEquals(1, world.count("SELECT count(*) FROM olm_prekey_gen WHERE gen_id = 9"))
    }

    // ----------------------------------------------------------- the other rows

    /** §10.6: `dm_seen` tags past `until_day` (D3's window, §21.10 point 3). */
    @Test
    fun seenTagsGoAtTheirDay() = OwnerWorld().use { world ->
        world.activate()
        val today = DmTime.day(world.clock.now)
        world.seedSeen(tag = 0x01, untilDay = ceil7(today - 14))
        world.seedSeen(tag = 0x02, untilDay = ceil7(today + 30))

        assertEquals(1, world.sweeper.sweep().seenTags)
        assertEquals(1, world.count("SELECT count(*) FROM dm_seen"))
    }

    /** §12.3 and §10.6: a request past `request_until_day` takes its contact and its rows. */
    @Test
    fun anExpiredRequestTakesItsContact() = OwnerWorld().use { world ->
        world.activate()
        world.seedContact(trust = "request", requestUntilDay = DmTime.day(world.clock.now) - 1)

        assertEquals(1, world.sweeper.sweep().requests)
        assertEquals(0, world.count("SELECT count(*) FROM dm_contact"))
    }

    /** §8.7 and §10.6: a `previous` session is deleted at its `retire_day`, and not before. */
    @Test
    fun aRetiredSessionGoesAtItsDay() = OwnerWorld().use { world ->
        world.activate()
        world.seedContact()
        world.seedSession(slot = "previous", retireDay = DmTime.day(world.clock.now) + 2)

        assertEquals("not yet", 0, world.sweeper.sweep().retiredSessions)
        world.clock.now += 3 * day
        assertEquals(1, world.sweeper.sweep().retiredSessions)
        assertEquals(0, world.count("SELECT count(*) FROM olm_session"))
    }

    /**
     * §22.8.5 rule 4 and §10.6: `prov_env` past `prov_erase_minute` goes, and the **session stays**.
     *
     * The two columns go together because the schema makes them: `CHECK (prov_erase_minute IS NULL
     * OR prov_env IS NOT NULL)` refuses a row that kept the minute without the bytes.
     */
    @Test
    fun theProvisionalSeedIsErasedAndTheSessionKept() = OwnerWorld().use { world ->
        world.activate()
        world.seedContact()
        val eraseAt = DmTime.floorMinute(world.clock.now) - minute
        world.seedSession(slot = "current", provEraseMinute = eraseAt)

        assertEquals(1, world.sweeper.sweep().provisional)
        assertEquals("the session is a live ratchet and stays", 1, world.count("SELECT count(*) FROM olm_session"))
        assertEquals(0, world.count("SELECT count(*) FROM olm_session WHERE prov_env IS NOT NULL"))
        assertEquals(0, world.count("SELECT count(*) FROM olm_session WHERE prov_erase_minute IS NOT NULL"))
    }

    /** §22.8.6 rule 2: a peer X-Wing key is usable while `now < start(b + 5)`, and swept after. */
    @Test
    fun aPeerXWingKeyGoesOnceItsWeekCanNoLongerBeEncapsulatedTo() = OwnerWorld().use { world ->
        world.activate()
        world.seedContact()
        val week = DmTime.week(world.clock.now)
        world.seedPeerPq(genId = 1, bundleWeek = week - 5)
        world.seedPeerPq(genId = 2, bundleWeek = week - 4)

        assertEquals(1, world.sweeper.sweep().peerPq)
        assertEquals(
            listOf(2L),
            world.longs("SELECT gen_id FROM dm_peer_pq ORDER BY gen_id"),
        )
    }

    /**
     * §21.12 point 3: `Namespaces.remove` for each `dm_orphan_namespace` row, and the row is
     * deleted when it answers true.
     *
     * `ContactSteps` records the orphans of a blocked or deleted contact and removes nothing
     * (§22.12 item 13); this is the other half, and it is the whole of L7-D7's ≤ 7-day bound on
     * the `:sync` residue. `Sweeper.kt` is on gate G-DM2's `REMOVE_ONLY` list for exactly this
     * call and no other.
     */
    @Test
    fun anOrphanNamespaceIsRemovedFromSyncAndItsRowDeleted() = OwnerWorld().use { world ->
        world.activate()
        val namespace = ByteArray(32) { 0x7a }
        world.database.transaction { tx ->
            world.stores.namespaces.register(
                tx,
                org.ghost.sync.api.NamespaceId(namespace),
                org.ghost.sync.api.Consumer.PREKEYS,
                emptySet(),
                listen = true,
            )
        }
        world.sql.exec("INSERT INTO dm_orphan_namespace(namespace_id) VALUES (?)", listOf(namespace))
        assertEquals(
            1,
            world.count(
                "SELECT count(*) FROM sync_namespace WHERE namespace_id = ? AND listening = 1",
                listOf(namespace),
            ),
        )

        assertEquals(1, world.sweeper.sweep().namespaces)
        assertEquals("the record is discharged", 0, world.count("SELECT count(*) FROM dm_orphan_namespace"))
        assertEquals(
            "and `:sync` no longer listens on it",
            0,
            world.count(
                "SELECT count(*) FROM sync_namespace WHERE namespace_id = ? AND listening = 1",
                listOf(namespace),
            ),
        )
    }

    // --------------------------------------------------------- the expiry clock

    /**
     * R-T7 (§10.3): `now_e = max(floor_minute(wall), dm_self.expiry_clock_minute)`, every sweep
     * raises the stored half, and **a clock stepped backwards never delays a deletion** (mutant
     * **ME-17**).
     *
     * The shape matters. R-T7 protects what a sweep has already observed, not the future: a device
     * whose clock is set back an hour before it ever ran cannot know what it missed. What it
     * guarantees is that a row whose deadline is below a minute a sweep has already seen goes at
     * the next sweep, whatever the wall clock now says — which is the case a user who sets the
     * clock back to keep a message would create.
     */
    @Test
    fun aClockSteppedBackDoesNotDelayDeletion() = OwnerWorld().use { world ->
        world.activate()
        world.seedConversation()
        val observed = DmTime.floorMinute(world.clock.now)
        world.sweeper.sweep()
        assertEquals(observed, world.expiryClock())

        // A day back on the wall clock, and a message whose deadline is an hour from *that*.
        world.clock.now = observed - day
        world.seedMessage(id = 0xE1, deleteAt = DmTime.floorMinute(world.clock.now) + hour)
        assertTrue("the wall clock says it is fresh", world.clock.now + hour > world.clock.now)

        val report = world.sweeper.sweep()
        assertEquals("the expiry clock decided, not the wall clock", 1, report.messages)
        assertEquals("and it did not go backwards", observed, world.expiryClock())
    }

    // ------------------------------------------------------------- the checkpoint

    /**
     * §10.7 and mutants **ME-10** ("checkpoint result ignored") and **ME-11** ("no checkpoint").
     *
     * > require `busy = 0`, retry 3 times 100 ms apart, else keep `checkpoint_due` in memory and
     * > retry at the next sweep.
     *
     * Three facts in one sequence: a sweep that deleted rows checkpoints; a checkpoint a reader
     * held is **not forgotten** — the next sweep runs it again although it deleted nothing; and a
     * sweep with nothing freed and nothing owed does not run the pragma at all, so an idle device
     * does not write on every pass.
     */
    @Test
    fun aBusyCheckpointIsRetriedAtTheNextSweepAndAnIdleOneIsNotRun() = OwnerWorld().use { world ->
        world.activate()
        world.seedConversation()
        world.seedMessage(id = 0xE1, deleteAt = DmTime.floorMinute(world.clock.now) - minute)

        world.checkpoints.busy = true
        val first = world.sweeper.sweep()
        assertEquals(1, first.messages)
        assertEquals(1, world.checkpoints.calls)
        assertFalse("the reader held the log", first.checkpointed)

        world.checkpoints.busy = false
        val second = world.sweeper.sweep()
        assertEquals("nothing was left to delete", 0, second.rows)
        assertEquals("and the owed checkpoint ran anyway", 2, world.checkpoints.calls)
        assertTrue(second.checkpointed)

        val third = world.sweeper.sweep()
        assertEquals("nothing freed, nothing owed, no pragma", 2, world.checkpoints.calls)
        assertTrue(third.checkpointed)
    }

    // --------------------------------------------------------------- a full disk

    /**
     * §13.1, §21.12 point 1: `SQLITE_FULL` is a **state of the device**, not a bug — and SWEEP is
     * the first step of every actor pass (§13.7's order), so a full disk propagating out of it
     * would take `RECV`, `OUTCOME` and the bundle claims down with it.
     *
     * A device that cannot delete would then also stop receiving, which is the opposite of what a
     * disk-full device needs. SQLite rolls its own transaction back, so nothing partial commits;
     * the next sweep finds the same rows and takes them.
     *
     * The fault is injected at the media port, which is the one seam inside SWEEP's transaction a
     * Phase 11 implementation really writes through.
     */
    @Test
    fun aFullDiskLeavesTheRowsAndDoesNotEscapeTheSweep() = OwnerWorld().use { world ->
        world.activate()
        world.seedConversation()
        world.seedMessage(id = 0xE1, deleteAt = DmTime.floorMinute(world.clock.now) - minute)

        world.media.failStorageFull = true
        val failed = world.sweeper.sweep()
        assertEquals("nothing was deleted", 0, failed.rows)
        assertEquals("and nothing was committed", 1, world.count("SELECT count(*) FROM dm_message"))
        assertEquals("the expiry clock did not move either", 0L, world.expiryClock() % 60)

        world.media.failStorageFull = false
        assertEquals("the next sweep takes the same row", 1, world.sweeper.sweep().messages)
        assertEquals(0, world.count("SELECT count(*) FROM dm_message"))
    }

    // ------------------------------------------------------------------- the wake

    /**
     * §10.7 triggers 1 and 5, §21.9 rule 1: the wake is the **next** due minute, and null — the
     * cancel both the timer and the alarm take — when nothing is pending.
     *
     * Null is a rule and not tidiness: an alarm left standing is an expiry minute a rooted examiner
     * reads out of the system's alarm table (L7-D7).
     */
    @Test
    fun theWakeIsTheNextDeadlineAndNullWhenNothingIsPending() = OwnerWorld().use { world ->
        world.activate()
        world.seedConversation()
        assertNull("nothing is pending", world.sweeper.nextWakeMinute())

        val now = DmTime.floorMinute(world.clock.now)
        world.seedMessage(id = 0x11, deleteAt = now + 2 * hour)
        world.seedMessage(id = 0x12, deleteAt = now + hour)
        assertEquals(now + hour, world.sweeper.nextWakeMinute())

        // A held row due sooner wins: the wake is over every deadline the schema holds, not only
        // over `dm_message`.
        world.seedContact(contact = 0x33, identity = 0x44)
        world.seedHeld(heldId = 0xA1, genId = 1, holdUntil = now + 30 * minute, contact = 0x33)
        assertEquals(now + 30 * minute, world.sweeper.nextWakeMinute())

        world.clock.now = now + 3 * hour
        world.sweeper.sweep()
        assertNull("everything is gone, so the alarm is cancelled", world.sweeper.nextWakeMinute())
    }

    /** §7.2's "After commit: notification count", over the **live** rows only (§10.7 point 4). */
    @Test
    fun theUnreadCountIsOverLiveRowsAndReachesThePortOncePerChange() = OwnerWorld().use { world ->
        world.activate()
        world.seedConversation()
        val now = DmTime.floorMinute(world.clock.now)
        world.seedMessage(id = 0x11, deleteAt = now + hour, incoming = true)
        world.seedMessage(id = 0xE1, deleteAt = now - minute, incoming = true)
        assertEquals("the expired one is not counted before it is deleted", 1, world.sweeper.unreadCount())

        world.schedule.setNotificationPort(world.notifications)
        assertEquals(listOf(1), world.notifications.counts)
        world.schedule.afterCommit()
        assertEquals("unchanged, so nothing is posted again", listOf(1), world.notifications.counts)

        world.sweeper.sweep()
        world.schedule.afterCommit()
        assertEquals("still one live unread row", listOf(1), world.notifications.counts)

        world.clock.now = now + 2 * hour
        world.sweeper.sweep()
        world.schedule.afterCommit()
        assertEquals("and 0 is the cancel", listOf(1, 0), world.notifications.counts)
    }

    private fun ceil7(day: Long): Long = -Math.floorDiv(-day, 7L) * 7L
}
