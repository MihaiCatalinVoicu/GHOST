package org.ghost.messaging

import org.ghost.messaging.api.AddContactResult
import org.ghost.messaging.api.CardSource
import org.ghost.messaging.api.ContactId
import org.ghost.messaging.api.MessageState
import org.ghost.messaging.api.SendResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * **OUTCOME** and the automatic **RESEND** of §7.5, §21.8 point 1 and G-7 / C-15.
 *
 * The S7 review found that nothing exercised either: `DmFlowTest` drives sends and receipts, and
 * every op in those worlds stays `pending` for ever, so the resend bound, the once-only release and
 * the retained-blob rule were argued in comments and never run. This file drives the four outcomes
 * by setting the Phase 7 columns the outbox's own engine would set — the engine itself is Phase 7's
 * and is proved by `sync-exit-gate`; what is under test here is what `:messaging` does with the
 * result.
 */
class DmOutcomeTest {

    private fun requireNative() {
        assumeTrue(
            "set -Dghost.dm.native to the ghost-dm-host library",
            DmWorld.nativeAvailable(),
        )
    }

    /**
     * SENT is terminal: the message is `sent`, the retained blob goes and so does the item's stored
     * L0 (§21.8 point 1 — `l0_env` becomes NULL at SENT, DEGRADED or INDETERMINATE, and only a
     * FAILED item keeps it for the user retry).
     */
    @Test
    fun aSentOutcomeIsTerminalAndTakesTheRetainedBytesWithIt() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            val contactB = introduce(world)
            assertEquals(1, itemOps(alice))

            decide(alice, "sent")
            assertEquals(1, alice.outcomeStep.run())

            assertEquals(
                listOf(MessageState.SENT),
                alice.engine.conversation(contactB, 10, null).map { it.state },
            )
            assertEquals("the retained blob goes", 0, retainedItemBlobs(alice))
            assertEquals("and so does the stored L0", 0, storedL0s(alice))
        }
    }

    /**
     * FAILED keeps the L0, because §7.5's user retry re-encrypts exactly those bytes; the blob goes,
     * because a FAILED op is never resent with identical bytes.
     */
    @Test
    fun aFailedOutcomeKeepsTheL0ForTheUserRetry() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            val contactB = introduce(world)

            decide(alice, "failed")
            assertEquals(1, alice.outcomeStep.run())

            assertEquals(
                listOf(MessageState.FAILED),
                alice.engine.conversation(contactB, 10, null).map { it.state },
            )
            assertEquals("the L0 stays until the deadline", 1, storedL0s(alice))
            assertEquals("the identical bytes do not", 0, retainedItemBlobs(alice))
        }
    }

    /**
     * INDETERMINATE resends the **identical bytes** as a new op, at most twice (G-7, C-15), and
     * then ends the item `indeterminate`.
     *
     * The bytes are the retained ones and never a re-encryption: a second ratchet step would cost
     * a message key and make the recipient dedup at D3 instead of D1 (mutant MC-3). Each round here
     * is one decided outcome, so the `resend_count < 2` bound is exercised at its edge rather than
     * asserted from the constant.
     */
    @Test
    fun anIndeterminateOutcomeResendsTheIdenticalBytesAtMostTwice() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            val contactB = introduce(world)
            val bytes = itemOpBlobs(alice).single()

            decide(alice, "indeterminate")
            assertEquals(1, alice.outcomeStep.run())
            assertEquals("the first resend carries the same bytes", listOf(bytes), itemOpBlobs(alice))
            assertEquals(listOf(1L), resendCounts(alice))

            decide(alice, "indeterminate")
            assertEquals(1, alice.outcomeStep.run())
            assertEquals(listOf(bytes), itemOpBlobs(alice))
            assertEquals(listOf(2L), resendCounts(alice))

            // The third is past the bound: no new op, and the item is decided.
            decide(alice, "indeterminate")
            assertEquals(1, alice.outcomeStep.run())
            assertEquals("two resends and no more", 0, retainedItemBlobs(alice))
            assertEquals(
                listOf(MessageState.INDETERMINATE),
                alice.engine.conversation(contactB, 10, null).map { it.state },
            )
        }
    }

    /**
     * §7.8: `Outbox.release` answers true exactly once per operation, so a second pass over the
     * same outcome applies nothing — the property the whole "release and effect in one transaction"
     * argument rests on, and the one a crash between two passes would otherwise break.
     */
    @Test
    fun anOutcomeIsAppliedOnceHoweverManyPassesRun() {
        requireNative()
        DmWorld().use { world ->
            val alice = world.alice
            introduce(world)

            decide(alice, "indeterminate")
            assertEquals(1, alice.outcomeStep.run())
            val opsAfterFirst = itemOps(alice)
            assertEquals("the resend happened", 2, opsAfterFirst)

            assertEquals("nothing is left to release", 0, alice.outcomeStep.run())
            assertEquals("and no second resend", opsAfterFirst, itemOps(alice))
        }
    }

    // ---------------------------------------------------------------- helpers

    /** A adds B's card, sends once, and the establishment enqueues the intro envelope. */
    private fun introduce(world: DmWorld): ContactId {
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
        assertTrue("the message is on its way", itemOps(world.alice) > 0)
        return contactB
    }

    /**
     * What the Phase 7 outbox engine writes when an operation is decided: the outcome, a wiped
     * ciphertext, and — for INDETERMINATE — the `copy_hour` that `resendNotAfter` is measured from.
     *
     * The wipe matters and is not decoration: `OutboxStore.enqueue` lets identical bytes into a
     * namespace again only once the earlier op is released **and** its ciphertext is gone, which is
     * what makes the identical-bytes resend of §7.5 legal at all.
     */
    private fun decide(device: DmDevice, outcome: String) {
        val hour = device.clock.nowEpochSeconds().let { it - it % 3600 }
        // The deliveries settle first, and they have to: `outbox_op_payload` refuses to wipe a
        // ciphertext while any delivery of the op is still `pending`, `wait_capability`, `acked` or
        // in flight — "wiped only after the last possible store". A `copy_hour` comes with them,
        // because `outcomes` derives the INDETERMINATE resend bound from the earliest one, and an
        // op without it would carry no bound at all and make that case pass for the wrong reason.
        device.sql.exec(
            "UPDATE outbox_delivery SET state = 'verified', inflight = 0, copy_hour = ? " +
                "WHERE state = 'pending' AND operation_id IN (" +
                "SELECT o.operation_id FROM outbox_op o JOIN sync_namespace n " +
                "ON n.namespace_id = o.namespace_id WHERE o.outcome = 'pending' AND n.consumer = 'dm')",
            listOf(hour),
        )
        device.sql.exec(
            "UPDATE outbox_op SET outcome = ?, ciphertext = NULL WHERE outcome = 'pending' " +
                "AND namespace_id IN (SELECT namespace_id FROM sync_namespace WHERE consumer = 'dm')",
            listOf(outcome),
        )
    }

    private fun countWhere(device: DmDevice, sql: String): Int {
        var count = 0
        device.sql.query(sql) { count = it.long(0).toInt() }
        return count
    }

    private fun itemOps(device: DmDevice): Int =
        countWhere(device, "SELECT count(*) FROM dm_outbound_op WHERE purpose = 'item'")

    private fun retainedItemBlobs(device: DmDevice): Int =
        countWhere(
            device,
            "SELECT count(*) FROM dm_outbound_op WHERE purpose = 'item' AND blob IS NOT NULL",
        )

    private fun storedL0s(device: DmDevice): Int =
        countWhere(device, "SELECT count(*) FROM dm_outbound_item WHERE l0_env IS NOT NULL")

    /** The bytes of every item op that still holds them, so a resend can be compared to them. */
    private fun itemOpBlobs(device: DmDevice): List<String> {
        val out = ArrayList<String>()
        device.sql.query(
            "SELECT hex(blob) FROM dm_outbound_op WHERE purpose = 'item' AND blob IS NOT NULL " +
                "ORDER BY operation_id",
        ) { out += it.string(0) }
        return out
    }

    private fun resendCounts(device: DmDevice): List<Long> {
        val out = ArrayList<Long>()
        device.sql.query(
            "SELECT resend_count FROM dm_outbound_op WHERE purpose = 'item' AND blob IS NOT NULL " +
                "ORDER BY operation_id",
        ) { out += it.long(0) }
        return out
    }
}
