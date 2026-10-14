package org.ghost.messaging

import org.ghost.crypto.bridge.DmCards
import org.ghost.messaging.engine.MediaOrphanSteps
import org.ghost.sync.api.CapabilitySource
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.NamespaceId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The `M_c` orphan rule (Phase 11 design §5.1) over a real migrated v8 database ([OwnerWorld]):
 * the three clauses that block the orphan, the recording (the upload rows go, the orphan row
 * comes), and the two wired producers — SWEEP's expired-message cascade and SWEEP's discharge of
 * the recorded row. The OUTCOME producer ([org.ghost.messaging.engine.OutcomeStep]) runs the same
 * [MediaOrphanSteps.recordIfOrphaned] this file drives directly; its kind-5 items arrive with
 * slice S5's sender pipeline, so the seam itself is pinned structurally and the rule's edges are
 * pinned here.
 */
class MediaOrphanStepsTest {

    private val week = 604_800L
    private val day = 86_400L
    private val hour = 3_600L
    private val weekOrigin = 345_600L
    private val now = weekStart(2_870) + 2 * day

    private fun weekStart(w: Long) = weekOrigin + week * w

    private fun floorMinute(t: Long) = Math.floorDiv(t, 60L) * 60L

    private fun ceilHour(t: Long) = -Math.floorDiv(-t, hour) * hour

    /** The ids the fixtures and the assertions share. */
    private class Fx(
        val contactId: ByteArray,
        val mediaNs: ByteArray,
        val objectId: ByteArray,
        val messageId: ByteArray,
        val itemId: ByteArray,
        val blobHash: ByteArray,
        val opId: ByteArray,
    )

    /**
     * A contact with a **real** `card_env` (so `M_c` is derivable from the card, as §5.1's
     * recording requires) and `M_c` registered `:sync`-side, LOCAL and never redeemed (§5.1). The
     * object, its descriptor item, fragments, blobs and the operation row are seeded by
     * [seedObject]; every test degrades exactly the clause it names.
     */
    private fun seedContact(world: OwnerWorld): Fx {
        world.clock.now = now
        world.activate()
        val self = world.contexts.get()!!
        val card = world.crypto.ownCard(0)!!.card
        val contactId = ByteArray(16) { 0x21 }
        val cardEnv = self.content.seal(world.random.bytes(12), contactId, card)
        world.sql.exec(
            "INSERT INTO dm_contact(contact_id, identity_pk, card_env, card_index, trust_state, " +
                "source, establishment) VALUES (?, ?, ?, 0, 'unverified', 'link', 'card_only')",
            listOf(contactId, ByteArray(32) { 0x22 }, cardEnv),
        )
        world.sql.exec(
            "INSERT INTO dm_conversation(conversation_id, contact_id) VALUES (?, ?)",
            listOf(ByteArray(16) { 0x23 }, contactId),
        )
        val derived = world.crypto.deriveCard(card, 0)
        assertTrue(derived is DmCards.DeriveResult.Ok)
        val mediaNs = (derived as DmCards.DeriveResult.Ok).values.mediaNamespace
        (derived as DmCards.DeriveResult.Ok).values.clearSecrets()
        world.database.transaction { tx ->
            world.stores.namespaces.register(
                tx,
                NamespaceId(mediaNs),
                Consumer.MEDIA,
                setOf(world.slots.first().relay),
                listen = false,
                capabilitySource = CapabilitySource.LOCAL,
            )
        }
        return Fx(
            contactId = contactId,
            mediaNs = mediaNs,
            objectId = world.messageId(0x41),
            messageId = world.messageId(0x42),
            itemId = world.messageId(0x43),
            blobHash = ByteArray(32) { 0x44 },
            opId = world.messageId(0x45),
        )
    }

    /**
     * One outgoing media object of [objectState] with its descriptor [itemState] (`sent` when
     * final), one bound fragment, its blob and — unless [opReleased] — an unreleased operation.
     * The upload's deadline and the item's deadline are separate knobs for the deadline edges.
     */
    private fun seedObject(
        world: OwnerWorld,
        fx: Fx,
        objectState: String,
        itemState: String,
        uploadDeadline: Long = ceilHour(now) + day,
        itemDeadline: Long = ceilHour(now) + day,
        opReleased: Boolean = true,
    ) {
        val expires = floorMinute(now) + week
        world.sql.exec(
            "INSERT INTO dm_message(message_id, conversation_id, direction, kind, author_minute, " +
                "sort_minute, minute_index, timer_code, body_env, state, expire_at_minute, " +
                "delete_at_minute) " +
                "VALUES (?, ?, 'out', 5, ?, ?, 0, 4, ?, 'sent', ?, ?)",
            listOf(
                fx.messageId,
                ByteArray(16) { 0x23 },
                floorMinute(now),
                floorMinute(now),
                ByteArray(60) { 0x51 },
                expires,
                expires,
            ),
        )
        world.sql.exec(
            "INSERT INTO dm_outbound_item(item_id, contact_id, message_ref, kind, control, l0_env, " +
                "deadline_hour, state, ttl_seconds) VALUES (?, ?, ?, 5, NULL, NULL, ?, ?, 604800)",
            listOf(fx.itemId, fx.contactId, fx.messageId, itemDeadline, itemState),
        )
        world.sql.exec(
            "INSERT INTO media_object(object_id, role, dest_id, kind, view_once, class_code, " +
                "manifest_hash, key_env, state, message_id, decode_failures, incomplete_after_hour) " +
                "VALUES (?, 'out', ?, 1, 0, 0, ?, ?, ?, ?, 0, NULL)",
            listOf(
                fx.objectId,
                fx.contactId,
                ByteArray(32) { 0x52 },
                ByteArray(60) { 0x53 },
                objectState,
                fx.messageId,
            ),
        )
        world.sql.exec(
            "INSERT INTO media_upload(object_id, namespace_id, ttl_seconds, deadline_hour, retry_gen) " +
                "VALUES (?, ?, 604800, ?, 0)",
            listOf(fx.objectId, fx.mediaNs, uploadDeadline),
        )
        world.sql.exec(
            "INSERT INTO media_blob(blob_hash, file_name, origin, retain_until_day) VALUES (?, ?, 'sealed', NULL)",
            listOf(fx.blobHash, ByteArray(16) { 0x54 }),
        )
        // The schema's first-state rule: an outgoing fragment starts `bound` and `unsent`
        // (`media_fragment_state`), and the walk to `sent` passes through `open`.
        world.sql.exec(
            "INSERT INTO media_fragment(object_id, ordinal, blob_hash, state, upload_state) " +
                "VALUES (?, 0, ?, 'bound', 'unsent')",
            listOf(fx.objectId, fx.blobHash),
        )
        if (objectState == "uploaded") {
            world.sql.exec(
                "UPDATE media_fragment SET upload_state = 'open' WHERE object_id = ? AND ordinal = 0",
                listOf(fx.objectId),
            )
            world.sql.exec(
                "UPDATE media_fragment SET upload_state = 'sent' WHERE object_id = ? AND ordinal = 0",
                listOf(fx.objectId),
            )
        }
        world.sql.exec(
            "INSERT INTO media_outbound_op(operation_id, object_id, ordinal, retry_gen, resend_count) " +
                "VALUES (?, ?, 0, 0, 0)",
            listOf(fx.opId, fx.objectId),
        )
        world.sql.exec(
            "INSERT INTO outbox_op(operation_id, namespace_id, blob_hash, ttl_seconds, " +
                "not_before_minute, required_operators, outcome, released) VALUES (?, ?, ?, 604800, ?, 2, ?, ?)",
            listOf(
                fx.opId,
                fx.mediaNs,
                ByteArray(32) { 0x55 },
                floorMinute(now),
                if (opReleased) "sent" else "pending",
                if (opReleased) 1 else 0,
            ),
        )
    }

    private fun steps(world: OwnerWorld) = MediaOrphanSteps(world.crypto, world.clock)

    private fun orphanRows(world: OwnerWorld, fx: Fx): Int =
        world.count("SELECT count(*) FROM dm_orphan_namespace WHERE namespace_id = ?", listOf(fx.mediaNs))

    private fun uploadRows(world: OwnerWorld, fx: Fx): Int =
        world.count("SELECT count(*) FROM media_upload WHERE namespace_id = ?", listOf(fx.mediaNs))

    // ---------------------------------------------------------- the three clauses

    @Test
    fun anObjectStillUploadingWithALiveDeadlineBlocksTheOrphan() {
        OwnerWorld().use { world ->
            val fx = seedContact(world)
            seedObject(world, fx, objectState = "uploading", itemState = "sent")
            val recorded = world.database.transaction { tx ->
                steps(world).recordIfOrphaned(tx, world.contexts.get(), fx.contactId)
            }
            assertFalse(recorded)
            assertEquals(0, orphanRows(world, fx))
            assertEquals(1, uploadRows(world, fx))
        }
    }

    @Test
    fun anObjectFailedPastItsDeadlineDoesNotBlock() {
        OwnerWorld().use { world ->
            val fx = seedContact(world)
            // Stored state still `uploading`, but the deadline is an hour gone: §5.1 counts it as
            // "failed past its deadline" (the read applies the deadline the MEDIA-DEADLINE pass
            // has not applied yet, §22.5 row 12).
            seedObject(
                world, fx,
                objectState = "uploading",
                itemState = "sent",
                uploadDeadline = ceilHour(now) - hour,
            )
            val recorded = world.database.transaction { tx ->
                steps(world).recordIfOrphaned(tx, world.contexts.get(), fx.contactId)
            }
            assertTrue(recorded)
            assertEquals(1, orphanRows(world, fx))
            assertEquals("the upload rows — the only foreign key into M_c — are gone", 0, uploadRows(world, fx))
        }
    }

    @Test
    fun aPendingDescriptorItemBlocksTheOrphan() {
        OwnerWorld().use { world ->
            val fx = seedContact(world)
            seedObject(world, fx, objectState = "uploaded", itemState = "enqueued")
            val recorded = world.database.transaction { tx ->
                steps(world).recordIfOrphaned(tx, world.contexts.get(), fx.contactId)
            }
            assertFalse(recorded)
            assertEquals(0, orphanRows(world, fx))
        }
    }

    @Test
    fun aFailedDescriptorBlocksOnlyUntilItsDeadline() {
        OwnerWorld().use { world ->
            val fx = seedContact(world)
            seedObject(
                world, fx,
                objectState = "uploaded",
                itemState = "failed",
                itemDeadline = ceilHour(now) + 2 * hour,
            )
            val blocked = world.database.transaction { tx ->
                steps(world).recordIfOrphaned(tx, world.contexts.get(), fx.contactId)
            }
            assertFalse("a FAILED descriptor may still be retried until its deadline", blocked)

            world.sql.exec(
                "UPDATE dm_outbound_item SET deadline_hour = ? WHERE item_id = ?",
                listOf(ceilHour(now) - hour, fx.itemId),
            )
            val recorded = world.database.transaction { tx ->
                steps(world).recordIfOrphaned(tx, world.contexts.get(), fx.contactId)
            }
            assertTrue(recorded)
            assertEquals(1, orphanRows(world, fx))
        }
    }

    @Test
    fun anUnreleasedMediaOpBlocksTheOrphan() {
        OwnerWorld().use { world ->
            val fx = seedContact(world)
            seedObject(world, fx, objectState = "uploaded", itemState = "sent", opReleased = false)
            val recorded = world.database.transaction { tx ->
                steps(world).recordIfOrphaned(tx, world.contexts.get(), fx.contactId)
            }
            assertFalse(recorded)
            assertEquals(0, orphanRows(world, fx))
            assertEquals(1, uploadRows(world, fx))
        }
    }

    @Test
    fun whenEveryClauseIsOverTheOrphanIsRecordedOnce() {
        OwnerWorld().use { world ->
            val fx = seedContact(world)
            seedObject(world, fx, objectState = "uploaded", itemState = "sent")

            val first = world.database.transaction { tx ->
                steps(world).recordIfOrphaned(tx, world.contexts.get(), fx.contactId)
            }
            assertTrue(first)
            assertEquals(1, orphanRows(world, fx))
            assertEquals(0, uploadRows(world, fx))
            // The object, fragments, blobs and the message die with the message's expiry; §5.1's
            // recording takes only the upload rows.
            assertEquals(1, world.count("SELECT count(*) FROM media_object WHERE object_id = ?", listOf(fx.objectId)))

            val second = world.database.transaction { tx ->
                steps(world).recordIfOrphaned(tx, world.contexts.get(), fx.contactId)
            }
            assertTrue("the rule is idempotent: a re-execution records no second row", second)
            assertEquals(1, orphanRows(world, fx))
        }
    }

    @Test
    fun aContactWithoutACardRecordsNothing() {
        OwnerWorld().use { world ->
            val fx = seedContact(world)
            seedObject(world, fx, objectState = "uploaded", itemState = "sent")
            // Block erases the card; §5.1's recording derives M_c from it, and block itself
            // recorded the orphan rows (ContactSteps).
            world.sql.exec(
                "UPDATE dm_contact SET card_env = NULL, trust_state = 'blocked' WHERE contact_id = ?",
                listOf(fx.contactId),
            )
            val recorded = world.database.transaction { tx ->
                steps(world).recordIfOrphaned(tx, world.contexts.get(), fx.contactId)
            }
            assertFalse(recorded)
            assertEquals(0, orphanRows(world, fx))
        }
    }

    @Test
    fun aClosedContextRecordsNothingAndWaitsForAPassThatCanDeriveMc() {
        OwnerWorld().use { world ->
            val fx = seedContact(world)
            seedObject(world, fx, objectState = "uploaded", itemState = "sent")
            val recorded = world.database.transaction { tx ->
                steps(world).recordIfOrphaned(tx, null, fx.contactId)
            }
            assertFalse(recorded)
            assertEquals(0, orphanRows(world, fx))
        }
    }

    // ---------------------------------------------------------- the SWEEP producers

    /**
     * §5.1's "or SWEEP": the message of an uploaded object expires; SWEEP's cascade takes the
     * object, the upload and the media-op mapping with it, and the same transaction records the
     * orphan — post-cascade the three clauses read as over, final and released, and no later
     * transaction would ever look at the contact's media rows again.
     */
    @Test
    fun sweepRecordsTheOrphanWhenTheExpiredMessageCascades() {
        OwnerWorld().use { world ->
            val fx = seedContact(world)
            seedObject(world, fx, objectState = "uploaded", itemState = "sent")
            // The operation row outlives the message (SWEEP never cancels; it runs to its
            // outcome): the orphan is still recorded, and the discharge below waits for it.
            // Both move together (the schema CHECK ties delete_at to expire_at, and the expiry
            // trigger admits only "earlier").
            world.sql.exec(
                "UPDATE dm_message SET expire_at_minute = ?, delete_at_minute = ? WHERE message_id = ?",
                listOf(floorMinute(now) - 60, floorMinute(now) - 60, fx.messageId),
            )

            world.sweeper.sweep()

            assertEquals(1, orphanRows(world, fx))
            assertEquals(0, world.count("SELECT count(*) FROM media_object WHERE object_id = ?", listOf(fx.objectId)))
            assertEquals(0, uploadRows(world, fx))
            // The unreleased Phase 7 operation keeps the namespace alive: SWEEP's discharge
            // (§21.12 point 3) answers false while an op or a fetched row is left.
            assertEquals(
                1,
                world.count("SELECT count(*) FROM sync_namespace WHERE namespace_id = ?", listOf(fx.mediaNs)),
            )

            // The op drains (released, then garbage-collected): the next sweep removes M_c and
            // its credentials exactly as for X_c and P_c — LOCAL, never redeemed, so nothing
            // relay-side moves.
            world.sql.exec("DELETE FROM outbox_op WHERE operation_id = ?", listOf(fx.opId))
            world.sweeper.sweep()
            assertEquals(0, orphanRows(world, fx))
            assertEquals(
                0,
                world.count("SELECT count(*) FROM sync_namespace WHERE namespace_id = ?", listOf(fx.mediaNs)),
            )
            assertEquals(
                0,
                world.count("SELECT count(*) FROM relay_capability WHERE namespace_id = ?", listOf(fx.mediaNs)),
            )
        }
    }

    /**
     * The mirror edge: an upload that is **not** over keeps SWEEP from recording anything even
     * when the message it is under has expired — the cascade cannot make the condition true
     * while a live deadline or an open op still names work.
     *
     * Here the expired message belongs to an object whose operation is still unreleased; the
     * cascade removes the media-op mapping, so the orphan IS recorded (nothing can ever release
     * through the mapping again) — what must NOT happen is the namespace's removal while the
     * Phase 7 op is alive, which the test above already pins. So this test pins the other half:
     * a message that has NOT expired must not record the orphan even when everything else is
     * over.
     */
    @Test
    fun sweepRecordsNothingWhileTheMessageLives() {
        OwnerWorld().use { world ->
            val fx = seedContact(world)
            seedObject(world, fx, objectState = "uploaded", itemState = "sent")
            world.sweeper.sweep()
            assertEquals(0, orphanRows(world, fx))
            assertEquals(1, uploadRows(world, fx))
        }
    }

    /** `recordOrphans` at block covers M_c with X_c and P_c (§5.1: "Blocking or deleting the
     *  contact records M_c with X_c and P_c"). */
    @Test
    fun blockRecordsMcWithTheOtherTwoNamespaces() {
        OwnerWorld().use { world ->
            val fx = seedContact(world)
            seedObject(world, fx, objectState = "uploaded", itemState = "sent")
            assertTrue(world.contactSteps.block(fx.contactId))
            assertEquals(1, orphanRows(world, fx))
        }
    }
}
