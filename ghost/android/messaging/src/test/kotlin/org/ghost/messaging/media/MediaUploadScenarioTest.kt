package org.ghost.messaging.media

import org.ghost.media.send.MediaPreparer
import org.ghost.messaging.engine.MediaSteps
import org.ghost.storage.queryLong
import org.ghost.storage.queryString
import org.ghost.sync.api.Outcome
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * **SCN-MB** (Phase 11 design §15.3): the upload state machine on a class-0 object (17 ordinals)
 * with scripted outcomes — SENT to READY (the countdown, the descriptor sendable exactly once),
 * INDETERMINATE with the two resends and the final-indeterminate rule, FAILED with the user retry
 * (a new generation, the acknowledged ordinals never re-enqueued, the failed one re-fed from the
 * same ciphertext files), and the deadline. The per-ordinal oracles: op ids unique and
 * deterministic, at most two resends per ordinal and generation, an acknowledged ordinal never
 * enqueued again, and `expire_at_minute` never increasing, lowered exactly at READY.
 */
class MediaUploadScenarioTest {

    private class Sandbox {
        val dir: File = java.nio.file.Files.createTempDirectory("ghost-scn-mb").toFile()
        val db: String = File(dir, "world.db").absolutePath
        var world: MediaWorld = MediaWorld(db, dir)
        var activated = false

        fun open(relay: ScriptedOutbox = this.world.relay): MediaWorld {
            world.close()
            world = MediaWorld(db, dir, relay)
            if (!activated) {
                world.activate()
                activated = true
            }
            return world
        }
    }

    private fun commitRequest(prepared: MediaPreparer.Prepared, contactId: ByteArray): MediaSteps.CommitRequest {
        val sealed = prepared.sealed
        return MediaSteps.CommitRequest(
            contactId = contactId,
            kind = org.ghost.media.store.MediaKind.IMAGE,
            viewOnce = prepared.viewOnce,
            classCode = sealed.classCode,
            objectId = prepared.objectId,
            manifestHash = sealed.manifestHash,
            caption = "scn-mb".toByteArray(),
            keyEnv = sealed.keyEnv,
            manifestBlob = sealed.manifestBlob,
            manifestFile = sealed.manifestFile,
            fragmentHashes = sealed.fragmentHashes,
            fragmentFiles = sealed.fragmentFiles,
        )
    }

    private fun commitOne(world: MediaWorld, contact: ByteArray, tag: Byte): ByteArray {
        val prepared = world.preparer.prepareImage(Goldens.jpeg, contact, viewOnce = false)
        // Distinguish objects: rewrite the object id the request names (the sealer's id is fixed).
        val request = commitRequest(prepared, contact).let { r ->
            MediaSteps.CommitRequest(
                contactId = r.contactId, kind = r.kind, viewOnce = r.viewOnce, classCode = r.classCode,
                objectId = ByteArray(16) { tag.toByte() }, manifestHash = r.manifestHash,
                caption = r.caption, keyEnv = r.keyEnv, manifestBlob = r.manifestBlob,
                manifestFile = r.manifestFile, fragmentHashes = r.fragmentHashes,
                fragmentFiles = r.fragmentFiles,
            )
        }
        val result = world.steps.commit(world.contexts.get()!!, request)
        check(result is MediaSteps.CommitResult.Committed)
        world.steps.feed()
        return request.objectId
    }

    private fun oracleOps(world: MediaWorld, objectId: ByteArray): Long =
        world.sql.queryLong(
            "SELECT count(*) FROM media_outbound_op WHERE object_id = ?",
            listOf(objectId),
        )!!

    @Test
    fun sentOutcomesReachReadyExactlyOnceWithTheCountdownStarted() {
        val box = Sandbox()
        val world = box.open()
        val contact = ByteArray(16) { 0x21 }
        world.addContact(contact)
        val objectId = commitOne(world, contact, tag = 0x30)

        val expireBefore = world.sql.queryLong(
            "SELECT expire_at_minute FROM dm_message WHERE kind = 5",
            emptyList(),
        )!!
        // SENT for every ordinal, one pass.
        repeat(17) { i ->
            world.relay.script(world.relay.opIdOf(objectId, i - 1), Outcome.SENT)
        }
        world.steps.outcomes()
        assertEquals(
            "uploaded",
            world.sql.queryString("SELECT state FROM media_object WHERE object_id = ?", listOf(objectId)),
        )
        val expireAfter = world.sql.queryLong(
            "SELECT expire_at_minute FROM dm_message WHERE kind = 5",
            emptyList(),
        )!!
        assertTrue("the countdown never increases", expireAfter <= expireBefore)
        assertTrue("the countdown moved to the deadline hour + timer", expireAfter < expireBefore)
        // The descriptor is sendable exactly once: with the envelope layer closed the flush stops
        // at the decode (the item stays pending, no descriptor op reaches the relay — on a device
        // the session check queues it in dm_pending_send; §6.3's "waits exactly as a text does").
        assertEquals(
            "pending",
            world.sql.queryString("SELECT state FROM dm_outbound_item WHERE kind = 5", emptyList()),
        )
        assertEquals(18, world.relay.held.size) // 17 media ops + the owner's bundle op, no descriptor
        // A further pass changes nothing.
        world.steps.outcomes()
        assertEquals(18, world.relay.held.size)
        box.world.close()
    }

    @Test
    fun indeterminateResendsTwiceThenSettlesFinal() {
        val box = Sandbox()
        val world = box.open()
        val contact = ByteArray(16) { 0x21 }
        world.addContact(contact)
        val objectId = commitOne(world, contact, tag = 0x31)

        val op0 = world.relay.opIdOf(objectId, 0)
        // INDETERMINATE with resend budget: resend 1; again: resend 2; again: no budget left.
        world.relay.script(op0, Outcome.INDETERMINATE, resendNotAfter = MediaWorld.NOW + 3_600)
        world.steps.outcomes()
        assertEquals(
            "the ordinal stays open on a resend",
            "open",
            world.sql.queryString(
                "SELECT upload_state FROM media_fragment WHERE object_id = ? AND ordinal = 0",
                listOf(objectId),
            ),
        )
        val resend1 = world.relay.opIdOf(objectId, 0, resend = 1)
        world.relay.script(resend1, Outcome.INDETERMINATE, resendNotAfter = MediaWorld.NOW + 3_600)
        world.steps.outcomes()
        val resend2 = world.relay.opIdOf(objectId, 0, resend = 2)
        world.relay.script(resend2, Outcome.INDETERMINATE, resendNotAfter = MediaWorld.NOW + 3_600)
        world.steps.outcomes()
        assertEquals(
            "final indeterminate after the budget",
            "indeterminate",
            world.sql.queryString(
                "SELECT upload_state FROM media_fragment WHERE object_id = ? AND ordinal = 0",
                listOf(objectId),
            ),
        )
        // Oracle: 17 first-feed ops + 2 resends for ordinal 0, every id unique.
        assertEquals(19L, oracleOps(world, objectId))
        // The other ordinals are still open (no outcomes scripted for them): 1..15 = 15.
        assertEquals(
            15L,
            world.sql.queryLong(
                "SELECT count(*) FROM media_fragment WHERE object_id = ? AND upload_state = 'open' AND ordinal > 0",
                listOf(objectId),
            ),
        )
        box.world.close()
    }

    @Test
    fun aFailedOrdinalFailsTheObjectAndTheUserRetryRefeedsOnlyTheFailedOrdinal() {
        val box = Sandbox()
        val world = box.open()
        val contact = ByteArray(16) { 0x21 }
        world.addContact(contact)
        val objectId = commitOne(world, contact, tag = 0x32)

        // SENT for ordinals -1..14, FAILED for 15: the object fails mid-burst.
        repeat(16) { i ->
            world.relay.script(world.relay.opIdOf(objectId, i - 1), Outcome.SENT)
        }
        world.relay.script(world.relay.opIdOf(objectId, 15), Outcome.FAILED)
        world.steps.outcomes()
        assertEquals(
            "failed",
            world.sql.queryString("SELECT state FROM media_object WHERE object_id = ?", listOf(objectId)),
        )
        assertEquals(
            "failed",
            world.sql.queryString("SELECT state FROM dm_message WHERE kind = 5", emptyList()),
        )
        // User retry before the deadline: generation 1, the failed ordinal back to unsent.
        val retried = world.database.transaction { tx -> world.objects.retryUpload(tx, objectId, MediaWorld.NOW) }
        assertEquals(org.ghost.media.store.RetryResult.RETRIED, retried)
        world.steps.feed()
        // Oracle: the acknowledged 16 ordinals were never enqueued again; only ordinal 15 re-fed.
        assertEquals(18L, oracleOps(world, objectId)) // 17 first feed + 1 retry
        assertEquals(
            1L,
            world.sql.queryLong(
                "SELECT count(*) FROM media_outbound_op WHERE object_id = ? AND ordinal = 15 AND retry_gen = 1",
                listOf(objectId),
            ),
        )
        assertEquals(
            0L,
            world.sql.queryLong(
                "SELECT count(*) FROM media_outbound_op WHERE object_id = ? AND ordinal = 0 AND retry_gen = 1",
                listOf(objectId),
            ),
        )
        box.world.close()
    }

    @Test
    fun theDeadlineFailsTheObjectAndTheOrphanRuleTakesTheUpload() {
        val box = Sandbox()
        val world = box.open()
        val contact = ByteArray(16) { 0x21 }
        val mediaNs = world.addContact(contact)
        val objectId = commitOne(world, contact, tag = 0x33)

        world.clock.now = MediaWorld.NOW + 7 * 86_400L + 3_600L
        world.steps.deadline()
        assertEquals(
            "failed",
            world.sql.queryString("SELECT state FROM media_object WHERE object_id = ?", listOf(objectId)),
        )
        // The descriptor item is failed-past-deadline and no ops are in flight: the orphan rule
        // completed in the same transaction — the upload row is gone, M_c recorded.
        assertEquals(
            0L,
            world.sql.queryLong("SELECT count(*) FROM media_upload WHERE object_id = ?", listOf(objectId)),
        )
        assertEquals(
            1L,
            world.sql.queryLong(
                "SELECT count(*) FROM dm_orphan_namespace WHERE namespace_id = ?",
                listOf(mediaNs),
            ),
        )
        box.world.close()
    }
}
