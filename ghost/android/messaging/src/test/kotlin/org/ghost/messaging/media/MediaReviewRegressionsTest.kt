package org.ghost.messaging.media

import org.ghost.media.send.Preparations
import org.ghost.media.store.RetryResult
import org.ghost.messaging.api.SendResult
import org.ghost.messaging.engine.MediaEngineSupport
import org.ghost.messaging.engine.MediaPipelinePorts
import org.ghost.storage.queryLong
import org.ghost.storage.queryString
import org.ghost.sync.api.Outcome
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.concurrent.Executors

/**
 * The S5 review's four findings (§22.8 rows 26–29), each a regression over [MediaWorld]:
 *
 *  - **F1 / F-S5-15**: the facade's `retryMedia` nested the re-feed inside the retry transaction
 *    (`SyncDatabase` is not reentrant — the facade always threw; the store-level suites bypass the
 *    facade). Driven here through the production [MediaEngineSupport.retryMedia].
 *  - **F2 / F-S5-16**: a deadline-failed object's ops, decided later FAILED, wedged the pass
 *    (`markFailed` on an already-failed object threw, rolling back the release). The interleaving:
 *    deadline pass first, outbox decides after — `outcomes()` must be green, and the world's relay
 *    now writes real `outbox_op` rows so `MEDIA_ORPHAN_OP_BLOCKERS` is live (an unreleased op must
 *    block the orphan rule).
 *  - **F3 / F-S5-17**: the READY descriptor had no recovery (crash between the commit and the
 *    flush, or a transient flush refusal, stranded it with `M_c` pinned). The flush failure now
 *    queues the pending send, and `recoverDescriptors` re-sends an uploaded object's pending
 *    descriptor after a reboot — exactly-once (guards + no duplicate pending rows).
 *  - **F4 / F-S5-18**: a FAILED outcome now starts the sender's countdown at the failure (the
 *    commit-time bound ran deletion late by up to the deadline window).
 */
class MediaReviewRegressionsTest {

    private class Sandbox {
        val dir: File = java.nio.file.Files.createTempDirectory("ghost-review").toFile()
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

    private fun commitOne(world: MediaWorld, contact: ByteArray, tag: Byte): ByteArray {
        val prepared = world.preparer.prepareImage(Goldens.jpeg, contact, viewOnce = false)
        val sealed = prepared.sealed
        val objectId = ByteArray(16) { tag.toByte() }
        val result = world.steps.commit(
            world.contexts.get()!!,
            org.ghost.messaging.engine.MediaSteps.CommitRequest(
                contactId = contact,
                kind = org.ghost.media.store.MediaKind.IMAGE,
                viewOnce = false,
                classCode = sealed.classCode,
                objectId = objectId,
                manifestHash = sealed.manifestHash,
                caption = "review".toByteArray(),
                keyEnv = sealed.keyEnv,
                manifestBlob = sealed.manifestBlob,
                manifestFile = sealed.manifestFile,
                fragmentHashes = sealed.fragmentHashes,
                fragmentFiles = sealed.fragmentFiles,
            ),
        )
        check(result is org.ghost.messaging.engine.MediaSteps.CommitResult.Committed)
        world.steps.feed()
        return objectId
    }

    /** The production facade's support over this world (the worker/actor are the test's own). */
    private fun support(world: MediaWorld): MediaEngineSupport = MediaEngineSupport(
        database = world.database,
        steps = world.steps,
        preparations = Preparations(),
        pipeline = MediaPipelinePorts(world.files, world.preparing, FakeStripper, FakeVideoExport),
        worker = Executors.newSingleThreadExecutor(),
        random = world.random,
        contexts = world.contexts,
        actorCall = { it() },
    )

    private fun expireOf(world: MediaWorld): Long {
        var v = 0L
        world.sql.query("SELECT expire_at_minute FROM dm_message WHERE kind = 5", emptyList()) { v = it.long(0) }
        return v
    }

    @Test
    fun theFacadeRetryRefeedsOutsideTheRetryTransaction() {
        val box = Sandbox()
        val world = box.open()
        val contact = ByteArray(16) { 0x21 }
        world.addContact(contact)
        val objectId = commitOne(world, contact, tag = 0x41)

        // A FAILED outcome fails the object; the facade retry must re-feed and answer QUEUED —
        // with the nesting restored this throws IllegalStateException out of the facade.
        world.relay.script(world.relay.opIdOf(objectId, 0), Outcome.FAILED)
        world.steps.outcomes()
        assertEquals(
            "failed",
            world.sql.queryString("SELECT state FROM media_object WHERE object_id = ?", listOf(objectId)),
        )
        var messageId = ByteArray(0)
        world.sql.query("SELECT message_id FROM media_object WHERE object_id = ?", listOf(objectId)) {
            messageId = it.blob(0)
        }
        val facade = support(world)
        assertEquals(SendResult.QUEUED, facade.retryMedia(messageId))
        // F-S5-19: the re-feed of the identical bytes is refused by Phase 7's
        // UNIQUE(namespace, blob_hash) — the retried ordinal stays unsent, documented for the
        // owner (per-retry-generation op ids vs the frozen-bytes rule).
        assertEquals(
            0L,
            world.sql.queryLong(
                "SELECT count(*) FROM media_outbound_op WHERE object_id = ? AND ordinal = 0 AND retry_gen = 1",
                listOf(objectId),
            ),
        )
        assertEquals(
            "unsent",
            world.sql.queryString(
                "SELECT upload_state FROM media_fragment WHERE object_id = ? AND ordinal = 0",
                listOf(objectId),
            ),
        )
        facade.close()
        box.world.close()
    }

    @Test
    fun aDeadlineFailedObjectsLateFailedOutcomeDoesNotWedgeThePass() {
        val box = Sandbox()
        val world = box.open()
        val contact = ByteArray(16) { 0x21 }
        world.addContact(contact)
        val objectId = commitOne(world, contact, tag = 0x42)

        // The device is offline at the deadline: the deadline pass fails the object while its 17
        // ops sit unreleased at the relay.
        world.clock.now = MediaWorld.NOW + 7 * 86_400L + 3_600L
        world.steps.deadline()
        assertEquals(
            "failed",
            world.sql.queryString("SELECT state FROM media_object WHERE object_id = ?", listOf(objectId)),
        )
        // F-S5-16's live clause: the unreleased ops block the orphan rule.
        assertEquals(
            0L,
            world.sql.queryLong("SELECT count(*) FROM dm_orphan_namespace", emptyList()),
        )
        assertEquals(
            1L,
            world.sql.queryLong("SELECT count(*) FROM media_upload WHERE object_id = ?", listOf(objectId)),
        )
        // The outbox decides them all FAILED later: the pass is green (with the unguarded move,
        // the first outcome re-threw every pass, rolling back its own release).
        repeat(17) { i ->
            world.relay.script(world.relay.opIdOf(objectId, i - 1), Outcome.FAILED)
        }
        world.steps.outcomes()
        world.steps.feed()
        assertEquals(
            17L,
            world.sql.queryLong(
                "SELECT count(*) FROM media_fragment WHERE object_id = ? AND upload_state = 'failed'",
                listOf(objectId),
            ),
        )
        // Every op released, the descriptor item failed past its deadline: the orphan completes.
        assertEquals(
            1L,
            world.sql.queryLong("SELECT count(*) FROM dm_orphan_namespace", emptyList()),
        )
        assertEquals(
            0L,
            world.sql.queryLong("SELECT count(*) FROM media_upload", emptyList()),
        )
        box.world.close()
    }

    @Test
    fun aReadyDescriptorLeftPendingIsRecoveredAfterAReboot() {
        val box = Sandbox()
        var world = box.open()
        val contact = ByteArray(16) { 0x21 }
        world.addContact(contact)
        val objectId = commitOne(world, contact, tag = 0x43)

        // Every ordinal SENT: READY commits, the flush runs — and in this world the envelope
        // layer is closed, so the flush fails and (F-S5-17) queues the descriptor like a text.
        repeat(17) { i ->
            world.relay.script(world.relay.opIdOf(objectId, i - 1), Outcome.SENT)
        }
        world.steps.outcomes()
        assertEquals(
            "uploaded",
            world.sql.queryString("SELECT state FROM media_object WHERE object_id = ?", listOf(objectId)),
        )
        assertEquals(
            1L,
            world.sql.queryLong("SELECT count(*) FROM dm_pending_send", emptyList()),
        )
        // The crash window: reboot between the READY commit and any successful flush.
        world = box.open(box.world.relay)
        // The pass's recovery finds the uploaded object with its descriptor still pending.
        world.steps.recoverDescriptors()
        assertEquals(
            1L,
            world.sql.queryLong("SELECT count(*) FROM dm_pending_send", emptyList()),
        )
        assertEquals(
            "pending",
            world.sql.queryString("SELECT state FROM dm_outbound_item WHERE kind = 5", emptyList()),
        )
        // And the ordinary pass hook does the same (idempotent: no second pending row).
        world.steps.recoverDescriptors()
        assertEquals(
            1L,
            world.sql.queryLong("SELECT count(*) FROM dm_pending_send", emptyList()),
        )
        box.world.close()
    }

    @Test
    fun aFailedOutcomeStartsTheCountdownAtTheFailure() {
        val box = Sandbox()
        val world = box.open()
        val contact = ByteArray(16) { 0x21 }
        world.addContact(contact)
        val objectId = commitOne(world, contact, tag = 0x44)

        val upper = expireOf(world)
        world.relay.script(world.relay.opIdOf(objectId, 0), Outcome.FAILED)
        world.steps.outcomes()
        val timerCode = world.sql.queryLong("SELECT timer_code FROM dm_conversation", emptyList())!!.toInt()
        val timerSeconds = org.ghost.messaging.engine.DmTimers.timerSeconds(timerCode)
        // The countdown anchors at the failure moment: ceil-to-minute(now + timer), strictly
        // earlier than the commit-time upper bound (deadline hour + timer).
        val expect = -Math.floorDiv(-(MediaWorld.NOW + timerSeconds), 60L) * 60L
        val lowered = expireOf(world)
        assertTrue("lowered=$lowered expect=$expect upper=$upper", lowered in expect..expect + 60 && lowered < upper)
        box.world.close()
    }
}
