package org.ghost.messaging.media

import org.ghost.media.send.MediaPreparer
import org.ghost.messaging.engine.MediaSteps
import org.ghost.storage.queryLong
import org.ghost.storage.queryString
import org.ghost.sync.api.Outcome
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * **SCN-MA** (Phase 11 design §15.3): one scripted send — the image preparation through the real
 * `SealingChannel` and file store, then `MEDIA-COMMIT` and `MEDIA-FEED` — with a crash (a real
 * process exit: the world closes, the database file and the directory stay) **at every file
 * operation** of the run. After every reboot: reconcile, then the invariants — no committed object
 * with a missing or wrong-hash file, no `key_env` without all F + 1 bound rows, no stray file —
 * then the run resumes to quiescence. A crash before the commit leaves no committed object (the
 * preparation is memory-only, S0-23); a crash after it resumes at `MEDIA-FEED` without a double
 * feed (deterministic op ids), and a re-delivered outcome is applied exactly once (release-first).
 */
class MediaSendScenarioTest {

    private class Sandbox {
        val dir: File = java.nio.file.Files.createTempDirectory("ghost-scn-ma").toFile()
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
            caption = "scn-ma".toByteArray(),
            keyEnv = sealed.keyEnv,
            manifestBlob = sealed.manifestBlob,
            manifestFile = sealed.manifestFile,
            fragmentHashes = sealed.fragmentHashes,
            fragmentFiles = sealed.fragmentFiles,
        )
    }

    /** The scripted run: prepare, commit, feed. Returns the committed object id. */
    private fun runOnce(world: MediaWorld, contactId: ByteArray): ByteArray {
        val prepared = world.preparer.prepareImage(Goldens.jpeg, contactId, viewOnce = false)
        val result = world.steps.commit(world.contexts.get()!!, commitRequest(prepared, contactId))
        check(result is MediaSteps.CommitResult.Committed)
        world.steps.feed()
        return prepared.objectId
    }

    @Test
    fun aCrashAtEveryFileOperationLeavesAWholeObjectOrNothing() {
        if (!MediaScenarios.owns(0)) return
        // Measure the run's file calls on a quiet pass first.
        val counter = Sandbox()
        val cw = counter.open()
        val ccid = ByteArray(16) { 0x21 }
        cw.addContact(ccid)
        runOnce(cw, ccid)
        val totalCalls = cw.crashFs.trace.size
        counter.world.close()

        for (k in 1..totalCalls) {
            val box = Sandbox()
            var world = box.open()
            val contact = ByteArray(16) { 0x21 }
            world.addContact(contact)
            val fs = world.crashFs
            fs.crashAtCall = k
            // The preparation dies at its k-th file call; the "process" exits with the exception.
            try {
                world.preparer.prepareImage(Goldens.jpeg, contact, viewOnce = false)
                error("the crash at call $k did not fire")
            } catch (e: Exception) {
                // the crash: close without reconcile, like a power loss
            }
            box.world.close()
            world = box.open()
            world.reconcile()
            world.assertSendInvariants()
            // No commit happened: nothing references the world.
            assertEquals(
                "crash at call $k left no object",
                0L,
                world.sql.queryLong("SELECT count(*) FROM media_object", emptyList()),
            )
            // Resume: the preparation re-runs (its names died with the process; the reconcile took
            // the orphans), then commit and feed complete.
            runOnce(world, contact)
            world.reconcile()
            world.assertSendInvariants()
            assertEquals(
                "crash at call $k: exactly one object",
                1L,
                world.sql.queryLong("SELECT count(*) FROM media_object", emptyList()),
            )
            assertEquals(
                "crash at call $k: 17 blobs",
                17L,
                world.sql.queryLong("SELECT count(*) FROM media_blob", emptyList()),
            )
            assertEquals(
                "crash at call $k: every ordinal open (fed once)",
                17L,
                world.sql.queryLong(
                    "SELECT count(*) FROM media_fragment WHERE upload_state = 'open'",
                    emptyList(),
                ),
            )
            box.world.close()
        }
        // §15.3's close-out: the enumeration ran whole and every reboot's invariants held.
        MediaScenarios.report("SCN-MA", totalCalls, "preparation and MEDIA-COMMIT file operations")
    }

    @Test
    fun aCrashBetweenCommitAndFeedResumesWithoutADoubleFeed() {
        val box = Sandbox()
        var world = box.open()
        val contact = ByteArray(16) { 0x21 }
        world.addContact(contact)

        val prepared = world.preparer.prepareImage(Goldens.jpeg, contact, viewOnce = false)
        val committed = world.steps.commit(world.contexts.get()!!, commitRequest(prepared, contact))
        check(committed is MediaSteps.CommitResult.Committed)
        box.world.close()

        world = box.open(box.world.relay)
        world.assertSendInvariants()
        world.steps.feed()
        world.steps.feed() // the second pass must be a no-op: the windows are per state
        assertEquals(17L, world.sql.queryLong("SELECT count(*) FROM media_outbound_op", emptyList()))
        // 18 ops reached the relay: 17 media ops + the owner's bundle op ACTIVATE published.
        assertEquals(18, world.relay.held.size)
        box.world.close()
    }

    @Test
    fun aReDeliveredOutcomeIsAppliedExactlyOnce() {
        val box = Sandbox()
        var world = box.open()
        val contact = ByteArray(16) { 0x21 }
        world.addContact(contact)
        val objectId = runOnce(world, contact)

        // Script SENT for every ordinal; apply the first half, crash, reopen, re-offer ALL of it
        // (a relay re-delivers), apply again: release-first + the guarded transitions make the
        // second application a no-op.
        repeat(17) { i ->
            world.relay.script(world.relay.opIdOf(objectId, i - 1), Outcome.SENT)
        }
        world.steps.outcomes()
        box.world.close()
        world = box.open(box.world.relay)
        world.assertSendInvariants()
        repeat(17) { i ->
            world.relay.script(world.relay.opIdOf(objectId, i - 1), Outcome.SENT)
        }
        world.steps.outcomes()
        world.steps.outcomes()
        assertEquals(
            "uploaded once every ordinal is final",
            "uploaded",
            world.sql.queryString("SELECT state FROM media_object WHERE object_id = ?", listOf(objectId)),
        )
        // The descriptor SEND stops at the closed envelope layer: the item stays pending (on a
        // device the session check queues dm_pending_send), and the relay holds no descriptor op.
        assertEquals(
            "pending",
            world.sql.queryString("SELECT state FROM dm_outbound_item WHERE kind = 5", emptyList()),
        )
        assertEquals(18, world.relay.held.size)
        box.world.close()
    }
}
